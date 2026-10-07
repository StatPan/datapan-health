package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	OperationAttemptStoreSchemaVersion   = "datapan.health-operation-attempt-store.v2"
	maxOperationAttemptStateBytes        = 32 * 1024
	maxOperationAttemptHistory           = 24
	maxOperationAttemptStoreOperations   = 16_000
	maxOperationAttemptLease             = 10 * time.Minute
	maxOperationAttemptStoreBytes        = int64(512 * 1024 * 1024)
	operationAttemptIdentityBatchMaximum = 256
)

var (
	ErrOperationAttemptUnavailable = errors.New("operation attempt state is unavailable")
	ErrOperationAttemptHeld        = errors.New("operation attempt lease is held")
	ErrOperationAttemptAmbiguous   = errors.New("operation attempt outcome is ambiguous")
	ErrOperationAttemptNotDue      = errors.New("operation observation is not due")
	ErrOperationAttemptDelivery    = errors.New("operation delivery is pending")
	ErrOperationAttemptFenced      = errors.New("operation attempt claim is fenced")
	ErrOperationAttemptCapacity    = errors.New("operation attempt history is full")
	operationGatusKeyPattern       = regexp.MustCompile(`^[a-z0-9-]+_[a-z0-9-]+$`)
)

// OperationAttemptBinding is the immutable Registry identity chain for one
// selected observation. It contains no request target or credential value.
type OperationAttemptBinding struct {
	SourceID           string        `json:"source_id"`
	OperationID        string        `json:"operation_id"`
	RegistryRevision   string        `json:"registry_revision"`
	ReleaseManifestSHA string        `json:"release_manifest_sha256"`
	IndexSHA           string        `json:"index_sha256"`
	ShardSHA           string        `json:"shard_sha256"`
	GatusKey           string        `json:"gatus_key"`
	ObservationPeriod  time.Duration `json:"observation_period_ns"`
}

// OperationObservationResult is the minimal validated result kept by the
// attempt ledger. Raw receipt text, provider URLs, credentials, and response
// bodies never enter this record.
type OperationObservationResult struct {
	State      string    `json:"state"`
	Category   string    `json:"category"`
	ObservedAt time.Time `json:"observed_at"`
	ReceivedAt time.Time `json:"received_at"`
	ReceiptSHA string    `json:"receipt_sha256"`
	LatencyMS  int64     `json:"latency_ms"`
}

// OperationAttemptClaim is a fenced authorization to begin a child invocation.
// It is durably claimed work, not evidence that a provider request started.
type OperationAttemptClaim struct {
	Binding    OperationAttemptBinding
	AttemptID  string
	Generation uint64
	StartedAt  time.Time
	ExpiresAt  time.Time
}

type OperationDeliveryClaim struct {
	Binding            OperationAttemptBinding
	AttemptID          string
	AttemptGeneration  uint64
	DeliveryGeneration uint64
	AttemptCount       int
	Result             OperationObservationResult
}

type OperationStoredAttempt struct {
	Binding            OperationAttemptBinding     `json:"binding"`
	AttemptID          string                      `json:"attempt_id"`
	Generation         uint64                      `json:"generation"`
	StartedAt          time.Time                   `json:"started_at"`
	LeaseExpiresAt     time.Time                   `json:"lease_expires_at"`
	FinishedAt         time.Time                   `json:"finished_at,omitempty"`
	State              string                      `json:"state"`
	ReceiptValidated   bool                        `json:"receipt_validated"`
	ReceiptSHA256      string                      `json:"receipt_sha256,omitempty"`
	RequestStarted     *bool                       `json:"request_started"`
	BlockReason        string                      `json:"block_reason,omitempty"`
	Result             *OperationObservationResult `json:"result,omitempty"`
	DeliveryState      string                      `json:"delivery_state"`
	DeliveryGeneration uint64                      `json:"delivery_generation"`
	DeliveryAttempts   int                         `json:"delivery_attempts"`
	DeliveryStartedAt  time.Time                   `json:"delivery_started_at,omitempty"`
	DeliveryAckAt      time.Time                   `json:"delivery_response_at,omitempty"`
	GatusReceivedAt    time.Time                   `json:"gatus_received_at,omitempty"`
	GatusResultState   string                      `json:"gatus_result_state,omitempty"`
}

type operationAttemptState struct {
	SchemaVersion                 string                   `json:"schema_version"`
	OperationID                   string                   `json:"operation_id"`
	SourceID                      string                   `json:"source_id"`
	Generation                    uint64                   `json:"generation"`
	EverRequestStarted            bool                     `json:"ever_request_started"`
	CurrentPlanSHA256             string                   `json:"current_plan_sha256"`
	CurrentPlanEverRequestStarted bool                     `json:"current_plan_ever_request_started"`
	Attempts                      []OperationStoredAttempt `json:"attempts"`
}

// OperationAttemptStore stores one bounded, atomically replaced state file per
// operation. A shared flock coordinates processes on one filesystem with
// working flock semantics; this alone is not a cross-host guarantee.
type OperationAttemptStore struct {
	root       string
	stampsMu   sync.Mutex
	readStamps map[string]operationAttemptFileStamp
}

type OperationAttemptIdentity struct {
	SourceID    string
	OperationID string
}

type operationAttemptFileStamp struct {
	exists     bool
	modifiedNS int64
	size       int64
	inode      uint64
}

type OperationAttemptStorageBudget struct {
	PlannedOperations int   `json:"planned_operations"`
	MaximumOperations int   `json:"maximum_operations"`
	MaximumStateBytes int64 `json:"maximum_state_bytes_per_operation"`
	EstimatedMaximum  int64 `json:"estimated_maximum_bytes"`
	MaximumStoreBytes int64 `json:"maximum_store_bytes"`
}

// ValidateOperationAttemptStorageBudget proves that worst-case per-operation
// receipts fit the explicit store ceiling for the complete Registry plan.
func ValidateOperationAttemptStorageBudget(plannedOperations int) (OperationAttemptStorageBudget, error) {
	budget := OperationAttemptStorageBudget{PlannedOperations: plannedOperations, MaximumOperations: maxOperationAttemptStoreOperations, MaximumStateBytes: maxOperationAttemptStateBytes, MaximumStoreBytes: maxOperationAttemptStoreBytes}
	if plannedOperations < 1 || plannedOperations > maxOperationAttemptStoreOperations {
		return OperationAttemptStorageBudget{}, ErrOperationAttemptCapacity
	}
	budget.EstimatedMaximum = int64(plannedOperations) * int64(maxOperationAttemptStateBytes)
	if budget.EstimatedMaximum > maxOperationAttemptStoreBytes {
		return OperationAttemptStorageBudget{}, ErrOperationAttemptCapacity
	}
	return budget, nil
}

func OpenOperationAttemptStore(root string) (*OperationAttemptStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, ErrOperationAttemptUnavailable
	}
	abs, err := filepath.Abs(root)
	if err != nil || filepath.Clean(abs) == string(filepath.Separator) {
		return nil, ErrOperationAttemptUnavailable
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, ErrOperationAttemptUnavailable
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || os.Chmod(abs, 0o700) != nil {
		return nil, ErrOperationAttemptUnavailable
	}
	return &OperationAttemptStore{root: abs, readStamps: make(map[string]operationAttemptFileStamp)}, nil
}

// SnapshotReadModelAttemptsForIdentities reads only the deterministic state
// files for one bounded Registry identity batch. File stamps let the separate
// public process skip unchanged files without walking the whole store or
// taking the writer flock. A later atomic rename changes the inode/stamp and
// is picked up on the next pass.
func (store *OperationAttemptStore) SnapshotReadModelAttemptsForIdentities(identities []OperationAttemptIdentity) ([]OperationReadModelAttempt, error) {
	if store == nil || len(identities) > operationAttemptIdentityBatchMaximum {
		return nil, ErrOperationAttemptUnavailable
	}
	store.stampsMu.Lock()
	defer store.stampsMu.Unlock()
	if store.readStamps == nil {
		store.readStamps = make(map[string]operationAttemptFileStamp)
	}
	snapshots := make([]OperationReadModelAttempt, 0, len(identities))
	stampUpdates := make(map[string]operationAttemptFileStamp, len(identities))
	seen := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		if !operationSourceIDPattern.MatchString(identity.SourceID) || identity.OperationID == "" || len(identity.OperationID) > 256 {
			return nil, ErrOperationAttemptUnavailable
		}
		key := operationReadModelIdentityKey(identity.SourceID, identity.OperationID)
		if _, duplicate := seen[key]; duplicate {
			return nil, ErrOperationAttemptUnavailable
		}
		seen[key] = struct{}{}
		path := store.statePath(identity.SourceID, identity.OperationID)
		stamp, exists, err := operationAttemptFileStampAt(path)
		if err != nil {
			return nil, ErrOperationAttemptUnavailable
		}
		previous, known := store.readStamps[path]
		if known && previous == stamp {
			continue
		}
		if !exists {
			if known && previous.exists {
				return nil, ErrOperationAttemptUnavailable
			}
			stampUpdates[path] = stamp
			continue
		}
		state, found, err := store.readState(identity.SourceID, identity.OperationID)
		if err != nil || !found {
			return nil, ErrOperationAttemptUnavailable
		}
		after, stillExists, err := operationAttemptFileStampAt(path)
		if err != nil || !stillExists || after != stamp {
			// A writer replaced this one file while we read it. Do not advance the
			// cache stamp; the next bounded pass will read the settled version.
			continue
		}
		projection, ok := operationReadModelAttemptFromState(state)
		if !ok || projection.SourceID != identity.SourceID || projection.OperationID != identity.OperationID {
			return nil, ErrOperationAttemptUnavailable
		}
		stampUpdates[path] = stamp
		snapshots = append(snapshots, projection)
	}
	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].SourceID != snapshots[j].SourceID {
			return snapshots[i].SourceID < snapshots[j].SourceID
		}
		return snapshots[i].OperationID < snapshots[j].OperationID
	})
	// Do not advance any stamp until every identity in this batch has passed
	// validation; otherwise a later corrupt file could discard earlier decoded
	// snapshots and make the next pass skip them permanently.
	for path, stamp := range stampUpdates {
		store.readStamps[path] = stamp
	}
	return snapshots, nil
}

func operationAttemptFileStampAt(path string) (operationAttemptFileStamp, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return operationAttemptFileStamp{}, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxOperationAttemptStateBytes {
		return operationAttemptFileStamp{}, false, ErrOperationAttemptUnavailable
	}
	stamp := operationAttemptFileStamp{exists: true, modifiedNS: info.ModTime().UnixNano(), size: info.Size()}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		stamp.inode = stat.Ino
	}
	return stamp, true, nil
}

func (store *OperationAttemptStore) BeginAttempt(binding OperationAttemptBinding, attemptID string, now time.Time, lease time.Duration) (OperationAttemptClaim, error) {
	if store == nil || !validOperationAttemptBinding(binding) || !quotaAttemptIDPattern.MatchString(attemptID) || now.IsZero() || lease < time.Second || lease > maxOperationAttemptLease {
		return OperationAttemptClaim{}, ErrOperationAttemptUnavailable
	}
	now = now.UTC()
	var claim OperationAttemptClaim
	var resultErr error
	if err := store.withStoreLock(func() error {
		state, found, err := store.readState(binding.SourceID, binding.OperationID)
		if err != nil {
			return err
		}
		if !found {
			state = operationAttemptState{SchemaVersion: OperationAttemptStoreSchemaVersion, SourceID: binding.SourceID, OperationID: binding.OperationID}
		}
		if len(state.Attempts) > 0 {
			latest := &state.Attempts[len(state.Attempts)-1]
			if latest.State == "claimed" {
				if now.Before(latest.LeaseExpiresAt) {
					return ErrOperationAttemptHeld
				}
				latest.State = "unknown"
				latest.FinishedAt = now
				state.Generation++
				if err := store.writeState(state); err != nil {
					return err
				}
				resultErr = ErrOperationAttemptAmbiguous
				return nil
			}
			period := latest.Binding.ObservationPeriod
			if binding.ObservationPeriod > period {
				period = binding.ObservationPeriod
			}
			dueAt := latest.StartedAt.Add(period)
			if now.Before(dueAt) {
				return ErrOperationAttemptNotDue
			}
		}
		if len(state.Attempts) >= maxOperationAttemptHistory {
			oldest := state.Attempts[0]
			if oldest.State == "unknown" || oldest.State == "observed" && oldest.DeliveryState != "readback_verified" {
				return ErrOperationAttemptCapacity
			}
			state.Attempts = append([]OperationStoredAttempt(nil), state.Attempts[len(state.Attempts)-maxOperationAttemptHistory+1:]...)
		}
		bindingSHA := operationAttemptPlanBindingSHA256(binding)
		if state.CurrentPlanSHA256 != bindingSHA {
			state.CurrentPlanSHA256 = bindingSHA
			state.CurrentPlanEverRequestStarted = false
		}
		state.Generation++
		stored := OperationStoredAttempt{Binding: binding, AttemptID: attemptID, Generation: state.Generation, StartedAt: now, LeaseExpiresAt: now.Add(lease), State: "claimed", DeliveryState: "not_ready"}
		state.Attempts = append(state.Attempts, stored)
		if err := store.writeState(state); err != nil {
			return err
		}
		claim = OperationAttemptClaim{Binding: binding, AttemptID: attemptID, Generation: stored.Generation, StartedAt: stored.StartedAt, ExpiresAt: stored.LeaseExpiresAt}
		return nil
	}); err != nil {
		return OperationAttemptClaim{}, err
	}
	if resultErr != nil {
		return OperationAttemptClaim{}, resultErr
	}
	return claim, nil
}

func (store *OperationAttemptStore) CompleteAttempt(claim OperationAttemptClaim, result OperationObservationResult, now time.Time) error {
	if store == nil || !validOperationAttemptClaim(claim) || !validOperationObservationResult(result) || now.IsZero() {
		return ErrOperationAttemptUnavailable
	}
	now = now.UTC()
	return store.transitionClaim(claim, now, func(state *operationAttemptState, attempt *OperationStoredAttempt) error {
		if !now.Before(attempt.LeaseExpiresAt) {
			attempt.State = "unknown"
			attempt.FinishedAt = now
			return ErrOperationAttemptFenced
		}
		if result.ObservedAt.Before(attempt.StartedAt) || result.ObservedAt.After(now) {
			attempt.State = "failed"
			attempt.FinishedAt = now
			return ErrOperationAttemptUnavailable
		}
		copy := result
		copy.ObservedAt = copy.ObservedAt.UTC()
		copy.ReceivedAt = now
		attempt.State = "observed"
		attempt.ReceiptValidated = true
		attempt.ReceiptSHA256 = copy.ReceiptSHA
		started := true
		attempt.RequestStarted = &started
		attempt.FinishedAt = now
		attempt.Result = &copy
		attempt.DeliveryState = "not_ready"
		state.EverRequestStarted = true
		if state.CurrentPlanSHA256 == operationAttemptPlanBindingSHA256(attempt.Binding) {
			state.CurrentPlanEverRequestStarted = true
		}
		return nil
	})
}

// RecordRequestStartedWithoutObservation records a validated child receipt
// proving one provider request started when no provider response was observed.
func (store *OperationAttemptStore) RecordRequestStartedWithoutObservation(claim OperationAttemptClaim, receiptSHA string, now time.Time) error {
	if store == nil || !validOperationAttemptClaim(claim) || !sha256Pattern.MatchString(receiptSHA) || now.IsZero() {
		return ErrOperationAttemptUnavailable
	}
	now = now.UTC()
	return store.transitionClaim(claim, now, func(state *operationAttemptState, attempt *OperationStoredAttempt) error {
		if !now.Before(attempt.LeaseExpiresAt) {
			attempt.State = "unknown"
			attempt.FinishedAt = now
			return ErrOperationAttemptFenced
		}
		started := true
		attempt.State = "request_started"
		attempt.ReceiptValidated = true
		attempt.RequestStarted = &started
		attempt.FinishedAt = now
		attempt.ReceiptSHA256 = receiptSHA
		state.EverRequestStarted = true
		if state.CurrentPlanSHA256 == operationAttemptPlanBindingSHA256(attempt.Binding) {
			state.CurrentPlanEverRequestStarted = true
		}
		return nil
	})
}

// RecordBlockedAttempt persists a validated receipt proving no request was
// dispatched. blockReason is a safe enum, never provider-controlled text.
func (store *OperationAttemptStore) RecordBlockedAttempt(claim OperationAttemptClaim, receiptSHA, blockReason string, now time.Time) error {
	if store == nil || !validOperationAttemptClaim(claim) || !sha256Pattern.MatchString(receiptSHA) || !validOperationAttemptBlockReason(blockReason) || now.IsZero() {
		return ErrOperationAttemptUnavailable
	}
	now = now.UTC()
	return store.transitionClaim(claim, now, func(_ *operationAttemptState, attempt *OperationStoredAttempt) error {
		if !now.Before(attempt.LeaseExpiresAt) {
			attempt.State = "unknown"
			attempt.FinishedAt = now
			return ErrOperationAttemptFenced
		}
		started := false
		attempt.State = "failed"
		attempt.ReceiptValidated = true
		attempt.RequestStarted = &started
		attempt.ReceiptSHA256 = receiptSHA
		attempt.BlockReason = blockReason
		attempt.FinishedAt = now
		return nil
	})
}

func (store *OperationAttemptStore) FailAttempt(claim OperationAttemptClaim, now time.Time) error {
	if store == nil || !validOperationAttemptClaim(claim) || now.IsZero() {
		return ErrOperationAttemptUnavailable
	}
	now = now.UTC()
	return store.transitionClaim(claim, now, func(_ *operationAttemptState, attempt *OperationStoredAttempt) error {
		attempt.State = "unknown"
		attempt.FinishedAt = now
		return nil
	})
}

func validOperationAttemptBlockReason(value string) bool {
	switch value {
	case "credential_unavailable", "credential_mismatch", "plan_not_admitted", "unsupported_contract", "local_deadline", "child_validation_failed":
		return true
	default:
		return false
	}
}

// ClaimDelivery durably marks the summary pending before the HTTP request.
// Reclaiming an expired pending delivery may create duplicate Gatus history;
// it never repeats the provider operation.
func (store *OperationAttemptStore) ClaimDelivery(sourceID, operationID, attemptID string, generation uint64, now time.Time, lease time.Duration) (OperationDeliveryClaim, error) {
	if store == nil || !operationSourceIDPattern.MatchString(sourceID) || operationID == "" || len(operationID) > 256 || !quotaAttemptIDPattern.MatchString(attemptID) || generation == 0 || now.IsZero() || lease < time.Second || lease > maxOperationAttemptLease {
		return OperationDeliveryClaim{}, ErrOperationAttemptUnavailable
	}
	now = now.UTC()
	var claim OperationDeliveryClaim
	err := store.withStoreLock(func() error {
		state, found, err := store.readState(sourceID, operationID)
		if err != nil || !found {
			return ErrOperationAttemptUnavailable
		}
		attempt := findOperationAttempt(&state, attemptID, generation)
		if attempt == nil || attempt.State != "observed" || attempt.Result == nil || now.Before(attempt.Result.ReceivedAt) || attempt.DeliveryState == "acknowledged" || attempt.DeliveryState == "readback_verified" {
			return ErrOperationAttemptFenced
		}
		if attempt.DeliveryState == "pending" && now.Before(attempt.DeliveryStartedAt.Add(lease)) {
			return ErrOperationAttemptHeld
		}
		attempt.DeliveryGeneration++
		attempt.DeliveryAttempts++
		attempt.DeliveryState = "pending"
		attempt.DeliveryStartedAt = now
		state.Generation++
		if err := store.writeState(state); err != nil {
			return err
		}
		claim = OperationDeliveryClaim{Binding: attempt.Binding, AttemptID: attempt.AttemptID, AttemptGeneration: attempt.Generation, DeliveryGeneration: attempt.DeliveryGeneration, AttemptCount: attempt.DeliveryAttempts, Result: *attempt.Result}
		return nil
	})
	return claim, err
}

func (store *OperationAttemptStore) AcknowledgeDelivery(claim OperationDeliveryClaim, responseAt time.Time) error {
	if store == nil || !validOperationDeliveryClaim(claim) || responseAt.IsZero() {
		return ErrOperationAttemptUnavailable
	}
	responseAt = responseAt.UTC()
	return store.withStoreLock(func() error {
		state, found, err := store.readState(claim.Binding.SourceID, claim.Binding.OperationID)
		if err != nil || !found {
			return ErrOperationAttemptUnavailable
		}
		attempt := findOperationAttempt(&state, claim.AttemptID, claim.AttemptGeneration)
		if attempt == nil || attempt.DeliveryState != "pending" || attempt.DeliveryGeneration != claim.DeliveryGeneration || attempt.Result == nil || responseAt.Before(attempt.DeliveryStartedAt) {
			return ErrOperationAttemptFenced
		}
		attempt.DeliveryState = "acknowledged"
		attempt.DeliveryAckAt = responseAt
		state.Generation++
		return store.writeState(state)
	})
}

// RecordGatusReadback binds a per-key readback timestamp to a previously
// accepted summary. It does not change the original provider observation time.
func (store *OperationAttemptStore) RecordGatusReadback(sourceID, operationID, attemptID string, generation uint64, receivedAt time.Time, resultState string) error {
	if store == nil || !operationSourceIDPattern.MatchString(sourceID) || operationID == "" || !quotaAttemptIDPattern.MatchString(attemptID) || generation == 0 || receivedAt.IsZero() || !validGatusResultState(resultState) {
		return ErrOperationAttemptUnavailable
	}
	receivedAt = receivedAt.UTC()
	return store.withStoreLock(func() error {
		state, found, err := store.readState(sourceID, operationID)
		if err != nil || !found {
			return ErrOperationAttemptUnavailable
		}
		attempt := findOperationAttempt(&state, attemptID, generation)
		if attempt == nil || attempt.DeliveryState != "acknowledged" || attempt.Result == nil || receivedAt.Before(attempt.DeliveryAckAt) {
			return ErrOperationAttemptFenced
		}
		attempt.GatusReceivedAt = receivedAt
		attempt.GatusResultState = resultState
		attempt.DeliveryState = "readback_verified"
		state.Generation++
		return store.writeState(state)
	})
}

func (store *OperationAttemptStore) Latest(sourceID, operationID string) (OperationStoredAttempt, bool, error) {
	if store == nil || !operationSourceIDPattern.MatchString(sourceID) || operationID == "" || len(operationID) > 256 {
		return OperationStoredAttempt{}, false, ErrOperationAttemptUnavailable
	}
	var latest OperationStoredAttempt
	var foundAttempt bool
	err := store.withStoreLock(func() error {
		state, found, err := store.readState(sourceID, operationID)
		if err != nil || !found {
			return err
		}
		latest = state.Attempts[len(state.Attempts)-1]
		foundAttempt = true
		return nil
	})
	return latest, foundAttempt, err
}

// SnapshotReadModelAttempts returns one safe latest-state projection per
// operation identity. It performs a bounded directory scan intended for
// startup/background cache refresh, never for an HTTP page request.
func (store *OperationAttemptStore) SnapshotReadModelAttempts() ([]OperationReadModelAttempt, error) {
	if store == nil {
		return nil, ErrOperationAttemptUnavailable
	}
	var snapshots []OperationReadModelAttempt
	err := store.withStoreLock(func() error {
		entries, err := os.ReadDir(store.root)
		if err != nil || len(entries) > maxOperationAttemptStoreOperations+1 {
			return ErrOperationAttemptUnavailable
		}
		snapshots = make([]OperationReadModelAttempt, 0, len(entries))
		seen := make(map[string]struct{}, len(entries))
		for _, entry := range entries {
			name := entry.Name()
			if name == ".operation-attempt.lock" || strings.HasPrefix(name, ".operation-attempt-") {
				continue
			}
			if !strings.HasSuffix(name, ".json") {
				return ErrOperationAttemptUnavailable
			}
			path := filepath.Join(store.root, name)
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxOperationAttemptStateBytes {
				return ErrOperationAttemptUnavailable
			}
			file, err := os.Open(path)
			if err != nil {
				return ErrOperationAttemptUnavailable
			}
			raw, readErr := io.ReadAll(io.LimitReader(file, maxOperationAttemptStateBytes+1))
			closeErr := file.Close()
			if readErr != nil || closeErr != nil || len(raw) > maxOperationAttemptStateBytes {
				return ErrOperationAttemptUnavailable
			}
			var state operationAttemptState
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&state) != nil || ensureEOF(decoder) != nil || !validOperationAttemptState(state, state.SourceID, state.OperationID) || filepath.Base(store.statePath(state.SourceID, state.OperationID)) != name {
				return ErrOperationAttemptUnavailable
			}
			key := operationReadModelIdentityKey(state.SourceID, state.OperationID)
			if _, duplicate := seen[key]; duplicate {
				return ErrOperationAttemptUnavailable
			}
			seen[key] = struct{}{}
			projection, ok := operationReadModelAttemptFromState(state)
			if !ok {
				return ErrOperationAttemptUnavailable
			}
			snapshots = append(snapshots, projection)
		}
		return nil
	})
	if err != nil {
		return nil, ErrOperationAttemptUnavailable
	}
	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].SourceID != snapshots[j].SourceID {
			return snapshots[i].SourceID < snapshots[j].SourceID
		}
		return snapshots[i].OperationID < snapshots[j].OperationID
	})
	return snapshots, nil
}

func operationReadModelAttemptFromState(state operationAttemptState) (OperationReadModelAttempt, bool) {
	if len(state.Attempts) == 0 {
		return OperationReadModelAttempt{}, false
	}
	latest := state.Attempts[len(state.Attempts)-1]
	projection := OperationReadModelAttempt{
		SourceID: state.SourceID, OperationID: state.OperationID, AttemptState: latest.State, ObservationAttemptState: "none",
		LatestPlanBinding: latest.Binding,
		ReceiptValidated:  latest.ReceiptValidated, RequestStarted: cloneBool(latest.RequestStarted),
		EverRequestStarted: state.CurrentPlanSHA256 == operationAttemptPlanBindingSHA256(latest.Binding) && state.CurrentPlanEverRequestStarted,
		GatusDeliveryState: "not_ready", UpdatedAt: latest.StartedAt,
	}
	projection.UpdatedAt = laterOperationAttemptTime(projection.UpdatedAt, latest.FinishedAt)
	for index := len(state.Attempts) - 1; index >= 0; index-- {
		attempt := state.Attempts[index]
		if attempt.Result == nil {
			continue
		}
		observationBinding := attempt.Binding
		projection.ObservationPlanBinding = &observationBinding
		projection.ResultState = attempt.Result.State
		projection.ResultCategory = attempt.Result.Category
		projection.ObservationAttemptState = "observed"
		projection.ProviderObservedAt = attempt.Result.ObservedAt
		projection.HealthReceivedAt = attempt.Result.ReceivedAt
		projection.UpdatedAt = laterOperationAttemptTime(projection.UpdatedAt,
			attempt.StartedAt, attempt.FinishedAt, attempt.Result.ObservedAt, attempt.Result.ReceivedAt,
			attempt.DeliveryStartedAt, attempt.DeliveryAckAt, attempt.GatusReceivedAt)
		switch attempt.DeliveryState {
		case "not_ready", "pending":
			projection.GatusDeliveryState = "pending"
		case "acknowledged":
			projection.GatusDeliveryState = "acknowledged"
			projection.GatusAcknowledgedAt = attempt.DeliveryAckAt
		case "readback_verified":
			projection.GatusDeliveryState = "readback_verified"
			projection.GatusAcknowledgedAt = attempt.DeliveryAckAt
			projection.GatusReadbackAt = attempt.GatusReceivedAt
			projection.GatusObservedState = attempt.GatusResultState
		}
		break
	}
	return projection, validOperationReadModelAttempt(projection)
}

func operationAttemptPlanBindingSHA256(binding OperationAttemptBinding) string {
	identity := struct {
		SchemaVersion      string        `json:"schema_version"`
		SourceID           string        `json:"source_id"`
		OperationID        string        `json:"operation_id"`
		RegistryRevision   string        `json:"registry_revision"`
		ReleaseManifestSHA string        `json:"release_manifest_sha256"`
		IndexSHA           string        `json:"index_sha256"`
		ShardSHA           string        `json:"shard_sha256"`
		ObservationPeriod  time.Duration `json:"observation_period_ns"`
	}{"datapan.health-operation-plan-binding.v1", binding.SourceID, binding.OperationID, binding.RegistryRevision, binding.ReleaseManifestSHA, binding.IndexSHA, binding.ShardSHA, binding.ObservationPeriod}
	raw, _ := json.Marshal(identity)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func laterOperationAttemptTime(current time.Time, candidates ...time.Time) time.Time {
	for _, candidate := range candidates {
		if candidate.After(current) {
			current = candidate
		}
	}
	return current
}

// PendingDeliveries returns the bounded per-operation outbox entries. It may
// include receipts from older scheduled observations when Gatus is down; a
// caller retries these independently from any new provider attempt.
func (store *OperationAttemptStore) PendingDeliveries(sourceID, operationID string) ([]OperationStoredAttempt, error) {
	if store == nil || !operationSourceIDPattern.MatchString(sourceID) || operationID == "" || len(operationID) > 256 {
		return nil, ErrOperationAttemptUnavailable
	}
	var pending []OperationStoredAttempt
	err := store.withStoreLock(func() error {
		state, found, err := store.readState(sourceID, operationID)
		if err != nil || !found {
			return err
		}
		for _, attempt := range state.Attempts {
			if attempt.State == "observed" && attempt.DeliveryState == "not_ready" || attempt.State == "observed" && attempt.DeliveryState == "pending" {
				pending = append(pending, attempt)
			}
		}
		return nil
	})
	return pending, err
}

func (store *OperationAttemptStore) transitionClaim(claim OperationAttemptClaim, now time.Time, apply func(*operationAttemptState, *OperationStoredAttempt) error) error {
	return store.withStoreLock(func() error {
		state, found, err := store.readState(claim.Binding.SourceID, claim.Binding.OperationID)
		if err != nil || !found {
			return ErrOperationAttemptUnavailable
		}
		attempt := findOperationAttempt(&state, claim.AttemptID, claim.Generation)
		if attempt == nil || attempt.State != "claimed" || attempt.Binding != claim.Binding || !attempt.StartedAt.Equal(claim.StartedAt) || !attempt.LeaseExpiresAt.Equal(claim.ExpiresAt) {
			return ErrOperationAttemptFenced
		}
		applyErr := apply(&state, attempt)
		state.Generation++
		if err := store.writeState(state); err != nil {
			return err
		}
		return applyErr
	})
}

func (store *OperationAttemptStore) readState(sourceID, operationID string) (operationAttemptState, bool, error) {
	path := store.statePath(sourceID, operationID)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return operationAttemptState{}, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxOperationAttemptStateBytes {
		return operationAttemptState{}, false, ErrOperationAttemptUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return operationAttemptState{}, false, ErrOperationAttemptUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxOperationAttemptStateBytes+1))
	if err != nil || len(raw) > maxOperationAttemptStateBytes {
		return operationAttemptState{}, false, ErrOperationAttemptUnavailable
	}
	var state operationAttemptState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || ensureEOF(decoder) != nil || !validOperationAttemptState(state, sourceID, operationID) {
		return operationAttemptState{}, false, ErrOperationAttemptUnavailable
	}
	return state, true, nil
}

func (store *OperationAttemptStore) writeState(state operationAttemptState) error {
	if !validOperationAttemptState(state, state.SourceID, state.OperationID) {
		return ErrOperationAttemptUnavailable
	}
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > maxOperationAttemptStateBytes {
		return ErrOperationAttemptUnavailable
	}
	path := store.statePath(state.SourceID, state.OperationID)
	tmp, err := os.CreateTemp(store.root, ".operation-attempt-")
	if err != nil {
		return ErrOperationAttemptUnavailable
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if tmp.Chmod(0o600) != nil {
		_ = tmp.Close()
		return ErrOperationAttemptUnavailable
	}
	if n, err := tmp.Write(raw); err != nil || n != len(raw) || tmp.Sync() != nil || tmp.Close() != nil || os.Rename(tmpPath, path) != nil {
		return ErrOperationAttemptUnavailable
	}
	directory, err := os.Open(store.root)
	if err != nil {
		return ErrOperationAttemptUnavailable
	}
	defer directory.Close()
	if directory.Sync() != nil {
		return ErrOperationAttemptUnavailable
	}
	return nil
}

func (store *OperationAttemptStore) withStoreLock(apply func() error) error {
	lock, err := os.OpenFile(filepath.Join(store.root, ".operation-attempt.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return ErrOperationAttemptUnavailable
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return ErrOperationAttemptUnavailable
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return apply()
}

func (store *OperationAttemptStore) statePath(sourceID, operationID string) string {
	sum := sha256.Sum256([]byte(sourceID + "\x00" + operationID))
	return filepath.Join(store.root, hex.EncodeToString(sum[:])+".json")
}

func validOperationAttemptBinding(binding OperationAttemptBinding) bool {
	return operationSourceIDPattern.MatchString(binding.SourceID) && binding.OperationID != "" && len(binding.OperationID) <= 256 && commitPattern.MatchString(binding.RegistryRevision) && sha256Pattern.MatchString(binding.ReleaseManifestSHA) && sha256Pattern.MatchString(binding.IndexSHA) && sha256Pattern.MatchString(binding.ShardSHA) && operationGatusKeyPattern.MatchString(binding.GatusKey) && binding.ObservationPeriod >= time.Second && binding.ObservationPeriod <= 365*24*time.Hour
}

func validOperationAttemptClaim(claim OperationAttemptClaim) bool {
	return validOperationAttemptBinding(claim.Binding) && quotaAttemptIDPattern.MatchString(claim.AttemptID) && claim.Generation > 0 && !claim.StartedAt.IsZero() && !claim.ExpiresAt.IsZero() && claim.ExpiresAt.After(claim.StartedAt) && claim.ExpiresAt.Sub(claim.StartedAt) <= maxOperationAttemptLease
}

func validOperationDeliveryClaim(claim OperationDeliveryClaim) bool {
	return validOperationAttemptBinding(claim.Binding) && quotaAttemptIDPattern.MatchString(claim.AttemptID) && claim.AttemptGeneration > 0 && claim.DeliveryGeneration > 0 && claim.AttemptCount > 0 && validOperationObservationResult(claim.Result)
}

func validOperationObservationResult(result OperationObservationResult) bool {
	validState := result.State == "healthy" || result.State == "unhealthy" || result.State == "indeterminate"
	validCategory := result.Category == "healthy" || result.Category == "transport_failure" || result.Category == "timeout" || result.Category == "rate_limited" || result.Category == "credential_missing" || result.Category == "credential_rejected" || result.Category == "parameter_blocked" || result.Category == "provider_failure" || result.Category == "semantic_failure" || result.Category == "schema_drift" || result.Category == "unsupported" || result.Category == "observer_failure" || result.Category == "indeterminate"
	if !validOperationReadModelResultPair(result.State, result.Category) {
		return false
	}
	return validState && validCategory && !result.ObservedAt.IsZero() && (result.ReceivedAt.IsZero() || !result.ReceivedAt.Before(result.ObservedAt)) && sha256Pattern.MatchString(result.ReceiptSHA) && result.LatencyMS >= 0 && result.LatencyMS <= int64((365*24*time.Hour)/time.Millisecond)
}

func validOperationAttemptState(state operationAttemptState, sourceID, operationID string) bool {
	if state.SchemaVersion != OperationAttemptStoreSchemaVersion || state.SourceID != sourceID || state.OperationID != operationID || !operationSourceIDPattern.MatchString(sourceID) || operationID == "" || len(operationID) > 256 || state.Generation == 0 || len(state.Attempts) == 0 || len(state.Attempts) > maxOperationAttemptHistory {
		return false
	}
	latest := state.Attempts[len(state.Attempts)-1]
	if !sha256Pattern.MatchString(state.CurrentPlanSHA256) || state.CurrentPlanSHA256 != operationAttemptPlanBindingSHA256(latest.Binding) || state.CurrentPlanEverRequestStarted && !state.EverRequestStarted {
		return false
	}
	if latest.RequestStarted != nil && *latest.RequestStarted && !state.CurrentPlanEverRequestStarted {
		return false
	}
	var previousGeneration uint64
	for _, attempt := range state.Attempts {
		if !validOperationAttemptBinding(attempt.Binding) || attempt.Binding.SourceID != sourceID || attempt.Binding.OperationID != operationID || !quotaAttemptIDPattern.MatchString(attempt.AttemptID) || attempt.Generation <= previousGeneration || attempt.Generation > state.Generation || attempt.StartedAt.IsZero() || attempt.LeaseExpiresAt.Before(attempt.StartedAt) || attempt.LeaseExpiresAt.Sub(attempt.StartedAt) > maxOperationAttemptLease || !validOperationAttemptStateName(attempt.State) || !validOperationDeliveryState(attempt.DeliveryState) || attempt.DeliveryAttempts < 0 || attempt.DeliveryAttempts > 1_000_000 {
			return false
		}
		previousGeneration = attempt.Generation
		if attempt.State == "claimed" {
			if !attempt.FinishedAt.IsZero() || attempt.DeliveryState != "not_ready" || attempt.ReceiptValidated || attempt.RequestStarted != nil || attempt.Result != nil || attempt.ReceiptSHA256 != "" || attempt.BlockReason != "" {
				return false
			}
		} else if attempt.FinishedAt.IsZero() || attempt.FinishedAt.Before(attempt.StartedAt) {
			return false
		}
		switch attempt.State {
		case "observed":
			if attempt.Result == nil || !validOperationObservationResult(*attempt.Result) || attempt.Result.ReceivedAt.IsZero() || attempt.FinishedAt.Before(attempt.Result.ReceivedAt) || !attempt.ReceiptValidated || attempt.RequestStarted == nil || !*attempt.RequestStarted || attempt.ReceiptSHA256 != attempt.Result.ReceiptSHA || attempt.BlockReason != "" {
				return false
			}
		case "request_started":
			if attempt.Result != nil || !attempt.ReceiptValidated || attempt.RequestStarted == nil || !*attempt.RequestStarted || !sha256Pattern.MatchString(attempt.ReceiptSHA256) || attempt.BlockReason != "" {
				return false
			}
		case "failed":
			if attempt.Result != nil || !attempt.ReceiptValidated || attempt.RequestStarted == nil || *attempt.RequestStarted || !sha256Pattern.MatchString(attempt.ReceiptSHA256) || !validOperationAttemptBlockReason(attempt.BlockReason) {
				return false
			}
		case "unknown":
			if attempt.Result != nil || attempt.ReceiptValidated || attempt.RequestStarted != nil || attempt.ReceiptSHA256 != "" || attempt.BlockReason != "" || attempt.DeliveryState != "not_ready" {
				return false
			}
		}
		if attempt.RequestStarted != nil && *attempt.RequestStarted && !state.EverRequestStarted {
			return false
		}
		if (attempt.DeliveryState == "pending" || attempt.DeliveryState == "acknowledged" || attempt.DeliveryState == "readback_verified") && attempt.State != "observed" {
			return false
		}
		if attempt.DeliveryState == "pending" && (attempt.DeliveryAttempts < 1 || attempt.DeliveryStartedAt.IsZero()) {
			return false
		}
		if attempt.DeliveryState == "pending" && attempt.DeliveryStartedAt.Before(attempt.Result.ReceivedAt) {
			return false
		}
		if (attempt.DeliveryState == "acknowledged" || attempt.DeliveryState == "readback_verified") && (attempt.DeliveryAckAt.IsZero() || attempt.DeliveryAttempts < 1 || attempt.DeliveryAckAt.Before(attempt.DeliveryStartedAt) || attempt.DeliveryAckAt.Before(attempt.Result.ReceivedAt)) {
			return false
		}
		if attempt.DeliveryState == "readback_verified" && (attempt.GatusReceivedAt.IsZero() || !validGatusResultState(attempt.GatusResultState)) {
			return false
		}
		if attempt.DeliveryState != "readback_verified" && (!attempt.GatusReceivedAt.IsZero() || attempt.GatusResultState != "") {
			return false
		}
	}
	return latest.Generation <= state.Generation
}

func validOperationAttemptStateName(value string) bool {
	return value == "claimed" || value == "request_started" || value == "observed" || value == "unknown" || value == "failed"
}

func validOperationDeliveryState(value string) bool {
	return value == "not_ready" || value == "pending" || value == "acknowledged" || value == "readback_verified"
}

func findOperationAttempt(state *operationAttemptState, attemptID string, generation uint64) *OperationStoredAttempt {
	for index := range state.Attempts {
		attempt := &state.Attempts[index]
		if attempt.AttemptID == attemptID && attempt.Generation == generation {
			return attempt
		}
	}
	return nil
}

func latestPlanMatchesAttempts(attempts []OperationStoredAttempt, binding OperationAttemptBinding) bool {
	if len(attempts) == 0 {
		return false
	}
	last := attempts[len(attempts)-1].Binding
	return last.RegistryRevision == binding.RegistryRevision && last.IndexSHA == binding.IndexSHA && last.ShardSHA == binding.ShardSHA
}

func latestAttemptDeliveryPending(attempts []OperationStoredAttempt) bool {
	return len(attempts) > 0 && attempts[len(attempts)-1].DeliveryState == "pending"
}
