package health

import (
	"bytes"
	"context"
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
	"syscall"
	"time"
)

const (
	OperationQuotaStateSchemaVersion = "datapan.health-operation-quota-state.v1"
	maxOperationQuotaStateBytes      = 64 * 1024
	maxOperationQuotaConcurrent      = 256
	maxOperationQuotaLease           = 10 * time.Minute
	maxOperationQuotaScopesPerCall   = 16
	maxOperationQuotaTransactionSize = 2 * 1024 * 1024
)

var (
	ErrOperationQuotaUnavailable = errors.New("operation quota is unavailable")
	ErrOperationQuotaExhausted   = errors.New("operation quota is exhausted")
	ErrOperationQuotaFenced      = errors.New("operation quota claim is fenced")
	ErrOperationQuotaTransition  = errors.New("operation quota policy transition is unsafe")
	quotaAttemptIDPattern        = regexp.MustCompile(`^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|[0-9a-f]{64})$`)
	quotaScopeKindPattern        = regexp.MustCompile(`^(?:global|provider|credential|api|organization)$`)
	quotaEvidencePointerPattern  = regexp.MustCompile(`^#(?:/.*)?$`)
)

// OperationQuotaPolicy is a runtime projection of limits supplied by a
// separately pinned Registry plan. ScopeSHA256 must bind the provider, API,
// and credential reference scope without exposing the credential reference.
// This type is deliberately not an operation-plan schema or a source of
// default limits.
type OperationQuotaPolicy struct {
	ScopeSHA256       string
	MaxConcurrent     int
	RequestsPerWindow int
	Window            time.Duration
	MinimumInterval   time.Duration
}

// OperationQuotaEvidenceRef is the bounded reference projection used by the
// Registry plan adapter. It carries no source document content or URL.
type OperationQuotaEvidenceRef struct {
	ArtifactPath string `json:"artifact_path"`
	SHA256       string `json:"sha256"`
	JSONPointer  string `json:"json_pointer"`
	EvidenceKind string `json:"evidence_kind"`
}

// OperationQuotaClaim fences the right to hold one provider, shared
// credential, API, or global request slot. A call carries one claim for every
// applicable scope. The request budgets are charged durably before any claim
// is returned; callers must not refund them when an outcome is ambiguous.
type OperationQuotaClaim struct {
	ScopeSHA256 string    `json:"scope_sha256"`
	AttemptID   string    `json:"attempt_id"`
	Generation  uint64    `json:"generation"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type operationQuotaState struct {
	SchemaVersion string                         `json:"schema_version"`
	ScopeSHA256   string                         `json:"scope_sha256"`
	PolicySHA256  string                         `json:"policy_sha256"`
	WindowStarted time.Time                      `json:"window_started_at"`
	RequestsUsed  int                            `json:"requests_used"`
	LastClaimAt   time.Time                      `json:"last_claim_at,omitempty"`
	Generation    uint64                         `json:"generation"`
	UpdatedAt     time.Time                      `json:"updated_at"`
	Active        map[string]operationQuotaLease `json:"active"`
}

type operationQuotaLease struct {
	Generation uint64    `json:"generation"`
	ExpiresAt  time.Time `json:"expires_at"`
}

const operationQuotaTransactionSchemaVersion = "datapan.health-operation-quota-transaction.v1"

type operationQuotaTransaction struct {
	SchemaVersion string                `json:"schema_version"`
	Kind          string                `json:"kind"`
	AttemptID     string                `json:"attempt_id"`
	States        []operationQuotaState `json:"states"`
}

// OperationQuotaAuthority stores one tiny state file per opaque quota scope.
// A single short-held lock and recoverable write-ahead transaction reserve or
// release every applicable scope as one unit. Independent worker processes
// coordinate only when this directory is on a filesystem with working flock
// semantics; that does not establish a cross-host guarantee by itself.
type OperationQuotaAuthority struct {
	root string
}

// OperationQuotaPolicyFromEvidence maps one evidence-backed quota scope in a
// Registry operation-observation-plan entry into the Health runtime guard.
// The caller must first validate the pinned plan schema. This function also
// requires a complete request plan, runtime_binding.status="bound", and
// admission.status="admitted"; no one field implies the other two. Evidence
// refs are required so unbound/default limits cannot accidentally be run.
func OperationQuotaPolicyFromEvidence(
	requestPlanStatus, runtimeBindingStatus, admissionStatus string,
	scopeKind, scopeKey, declaredScopeSHA256 string,
	maxConcurrent, requestsPerWindow int,
	windowSeconds, minimumIntervalSeconds int64,
	evidenceRefs []OperationQuotaEvidenceRef,
) (OperationQuotaPolicy, error) {
	maximumWindowSeconds := int64((365 * 24 * time.Hour) / time.Second)
	if requestPlanStatus != "complete" || runtimeBindingStatus != "bound" || admissionStatus != "admitted" || !quotaScopeKindPattern.MatchString(scopeKind) || strings.TrimSpace(scopeKey) == "" || len(evidenceRefs) == 0 || windowSeconds < 1 || windowSeconds > maximumWindowSeconds || minimumIntervalSeconds < 0 || minimumIntervalSeconds > windowSeconds {
		return OperationQuotaPolicy{}, ErrOperationQuotaUnavailable
	}
	for _, reference := range evidenceRefs {
		if strings.TrimSpace(reference.ArtifactPath) == "" || !sha256Pattern.MatchString(reference.SHA256) || !quotaEvidencePointerPattern.MatchString(reference.JSONPointer) || !validOperationQuotaEvidenceKind(reference.EvidenceKind) {
			return OperationQuotaPolicy{}, ErrOperationQuotaUnavailable
		}
	}
	policy := OperationQuotaPolicy{
		ScopeSHA256:       OperationQuotaScopeDigest(scopeKind, scopeKey),
		MaxConcurrent:     maxConcurrent,
		RequestsPerWindow: requestsPerWindow,
		Window:            time.Duration(windowSeconds) * time.Second,
		MinimumInterval:   time.Duration(minimumIntervalSeconds) * time.Second,
	}
	if policy.ScopeSHA256 != declaredScopeSHA256 || !validOperationQuotaPolicy(policy) {
		return OperationQuotaPolicy{}, ErrOperationQuotaUnavailable
	}
	return policy, nil
}

func validOperationQuotaEvidenceKind(kind string) bool {
	switch kind {
	case "operation_document", "operation_manifest", "source_profile", "reviewed_policy", "runtime_binding", "synthetic_fixture":
		return true
	default:
		return false
	}
}

func OpenOperationQuotaAuthority(root string) (*OperationQuotaAuthority, error) {
	if strings.TrimSpace(root) == "" {
		return nil, errors.New("operation quota state directory is invalid")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, errors.New("operation quota state directory is invalid")
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, errors.New("operation quota state directory is unavailable")
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("operation quota state directory is unsafe")
	}
	if err := os.Chmod(abs, 0o700); err != nil {
		return nil, errors.New("operation quota state directory is unavailable")
	}
	return &OperationQuotaAuthority{root: abs}, nil
}

// OperationQuotaScopeDigest follows the Registry plan's canonical opaque
// bucket identity derivation. scopeKey is a non-secret stable key shared by
// every operation constrained by this bucket; it must never contain a
// credential value.
func OperationQuotaScopeDigest(scopeKind, scopeKey string) string {
	identity := "datapan.quota-scope.v1\x00" + scopeKind + "\x00" + scopeKey
	sum := sha256.Sum256([]byte(identity))
	return hex.EncodeToString(sum[:])
}

// Acquire is the single-scope convenience wrapper. Multi-level limits should
// use AcquireMany so every applicable scope is reserved atomically.
func (a *OperationQuotaAuthority) Acquire(policy OperationQuotaPolicy, attemptID string, now time.Time, lease time.Duration) (OperationQuotaClaim, error) {
	claims, err := a.AcquireMany([]OperationQuotaPolicy{policy}, attemptID, now, lease)
	if err != nil {
		return OperationQuotaClaim{}, err
	}
	return claims[0], nil
}

// AcquireMany atomically reserves all quota scopes that constrain one provider
// call, such as global, provider, shared credential, and API budgets. The
// recoverable write-ahead record ensures a crash during persistence completes
// the conservative reservation before another worker can observe the scopes.
func (a *OperationQuotaAuthority) AcquireMany(policies []OperationQuotaPolicy, attemptID string, now time.Time, lease time.Duration) ([]OperationQuotaClaim, error) {
	return a.AcquireManyContext(context.Background(), policies, attemptID, now, lease)
}

func (a *OperationQuotaAuthority) AcquireManyContext(ctx context.Context, policies []OperationQuotaPolicy, attemptID string, now time.Time, lease time.Duration) ([]OperationQuotaClaim, error) {
	if a == nil || ctx == nil || ctx.Err() != nil || !quotaAttemptIDPattern.MatchString(attemptID) || now.IsZero() || lease <= 0 || lease > maxOperationQuotaLease {
		return nil, ErrOperationQuotaUnavailable
	}
	policies, err := normalizeOperationQuotaPolicies(policies)
	if err != nil {
		return nil, err
	}
	now = now.UTC()
	claims := make([]OperationQuotaClaim, 0, len(policies))
	err = a.withAuthorityLockContext(ctx, func() error {
		if err := a.recoverOperationQuotaTransaction(); err != nil {
			return ErrOperationQuotaUnavailable
		}
		states := make([]operationQuotaState, 0, len(policies))
		claims = claims[:0]
		for _, policy := range policies {
			path := a.statePath(policy.ScopeSHA256)
			state, found, err := readOperationQuotaState(path)
			if err != nil {
				return ErrOperationQuotaUnavailable
			}
			candidate, claim, err := nextOperationQuotaClaim(state, found, policy, attemptID, now, lease)
			if err != nil {
				return err
			}
			states = append(states, candidate)
			claims = append(claims, claim)
		}
		transaction := operationQuotaTransaction{SchemaVersion: operationQuotaTransactionSchemaVersion, Kind: "reserve", AttemptID: attemptID, States: states}
		if err := a.writeOperationQuotaTransaction(transaction); err != nil {
			return ErrOperationQuotaUnavailable
		}
		if err := a.commitOperationQuotaTransaction(transaction); err != nil {
			return ErrOperationQuotaUnavailable
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

// Release frees concurrency in every scope atomically. It never refunds the
// request allowance. A stale or expired claim cannot release a newer worker's
// lease in any scope.
func (a *OperationQuotaAuthority) Release(claim OperationQuotaClaim, now time.Time) error {
	return a.ReleaseMany([]OperationQuotaClaim{claim}, now)
}

func (a *OperationQuotaAuthority) ReleaseMany(claims []OperationQuotaClaim, now time.Time) error {
	return a.ReleaseManyContext(context.Background(), claims, now)
}

func (a *OperationQuotaAuthority) ReleaseManyContext(ctx context.Context, claims []OperationQuotaClaim, now time.Time) error {
	if a == nil || ctx == nil || ctx.Err() != nil || len(claims) == 0 || len(claims) > maxOperationQuotaScopesPerCall || now.IsZero() {
		return ErrOperationQuotaUnavailable
	}
	now = now.UTC()
	claims = append([]OperationQuotaClaim(nil), claims...)
	sort.Slice(claims, func(i, j int) bool { return claims[i].ScopeSHA256 < claims[j].ScopeSHA256 })
	attemptID := claims[0].AttemptID
	for i, claim := range claims {
		if !sha256Pattern.MatchString(claim.ScopeSHA256) || !quotaAttemptIDPattern.MatchString(claim.AttemptID) || claim.AttemptID != attemptID || claim.Generation == 0 || claim.ExpiresAt.IsZero() || (i > 0 && claims[i-1].ScopeSHA256 == claim.ScopeSHA256) {
			return ErrOperationQuotaUnavailable
		}
	}
	return a.withAuthorityLockContext(ctx, func() error {
		if err := a.recoverOperationQuotaTransaction(); err != nil {
			return ErrOperationQuotaUnavailable
		}
		states := make([]operationQuotaState, 0, len(claims))
		for _, claim := range claims {
			path := a.statePath(claim.ScopeSHA256)
			state, found, err := readOperationQuotaState(path)
			if err != nil || !found || state.ScopeSHA256 != claim.ScopeSHA256 || now.Before(state.UpdatedAt) {
				return ErrOperationQuotaUnavailable
			}
			current, ok := state.Active[claim.AttemptID]
			if !ok || current.Generation != claim.Generation || !current.ExpiresAt.Equal(claim.ExpiresAt) || !now.Before(current.ExpiresAt) {
				return ErrOperationQuotaFenced
			}
			delete(state.Active, claim.AttemptID)
			state.Generation++
			state.UpdatedAt = now
			states = append(states, state)
		}
		transaction := operationQuotaTransaction{SchemaVersion: operationQuotaTransactionSchemaVersion, Kind: "release", AttemptID: attemptID, States: states}
		if err := a.writeOperationQuotaTransaction(transaction); err != nil {
			return ErrOperationQuotaUnavailable
		}
		if err := a.commitOperationQuotaTransaction(transaction); err != nil {
			return ErrOperationQuotaUnavailable
		}
		return nil
	})
}

func normalizeOperationQuotaPolicies(policies []OperationQuotaPolicy) ([]OperationQuotaPolicy, error) {
	if len(policies) == 0 || len(policies) > maxOperationQuotaScopesPerCall {
		return nil, ErrOperationQuotaUnavailable
	}
	byScope := make(map[string]OperationQuotaPolicy, len(policies))
	for _, policy := range policies {
		if !validOperationQuotaPolicy(policy) {
			return nil, ErrOperationQuotaUnavailable
		}
		if previous, exists := byScope[policy.ScopeSHA256]; exists {
			if operationQuotaPolicyDigest(previous) != operationQuotaPolicyDigest(policy) {
				return nil, ErrOperationQuotaTransition
			}
			continue
		}
		byScope[policy.ScopeSHA256] = policy
	}
	result := make([]OperationQuotaPolicy, 0, len(byScope))
	for _, policy := range byScope {
		result = append(result, policy)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ScopeSHA256 < result[j].ScopeSHA256 })
	return result, nil
}

func nextOperationQuotaClaim(state operationQuotaState, found bool, policy OperationQuotaPolicy, attemptID string, now time.Time, lease time.Duration) (operationQuotaState, OperationQuotaClaim, error) {
	windowStart := now.Truncate(policy.Window)
	policyHash := operationQuotaPolicyDigest(policy)
	if !found {
		state = operationQuotaState{SchemaVersion: OperationQuotaStateSchemaVersion, ScopeSHA256: policy.ScopeSHA256, PolicySHA256: policyHash, WindowStarted: windowStart, Active: map[string]operationQuotaLease{}}
	} else {
		if state.ScopeSHA256 != policy.ScopeSHA256 || now.Before(state.UpdatedAt) {
			return operationQuotaState{}, OperationQuotaClaim{}, ErrOperationQuotaUnavailable
		}
		if !state.WindowStarted.Equal(windowStart) {
			if len(operationQuotaActive(state.Active, now)) != 0 {
				return operationQuotaState{}, OperationQuotaClaim{}, ErrOperationQuotaTransition
			}
			state.WindowStarted = windowStart
			state.PolicySHA256 = policyHash
			state.RequestsUsed = 0
		} else if state.PolicySHA256 != policyHash {
			return operationQuotaState{}, OperationQuotaClaim{}, ErrOperationQuotaTransition
		}
	}
	state.Active = operationQuotaActive(state.Active, now)
	if _, duplicate := state.Active[attemptID]; duplicate {
		return operationQuotaState{}, OperationQuotaClaim{}, ErrOperationQuotaFenced
	}
	if len(state.Active) >= policy.MaxConcurrent || state.RequestsUsed >= policy.RequestsPerWindow {
		return operationQuotaState{}, OperationQuotaClaim{}, ErrOperationQuotaExhausted
	}
	if !state.LastClaimAt.IsZero() && now.Sub(state.LastClaimAt) < policy.MinimumInterval {
		return operationQuotaState{}, OperationQuotaClaim{}, ErrOperationQuotaExhausted
	}
	state.Generation++
	claim := OperationQuotaClaim{ScopeSHA256: policy.ScopeSHA256, AttemptID: attemptID, Generation: state.Generation, ExpiresAt: now.Add(lease)}
	state.Active[attemptID] = operationQuotaLease{Generation: claim.Generation, ExpiresAt: claim.ExpiresAt}
	state.RequestsUsed++
	state.LastClaimAt = now
	state.UpdatedAt = now
	return state, claim, nil
}

func validOperationQuotaPolicy(policy OperationQuotaPolicy) bool {
	return sha256Pattern.MatchString(policy.ScopeSHA256) && policy.MaxConcurrent >= 1 && policy.MaxConcurrent <= maxOperationQuotaConcurrent && policy.RequestsPerWindow >= 1 && policy.RequestsPerWindow <= 1_000_000 && policy.Window >= time.Second && policy.Window <= 365*24*time.Hour && policy.MinimumInterval >= 0 && policy.MinimumInterval <= policy.Window
}

func operationQuotaPolicyDigest(policy OperationQuotaPolicy) string {
	encoded, _ := json.Marshal(struct {
		ScopeSHA256       string `json:"scope_sha256"`
		MaxConcurrent     int    `json:"max_concurrent"`
		RequestsPerWindow int    `json:"requests_per_window"`
		WindowNS          int64  `json:"window_ns"`
		MinimumIntervalNS int64  `json:"minimum_interval_ns"`
	}{policy.ScopeSHA256, policy.MaxConcurrent, policy.RequestsPerWindow, int64(policy.Window), int64(policy.MinimumInterval)})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func operationQuotaActive(active map[string]operationQuotaLease, now time.Time) map[string]operationQuotaLease {
	kept := make(map[string]operationQuotaLease, len(active))
	for attemptID, lease := range active {
		if lease.ExpiresAt.After(now) {
			kept[attemptID] = lease
		}
	}
	return kept
}

func (a *OperationQuotaAuthority) statePath(scope string) string {
	return filepath.Join(a.root, scope+".json")
}

func (a *OperationQuotaAuthority) withAuthorityLock(apply func() error) error {
	return a.withAuthorityLockContext(context.Background(), apply)
}

func (a *OperationQuotaAuthority) withAuthorityLockContext(ctx context.Context, apply func() error) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrOperationQuotaUnavailable
	}
	lockPath := filepath.Join(a.root, ".authority.lock")
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return ErrOperationQuotaUnavailable
	}
	defer lock.Close()
	if err := flockExclusiveContext(ctx, lock); err != nil {
		return ErrOperationQuotaUnavailable
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return apply()
}

func (a *OperationQuotaAuthority) quotaTransactionPath() string {
	return filepath.Join(a.root, ".pending-transaction.json")
}

func (a *OperationQuotaAuthority) writeOperationQuotaTransaction(transaction operationQuotaTransaction) error {
	if !validOperationQuotaTransaction(transaction) {
		return ErrOperationQuotaUnavailable
	}
	raw, err := json.Marshal(transaction)
	if err != nil || len(raw) > maxOperationQuotaTransactionSize {
		return ErrOperationQuotaUnavailable
	}
	return writeOperationQuotaBytes(a.root, a.quotaTransactionPath(), raw)
}

func (a *OperationQuotaAuthority) readOperationQuotaTransaction() (operationQuotaTransaction, bool, error) {
	file, err := os.Open(a.quotaTransactionPath())
	if errors.Is(err, os.ErrNotExist) {
		return operationQuotaTransaction{}, false, nil
	}
	if err != nil {
		return operationQuotaTransaction{}, false, ErrOperationQuotaUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxOperationQuotaTransactionSize+1))
	if err != nil || len(raw) == 0 || len(raw) > maxOperationQuotaTransactionSize {
		return operationQuotaTransaction{}, false, ErrOperationQuotaUnavailable
	}
	var transaction operationQuotaTransaction
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&transaction) != nil || ensureEOF(decoder) != nil || !validOperationQuotaTransaction(transaction) {
		return operationQuotaTransaction{}, false, ErrOperationQuotaUnavailable
	}
	return transaction, true, nil
}

func validOperationQuotaTransaction(transaction operationQuotaTransaction) bool {
	if transaction.SchemaVersion != operationQuotaTransactionSchemaVersion || (transaction.Kind != "reserve" && transaction.Kind != "release") || !quotaAttemptIDPattern.MatchString(transaction.AttemptID) || len(transaction.States) == 0 || len(transaction.States) > maxOperationQuotaScopesPerCall {
		return false
	}
	seen := make(map[string]bool, len(transaction.States))
	for _, state := range transaction.States {
		if !validOperationQuotaState(state) || seen[state.ScopeSHA256] {
			return false
		}
		seen[state.ScopeSHA256] = true
		_, active := state.Active[transaction.AttemptID]
		if (transaction.Kind == "reserve" && !active) || (transaction.Kind == "release" && active) {
			return false
		}
	}
	return true
}

func (a *OperationQuotaAuthority) commitOperationQuotaTransaction(transaction operationQuotaTransaction) error {
	if !validOperationQuotaTransaction(transaction) {
		return ErrOperationQuotaUnavailable
	}
	for _, state := range transaction.States {
		if err := writeOperationQuotaState(a.statePath(state.ScopeSHA256), state); err != nil {
			return ErrOperationQuotaUnavailable
		}
	}
	if err := os.Remove(a.quotaTransactionPath()); err != nil {
		return ErrOperationQuotaUnavailable
	}
	return syncOperationQuotaDirectory(a.root)
}

func (a *OperationQuotaAuthority) recoverOperationQuotaTransaction() error {
	transaction, found, err := a.readOperationQuotaTransaction()
	if err != nil {
		return ErrOperationQuotaUnavailable
	}
	if !found {
		return nil
	}
	return a.commitOperationQuotaTransaction(transaction)
}

func writeOperationQuotaBytes(directory, path string, raw []byte) error {
	if filepath.Dir(path) != directory || len(raw) == 0 || len(raw) > maxOperationQuotaTransactionSize {
		return ErrOperationQuotaUnavailable
	}
	tmp, err := os.CreateTemp(directory, ".operation-quota-txn-")
	if err != nil {
		return ErrOperationQuotaUnavailable
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	defer tmp.Close()
	if err := tmp.Chmod(0o600); err != nil {
		return ErrOperationQuotaUnavailable
	}
	n, err := tmp.Write(raw)
	if err != nil || n != len(raw) || tmp.Sync() != nil || tmp.Close() != nil {
		return ErrOperationQuotaUnavailable
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return ErrOperationQuotaUnavailable
	}
	return syncOperationQuotaDirectory(directory)
}

func syncOperationQuotaDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return ErrOperationQuotaUnavailable
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrOperationQuotaUnavailable
	}
	return nil
}

func readOperationQuotaState(path string) (operationQuotaState, bool, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return operationQuotaState{}, false, nil
	}
	if err != nil {
		return operationQuotaState{}, false, ErrOperationQuotaUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxOperationQuotaStateBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxOperationQuotaStateBytes {
		return operationQuotaState{}, false, ErrOperationQuotaUnavailable
	}
	var state operationQuotaState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || ensureEOF(decoder) != nil || !validOperationQuotaState(state) {
		return operationQuotaState{}, false, ErrOperationQuotaUnavailable
	}
	return state, true, nil
}

func validOperationQuotaState(state operationQuotaState) bool {
	if state.SchemaVersion != OperationQuotaStateSchemaVersion || !sha256Pattern.MatchString(state.ScopeSHA256) || !sha256Pattern.MatchString(state.PolicySHA256) || state.WindowStarted.IsZero() || state.RequestsUsed < 0 || state.RequestsUsed > 1_000_000 || state.Generation == 0 || state.UpdatedAt.IsZero() || state.Active == nil || len(state.Active) > maxOperationQuotaConcurrent {
		return false
	}
	for attemptID, lease := range state.Active {
		if !quotaAttemptIDPattern.MatchString(attemptID) || lease.Generation == 0 || lease.Generation > state.Generation || lease.ExpiresAt.IsZero() {
			return false
		}
	}
	return true
}

func writeOperationQuotaState(path string, state operationQuotaState) error {
	if !validOperationQuotaState(state) {
		return ErrOperationQuotaUnavailable
	}
	raw, err := json.Marshal(state)
	if err != nil || len(raw) > maxOperationQuotaStateBytes {
		return ErrOperationQuotaUnavailable
	}
	directory := filepath.Dir(path)
	tmp, err := os.CreateTemp(directory, ".operation-quota-")
	if err != nil {
		return ErrOperationQuotaUnavailable
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	defer tmp.Close()
	if err := tmp.Chmod(0o600); err != nil {
		return ErrOperationQuotaUnavailable
	}
	n, err := tmp.Write(raw)
	if err != nil || n != len(raw) {
		return ErrOperationQuotaUnavailable
	}
	if tmp.Sync() != nil {
		return ErrOperationQuotaUnavailable
	}
	if tmp.Close() != nil {
		return ErrOperationQuotaUnavailable
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return ErrOperationQuotaUnavailable
	}
	dir, err := os.Open(directory)
	if err != nil {
		return ErrOperationQuotaUnavailable
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return ErrOperationQuotaUnavailable
	}
	return nil
}
