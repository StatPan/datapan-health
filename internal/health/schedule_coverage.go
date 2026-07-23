package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

// ScheduleCoverageReceiptSchemaVersion is a private, identity-preserving
// scheduling receipt. It deliberately has no provider request or response
// fields: making work due is not evidence that a provider was called.
const ScheduleCoverageReceiptSchemaVersion = "datapan.health-schedule-coverage.v1"

const (
	scheduleInterval     = 10 * time.Minute
	scheduleAssignmentV1 = "operation-id-sha256-mod-v1"
)

var (
	ErrScheduleLeaseHeld = errors.New("schedule work lease is held")
	ErrScheduleFenced    = errors.New("schedule work claim is fenced")
	ErrScheduleComplete  = errors.New("schedule work is already complete")
)

// ScheduleCoveragePlan is the deterministic queue assignment for one Registry
// manifest revision and one ten-minute interval. Every queue item is keyed by
// ManifestOperation.StatusSubject(), never API, dataset, host, endpoint, or
// the separate public-canary catalog.
type ScheduleCoveragePlan struct {
	SchemaVersion string                    `json:"schema_version"`
	Registry      ScheduleCoverageRegistry  `json:"registry"`
	Interval      ScheduleCoverageInterval  `json:"interval"`
	Scheduler     ScheduleCoverageScheduler `json:"scheduler"`
	Shards        []ScheduleCoverageShard   `json:"shards"`
}

type ScheduleCoverageRegistry struct {
	Revision       string `json:"revision"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type ScheduleCoverageInterval struct {
	Start           time.Time `json:"start"`
	DurationSeconds int64     `json:"duration_seconds"`
}

type ScheduleCoverageScheduler struct {
	ShardCount          int    `json:"shard_count"`
	AssignmentAlgorithm string `json:"assignment_algorithm"`
}

// ScheduleCoverageShard binds an opaque queue digest and counts to a shard.
// The queue itself remains private scheduler input and contains only stable
// Registry operation identities.
type ScheduleCoverageShard struct {
	Index       int    `json:"index"`
	QueueSHA256 string `json:"queue_sha256"`
	Expected    int    `json:"expected"`
}

type ScheduledOperation struct {
	Subject       string
	Registry      ScheduleCoverageRegistry
	IntervalStart time.Time
	Shard         int
}

// ScheduleClaim is a lease/fencing token. A completion is authoritative only
// when the matching current generation is presented to the ledger.
type ScheduleClaim struct {
	Subject       string
	Registry      ScheduleCoverageRegistry
	IntervalStart time.Time
	Shard         int
	Generation    uint64
	LeaseExpires  time.Time
}

type ScheduleCoverageCounts struct {
	Expected  int `json:"expected"`
	Assigned  int `json:"assigned"`
	Attempted int `json:"attempted"`
	Completed int `json:"completed"`
	Late      int `json:"late"`
	Missing   int `json:"missing"`
}

type ScheduleCoverageShardReceipt struct {
	Index       int                    `json:"index"`
	QueueSHA256 string                 `json:"queue_sha256"`
	Counts      ScheduleCoverageCounts `json:"counts"`
}

// ScheduleCoverageReceipt is an explicit schedule and queue-coverage proof.
// It records assignments and authoritative lifecycle results separately, so a
// full queue with zero attempts cannot be mistaken for provider success.
type ScheduleCoverageReceipt struct {
	SchemaVersion string                         `json:"schema_version"`
	Registry      ScheduleCoverageRegistry       `json:"registry"`
	Interval      ScheduleCoverageInterval       `json:"interval"`
	Scheduler     ScheduleCoverageScheduler      `json:"scheduler"`
	ObservedAt    time.Time                      `json:"observed_at"`
	Shards        []ScheduleCoverageShardReceipt `json:"shards"`
	Aggregate     ScheduleCoverageCounts         `json:"aggregate"`
}

type scheduleEntry struct {
	Operation    ScheduledOperation `json:"operation"`
	State        string             `json:"state"`
	Attempted    bool               `json:"attempted"`
	Generation   uint64             `json:"generation"`
	LeaseExpires time.Time          `json:"lease_expires,omitempty"`
	CompletedAt  time.Time          `json:"completed_at,omitempty"`
}

type ScheduleCoverageLedgerSnapshot struct {
	Plan    ScheduleCoveragePlan     `json:"plan"`
	Entries map[string]scheduleEntry `json:"entries"`
}

// ScheduleCoverageLedger owns no provider invocation. It is the minimal
// authoritative state machine that a durable scheduler store must preserve
// across retry, crash/restart, and worker rebalance.
type ScheduleCoverageLedger struct {
	mu      sync.Mutex
	plan    ScheduleCoveragePlan
	entries map[string]scheduleEntry
}

// DecodeScheduleCoverageReceipt validates schema shape before decoding, so an
// unrecognized field (including a leaked provider value) is rejected rather
// than silently dropped by a Go struct decoder.
func DecodeScheduleCoverageReceipt(r io.Reader) (ScheduleCoverageReceipt, error) {
	raw, err := io.ReadAll(io.LimitReader(r, 2*1024*1024+1))
	if err != nil || len(raw) > 2*1024*1024 || schemas.ValidateHealthScheduleCoverageV1(raw) != nil {
		return ScheduleCoverageReceipt{}, errors.New("schedule coverage receipt is invalid")
	}
	var receipt ScheduleCoverageReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil || ensureEOF(decoder) != nil || receipt.Validate() != nil {
		return ScheduleCoverageReceipt{}, errors.New("schedule coverage receipt is invalid")
	}
	return receipt, nil
}

func BuildScheduleCoveragePlan(manifest OperationManifest, receipt OperationManifestReceipt, at time.Time, shardCount int) (ScheduleCoveragePlan, []ScheduledOperation, error) {
	if err := manifest.Validate(receipt); err != nil || shardCount < 1 || shardCount > 4096 || at.IsZero() {
		return ScheduleCoveragePlan{}, nil, errors.New("schedule coverage input is invalid")
	}
	start := at.UTC().Truncate(scheduleInterval)
	registry := ScheduleCoverageRegistry{Revision: receipt.Registry.Revision, ManifestSHA256: receipt.Manifest.SHA256}
	byShard := make([][]string, shardCount)
	seen := make(map[string]bool, len(manifest.Operations))
	queue := make([]ScheduledOperation, 0, len(manifest.Operations))
	for _, operation := range manifest.Operations {
		subject := operation.StatusSubject()
		if subject == "" || seen[subject] {
			return ScheduleCoveragePlan{}, nil, errors.New("schedule coverage identities are invalid")
		}
		seen[subject] = true
		shard := scheduleShard(subject, shardCount)
		byShard[shard] = append(byShard[shard], subject)
		queue = append(queue, ScheduledOperation{Subject: subject, Registry: registry, IntervalStart: start, Shard: shard})
	}
	if len(queue) != receipt.Denominator.OperationStatusSubjects {
		return ScheduleCoveragePlan{}, nil, errors.New("schedule coverage denominator does not match")
	}
	sort.Slice(queue, func(i, j int) bool { return queue[i].Subject < queue[j].Subject })
	plan := ScheduleCoveragePlan{SchemaVersion: ScheduleCoverageReceiptSchemaVersion, Registry: registry, Interval: ScheduleCoverageInterval{Start: start, DurationSeconds: int64(scheduleInterval / time.Second)}, Scheduler: ScheduleCoverageScheduler{ShardCount: shardCount, AssignmentAlgorithm: scheduleAssignmentV1}, Shards: make([]ScheduleCoverageShard, shardCount)}
	for index := range byShard {
		sort.Strings(byShard[index])
		plan.Shards[index] = ScheduleCoverageShard{Index: index, QueueSHA256: scheduleQueueDigest(index, byShard[index]), Expected: len(byShard[index])}
	}
	if err := VerifyScheduleCoveragePlan(plan, queue); err != nil {
		return ScheduleCoveragePlan{}, nil, err
	}
	return plan, queue, nil
}

func VerifyScheduleCoveragePlan(plan ScheduleCoveragePlan, queue []ScheduledOperation) error {
	if !validSchedulePlan(plan) || len(queue) == 0 {
		return errors.New("schedule coverage plan is invalid")
	}
	byShard := make([][]string, plan.Scheduler.ShardCount)
	seen := make(map[string]bool, len(queue))
	for _, item := range queue {
		if item.Subject == "" || seen[item.Subject] || item.Registry != plan.Registry || !item.IntervalStart.Equal(plan.Interval.Start) || item.Shard < 0 || item.Shard >= len(byShard) || item.Shard != scheduleShard(item.Subject, len(byShard)) {
			return errors.New("schedule coverage queue is invalid")
		}
		seen[item.Subject] = true
		byShard[item.Shard] = append(byShard[item.Shard], item.Subject)
	}
	for index, subjects := range byShard {
		sort.Strings(subjects)
		shard := plan.Shards[index]
		if shard.Index != index || shard.Expected != len(subjects) || shard.QueueSHA256 != scheduleQueueDigest(index, subjects) {
			return errors.New("schedule coverage queue does not match plan")
		}
	}
	return nil
}

func NewScheduleCoverageLedger(plan ScheduleCoveragePlan, queue []ScheduledOperation) (*ScheduleCoverageLedger, error) {
	if err := VerifyScheduleCoveragePlan(plan, queue); err != nil {
		return nil, err
	}
	entries := make(map[string]scheduleEntry, len(queue))
	for _, item := range queue {
		entries[item.Subject] = scheduleEntry{Operation: item, State: "queued"}
	}
	return &ScheduleCoverageLedger{plan: plan, entries: entries}, nil
}

func RestoreScheduleCoverageLedger(snapshot ScheduleCoverageLedgerSnapshot) (*ScheduleCoverageLedger, error) {
	queue := make([]ScheduledOperation, 0, len(snapshot.Entries))
	for subject, entry := range snapshot.Entries {
		if subject != entry.Operation.Subject || (entry.State != "queued" && entry.State != "claimed" && entry.State != "completed") {
			return nil, errors.New("schedule coverage snapshot is invalid")
		}
		queue = append(queue, entry.Operation)
	}
	if err := VerifyScheduleCoveragePlan(snapshot.Plan, queue); err != nil {
		return nil, errors.New("schedule coverage snapshot is invalid")
	}
	entries := make(map[string]scheduleEntry, len(snapshot.Entries))
	for subject, entry := range snapshot.Entries {
		entries[subject] = entry
	}
	return &ScheduleCoverageLedger{plan: snapshot.Plan, entries: entries}, nil
}

func (l *ScheduleCoverageLedger) Snapshot() ScheduleCoverageLedgerSnapshot {
	l.mu.Lock()
	defer l.mu.Unlock()
	entries := make(map[string]scheduleEntry, len(l.entries))
	for subject, entry := range l.entries {
		entries[subject] = entry
	}
	return ScheduleCoverageLedgerSnapshot{Plan: l.plan, Entries: entries}
}

func (l *ScheduleCoverageLedger) ClaimNext(shard int, now time.Time, lease time.Duration) (ScheduleClaim, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if shard < 0 || shard >= l.plan.Scheduler.ShardCount || lease <= 0 || now.Before(l.plan.Interval.Start) {
		return ScheduleClaim{}, false, errors.New("schedule claim input is invalid")
	}
	subjects := make([]string, 0)
	for subject, entry := range l.entries {
		if entry.Operation.Shard == shard {
			subjects = append(subjects, subject)
		}
	}
	sort.Strings(subjects)
	for _, subject := range subjects {
		claim, err := l.claimLocked(subject, now.UTC(), lease)
		if err == nil {
			return claim, true, nil
		}
		if errors.Is(err, ErrScheduleLeaseHeld) || errors.Is(err, ErrScheduleComplete) {
			continue
		}
		return ScheduleClaim{}, false, err
	}
	return ScheduleClaim{}, false, nil
}

func (l *ScheduleCoverageLedger) Claim(subject string, now time.Time, lease time.Duration) (ScheduleClaim, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if lease <= 0 || now.Before(l.plan.Interval.Start) {
		return ScheduleClaim{}, errors.New("schedule claim input is invalid")
	}
	return l.claimLocked(subject, now.UTC(), lease)
}

func (l *ScheduleCoverageLedger) claimLocked(subject string, now time.Time, lease time.Duration) (ScheduleClaim, error) {
	entry, found := l.entries[subject]
	if !found {
		return ScheduleClaim{}, errors.New("schedule subject is unknown")
	}
	if entry.State == "completed" {
		return ScheduleClaim{}, ErrScheduleComplete
	}
	if entry.State == "claimed" && now.Before(entry.LeaseExpires) {
		return ScheduleClaim{}, ErrScheduleLeaseHeld
	}
	entry.State, entry.Attempted, entry.Generation = "claimed", true, entry.Generation+1
	entry.LeaseExpires = now.Add(lease)
	l.entries[subject] = entry
	return ScheduleClaim{Subject: subject, Registry: entry.Operation.Registry, IntervalStart: entry.Operation.IntervalStart, Shard: entry.Operation.Shard, Generation: entry.Generation, LeaseExpires: entry.LeaseExpires}, nil
}

// Retry releases a current claim without creating a second authoritative
// terminal transition. The next claim advances its generation and fences the
// abandoned worker.
func (l *ScheduleCoverageLedger) Retry(claim ScheduleClaim) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, err := l.currentClaimLocked(claim)
	if err != nil {
		return err
	}
	entry.State, entry.LeaseExpires = "queued", time.Time{}
	l.entries[claim.Subject] = entry
	return nil
}

func (l *ScheduleCoverageLedger) Complete(claim ScheduleClaim, now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, err := l.currentClaimLocked(claim)
	if err != nil {
		return err
	}
	if now.UTC().After(entry.LeaseExpires) {
		return ErrScheduleFenced
	}
	entry.State, entry.CompletedAt, entry.LeaseExpires = "completed", now.UTC(), time.Time{}
	l.entries[claim.Subject] = entry
	return nil
}

func (l *ScheduleCoverageLedger) currentClaimLocked(claim ScheduleClaim) (scheduleEntry, error) {
	entry, found := l.entries[claim.Subject]
	if !found || entry.State != "claimed" || entry.Generation != claim.Generation || entry.Operation.Registry != claim.Registry || !entry.Operation.IntervalStart.Equal(claim.IntervalStart) || entry.Operation.Shard != claim.Shard || !entry.LeaseExpires.Equal(claim.LeaseExpires) {
		return scheduleEntry{}, ErrScheduleFenced
	}
	return entry, nil
}

func (l *ScheduleCoverageLedger) CoverageReceipt(observedAt time.Time) (ScheduleCoverageReceipt, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if observedAt.IsZero() || observedAt.Before(l.plan.Interval.Start) {
		return ScheduleCoverageReceipt{}, errors.New("schedule coverage observation time is invalid")
	}
	receipt := ScheduleCoverageReceipt{SchemaVersion: ScheduleCoverageReceiptSchemaVersion, Registry: l.plan.Registry, Interval: l.plan.Interval, Scheduler: l.plan.Scheduler, ObservedAt: observedAt.UTC(), Shards: make([]ScheduleCoverageShardReceipt, len(l.plan.Shards))}
	deadline := l.plan.Interval.Start.Add(scheduleInterval)
	for index, shard := range l.plan.Shards {
		counts := ScheduleCoverageCounts{Expected: shard.Expected, Assigned: shard.Expected}
		for _, entry := range l.entries {
			if entry.Operation.Shard != index {
				continue
			}
			if entry.Attempted {
				counts.Attempted++
			}
			if entry.State == "completed" && !entry.CompletedAt.After(receipt.ObservedAt) {
				counts.Completed++
				if entry.CompletedAt.After(deadline) {
					counts.Late++
				}
			}
		}
		counts.Missing = counts.Expected - counts.Completed
		receipt.Shards[index] = ScheduleCoverageShardReceipt{Index: index, QueueSHA256: shard.QueueSHA256, Counts: counts}
		receipt.Aggregate = addScheduleCounts(receipt.Aggregate, counts)
	}
	if err := receipt.Validate(); err != nil {
		return ScheduleCoverageReceipt{}, err
	}
	return receipt, nil
}

func (r ScheduleCoverageReceipt) Validate() error {
	raw, err := json.Marshal(r)
	if err != nil || schemas.ValidateHealthScheduleCoverageV1(raw) != nil || !validSchedulePlan(ScheduleCoveragePlan{SchemaVersion: r.SchemaVersion, Registry: r.Registry, Interval: r.Interval, Scheduler: r.Scheduler, Shards: receiptPlanShards(r.Shards)}) || r.ObservedAt.IsZero() || r.ObservedAt.Before(r.Interval.Start) {
		return errors.New("schedule coverage receipt is invalid")
	}
	aggregate := ScheduleCoverageCounts{}
	for index, shard := range r.Shards {
		if shard.Index != index || !sha256Pattern.MatchString(shard.QueueSHA256) || !validScheduleCounts(shard.Counts) {
			return errors.New("schedule coverage receipt is invalid")
		}
		aggregate = addScheduleCounts(aggregate, shard.Counts)
	}
	if aggregate != r.Aggregate || !validScheduleCounts(r.Aggregate) {
		return errors.New("schedule coverage receipt is invalid")
	}
	return nil
}

func receiptPlanShards(receipt []ScheduleCoverageShardReceipt) []ScheduleCoverageShard {
	shards := make([]ScheduleCoverageShard, len(receipt))
	for index, shard := range receipt {
		shards[index] = ScheduleCoverageShard{Index: shard.Index, QueueSHA256: shard.QueueSHA256, Expected: shard.Counts.Expected}
	}
	return shards
}

func validSchedulePlan(plan ScheduleCoveragePlan) bool {
	if plan.SchemaVersion != ScheduleCoverageReceiptSchemaVersion || !commitPattern.MatchString(plan.Registry.Revision) || !sha256Pattern.MatchString(plan.Registry.ManifestSHA256) || plan.Interval.Start.IsZero() || !plan.Interval.Start.Equal(plan.Interval.Start.UTC().Truncate(scheduleInterval)) || plan.Interval.DurationSeconds != int64(scheduleInterval/time.Second) || plan.Scheduler.ShardCount < 1 || plan.Scheduler.ShardCount > 4096 || plan.Scheduler.AssignmentAlgorithm != scheduleAssignmentV1 || len(plan.Shards) != plan.Scheduler.ShardCount {
		return false
	}
	for index, shard := range plan.Shards {
		if shard.Index != index || shard.Expected < 0 || !sha256Pattern.MatchString(shard.QueueSHA256) {
			return false
		}
	}
	return true
}

func validScheduleCounts(counts ScheduleCoverageCounts) bool {
	return counts.Expected >= 0 && counts.Assigned == counts.Expected && counts.Attempted >= 0 && counts.Attempted <= counts.Expected && counts.Completed >= 0 && counts.Completed <= counts.Attempted && counts.Late >= 0 && counts.Late <= counts.Completed && counts.Missing == counts.Expected-counts.Completed
}

func addScheduleCounts(left, right ScheduleCoverageCounts) ScheduleCoverageCounts {
	return ScheduleCoverageCounts{Expected: left.Expected + right.Expected, Assigned: left.Assigned + right.Assigned, Attempted: left.Attempted + right.Attempted, Completed: left.Completed + right.Completed, Late: left.Late + right.Late, Missing: left.Missing + right.Missing}
}

func scheduleShard(subject string, count int) int {
	hash := sha256.Sum256([]byte(subject))
	return int(binary.BigEndian.Uint64(hash[:8]) % uint64(count))
}

func scheduleQueueDigest(index int, subjects []string) string {
	hash := sha256.New()
	_, _ = fmt.Fprintf(hash, "%s:%d:", scheduleAssignmentV1, index)
	for _, subject := range subjects {
		_, _ = fmt.Fprintf(hash, "%d:%s", len(subject), subject)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
