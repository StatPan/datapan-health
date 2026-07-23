package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const ScheduleCoverageAuthorityStateVersion = "datapan.health-schedule-coverage-authority.v1"

var ErrSchedulePlanTransition = errors.New("schedule plan transition is unsafe")

// ErrScheduleAuthorityConflict is returned when the persisted generation has
// changed before a state transition can be committed. Callers must reload the
// authority; they must never retry a stale in-memory ledger blindly.
var ErrScheduleAuthorityConflict = errors.New("schedule authority state changed")

// ScheduleCoverageAuthority persists the queue state before returning a claim
// or terminal transition. It intentionally has no provider runner: the only
// supported mode in #49 is dry-run scheduling and evidence production.
type ScheduleCoverageAuthority struct {
	mu         sync.Mutex
	statePath  string
	ledger     *ScheduleCoverageLedger
	latest     *ScheduleCoverageReceipt
	previous   *ScheduleCoverageReceipt
	generation uint64
}

type scheduleCoverageAuthorityState struct {
	SchemaVersion string                         `json:"schema_version"`
	Generation    uint64                         `json:"generation"`
	Ledger        ScheduleCoverageLedgerSnapshot `json:"ledger"`
	Latest        *ScheduleCoverageReceipt       `json:"latest_receipt,omitempty"`
	Previous      *ScheduleCoverageReceipt       `json:"previous_receipt,omitempty"`
}

// ScheduleCoverageDoctorReport contains only bounded scheduler evidence. It
// never includes operation subjects, endpoints, queue contents, credentials,
// provider text, or request/response data.
type ScheduleCoverageDoctorReport struct {
	SchemaVersion  string                   `json:"schema_version"`
	ReceiptState   string                   `json:"receipt_state"`
	Registry       ScheduleCoverageRegistry `json:"registry,omitempty"`
	ShardCount     int                      `json:"shard_count"`
	LatestInterval time.Time                `json:"latest_interval,omitempty"`
	Counts         ScheduleCoverageCounts   `json:"counts"`
}

func OpenScheduleCoverageAuthority(statePath string, plan ScheduleCoveragePlan, queue []ScheduledOperation) (*ScheduleCoverageAuthority, error) {
	if statePath == "" || VerifyScheduleCoveragePlan(plan, queue) != nil {
		return nil, errors.New("schedule authority input is invalid")
	}
	var authority *ScheduleCoverageAuthority
	err := withScheduleCoverageAuthorityLock(statePath, func() error {
		state, found, err := readScheduleCoverageAuthorityState(statePath)
		if err != nil {
			return err
		}
		if !found {
			ledger, err := NewScheduleCoverageLedger(plan, queue)
			if err != nil {
				return err
			}
			state = scheduleCoverageAuthorityState{SchemaVersion: ScheduleCoverageAuthorityStateVersion, Ledger: ledger.Snapshot()}
			if err := commitScheduleCoverageAuthorityState(statePath, 0, state); err != nil {
				return err
			}
			authority = &ScheduleCoverageAuthority{statePath: statePath, ledger: ledger, generation: 1}
			return nil
		}
		ledger, err := restoreScheduleCoverageAuthorityState(state)
		if err != nil || !sameScheduleCoveragePlan(ledger.plan, plan) {
			return ErrSchedulePlanTransition
		}
		authority = &ScheduleCoverageAuthority{statePath: statePath, ledger: ledger, latest: state.Latest, previous: state.Previous, generation: state.Generation}
		return nil
	})
	return authority, err
}

func LoadScheduleCoverageAuthority(statePath string) (*ScheduleCoverageAuthority, error) {
	if statePath == "" {
		return nil, errors.New("schedule authority input is invalid")
	}
	var authority *ScheduleCoverageAuthority
	err := withScheduleCoverageAuthorityLock(statePath, func() error {
		state, found, err := readScheduleCoverageAuthorityState(statePath)
		if err != nil || !found {
			return errors.New("schedule authority state is unavailable")
		}
		ledger, err := restoreScheduleCoverageAuthorityState(state)
		if err != nil {
			return errors.New("schedule authority state is unavailable")
		}
		authority = &ScheduleCoverageAuthority{statePath: statePath, ledger: ledger, latest: state.Latest, previous: state.Previous, generation: state.Generation}
		return nil
	})
	return authority, err
}

func (a *ScheduleCoverageAuthority) Claim(subject string, now time.Time, lease time.Duration) (ScheduleClaim, error) {
	var claim ScheduleClaim
	err := a.transition(func(candidate *ScheduleCoverageLedger) error {
		var err error
		claim, err = candidate.Claim(subject, now, lease)
		return err
	})
	return claim, err
}

func (a *ScheduleCoverageAuthority) ClaimNext(shard int, now time.Time, lease time.Duration) (ScheduleClaim, bool, error) {
	var claim ScheduleClaim
	var found bool
	err := a.transition(func(candidate *ScheduleCoverageLedger) error {
		var err error
		claim, found, err = candidate.ClaimNext(shard, now, lease)
		return err
	})
	return claim, found, err
}

func (a *ScheduleCoverageAuthority) Retry(claim ScheduleClaim) error {
	return a.transition(func(candidate *ScheduleCoverageLedger) error { return candidate.Retry(claim) })
}

func (a *ScheduleCoverageAuthority) Complete(claim ScheduleClaim, now time.Time) error {
	return a.transition(func(candidate *ScheduleCoverageLedger) error { return candidate.Complete(claim, now) })
}

// RecordCoverage durably stores the latest receipt. A dry-run has zero
// attempts and completions; it is an explicit schedule proof, not a call
// receipt.
func (a *ScheduleCoverageAuthority) RecordCoverage(observedAt time.Time) (ScheduleCoverageReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var receipt ScheduleCoverageReceipt
	err := a.withFreshStateLocked(func(state scheduleCoverageAuthorityState, ledger *ScheduleCoverageLedger) (scheduleCoverageAuthorityState, *ScheduleCoverageLedger, error) {
		var err error
		receipt, err = ledger.CoverageReceipt(observedAt)
		if err != nil {
			return state, ledger, err
		}
		state.Latest = &receipt
		return state, ledger, nil
	})
	return receipt, err
}

func ReadScheduleCoverageDoctorReport(statePath string, reference time.Time, maxAge time.Duration) ScheduleCoverageDoctorReport {
	if statePath == "" {
		return ScheduleCoverageDoctorReport{SchemaVersion: "datapan.health-schedule-coverage-doctor.v1", ReceiptState: "not_configured"}
	}
	authority, err := LoadScheduleCoverageAuthority(statePath)
	if err != nil {
		state, found, readErr := readScheduleCoverageAuthorityState(statePath)
		if readErr == nil && !found {
			return ScheduleCoverageDoctorReport{SchemaVersion: "datapan.health-schedule-coverage-doctor.v1", ReceiptState: "missing"}
		}
		_ = state
		return ScheduleCoverageDoctorReport{SchemaVersion: "datapan.health-schedule-coverage-doctor.v1", ReceiptState: "invalid"}
	}
	return authority.Doctor(reference, maxAge)
}

// Rebalance only permits a different shard count at the next exact interval
// boundary and only after every old lease has completed or expired. The old
// interval receipt is retained as evidence; unfinished work is never silently
// moved into the candidate plan.
func (a *ScheduleCoverageAuthority) Rebalance(next ScheduleCoveragePlan, queue []ScheduledOperation, at time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.withFreshStateLocked(func(state scheduleCoverageAuthorityState, ledger *ScheduleCoverageLedger) (scheduleCoverageAuthorityState, *ScheduleCoverageLedger, error) {
		if VerifyScheduleCoveragePlan(next, queue) != nil || !at.UTC().Equal(next.Interval.Start) || !next.Interval.Start.After(ledger.plan.Interval.Start) || next.Interval.Start.Sub(ledger.plan.Interval.Start)%scheduleInterval != 0 {
			return state, ledger, ErrSchedulePlanTransition
		}
		for _, entry := range ledger.entries {
			if entry.State == "claimed" && entry.LeaseExpires.After(at.UTC()) {
				return state, ledger, ErrSchedulePlanTransition
			}
		}
		previous, err := ledger.CoverageReceipt(at)
		if err != nil {
			return state, ledger, ErrSchedulePlanTransition
		}
		nextLedger, err := NewScheduleCoverageLedger(next, queue)
		if err != nil {
			return state, ledger, ErrSchedulePlanTransition
		}
		state.Latest, state.Previous = nil, &previous
		return state, nextLedger, nil
	})
}

func (a *ScheduleCoverageAuthority) transition(apply func(*ScheduleCoverageLedger) error) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.withFreshStateLocked(func(state scheduleCoverageAuthorityState, ledger *ScheduleCoverageLedger) (scheduleCoverageAuthorityState, *ScheduleCoverageLedger, error) {
		candidate, err := RestoreScheduleCoverageLedger(ledger.Snapshot())
		if err != nil {
			return state, ledger, errors.New("schedule authority state is unavailable")
		}
		if err := apply(candidate); err != nil {
			return state, ledger, err
		}
		return state, candidate, nil
	})
}

func (a *ScheduleCoverageAuthority) Doctor(reference time.Time, maxAge time.Duration) ScheduleCoverageDoctorReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.refreshLocked(); err != nil {
		return ScheduleCoverageDoctorReport{SchemaVersion: "datapan.health-schedule-coverage-doctor.v1", ReceiptState: "invalid"}
	}
	plan := a.ledger.plan
	report := ScheduleCoverageDoctorReport{SchemaVersion: "datapan.health-schedule-coverage-doctor.v1", ReceiptState: "missing", Registry: plan.Registry, ShardCount: plan.Scheduler.ShardCount, LatestInterval: plan.Interval.Start, Counts: ScheduleCoverageCounts{Expected: totalScheduleExpected(plan), Assigned: totalScheduleExpected(plan), Missing: totalScheduleExpected(plan)}}
	if a.latest == nil {
		return report
	}
	if a.latest.Validate() != nil || !sameScheduleCoveragePlan(plan, ScheduleCoveragePlan{SchemaVersion: a.latest.SchemaVersion, Registry: a.latest.Registry, Interval: a.latest.Interval, Scheduler: a.latest.Scheduler, Shards: receiptPlanShards(a.latest.Shards)}) {
		report.ReceiptState = "invalid"
		return report
	}
	report.Counts = a.latest.Aggregate
	if reference.IsZero() || maxAge <= 0 || a.latest.ObservedAt.After(reference.UTC()) || reference.UTC().Sub(a.latest.ObservedAt) > maxAge {
		report.ReceiptState = "stale"
		return report
	}
	report.ReceiptState = "current"
	return report
}

func (a *ScheduleCoverageAuthority) refreshLocked() error {
	return withScheduleCoverageAuthorityLock(a.statePath, func() error {
		state, found, err := readScheduleCoverageAuthorityState(a.statePath)
		if err != nil || !found {
			return errors.New("schedule authority state is unavailable")
		}
		ledger, err := restoreScheduleCoverageAuthorityState(state)
		if err != nil || !sameScheduleCoveragePlan(a.ledger.plan, ledger.plan) {
			return ErrSchedulePlanTransition
		}
		a.ledger, a.latest, a.previous, a.generation = ledger, state.Latest, state.Previous, state.Generation
		return nil
	})
}

// withFreshStateLocked serializes writers across scheduler processes, reloads
// the durable generation while holding the lock, and CAS-commits the candidate.
// A stale instance can therefore neither overwrite a newer claim nor mutate a
// ledger after a rebalance changed its schedule plan.
func (a *ScheduleCoverageAuthority) withFreshStateLocked(apply func(scheduleCoverageAuthorityState, *ScheduleCoverageLedger) (scheduleCoverageAuthorityState, *ScheduleCoverageLedger, error)) error {
	return withScheduleCoverageAuthorityLock(a.statePath, func() error {
		state, found, err := readScheduleCoverageAuthorityState(a.statePath)
		if err != nil || !found {
			return errors.New("schedule authority state is unavailable")
		}
		ledger, err := restoreScheduleCoverageAuthorityState(state)
		if err != nil {
			return errors.New("schedule authority state is unavailable")
		}
		if !sameScheduleCoveragePlan(a.ledger.plan, ledger.plan) {
			return ErrSchedulePlanTransition
		}
		nextState, nextLedger, err := apply(state, ledger)
		if err != nil {
			return err
		}
		nextState.SchemaVersion = ScheduleCoverageAuthorityStateVersion
		nextState.Ledger = nextLedger.Snapshot()
		if err := commitScheduleCoverageAuthorityState(a.statePath, state.Generation, nextState); err != nil {
			return err
		}
		a.ledger, a.latest, a.previous, a.generation = nextLedger, nextState.Latest, nextState.Previous, state.Generation+1
		return nil
	})
}

func readScheduleCoverageAuthorityState(path string) (scheduleCoverageAuthorityState, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return scheduleCoverageAuthorityState{}, false, nil
	}
	if err != nil {
		return scheduleCoverageAuthorityState{}, false, errors.New("schedule authority state is unavailable")
	}
	var state scheduleCoverageAuthorityState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&state); err != nil || ensureEOF(decoder) != nil || state.SchemaVersion != ScheduleCoverageAuthorityStateVersion {
		return scheduleCoverageAuthorityState{}, false, errors.New("schedule authority state is unavailable")
	}
	return state, true, nil
}

func restoreScheduleCoverageAuthorityState(state scheduleCoverageAuthorityState) (*ScheduleCoverageLedger, error) {
	ledger, err := RestoreScheduleCoverageLedger(state.Ledger)
	if err != nil {
		return nil, err
	}
	for _, receipt := range []*ScheduleCoverageReceipt{state.Latest, state.Previous} {
		if receipt == nil {
			continue
		}
		if receipt.Validate() != nil {
			return nil, errors.New("schedule authority receipt is invalid")
		}
	}
	return ledger, nil
}

func writeScheduleCoverageAuthorityState(path string, state scheduleCoverageAuthorityState) error {
	if filepath.IsAbs(path) && filepath.Clean(path) == string(filepath.Separator) {
		return errors.New("schedule authority state is unsafe")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return errors.New("schedule authority state is unavailable")
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return errors.New("schedule authority state is unavailable")
	}
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".schedule-authority-")
	if err != nil {
		return errors.New("schedule authority state is unavailable")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if temporary.Chmod(0o600) != nil || writeAllAndSync(temporary, raw) != nil || temporary.Close() != nil || os.Rename(temporaryPath, path) != nil || syncScheduleAuthorityDirectory(directory) != nil {
		return errors.New("schedule authority state is unavailable")
	}
	return nil
}

// commitScheduleCoverageAuthorityState is a generation-checked compare and
// swap. It is called only while the adjacent lock file is exclusively held;
// retaining the generation check makes stale/miswired writers fail closed even
// if a future storage implementation changes the lock boundary.
func commitScheduleCoverageAuthorityState(path string, expectedGeneration uint64, state scheduleCoverageAuthorityState) error {
	current, found, err := readScheduleCoverageAuthorityState(path)
	if err != nil {
		return err
	}
	actual := uint64(0)
	if found {
		actual = current.Generation
	}
	if actual != expectedGeneration {
		return ErrScheduleAuthorityConflict
	}
	state.Generation = expectedGeneration + 1
	return writeScheduleCoverageAuthorityState(path, state)
}

func withScheduleCoverageAuthorityLock(statePath string, apply func() error) error {
	if filepath.IsAbs(statePath) && filepath.Clean(statePath) == string(filepath.Separator) {
		return errors.New("schedule authority state is unsafe")
	}
	directory := filepath.Dir(statePath)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return errors.New("schedule authority state is unavailable")
	}
	lock, err := os.OpenFile(statePath+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return errors.New("schedule authority state is unavailable")
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return errors.New("schedule authority state is unavailable")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	return apply()
}

func writeAllAndSync(file *os.File, data []byte) error {
	if _, err := file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func syncScheduleAuthorityDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func sameScheduleCoveragePlan(left, right ScheduleCoveragePlan) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func totalScheduleExpected(plan ScheduleCoveragePlan) int {
	total := 0
	for _, shard := range plan.Shards {
		total += shard.Expected
	}
	return total
}
