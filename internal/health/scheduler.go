package health

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const receiptWriteGrace = time.Second

// ProbeRunner is intentionally a process boundary: datapan-cli owns probing,
// trust, parameter planning, and receipt semantics.
type ProbeRunner interface {
	Run(context.Context, Canary, CatalogEntry, string) error
}

// ReceiptDeliverer invokes the existing health-runner adapter. It receives the
// only receipt emitted by one CLI invocation and must not inspect its content.
type ReceiptDeliverer interface {
	Deliver(context.Context, string) error
}

type Scheduler struct {
	config    CanaryConfig
	runner    ProbeRunner
	deliverer ReceiptDeliverer
	statePath string
	mu        sync.Mutex
	state     scheduleState
	active    map[string]bool
	sem       chan struct{}
	wg        sync.WaitGroup
	metrics   SchedulerMetrics
}

type scheduleState struct {
	Version int                   `json:"version"`
	Slots   map[string]slotRecord `json:"slots"`
}
type slotRecord struct {
	LastClaimedSlot int64     `json:"last_claimed_slot"`
	NextDue         time.Time `json:"next_due"`
}

type SchedulerMetrics struct {
	mu                  sync.Mutex
	RunsStarted         uint64
	RunsCompleted       uint64
	RunsFailed          uint64
	RunsSkippedCapacity uint64
	DeliveryFailed      uint64
	LastCompleted       time.Time
}

type MetricsSnapshot struct {
	RunsStarted         uint64
	RunsCompleted       uint64
	RunsFailed          uint64
	RunsSkippedCapacity uint64
	DeliveryFailed      uint64
	LastCompleted       time.Time
}

func NewScheduler(config CanaryConfig, statePath string, runner ProbeRunner, deliverer ReceiptDeliverer) (*Scheduler, error) {
	if runner == nil || deliverer == nil || statePath == "" {
		return nil, errors.New("scheduler dependencies are required")
	}
	state, err := loadScheduleState(statePath)
	if err != nil {
		return nil, err
	}
	return &Scheduler{config: config, statePath: statePath, runner: runner, deliverer: deliverer, state: state, active: map[string]bool{}, sem: make(chan struct{}, config.GlobalConcurrency)}, nil
}

func loadScheduleState(path string) (scheduleState, error) {
	state := scheduleState{Version: 1, Slots: map[string]slotRecord{}}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(raw, &state); err != nil || state.Version != 1 || state.Slots == nil {
		return scheduleState{}, errors.New("invalid scheduler state")
	}
	return state, nil
}

func (s *Scheduler) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.statePath), 0o750); err != nil {
		return err
	}
	raw, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.statePath), ".scheduler-state-")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.statePath)
}

// ProcessDue is clock-driven so tests can advance time without sleeping. It
// claims a slot before execution; a crash may skip that slot but can never
// replay it after restart, preventing catch-up storms and duplicate probes.
func (s *Scheduler) ProcessDue(ctx context.Context, now time.Time) error {
	now = now.UTC()
	for _, canary := range s.config.Canaries {
		entry, _ := s.config.Entry(canary)
		if err := s.claimAndStart(ctx, now, canary, entry); err != nil {
			return err
		}
	}
	return nil
}

func (s *Scheduler) claimAndStart(ctx context.Context, now time.Time, canary Canary, entry CatalogEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, exists := s.state.Slots[canary.OperationID]
	if !exists {
		record.NextDue = nextDueAfter(canary, now, s.config.JitterSeconds, canary.OperationID)
		s.state.Slots[canary.OperationID] = record
		return s.saveLocked()
	}
	if record.NextDue.After(now) || s.active[canary.OperationID] {
		return nil
	}
	currentSlot := slotAt(canary, now)
	dueSlot := slotAt(canary, record.NextDue)
	if dueSlot != currentSlot { // missed while stopped or constrained: skip, never catch up.
		record.NextDue = nextDueAfter(canary, now, s.config.JitterSeconds, canary.OperationID)
		s.state.Slots[canary.OperationID] = record
		s.metrics.incSkippedCapacity()
		return s.saveLocked()
	}
	select {
	case s.sem <- struct{}{}:
	default:
		s.metrics.incSkippedCapacity()
		return nil
	}
	record.LastClaimedSlot = dueSlot
	record.NextDue = nextDueAfter(canary, now, s.config.JitterSeconds, canary.OperationID)
	s.state.Slots[canary.OperationID] = record
	if err := s.saveLocked(); err != nil {
		<-s.sem
		return err
	}
	s.active[canary.OperationID] = true
	s.wg.Add(1)
	s.metrics.incStarted()
	go func() {
		defer func() { <-s.sem; s.mu.Lock(); delete(s.active, canary.OperationID); s.mu.Unlock(); s.wg.Done() }()
		s.run(ctx, canary, entry)
	}()
	return nil
}

func (s *Scheduler) run(parent context.Context, canary Canary, entry CatalogEntry) {
	dir, err := os.MkdirTemp("", "datapan-health-receipt-")
	if err != nil {
		s.metrics.incFailed()
		return
	}
	defer os.RemoveAll(dir)
	receiptPath := filepath.Join(dir, "receipt.json")
	started := time.Now().UTC()
	probeCtx, cancelProbe := context.WithTimeout(parent, probeDeadline(entry))
	defer cancelProbe()
	// A non-zero CLI exit is expected for unhealthy/skipped outcomes. A receipt
	// still must exist and is the sole authority for the public projection.
	cliErr := s.runner.Run(probeCtx, canary, entry, receiptPath)
	receipt, receiptErr := ReadReceipt(receiptPath)
	if receiptErr != nil {
		// A receipt-less bounded child must replace, not leave behind, an older
		// healthy status. This fallback never reads child output or request data.
		fallback, err := s.receiptlessOutcome(entry, started, time.Now().UTC(), cliErr, probeCtx.Err())
		if err != nil || writeReceipt(receiptPath, fallback) != nil {
			s.metrics.incFailed()
			return
		}
		receipt = fallback
	}
	if validateCatalogReceipt(receipt, entry) != nil {
		s.metrics.incFailed()
		_ = cliErr // errors may contain provider details and are deliberately not logged.
		return
	}
	// The CLI owns the execution ceiling. Delivery gets an independent short
	// window so a timeout receipt can be projected after the probe deadline.
	deliveryCtx, cancelDelivery := context.WithTimeout(parent, 10*time.Second)
	defer cancelDelivery()
	if err := s.deliverer.Deliver(deliveryCtx, receiptPath); err != nil {
		s.metrics.incDeliveryFailed()
		return
	}
	s.metrics.incCompleted()
}

func probeDeadline(entry CatalogEntry) time.Duration {
	return time.Duration(entry.Execution.TimeoutCeilingMS)*time.Millisecond + receiptWriteGrace
}

func (s *Scheduler) receiptlessOutcome(entry CatalogEntry, started, observed time.Time, cliErr, contextErr error) (Receipt, error) {
	probeID, err := schedulerProbeID()
	if err != nil {
		return Receipt{}, err
	}
	category, reason := "indeterminate", "cli_receipt_missing"
	if errors.Is(cliErr, context.DeadlineExceeded) || errors.Is(contextErr, context.DeadlineExceeded) {
		category, reason = "timeout", "scheduler_timeout_without_cli_receipt"
	}
	parameterNames := make([]string, 0, len(entry.Execution.SafeParameters))
	for _, parameter := range entry.Execution.SafeParameters {
		parameterNames = append(parameterNames, parameter.Name)
	}
	sort.Strings(parameterNames)
	latency := observed.Sub(started).Milliseconds()
	if latency < 0 {
		latency = 0
	}
	return Receipt{
		SchemaVersion: SchemaVersion,
		ProbeID:       probeID,
		ObservedAt:    observed.UTC(),
		Operation: Operation{
			OperationKey: entry.Aliases.CLIOperationKey, DatasetID: entry.Aliases.DatasetID,
			OperationName: entry.Aliases.OperationName, Provider: entry.Provider,
			EndpointHost: entry.Endpoint.Host, EndpointPath: entry.Endpoint.Path,
			DependencyClass: entry.Endpoint.DependencyClass,
		},
		Registry:    Registry{DatasetID: entry.Aliases.DatasetID, DatasetRevision: s.config.catalog.SourceRegistry.SHA256, RegistrySHA256: s.config.catalog.SourceRegistry.SHA256},
		Policy:      &Policy{Key: entry.Policy.Key, Version: entry.Policy.Version, Authority: entry.Policy.Authority, MaxLevel: entry.Policy.MaxLevel},
		Execution:   Execution{CLIVersion: "scheduler-receiptless-fallback", Attempted: true, TimeoutMS: int64(entry.Execution.TimeoutCeilingMS), RequestBudget: entry.Execution.RequestBudget, SafeParameterNames: parameterNames},
		Observation: Observation{MaxLevel: entry.Policy.MaxLevel, LatencyMS: latency, ProviderMessageClass: "not_observed", DataPresence: "not_observed", SchemaStatus: "not_observed", FreshnessStatus: "not_observed"},
		Assessment:  Assessment{Outcome: "indeterminate", Category: category, Retryable: category == "timeout", ReasonCode: reason, NextActions: []string{"review scheduler and provider evidence"}},
		Redaction:   Redaction{CredentialsRemoved: true, QueryValuesRemoved: true, ResponseRowsRemoved: true},
	}, nil
}

func schedulerProbeID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", raw[:4], raw[4:6], raw[6:8], raw[8:10], raw[10:]), nil
}

func writeReceipt(path string, receipt Receipt) error {
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func validateCatalogReceipt(receipt Receipt, entry CatalogEntry) error {
	if receipt.Operation.OperationKey != entry.Aliases.CLIOperationKey || receipt.Operation.DatasetID != entry.Aliases.DatasetID || receipt.Operation.OperationName != entry.Aliases.OperationName || receipt.Operation.DependencyClass != entry.Endpoint.DependencyClass || receipt.Execution.RequestBudget > entry.Execution.RequestBudget || receipt.Execution.TimeoutMS > int64(entry.Execution.TimeoutCeilingMS) {
		return errors.New("receipt does not match pinned catalog")
	}
	want := make([]string, 0, len(entry.Execution.SafeParameters))
	for _, parameter := range entry.Execution.SafeParameters {
		want = append(want, parameter.Name)
	}
	got := append([]string(nil), receipt.Execution.SafeParameterNames...)
	sort.Strings(want)
	sort.Strings(got)
	if len(want) != len(got) {
		return errors.New("receipt parameters do not match catalog")
	}
	for i := range want {
		if want[i] != got[i] {
			return errors.New("receipt parameters do not match catalog")
		}
	}
	return nil
}

func slotAt(canary Canary, at time.Time) int64 {
	return at.UTC().Unix() / int64(canary.IntervalMinutes*60)
}
func nextDueAfter(canary Canary, now time.Time, jitter int, operationID string) time.Time {
	slot := slotAt(canary, now)
	due := dueForSlot(canary, slot, jitter, operationID)
	if !due.After(now) {
		due = dueForSlot(canary, slot+1, jitter, operationID)
	}
	return due
}
func dueForSlot(canary Canary, slot int64, jitter int, operationID string) time.Time {
	jitterOffset := deterministicJitter(operationID, slot, jitter)
	return time.Unix(slot*int64(canary.IntervalMinutes*60)+int64(jitterOffset), 0).UTC()
}
func deterministicJitter(operationID string, slot int64, max int) int {
	if max <= 0 {
		return 0
	}
	h := sha256.New()
	_, _ = h.Write([]byte(operationID))
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(slot))
	_, _ = h.Write(buf[:])
	return int(binary.BigEndian.Uint64(h.Sum(nil)[:8]) % uint64(max+1))
}

func (s *Scheduler) Wait() { s.wg.Wait() }
func (s *Scheduler) Metrics() MetricsSnapshot {
	s.metrics.mu.Lock()
	defer s.metrics.mu.Unlock()
	return MetricsSnapshot{RunsStarted: s.metrics.RunsStarted, RunsCompleted: s.metrics.RunsCompleted, RunsFailed: s.metrics.RunsFailed, RunsSkippedCapacity: s.metrics.RunsSkippedCapacity, DeliveryFailed: s.metrics.DeliveryFailed, LastCompleted: s.metrics.LastCompleted}
}
func (m *SchedulerMetrics) incStarted() { m.mu.Lock(); m.RunsStarted++; m.mu.Unlock() }
func (m *SchedulerMetrics) incCompleted() {
	m.mu.Lock()
	m.RunsCompleted++
	m.LastCompleted = time.Now().UTC()
	m.mu.Unlock()
}
func (m *SchedulerMetrics) incFailed()          { m.mu.Lock(); m.RunsFailed++; m.mu.Unlock() }
func (m *SchedulerMetrics) incSkippedCapacity() { m.mu.Lock(); m.RunsSkippedCapacity++; m.mu.Unlock() }
func (m *SchedulerMetrics) incDeliveryFailed()  { m.mu.Lock(); m.DeliveryFailed++; m.mu.Unlock() }

func (s *Scheduler) String() string {
	return fmt.Sprintf("scheduler(canaries=%d)", len(s.config.Canaries))
}
