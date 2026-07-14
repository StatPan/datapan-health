package health

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeProbeRunner struct {
	mu                  sync.Mutex
	runs                int
	started             chan struct{}
	release             chan struct{}
	file                string
	err                 error
	deadlineRemaining   time.Duration
	waitForCancellation bool
}

func (r *fakeProbeRunner) Run(ctx context.Context, _ Canary, entry CatalogEntry, output string) error {
	r.mu.Lock()
	r.runs++
	if deadline, ok := ctx.Deadline(); ok {
		r.deadlineRemaining = time.Until(deadline)
	}
	r.mu.Unlock()
	if r.started != nil {
		r.started <- struct{}{}
	}
	if r.release != nil {
		<-r.release
	}
	if r.waitForCancellation {
		<-ctx.Done()
		return ctx.Err()
	}
	raw, err := os.ReadFile(r.file)
	if err != nil {
		return err
	}
	// Fixtures use the two reviewed Registry canaries; the runner itself does
	// not manufacture a receipt or exercise a provider.
	if entry.OperationID == "dpr-op-00000002" {
		raw, err = os.ReadFile("../../testdata/receipts/v1/unhealthy.json")
	}
	if err != nil {
		return err
	}
	if err := os.WriteFile(output, raw, 0o600); err != nil {
		return err
	}
	return r.err
}
func (r *fakeProbeRunner) count() int { r.mu.Lock(); defer r.mu.Unlock(); return r.runs }
func (r *fakeProbeRunner) deadline() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.deadlineRemaining
}

type fakeDeliverer struct {
	mu       sync.Mutex
	paths    []string
	receipts []Receipt
	fail     error
}

func (d *fakeDeliverer) Deliver(_ context.Context, path string) error {
	receipt, err := ReadReceipt(path)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paths = append(d.paths, path)
	d.receipts = append(d.receipts, receipt)
	return d.fail
}
func (d *fakeDeliverer) count() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.paths) }
func (d *fakeDeliverer) lastReceipt(t *testing.T) Receipt {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.receipts) == 0 {
		t.Fatal("no delivered receipt")
	}
	return d.receipts[len(d.receipts)-1]
}

func schedulerConfig(t *testing.T, concurrency int) CanaryConfig {
	t.Helper()
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	config.GlobalConcurrency = concurrency
	return config
}

func TestTierSlotsAndJitterAreDeterministicAndBounded(t *testing.T) {
	for _, canary := range []Canary{{Tier: "A", IntervalMinutes: 5}, {Tier: "B", IntervalMinutes: 10}, {Tier: "C", IntervalMinutes: 15}} {
		at := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
		one := nextDueAfter(canary, at, 30, "dpr-op-test")
		two := nextDueAfter(canary, at, 30, "dpr-op-test")
		if !one.Equal(two) || one.Sub(at) < 0 || one.Sub(at) >= time.Duration(canary.IntervalMinutes)*time.Minute {
			t.Fatalf("tier %s has unbounded or unstable jitter: %s", canary.Tier, one.Sub(at))
		}
		if dueForSlot(canary, 42, 30, "dpr-op-test") != dueForSlot(canary, 42, 30, "dpr-op-test") {
			t.Fatal("slot jitter changed")
		}
	}
}

func TestSchedulerDeliversOneCanonicalReceiptAndDoesNotRetryProvider(t *testing.T) {
	config := schedulerConfig(t, 2)
	config.Canaries = config.Canaries[:1]
	runner := &fakeProbeRunner{file: "../../testdata/receipts/v1/healthy.json", started: make(chan struct{}, 2)}
	delivery := &fakeDeliverer{}
	s, err := NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), runner, delivery)
	if err != nil {
		t.Fatal(err)
	}
	canary := config.Canaries[0]
	now := time.Date(2026, 7, 13, 0, 0, 0, 0, time.UTC)
	if err := s.ProcessDue(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	due := nextDueAfter(canary, now, config.JitterSeconds, canary.OperationID)
	if err := s.ProcessDue(context.Background(), due); err != nil {
		t.Fatal(err)
	}
	<-runner.started
	s.Wait()
	if runner.count() != 1 || delivery.count() != 1 {
		t.Fatalf("want one CLI invocation and one adapter delivery, got cli=%d delivery=%d", runner.count(), delivery.count())
	}
	if err := s.ProcessDue(context.Background(), due); err != nil {
		t.Fatal(err)
	}
	if runner.count() != 1 {
		t.Fatal("completed slot was executed twice")
	}
}

func TestSchedulerCapsConcurrencyAndPreventsOverlap(t *testing.T) {
	config := schedulerConfig(t, 1)
	runner := &fakeProbeRunner{file: "../../testdata/receipts/v1/healthy.json", started: make(chan struct{}, 2), release: make(chan struct{}, 2)}
	delivery := &fakeDeliverer{}
	s, err := NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), runner, delivery)
	if err != nil {
		t.Fatal(err)
	}
	first, second := config.Canaries[0], config.Canaries[1]
	firstDue := dueForSlot(first, 1000, config.JitterSeconds, first.OperationID)
	secondDue := dueForSlot(second, 1000, config.JitterSeconds, second.OperationID)
	s.mu.Lock()
	s.state.Slots[first.OperationID] = slotRecord{NextDue: firstDue}
	s.state.Slots[second.OperationID] = slotRecord{NextDue: secondDue}
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	if err := s.ProcessDue(context.Background(), firstDue); err != nil {
		t.Fatal(err)
	}
	<-runner.started
	if err := s.ProcessDue(context.Background(), secondDue); err != nil {
		t.Fatal(err)
	}
	if runner.count() != 1 {
		t.Fatal("global concurrency cap was bypassed")
	}
	// A second tick for the active canary must not overlap it.
	if err := s.ProcessDue(context.Background(), firstDue); err != nil {
		t.Fatal(err)
	}
	if runner.count() != 1 {
		t.Fatal("canary overlap was allowed")
	}
	runner.release <- struct{}{}
	s.Wait()
}

func TestRestartClaimsSlotBeforeExecutionAndSkipsCatchup(t *testing.T) {
	config := schedulerConfig(t, 1)
	state := filepath.Join(t.TempDir(), "state.json")
	runner := &fakeProbeRunner{file: "../../testdata/receipts/v1/healthy.json", started: make(chan struct{}, 1), release: make(chan struct{}, 1)}
	delivery := &fakeDeliverer{}
	first, err := NewScheduler(config, state, runner, delivery)
	if err != nil {
		t.Fatal(err)
	}
	canary := config.Canaries[0]
	due := dueForSlot(canary, 2000, config.JitterSeconds, canary.OperationID)
	first.mu.Lock()
	first.state.Slots[canary.OperationID] = slotRecord{NextDue: due}
	if err := first.saveLocked(); err != nil {
		first.mu.Unlock()
		t.Fatal(err)
	}
	first.mu.Unlock()
	if err := first.ProcessDue(context.Background(), due); err != nil {
		t.Fatal(err)
	}
	<-runner.started
	restartedRunner := &fakeProbeRunner{file: "../../testdata/receipts/v1/healthy.json"}
	restarted, err := NewScheduler(config, state, restartedRunner, &fakeDeliverer{})
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.ProcessDue(context.Background(), due); err != nil {
		t.Fatal(err)
	}
	if restartedRunner.count() != 0 {
		t.Fatal("restart replayed a claimed schedule slot")
	}
	// Far after the slot, a fresh scheduler advances to a future slot without a burst.
	if err := restarted.ProcessDue(context.Background(), due.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if restartedRunner.count() != 0 {
		t.Fatal("restart created a catch-up storm")
	}
	runner.release <- struct{}{}
	first.Wait()
}

func TestCatalogReceiptValidationRejectsSemanticDrift(t *testing.T) {
	config := schedulerConfig(t, 1)
	entry, _ := config.Entry(config.Canaries[0])
	receipt, err := ReadReceipt("../../testdata/receipts/v1/healthy.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCatalogReceipt(receipt, entry); err != nil {
		t.Fatal(err)
	}
	receipt.Execution.RequestBudget = 2
	if err := validateCatalogReceipt(receipt, entry); err == nil {
		t.Fatal("catalog request budget drift was accepted")
	}
}

func TestCLIHealthArgsUseReviewedCatalogTimeout(t *testing.T) {
	config := schedulerConfig(t, 1)
	entry, _ := config.Entry(config.Canaries[0])
	entry.Execution.TimeoutCeilingMS = 15000
	got := cliHealthArgs(entry, "/tmp/receipt.json")
	want := []string{"verify", "--ref", entry.Aliases.DatasetID, "--operation", entry.Aliases.OperationName, "--health", "--timeout", "15s", "--output", "/tmp/receipt.json", "--json"}
	if len(got) != len(want) {
		t.Fatalf("args length=%d want=%d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg[%d]=%q want=%q", i, got[i], want[i])
		}
	}
}

func TestSchedulerTimeoutProducesRedactedFallbackAndReplacesStaleSuccess(t *testing.T) {
	config := schedulerConfig(t, 1)
	config.Canaries = config.Canaries[:1]
	canary := config.Canaries[0]
	entry, _ := config.Entry(canary)
	// The catalog loader validates production ceilings. A shorter in-memory
	// value keeps this cancellation test fast while exercising the same path.
	entry.Execution.TimeoutCeilingMS = 1
	config.catalog.byID[canary.OperationID] = entry
	runner := &fakeProbeRunner{started: make(chan struct{}, 1), waitForCancellation: true}
	delivery := &fakeDeliverer{}
	s, err := NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), runner, delivery)
	if err != nil {
		t.Fatal(err)
	}
	due := dueForSlot(canary, 3000, config.JitterSeconds, canary.OperationID)
	s.mu.Lock()
	s.state.Slots[canary.OperationID] = slotRecord{NextDue: due}
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	if err := s.ProcessDue(context.Background(), due); err != nil {
		t.Fatal(err)
	}
	<-runner.started
	s.Wait()
	if got := runner.deadline(); got < 900*time.Millisecond || got > 1100*time.Millisecond {
		t.Fatalf("scheduler deadline=%s, want catalog ceiling plus bounded receipt grace", got)
	}
	if delivery.count() != 1 {
		t.Fatalf("receipt-less timeout was not delivered: deliveries=%d", delivery.count())
	}
	receipt := delivery.lastReceipt(t)
	if receipt.Assessment.Outcome != "indeterminate" || receipt.Assessment.Category != "timeout" || receipt.Assessment.ReasonCode != "scheduler_timeout_without_cli_receipt" {
		t.Fatalf("unexpected fallback assessment: %#v", receipt.Assessment)
	}
	if !receipt.Redaction.CredentialsRemoved || !receipt.Redaction.QueryValuesRemoved || !receipt.Redaction.ResponseRowsRemoved || Summarize(receipt, canary.GatusEndpointKey).Success {
		t.Fatal("receipt-less timeout could leak data or preserve a stale healthy status")
	}
}

func TestSchedulerPreservesCLIReceiptWhenExitIsNonzero(t *testing.T) {
	config := schedulerConfig(t, 1)
	config.Canaries = config.Canaries[:1]
	runner := &fakeProbeRunner{file: "../../testdata/receipts/v1/healthy.json", started: make(chan struct{}, 1), err: context.DeadlineExceeded}
	delivery := &fakeDeliverer{}
	s, err := NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), runner, delivery)
	if err != nil {
		t.Fatal(err)
	}
	canary := config.Canaries[0]
	due := dueForSlot(canary, 4000, config.JitterSeconds, canary.OperationID)
	s.mu.Lock()
	s.state.Slots[canary.OperationID] = slotRecord{NextDue: due}
	if err := s.saveLocked(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	if err := s.ProcessDue(context.Background(), due); err != nil {
		t.Fatal(err)
	}
	<-runner.started
	s.Wait()
	if delivery.count() != 1 || delivery.lastReceipt(t).Assessment.Outcome != "healthy" {
		t.Fatal("a valid CLI receipt was discarded because of a nonzero exit")
	}
}

func TestReviewedCatalogContainsTenBoundedCanaries(t *testing.T) {
	config := schedulerConfig(t, 2)
	if len(config.Canaries) != 10 || len(config.catalog.Entries) != 10 {
		t.Fatalf("canary/catalog boundary changed: canaries=%d entries=%d", len(config.Canaries), len(config.catalog.Entries))
	}
	classes := map[string]int{}
	for _, canary := range config.Canaries {
		entry, ok := config.Entry(canary)
		if !ok || entry.Execution.TimeoutCeilingMS < 1000 || entry.Execution.TimeoutCeilingMS > 30000 || entry.Execution.RequestBudget != 1 {
			t.Fatalf("invalid reviewed execution boundary for %s", canary.OperationID)
		}
		classes[entry.Endpoint.DependencyClass]++
	}
	if classes["data_go_kr_gateway"] != 5 || classes["external_endpoint"] != 5 {
		t.Fatalf("routing coverage changed: %#v", classes)
	}
}
