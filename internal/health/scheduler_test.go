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
	mu      sync.Mutex
	runs    int
	started chan struct{}
	release chan struct{}
	file    string
}

func (r *fakeProbeRunner) Run(_ context.Context, _ Canary, entry CatalogEntry, output string) error {
	r.mu.Lock()
	r.runs++
	r.mu.Unlock()
	if r.started != nil {
		r.started <- struct{}{}
	}
	if r.release != nil {
		<-r.release
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
	return os.WriteFile(output, raw, 0o600)
}
func (r *fakeProbeRunner) count() int { r.mu.Lock(); defer r.mu.Unlock(); return r.runs }

type fakeDeliverer struct {
	mu    sync.Mutex
	paths []string
	fail  error
}

func (d *fakeDeliverer) Deliver(_ context.Context, path string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paths = append(d.paths, path)
	return d.fail
}
func (d *fakeDeliverer) count() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.paths) }

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
