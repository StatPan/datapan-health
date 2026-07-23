package health

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func fullSchedulePlan(t *testing.T, at time.Time, shards int) (ScheduleCoveragePlan, []ScheduledOperation) {
	t.Helper()
	manifest, receipt, err := LoadPinnedOperationManifest(pinnedOperationManifestFixture, pinnedReleaseManifestFixture, pinnedOperationManifestReceipt)
	if err != nil {
		t.Fatal(err)
	}
	plan, queue, err := BuildScheduleCoveragePlan(manifest, receipt, at, shards)
	if err != nil {
		t.Fatal(err)
	}
	return plan, queue
}

func TestFullPopulationScheduleAssignsEveryRegistryIdentityExactlyOnce(t *testing.T) {
	plan, queue := fullSchedulePlan(t, time.Date(2026, 7, 23, 0, 4, 59, 0, time.UTC), 64)
	if len(queue) != 12385 || plan.Interval.Start != time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC) || plan.Interval.DurationSeconds != 600 || plan.Registry.Revision != "420edc34b16d1243e2a2389226615fff9e5b708f" {
		t.Fatalf("unexpected full schedule plan: %#v queue=%d", plan, len(queue))
	}
	seen := make(map[string]bool, len(queue))
	for _, item := range queue {
		if seen[item.Subject] || item.Shard != scheduleShard(item.Subject, plan.Scheduler.ShardCount) || item.Registry != plan.Registry || !item.IntervalStart.Equal(plan.Interval.Start) {
			t.Fatalf("identity was not assigned exactly once: %#v", item)
		}
		seen[item.Subject] = true
	}
	if len(seen) != 12385 {
		t.Fatalf("unassigned or duplicate identities: seen=%d", len(seen))
	}
	if err := VerifyScheduleCoveragePlan(plan, queue); err != nil {
		t.Fatal(err)
	}
	ledger, err := NewScheduleCoverageLedger(plan, queue)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ledger.CoverageReceipt(plan.Interval.Start)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Aggregate != (ScheduleCoverageCounts{Expected: 12385, Assigned: 12385, Attempted: 0, Completed: 0, Late: 0, Missing: 12385}) || len(receipt.Shards) != 64 {
		t.Fatalf("queue proof confused schedule with execution: %#v", receipt.Aggregate)
	}
}

func TestFullPopulationScheduleCannotCollapseToMetadataOrCanaries(t *testing.T) {
	plan, queue := fullSchedulePlan(t, time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC), 31)
	if len(plan.Shards) != 31 || len(queue) != 12385 {
		t.Fatal("unexpected schedule cardinality")
	}
	manifest, _, err := LoadPinnedOperationManifest(pinnedOperationManifestFixture, pinnedReleaseManifestFixture, pinnedOperationManifestReceipt)
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string]func(ManifestOperation) string{
		"api":     func(operation ManifestOperation) string { return operation.Provenance.SourceURL },
		"dataset": func(operation ManifestOperation) string { return operation.Provenance.DatasetID },
		"host":    endpointHost,
		"endpoint": func(operation ManifestOperation) string {
			if operation.Transport.Endpoint == nil {
				return ""
			}
			return *operation.Transport.Endpoint
		},
	}
	for name, key := range groups {
		metadata := map[string]bool{}
		for _, operation := range manifest.Operations {
			metadata[key(operation)] = true
		}
		if len(metadata) >= len(queue) {
			t.Fatalf("fixture does not demonstrate %s aggregation", name)
		}
		if len(queue) != 12385 {
			t.Fatalf("%s aggregation changed operation queue", name)
		}
	}
	if len(queue) == 10 {
		t.Fatal("separate ten-canary catalog was used as the full operation queue")
	}
}

func TestScheduleHasOneDueSlotPerIdentityPerTenMinuteInterval(t *testing.T) {
	firstAt := time.Date(2026, 7, 23, 0, 3, 0, 0, time.UTC)
	first, firstQueue := fullSchedulePlan(t, firstAt, 64)
	same, sameQueue := fullSchedulePlan(t, firstAt.Add(6*time.Minute), 64)
	next, nextQueue := fullSchedulePlan(t, firstAt.Add(10*time.Minute), 64)
	if !same.Interval.Start.Equal(first.Interval.Start) || !next.Interval.Start.Equal(first.Interval.Start.Add(10*time.Minute)) {
		t.Fatalf("ten-minute due windows drifted: first=%s same=%s next=%s", first.Interval.Start, same.Interval.Start, next.Interval.Start)
	}
	for index := range firstQueue {
		if firstQueue[index].Subject != sameQueue[index].Subject || firstQueue[index].Subject != nextQueue[index].Subject || firstQueue[index].Shard != sameQueue[index].Shard || firstQueue[index].Shard != nextQueue[index].Shard || !firstQueue[index].IntervalStart.Equal(first.Interval.Start) || !sameQueue[index].IntervalStart.Equal(same.Interval.Start) || !nextQueue[index].IntervalStart.Equal(next.Interval.Start) {
			t.Fatalf("identity did not receive exactly one stable due slot")
		}
	}
}

func TestScheduleLeaseRetryDelayCrashAndRebalanceFenceAuthoritativeCompletion(t *testing.T) {
	at := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	plan, queue := fullSchedulePlan(t, at, 64)
	ledger, err := NewScheduleCoverageLedger(plan, queue)
	if err != nil {
		t.Fatal(err)
	}
	subject := queue[0].Subject
	first, err := ledger.Claim(subject, at, 2*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Claim(subject, at.Add(time.Minute), time.Minute); !errors.Is(err, ErrScheduleLeaseHeld) {
		t.Fatalf("concurrent lease was accepted: %v", err)
	}
	if err := ledger.Retry(first); err != nil {
		t.Fatal(err)
	}
	retry, err := ledger.Claim(subject, at.Add(time.Minute), 2*time.Minute)
	if err != nil || retry.Generation != first.Generation+1 {
		t.Fatalf("retry did not advance fencing generation: claim=%#v err=%v", retry, err)
	}
	if err := ledger.Complete(first, at.Add(time.Minute)); !errors.Is(err, ErrScheduleFenced) {
		t.Fatalf("abandoned attempt completed authoritatively: %v", err)
	}
	if err := ledger.Complete(retry, at.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Claim(subject, at.Add(4*time.Minute), time.Minute); !errors.Is(err, ErrScheduleComplete) {
		t.Fatalf("completed work was claimed twice: %v", err)
	}

	crashSubject := queue[1].Subject
	crashed, err := ledger.Claim(crashSubject, at, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := RestoreScheduleCoverageLedger(ledger.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	afterRestart, err := restarted.Claim(crashSubject, at.Add(2*time.Minute), 20*time.Minute)
	if err != nil || afterRestart.Generation != crashed.Generation+1 {
		t.Fatalf("expired crash lease was not safely recovered: claim=%#v err=%v", afterRestart, err)
	}
	if err := restarted.Complete(crashed, at.Add(2*time.Minute)); !errors.Is(err, ErrScheduleFenced) {
		t.Fatalf("pre-crash worker completed after restart: %v", err)
	}
	if err := restarted.Complete(afterRestart, at.Add(11*time.Minute)); err != nil {
		t.Fatal(err)
	}
	receipt, err := restarted.CoverageReceipt(at.Add(12 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Aggregate.Attempted != 2 || receipt.Aggregate.Completed != 2 || receipt.Aggregate.Late != 1 || receipt.Aggregate.Missing != 12383 {
		t.Fatalf("retry/delay coverage counts are wrong: %#v", receipt.Aggregate)
	}

	rebalanced, rebalancedQueue := fullSchedulePlan(t, at, 127)
	if rebalanced.Registry != plan.Registry || len(rebalancedQueue) != len(queue) {
		t.Fatal("shard rebalance changed the Registry identity universe")
	}
	before, after := map[string]bool{}, map[string]bool{}
	for _, item := range queue {
		before[item.Subject] = true
	}
	for _, item := range rebalancedQueue {
		if after[item.Subject] || !before[item.Subject] {
			t.Fatalf("rebalance lost or duplicated identity: %#v", item)
		}
		after[item.Subject] = true
	}
	if len(after) != len(before) {
		t.Fatalf("rebalance coverage changed: before=%d after=%d", len(before), len(after))
	}
}

func TestScheduleCoverageReceiptRejectsAggregateAndLeakDrift(t *testing.T) {
	at := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	plan, queue := fullSchedulePlan(t, at, 8)
	ledger, err := NewScheduleCoverageLedger(plan, queue)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := ledger.CoverageReceipt(at)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]any){
		func(document map[string]any) { document["aggregate"].(map[string]any)["missing"] = float64(0) },
		func(document map[string]any) {
			document["provider_url"] = "https://provider.example/?serviceKey=not-a-secret"
		},
	} {
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			t.Fatal(err)
		}
		mutate(document)
		mutated, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		_, err = DecodeScheduleCoverageReceipt(strings.NewReader(string(mutated)))
		if err == nil || strings.Contains(err.Error(), "not-a-secret") {
			t.Fatalf("unsafe or inconsistent schedule receipt was accepted: %v", err)
		}
	}
}
