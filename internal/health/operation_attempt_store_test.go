package health

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOperationAttemptStorePersistsReceiptBeforeIndependentDeliveryRetry(t *testing.T) {
	root := t.TempDir()
	first, err := OpenOperationAttemptStore(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := OpenOperationAttemptStore(root)
	if err != nil {
		t.Fatal(err)
	}
	binding := testOperationAttemptBinding()
	started := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	claim, err := first.BeginAttempt(binding, strings.Repeat("a", 64), started, time.Minute)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := second.BeginAttempt(binding, strings.Repeat("b", 64), started.Add(time.Second), time.Minute); !errors.Is(err, ErrOperationAttemptHeld) {
		t.Fatalf("concurrent worker could claim same operation: %v", err)
	}
	observedAt := started.Add(2 * time.Second)
	result := OperationObservationResult{State: "healthy", Category: "healthy", ObservedAt: observedAt, ReceiptSHA: strings.Repeat("c", 64), LatencyMS: 125}
	if err := first.CompleteAttempt(claim, result, started.Add(3*time.Second)); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if err := first.FailAttempt(claim, started.Add(4*time.Second)); !errors.Is(err, ErrOperationAttemptFenced) {
		t.Fatalf("completed claim was reused: %v", err)
	}
	stored, ok, err := second.Latest(binding.SourceID, binding.OperationID)
	if err != nil || !ok || stored.State != "observed" || stored.Result == nil || !stored.Result.ObservedAt.Equal(observedAt) || stored.DeliveryState != "not_ready" {
		t.Fatalf("durable receipt was not available before publication: %#v %v", stored, err)
	}

	delivery1, err := first.ClaimDelivery(binding.SourceID, binding.OperationID, claim.AttemptID, claim.Generation, started.Add(4*time.Second), 5*time.Second)
	if err != nil {
		t.Fatalf("claim first delivery: %v", err)
	}
	if _, err := second.ClaimDelivery(binding.SourceID, binding.OperationID, claim.AttemptID, claim.Generation, started.Add(5*time.Second), 5*time.Second); !errors.Is(err, ErrOperationAttemptHeld) {
		t.Fatalf("concurrent delivery was not fenced: %v", err)
	}
	// Reopen after an ambiguous sender loss. The summary may be accepted twice
	// by Gatus, but this retry never re-enters the provider-attempt state.
	second, err = OpenOperationAttemptStore(root)
	if err != nil {
		t.Fatal(err)
	}
	delivery2, err := second.ClaimDelivery(binding.SourceID, binding.OperationID, claim.AttemptID, claim.Generation, started.Add(10*time.Second), 5*time.Second)
	if err != nil || delivery2.AttemptCount != 2 || delivery2.DeliveryGeneration != delivery1.DeliveryGeneration+1 {
		t.Fatalf("delivery retry state was not recovered: %#v %v", delivery2, err)
	}
	if err := first.AcknowledgeDelivery(delivery1, started.Add(11*time.Second)); !errors.Is(err, ErrOperationAttemptFenced) {
		t.Fatalf("stale delivery claim acknowledged a retry: %v", err)
	}
	responseAt := started.Add(12 * time.Second)
	if err := second.AcknowledgeDelivery(delivery2, responseAt); err != nil {
		t.Fatalf("acknowledge retry: %v", err)
	}
	gatusReceivedAt := started.Add(15 * time.Second)
	if err := first.RecordGatusReadback(binding.SourceID, binding.OperationID, claim.AttemptID, claim.Generation, gatusReceivedAt, "healthy"); err != nil {
		t.Fatalf("record per-key Gatus readback: %v", err)
	}
	stored, ok, err = first.Latest(binding.SourceID, binding.OperationID)
	if err != nil || !ok || !stored.Result.ObservedAt.Equal(observedAt) || !stored.DeliveryAckAt.Equal(responseAt) || !stored.GatusReceivedAt.Equal(gatusReceivedAt) {
		t.Fatalf("provider time and delivery/readback times were conflated: %#v %v", stored, err)
	}
	if _, err := first.BeginAttempt(binding, strings.Repeat("d", 64), started.Add(4*time.Minute), time.Minute); !errors.Is(err, ErrOperationAttemptNotDue) {
		t.Fatalf("observation cadence was bypassed: %v", err)
	}
	if _, err := first.BeginAttempt(binding, strings.Repeat("e", 64), started.Add(5*time.Minute), time.Minute); err != nil {
		t.Fatalf("next scheduled observation was not admitted: %v", err)
	}
}

func TestOperationAttemptSnapshotSeparatesClaimReceiptObservationAndReadback(t *testing.T) {
	store, err := OpenOperationAttemptStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 10, 7, 5, 0, 0, 0, time.UTC)
	model := testOperationReadModelForStore(t, started)
	binding := testOperationReadModelAttemptBinding(t, model, "synthetic_test", "synthetic-rest-list")
	claim, err := store.BeginAttempt(binding, strings.Repeat("9", 64), started, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	if err := model.RefreshFromStore(store, started.Add(time.Second)); err != nil {
		t.Fatalf("refresh claim snapshot: %v", err)
	}
	page, err := model.PageOperations(OperationPageQuery{Query: "synthetic-rest-list", Limit: 10}, started.Add(time.Second))
	if err != nil || len(page.Operations) != 1 {
		t.Fatalf("read claimed operation: %#v %v", page, err)
	}
	claimed := page.Operations[0]
	if claimed.AttemptState != "claimed" || claimed.Attempted || claimed.RequestStarted != nil || claimed.HealthReceivedAt != nil {
		t.Fatalf("durable claim was misreported as provider traffic: %#v", claimed)
	}

	providerObserved := started.Add(20 * time.Second)
	healthReceived := started.Add(25 * time.Second)
	result := OperationObservationResult{State: "healthy", Category: "healthy", ObservedAt: providerObserved, ReceiptSHA: strings.Repeat("8", 64), LatencyMS: 400}
	if err := store.CompleteAttempt(claim, result, healthReceived); err != nil {
		t.Fatalf("persist validated receipt: %v", err)
	}
	if err := model.RefreshFromStore(store, healthReceived.Add(time.Second)); err != nil {
		t.Fatalf("refresh observed result: %v", err)
	}
	page, err = model.PageOperations(OperationPageQuery{Query: "synthetic-rest-list", Limit: 10}, healthReceived.Add(time.Second))
	if err != nil || len(page.Operations) != 1 {
		t.Fatalf("read observed operation: %#v %v", page, err)
	}
	observed := page.Operations[0]
	if !observed.Attempted || observed.AttemptState != "observed" || observed.RequestStarted == nil || !*observed.RequestStarted || observed.ProviderObservedAt == nil || observed.HealthReceivedAt == nil || !observed.ProviderObservedAt.Equal(providerObserved) || !observed.HealthReceivedAt.Equal(healthReceived) || observed.GatusDeliveryState != "pending" {
		t.Fatalf("validated request, provider observation, persistence, or pending delivery was conflated: %#v", observed)
	}

	delivery, err := store.ClaimDelivery(binding.SourceID, binding.OperationID, claim.AttemptID, claim.Generation, healthReceived.Add(2*time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	acknowledgedAt := healthReceived.Add(3 * time.Second)
	if err := store.AcknowledgeDelivery(delivery, acknowledgedAt); err != nil {
		t.Fatal(err)
	}
	if err := model.RefreshFromStore(store, acknowledgedAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	page, err = model.PageOperations(OperationPageQuery{Query: "synthetic-rest-list", Limit: 10}, acknowledgedAt.Add(time.Second))
	if err != nil || len(page.Operations) != 1 || page.Operations[0].GatusDeliveryState != "acknowledged" || page.Operations[0].GatusReadbackAt != nil {
		t.Fatalf("HTTP acknowledgement was treated as Gatus readback: %#v %v", page, err)
	}

	readbackAt := acknowledgedAt.Add(2 * time.Second)
	if err := store.RecordGatusReadback(binding.SourceID, binding.OperationID, claim.AttemptID, claim.Generation, readbackAt, "healthy"); err != nil {
		t.Fatal(err)
	}
	if err := model.RefreshFromStore(store, readbackAt.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	page, err = model.PageOperations(OperationPageQuery{Query: "synthetic-rest-list", Limit: 10}, readbackAt.Add(time.Second))
	if err != nil || len(page.Operations) != 1 || page.Operations[0].GatusDeliveryState != "readback_verified" || page.Operations[0].GatusReadbackAt == nil || !page.Operations[0].GatusReadbackAt.Equal(readbackAt) {
		t.Fatalf("per-key readback was not recorded independently: %#v %v", page, err)
	}

	// A later claim is not a provider attempt and must not erase the last
	// persisted observation while the worker is running.
	next, err := store.BeginAttempt(binding, strings.Repeat("7", 64), started.Add(time.Hour), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := model.RefreshFromStore(store, started.Add(time.Hour+time.Second)); err != nil {
		t.Fatal(err)
	}
	page, err = model.PageOperations(OperationPageQuery{Query: "synthetic-rest-list", Limit: 10}, started.Add(time.Hour+time.Second))
	if err != nil || len(page.Operations) != 1 {
		t.Fatalf("read newer claim: %#v %v", page, err)
	}
	latest := page.Operations[0]
	if latest.AttemptState != "claimed" || !latest.Attempted || latest.ProviderObservedAt == nil || !latest.ProviderObservedAt.Equal(providerObserved) || latest.GatusDeliveryState != "readback_verified" {
		t.Fatalf("new claim erased or promoted the previous durable observation: %#v", latest)
	}
	if err := store.RecordBlockedAttempt(next, strings.Repeat("6", 64), "credential_unavailable", started.Add(time.Hour+2*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestOperationReadModelRefreshFailureKeepsLastAtomicSnapshotAndPagesAvoidDisk(t *testing.T) {
	root := t.TempDir()
	store, err := OpenOperationAttemptStore(filepath.Join(root, "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 10, 7, 6, 0, 0, 0, time.UTC)
	model := testOperationReadModelForStore(t, started)
	binding := testOperationReadModelAttemptBinding(t, model, "synthetic_test", "synthetic-rest-list")
	claim, err := store.BeginAttempt(binding, strings.Repeat("5", 64), started, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteAttempt(claim, OperationObservationResult{State: "unhealthy", Category: "provider_failure", ObservedAt: started.Add(time.Second), ReceiptSHA: strings.Repeat("4", 64), LatencyMS: 10}, started.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := model.RefreshFromStore(store, started.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	before, err := model.PageOperations(OperationPageQuery{Query: "synthetic-rest-list", Limit: 10}, started.Add(3*time.Second))
	if err != nil || len(before.Operations) != 1 || before.Operations[0].ObservationState != "current_fail" {
		t.Fatalf("initial cached page is invalid: %#v %v", before, err)
	}

	// Corrupt the store after refresh. A page read must remain a pure in-memory
	// operation, and an explicitly failed refresh must not partially publish.
	statePath := store.statePath(binding.SourceID, binding.OperationID)
	if err := os.WriteFile(statePath, []byte(`{"corrupt":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := model.RefreshFromStore(store, started.Add(4*time.Second)); !errors.Is(err, ErrOperationReadModelUnavailable) {
		t.Fatalf("corrupt snapshot was accepted: %v", err)
	}
	after, err := model.PageOperations(OperationPageQuery{Query: "synthetic-rest-list", Limit: 10}, started.Add(4*time.Second))
	if err != nil || len(after.Operations) != 1 || after.Operations[0].ObservationState != "current_fail" || !after.Operations[0].ProviderObservedAt.Equal(*before.Operations[0].ProviderObservedAt) {
		t.Fatalf("failed refresh damaged the last good in-memory view: %#v %v", after, err)
	}
}

func TestOperationAttemptSnapshotKeepsPlanLineageAcrossRevisionChangeAndDelayedGatusReadback(t *testing.T) {
	rootA, planBindingA, _ := writeSyntheticOperationObservationPlanVersion(t, false, strings.Repeat("a", 40), 300)
	planA, err := LoadPinnedOperationObservationPlan(rootA, planBindingA)
	if err != nil {
		t.Fatal(err)
	}
	modelA, err := NewOperationReadModel(planA, testRegistryAPIMetadataPin(0, 0), nil, nil, time.Date(2026, 10, 7, 7, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}

	rootB, planBindingB, _ := writeSyntheticOperationObservationPlanVersion(t, false, strings.Repeat("b", 40), 600)
	planB, err := LoadPinnedOperationObservationPlan(rootB, planBindingB)
	if err != nil {
		t.Fatal(err)
	}
	modelB, err := NewOperationReadModel(planB, testRegistryAPIMetadataPin(0, 0), nil, nil, time.Date(2026, 10, 7, 7, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	bindingA := testOperationReadModelAttemptBinding(t, modelA, "synthetic_test", "synthetic-rest-list")
	bindingB := testOperationReadModelAttemptBinding(t, modelB, "synthetic_test", "synthetic-rest-list")
	if bindingA.RegistryRevision == bindingB.RegistryRevision || bindingA.IndexSHA == bindingB.IndexSHA || bindingA.ObservationPeriod == bindingB.ObservationPeriod {
		t.Fatal("synthetic Registry plan change did not alter revision, index, and cadence")
	}

	store, err := OpenOperationAttemptStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	started := time.Date(2026, 10, 7, 7, 0, 0, 0, time.UTC)
	claimA, err := store.BeginAttempt(bindingA, strings.Repeat("a", 64), started, time.Minute)
	if err != nil {
		t.Fatalf("claim under plan A: %v", err)
	}
	providerObserved := started.Add(20 * time.Second)
	healthReceived := started.Add(30 * time.Second)
	if err := store.CompleteAttempt(claimA, OperationObservationResult{State: "healthy", Category: "healthy", ObservedAt: providerObserved, ReceiptSHA: strings.Repeat("c", 64), LatencyMS: 10}, healthReceived); err != nil {
		t.Fatalf("persist plan A observation: %v", err)
	}

	claimBAt := started.Add(10 * time.Minute)
	claimB, err := store.BeginAttempt(bindingB, strings.Repeat("b", 64), claimBAt, time.Minute)
	if err != nil {
		t.Fatalf("claim under changed plan B at its cadence: %v", err)
	}
	// A's publisher was delayed until after B started. The readback remains
	// bound to A and must neither invalidate the snapshot nor appear under B.
	delivery, err := store.ClaimDelivery(bindingA.SourceID, bindingA.OperationID, claimA.AttemptID, claimA.Generation, claimBAt.Add(time.Minute), time.Minute)
	if err != nil {
		t.Fatalf("claim delayed plan A delivery: %v", err)
	}
	acknowledgedAt := claimBAt.Add(2 * time.Minute)
	if err := store.AcknowledgeDelivery(delivery, acknowledgedAt); err != nil {
		t.Fatalf("acknowledge delayed plan A delivery: %v", err)
	}
	readbackAt := claimBAt.Add(3 * time.Minute)
	if err := store.RecordGatusReadback(bindingA.SourceID, bindingA.OperationID, claimA.AttemptID, claimA.Generation, readbackAt, "healthy"); err != nil {
		t.Fatalf("record delayed plan A readback: %v", err)
	}

	snapshots, err := store.SnapshotReadModelAttempts()
	if err != nil || len(snapshots) != 1 {
		t.Fatalf("delayed delivery made the full snapshot unavailable: count=%d err=%v", len(snapshots), err)
	}
	snapshot := snapshots[0]
	if snapshot.LatestPlanBinding.IndexSHA != bindingB.IndexSHA || snapshot.ObservationPlanBinding == nil || snapshot.ObservationPlanBinding.IndexSHA != bindingA.IndexSHA || !snapshot.UpdatedAt.Equal(readbackAt) || snapshot.UpdatedAt.Before(claimB.StartedAt) {
		t.Fatalf("snapshot lost independent plan lineage or event watermark: %#v", snapshot)
	}

	if err := modelB.RefreshAttempts(snapshots, readbackAt.Add(time.Second)); err != nil {
		t.Fatalf("refresh changed plan B from valid A/B lineage: %v", err)
	}
	pageB, err := modelB.PageOperations(OperationPageQuery{Query: "synthetic-rest-list", Limit: 10}, readbackAt.Add(time.Second))
	if err != nil || len(pageB.Operations) != 1 {
		t.Fatalf("read plan B projection: %#v %v", pageB, err)
	}
	rowB := pageB.Operations[0]
	if rowB.AttemptState != "claimed" || rowB.Attempted || rowB.ObservationAttemptState != "none" || rowB.ResultState != "" || rowB.ProviderObservedAt != nil || rowB.HealthReceivedAt != nil || rowB.GatusDeliveryState != "not_ready" || pageB.IdentityCounts.Attempted != 0 {
		t.Fatalf("plan A receipt/readback was relabeled as plan B evidence: %#v", rowB)
	}

	if err := modelA.RefreshAttempts(snapshots, readbackAt.Add(time.Second)); err != nil {
		t.Fatalf("refresh old plan model with newer plan claim: %v", err)
	}
	pageA, err := modelA.PageOperations(OperationPageQuery{Query: "synthetic-rest-list", Limit: 10}, readbackAt.Add(time.Second))
	if err != nil || len(pageA.Operations) != 1 || pageA.Operations[0].ObservationAttemptState != "none" || pageA.Operations[0].ProviderObservedAt != nil {
		t.Fatalf("old plan model exposed a newer plan result or stale claim: %#v %v", pageA, err)
	}

	// The store's sticky request-start history remains visible when the latest
	// claim is under the same pinned plan, even if that provider response was
	// lost. It must not leak across the plan change tested above.
	lostReceiptStore, err := OpenOperationAttemptStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lostClaim, err := lostReceiptStore.BeginAttempt(bindingA, strings.Repeat("d", 64), started, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := lostReceiptStore.RecordRequestStartedWithoutObservation(lostClaim, strings.Repeat("e", 64), started.Add(time.Second)); err != nil {
		t.Fatalf("record validated request without response: %v", err)
	}
	if _, err := lostReceiptStore.BeginAttempt(bindingA, strings.Repeat("f", 64), started.Add(5*time.Minute), time.Minute); err != nil {
		t.Fatalf("start another observation under same plan: %v", err)
	}
	lostSnapshots, err := lostReceiptStore.SnapshotReadModelAttempts()
	if err != nil || len(lostSnapshots) != 1 || !lostSnapshots[0].EverRequestStarted {
		t.Fatalf("same-plan request-start history was lost: %#v %v", lostSnapshots, err)
	}
	if err := modelA.RefreshAttempts(lostSnapshots, started.Add(5*time.Minute+time.Second)); err != nil {
		t.Fatalf("refresh same-plan sticky history: %v", err)
	}
	lostPage, err := modelA.PageOperations(OperationPageQuery{Query: "synthetic-rest-list", Limit: 10}, started.Add(5*time.Minute+time.Second))
	if err != nil || len(lostPage.Operations) != 1 || !lostPage.Operations[0].Attempted || lostPage.IdentityCounts.Attempted != 1 {
		t.Fatalf("same-plan request-start history was not counted: %#v %v", lostPage, err)
	}
}

func TestOperationAttemptStoreFencesExpiredWorkerAndRetainsAmbiguousOutcome(t *testing.T) {
	store, err := OpenOperationAttemptStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binding := testOperationAttemptBinding()
	started := time.Date(2026, 10, 7, 1, 0, 0, 0, time.UTC)
	claim, err := store.BeginAttempt(binding, strings.Repeat("1", 64), started, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BeginAttempt(binding, strings.Repeat("2", 64), started.Add(time.Second), time.Second); !errors.Is(err, ErrOperationAttemptAmbiguous) {
		t.Fatalf("expired process was not recorded as ambiguous: %v", err)
	}
	if err := store.CompleteAttempt(claim, OperationObservationResult{State: "healthy", Category: "healthy", ObservedAt: started.Add(500 * time.Millisecond), ReceiptSHA: strings.Repeat("3", 64)}, started.Add(2*time.Second)); !errors.Is(err, ErrOperationAttemptFenced) {
		t.Fatalf("stale worker completed after expiry: %v", err)
	}
	latest, ok, err := store.Latest(binding.SourceID, binding.OperationID)
	if err != nil || !ok || latest.State != "unknown" || latest.Result != nil {
		t.Fatalf("ambiguous attempt was promoted: %#v %v", latest, err)
	}
	if _, err := store.BeginAttempt(binding, strings.Repeat("4", 64), started.Add(4*time.Minute), time.Minute); !errors.Is(err, ErrOperationAttemptNotDue) {
		t.Fatalf("immediate replay after ambiguity was allowed: %v", err)
	}
	rollover := binding
	rollover.RegistryRevision = strings.Repeat("f", 40)
	rollover.IndexSHA = strings.Repeat("9", 64)
	if _, err := store.BeginAttempt(rollover, strings.Repeat("5", 64), started.Add(5*time.Minute), time.Minute); err != nil {
		t.Fatalf("new pinned plan could not schedule after the old cadence: %v", err)
	}
}

func TestOperationAttemptStoreRetriesDeliveryWithoutBlockingNextDueProviderAttempt(t *testing.T) {
	store, err := OpenOperationAttemptStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	binding := testOperationAttemptBinding()
	started := time.Date(2026, 10, 7, 3, 0, 0, 0, time.UTC)
	first, err := store.BeginAttempt(binding, strings.Repeat("6", 64), started, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	result := OperationObservationResult{State: "healthy", Category: "healthy", ObservedAt: started.Add(time.Second), ReceiptSHA: strings.Repeat("7", 64), LatencyMS: 20}
	if err := store.CompleteAttempt(first, result, started.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	// Simulate a Gatus outage: the receipt remains in the outbox, but the
	// scheduled next provider observation is still governed by its own cadence.
	nextAt := started.Add(binding.ObservationPeriod)
	if _, err := store.BeginAttempt(binding, strings.Repeat("8", 64), nextAt, time.Minute); err != nil {
		t.Fatalf("pending delivery blocked an independently due observation: %v", err)
	}
	pending, err := store.PendingDeliveries(binding.SourceID, binding.OperationID)
	if err != nil || len(pending) != 1 || pending[0].AttemptID != first.AttemptID {
		t.Fatalf("old durable receipt disappeared from the delivery outbox: %#v %v", pending, err)
	}
	delivery, err := store.ClaimDelivery(binding.SourceID, binding.OperationID, first.AttemptID, first.Generation, nextAt, time.Minute)
	if err != nil || delivery.Result.ReceiptSHA != result.ReceiptSHA {
		t.Fatalf("old delivery could not be retried independently: %#v %v", delivery, err)
	}
}

func TestOperationAttemptStoreCrossProcessStyleClaimsAreExclusive(t *testing.T) {
	root := t.TempDir()
	stores := make([]*OperationAttemptStore, 12)
	for i := range stores {
		var err error
		stores[i], err = OpenOperationAttemptStore(root)
		if err != nil {
			t.Fatal(err)
		}
	}
	binding := testOperationAttemptBinding()
	now := time.Date(2026, 10, 7, 2, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup
	var mu sync.Mutex
	claimed := 0
	unexpected := []error{}
	for i, store := range stores {
		wg.Add(1)
		go func(i int, store *OperationAttemptStore) {
			defer wg.Done()
			id := fmt.Sprintf("%064x", i+1)
			_, err := store.BeginAttempt(binding, id, now, time.Minute)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				claimed++
			} else if !errors.Is(err, ErrOperationAttemptHeld) {
				unexpected = append(unexpected, err)
			}
		}(i, store)
	}
	wg.Wait()
	if claimed != 1 || len(unexpected) != 0 {
		t.Fatalf("atomic operation claim failed: claimed=%d unexpected=%v", claimed, unexpected)
	}
}

func TestOperationAttemptStorageBudgetUsesCompletePlannedPopulation(t *testing.T) {
	budget, err := ValidateOperationAttemptStorageBudget(12_666)
	if err != nil || budget.EstimatedMaximum != int64(12_666)*int64(maxOperationAttemptStateBytes) || budget.EstimatedMaximum > budget.MaximumStoreBytes {
		t.Fatalf("current Registry plan population did not fit the declared bounded store: %#v %v", budget, err)
	}
	if _, err := ValidateOperationAttemptStorageBudget(maxOperationAttemptStoreOperations + 1); !errors.Is(err, ErrOperationAttemptCapacity) {
		t.Fatalf("over-capacity population was accepted: %v", err)
	}
}

func testOperationAttemptBinding() OperationAttemptBinding {
	return OperationAttemptBinding{
		SourceID: "synthetic_test", OperationID: "synthetic-rest-list", RegistryRevision: strings.Repeat("a", 40),
		ReleaseManifestSHA: strings.Repeat("b", 64), IndexSHA: strings.Repeat("c", 64), ShardSHA: strings.Repeat("d", 64),
		GatusKey: "public-data_registry-" + strings.Repeat("e", 64), ObservationPeriod: 5 * time.Minute,
	}
}

func testOperationReadModelForStore(t *testing.T, now time.Time) *OperationReadModel {
	t.Helper()
	root, planBinding, _ := writeSyntheticOperationObservationPlan(t, false)
	plan, err := LoadPinnedOperationObservationPlan(root, planBinding)
	if err != nil {
		t.Fatal(err)
	}
	model, err := NewOperationReadModel(plan, testRegistryAPIMetadataPin(0, 0), nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	return model
}
