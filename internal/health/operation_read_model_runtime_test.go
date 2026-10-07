package health

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadOperationObservationPlanRuntimePinRequiresExactBoundedContract(t *testing.T) {
	root, binding, _ := writeSyntheticOperationObservationPlan(t, false)
	pinPath := filepath.Join(root, "operation-plan-pin.json")
	raw, err := json.Marshal(operationObservationPlanRuntimePin{SchemaVersion: OperationObservationPlanRuntimePinSchema, Plan: binding})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadOperationObservationPlanRuntimePin(pinPath)
	if err != nil || loaded != binding {
		t.Fatalf("valid exact plan pin was rejected: equal=%v err=%v", loaded == binding, err)
	}
	if err := os.WriteFile(pinPath, append(raw, []byte(` {"unrecognized":true}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperationObservationPlanRuntimePin(pinPath); err == nil {
		t.Fatal("trailing JSON content in the plan pin was accepted")
	}
	if err := os.WriteFile(pinPath, bytesOfSize(maxOperationObservationPlanRuntimePin+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOperationObservationPlanRuntimePin(pinPath); !errors.Is(err, errOperationReadModelRuntimeUnavailable) {
		t.Fatalf("oversized plan pin was not rejected with a bounded error: %v", err)
	}
}

func TestOperationReadModelRuntimeLoaderFailsClosedWithoutImageOwnedPlanPin(t *testing.T) {
	root := t.TempDir()
	storePath := filepath.Join(root, "attempts")
	_, err := LoadOperationReadModelRuntime(
		filepath.Join(root, "release"),
		filepath.Join(root, "missing-runtime-pin.json"),
		storePath,
		VerifiedRegistryAPIMetadata{},
		5*time.Minute,
		time.Now().UTC(),
	)
	if !errors.Is(err, errOperationReadModelRuntimeUnavailable) {
		t.Fatalf("runtime without an image-owned plan pin did not fail closed: %v", err)
	}
	if _, err := os.Lstat(storePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed plan startup created or touched the attempt store: %v", err)
	}
}

func TestOperationReadModelRuntimePublishesOnlyCompleteRefreshAndKeepsLastGood(t *testing.T) {
	started := time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC)
	root, planBinding, _ := writeSyntheticOperationObservationPlan(t, false)
	plan, err := LoadPinnedOperationObservationPlan(root, planBinding)
	if err != nil {
		t.Fatal(err)
	}
	model, err := newOperationReadModel(plan, testRegistryAPIMetadataPin(0, 0), nil, nil, started)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenOperationAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := NewOperationReadModelRuntime(model, store, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	initial := runtime.Status(started)
	if initial.ReadModelState != "starting" || initial.IdentityCounts.Known != 2 || initial.CoverageReady {
		t.Fatalf("runtime did not distinguish pinned inventory from a completed cache or admitted coverage: %#v", initial)
	}

	complete, err := runtime.RefreshNextBatch(started, 1)
	if err != nil || complete {
		t.Fatalf("first half of the initial bounded refresh had unexpected state: complete=%t err=%v", complete, err)
	}
	if page, err := runtime.PageOperations(OperationPageQuery{Limit: 10}, started); !errors.Is(err, ErrOperationReadModelUnavailable) || len(page.Operations) != 0 {
		t.Fatalf("partial initial snapshot was published to readers: %#v %v", page, err)
	}
	complete, err = runtime.RefreshNextBatch(started.Add(time.Second), 1)
	if err != nil || !complete {
		t.Fatalf("second half did not complete the initial bounded refresh: complete=%t err=%v", complete, err)
	}
	page, err := runtime.PageOperations(OperationPageQuery{Limit: 10}, started.Add(time.Second))
	if err != nil || len(page.Operations) != 2 {
		t.Fatalf("complete initial snapshot is not readable: %#v %v", page, err)
	}
	if status := runtime.Status(started.Add(time.Second)); status.ReadModelState != "ready" || status.CoverageReady != (status.IdentityCounts.Admitted > 0) || status.CoverageReady && status.IdentityCounts.Admitted == 0 {
		t.Fatalf("cache state and nonvacuous coverage readiness were conflated: %#v", status)
	}

	identities, err := model.AttemptIdentities(0, 2)
	if err != nil || len(identities) != 2 {
		t.Fatalf("synthetic full scope did not expose both exact IDs: %#v %v", identities, err)
	}
	bindings := make([]OperationAttemptBinding, 2)
	claims := make([]OperationAttemptClaim, 2)
	for i, identity := range identities {
		bindings[i] = testOperationReadModelAttemptBinding(t, model, identity.SourceID, identity.OperationID)
		claims[i], err = store.BeginAttempt(bindings[i], strings.Repeat(string(rune('a'+i)), 64), started.Add(2*time.Second), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		state := "healthy"
		category := "healthy"
		if i == 1 {
			state = "unhealthy"
			category = "provider_failure"
		}
		result := OperationObservationResult{State: state, Category: category, ObservedAt: started.Add(3 * time.Second), ReceivedAt: started.Add(4 * time.Second), ReceiptSHA: strings.Repeat(string(rune('f'-i)), 64), LatencyMS: 100}
		if err := store.CompleteAttempt(claims[i], result, started.Add(5*time.Second)); err != nil {
			t.Fatal(err)
		}
	}

	pathB := store.statePath(bindings[1].SourceID, bindings[1].OperationID)
	validB, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, []byte(`{"corrupt":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	complete, err = runtime.RefreshNextBatch(started.Add(6*time.Second), 1)
	if err != nil || complete {
		t.Fatalf("first changed identity batch did not remain staged: complete=%t err=%v", complete, err)
	}
	if complete, err = runtime.RefreshNextBatch(started.Add(7*time.Second), 1); !errors.Is(err, errOperationReadModelRuntimeUnavailable) || complete {
		t.Fatalf("later corrupt state did not stop the whole refresh before publish: complete=%t err=%v", complete, err)
	}
	oldPage, err := runtime.PageOperations(OperationPageQuery{Limit: 10}, started.Add(7*time.Second))
	if err != nil || len(oldPage.Operations) != 2 || oldPage.Operations[0].ObservationState != "unobserved" || oldPage.Operations[1].ObservationState != "unobserved" {
		t.Fatalf("failed partial refresh replaced the last complete snapshot: %#v %v", oldPage, err)
	}
	if status := runtime.Status(started.Add(7 * time.Second)); status.ReadModelState != "refresh_error" || status.ReadModelReason != "state_unavailable" {
		t.Fatalf("refresh failure was not exposed separately from the last good snapshot: %#v", status)
	}
	if err := os.WriteFile(pathB, validB, 0o600); err != nil {
		t.Fatal(err)
	}
	if complete, err = runtime.RefreshNextBatch(started.Add(8*time.Second), 1); err != nil || !complete {
		t.Fatalf("repaired in-progress sweep did not complete: complete=%t err=%v", complete, err)
	}
	updated, err := runtime.PageOperations(OperationPageQuery{Limit: 10}, started.Add(8*time.Second))
	if err != nil || len(updated.Operations) != 2 || updated.Operations[0].ObservationState != "current_pass" || updated.Operations[1].ObservationState != "current_fail" {
		t.Fatalf("repaired full sweep did not atomically publish both validated observations: %#v %v", updated, err)
	}
}

func TestOperationReadModelRefreshKeepsFutureObservationOutOfCurrentCoverage(t *testing.T) {
	started := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	root, planBinding, _ := writeSyntheticOperationObservationPlan(t, false)
	plan, err := LoadPinnedOperationObservationPlan(root, planBinding)
	if err != nil {
		t.Fatal(err)
	}
	model, err := newOperationReadModel(plan, testRegistryAPIMetadataPin(0, 0), nil, nil, started)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenOperationAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	identities, err := model.AttemptIdentities(0, 1)
	if err != nil || len(identities) != 1 {
		t.Fatalf("synthetic model did not provide the first exact identity: %#v %v", identities, err)
	}
	binding := testOperationReadModelAttemptBinding(t, model, identities[0].SourceID, identities[0].OperationID)
	claim, err := store.BeginAttempt(binding, strings.Repeat("c", 64), started.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	result := OperationObservationResult{
		State: "healthy", Category: "healthy", ObservedAt: started.Add(3 * time.Second),
		ReceivedAt: started.Add(4 * time.Second), ReceiptSHA: strings.Repeat("d", 64), LatencyMS: 25,
	}
	if err := store.CompleteAttempt(claim, result, started.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if next, complete, err := model.RefreshFromStoreBatch(store, 0, 1, started.Add(2*time.Second)); err != nil || complete || next != 1 {
		t.Fatalf("future observation did not remain a bounded noncoverage row: next=%d complete=%t err=%v", next, complete, err)
	}
	early, err := model.PageOperations(OperationPageQuery{Limit: 1}, started.Add(2*time.Second))
	if err != nil || len(early.Operations) != 1 || early.Operations[0].ObservationState != "unobserved" || early.Operations[0].MissingReason != "future_observation" {
		t.Fatalf("future provider observation was presented as current coverage: %#v %v", early, err)
	}
	page, err := model.PageOperations(OperationPageQuery{Limit: 1}, started.Add(5*time.Second))
	if err != nil || len(page.Operations) != 1 || page.Operations[0].ObservationState != "current_pass" {
		t.Fatalf("observation did not become current once its evidence time arrived: %#v %v", page, err)
	}
}

func TestOperationReadModelRejectedProjectionDoesNotAdvancePreparedStoreStamp(t *testing.T) {
	started := time.Date(2026, 10, 7, 10, 0, 0, 0, time.UTC)
	root, planBinding, _ := writeSyntheticOperationObservationPlan(t, false)
	plan, err := LoadPinnedOperationObservationPlan(root, planBinding)
	if err != nil {
		t.Fatal(err)
	}
	model, err := newOperationReadModel(plan, testRegistryAPIMetadataPin(0, 0), nil, nil, started)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenOperationAttemptStore(filepath.Join(t.TempDir(), "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	identities, err := model.AttemptIdentities(0, 1)
	if err != nil || len(identities) != 1 {
		t.Fatalf("synthetic model did not provide the first exact identity: %#v %v", identities, err)
	}
	binding := testOperationReadModelAttemptBinding(t, model, identities[0].SourceID, identities[0].OperationID)
	claim, err := store.BeginAttempt(binding, strings.Repeat("e", 64), started.Add(time.Second), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	result := OperationObservationResult{
		State: "healthy", Category: "healthy", ObservedAt: started.Add(2 * time.Second),
		ReceivedAt: started.Add(3 * time.Second), ReceiptSHA: strings.Repeat("f", 64), LatencyMS: 25,
	}
	if err := store.CompleteAttempt(claim, result, started.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	batch, err := store.prepareReadModelAttemptsForIdentities(identities)
	if err != nil || len(batch.attempts) != 1 {
		t.Fatalf("valid durable state did not decode into a staged batch: %#v %v", batch, err)
	}
	// Simulate a projection-validation fault after successful disk decoding.
	// The store's validated record remains unchanged; only the private pending
	// projection is made inconsistent so the model must reject the transaction.
	batch.attempts[0].ResultCategory = "not_a_public_result_category"
	if err := model.applyReadModelAttemptBatch(store, batch, started.Add(5*time.Second)); !errors.Is(err, ErrOperationReadModelUnavailable) {
		t.Fatalf("invalid projection batch was accepted: %v", err)
	}
	retry, err := store.prepareReadModelAttemptsForIdentities(identities)
	if err != nil || len(retry.attempts) != 1 || retry.attempts[0].ResultCategory != "healthy" {
		t.Fatalf("projection rejection advanced the durable read stamp and lost its delta: %#v %v", retry, err)
	}
}

func bytesOfSize(size int) []byte { return make([]byte, size) }
