package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestOperationPlanSchedulerRunsOneBoundedLocalAttemptThenIndependentDelivery(t *testing.T) {
	worker, attempts, history, gatus, target := newOperationPlanSchedulerTestWorker(t)
	scheduler, err := NewOperationPlanScheduler(OperationPlanSchedulerConfig{
		Worker: worker, MaxConcurrent: 1, MaxStartsPerPass: 1, MaxDeliveriesPerPass: 1,
		CandidateScanPerPass: 2, DeliveryLease: time.Minute,
	})
	if err != nil {
		t.Fatal("local synthetic plan could not construct a bounded scheduler:", err)
	}
	started := time.Now().UTC()
	if err := scheduler.ProcessDue(context.Background(), started); err != nil {
		t.Fatal("first bounded pass failed:", err)
	}
	scheduler.Wait()
	latest, found, err := attempts.Latest(target.Record.SourceID, target.Record.OperationID)
	if err != nil || !found || latest.State != "observed" || latest.Result == nil || latest.DeliveryState != "not_ready" {
		t.Fatalf("scheduler did not persist one local child observation before delivery: latest=%#v found=%t err=%v", latest, found, err)
	}
	usage, err := history.Usage(context.Background())
	if err != nil || usage.RecordCount != 1 || usage.ReservationCount != 0 {
		t.Fatalf("worker did not append the validated receipt before marking the observation: usage=%#v err=%v", usage, err)
	}

	// The next one-second pass finds the exact durable outbox record and uses
	// only the per-key test client. It must not issue another provider child.
	nextPassAt := waitForOperationPlanSchedulerPass(t, started)
	if err := scheduler.ProcessDue(context.Background(), nextPassAt); err != nil {
		t.Fatal("bounded delivery pass failed:", err)
	}
	scheduler.Wait()
	latest, found, err = attempts.Latest(target.Record.SourceID, target.Record.OperationID)
	if err != nil || !found || latest.DeliveryState != "readback_verified" || latest.Result == nil || gatus.pushes != 1 || gatus.readbacks != 1 {
		t.Fatalf("scheduler did not advance only the independent Gatus outbox: latest=%#v found=%t push=%d readback=%d err=%v", latest, found, gatus.pushes, gatus.readbacks, err)
	}
	nextPassAt = waitForOperationPlanSchedulerPass(t, nextPassAt)
	if err := scheduler.ProcessDue(context.Background(), nextPassAt); err != nil {
		t.Fatal("bounded evidence sweep failed:", err)
	}
	status := scheduler.Status(time.Now().UTC())
	if !status.Ready || status.State != "ready" || status.EvidenceCheckedOperations != 1 || status.EvidenceCurrentOperations != 1 || status.EvidenceMissingOperations != 0 || status.EvidenceSweepAt.IsZero() || status.KnownOperations != worker.runtime.Plan.Counts().KnownOperations || status.AdmittedOperations != 1 || status.ExecutionTasksStartedSinceStart != 1 || status.RequestStartsSinceStart != 1 || status.ObservationsSinceStart != 1 || status.ReadbacksSinceStart != 1 || !status.CapacityFeasible {
		t.Fatalf("scheduler readiness/counters do not describe the one admitted synthetic operation: %#v", status)
	}
	scheduler.recordFailure(time.Now().UTC(), "delivery_unavailable")
	if status := scheduler.Status(time.Now().UTC().Add(40 * time.Second)); status.Ready || status.LastErrorReason != "delivery_unavailable" {
		t.Fatalf("unresolved pipeline error expired into false readiness: %#v", status)
	}
}

func waitForOperationPlanSchedulerPass(t *testing.T, previous time.Time) time.Time {
	t.Helper()
	next := previous.Add(operationPlanSchedulerPassInterval)
	if wait := time.Until(next); wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		<-timer.C
	}
	return time.Now().UTC()
}

func TestOperationPlanDeliveryEvidenceTreatsProviderFailureAndObservationOnlyAsPipelineEvidence(t *testing.T) {
	now := time.Now().UTC()
	tests := []struct {
		name    string
		attempt OperationStoredAttempt
		want    bool
	}{
		{
			name:    "healthy readback",
			attempt: OperationStoredAttempt{Result: &OperationObservationResult{State: "healthy", Category: "healthy", ObservedAt: now, ReceiptSHA: strings.Repeat("a", 64)}, DeliveryState: "readback_verified", DeliveryAckAt: now, GatusReceivedAt: now.Add(time.Second), GatusResultState: "healthy"},
			want:    true,
		},
		{
			name:    "provider failure readback remains observer evidence",
			attempt: OperationStoredAttempt{Result: &OperationObservationResult{State: "unhealthy", Category: "response_http_failure", HTTPStatus: 503, ObservedAt: now, ReceiptSHA: strings.Repeat("a", 64)}, DeliveryState: "readback_verified", DeliveryAckAt: now, GatusReceivedAt: now.Add(time.Second), GatusResultState: "unhealthy"},
			want:    true,
		},
		{
			name:    "2xx without reviewed semantics is not applicable",
			attempt: OperationStoredAttempt{Result: &OperationObservationResult{State: "indeterminate", Category: "response_semantics_unestablished", HTTPStatus: 200, ObservedAt: now, ReceiptSHA: strings.Repeat("a", 64), HistoryRecordID: "synthetic-history-record", HistoryRecordSHA256: strings.Repeat("b", 64)}, DeliveryState: "not_applicable"},
			want:    true,
		},
		{
			name:    "missing Gatus evidence",
			attempt: OperationStoredAttempt{Result: &OperationObservationResult{State: "healthy", Category: "healthy", ObservedAt: now, ReceiptSHA: strings.Repeat("a", 64)}, DeliveryState: "pending"},
			want:    false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := operationPlanDeliveryEvidenceValid(test.attempt); got != test.want {
				t.Fatalf("delivery evidence validity = %t, want %t", got, test.want)
			}
		})
	}
}

func TestOperationPlanReadinessKeepsFreshEvidenceDuringClaimAndRejectsFutureOrStaleProof(t *testing.T) {
	worker, attempts, _, _, target := newOperationPlanSchedulerTestWorker(t)
	scheduler, err := NewOperationPlanScheduler(OperationPlanSchedulerConfig{
		Worker: worker, MaxConcurrent: 1, MaxStartsPerPass: 1, MaxDeliveriesPerPass: 1,
		CandidateScanPerPass: 2, DeliveryLease: time.Minute,
	})
	if err != nil {
		t.Fatal("local synthetic plan could not construct a bounded scheduler:", err)
	}
	passAt := time.Now().UTC()
	for pass := 0; pass < 3; pass++ {
		if err := scheduler.ProcessDue(context.Background(), passAt); err != nil {
			t.Fatalf("synthetic pass %d failed: %v", pass, err)
		}
		scheduler.Wait()
		if pass < 2 {
			passAt = waitForOperationPlanSchedulerPass(t, passAt)
		}
	}
	completed, found, err := attempts.Latest(target.Record.SourceID, target.Record.OperationID)
	if err != nil || !found || completed.State != "observed" || completed.DeliveryState != "readback_verified" {
		t.Fatalf("test setup did not persist a complete observation: found=%t attempt=%#v err=%v", found, completed, err)
	}
	claimAt := completed.StartedAt.Add(target.Record.ObservationPeriod)
	if !claimAt.Before(completed.Result.ObservedAt.Add(target.Record.ObservationPeriod)) {
		t.Fatal("fixture has no fresh interval between next due claim and the prior observation expiry")
	}
	claim, err := attempts.BeginAttempt(completed.Binding, "123e4567-e89b-12d3-a456-426614174000", claimAt, time.Minute)
	if err != nil {
		t.Fatalf("could not create a future-due in-flight claim: %v", err)
	}
	latest, prior, latestFound, priorFound, err := attempts.LatestReadinessSnapshotContext(context.Background(), target.Record.SourceID, target.Record.OperationID)
	if err != nil || !latestFound || !priorFound || latest.State != "claimed" || prior.State != "observed" {
		t.Fatalf("readiness snapshot did not preserve latest and completed attempts atomically: latest=%#v prior=%#v err=%v", latest, prior, err)
	}
	evidence, err := scheduler.operationEvidenceForTarget(context.Background(), target, latest, prior, priorFound, claim.StartedAt)
	if err != nil || !evidence.Proven || !claim.StartedAt.Before(evidence.ValidUntil) {
		t.Fatalf("fresh completed proof disappeared during the next active claim: evidence=%#v err=%v", evidence, err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*OperationStoredAttempt)
	}{
		{name: "future attempt start", mutate: func(attempt *OperationStoredAttempt) { attempt.StartedAt = claim.StartedAt.Add(time.Nanosecond) }},
		{name: "future finished time", mutate: func(attempt *OperationStoredAttempt) { attempt.FinishedAt = claim.StartedAt.Add(time.Nanosecond) }},
		{name: "future observed time", mutate: func(attempt *OperationStoredAttempt) {
			result := *attempt.Result
			result.ObservedAt = claim.StartedAt.Add(time.Nanosecond)
			attempt.Result = &result
		}},
		{name: "future received time", mutate: func(attempt *OperationStoredAttempt) {
			result := *attempt.Result
			result.ReceivedAt = claim.StartedAt.Add(time.Nanosecond)
			attempt.Result = &result
		}},
		{name: "future readback time", mutate: func(attempt *OperationStoredAttempt) { attempt.GatusReceivedAt = claim.StartedAt.Add(time.Nanosecond) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			future := cloneOperationStoredAttempt(prior)
			test.mutate(&future)
			observed, err := scheduler.operationEvidenceForTarget(context.Background(), target, latest, future, true, claim.StartedAt)
			if err != nil || observed.Proven {
				t.Fatalf("future persisted timestamp was accepted as current evidence: evidence=%#v err=%v", observed, err)
			}
		})
	}

	identityKey := operationReadModelIdentityKey(target.Record.SourceID, target.Record.OperationID)
	failureAt := claim.StartedAt.Add(time.Nanosecond)
	scheduler.mu.Lock()
	scheduler.passes = 1
	scheduler.lastPass = failureAt
	scheduler.latchIdentityErrorLocked(identityKey, "execution_unavailable", failureAt, true)
	scheduler.mu.Unlock()
	if err := scheduler.advanceEvidenceSweep(context.Background(), failureAt.Add(time.Nanosecond)); err != nil {
		t.Fatal("fresh prior evidence sweep failed:", err)
	}
	status := scheduler.Status(failureAt.Add(2 * time.Nanosecond))
	if status.Ready || status.LastErrorReason != "execution_unavailable" || status.EvidenceCurrentOperations != 1 {
		t.Fatalf("old proof incorrectly cleared a newer same-identity execution failure: %#v", status)
	}
	if status := scheduler.Status(failureAt); status.Ready || status.Reason != "operation_observations_incomplete" {
		t.Fatalf("status evaluated before its evidence sweep was incorrectly ready: %#v", status)
	}
	if status := scheduler.Status(failureAt.Add(-time.Nanosecond)); status.Ready || status.Reason != "scheduler_loop_stale" {
		t.Fatalf("status evaluated before its last pass was incorrectly ready: %#v", status)
	}

	if err := attempts.FailAttempt(claim, claim.StartedAt.Add(2*time.Second)); err != nil {
		t.Fatalf("could not create a newer terminal failure fixture: %v", err)
	}
	terminal, older, latestFound, olderFound, err := attempts.LatestReadinessSnapshotContext(context.Background(), target.Record.SourceID, target.Record.OperationID)
	if err != nil || !latestFound || !olderFound || terminal.State != "unknown" {
		t.Fatalf("terminal failure snapshot lost the old receipt: latest=%#v older=%#v err=%v", terminal, older, err)
	}
	evidence, err = scheduler.operationEvidenceForTarget(context.Background(), target, terminal, older, olderFound, claim.StartedAt.Add(2*time.Second))
	if err != nil || evidence.Proven {
		t.Fatalf("older proof hid a newer terminal failure: evidence=%#v err=%v", evidence, err)
	}
}

func TestOperationPlanSchedulerStoreLockCannotBlockControllerPassOrLaunchProvider(t *testing.T) {
	worker, attempts, _, _, target := newOperationPlanSchedulerTestWorker(t)
	called := make(chan struct{}, 1)
	worker.runner = schedulerCalledReceiptExecutor{called: called}
	scheduler, err := NewOperationPlanScheduler(OperationPlanSchedulerConfig{
		Worker: worker, MaxConcurrent: 1, MaxStartsPerPass: 1, MaxDeliveriesPerPass: 1,
		CandidateScanPerPass: 2, DeliveryLease: time.Minute,
	})
	if err != nil {
		t.Fatal("local synthetic plan could not construct a bounded scheduler:", err)
	}
	lock, err := os.OpenFile(attempts.root+"/.operation-attempt.lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	started := time.Now().UTC()
	passDone := make(chan error, 1)
	go func() { passDone <- scheduler.ProcessDue(context.Background(), started) }()
	select {
	case err := <-passDone:
		if err == nil {
			t.Fatal("controller pass ignored the held attempt-store lock")
		}
	case <-time.After(operationPlanSchedulerScanTimeout + time.Second):
		t.Fatal("controller pass remained blocked on the attempt-store lock")
	}
	select {
	case <-called:
		t.Fatal("provider executor ran while the bounded store scan was unavailable")
	default:
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_UN); err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := scheduler.ProcessDue(context.Background(), time.Now().UTC()); err != nil {
		t.Fatal("controller did not recover after the attempt-store lock was released:", err)
	}
	scheduler.Wait()
	select {
	case <-called:
	default:
		t.Fatal("provider executor was not reached after the bounded scan recovered")
	}
	latest, found, err := attempts.Latest(target.Record.SourceID, target.Record.OperationID)
	if err != nil || !found || latest.State != "observed" {
		t.Fatalf("recovered bounded pass did not persist one local attempt: found=%t state=%q err=%v", found, latest.State, err)
	}
}

func TestOperationPlanSchedulerDoesNotStartProviderWorkWhenCapacityIsInfeasible(t *testing.T) {
	worker, attempts, history, gatus, target := newOperationPlanSchedulerTestWorker(t)
	scheduler, err := NewOperationPlanScheduler(OperationPlanSchedulerConfig{
		Worker: worker, MaxConcurrent: 1, MaxStartsPerPass: 1, MaxDeliveriesPerPass: 1,
		CandidateScanPerPass: 2, DeliveryLease: time.Minute,
	})
	if err != nil {
		t.Fatal("local synthetic plan could not construct a bounded scheduler:", err)
	}
	// Model a plan whose immutable cadence cannot fit the configured global,
	// per-provider, or per-credential quota and worker capacity.
	scheduler.capacity.Feasible = false
	scheduler.capacity.RequiredStartsPerSecond = 2
	started := time.Now().UTC()
	if err := scheduler.ProcessDue(context.Background(), started); err != nil {
		t.Fatal("infeasible-capacity pass failed before reporting readiness:", err)
	}
	scheduler.Wait()
	if _, found, err := attempts.Latest(target.Record.SourceID, target.Record.OperationID); err != nil || found {
		t.Fatalf("infeasible capacity still reserved a provider attempt: found=%t err=%v", found, err)
	}
	usage, err := history.Usage(context.Background())
	if err != nil || usage.RecordCount != 0 || usage.ReservationCount != 0 || gatus.pushes != 0 || gatus.readbacks != 0 {
		t.Fatalf("infeasible capacity created receipt or delivery work: usage=%#v push=%d readback=%d err=%v", usage, gatus.pushes, gatus.readbacks, err)
	}
	status := scheduler.Status(started)
	if status.Ready || status.State != "degraded" || status.Reason != "capacity_infeasible" || status.ExecutionTasksStartedSinceStart != 0 {
		t.Fatalf("infeasible plan was not held closed and visible: %#v", status)
	}
}

func TestOperationPlanCapacityReportsWholeFleetInfeasibleAtSafeCaps(t *testing.T) {
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	metadataArtifact, err := LoadRegistryAPIMetadata("../../config/registry/api-metadata.v1.json", "../../config/registry/api-metadata-source-pin.v1.json", canaries)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := NewVerifiedRegistryAPIMetadata(metadataArtifact)
	if err != nil {
		t.Fatal(err)
	}
	fleetSize := metadata.pin.OperationCount
	policy := OperationQuotaPolicy{
		ScopeSHA256:   OperationQuotaScopeDigest("global", "synthetic-global"),
		MaxConcurrent: 256, RequestsPerWindow: fleetSize, Window: 10 * time.Minute,
	}
	targets := make([]OperationPlanWorkerTarget, fleetSize)
	for index := range targets {
		targets[index] = OperationPlanWorkerTarget{
			Record: OperationObservationPlanRecord{
				SourceID: "data_go_kr", OperationID: fmt.Sprintf("synthetic-%05d", index),
				ObservationPeriod: 10 * time.Minute, RequestTimeout: 20 * time.Second,
				RequestPlanStatus: "complete", RuntimeBindingStatus: "bound", AdmissionStatus: "admitted",
				ExecutionEligible: true, QuotaPoliciesAdmitted: true, QuotaPolicies: []OperationQuotaPolicy{policy},
			}, ShardSHA256: strings.Repeat("a", 64), GatusEndpointKey: fmt.Sprintf("registered_synthetic-%05d", index),
		}
	}
	assessment, err := assessOperationPlanCapacity(targets, 32, 32, 256)
	if err != nil {
		t.Fatal("fleet capacity calculation rejected a bounded synthetic inventory:", err)
	}
	// The request timeout is 20 seconds, and the child process plus receipt
	// handling reserves another 5 seconds under the current runner contract.
	if assessment.Feasible || assessment.RequiredConcurrency != 528 || assessment.RequiredStartsPerSecond < 21.1 || assessment.RequiredStartsPerSecond > 21.2 || assessment.FailureScopes != 1 {
		t.Fatalf("scheduler overstated 12,666-operation/10-minute feasibility: %#v", assessment)
	}
}

func TestOperationPlanTargetDueUsesSlowerBoundPlanCadenceAndDoesNotReplaySlots(t *testing.T) {
	started := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	target := OperationPlanWorkerTarget{Record: OperationObservationPlanRecord{ObservationPeriod: 10 * time.Minute}}
	latest := OperationStoredAttempt{StartedAt: started, Binding: OperationAttemptBinding{ObservationPeriod: 5 * time.Minute}}
	if operationPlanTargetDue(target, latest, started.Add(9*time.Minute+59*time.Second)) {
		t.Fatal("operation was rescheduled before the slower immutable period elapsed")
	}
	if !operationPlanTargetDue(target, latest, started.Add(10*time.Minute)) {
		t.Fatal("operation did not become due at its immutable period")
	}
	if !operationPlanTargetDue(target, latest, started.Add(24*time.Hour)) {
		t.Fatal("missed periods were treated as a reason to replay a backlog of calls")
	}
}

type schedulerSyntheticReceiptExecutor struct{}

func (schedulerSyntheticReceiptExecutor) Run(ctx context.Context, expected OperationPlanProbeExpectation, deadline time.Time) (OperationPlanProbeResult, int, error) {
	if ctx.Err() != nil || !deadline.After(time.Now()) {
		return OperationPlanProbeResult{}, -1, errOperationPlanProbeUnavailable
	}
	now := time.Now().UTC()
	receipt := testOperationPlanProbeReceipt(expected, now, "healthy", "response_assertion_passed", "passed", true, true, 1, http.StatusOK)
	raw, err := json.Marshal(receipt)
	if err != nil {
		return OperationPlanProbeResult{}, -1, errOperationPlanProbeUnavailable
	}
	raw = append(raw, '\n')
	result, err := ValidateOperationPlanProbeReceipt(raw, expected, expected.StartedAt, time.Now().UTC(), 0)
	if err != nil {
		return OperationPlanProbeResult{}, -1, err
	}
	return result, 0, nil
}

type schedulerCalledReceiptExecutor struct{ called chan<- struct{} }

func (executor schedulerCalledReceiptExecutor) Run(ctx context.Context, expected OperationPlanProbeExpectation, deadline time.Time) (OperationPlanProbeResult, int, error) {
	select {
	case executor.called <- struct{}{}:
	default:
	}
	return (schedulerSyntheticReceiptExecutor{}).Run(ctx, expected, deadline)
}

type schedulerSyntheticGatus struct {
	mu        sync.Mutex
	pushes    int
	readbacks int
	results   map[string]OperationObservationResult
}

func (client *schedulerSyntheticGatus) Push(ctx context.Context, key string, result OperationObservationResult) (time.Time, error) {
	if ctx.Err() != nil || !validPlanGatusEndpointKey(key) || !validOperationObservationResult(result) {
		return time.Time{}, errOperationGatusDeliveryUnavailable
	}
	client.mu.Lock()
	if client.results == nil {
		client.results = make(map[string]OperationObservationResult)
	}
	client.results[key] = result
	client.pushes++
	client.mu.Unlock()
	return time.Now().UTC(), nil
}

func (client *schedulerSyntheticGatus) Readback(ctx context.Context, key string, expected OperationObservationResult, acknowledgedAt time.Time) (time.Time, string, error) {
	if ctx.Err() != nil || acknowledgedAt.IsZero() {
		return time.Time{}, "", errOperationGatusDeliveryUnavailable
	}
	client.mu.Lock()
	result, found := client.results[key]
	client.readbacks++
	client.mu.Unlock()
	if !found || result != expected {
		return time.Time{}, "", errOperationGatusDeliveryUnavailable
	}
	return time.Now().UTC(), expected.State, nil
}

func newOperationPlanSchedulerTestWorker(t *testing.T) (*OperationPlanWorker, *OperationAttemptStore, *OperationHistoryStore, *schedulerSyntheticGatus, OperationPlanWorkerTarget) {
	t.Helper()
	planRoot, binding, sourceSHA, operationIDs := writeGatusPlanFixture(t)
	plan, err := LoadPinnedOperationObservationPlan(planRoot, binding)
	if err != nil {
		t.Fatal(err)
	}
	metadata, canaries := gatusTestMetadata(sourceSHA, operationIDs)
	activationRaw, err := json.Marshal(OperationGatusActivation{
		SchemaVersion:    OperationGatusActivationSchemaVersion,
		RegistryRevision: plan.RegistryRevision(), IndexSHA256: plan.IndexSHA256(),
		Operations: []OperationGatusActivationEntry{{SourceID: "data_go_kr", OperationID: operationIDs[0]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	activation, activationSHA, err := DecodeOperationGatusActivation(activationRaw, plan)
	if err != nil {
		t.Fatal(err)
	}
	base := []byte("web:\n  port: 8080\nexternal-endpoints:\n  - name: placeholder\n")
	canaryRaw := []byte("verified synthetic scheduler canary\n")
	artifacts, err := GenerateOperationGatusArtifacts(base, digestOperationGatusBytes(canaryRaw), canaries, metadata, &plan, &activation, activationSHA)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	paths := operationPlanTestRuntimePaths(root)
	for path, raw := range map[string][]byte{
		paths.BaseGatusConfigPath: base, paths.GeneratedConfigPath: artifacts.Config,
		paths.IdentityMappingPath: artifacts.Mapping, paths.RuntimePinPath: artifacts.RuntimePin,
	} {
		if err := os.WriteFile(path, raw, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	paths.ActivationPath = root + "/activation.json"
	paths.ActivationSHA256 = activationSHA
	if err := os.WriteFile(paths.ActivationPath, activationRaw, 0o400); err != nil {
		t.Fatal(err)
	}
	runtime, err := verifyOperationGatusRuntimeArtifacts(paths, canaryRaw, canaries, metadata, plan)
	if err != nil || len(runtime.ActiveTargets) != 1 {
		t.Fatalf("could not bind one synthetic admitted target: active=%d err=%v", len(runtime.ActiveTargets), err)
	}
	target := runtime.ActiveTargets[0]
	lock := testOperationPlanRuntimeLock(strings.Repeat("9", 64))
	resolver, err := NewPinnedOperationPlanProbeExpectationResolver(plan, lock, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	validator, err := NewOperationPlanProbeHistoryValidator(strings.Repeat("8", 40), resolver)
	if err != nil {
		t.Fatal(err)
	}
	history, err := OpenOperationHistoryStore(root+"/history", 16<<20, validator)
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := OpenOperationAttemptStore(root + "/attempts")
	if err != nil {
		t.Fatal(err)
	}
	quotas, err := OpenOperationQuotaAuthority(root + "/quotas")
	if err != nil {
		t.Fatal(err)
	}
	probeConfig, err := OperationPlanProbeConfigFromRuntimeLock(lock, "amd64", "/synthetic/datapan", bindingIndexPath(planRoot, binding), root+"/credential-bindings.json", root+"/receipts", nil)
	if err != nil {
		t.Fatal(err)
	}
	workerConfig := OperationPlanWorkerConfig{
		Runtime: runtime, Runner: schedulerSyntheticReceiptExecutor{}, Attempts: attempts,
		Quotas: quotas, History: history, HistoryValidator: validator,
		Gatus: &schedulerSyntheticGatus{}, RuntimeLock: lock, Architecture: "amd64",
		AttemptLease: time.Minute, QuotaLease: time.Minute,
	}
	worker, err := newOperationPlanWorker(workerConfig, probeConfig)
	if err != nil {
		t.Fatal("could not construct the deterministic synthetic operation worker:", err)
	}
	client := &schedulerSyntheticGatus{}
	worker.gatus = client
	return worker, attempts, history, client, target
}

func bindingIndexPath(planRoot string, binding OperationObservationPlanBinding) string {
	return planRoot + "/" + binding.IndexPath
}
