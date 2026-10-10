package health

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/internal/runtimebundle"
)

func TestOperationPlanProbeDeadlineMustFitEveryQuotaLeaseAfterAcquisition(t *testing.T) {
	started := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	attemptID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	attemptExpiry := started.Add(2 * time.Minute)
	quota := OperationQuotaClaim{ScopeSHA256: strings.Repeat("a", 64), AttemptID: attemptID, Generation: 1, ExpiresAt: started.Add(31 * time.Second)}

	deadline, ok := operationPlanProbeExecutionDeadline(started, 25*time.Second, attemptExpiry, attemptID, []OperationQuotaClaim{quota})
	if !ok || !deadline.Equal(started.Add(25*time.Second+maxOperationPlanProbeProcessOverhead)) {
		t.Fatalf("full request deadline did not fit a valid quota lease: %v %t", deadline, ok)
	}

	// AcquireMany starts the lease before its lock and fsync work. If that work
	// returns late, the child may not outlive the resulting quota lease.
	delayedAcquisition := started.Add(2 * time.Second)
	if _, ok := operationPlanProbeExecutionDeadline(delayedAcquisition, 25*time.Second, attemptExpiry, attemptID, []OperationQuotaClaim{quota}); ok {
		t.Fatal("child deadline exceeded a quota lease consumed by delayed acquisition")
	}

	secondScope := quota
	secondScope.ScopeSHA256 = strings.Repeat("b", 64)
	secondScope.ExpiresAt = started.Add(29 * time.Second)
	if _, ok := operationPlanProbeExecutionDeadline(started, 25*time.Second, attemptExpiry, attemptID, []OperationQuotaClaim{quota, secondScope}); ok {
		t.Fatal("child deadline ignored the earliest expiry among hierarchical quota leases")
	}

	if _, ok := operationPlanProbeExecutionDeadline(started, 25*time.Second, started.Add(30*time.Second), attemptID, []OperationQuotaClaim{quota}); ok {
		t.Fatal("child deadline was allowed to reach the durable attempt lease expiry")
	}
}

type cancelAfterOperationPlanProbeExecutor struct {
	runner    OperationPlanProbeExecutor
	cancel    context.CancelFunc
	lockPaths []string
	locked    chan []*os.File
}

func (executor cancelAfterOperationPlanProbeExecutor) Run(ctx context.Context, expected OperationPlanProbeExpectation, deadline time.Time) (OperationPlanProbeResult, int, error) {
	result, exitCode, err := executor.runner.Run(ctx, expected, deadline)
	executor.cancel()
	if executor.locked != nil {
		files, lockErr := holdOperationPlanTestLocks(executor.lockPaths)
		if lockErr != nil {
			return OperationPlanProbeResult{}, -1, lockErr
		}
		executor.locked <- files
	}
	return result, exitCode, err
}

type lockAfterOperationPlanProbeExecutor struct {
	runner    OperationPlanProbeExecutor
	lockPaths []string
	locked    chan []*os.File
}

func (executor lockAfterOperationPlanProbeExecutor) Run(ctx context.Context, expected OperationPlanProbeExpectation, deadline time.Time) (OperationPlanProbeResult, int, error) {
	result, exitCode, err := executor.runner.Run(ctx, expected, deadline)
	files, lockErr := holdOperationPlanTestLocks(executor.lockPaths)
	if lockErr != nil {
		return OperationPlanProbeResult{}, -1, lockErr
	}
	executor.locked <- files
	return result, exitCode, err
}

func holdOperationPlanTestLocks(paths []string) ([]*os.File, error) {
	files := make([]*os.File, 0, len(paths))
	for _, path := range paths {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			unlockOperationPlanTestLocks(files)
			return nil, err
		}
		if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
			_ = file.Close()
			unlockOperationPlanTestLocks(files)
			return nil, err
		}
		files = append(files, file)
	}
	return files, nil
}

func unlockOperationPlanTestLocks(files []*os.File) {
	for _, file := range files {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}
}

type unavailableOperationPlanProbeExecutor struct{}

func (unavailableOperationPlanProbeExecutor) Run(context.Context, OperationPlanProbeExpectation, time.Time) (OperationPlanProbeResult, int, error) {
	return OperationPlanProbeResult{}, -1, errOperationPlanProbeUnavailable
}

func TestOperationPlanWorkerArchivesCanceledChildReceiptBeforeGatusReadback(t *testing.T) {
	planRoot, planBinding, sourceSHA, operationIDs := writeGatusPlanFixture(t)
	plan, err := LoadPinnedOperationObservationPlan(planRoot, planBinding)
	if err != nil {
		t.Fatal(err)
	}
	metadata, canaries := gatusTestMetadata(sourceSHA, operationIDs)
	activationRaw, err := json.Marshal(OperationGatusActivation{
		SchemaVersion: OperationGatusActivationSchemaVersion, RegistryRevision: plan.RegistryRevision(),
		IndexSHA256: plan.IndexSHA256(), Operations: []OperationGatusActivationEntry{{SourceID: "data_go_kr", OperationID: operationIDs[0]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	activation, activationSHA, err := DecodeOperationGatusActivation(activationRaw, plan)
	if err != nil {
		t.Fatal(err)
	}
	baseConfig := []byte("web:\n  port: 8080\nendpoints:\n  - name: local-health\n    url: http://127.0.0.1:8080/health\nexternal-endpoints:\n  - name: placeholder\n")
	canaryRaw := []byte("synthetic canary fixture; no provider data\n")
	artifacts, err := GenerateOperationGatusArtifacts(baseConfig, digestOperationGatusBytes(canaryRaw), canaries, metadata, &plan, &activation, activationSHA)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := t.TempDir()
	paths := operationPlanTestRuntimePaths(runtimeRoot)
	for path, raw := range map[string][]byte{
		paths.BaseGatusConfigPath: baseConfig, paths.GeneratedConfigPath: artifacts.Config,
		paths.IdentityMappingPath: artifacts.Mapping, paths.RuntimePinPath: artifacts.RuntimePin,
	} {
		if err := os.WriteFile(path, raw, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	paths.ActivationPath = filepath.Join(runtimeRoot, "activation.json")
	paths.ActivationSHA256 = activationSHA
	if err := os.WriteFile(paths.ActivationPath, activationRaw, 0o400); err != nil {
		t.Fatal(err)
	}
	runtime, err := verifyOperationGatusRuntimeArtifacts(paths, canaryRaw, canaries, metadata, plan)
	if err != nil || len(runtime.ActiveTargets) != 1 {
		t.Fatalf("synthetic verified runtime did not produce exactly one active target: runtime=%#v err=%v", runtime, err)
	}
	target := runtime.ActiveTargets[0]
	if target.Record.ResponseAssertionKind != "http_status" {
		t.Fatalf("fixture must exercise typed HTTP assertion delivery, got %q", target.Record.ResponseAssertionKind)
	}

	scriptPath := filepath.Join(runtimeRoot, "synthetic-datapan")
	script := []byte("#!/bin/sh\nset -eu\nattempt=\nout=\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    --health-attempt-id) attempt=$2; shift 2 ;;\n    --output) out=$2; shift 2 ;;\n    *) shift ;;\n  esac\ndone\n[ -n \"$attempt\" ] && [ -n \"$out\" ]\nobserved=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\nsed -e \"s/SYNTHETIC_ATTEMPT_ID/$attempt/g\" -e \"s/OBSERVATION_TIME/$observed/g\" \"$HEALTH_TEST_RECEIPT_TEMPLATE\" > \"$out\"\nchmod 600 \"$out\"\ncat \"$out\"\n")
	if err := os.WriteFile(scriptPath, script, 0o700); err != nil {
		t.Fatal(err)
	}
	executableSHA := digestOperationGatusBytes(script)
	lock := testOperationPlanRuntimeLock(executableSHA)
	const placeholderAttemptID = "817c7c1d-f844-4b79-bdad-891a273c1a4e"
	expected, err := operationPlanProbeExpected(plan, target.Record, target.ShardSHA256, placeholderAttemptID, lock, "amd64", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	receipt := testOperationPlanProbeReceipt(expected, time.Time{}, "healthy", "response_assertion_passed", "passed", true, true, 1, http.StatusOK)
	receipt.AttemptID = "SYNTHETIC_ATTEMPT_ID"
	receipt.Observation.ObservedAt = "OBSERVATION_TIME"
	templatePath := filepath.Join(runtimeRoot, "receipt-template.json")
	if err := os.WriteFile(templatePath, marshalOperationPlanProbeReceipt(t, receipt), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HEALTH_TEST_RECEIPT_TEMPLATE", templatePath)
	credentialBindings := filepath.Join(runtimeRoot, "credential-bindings.json")
	if err := os.WriteFile(credentialBindings, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	probeConfig, err := OperationPlanProbeConfigFromRuntimeLock(lock, "amd64", scriptPath, filepath.Join(planRoot, filepath.FromSlash(planBinding.IndexPath)), credentialBindings, filepath.Join(runtimeRoot, "receipts"), []string{"HEALTH_TEST_RECEIPT_TEMPLATE"})
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewOperationPlanProbeRunner(probeConfig)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewPinnedOperationPlanProbeExpectationResolver(plan, lock, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	historyValidator, err := NewOperationPlanProbeHistoryValidator(strings.Repeat("9", 40), resolver)
	if err != nil {
		t.Fatal(err)
	}
	history, err := OpenOperationHistoryStore(filepath.Join(runtimeRoot, "history"), 16<<20, historyValidator)
	if err != nil {
		t.Fatal(err)
	}
	attempts, err := OpenOperationAttemptStore(filepath.Join(runtimeRoot, "attempts"))
	if err != nil {
		t.Fatal(err)
	}
	quotas, err := OpenOperationQuotaAuthority(filepath.Join(runtimeRoot, "quotas"))
	if err != nil {
		t.Fatal(err)
	}

	var postCalls, getCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-gatus-token" {
			t.Errorf("synthetic Gatus token was not passed to the local endpoint")
		}
		switch r.Method {
		case http.MethodPost:
			postCalls++
			if r.URL.Path != "/api/v1/endpoints/"+target.GatusEndpointKey+"/external" || r.URL.Query().Get("success") != "true" || r.URL.Query().Get("duration") != "1ms" {
				t.Errorf("unexpected per-key external result: path_matches=%t success=%q duration=%q", r.URL.Path == "/api/v1/endpoints/"+target.GatusEndpointKey+"/external", r.URL.Query().Get("success"), r.URL.Query().Get("duration"))
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			getCalls++
			if r.URL.Path != "/api/v1/endpoints/"+target.GatusEndpointKey+"/statuses" || r.URL.Query().Get("page") != "1" || r.URL.Query().Get("pageSize") != "1" {
				t.Errorf("readback was not limited to the exact key/latest row")
			}
			fmt.Fprintf(w, `{"key":%q,"results":[{"success":true,"duration":1000000,"timestamp":%q}]}`, target.GatusEndpointKey, time.Now().UTC().Format(time.RFC3339Nano))
		default:
			t.Errorf("unexpected local Gatus method %s", r.Method)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	gatus, err := NewOperationPlanGatusDelivery(server.URL, "synthetic-gatus-token", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	config := OperationPlanWorkerConfig{
		Runtime: runtime, Runner: runner, Attempts: attempts, Quotas: quotas, History: history,
		HistoryValidator: historyValidator, Gatus: gatus, RuntimeLock: lock, Architecture: "amd64",
		AttemptLease: time.Minute, QuotaLease: time.Minute,
	}
	badConfig := config
	badConfig.Runner = unavailableOperationPlanProbeExecutor{}
	if _, err := NewOperationPlanWorker(badConfig); err == nil {
		t.Fatal("production constructor accepted an unattested fixture executor")
	}
	worker, err := NewOperationPlanWorker(config)
	if err != nil {
		t.Fatalf("production constructor rejected the verified local runner/runtime: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	quotaLockHeld := make(chan []*os.File, 1)
	worker.quotaRelease = 250 * time.Millisecond
	worker.runner = cancelAfterOperationPlanProbeExecutor{runner: runner, cancel: cancel, lockPaths: []string{filepath.Join(quotas.root, ".authority.lock")}, locked: quotaLockHeld}
	startedAt := time.Now()
	result, err := worker.ExecuteOne(ctx, target.Record.SourceID, target.Record.OperationID, time.Now().UTC())
	var quotaLocks []*os.File
	select {
	case quotaLocks = <-quotaLockHeld:
	default:
		t.Fatalf("synthetic child returned without acquiring the test quota lock: result=%#v err=%v", result, err)
	}
	maximumCommitTime := operationPlanPreDispatchCleanupTimeout + maxOperationPlanProbeDeadline + operationPlanPostChildCommitTimeout
	if err == nil || time.Since(startedAt) > maximumCommitTime || result.AttemptState != "observed" || result.DeliveryState != "not_ready" || !result.RequestStarted || result.ReceiptSHA256 == "" || ctx.Err() == nil {
		unlockOperationPlanTestLocks(quotaLocks)
		t.Fatalf("validated local child receipt was not committed despite caller cancellation: result=%#v err=%v canceled=%t", result, err, ctx.Err() != nil)
	}
	unlockOperationPlanTestLocks(quotaLocks)
	cancel()
	stored, found, err := attempts.GetAttempt(result.SourceID, result.OperationID, result.AttemptID, result.Generation)
	if err != nil || !found || stored.State != "observed" || stored.Result == nil || stored.Result.HistoryRecordID == "" || stored.DeliveryState != "not_ready" {
		t.Fatalf("archive proof was not committed to the durable attempt row: stored=%#v found=%t err=%v", stored, found, err)
	}
	usage, err := history.Usage(context.Background())
	if err != nil || usage.RecordCount != 1 || usage.ReservationCount != 0 {
		t.Fatalf("validated synthetic receipt was not durably appended: usage=%#v err=%v", usage, err)
	}
	deliveryCtx, deliveryCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer deliveryCancel()
	if err := worker.DeliverOne(deliveryCtx, result.SourceID, result.OperationID, result.AttemptID, result.Generation, time.Now().UTC(), time.Minute); err != nil {
		t.Fatalf("stored result could not pass the per-key Gatus push/readback path: %v", err)
	}
	stored, found, err = attempts.GetAttempt(result.SourceID, result.OperationID, result.AttemptID, result.Generation)
	if err != nil || !found || stored.DeliveryState != "readback_verified" || stored.DeliveryAckAt.IsZero() || stored.GatusReceivedAt.Before(stored.DeliveryAckAt) || postCalls != 1 || getCalls != 1 {
		t.Fatalf("Gatus ACK/readback were not stored as distinct events: stored=%#v found=%t post=%d get=%d err=%v", stored, found, postCalls, getCalls, err)
	}

	// Move only the fixture's due timestamp back by one observation period. This
	// preserves valid event ordering while making a second exact same-plan
	// attempt due without sleeping through the configured production interval.
	if err := attempts.withStoreLock(func() error {
		state, found, err := attempts.readState(target.Record.SourceID, target.Record.OperationID)
		if err != nil || !found || len(state.Attempts) == 0 {
			return ErrOperationAttemptUnavailable
		}
		latest := &state.Attempts[len(state.Attempts)-1]
		latest.StartedAt = time.Now().UTC().Add(-latest.Binding.ObservationPeriod - time.Minute)
		latest.LeaseExpiresAt = latest.StartedAt.Add(time.Minute)
		return attempts.writeState(state)
	}); err != nil {
		t.Fatal("could not prepare a due same-plan lock-contention regression", err)
	}
	secondQuotas, err := OpenOperationQuotaAuthority(filepath.Join(runtimeRoot, "second-quotas"))
	if err != nil {
		t.Fatal("could not open an isolated quota authority for the second synthetic attempt", err)
	}
	worker.quotas = secondQuotas

	attemptLockHeld := make(chan []*os.File, 1)
	worker.postChildCommit = 250 * time.Millisecond
	worker.runner = lockAfterOperationPlanProbeExecutor{runner: runner, lockPaths: []string{filepath.Join(attempts.root, ".operation-attempt.lock")}, locked: attemptLockHeld}
	startedAt = time.Now()
	blockedResult, blockedErr := worker.ExecuteOne(context.Background(), target.Record.SourceID, target.Record.OperationID, time.Now().UTC())
	var attemptLocks []*os.File
	select {
	case attemptLocks = <-attemptLockHeld:
	default:
		t.Fatalf("worker did not reach the post-child lock boundary: result=%#v err=%v", blockedResult, blockedErr)
	}
	if blockedErr == nil || time.Since(startedAt) > 3*time.Second || blockedResult.AttemptState != "observed" || blockedResult.ReceiptSHA256 == "" {
		unlockOperationPlanTestLocks(attemptLocks)
		t.Fatalf("attempt-store contention was not bounded after receipt archival: result=%#v err=%v duration=%s", blockedResult, blockedErr, time.Since(startedAt))
	}
	unlockOperationPlanTestLocks(attemptLocks)
	blockedAttempt, found, err := attempts.GetAttempt(blockedResult.SourceID, blockedResult.OperationID, blockedResult.AttemptID, blockedResult.Generation)
	if err != nil || !found || blockedAttempt.State != "claimed" || blockedAttempt.Result != nil {
		t.Fatalf("bounded commit timeout unexpectedly mutated the fenced attempt row: attempt=%#v found=%t err=%v", blockedAttempt, found, err)
	}
	usage, err = history.Usage(context.Background())
	if err != nil || usage.RecordCount != 2 || usage.ReservationCount != 0 {
		t.Fatalf("attempt-store lock caused a validated receipt to be lost: usage=%#v err=%v", usage, err)
	}
}

func testOperationPlanRuntimeLock(binarySHA string) runtimebundle.Lock {
	lock := runtimebundle.Lock{SchemaVersion: runtimebundle.Schema}
	lock.CLI.SourceSHA = strings.Repeat("a", 40)
	lock.CLI.Release = "v0.1.41"
	lock.CLI.Binaries = map[string]runtimebundle.Binary{
		"amd64": {ArchiveSHA256: strings.Repeat("b", 64), BinarySHA256: binarySHA},
		"arm64": {ArchiveSHA256: strings.Repeat("c", 64), BinarySHA256: strings.Repeat("d", 64)},
	}
	lock.Registry.DatasetRevision = strings.Repeat("e", 40)
	lock.Registry.DistributionRevision = strings.Repeat("e", 40)
	lock.Registry.DistributionSHA256 = strings.Repeat("f", 64)
	lock.Registry.SourceSHA = strings.Repeat("1", 40)
	lock.Registry.SourceRegistrySHA256 = strings.Repeat("2", 64)
	lock.Registry.ManifestSHA256 = strings.Repeat("3", 64)
	lock.Registry.CatalogSHA256 = strings.Repeat("4", 64)
	lock.Registry.ReleaseTag = lock.Registry.DatasetRevision
	lock.Registry.AcquiredAt = "2026-10-07T00:00:00Z"
	return lock
}
