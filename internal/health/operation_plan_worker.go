package health

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"syscall"
	"time"

	"github.com/StatPan/datapan-health/internal/runtimebundle"
)

var errOperationPlanWorkerUnavailable = errors.New("operation-plan worker is unavailable")

// operationPlanWorkerFailure carries allowlisted diagnostic codes and keeps
// the cause private for errors.Is compatibility. Error remains the existing
// fixed redacted message for callers that log errors.
type operationPlanWorkerFailure struct {
	stage    string
	category string
	cause    error
}

func (failure *operationPlanWorkerFailure) Error() string {
	return errOperationPlanWorkerUnavailable.Error()
}

func (failure *operationPlanWorkerFailure) Is(target error) bool {
	return target == errOperationPlanWorkerUnavailable || failure != nil && errors.Is(failure.cause, target)
}

func newOperationPlanWorkerFailure(stage string, cause error) error {
	if !validOperationPlanWorkerFailureStage(stage) {
		stage = "unavailable"
	}
	return &operationPlanWorkerFailure{stage: stage, category: operationPlanWorkerFailureCategory(cause), cause: cause}
}

func validOperationPlanWorkerFailureStage(stage string) bool {
	switch stage {
	case "runtime_validation", "target_lookup", "attempt_id", "attempt_begin", "expectation", "history_reservation", "quota_acquire", "quota_acquire_cleanup", "pre_dispatch_cleanup", "execution_deadline", "runner", "history_validate", "history_append", "attempt_complete", "quota_release", "unavailable":
		return true
	default:
		return false
	}
}

func validOperationPlanWorkerFailureCategory(category string) bool {
	switch category {
	case "deadline", "canceled", "capacity", "lock", "io", "store_unavailable", "unavailable":
		return true
	default:
		return false
	}
}

func operationPlanWorkerFailureCategory(cause error) string {
	if cause == nil {
		return "unavailable"
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return "deadline"
	}
	if errors.Is(cause, context.Canceled) {
		return "canceled"
	}
	if errors.Is(cause, ErrOperationQuotaExhausted) || errors.Is(cause, ErrOperationAttemptCapacity) || errors.Is(cause, ErrOperationHistoryCapacity) || errors.Is(cause, ErrOperationAttemptHeld) || errors.Is(cause, ErrOperationAttemptNotDue) {
		return "capacity"
	}
	var quotaFailure *operationQuotaFailure
	if errors.As(cause, &quotaFailure) && quotaFailure.category != "" {
		if validOperationPlanWorkerFailureCategory(quotaFailure.category) {
			return quotaFailure.category
		}
	}
	var pathError *os.PathError
	var syscallError syscall.Errno
	if errors.As(cause, &pathError) || errors.As(cause, &syscallError) {
		return "io"
	}
	if errors.Is(cause, ErrOperationQuotaUnavailable) || errors.Is(cause, ErrOperationAttemptUnavailable) || errors.Is(cause, ErrOperationHistoryUnavailable) {
		return "store_unavailable"
	}
	return "unavailable"
}

const operationPlanPostChildCommitTimeout = 15 * time.Second

const operationPlanPreDispatchCleanupTimeout = 5 * time.Second

const operationPlanQuotaReleaseTimeout = 2 * time.Second

// OperationPlanProbeExecutor is the worker's single-operation child boundary.
// The production constructor accepts only an attested OperationPlanProbeRunner;
// same-package tests may instantiate the worker with a deterministic executor
// without reaching a provider.
type OperationPlanProbeExecutor interface {
	Run(context.Context, OperationPlanProbeExpectation, time.Time) (OperationPlanProbeResult, int, error)
}

// OperationPlanGatusClient is restricted to per-key push and readback. It has
// no aggregate endpoint method and cannot fan out to provider APIs.
type OperationPlanGatusClient interface {
	Push(context.Context, string, OperationObservationResult) (time.Time, error)
	Readback(context.Context, string, OperationObservationResult, time.Time) (time.Time, string, error)
}

type OperationPlanWorkerConfig struct {
	Runtime          *VerifiedOperationPlanRuntime
	Runner           OperationPlanProbeExecutor
	Attempts         *OperationAttemptStore
	Quotas           *OperationQuotaAuthority
	History          OperationHistoryAppender
	HistoryValidator OperationPlanProbeHistoryValidator
	Gatus            OperationPlanGatusClient
	RuntimeLock      runtimebundle.Lock
	Architecture     string
	AttemptLease     time.Duration
	QuotaLease       time.Duration
}

// OperationPlanWorker owns the fenced one-attempt path. It accepts only the
// exact active identities from a loader-sealed runtime and never accepts
// caller-supplied endpoints, request parameters, or credentials.
type OperationPlanWorker struct {
	runtime             *VerifiedOperationPlanRuntime
	runtimeIdentity     operationPlanWorkerRuntimeIdentity
	runtimeIdentitySeal string
	runner              OperationPlanProbeExecutor
	attempts            *OperationAttemptStore
	quotas              *OperationQuotaAuthority
	history             OperationHistoryAppender
	historyValidator    OperationPlanProbeHistoryValidator
	gatus               OperationPlanGatusClient
	lock                runtimebundle.Lock
	arch                string
	attemptLease        time.Duration
	quotaLease          time.Duration
	targets             map[string]OperationPlanWorkerTarget
	postChildCommit     time.Duration
	quotaRelease        time.Duration
}

type operationPlanWorkerRuntimeIdentity struct {
	verificationSeal      string
	registryRevision      string
	releaseManifestSHA256 string
	indexSHA256           string
	activationSHA256      string
	canaryConfigSHA256    string
	identityMappingSHA256 string
	runtimePinSHA256      string
	knownOperations       int
	admittedOperations    int
	suppressedLegacy      []string
}

type OperationPlanWorkerResult struct {
	SourceID             string
	OperationID          string
	AttemptID            string
	Generation           uint64
	AttemptState         string
	RequestStarted       bool
	ExecutionBlockReason string
	DeliveryState        string
	ReceiptSHA256        string
}

func NewOperationPlanWorker(config OperationPlanWorkerConfig) (*OperationPlanWorker, error) {
	productionRunner, ok := config.Runner.(*OperationPlanProbeRunner)
	if !ok || productionRunner == nil {
		return nil, errOperationPlanWorkerUnavailable
	}
	if err := productionRunner.VerifyExecutable(); err != nil {
		return nil, errOperationPlanWorkerUnavailable
	}
	return newOperationPlanWorker(config, productionRunner.config)
}

func newOperationPlanWorker(config OperationPlanWorkerConfig, runnerConfig OperationPlanProbeConfig) (*OperationPlanWorker, error) {
	if !validVerifiedOperationPlanRuntime(config.Runtime) || config.Runner == nil || config.Attempts == nil || config.Quotas == nil || config.History == nil || config.HistoryValidator.Expectations == nil || config.HistoryValidator.ValidatorRevision == "" || config.RuntimeLock.Validate() != nil || config.Architecture == "" || config.AttemptLease < maxOperationPlanProbeDeadline || config.AttemptLease > maxOperationAttemptLease || config.QuotaLease < maxOperationPlanProbeDeadline || config.QuotaLease > maxOperationQuotaLease {
		return nil, errOperationPlanWorkerUnavailable
	}
	resolver, ok := config.HistoryValidator.Expectations.(*PinnedOperationPlanProbeExpectationResolver)
	if !ok || resolver == nil || resolver.plan.RegistryRevision() != config.Runtime.Plan.RegistryRevision() || resolver.plan.binding.ReleaseManifestSHA256 != config.Runtime.Plan.binding.ReleaseManifestSHA256 || resolver.plan.IndexSHA256() != config.Runtime.Plan.IndexSHA256() {
		return nil, errOperationPlanWorkerUnavailable
	}
	verifiedTargets, err := exactActivePlanTargets(config.Runtime.Plan, config.Runtime.IdentityMapping)
	if err != nil || !sameOperationPlanWorkerTargets(config.Runtime.ActiveTargets, verifiedTargets) {
		return nil, errOperationPlanWorkerUnavailable
	}
	runtimeSnapshot, err := cloneVerifiedOperationPlanRuntime(config.Runtime)
	if err != nil {
		return nil, errOperationPlanWorkerUnavailable
	}
	verifiedTargets, err = exactActivePlanTargets(runtimeSnapshot.Plan, runtimeSnapshot.IdentityMapping)
	if err != nil || !sameOperationPlanWorkerTargets(runtimeSnapshot.ActiveTargets, verifiedTargets) {
		return nil, errOperationPlanWorkerUnavailable
	}
	resolverSnapshot := *resolver
	resolverSnapshot.plan = runtimeSnapshot.Plan
	resolverSnapshot.lock = cloneOperationPlanRuntimeLock(resolver.lock)
	resolverSnapshot.templates = make(map[string]OperationPlanProbeExpectation, len(resolver.templates))
	for key, expected := range resolver.templates {
		resolverSnapshot.templates[key] = expected
	}
	historyValidator := config.HistoryValidator
	historyValidator.Expectations = &resolverSnapshot
	worker := &OperationPlanWorker{
		runtime: runtimeSnapshot, runner: config.Runner, attempts: config.Attempts, quotas: config.Quotas,
		history: config.History, historyValidator: historyValidator, gatus: config.Gatus,
		lock: cloneOperationPlanRuntimeLock(config.RuntimeLock), arch: config.Architecture, attemptLease: config.AttemptLease,
		quotaLease: config.QuotaLease, targets: make(map[string]OperationPlanWorkerTarget, len(verifiedTargets)),
		postChildCommit: operationPlanPostChildCommitTimeout, quotaRelease: operationPlanQuotaReleaseTimeout,
	}
	worker.runtimeIdentity = operationPlanWorkerRuntimeIdentityFromRuntime(runtimeSnapshot)
	worker.runtimeIdentitySeal = operationPlanWorkerRuntimeIdentitySeal(worker.runtimeIdentity)
	if !worker.validRuntimeSnapshot() {
		return nil, errOperationPlanWorkerUnavailable
	}
	const validationAttemptID = "00000000-0000-4000-8000-000000000000"
	validationTime := time.Unix(1, 0).UTC()
	for _, target := range verifiedTargets {
		if !validOperationWorkerTarget(target) {
			return nil, errOperationPlanWorkerUnavailable
		}
		key := operationReadModelIdentityKey(target.Record.SourceID, target.Record.OperationID)
		if _, duplicate := worker.targets[key]; duplicate {
			return nil, errOperationPlanWorkerUnavailable
		}
		expected, expectedErr := operationPlanProbeExpected(runtimeSnapshot.Plan, target.Record, target.ShardSHA256, validationAttemptID, worker.lock, config.Architecture, validationTime)
		if expectedErr != nil || !validOperationProbeExpectation(expected, runnerConfig) {
			return nil, errOperationPlanWorkerUnavailable
		}
		worker.targets[key] = cloneOperationPlanWorkerTarget(target)
	}
	return worker, nil
}

// ExecuteOne runs one due-checked active identity. A call with an unknown or
// inactive identity performs no attempt, quota reservation, child spawn, or
// network request.
func (worker *OperationPlanWorker) ExecuteOne(ctx context.Context, sourceID, operationID string, now time.Time) (result OperationPlanWorkerResult, runErr error) {
	stage := "runtime_validation"
	defer func() {
		if runErr == nil {
			return
		}
		var failure *operationPlanWorkerFailure
		if !errors.As(runErr, &failure) {
			runErr = newOperationPlanWorkerFailure(stage, runErr)
		}
	}()
	if worker == nil || ctx == nil || ctx.Err() != nil || !worker.validRuntimeSnapshot() || !operationSourceIDPattern.MatchString(sourceID) || operationID == "" || len(operationID) > 256 || now.IsZero() {
		return OperationPlanWorkerResult{}, errOperationPlanWorkerUnavailable
	}
	stage = "target_lookup"
	target, found := worker.targets[operationReadModelIdentityKey(sourceID, operationID)]
	if !found {
		return OperationPlanWorkerResult{}, errOperationPlanWorkerUnavailable
	}
	now = now.UTC()
	stage = "attempt_id"
	attemptID, err := NewOperationPlanProbeAttemptID()
	if err != nil {
		return OperationPlanWorkerResult{}, errOperationPlanWorkerUnavailable
	}
	binding := OperationAttemptBinding{
		SourceID: sourceID, OperationID: operationID, RegistryRevision: worker.runtime.Plan.RegistryRevision(),
		ReleaseManifestSHA: worker.runtime.Plan.binding.ReleaseManifestSHA256, IndexSHA: worker.runtime.Plan.IndexSHA256(),
		ShardSHA: target.ShardSHA256, GatusKey: target.GatusEndpointKey, ObservationPeriod: target.Record.ObservationPeriod,
	}
	preDispatchCtx, cancelPreDispatch := context.WithTimeout(ctx, operationPlanPreDispatchCleanupTimeout)
	defer cancelPreDispatch()
	stage = "attempt_begin"
	claim, err := worker.attempts.BeginAttemptContext(preDispatchCtx, binding, attemptID, now, worker.attemptLease)
	if err != nil {
		return OperationPlanWorkerResult{}, err
	}
	result = OperationPlanWorkerResult{SourceID: sourceID, OperationID: operationID, AttemptID: claim.AttemptID, Generation: claim.Generation, AttemptState: "claimed"}
	identity := OperationHistoryIdentity{
		SourceID: claim.Binding.SourceID, OperationID: claim.Binding.OperationID, AttemptID: claim.AttemptID,
		Generation: claim.Generation, RegistryRevision: claim.Binding.RegistryRevision,
		ReleaseManifestSHA256: claim.Binding.ReleaseManifestSHA, IndexSHA256: claim.Binding.IndexSHA, ShardSHA256: claim.Binding.ShardSHA,
	}
	stage = "expectation"
	expected, err := operationPlanProbeExpected(worker.runtime.Plan, target.Record, target.ShardSHA256, claim.AttemptID, worker.lock, worker.arch, claim.StartedAt)
	if err != nil {
		return worker.deferBeforeDispatch(claim, result, operationAttemptReasonChildUnavailable, now, nil, OperationHistoryReservation{})
	}
	stage = "history_reservation"
	reservation, err := worker.history.Reserve(preDispatchCtx, identity)
	if err != nil {
		if reservation.Matches(identity) {
			if cancelErr := cancelOperationHistoryReservation(worker.history, identity, reservation); cancelErr != nil {
				return result, newOperationPlanWorkerFailure("pre_dispatch_cleanup", cancelErr)
			}
		}
		reason := operationAttemptReasonChildUnavailable
		if errors.Is(err, ErrOperationHistoryCapacity) {
			reason = operationAttemptReasonHistoryCapacity
		}
		return worker.deferBeforeDispatch(claim, result, reason, now, nil, OperationHistoryReservation{})
	}
	quotaNow := time.Now().UTC()
	stage = "quota_acquire"
	quotaClaims, _, err := worker.quotas.acquireManyLiveContext(preDispatchCtx, target.Record.QuotaPolicies, attemptID, worker.quotaLease)
	if err != nil {
		stage = "quota_acquire_cleanup"
		cancelErr := cancelOperationHistoryReservation(worker.history, identity, reservation)
		reason := operationAttemptReasonChildUnavailable
		if errors.Is(err, ErrOperationQuotaExhausted) {
			reason = operationAttemptReasonQuotaCapacity
		}
		deferred, deferErr := worker.deferBeforeDispatch(claim, result, reason, quotaNow, nil, OperationHistoryReservation{})
		if cancelErr != nil {
			return deferred, newOperationPlanWorkerFailure("quota_acquire_cleanup", cancelErr)
		}
		if deferErr != nil {
			return deferred, deferErr
		}
		return deferred, nil
	}
	deadlineNow := time.Now().UTC()
	stage = "execution_deadline"
	deadline, deadlineOK := operationPlanProbeExecutionDeadline(deadlineNow, target.Record.RequestTimeout, claim.ExpiresAt, attemptID, quotaClaims)
	if !deadlineOK {
		releasedErr := worker.releaseQuotaClaims(quotaClaims)
		deferred, deferErr := worker.deferBeforeDispatch(claim, result, operationAttemptReasonChildUnavailable, deadlineNow, worker.history, reservation)
		if deferErr != nil {
			return deferred, deferErr
		}
		if releasedErr != nil {
			return deferred, newOperationPlanWorkerFailure("quota_release", releasedErr)
		}
		return deferred, nil
	}
	stage = "runner"
	probeResult, _, runErr := worker.runner.Run(ctx, expected, deadline)
	if runErr != nil {
		finishedAt := time.Now().UTC()
		commitCtx, cancelCommit := worker.newPostChildCommitContext()
		_ = worker.attempts.failAttemptContext(commitCtx, claim, finishedAt)
		cancelCommit()
		_ = worker.releaseQuotaClaims(quotaClaims)
		result.AttemptState = "unknown"
		return result, newOperationPlanWorkerFailure("runner", runErr)
	}
	// A valid receipt may already exist in memory even if the scheduler context
	// was canceled as the child returned. Preserve and commit that evidence with
	// a short independent cleanup deadline; dropping it would leave a request
	// that may have reached the provider without its validated receipt.
	commitCtx, cancelCommit := worker.newPostChildCommitContext()
	defer cancelCommit()
	stage = "history_validate"
	record, err := worker.historyValidator.newRecord(identity, probeResult, expected, claim.StartedAt)
	if err != nil {
		_ = worker.attempts.failAttemptContext(commitCtx, claim, time.Now().UTC())
		_ = worker.releaseQuotaClaims(quotaClaims)
		result.AttemptState = "unknown"
		return result, newOperationPlanWorkerFailure("history_validate", err)
	}
	stage = "history_append"
	ref, err := worker.history.AppendValidated(commitCtx, reservation, record)
	if err != nil || !ref.MatchesValidatedRecord(record) {
		_ = worker.attempts.failAttemptContext(commitCtx, claim, time.Now().UTC())
		_ = worker.releaseQuotaClaims(quotaClaims)
		result.AttemptState = "unknown"
		if err == nil {
			err = ErrOperationHistoryUnavailable
		}
		return result, newOperationPlanWorkerFailure("history_append", err)
	}
	completedAt := time.Now().UTC()
	stage = "attempt_complete"
	if !probeResult.RequestStarted {
		err = worker.attempts.RecordBlockedAttemptFromValidatedHistory(commitCtx, claim, record, ref, worker.historyValidator, completedAt)
		result.AttemptState = "failed"
		result.ExecutionBlockReason, _ = operationPlanProbeBlockedReason(probeResult.ReasonCode)
	} else if probeResult.ObservedAt.IsZero() {
		err = worker.attempts.RecordRequestStartedFromValidatedHistory(commitCtx, claim, record, ref, worker.historyValidator, completedAt)
		result.AttemptState = "request_started"
		result.RequestStarted = true
	} else {
		err = worker.attempts.CompleteAttemptFromValidatedHistory(commitCtx, claim, record, ref, worker.historyValidator, completedAt)
		result.AttemptState = "observed"
		result.RequestStarted = true
		state, category := operationObservationClassification(probeResult)
		if category == "response_semantics_unestablished" && state == "indeterminate" {
			result.DeliveryState = "not_applicable"
		} else {
			result.DeliveryState = "not_ready"
		}
	}
	result.ReceiptSHA256 = probeResult.ReceiptSHA256
	stage = "quota_release"
	quotaReleaseErr := worker.releaseQuotaClaims(quotaClaims)
	if err != nil {
		return result, newOperationPlanWorkerFailure("attempt_complete", err)
	}
	if quotaReleaseErr != nil {
		return result, quotaReleaseErr
	}
	return result, nil
}

func operationPlanWorkerRuntimeIdentityFromRuntime(runtime *VerifiedOperationPlanRuntime) operationPlanWorkerRuntimeIdentity {
	if runtime == nil {
		return operationPlanWorkerRuntimeIdentity{}
	}
	suppressed := append([]string(nil), runtime.SuppressedLegacy...)
	sort.Strings(suppressed)
	return operationPlanWorkerRuntimeIdentity{
		verificationSeal: runtime.verificationSeal, registryRevision: runtime.Plan.RegistryRevision(),
		releaseManifestSHA256: runtime.IdentityMapping.ReleaseManifestSHA256, indexSHA256: runtime.Plan.IndexSHA256(),
		activationSHA256: runtime.IdentityMapping.ActivationSHA256, canaryConfigSHA256: runtime.IdentityMapping.CanaryConfigSHA256,
		identityMappingSHA256: runtime.Artifacts.MappingSHA256, runtimePinSHA256: runtime.Artifacts.RuntimePinSHA256,
		knownOperations: runtime.Plan.Counts().KnownOperations, admittedOperations: len(runtime.ActiveTargets),
		suppressedLegacy: suppressed,
	}
}

func operationPlanWorkerRuntimeIdentitySeal(identity operationPlanWorkerRuntimeIdentity) string {
	if !sha256Pattern.MatchString(identity.verificationSeal) || identity.registryRevision == "" ||
		!sha256Pattern.MatchString(identity.releaseManifestSHA256) || !sha256Pattern.MatchString(identity.indexSHA256) ||
		!sha256Pattern.MatchString(identity.activationSHA256) || !sha256Pattern.MatchString(identity.canaryConfigSHA256) ||
		!sha256Pattern.MatchString(identity.identityMappingSHA256) || !sha256Pattern.MatchString(identity.runtimePinSHA256) ||
		identity.knownOperations < 0 || identity.knownOperations > maxOperationGatusTargets ||
		identity.admittedOperations < 0 || identity.admittedOperations > identity.knownOperations ||
		len(identity.suppressedLegacy) > 100 || !isSortedUniqueOperationPlanIDs(identity.suppressedLegacy) {
		return ""
	}
	wire := struct {
		VerificationSeal      string   `json:"verification_seal"`
		RegistryRevision      string   `json:"registry_revision"`
		ReleaseManifestSHA256 string   `json:"release_manifest_sha256"`
		IndexSHA256           string   `json:"index_sha256"`
		ActivationSHA256      string   `json:"activation_sha256"`
		CanaryConfigSHA256    string   `json:"canary_config_sha256"`
		IdentityMappingSHA256 string   `json:"identity_mapping_sha256"`
		RuntimePinSHA256      string   `json:"runtime_pin_sha256"`
		KnownOperations       int      `json:"known_operations"`
		AdmittedOperations    int      `json:"admitted_operations"`
		SuppressedLegacy      []string `json:"suppressed_legacy"`
	}{
		VerificationSeal: identity.verificationSeal, RegistryRevision: identity.registryRevision,
		ReleaseManifestSHA256: identity.releaseManifestSHA256, IndexSHA256: identity.indexSHA256,
		ActivationSHA256: identity.activationSHA256, CanaryConfigSHA256: identity.canaryConfigSHA256,
		IdentityMappingSHA256: identity.identityMappingSHA256, RuntimePinSHA256: identity.runtimePinSHA256,
		KnownOperations: identity.knownOperations, AdmittedOperations: identity.admittedOperations,
		SuppressedLegacy: identity.suppressedLegacy,
	}
	raw, err := json.Marshal(wire)
	if err != nil || len(raw) == 0 {
		return ""
	}
	return digestOperationGatusBytes(raw)
}

// validRuntimeSnapshot checks only immutable constructor-owned summary fields.
// The loader and worker constructor already validated the complete target set;
// no status or worker hot path hashes the fleet again.
func (worker *OperationPlanWorker) validRuntimeSnapshot() bool {
	if worker == nil || worker.runtime == nil || !worker.runtime.verified || worker.runtimeIdentitySeal == "" ||
		operationPlanWorkerRuntimeIdentitySeal(worker.runtimeIdentity) != worker.runtimeIdentitySeal ||
		worker.runtime.verificationSeal != worker.runtimeIdentity.verificationSeal || worker.runtime.Plan.state == nil || !worker.runtime.Plan.state.verified {
		return false
	}
	runtime := worker.runtime
	identity := worker.runtimeIdentity
	if runtime.Plan.RegistryRevision() != identity.registryRevision || runtime.Plan.binding.ReleaseManifestSHA256 != identity.releaseManifestSHA256 ||
		runtime.Plan.IndexSHA256() != identity.indexSHA256 || runtime.Plan.Counts().KnownOperations != identity.knownOperations ||
		len(runtime.ActiveTargets) != identity.admittedOperations || runtime.IdentityMapping.ReleaseManifestSHA256 != identity.releaseManifestSHA256 ||
		runtime.IdentityMapping.ActivationSHA256 != identity.activationSHA256 || runtime.IdentityMapping.CanaryConfigSHA256 != identity.canaryConfigSHA256 ||
		runtime.Artifacts.MappingSHA256 != identity.identityMappingSHA256 || runtime.Artifacts.RuntimePinSHA256 != identity.runtimePinSHA256 ||
		!equalOperationPlanIdentityLists(runtime.SuppressedLegacy, identity.suppressedLegacy) {
		return false
	}
	return true
}

func cloneOperationPlanRuntimeLock(lock runtimebundle.Lock) runtimebundle.Lock {
	clone := lock
	clone.CLI.Binaries = make(map[string]runtimebundle.Binary, len(lock.CLI.Binaries))
	for architecture, binary := range lock.CLI.Binaries {
		clone.CLI.Binaries[architecture] = binary
	}
	return clone
}

func (worker *OperationPlanWorker) newPostChildCommitContext() (context.Context, context.CancelFunc) {
	deadline := operationPlanPostChildCommitTimeout
	if worker != nil && worker.postChildCommit > 0 && worker.postChildCommit < deadline {
		deadline = worker.postChildCommit
	}
	return context.WithTimeout(context.Background(), deadline)
}

func (worker *OperationPlanWorker) releaseQuotaClaims(claims []OperationQuotaClaim) error {
	if worker == nil || worker.quotas == nil || len(claims) == 0 {
		return ErrOperationQuotaUnavailable
	}
	deadline := operationPlanQuotaReleaseTimeout
	if worker.quotaRelease > 0 && worker.quotaRelease < deadline {
		deadline = worker.quotaRelease
	}
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	return worker.quotas.releaseManyLiveContext(ctx, claims)
}

func operationPlanProbeExecutionDeadline(now time.Time, requestTimeout time.Duration, attemptExpiresAt time.Time, attemptID string, quotaClaims []OperationQuotaClaim) (time.Time, bool) {
	if now.IsZero() || attemptExpiresAt.IsZero() || requestTimeout <= 0 || !quotaAttemptIDPattern.MatchString(attemptID) || len(quotaClaims) == 0 {
		return time.Time{}, false
	}
	deadline := now.UTC().Add(requestTimeout + maxOperationPlanProbeProcessOverhead)
	if !deadline.After(now) || deadline.Sub(now) > maxOperationPlanProbeDeadline || !deadline.Before(attemptExpiresAt) {
		return time.Time{}, false
	}
	for _, claim := range quotaClaims {
		if claim.Generation == 0 || claim.AttemptID != attemptID || claim.ExpiresAt.IsZero() || !deadline.Before(claim.ExpiresAt) {
			return time.Time{}, false
		}
	}
	return deadline, true
}

// DeliverOne retries a pending external result or its readback without ever
// repeating the provider request. A 2xx observation-only result is persisted
// with delivery_state=not_applicable and therefore bypasses Gatus entirely.
func (worker *OperationPlanWorker) DeliverOne(ctx context.Context, sourceID, operationID, attemptID string, generation uint64, now time.Time, lease time.Duration) error {
	if worker == nil || worker.attempts == nil || worker.gatus == nil || ctx == nil || ctx.Err() != nil || now.IsZero() {
		return errOperationPlanWorkerUnavailable
	}
	attempt, found, err := worker.attempts.GetAttemptContext(ctx, sourceID, operationID, attemptID, generation)
	if err != nil || !found || attempt.State != "observed" || attempt.Result == nil {
		return errOperationPlanWorkerUnavailable
	}
	if attempt.DeliveryState == "not_applicable" || attempt.DeliveryState == "readback_verified" {
		return nil
	}
	if attempt.DeliveryState == "acknowledged" {
		readbackAt, resultState, readErr := worker.gatus.Readback(ctx, attempt.Binding.GatusKey, *attempt.Result, attempt.DeliveryAckAt)
		if readErr != nil || worker.attempts.RecordGatusReadbackContext(ctx, sourceID, operationID, attemptID, generation, readbackAt, resultState) != nil {
			return errOperationPlanWorkerUnavailable
		}
		return nil
	}
	claim, err := worker.attempts.ClaimDeliveryContext(ctx, sourceID, operationID, attemptID, generation, now.UTC(), lease)
	if err != nil {
		return err
	}
	acknowledgedAt, err := worker.gatus.Push(ctx, claim.Binding.GatusKey, claim.Result)
	if err != nil || acknowledgedAt.IsZero() || worker.attempts.AcknowledgeDeliveryContext(ctx, claim, acknowledgedAt) != nil {
		return errOperationPlanWorkerUnavailable
	}
	readbackAt, resultState, err := worker.gatus.Readback(ctx, claim.Binding.GatusKey, claim.Result, acknowledgedAt)
	if err != nil || readbackAt.IsZero() || worker.attempts.RecordGatusReadbackContext(ctx, sourceID, operationID, attemptID, generation, readbackAt, resultState) != nil {
		return errOperationPlanWorkerUnavailable
	}
	return nil
}

func (worker *OperationPlanWorker) deferBeforeDispatch(claim OperationAttemptClaim, result OperationPlanWorkerResult, reason string, now time.Time, history OperationHistoryAppender, reservation OperationHistoryReservation) (OperationPlanWorkerResult, error) {
	if history != nil && reservation.Matches(OperationHistoryIdentity{
		SourceID: claim.Binding.SourceID, OperationID: claim.Binding.OperationID, AttemptID: claim.AttemptID,
		Generation: claim.Generation, RegistryRevision: claim.Binding.RegistryRevision,
		ReleaseManifestSHA256: claim.Binding.ReleaseManifestSHA, IndexSHA256: claim.Binding.IndexSHA, ShardSHA256: claim.Binding.ShardSHA,
	}) {
		identity := OperationHistoryIdentity{
			SourceID: claim.Binding.SourceID, OperationID: claim.Binding.OperationID, AttemptID: claim.AttemptID,
			Generation: claim.Generation, RegistryRevision: claim.Binding.RegistryRevision,
			ReleaseManifestSHA256: claim.Binding.ReleaseManifestSHA, IndexSHA256: claim.Binding.IndexSHA, ShardSHA256: claim.Binding.ShardSHA,
		}
		if err := cancelOperationHistoryReservation(history, identity, reservation); err != nil {
			return result, newOperationPlanWorkerFailure("pre_dispatch_cleanup", err)
		}
	}
	deferCtx, cancel := context.WithTimeout(context.Background(), operationPlanPreDispatchCleanupTimeout)
	defer cancel()
	if err := worker.attempts.recordPreDispatchDeferredContext(deferCtx, claim, reason, now.UTC()); err != nil {
		return result, newOperationPlanWorkerFailure("pre_dispatch_cleanup", err)
	}
	result.AttemptState = "deferred"
	result.ExecutionBlockReason = reason
	return result, nil
}

func cancelOperationHistoryReservation(history OperationHistoryAppender, identity OperationHistoryIdentity, reservation OperationHistoryReservation) error {
	if history == nil || !reservation.Matches(identity) {
		return errOperationPlanWorkerUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), operationPlanPreDispatchCleanupTimeout)
	defer cancel()
	return history.CancelReservation(ctx, identity, reservation)
}

func sameOperationPlanWorkerTargets(left, right []OperationPlanWorkerTarget) bool {
	leftRaw, leftErr := jsonMarshalOperationWorkerTargets(left)
	rightRaw, rightErr := jsonMarshalOperationWorkerTargets(right)
	return leftErr == nil && rightErr == nil && digestOperationGatusBytes(leftRaw) == digestOperationGatusBytes(rightRaw)
}

func validOperationWorkerTarget(target OperationPlanWorkerTarget) bool {
	return operationSourceIDPattern.MatchString(target.Record.SourceID) && target.Record.OperationID != "" && len(target.Record.OperationID) <= 256 && sha256Pattern.MatchString(target.ShardSHA256) && validPlanGatusEndpointKey(target.GatusEndpointKey) && target.Record.ExecutionEligible && target.Record.RequestPlanStatus == "complete" && target.Record.RuntimeBindingStatus == "bound" && target.Record.AdmissionStatus == "admitted" && target.Record.QuotaPoliciesAdmitted && target.Record.ObservationPeriod >= time.Second && target.Record.RequestTimeout > 0 && len(target.Record.QuotaPolicies) > 0
}

func cloneOperationPlanWorkerTarget(target OperationPlanWorkerTarget) OperationPlanWorkerTarget {
	target.Record.LegacySelectors = append([]string(nil), target.Record.LegacySelectors...)
	target.Record.RequestPlanMissing = append([]string(nil), target.Record.RequestPlanMissing...)
	target.Record.RuntimeBindingMissing = append([]string(nil), target.Record.RuntimeBindingMissing...)
	target.Record.AdmissionReasons = append([]string(nil), target.Record.AdmissionReasons...)
	target.Record.QuotaPolicies = append([]OperationQuotaPolicy(nil), target.Record.QuotaPolicies...)
	target.Record.quotaBindings = append([]operationQuotaPolicyBinding(nil), target.Record.quotaBindings...)
	return target
}

func jsonMarshalOperationWorkerTargets(targets []OperationPlanWorkerTarget) ([]byte, error) {
	return json.Marshal(targets)
}
