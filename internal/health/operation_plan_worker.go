package health

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/StatPan/datapan-health/internal/runtimebundle"
)

var errOperationPlanWorkerUnavailable = errors.New("operation-plan worker is unavailable")

const operationPlanPostChildCommitTimeout = 15 * time.Second

const operationPlanPreDispatchCleanupTimeout = 5 * time.Second

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
	runtime          *VerifiedOperationPlanRuntime
	runner           OperationPlanProbeExecutor
	attempts         *OperationAttemptStore
	quotas           *OperationQuotaAuthority
	history          OperationHistoryAppender
	historyValidator OperationPlanProbeHistoryValidator
	gatus            OperationPlanGatusClient
	lock             runtimebundle.Lock
	arch             string
	attemptLease     time.Duration
	quotaLease       time.Duration
	targets          map[string]OperationPlanWorkerTarget
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
	worker := &OperationPlanWorker{
		runtime: config.Runtime, runner: config.Runner, attempts: config.Attempts, quotas: config.Quotas,
		history: config.History, historyValidator: config.HistoryValidator, gatus: config.Gatus,
		lock: config.RuntimeLock, arch: config.Architecture, attemptLease: config.AttemptLease,
		quotaLease: config.QuotaLease, targets: make(map[string]OperationPlanWorkerTarget, len(verifiedTargets)),
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
		expected, expectedErr := operationPlanProbeExpected(config.Runtime.Plan, target.Record, target.ShardSHA256, validationAttemptID, config.RuntimeLock, config.Architecture, validationTime)
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
func (worker *OperationPlanWorker) ExecuteOne(ctx context.Context, sourceID, operationID string, now time.Time) (OperationPlanWorkerResult, error) {
	if worker == nil || ctx == nil || ctx.Err() != nil || !validVerifiedOperationPlanRuntime(worker.runtime) || !operationSourceIDPattern.MatchString(sourceID) || operationID == "" || len(operationID) > 256 || now.IsZero() {
		return OperationPlanWorkerResult{}, errOperationPlanWorkerUnavailable
	}
	target, found := worker.targets[operationReadModelIdentityKey(sourceID, operationID)]
	if !found {
		return OperationPlanWorkerResult{}, errOperationPlanWorkerUnavailable
	}
	now = now.UTC()
	attemptID, err := NewOperationPlanProbeAttemptID()
	if err != nil {
		return OperationPlanWorkerResult{}, errOperationPlanWorkerUnavailable
	}
	binding := OperationAttemptBinding{
		SourceID: sourceID, OperationID: operationID, RegistryRevision: worker.runtime.Plan.RegistryRevision(),
		ReleaseManifestSHA: worker.runtime.Plan.binding.ReleaseManifestSHA256, IndexSHA: worker.runtime.Plan.IndexSHA256(),
		ShardSHA: target.ShardSHA256, GatusKey: target.GatusEndpointKey, ObservationPeriod: target.Record.ObservationPeriod,
	}
	claim, err := worker.attempts.BeginAttempt(binding, attemptID, now, worker.attemptLease)
	if err != nil {
		return OperationPlanWorkerResult{}, err
	}
	result := OperationPlanWorkerResult{SourceID: sourceID, OperationID: operationID, AttemptID: claim.AttemptID, Generation: claim.Generation, AttemptState: "claimed"}
	identity := OperationHistoryIdentity{
		SourceID: claim.Binding.SourceID, OperationID: claim.Binding.OperationID, AttemptID: claim.AttemptID,
		Generation: claim.Generation, RegistryRevision: claim.Binding.RegistryRevision,
		ReleaseManifestSHA256: claim.Binding.ReleaseManifestSHA, IndexSHA256: claim.Binding.IndexSHA, ShardSHA256: claim.Binding.ShardSHA,
	}
	expected, err := operationPlanProbeExpected(worker.runtime.Plan, target.Record, target.ShardSHA256, claim.AttemptID, worker.lock, worker.arch, claim.StartedAt)
	if err != nil {
		return worker.deferBeforeDispatch(claim, result, operationAttemptReasonChildUnavailable, now, nil, OperationHistoryReservation{})
	}
	reservation, err := worker.history.Reserve(ctx, identity)
	if err != nil {
		if reservation.Matches(identity) {
			_ = cancelOperationHistoryReservation(worker.history, identity, reservation)
		}
		reason := operationAttemptReasonChildUnavailable
		if errors.Is(err, ErrOperationHistoryCapacity) {
			reason = operationAttemptReasonHistoryCapacity
		}
		return worker.deferBeforeDispatch(claim, result, reason, now, nil, OperationHistoryReservation{})
	}
	quotaNow := time.Now().UTC()
	quotaClaims, err := worker.quotas.AcquireMany(target.Record.QuotaPolicies, attemptID, quotaNow, worker.quotaLease)
	if err != nil {
		cancelErr := cancelOperationHistoryReservation(worker.history, identity, reservation)
		reason := operationAttemptReasonChildUnavailable
		if errors.Is(err, ErrOperationQuotaExhausted) {
			reason = operationAttemptReasonQuotaCapacity
		}
		deferred, deferErr := worker.deferBeforeDispatch(claim, result, reason, quotaNow, nil, OperationHistoryReservation{})
		if cancelErr != nil {
			return deferred, errOperationPlanWorkerUnavailable
		}
		if deferErr != nil {
			return deferred, deferErr
		}
		return deferred, nil
	}
	deadlineNow := time.Now().UTC()
	deadline, deadlineOK := operationPlanProbeExecutionDeadline(deadlineNow, target.Record.RequestTimeout, claim.ExpiresAt, attemptID, quotaClaims)
	if !deadlineOK {
		_ = worker.quotas.ReleaseMany(quotaClaims, deadlineNow)
		return worker.deferBeforeDispatch(claim, result, operationAttemptReasonChildUnavailable, deadlineNow, worker.history, reservation)
	}
	probeResult, _, runErr := worker.runner.Run(ctx, expected, deadline)
	quotaReleaseErr := worker.quotas.ReleaseMany(quotaClaims, time.Now().UTC())
	if runErr != nil {
		finishedAt := time.Now().UTC()
		_ = worker.attempts.FailAttempt(claim, finishedAt)
		result.AttemptState = "unknown"
		if quotaReleaseErr != nil {
			return result, errOperationPlanWorkerUnavailable
		}
		return result, errOperationPlanWorkerUnavailable
	}
	// A valid receipt may already exist in memory even if the scheduler context
	// was canceled as the child returned. Preserve and commit that evidence with
	// a short independent cleanup deadline; dropping it would leave a request
	// that may have reached the provider without its validated receipt.
	commitCtx, cancelCommit := context.WithTimeout(context.Background(), operationPlanPostChildCommitTimeout)
	defer cancelCommit()
	record, err := worker.historyValidator.newRecord(identity, probeResult, expected, claim.StartedAt)
	if err != nil {
		_ = worker.attempts.FailAttempt(claim, time.Now().UTC())
		result.AttemptState = "unknown"
		return result, errOperationPlanWorkerUnavailable
	}
	ref, err := worker.history.AppendValidated(commitCtx, reservation, record)
	if err != nil || !ref.MatchesValidatedRecord(record) {
		_ = worker.attempts.FailAttempt(claim, time.Now().UTC())
		result.AttemptState = "unknown"
		return result, errOperationPlanWorkerUnavailable
	}
	completedAt := time.Now().UTC()
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
	if err != nil || quotaReleaseErr != nil {
		return result, errOperationPlanWorkerUnavailable
	}
	result.ReceiptSHA256 = probeResult.ReceiptSHA256
	return result, nil
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
	attempt, found, err := worker.attempts.GetAttempt(sourceID, operationID, attemptID, generation)
	if err != nil || !found || attempt.State != "observed" || attempt.Result == nil {
		return errOperationPlanWorkerUnavailable
	}
	if attempt.DeliveryState == "not_applicable" || attempt.DeliveryState == "readback_verified" {
		return nil
	}
	if attempt.DeliveryState == "acknowledged" {
		readbackAt, resultState, readErr := worker.gatus.Readback(ctx, attempt.Binding.GatusKey, *attempt.Result, attempt.DeliveryAckAt)
		if readErr != nil || worker.attempts.RecordGatusReadback(sourceID, operationID, attemptID, generation, readbackAt, resultState) != nil {
			return errOperationPlanWorkerUnavailable
		}
		return nil
	}
	claim, err := worker.attempts.ClaimDelivery(sourceID, operationID, attemptID, generation, now.UTC(), lease)
	if err != nil {
		return err
	}
	acknowledgedAt, err := worker.gatus.Push(ctx, claim.Binding.GatusKey, claim.Result)
	if err != nil || acknowledgedAt.IsZero() || worker.attempts.AcknowledgeDelivery(claim, acknowledgedAt) != nil {
		return errOperationPlanWorkerUnavailable
	}
	readbackAt, resultState, err := worker.gatus.Readback(ctx, claim.Binding.GatusKey, claim.Result, acknowledgedAt)
	if err != nil || readbackAt.IsZero() || worker.attempts.RecordGatusReadback(sourceID, operationID, attemptID, generation, readbackAt, resultState) != nil {
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
		if cancelOperationHistoryReservation(history, identity, reservation) != nil {
			return result, errOperationPlanWorkerUnavailable
		}
	}
	if worker.attempts.RecordPreDispatchDeferred(claim, reason, now.UTC()) != nil {
		return result, errOperationPlanWorkerUnavailable
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
