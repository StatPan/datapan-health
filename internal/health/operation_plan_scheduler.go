package health

import (
	"context"
	"errors"
	"math"
	"sort"
	"sync"
	"time"
)

var errOperationPlanSchedulerUnavailable = errors.New("operation-plan scheduler is unavailable")

type operationPlanSchedulerFailure struct {
	stage    string
	category string
}

func (failure *operationPlanSchedulerFailure) Error() string {
	return errOperationPlanSchedulerUnavailable.Error()
}

func (failure *operationPlanSchedulerFailure) Unwrap() error {
	return errOperationPlanSchedulerUnavailable
}

func newOperationPlanSchedulerFailure(stage, category string) error {
	if !validOperationPlanSchedulerFailureStage(stage) {
		stage = "unavailable"
	}
	if !validOperationPlanSchedulerFailureCategory(category) {
		category = "unavailable"
	}
	return &operationPlanSchedulerFailure{stage: stage, category: category}
}

func operationPlanSchedulerFailureDetails(err error) (stage, category string, ok bool) {
	var failure *operationPlanSchedulerFailure
	if !errors.As(err, &failure) || failure == nil {
		return "", "", false
	}
	return failure.stage, failure.category, true
}

func validOperationPlanSchedulerFailureStage(stage string) bool {
	switch stage {
	case "entry", "pass_overlap", "delivery_scan", "execution_scan", "evidence_snapshot", "evidence_proof", "unavailable":
		return true
	default:
		return false
	}
}

func validOperationPlanSchedulerFailureCategory(category string) bool {
	switch category {
	case "invalid_input", "busy", "parent_deadline", "parent_canceled", "scan_deadline", "scan_canceled", "store_unavailable", "proof_unavailable", "unavailable":
		return true
	default:
		return false
	}
}

func operationPlanSchedulerParentContextFailureCategory(ctx context.Context) string {
	if ctx == nil {
		return "invalid_input"
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "parent_deadline"
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return "parent_canceled"
	}
	return "store_unavailable"
}

func operationPlanSchedulerScanContextFailureCategory(parent, scan context.Context) string {
	if parent != nil && parent.Err() != nil {
		return operationPlanSchedulerParentContextFailureCategory(parent)
	}
	if scan != nil && errors.Is(scan.Err(), context.DeadlineExceeded) {
		return "scan_deadline"
	}
	if scan != nil && errors.Is(scan.Err(), context.Canceled) {
		return "scan_canceled"
	}
	return "store_unavailable"
}

const (
	operationPlanSchedulerMaximumConcurrency = 32
	operationPlanSchedulerMaximumScanBudget  = 256
	operationPlanSchedulerPassInterval       = time.Second
	operationPlanSchedulerScanTimeout        = 2 * time.Second
	operationPlanDeliveryTimeout             = 15 * time.Second
)

// OperationPlanSchedulerConfig supplies explicit local capacity. A zero
// admitted target set can be inspected, but cannot be reported ready.
type OperationPlanSchedulerConfig struct {
	Worker               *OperationPlanWorker
	MaxConcurrent        int
	MaxStartsPerPass     int
	MaxDeliveriesPerPass int
	CandidateScanPerPass int
	DeliveryLease        time.Duration
}

// OperationPlanSchedulerStatus is a bounded operational summary. Its counts
// are process-local counters since startup, not claims about durable fleet
// coverage or native Gatus delivery.
type OperationPlanSchedulerStatus struct {
	SchemaVersion                   string            `json:"schema_version"`
	State                           string            `json:"state"`
	Ready                           bool              `json:"ready"`
	Reason                          string            `json:"reason,omitempty"`
	RegistryRevision                string            `json:"registry_revision,omitempty"`
	ReleaseManifestSHA256           string            `json:"release_manifest_sha256,omitempty"`
	IndexSHA256                     string            `json:"index_sha256,omitempty"`
	ActivationSHA256                string            `json:"activation_sha256,omitempty"`
	CanaryConfigSHA256              string            `json:"canary_config_sha256,omitempty"`
	IdentityMappingSHA256           string            `json:"identity_mapping_sha256,omitempty"`
	RuntimePinSHA256                string            `json:"runtime_pin_sha256,omitempty"`
	SuppressedLegacyCanaries        []string          `json:"suppressed_legacy_canaries,omitempty"`
	KnownOperations                 int               `json:"known_operations"`
	AdmittedOperations              int               `json:"admitted_operations"`
	ActiveWork                      int               `json:"active_work"`
	MaxConcurrent                   int               `json:"max_concurrent"`
	MaxStartsPerSecond              int               `json:"max_starts_per_second"`
	CandidateScanPerSecond          int               `json:"candidate_scan_per_second"`
	RequiredStartsPerSecond         float64           `json:"required_starts_per_second"`
	RequiredConcurrency             int               `json:"required_concurrency"`
	CapacityFeasible                bool              `json:"capacity_feasible"`
	CapacityFailureScopes           int               `json:"capacity_failure_scopes"`
	EvidenceSweepAt                 time.Time         `json:"evidence_sweep_at,omitempty"`
	EvidenceCheckedOperations       int               `json:"evidence_checked_operations"`
	EvidenceCurrentOperations       int               `json:"evidence_current_operations"`
	EvidenceMissingOperations       int               `json:"evidence_missing_operations"`
	EvidenceValidUntil              time.Time         `json:"evidence_valid_until,omitempty"`
	LastPassAt                      time.Time         `json:"last_pass_at,omitempty"`
	LastPassAgeSeconds              int64             `json:"last_pass_age_seconds,omitempty"`
	LastErrorReason                 string            `json:"last_error_reason,omitempty"`
	LastErrorStage                  string            `json:"last_error_stage,omitempty"`
	lastErrorCategory               string            `json:"-"`
	lastDiagnosticFailureStage      string            `json:"-"`
	lastDiagnosticFailureCategory   string            `json:"-"`
	failureStageCounts              map[string]uint64 `json:"-"`
	failureCategoryCounts           map[string]uint64 `json:"-"`
	lastPassElapsed                 time.Duration     `json:"-"`
	lastPassDeliveryScanned         int               `json:"-"`
	lastPassExecutionScanned        int               `json:"-"`
	lastPassEvidenceScanned         int               `json:"-"`
	LastErrorAt                     time.Time         `json:"last_error_at,omitempty"`
	PassesSinceStart                uint64            `json:"passes_since_start"`
	ExecutionTasksStartedSinceStart uint64            `json:"execution_tasks_started_since_start"`
	RequestStartsSinceStart         uint64            `json:"request_starts_since_start"`
	ObservationsSinceStart          uint64            `json:"observations_since_start"`
	DeferredSinceStart              uint64            `json:"deferred_since_start"`
	ExecutionFailuresSinceStart     uint64            `json:"execution_failures_since_start"`
	DeliveryTasksStartedSinceStart  uint64            `json:"delivery_tasks_started_since_start"`
	ReadbacksSinceStart             uint64            `json:"readbacks_since_start"`
	NotApplicableSinceStart         uint64            `json:"not_applicable_since_start"`
	DeliveryFailuresSinceStart      uint64            `json:"delivery_failures_since_start"`
	PendingDeliveryScanFailures     uint64            `json:"pending_delivery_scan_failures"`
	IdentityScanFailuresSinceStart  uint64            `json:"identity_scan_failures_since_start"`
}

type operationPlanCapacityAssessment struct {
	RequiredStartsPerSecond float64
	RequiredConcurrency     int
	FailureScopes           int
	Feasible                bool
}

type operationPlanScopeDemand struct {
	policy         OperationQuotaPolicy
	requestsPerSec float64
	concurrentLoad float64
}

type operationPlanReadinessEvidence struct {
	Proven     bool
	ProofAt    time.Time
	ValidUntil time.Time
}

type operationPlanIdentityError struct {
	At               time.Time
	RequiresNewProof bool
}

type OperationPlanScheduler struct {
	worker        *OperationPlanWorker
	targets       []OperationPlanWorkerTarget
	maxConcurrent int
	maxStarts     int
	maxDeliveries int
	scanBudget    int
	deliveryLease time.Duration
	capacity      operationPlanCapacityAssessment

	mu                            sync.Mutex
	passMu                        sync.Mutex
	active                        map[string]string
	activeCount                   int
	executionCursor               int
	deliveryCursor                int
	deliveryReservation           int
	lastPass                      time.Time
	lastErrorReason               string
	lastErrorStage                string
	lastErrorCategory             string
	lastDiagnosticFailureStage    string
	lastDiagnosticFailureCategory string
	failureStageCounts            map[string]uint64
	failureCategoryCounts         map[string]uint64
	lastPassElapsed               time.Duration
	lastPassDeliveryScanned       int
	lastPassExecutionScanned      int
	lastPassEvidenceScanned       int
	lastErrorAt                   time.Time
	errorEpoch                    uint64
	identityErrors                map[string]operationPlanIdentityError
	evidenceSweepAt               time.Time
	evidenceChecked               int
	evidenceCurrent               int
	evidenceMissing               int
	evidenceValidUntil            time.Time
	evidenceScanCursor            int
	evidenceSweepEpoch            uint64
	evidenceStaging               []operationPlanReadinessEvidence
	passes                        uint64
	executionTasksStarted         uint64
	requestStarts                 uint64
	observations                  uint64
	deferred                      uint64
	executionFailures             uint64
	deliveryTasksStarted          uint64
	readbacks                     uint64
	notApplicable                 uint64
	deliveryFailures              uint64
	deliveryScanErrors            uint64
	identityScanErrors            uint64
	wg                            sync.WaitGroup
}

func NewOperationPlanScheduler(config OperationPlanSchedulerConfig) (*OperationPlanScheduler, error) {
	if config.Worker == nil || !config.Worker.validRuntimeSnapshot() || config.MaxConcurrent < 1 || config.MaxConcurrent > operationPlanSchedulerMaximumConcurrency || config.MaxStartsPerPass < 1 || config.MaxStartsPerPass > config.MaxConcurrent || config.MaxDeliveriesPerPass < 1 || config.MaxDeliveriesPerPass > config.MaxConcurrent || config.CandidateScanPerPass < 1 || config.CandidateScanPerPass > operationPlanSchedulerMaximumScanBudget || config.DeliveryLease < time.Second || config.DeliveryLease > maxOperationAttemptLease {
		return nil, errOperationPlanSchedulerUnavailable
	}
	targets := make([]OperationPlanWorkerTarget, 0, len(config.Worker.targets))
	for _, target := range config.Worker.targets {
		targets = append(targets, cloneOperationPlanWorkerTarget(target))
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Record.SourceID != targets[j].Record.SourceID {
			return targets[i].Record.SourceID < targets[j].Record.SourceID
		}
		return targets[i].Record.OperationID < targets[j].Record.OperationID
	})
	for i, target := range targets {
		if !validOperationWorkerTarget(target) || i > 0 && targets[i-1].Record.SourceID == target.Record.SourceID && targets[i-1].Record.OperationID == target.Record.OperationID {
			return nil, errOperationPlanSchedulerUnavailable
		}
	}
	assessment, err := assessOperationPlanCapacity(targets, config.MaxConcurrent, config.MaxStartsPerPass, config.CandidateScanPerPass)
	if err != nil {
		return nil, errOperationPlanSchedulerUnavailable
	}
	return &OperationPlanScheduler{
		worker: config.Worker, targets: targets, maxConcurrent: config.MaxConcurrent,
		maxStarts: config.MaxStartsPerPass, maxDeliveries: config.MaxDeliveriesPerPass,
		scanBudget: config.CandidateScanPerPass, deliveryLease: config.DeliveryLease,
		capacity: assessment, active: make(map[string]string), identityErrors: make(map[string]operationPlanIdentityError), deliveryReservation: -1,
	}, nil
}

// ProcessDue performs bounded scans and launches only the configured number
// of tasks. The one-second caller loop is not replayed after downtime: each
// operation is independently due-gated by its durable attempt store.
func (scheduler *OperationPlanScheduler) ProcessDue(ctx context.Context, now time.Time) error {
	if scheduler == nil {
		return newOperationPlanSchedulerFailure("entry", "invalid_input")
	}
	if ctx == nil || now.IsZero() {
		scheduler.recordFailureDiagnostics("entry", "invalid_input")
		return newOperationPlanSchedulerFailure("entry", "invalid_input")
	}
	if ctx.Err() != nil {
		category := operationPlanSchedulerParentContextFailureCategory(ctx)
		scheduler.recordFailureDiagnostics("entry", category)
		return newOperationPlanSchedulerFailure("entry", category)
	}
	if len(scheduler.targets) == 0 {
		return nil
	}
	if !scheduler.passMu.TryLock() {
		scheduler.recordFailureDiagnostics("pass_overlap", "busy")
		return newOperationPlanSchedulerFailure("pass_overlap", "busy")
	}
	defer scheduler.passMu.Unlock()
	now = now.UTC()
	if !scheduler.recordPassIfDue(now) {
		return nil
	}
	passStartedAt := time.Now()
	deliveryScanned, executionScanned, evidenceScanned := 0, 0, 0
	defer func() {
		scheduler.recordPassDiagnostics(time.Since(passStartedAt), deliveryScanned, executionScanned, evidenceScanned)
	}()
	if !scheduler.capacity.Feasible {
		scheduler.recordFailure(now, "capacity_infeasible")
	}
	scanCtx, cancelScan := context.WithTimeout(ctx, operationPlanSchedulerScanTimeout)
	defer cancelScan()

	deliveryStart := scheduler.deliveryScanStart()
	deliveryStarted := 0
	for deliveryScanned < scheduler.scanBudget && deliveryScanned < len(scheduler.targets) && deliveryStarted < scheduler.maxDeliveries {
		if scanCtx.Err() != nil {
			category := operationPlanSchedulerScanContextFailureCategory(ctx, scanCtx)
			scheduler.recordFailureWithDiagnostics(now, "attempt_store_unavailable", "delivery_scan", category)
			return newOperationPlanSchedulerFailure("delivery_scan", category)
		}
		index := (deliveryStart + deliveryScanned) % len(scheduler.targets)
		target := scheduler.targets[index]
		deliveryScanned++
		pending, err := scheduler.worker.attempts.PendingDeliveriesSnapshotContext(scanCtx, target.Record.SourceID, target.Record.OperationID)
		if err != nil {
			scheduler.addDeliveryScanFailure(operationReadModelIdentityKey(target.Record.SourceID, target.Record.OperationID))
			if scanCtx.Err() != nil {
				category := operationPlanSchedulerScanContextFailureCategory(ctx, scanCtx)
				scheduler.recordFailureWithDiagnostics(now, "attempt_store_unavailable", "delivery_scan", category)
				return newOperationPlanSchedulerFailure("delivery_scan", category)
			}
			continue
		}
		if len(pending) == 0 {
			scheduler.clearDeliveryReservation(index)
			continue
		}
		attempt := pending[0]
		key := operationReadModelIdentityKey(target.Record.SourceID, target.Record.OperationID)
		if scheduler.launch(ctx, key, "delivery", index, func(taskCtx context.Context) {
			if err := scheduler.worker.DeliverOne(taskCtx, attempt.Binding.SourceID, attempt.Binding.OperationID, attempt.AttemptID, attempt.Generation, time.Now().UTC(), scheduler.deliveryLease); err != nil {
				scheduler.finishDelivery(taskCtx, attempt)
				return
			}
			scheduler.finishDelivery(taskCtx, attempt)
		}) {
			deliveryStarted++
			scheduler.addDeliveryTaskStarted()
		}
	}
	scheduler.finishDeliveryScan(deliveryStart, deliveryScanned)
	if scanCtx.Err() != nil {
		category := operationPlanSchedulerScanContextFailureCategory(ctx, scanCtx)
		scheduler.recordFailureWithDiagnostics(now, "attempt_store_unavailable", "delivery_scan", category)
		return newOperationPlanSchedulerFailure("delivery_scan", category)
	}

	if scheduler.capacity.Feasible {
		executionStarted := 0
		for executionScanned < scheduler.scanBudget && executionScanned < len(scheduler.targets) && executionStarted < scheduler.maxStarts {
			if scanCtx.Err() != nil {
				category := operationPlanSchedulerScanContextFailureCategory(ctx, scanCtx)
				scheduler.recordFailureWithDiagnostics(now, "attempt_store_unavailable", "execution_scan", category)
				return newOperationPlanSchedulerFailure("execution_scan", category)
			}
			index := (scheduler.executionCursor + executionScanned) % len(scheduler.targets)
			target := scheduler.targets[index]
			executionScanned++
			latest, found, err := scheduler.worker.attempts.LatestSnapshotContext(scanCtx, target.Record.SourceID, target.Record.OperationID)
			if err != nil {
				scheduler.addIdentityScanFailure(operationReadModelIdentityKey(target.Record.SourceID, target.Record.OperationID))
				if scanCtx.Err() != nil {
					category := operationPlanSchedulerScanContextFailureCategory(ctx, scanCtx)
					scheduler.recordFailureWithDiagnostics(now, "attempt_store_unavailable", "execution_scan", category)
					return newOperationPlanSchedulerFailure("execution_scan", category)
				}
				continue
			}
			binding := operationPlanTargetBinding(scheduler.worker.runtime.Plan, target)
			if found && (!operationPlanTargetDue(target, latest, binding, now) || latest.State == "claimed" && now.Before(latest.LeaseExpiresAt)) {
				continue
			}
			key := operationReadModelIdentityKey(target.Record.SourceID, target.Record.OperationID)
			if scheduler.launch(ctx, key, "execution", -1, func(taskCtx context.Context) {
				result, runErr := scheduler.worker.ExecuteOne(taskCtx, target.Record.SourceID, target.Record.OperationID, time.Now().UTC())
				scheduler.finishExecution(key, result, runErr)
			}) {
				executionStarted++
				scheduler.addExecutionTaskStarted()
			}
		}
		if len(scheduler.targets) > 0 {
			scheduler.executionCursor = (scheduler.executionCursor + executionScanned) % len(scheduler.targets)
		}
	}
	if scanCtx.Err() != nil {
		category := operationPlanSchedulerScanContextFailureCategory(ctx, scanCtx)
		scheduler.recordFailureWithDiagnostics(now, "attempt_store_unavailable", "execution_scan", category)
		return newOperationPlanSchedulerFailure("execution_scan", category)
	}
	var evidenceErr error
	evidenceScanned, evidenceErr = scheduler.advanceEvidenceSweepWithScanCount(scanCtx, now)
	if evidenceErr != nil {
		stage, category, ok := operationPlanSchedulerFailureDetails(evidenceErr)
		if !ok {
			stage, category = "evidence_snapshot", "store_unavailable"
		}
		if ctx.Err() != nil {
			category = operationPlanSchedulerParentContextFailureCategory(ctx)
		} else if scanCtx.Err() != nil {
			category = operationPlanSchedulerScanContextFailureCategory(ctx, scanCtx)
		}
		scheduler.recordFailureWithDiagnostics(now, "attempt_store_unavailable", stage, category)
		return newOperationPlanSchedulerFailure(stage, category)
	}
	return nil
}

// advanceEvidenceSweep checks a finite slice of the exact admitted set on
// each pass. Readiness publishes only a complete sweep; HTTP status reads the
// cached counts and earliest expiration in constant time.
func (scheduler *OperationPlanScheduler) advanceEvidenceSweep(ctx context.Context, now time.Time) error {
	_, err := scheduler.advanceEvidenceSweepWithScanCount(ctx, now)
	return err
}

func (scheduler *OperationPlanScheduler) advanceEvidenceSweepWithScanCount(ctx context.Context, now time.Time) (int, error) {
	if scheduler == nil || ctx == nil || ctx.Err() != nil || now.IsZero() || len(scheduler.targets) == 0 {
		category := "invalid_input"
		if ctx != nil && ctx.Err() != nil {
			category = operationPlanSchedulerParentContextFailureCategory(ctx)
		}
		return 0, newOperationPlanSchedulerFailure("evidence_snapshot", category)
	}
	if scheduler.evidenceScanCursor == 0 {
		scheduler.evidenceStaging = make([]operationPlanReadinessEvidence, len(scheduler.targets))
		scheduler.mu.Lock()
		scheduler.evidenceSweepEpoch = scheduler.errorEpoch
		scheduler.mu.Unlock()
	}
	end := scheduler.evidenceScanCursor + operationPlanSchedulerMaximumScanBudget
	if end > len(scheduler.targets) {
		end = len(scheduler.targets)
	}
	scanned := 0
	for index := scheduler.evidenceScanCursor; index < end; index++ {
		if ctx.Err() != nil {
			scheduler.resetEvidenceSweep()
			return scanned, newOperationPlanSchedulerFailure("evidence_snapshot", operationPlanSchedulerParentContextFailureCategory(ctx))
		}
		scanned++
		target := scheduler.targets[index]
		latest, completed, latestFound, completedFound, err := scheduler.worker.attempts.LatestReadinessSnapshotContext(ctx, target.Record.SourceID, target.Record.OperationID)
		if err != nil {
			scheduler.resetEvidenceSweep()
			scheduler.addIdentityScanFailure(operationReadModelIdentityKey(target.Record.SourceID, target.Record.OperationID))
			return scanned, newOperationPlanSchedulerFailure("evidence_snapshot", "store_unavailable")
		}
		if !latestFound {
			continue
		}
		evidence, err := scheduler.operationEvidenceForTarget(ctx, target, latest, completed, completedFound, now)
		if err != nil {
			scheduler.resetEvidenceSweep()
			scheduler.addIdentityScanFailure(operationReadModelIdentityKey(target.Record.SourceID, target.Record.OperationID))
			stage, category, ok := operationPlanSchedulerFailureDetails(err)
			if !ok {
				stage, category = "evidence_proof", "proof_unavailable"
			}
			return scanned, newOperationPlanSchedulerFailure(stage, category)
		}
		scheduler.evidenceStaging[index] = evidence
	}
	scheduler.evidenceScanCursor = end
	if end < len(scheduler.targets) {
		return scanned, nil
	}

	current, missing := 0, 0
	var validUntil time.Time
	for _, evidence := range scheduler.evidenceStaging {
		if evidence.Proven && now.Before(evidence.ValidUntil) {
			current++
		} else {
			missing++
		}
		if !evidence.ValidUntil.IsZero() && (validUntil.IsZero() || evidence.ValidUntil.Before(validUntil)) {
			validUntil = evidence.ValidUntil
		}
	}
	scheduler.mu.Lock()
	scheduler.evidenceSweepAt = now.UTC()
	scheduler.evidenceChecked = len(scheduler.targets)
	scheduler.evidenceCurrent = current
	scheduler.evidenceMissing = missing
	scheduler.evidenceValidUntil = validUntil
	if current == len(scheduler.targets) && scheduler.errorEpoch == scheduler.evidenceSweepEpoch {
		allIdentityErrorsRecovered := true
		for index, target := range scheduler.targets {
			key := operationReadModelIdentityKey(target.Record.SourceID, target.Record.OperationID)
			failure, found := scheduler.identityErrors[key]
			if !found {
				continue
			}
			evidence := scheduler.evidenceStaging[index]
			if !evidence.Proven || failure.RequiresNewProof && evidence.ProofAt.Before(failure.At) {
				allIdentityErrorsRecovered = false
				break
			}
		}
		if allIdentityErrorsRecovered {
			scheduler.identityErrors = make(map[string]operationPlanIdentityError)
			scheduler.lastErrorReason = ""
			scheduler.lastErrorStage = ""
			scheduler.lastErrorCategory = ""
			scheduler.lastErrorAt = time.Time{}
		}
	}
	scheduler.mu.Unlock()
	scheduler.evidenceScanCursor = 0
	scheduler.evidenceStaging = nil
	return scanned, nil
}

func (scheduler *OperationPlanScheduler) resetEvidenceSweep() {
	scheduler.evidenceScanCursor = 0
	scheduler.evidenceStaging = nil
}

func (scheduler *OperationPlanScheduler) operationEvidenceForTarget(ctx context.Context, target OperationPlanWorkerTarget, latest, completed OperationStoredAttempt, completedFound bool, now time.Time) (operationPlanReadinessEvidence, error) {
	expected := operationPlanTargetBinding(scheduler.worker.runtime.Plan, target)
	if latest.StartedAt.IsZero() || latest.StartedAt.After(now) || latest.FinishedAt.After(now) || latest.DeliveryStartedAt.After(now) || latest.DeliveryAckAt.After(now) || latest.GatusReceivedAt.After(now) {
		return operationPlanReadinessEvidence{}, nil
	}
	proof := latest
	if latest.State == "claimed" {
		if latest.Binding != expected || !now.Before(latest.LeaseExpiresAt) || !completedFound || completed.Generation >= latest.Generation {
			return operationPlanReadinessEvidence{}, nil
		}
		proof = completed
	} else if latest.State != "observed" {
		return operationPlanReadinessEvidence{}, nil
	}
	if proof.Binding != expected || proof.State != "observed" || proof.Result == nil || !proof.ReceiptValidated || proof.RequestStarted == nil || !*proof.RequestStarted {
		return operationPlanReadinessEvidence{}, nil
	}
	result := *proof.Result
	if proof.StartedAt.IsZero() || proof.StartedAt.After(now) || proof.FinishedAt.IsZero() || proof.FinishedAt.After(now) || result.ObservedAt.IsZero() || result.ObservedAt.After(now) || result.ReceivedAt.IsZero() || result.ReceivedAt.After(now) || proof.DeliveryStartedAt.After(now) || proof.DeliveryAckAt.After(now) || proof.GatusReceivedAt.After(now) {
		return operationPlanReadinessEvidence{}, nil
	}
	if !validOperationObservationResult(result) || result.ReceiptSHA != proof.ReceiptSHA256 || result.HistoryRecordID == "" || !sha256Pattern.MatchString(result.HistoryRecordSHA256) || result.ObservedAt.Before(proof.StartedAt) || result.ObservedAt.After(proof.FinishedAt) || result.ReceivedAt.Before(result.ObservedAt) || result.ReceivedAt.After(proof.FinishedAt) {
		return operationPlanReadinessEvidence{}, nil
	}
	identity := OperationHistoryIdentity{
		SourceID: expected.SourceID, OperationID: expected.OperationID, AttemptID: proof.AttemptID,
		Generation: proof.Generation, RegistryRevision: expected.RegistryRevision,
		ReleaseManifestSHA256: expected.ReleaseManifestSHA, IndexSHA256: expected.IndexSHA,
		ShardSHA256: expected.ShardSHA,
	}
	verifier, ok := scheduler.worker.history.(OperationHistoryReferenceVerifier)
	if !ok || verifier.VerifyStoredRecordReference(ctx, identity, result.HistoryRecordID, result.HistoryRecordSHA256) != nil {
		return operationPlanReadinessEvidence{}, newOperationPlanSchedulerFailure("evidence_proof", "proof_unavailable")
	}
	validUntil := result.ObservedAt.Add(target.Record.ObservationPeriod)
	if validUntil.IsZero() {
		return operationPlanReadinessEvidence{}, nil
	}
	if !operationPlanDeliveryEvidenceValid(proof) {
		return operationPlanReadinessEvidence{}, nil
	}
	proofAt := result.ReceivedAt
	if proof.DeliveryState == "readback_verified" {
		proofAt = proof.GatusReceivedAt
	}
	return operationPlanReadinessEvidence{Proven: true, ProofAt: proofAt, ValidUntil: validUntil}, nil
}

func operationPlanDeliveryEvidenceValid(attempt OperationStoredAttempt) bool {
	if attempt.Result == nil || !validOperationObservationResult(*attempt.Result) {
		return false
	}
	if attempt.Result.State == "indeterminate" && attempt.Result.Category == "response_semantics_unestablished" {
		return attempt.DeliveryState == "not_applicable" && attempt.DeliveryAckAt.IsZero() && attempt.GatusReceivedAt.IsZero() && attempt.GatusResultState == ""
	}
	wantState := "unhealthy"
	if attempt.Result.State == "healthy" {
		wantState = "healthy"
	}
	return attempt.DeliveryState == "readback_verified" && !attempt.GatusReceivedAt.IsZero() && !attempt.GatusReceivedAt.Before(attempt.DeliveryAckAt) && attempt.GatusResultState == wantState
}

func operationPlanTargetBinding(plan PinnedOperationObservationPlan, target OperationPlanWorkerTarget) OperationAttemptBinding {
	return OperationAttemptBinding{
		SourceID: target.Record.SourceID, OperationID: target.Record.OperationID,
		RegistryRevision: plan.RegistryRevision(), ReleaseManifestSHA: plan.binding.ReleaseManifestSHA256,
		IndexSHA: plan.IndexSHA256(), ShardSHA: target.ShardSHA256,
		GatusKey: target.GatusEndpointKey, ObservationPeriod: target.Record.ObservationPeriod,
	}
}

func operationPlanTargetDue(target OperationPlanWorkerTarget, latest OperationStoredAttempt, binding OperationAttemptBinding, now time.Time) bool {
	if target.Record.SourceID != binding.SourceID || target.Record.OperationID != binding.OperationID || target.ShardSHA256 != binding.ShardSHA || target.GatusEndpointKey != binding.GatusKey || target.Record.ObservationPeriod != binding.ObservationPeriod {
		return false
	}
	return operationAttemptDueForBinding(latest, binding, now)
}

func (scheduler *OperationPlanScheduler) deliveryScanStart() int {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if scheduler.deliveryReservation >= 0 && scheduler.deliveryReservation < len(scheduler.targets) {
		return scheduler.deliveryReservation
	}
	return scheduler.deliveryCursor
}

func (scheduler *OperationPlanScheduler) clearDeliveryReservation(index int) {
	scheduler.mu.Lock()
	if scheduler.deliveryReservation == index {
		scheduler.deliveryReservation = -1
	}
	scheduler.mu.Unlock()
}

func (scheduler *OperationPlanScheduler) finishDeliveryScan(start, scanned int) {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if scheduler.deliveryReservation >= 0 && scheduler.deliveryReservation < len(scheduler.targets) {
		scheduler.deliveryCursor = scheduler.deliveryReservation
		return
	}
	if len(scheduler.targets) > 0 {
		scheduler.deliveryCursor = (start + scanned) % len(scheduler.targets)
	}
}

func (scheduler *OperationPlanScheduler) reserveDeliveryLocked(index int) {
	if index >= 0 && index < len(scheduler.targets) && scheduler.deliveryReservation < 0 {
		scheduler.deliveryReservation = index
	}
}

func (scheduler *OperationPlanScheduler) launch(parent context.Context, identity, kind string, targetIndex int, run func(context.Context)) bool {
	if parent == nil || parent.Err() != nil {
		return false
	}
	scheduler.mu.Lock()
	if scheduler.activeCount >= scheduler.maxConcurrent || scheduler.active[identity] != "" {
		if kind == "delivery" {
			scheduler.reserveDeliveryLocked(targetIndex)
		}
		scheduler.mu.Unlock()
		return false
	}
	reservedDelivery := kind == "delivery" && targetIndex == scheduler.deliveryReservation
	if scheduler.deliveryReservation >= 0 && !reservedDelivery && scheduler.activeCount >= scheduler.maxConcurrent-1 {
		scheduler.mu.Unlock()
		return false
	}
	scheduler.active[identity] = kind
	scheduler.activeCount++
	if reservedDelivery {
		scheduler.deliveryReservation = -1
	}
	scheduler.wg.Add(1)
	scheduler.mu.Unlock()
	go func() {
		defer scheduler.wg.Done()
		defer func() {
			scheduler.mu.Lock()
			delete(scheduler.active, identity)
			scheduler.activeCount--
			scheduler.mu.Unlock()
		}()
		timeout := operationPlanDeliveryTimeout
		if kind == "execution" {
			timeout = maxOperationPlanProbeDeadline + operationPlanPostChildCommitTimeout
		}
		ctx, cancel := context.WithTimeout(parent, timeout)
		defer cancel()
		run(ctx)
	}()
	return true
}

func (scheduler *OperationPlanScheduler) finishExecution(identityKey string, result OperationPlanWorkerResult, err error) {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if result.RequestStarted {
		scheduler.requestStarts++
	}
	if result.AttemptState == "observed" {
		scheduler.observations++
		if result.DeliveryState == "not_applicable" {
			scheduler.notApplicable++
		}
	} else if result.AttemptState == "deferred" {
		scheduler.deferred++
	}
	if err != nil {
		scheduler.executionFailures++
		scheduler.latchIdentityErrorLocked(identityKey, "execution_unavailable", time.Now().UTC(), true)
		var failure *operationPlanWorkerFailure
		if errors.As(err, &failure) {
			if validOperationPlanWorkerFailureStage(failure.stage) {
				scheduler.lastErrorStage = failure.stage
			} else {
				scheduler.lastErrorStage = "unavailable"
			}
			if validOperationPlanWorkerFailureCategory(failure.category) {
				scheduler.lastErrorCategory = failure.category
			} else {
				scheduler.lastErrorCategory = "unavailable"
			}
		} else {
			scheduler.lastErrorStage = "unavailable"
			scheduler.lastErrorCategory = operationPlanWorkerFailureCategory(err)
		}
		if validOperationPlanWorkerFailureStage(scheduler.lastErrorStage) {
			if scheduler.failureStageCounts == nil {
				scheduler.failureStageCounts = make(map[string]uint64)
			}
			scheduler.failureStageCounts[scheduler.lastErrorStage]++
		}
		if validOperationPlanWorkerFailureCategory(scheduler.lastErrorCategory) {
			if scheduler.failureCategoryCounts == nil {
				scheduler.failureCategoryCounts = make(map[string]uint64)
			}
			scheduler.failureCategoryCounts[scheduler.lastErrorCategory]++
		}
		return
	}
	if result.AttemptState == "failed" || result.AttemptState == "unknown" {
		scheduler.executionFailures++
		scheduler.latchIdentityErrorLocked(identityKey, "execution_unavailable", time.Now().UTC(), true)
	}
}

func (scheduler *OperationPlanScheduler) finishDelivery(ctx context.Context, attempt OperationStoredAttempt) {
	stored, found, err := scheduler.worker.attempts.GetAttemptContext(ctx, attempt.Binding.SourceID, attempt.Binding.OperationID, attempt.AttemptID, attempt.Generation)
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if err != nil || !found {
		scheduler.deliveryFailures++
		scheduler.latchIdentityErrorLocked(operationReadModelIdentityKey(attempt.Binding.SourceID, attempt.Binding.OperationID), "delivery_state_unavailable", time.Now().UTC(), false)
		return
	}
	switch stored.DeliveryState {
	case "readback_verified":
		scheduler.readbacks++
	case "not_applicable":
		scheduler.notApplicable++
	case "pending", "acknowledged", "not_ready":
		// A push/readback error is not a provider failure. The durable outbox
		// remains available for the next bounded pass.
		scheduler.deliveryFailures++
		scheduler.latchIdentityErrorLocked(operationReadModelIdentityKey(attempt.Binding.SourceID, attempt.Binding.OperationID), "delivery_unavailable", time.Now().UTC(), true)
	default:
		scheduler.deliveryFailures++
		scheduler.latchIdentityErrorLocked(operationReadModelIdentityKey(attempt.Binding.SourceID, attempt.Binding.OperationID), "delivery_state_invalid", time.Now().UTC(), true)
	}
}

func (scheduler *OperationPlanScheduler) recordPassIfDue(now time.Time) bool {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if !scheduler.lastPass.IsZero() && (now.Before(scheduler.lastPass) || now.Sub(scheduler.lastPass) < operationPlanSchedulerPassInterval) {
		return false
	}
	scheduler.passes++
	if !now.IsZero() {
		scheduler.lastPass = now.UTC()
	}
	return true
}

func (scheduler *OperationPlanScheduler) recordFailure(now time.Time, reason string) {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	scheduler.latchErrorLocked(reason, now.UTC())
}

func (scheduler *OperationPlanScheduler) recordFailureWithDiagnostics(now time.Time, reason, stage, category string) {
	if scheduler == nil {
		return
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	scheduler.latchErrorLocked(reason, now.UTC())
	scheduler.setFailureDiagnosticsLocked(stage, category)
	scheduler.lastErrorStage = scheduler.lastDiagnosticFailureStage
	scheduler.lastErrorCategory = scheduler.lastDiagnosticFailureCategory
}

func (scheduler *OperationPlanScheduler) recordFailureDiagnostics(stage, category string) {
	if scheduler == nil {
		return
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	scheduler.setFailureDiagnosticsLocked(stage, category)
}

func (scheduler *OperationPlanScheduler) setFailureDiagnosticsLocked(stage, category string) {
	if !validOperationPlanSchedulerFailureStage(stage) {
		stage = "unavailable"
	}
	if !validOperationPlanSchedulerFailureCategory(category) {
		category = "unavailable"
	}
	scheduler.lastDiagnosticFailureStage = stage
	scheduler.lastDiagnosticFailureCategory = category
	if scheduler.failureStageCounts == nil {
		scheduler.failureStageCounts = make(map[string]uint64)
	}
	if scheduler.failureCategoryCounts == nil {
		scheduler.failureCategoryCounts = make(map[string]uint64)
	}
	scheduler.failureStageCounts[stage]++
	scheduler.failureCategoryCounts[category]++
}

func (scheduler *OperationPlanScheduler) recordPassDiagnostics(elapsed time.Duration, deliveryScanned, executionScanned, evidenceScanned int) {
	if scheduler == nil {
		return
	}
	scheduler.mu.Lock()
	scheduler.lastPassElapsed = elapsed
	scheduler.lastPassDeliveryScanned = deliveryScanned
	scheduler.lastPassExecutionScanned = executionScanned
	scheduler.lastPassEvidenceScanned = evidenceScanned
	scheduler.mu.Unlock()
}

func (scheduler *OperationPlanScheduler) latchErrorLocked(reason string, at time.Time) {
	scheduler.lastErrorReason = reason
	scheduler.lastErrorStage = ""
	scheduler.lastErrorCategory = ""
	scheduler.lastErrorAt = at.UTC()
	scheduler.errorEpoch++
}

func (scheduler *OperationPlanScheduler) addExecutionTaskStarted() {
	scheduler.mu.Lock()
	scheduler.executionTasksStarted++
	scheduler.mu.Unlock()
}

func (scheduler *OperationPlanScheduler) addDeliveryTaskStarted() {
	scheduler.mu.Lock()
	scheduler.deliveryTasksStarted++
	scheduler.mu.Unlock()
}

func (scheduler *OperationPlanScheduler) addDeliveryScanFailure(identityKey string) {
	scheduler.mu.Lock()
	scheduler.deliveryScanErrors++
	scheduler.latchIdentityErrorLocked(identityKey, "delivery_store_unavailable", time.Now().UTC(), false)
	scheduler.mu.Unlock()
}

func (scheduler *OperationPlanScheduler) addIdentityScanFailure(identityKey string) {
	scheduler.mu.Lock()
	scheduler.identityScanErrors++
	scheduler.latchIdentityErrorLocked(identityKey, "attempt_store_unavailable", time.Now().UTC(), false)
	scheduler.mu.Unlock()
}

func (scheduler *OperationPlanScheduler) latchIdentityErrorLocked(identityKey, reason string, at time.Time, requiresNewProof bool) {
	scheduler.latchErrorLocked(reason, at)
	if identityKey != "" {
		if previous, found := scheduler.identityErrors[identityKey]; found && previous.RequiresNewProof {
			requiresNewProof = true
		}
		scheduler.identityErrors[identityKey] = operationPlanIdentityError{At: at.UTC(), RequiresNewProof: requiresNewProof}
	}
}

func (scheduler *OperationPlanScheduler) Status(at time.Time) OperationPlanSchedulerStatus {
	status := OperationPlanSchedulerStatus{SchemaVersion: "datapan.health-operation-plan-scheduler-status.v1", State: "unavailable"}
	if scheduler == nil || scheduler.worker == nil || !scheduler.worker.validRuntimeSnapshot() {
		status.Reason = "plan_runtime_unavailable"
		return status
	}
	identity := scheduler.worker.runtimeIdentity
	status.RegistryRevision = identity.registryRevision
	status.ReleaseManifestSHA256 = identity.releaseManifestSHA256
	status.IndexSHA256 = identity.indexSHA256
	status.ActivationSHA256 = identity.activationSHA256
	status.CanaryConfigSHA256 = identity.canaryConfigSHA256
	status.IdentityMappingSHA256 = identity.identityMappingSHA256
	status.RuntimePinSHA256 = identity.runtimePinSHA256
	status.SuppressedLegacyCanaries = append([]string(nil), identity.suppressedLegacy...)
	status.KnownOperations = identity.knownOperations
	status.AdmittedOperations = identity.admittedOperations
	status.MaxConcurrent = scheduler.maxConcurrent
	status.MaxStartsPerSecond = scheduler.maxStarts
	status.CandidateScanPerSecond = scheduler.scanBudget
	status.RequiredStartsPerSecond = scheduler.capacity.RequiredStartsPerSecond
	status.RequiredConcurrency = scheduler.capacity.RequiredConcurrency
	status.CapacityFailureScopes = scheduler.capacity.FailureScopes
	status.CapacityFeasible = scheduler.capacity.Feasible
	scheduler.mu.Lock()
	status.ActiveWork = scheduler.activeCount
	status.EvidenceSweepAt = scheduler.evidenceSweepAt
	status.EvidenceCheckedOperations = scheduler.evidenceChecked
	status.EvidenceCurrentOperations = scheduler.evidenceCurrent
	status.EvidenceMissingOperations = scheduler.evidenceMissing
	status.EvidenceValidUntil = scheduler.evidenceValidUntil
	status.LastPassAt = scheduler.lastPass
	status.LastErrorReason = scheduler.lastErrorReason
	status.LastErrorStage = scheduler.lastErrorStage
	status.lastErrorCategory = scheduler.lastErrorCategory
	status.lastDiagnosticFailureStage = scheduler.lastDiagnosticFailureStage
	status.lastDiagnosticFailureCategory = scheduler.lastDiagnosticFailureCategory
	status.failureStageCounts = cloneOperationPlanFailureCounts(scheduler.failureStageCounts)
	status.failureCategoryCounts = cloneOperationPlanFailureCounts(scheduler.failureCategoryCounts)
	status.lastPassElapsed = scheduler.lastPassElapsed
	status.lastPassDeliveryScanned = scheduler.lastPassDeliveryScanned
	status.lastPassExecutionScanned = scheduler.lastPassExecutionScanned
	status.lastPassEvidenceScanned = scheduler.lastPassEvidenceScanned
	status.LastErrorAt = scheduler.lastErrorAt
	status.PassesSinceStart = scheduler.passes
	status.ExecutionTasksStartedSinceStart = scheduler.executionTasksStarted
	status.RequestStartsSinceStart = scheduler.requestStarts
	status.ObservationsSinceStart = scheduler.observations
	status.DeferredSinceStart = scheduler.deferred
	status.ExecutionFailuresSinceStart = scheduler.executionFailures
	status.DeliveryTasksStartedSinceStart = scheduler.deliveryTasksStarted
	status.ReadbacksSinceStart = scheduler.readbacks
	status.NotApplicableSinceStart = scheduler.notApplicable
	status.DeliveryFailuresSinceStart = scheduler.deliveryFailures
	status.PendingDeliveryScanFailures = scheduler.deliveryScanErrors
	status.IdentityScanFailuresSinceStart = scheduler.identityScanErrors
	scheduler.mu.Unlock()
	if at.IsZero() {
		at = time.Now().UTC()
	}
	if !status.LastPassAt.IsZero() && !at.Before(status.LastPassAt) {
		status.LastPassAgeSeconds = int64(at.Sub(status.LastPassAt) / time.Second)
	}
	switch {
	case status.AdmittedOperations == 0:
		status.Reason = "zero_admitted_operations"
	case !status.CapacityFeasible:
		status.Reason = "capacity_infeasible"
	case status.PassesSinceStart == 0 || status.LastPassAgeSeconds > 3 || !status.LastPassAt.IsZero() && at.Before(status.LastPassAt):
		status.Reason = "scheduler_loop_stale"
	case !status.EvidenceSweepAt.IsZero() && at.Before(status.EvidenceSweepAt):
		status.Reason = "operation_observations_incomplete"
	case status.LastErrorReason != "":
		status.Reason = status.LastErrorReason
	case status.EvidenceSweepAt.IsZero() || status.EvidenceCheckedOperations != status.AdmittedOperations:
		status.Reason = "awaiting_initial_evidence_sweep"
	case status.EvidenceCurrentOperations != status.AdmittedOperations:
		if !status.EvidenceValidUntil.IsZero() && !at.Before(status.EvidenceValidUntil) {
			status.Reason = "operation_observations_stale"
		} else {
			status.Reason = "operation_observations_incomplete"
		}
	case status.EvidenceValidUntil.IsZero() || !at.Before(status.EvidenceValidUntil):
		status.Reason = "operation_observations_stale"
	default:
		status.State = "ready"
		status.Ready = true
	}
	if status.Reason != "" {
		status.State = "degraded"
	}
	return status
}

func cloneOperationPlanFailureCounts(counts map[string]uint64) map[string]uint64 {
	if len(counts) == 0 {
		return nil
	}
	copy := make(map[string]uint64, len(counts))
	for key, count := range counts {
		copy[key] = count
	}
	return copy
}

func (scheduler *OperationPlanScheduler) Wait() {
	if scheduler != nil {
		scheduler.wg.Wait()
	}
}

func assessOperationPlanCapacity(targets []OperationPlanWorkerTarget, maxConcurrent, maxStartsPerSecond, candidateScanPerSecond int) (operationPlanCapacityAssessment, error) {
	assessment := operationPlanCapacityAssessment{Feasible: true}
	scopes := make(map[string]*operationPlanScopeDemand)
	concurrencyLoad := float64(0)
	for _, target := range targets {
		record := target.Record
		if !validOperationWorkerTarget(target) || record.ObservationPeriod <= 0 || record.RequestTimeout <= 0 {
			return operationPlanCapacityAssessment{}, errOperationPlanSchedulerUnavailable
		}
		rate := float64(time.Second) / float64(record.ObservationPeriod)
		service := float64(record.RequestTimeout+maxOperationPlanProbeProcessOverhead) / float64(record.ObservationPeriod)
		assessment.RequiredStartsPerSecond += rate
		concurrencyLoad += service
		for _, policy := range record.QuotaPolicies {
			if !validOperationQuotaPolicy(policy) {
				return operationPlanCapacityAssessment{}, errOperationPlanSchedulerUnavailable
			}
			demand := scopes[policy.ScopeSHA256]
			if demand == nil {
				demand = &operationPlanScopeDemand{policy: policy}
				scopes[policy.ScopeSHA256] = demand
			} else if demand.policy != policy {
				return operationPlanCapacityAssessment{}, errOperationPlanSchedulerUnavailable
			}
			demand.requestsPerSec += rate
			demand.concurrentLoad += service
		}
	}
	assessment.RequiredConcurrency = int(math.Ceil(concurrencyLoad - 1e-12))
	if assessment.RequiredStartsPerSecond > float64(maxStartsPerSecond)+1e-12 || assessment.RequiredStartsPerSecond > float64(candidateScanPerSecond)+1e-12 || assessment.RequiredConcurrency > maxConcurrent {
		assessment.Feasible = false
	}
	for _, demand := range scopes {
		maxRate := float64(demand.policy.RequestsPerWindow) / demand.policy.Window.Seconds()
		if demand.policy.MinimumInterval > 0 {
			minRate := float64(time.Second) / float64(demand.policy.MinimumInterval)
			if minRate < maxRate {
				maxRate = minRate
			}
		}
		if demand.requestsPerSec > maxRate+1e-12 || demand.concurrentLoad > float64(demand.policy.MaxConcurrent)+1e-12 {
			assessment.Feasible = false
			assessment.FailureScopes++
		}
	}
	return assessment, nil
}
