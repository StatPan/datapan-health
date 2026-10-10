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

const (
	operationPlanSchedulerMaximumConcurrency = 32
	operationPlanSchedulerMaximumScanBudget  = 256
	operationPlanSchedulerPassInterval       = time.Second
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
	SchemaVersion                   string    `json:"schema_version"`
	State                           string    `json:"state"`
	Ready                           bool      `json:"ready"`
	Reason                          string    `json:"reason,omitempty"`
	RegistryRevision                string    `json:"registry_revision,omitempty"`
	IndexSHA256                     string    `json:"index_sha256,omitempty"`
	KnownOperations                 int       `json:"known_operations"`
	AdmittedOperations              int       `json:"admitted_operations"`
	ActiveWork                      int       `json:"active_work"`
	MaxConcurrent                   int       `json:"max_concurrent"`
	MaxStartsPerSecond              int       `json:"max_starts_per_second"`
	CandidateScanPerSecond          int       `json:"candidate_scan_per_second"`
	RequiredStartsPerSecond         float64   `json:"required_starts_per_second"`
	RequiredConcurrency             int       `json:"required_concurrency"`
	CapacityFeasible                bool      `json:"capacity_feasible"`
	CapacityFailureScopes           int       `json:"capacity_failure_scopes"`
	LastPassAt                      time.Time `json:"last_pass_at,omitempty"`
	LastPassAgeSeconds              int64     `json:"last_pass_age_seconds,omitempty"`
	LastErrorReason                 string    `json:"last_error_reason,omitempty"`
	LastErrorAt                     time.Time `json:"last_error_at,omitempty"`
	PassesSinceStart                uint64    `json:"passes_since_start"`
	ExecutionTasksStartedSinceStart uint64    `json:"execution_tasks_started_since_start"`
	RequestStartsSinceStart         uint64    `json:"request_starts_since_start"`
	ObservationsSinceStart          uint64    `json:"observations_since_start"`
	DeferredSinceStart              uint64    `json:"deferred_since_start"`
	ExecutionFailuresSinceStart     uint64    `json:"execution_failures_since_start"`
	DeliveryTasksStartedSinceStart  uint64    `json:"delivery_tasks_started_since_start"`
	ReadbacksSinceStart             uint64    `json:"readbacks_since_start"`
	NotApplicableSinceStart         uint64    `json:"not_applicable_since_start"`
	DeliveryFailuresSinceStart      uint64    `json:"delivery_failures_since_start"`
	PendingDeliveryScanFailures     uint64    `json:"pending_delivery_scan_failures"`
	IdentityScanFailuresSinceStart  uint64    `json:"identity_scan_failures_since_start"`
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

type OperationPlanScheduler struct {
	worker        *OperationPlanWorker
	targets       []OperationPlanWorkerTarget
	maxConcurrent int
	maxStarts     int
	maxDeliveries int
	scanBudget    int
	deliveryLease time.Duration
	capacity      operationPlanCapacityAssessment

	mu                    sync.Mutex
	passMu                sync.Mutex
	active                map[string]string
	activeCount           int
	executionCursor       int
	deliveryCursor        int
	lastPass              time.Time
	lastErrorReason       string
	lastErrorAt           time.Time
	passes                uint64
	executionTasksStarted uint64
	requestStarts         uint64
	observations          uint64
	deferred              uint64
	executionFailures     uint64
	deliveryTasksStarted  uint64
	readbacks             uint64
	notApplicable         uint64
	deliveryFailures      uint64
	deliveryScanErrors    uint64
	identityScanErrors    uint64
	wg                    sync.WaitGroup
}

func NewOperationPlanScheduler(config OperationPlanSchedulerConfig) (*OperationPlanScheduler, error) {
	if config.Worker == nil || !validVerifiedOperationPlanRuntime(config.Worker.runtime) || config.MaxConcurrent < 1 || config.MaxConcurrent > operationPlanSchedulerMaximumConcurrency || config.MaxStartsPerPass < 1 || config.MaxStartsPerPass > config.MaxConcurrent || config.MaxDeliveriesPerPass < 1 || config.MaxDeliveriesPerPass > config.MaxConcurrent || config.CandidateScanPerPass < 1 || config.CandidateScanPerPass > operationPlanSchedulerMaximumScanBudget || config.DeliveryLease < time.Second || config.DeliveryLease > maxOperationAttemptLease {
		return nil, errOperationPlanSchedulerUnavailable
	}
	targets := append([]OperationPlanWorkerTarget(nil), config.Worker.runtime.ActiveTargets...)
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
		capacity: assessment, active: make(map[string]string),
	}, nil
}

// ProcessDue performs bounded scans and launches only the configured number
// of tasks. The one-second caller loop is not replayed after downtime: each
// operation is independently due-gated by its durable attempt store.
func (scheduler *OperationPlanScheduler) ProcessDue(ctx context.Context, now time.Time) error {
	if scheduler == nil || ctx == nil || ctx.Err() != nil || now.IsZero() {
		return errOperationPlanSchedulerUnavailable
	}
	if len(scheduler.targets) == 0 {
		return nil
	}
	if !scheduler.passMu.TryLock() {
		return errOperationPlanSchedulerUnavailable
	}
	defer scheduler.passMu.Unlock()
	now = now.UTC()
	if !scheduler.recordPassIfDue(now) {
		return nil
	}
	if !scheduler.capacity.Feasible {
		scheduler.recordFailure(now, "capacity_infeasible")
	}

	deliveryScanned, deliveryStarted := 0, 0
	for deliveryScanned < scheduler.scanBudget && deliveryScanned < len(scheduler.targets) && deliveryStarted < scheduler.maxDeliveries {
		index := (scheduler.deliveryCursor + deliveryScanned) % len(scheduler.targets)
		target := scheduler.targets[index]
		deliveryScanned++
		pending, err := scheduler.worker.attempts.PendingDeliveriesContext(ctx, target.Record.SourceID, target.Record.OperationID)
		if err != nil {
			scheduler.addDeliveryScanFailure()
			continue
		}
		if len(pending) == 0 {
			continue
		}
		attempt := pending[0]
		key := operationReadModelIdentityKey(target.Record.SourceID, target.Record.OperationID)
		if scheduler.launch(ctx, key, "delivery", func(taskCtx context.Context) {
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
	if len(scheduler.targets) > 0 {
		scheduler.deliveryCursor = (scheduler.deliveryCursor + deliveryScanned) % len(scheduler.targets)
	}

	if scheduler.capacity.Feasible {
		executionScanned, executionStarted := 0, 0
		for executionScanned < scheduler.scanBudget && executionScanned < len(scheduler.targets) && executionStarted < scheduler.maxStarts {
			index := (scheduler.executionCursor + executionScanned) % len(scheduler.targets)
			target := scheduler.targets[index]
			executionScanned++
			latest, found, err := scheduler.worker.attempts.LatestContext(ctx, target.Record.SourceID, target.Record.OperationID)
			if err != nil {
				scheduler.addIdentityScanFailure()
				continue
			}
			if found && (!operationPlanTargetDue(target, latest, now) || latest.State == "claimed" && now.Before(latest.LeaseExpiresAt)) {
				continue
			}
			key := operationReadModelIdentityKey(target.Record.SourceID, target.Record.OperationID)
			if scheduler.launch(ctx, key, "execution", func(taskCtx context.Context) {
				result, runErr := scheduler.worker.ExecuteOne(taskCtx, target.Record.SourceID, target.Record.OperationID, time.Now().UTC())
				scheduler.finishExecution(result, runErr)
			}) {
				executionStarted++
				scheduler.addExecutionTaskStarted()
			}
		}
		if len(scheduler.targets) > 0 {
			scheduler.executionCursor = (scheduler.executionCursor + executionScanned) % len(scheduler.targets)
		}
	}
	return nil
}

func operationPlanTargetDue(target OperationPlanWorkerTarget, latest OperationStoredAttempt, now time.Time) bool {
	if now.IsZero() || latest.StartedAt.IsZero() || target.Record.ObservationPeriod <= 0 {
		return false
	}
	period := target.Record.ObservationPeriod
	if latest.Binding.ObservationPeriod > period {
		period = latest.Binding.ObservationPeriod
	}
	return !now.Before(latest.StartedAt.Add(period))
}

func (scheduler *OperationPlanScheduler) launch(parent context.Context, identity, kind string, run func(context.Context)) bool {
	if parent == nil || parent.Err() != nil {
		return false
	}
	scheduler.mu.Lock()
	if scheduler.activeCount >= scheduler.maxConcurrent || scheduler.active[identity] != "" {
		scheduler.mu.Unlock()
		return false
	}
	scheduler.active[identity] = kind
	scheduler.activeCount++
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

func (scheduler *OperationPlanScheduler) finishExecution(result OperationPlanWorkerResult, err error) {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if err != nil {
		scheduler.executionFailures++
		scheduler.lastErrorReason = "execution_unavailable"
		scheduler.lastErrorAt = time.Now().UTC()
		return
	}
	if result.RequestStarted {
		scheduler.requestStarts++
	}
	switch result.AttemptState {
	case "observed":
		scheduler.observations++
		if result.DeliveryState == "not_applicable" {
			scheduler.notApplicable++
		}
	case "deferred":
		scheduler.deferred++
	case "failed", "unknown":
		scheduler.executionFailures++
	}
}

func (scheduler *OperationPlanScheduler) finishDelivery(ctx context.Context, attempt OperationStoredAttempt) {
	stored, found, err := scheduler.worker.attempts.GetAttemptContext(ctx, attempt.Binding.SourceID, attempt.Binding.OperationID, attempt.AttemptID, attempt.Generation)
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if err != nil || !found {
		scheduler.deliveryFailures++
		scheduler.lastErrorReason = "delivery_state_unavailable"
		scheduler.lastErrorAt = time.Now().UTC()
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
		scheduler.lastErrorReason = "delivery_unavailable"
		scheduler.lastErrorAt = time.Now().UTC()
	default:
		scheduler.deliveryFailures++
		scheduler.lastErrorReason = "delivery_state_invalid"
		scheduler.lastErrorAt = time.Now().UTC()
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
	scheduler.lastErrorReason = reason
	scheduler.lastErrorAt = now.UTC()
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

func (scheduler *OperationPlanScheduler) addDeliveryScanFailure() {
	scheduler.mu.Lock()
	scheduler.deliveryScanErrors++
	scheduler.lastErrorReason = "delivery_store_unavailable"
	scheduler.lastErrorAt = time.Now().UTC()
	scheduler.mu.Unlock()
}

func (scheduler *OperationPlanScheduler) addIdentityScanFailure() {
	scheduler.mu.Lock()
	scheduler.identityScanErrors++
	scheduler.lastErrorReason = "attempt_store_unavailable"
	scheduler.lastErrorAt = time.Now().UTC()
	scheduler.mu.Unlock()
}

func (scheduler *OperationPlanScheduler) Status(at time.Time) OperationPlanSchedulerStatus {
	status := OperationPlanSchedulerStatus{SchemaVersion: "datapan.health-operation-plan-scheduler-status.v1", State: "unavailable"}
	if scheduler == nil || !validVerifiedOperationPlanRuntime(scheduler.worker.runtime) {
		status.Reason = "plan_runtime_unavailable"
		return status
	}
	status.RegistryRevision = scheduler.worker.runtime.Plan.RegistryRevision()
	status.IndexSHA256 = scheduler.worker.runtime.Plan.IndexSHA256()
	status.KnownOperations = scheduler.worker.runtime.Plan.Counts().KnownOperations
	status.AdmittedOperations = len(scheduler.targets)
	status.MaxConcurrent = scheduler.maxConcurrent
	status.MaxStartsPerSecond = scheduler.maxStarts
	status.CandidateScanPerSecond = scheduler.scanBudget
	status.RequiredStartsPerSecond = scheduler.capacity.RequiredStartsPerSecond
	status.RequiredConcurrency = scheduler.capacity.RequiredConcurrency
	status.CapacityFailureScopes = scheduler.capacity.FailureScopes
	status.CapacityFeasible = scheduler.capacity.Feasible
	scheduler.mu.Lock()
	status.ActiveWork = scheduler.activeCount
	status.LastPassAt = scheduler.lastPass
	status.LastErrorReason = scheduler.lastErrorReason
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
	if status.LastErrorReason != "" && (status.LastErrorAt.IsZero() || at.Before(status.LastErrorAt) || at.Sub(status.LastErrorAt) > 30*time.Second) {
		status.LastErrorReason = ""
		status.LastErrorAt = time.Time{}
	}
	switch {
	case status.AdmittedOperations == 0:
		status.Reason = "zero_admitted_operations"
	case !status.CapacityFeasible:
		status.Reason = "capacity_infeasible"
	case status.PassesSinceStart == 0 || status.LastPassAgeSeconds > 3:
		status.Reason = "scheduler_loop_stale"
	case status.LastErrorReason != "" && !status.LastErrorAt.IsZero() && !at.Before(status.LastErrorAt) && at.Sub(status.LastErrorAt) <= 30*time.Second:
		status.Reason = status.LastErrorReason
	default:
		status.State = "ready"
		status.Ready = true
	}
	if status.Reason != "" {
		status.State = "degraded"
	}
	return status
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
