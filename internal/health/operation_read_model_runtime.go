package health

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

const (
	OperationObservationPlanRuntimePinSchema = "datapan.health-operation-plan-runtime-pin.v1"
	maxOperationObservationPlanRuntimePin    = 16 * 1024
)

var errOperationReadModelRuntimeUnavailable = errors.New("operation read model runtime unavailable")

type operationObservationPlanRuntimePin struct {
	SchemaVersion string                          `json:"schema_version"`
	Plan          OperationObservationPlanBinding `json:"plan"`
}

// LoadOperationObservationPlanRuntimePin reads the small image-owned pin that
// selects the Registry release already installed beside the Health binary.
// The release manifest, index, and shards are independently verified by
// LoadPinnedOperationObservationPlan before any operation is projected.
func LoadOperationObservationPlanRuntimePin(path string) (OperationObservationPlanBinding, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maxOperationObservationPlanRuntimePin {
		return OperationObservationPlanBinding{}, errOperationReadModelRuntimeUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return OperationObservationPlanBinding{}, errOperationReadModelRuntimeUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxOperationObservationPlanRuntimePin+1))
	if err != nil || len(raw) == 0 || len(raw) > maxOperationObservationPlanRuntimePin {
		return OperationObservationPlanBinding{}, errOperationReadModelRuntimeUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var pin operationObservationPlanRuntimePin
	if decoder.Decode(&pin) != nil || ensureEOF(decoder) != nil || pin.SchemaVersion != OperationObservationPlanRuntimePinSchema || !validOperationObservationPlanBinding(pin.Plan) {
		return OperationObservationPlanBinding{}, errOperationReadModelRuntimeUnavailable
	}
	return pin.Plan, nil
}

// LoadOperationReadModelRuntime verifies the image-owned Registry plan and
// byte-pinned Health metadata before opening the read-only observation cache.
// No provider or Gatus request is made by this constructor.
func LoadOperationReadModelRuntime(planRoot, planPinPath, attemptStorePath string, metadata VerifiedRegistryAPIMetadata, maxSnapshotAge time.Duration, now time.Time) (*OperationReadModelRuntime, error) {
	binding, err := LoadOperationObservationPlanRuntimePin(planPinPath)
	if err != nil {
		return nil, errOperationReadModelRuntimeUnavailable
	}
	plan, err := LoadPinnedOperationObservationPlan(planRoot, binding)
	if err != nil {
		return nil, errOperationReadModelRuntimeUnavailable
	}
	model, err := NewOperationReadModel(plan, metadata, nil, now)
	if err != nil {
		return nil, errOperationReadModelRuntimeUnavailable
	}
	store, err := OpenReadOnlyOperationAttemptStore(attemptStorePath)
	if err != nil {
		return nil, errOperationReadModelRuntimeUnavailable
	}
	return NewOperationReadModelRuntime(model, store, maxSnapshotAge)
}

type OperationReadModelRuntimeStatus struct {
	ReadModelState        string
	ReadModelReason       string
	CoverageState         string
	CoverageReady         bool
	RegistryRevision      string
	ReleaseManifestSHA256 string
	IndexSHA256           string
	SnapshotGeneratedAt   *time.Time
	LastCompleteRefreshAt *time.Time
	LastRefreshError      string
	RefreshOffset         int
	RefreshIdentityCount  int
	SnapshotMaxAge        time.Duration
	IdentityCounts        OperationReadModelIdentityCounts
	CurrentPass           int
	CurrentFail           int
	CurrentIndeterminate  int
}

// OperationReadModelRuntime is the separate-public-process view of the
// scheduler's durable store. It publishes only complete sweeps. During a
// failed or partial sweep, readers continue using the last complete snapshot
// until its explicit maximum age expires.
type OperationReadModelRuntime struct {
	refreshMu sync.Mutex
	mu        sync.RWMutex

	baseline             *OperationReadModel
	current              *OperationReadModel
	staging              *OperationReadModel
	store                *OperationAttemptStore
	maxAge               time.Duration
	refreshAt            time.Time
	offset               int
	lastGoodAt           time.Time
	lastError            string
	counts               OperationReadModelIdentityCounts
	currentPass          int
	currentFail          int
	currentIndeterminate int
}

type OperationReadModelRefreshPolicy struct {
	BatchSize           int
	BatchInterval       time.Duration
	FullRefreshInterval time.Duration
	MaxPassDuration     time.Duration
}

func NewOperationReadModelRuntime(model *OperationReadModel, store *OperationAttemptStore, maxSnapshotAge time.Duration) (*OperationReadModelRuntime, error) {
	if model == nil || store == nil || maxSnapshotAge < time.Minute || maxSnapshotAge > 24*time.Hour {
		return nil, errOperationReadModelRuntimeUnavailable
	}
	return &OperationReadModelRuntime{baseline: model, store: store, maxAge: maxSnapshotAge, counts: model.identityCounts(time.Now().UTC())}, nil
}

func validOperationReadModelRefreshPolicy(policy OperationReadModelRefreshPolicy) bool {
	return policy.BatchSize > 0 && policy.BatchSize <= operationAttemptIdentityBatchMaximum &&
		policy.BatchInterval >= 100*time.Millisecond && policy.BatchInterval <= time.Minute &&
		policy.FullRefreshInterval >= time.Second && policy.FullRefreshInterval <= 6*time.Hour &&
		policy.MaxPassDuration >= time.Second && policy.MaxPassDuration <= 10*time.Minute
}

// ValidateOperationReadModelRefreshPolicy rejects unbounded or pathological
// refresh settings before the background reader starts.
func ValidateOperationReadModelRefreshPolicy(policy OperationReadModelRefreshPolicy) error {
	if !validOperationReadModelRefreshPolicy(policy) {
		return errOperationReadModelRuntimeUnavailable
	}
	return nil
}

// Run performs one bounded identity batch at a time. A complete plan sweep
// consists of deterministic slices, each capped at 256 files and at most
// 8 MiB of state bytes. It waits for the configured full-refresh interval
// after a successful sweep and resumes an incomplete sweep after a failure.
func (runtime *OperationReadModelRuntime) Run(ctx context.Context, policy OperationReadModelRefreshPolicy) error {
	if runtime == nil || ctx == nil || !validOperationReadModelRefreshPolicy(policy) {
		return errOperationReadModelRuntimeUnavailable
	}
	passStarted := time.Time{}
	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		now := time.Now().UTC()
		if passStarted.IsZero() {
			passStarted = now
		}
		if now.Sub(passStarted) > policy.MaxPassDuration {
			runtime.setRefreshError("refresh_deadline")
			passStarted = time.Time{}
			if !waitOperationReadModelRefresh(ctx, policy.FullRefreshInterval) {
				return nil
			}
			continue
		}
		complete, err := runtime.RefreshNextBatch(now, policy.BatchSize)
		if err != nil {
			passStarted = time.Time{}
			if !waitOperationReadModelRefresh(ctx, policy.FullRefreshInterval) {
				return nil
			}
			continue
		}
		if complete {
			passStarted = time.Time{}
			if !waitOperationReadModelRefresh(ctx, policy.FullRefreshInterval) {
				return nil
			}
			continue
		}
		if !waitOperationReadModelRefresh(ctx, policy.BatchInterval) {
			return nil
		}
	}
}

func waitOperationReadModelRefresh(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// RefreshNextBatch reads at most one bounded identity batch. The staging
// projection is private until every plan identity has been checked, so a
// later corrupt file cannot publish a partial snapshot.
func (runtime *OperationReadModelRuntime) RefreshNextBatch(at time.Time, batchSize int) (bool, error) {
	if runtime == nil || at.IsZero() || batchSize < 1 || batchSize > operationAttemptIdentityBatchMaximum {
		return false, errOperationReadModelRuntimeUnavailable
	}
	runtime.refreshMu.Lock()
	defer runtime.refreshMu.Unlock()

	runtime.mu.Lock()
	if runtime.staging == nil {
		base := runtime.current
		if base == nil {
			base = runtime.baseline
		}
		runtime.staging = cloneOperationReadModelForRefresh(base, at.UTC())
		runtime.offset = 0
		runtime.refreshAt = at.UTC()
	}
	candidate := runtime.staging
	offset := runtime.offset
	runtime.mu.Unlock()

	next, complete, err := candidate.RefreshFromStoreBatch(runtime.store, offset, batchSize, at.UTC())
	if err != nil {
		runtime.setRefreshError("state_unavailable")
		return false, errOperationReadModelRuntimeUnavailable
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if !complete {
		runtime.offset = next
		runtime.lastError = ""
		return false, nil
	}
	counts := candidate.identityCounts(at.UTC())
	pass, fail, indeterminate := operationReadModelResultCounts(candidate, at.UTC())
	completed := at.UTC()
	runtime.current = candidate
	runtime.staging = nil
	runtime.offset = 0
	runtime.refreshAt = time.Time{}
	runtime.lastGoodAt = completed
	runtime.lastError = ""
	runtime.counts = counts
	runtime.currentPass = pass
	runtime.currentFail = fail
	runtime.currentIndeterminate = indeterminate
	return true, nil
}

func cloneOperationReadModelForRefresh(source *OperationReadModel, generatedAt time.Time) *OperationReadModel {
	source.mu.RLock()
	defer source.mu.RUnlock()
	return &OperationReadModel{
		registryRevision:       source.registryRevision,
		manifestSHA:            source.manifestSHA,
		indexSHA:               source.indexSHA,
		planSchemaSHA:          source.planSchemaSHA,
		pageSchemaSHA:          source.pageSchemaSHA,
		metadataPin:            source.metadataPin,
		inventoryUnknownScopes: source.inventoryUnknownScopes,
		generatedAt:            generatedAt.UTC(),
		rows:                   append([]OperationReadModelRow(nil), source.rows...),
		staticRows:             append([]OperationReadModelRow(nil), source.staticRows...),
		byIdentity:             source.byIdentity,
		byAPI:                  source.byAPI,
		expectedBindings:       source.expectedBindings,
	}
}

func (runtime *OperationReadModelRuntime) currentSnapshot(at time.Time) (*OperationReadModel, error) {
	if runtime == nil || at.IsZero() {
		return nil, errOperationReadModelRuntimeUnavailable
	}
	runtime.mu.RLock()
	model, completed, maxAge := runtime.current, runtime.lastGoodAt, runtime.maxAge
	runtime.mu.RUnlock()
	if model == nil || completed.IsZero() || at.Before(completed) || at.Sub(completed) > maxAge {
		return nil, ErrOperationReadModelUnavailable
	}
	return model, nil
}

func (runtime *OperationReadModelRuntime) setRefreshError(reason string) {
	if runtime == nil {
		return
	}
	runtime.mu.Lock()
	runtime.lastError = reason
	runtime.mu.Unlock()
}

func (runtime *OperationReadModelRuntime) LookupAPIProgress(apiIDs []string, at time.Time) ([]OperationAPIProgress, error) {
	model, err := runtime.currentSnapshot(at)
	if err != nil {
		return nil, err
	}
	return model.LookupAPIProgress(apiIDs, at)
}

func (runtime *OperationReadModelRuntime) PageOperations(query OperationPageQuery, at time.Time) (OperationReadModelPage, error) {
	model, err := runtime.currentSnapshot(at)
	if err != nil {
		return OperationReadModelPage{}, err
	}
	return model.PageOperations(query, at)
}

func (runtime *OperationReadModelRuntime) LookupPublicOperationRows(identities []RegistryOperationLookupIdentity, at time.Time) ([]OperationReadModelRow, error) {
	model, err := runtime.currentSnapshot(at)
	if err != nil {
		return nil, err
	}
	return model.LookupPublicOperationRows(identities, at)
}

// Status contains no error text, transport target, credential reference, or
// response content. It distinguishes cache availability from API coverage.
func (runtime *OperationReadModelRuntime) Status(at time.Time) OperationReadModelRuntimeStatus {
	status := OperationReadModelRuntimeStatus{ReadModelState: "starting", ReadModelReason: "awaiting_initial_snapshot", CoverageState: "unknown"}
	if runtime == nil || at.IsZero() {
		status.ReadModelState, status.ReadModelReason = "unavailable", "runtime_not_configured"
		return status
	}
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	status.SnapshotMaxAge = runtime.maxAge
	status.RefreshOffset = runtime.offset
	status.RefreshIdentityCount = len(runtime.baseline.staticRows)
	status.LastRefreshError = runtime.lastError
	status.IdentityCounts = runtime.counts
	status.CurrentPass = runtime.currentPass
	status.CurrentFail = runtime.currentFail
	status.CurrentIndeterminate = runtime.currentIndeterminate
	status.RegistryRevision = runtime.baseline.registryRevision
	status.ReleaseManifestSHA256 = runtime.baseline.manifestSHA
	status.IndexSHA256 = runtime.baseline.indexSHA
	if !runtime.lastGoodAt.IsZero() {
		completed := runtime.lastGoodAt
		status.LastCompleteRefreshAt = &completed
		generated := runtime.current.generatedAt
		status.SnapshotGeneratedAt = &generated
	}
	if runtime.current == nil {
		if runtime.staging != nil {
			status.ReadModelReason = "initial_snapshot_in_progress"
		} else if runtime.lastError != "" {
			status.ReadModelState, status.ReadModelReason = "unavailable", runtime.lastError
		}
		status.CoverageState = operationReadModelCoverageStateWithResults(status.IdentityCounts, 0, 0, 0)
		return status
	}
	if at.Before(runtime.lastGoodAt) || at.Sub(runtime.lastGoodAt) > runtime.maxAge {
		status.ReadModelState, status.ReadModelReason = "stale", "snapshot_stale"
	} else if runtime.lastError != "" {
		status.ReadModelState, status.ReadModelReason = "refresh_error", runtime.lastError
	} else if runtime.staging != nil {
		status.ReadModelState, status.ReadModelReason = "refreshing", "snapshot_refresh_in_progress"
	} else {
		status.ReadModelState, status.ReadModelReason = "ready", "snapshot_current"
	}
	status.CoverageState = operationReadModelCoverageStateWithResults(status.IdentityCounts, status.CurrentPass, status.CurrentFail, status.CurrentIndeterminate)
	status.CoverageReady = status.ReadModelState == "ready" && status.IdentityCounts.Known > 0 && status.IdentityCounts.Admitted > 0
	return status
}

func operationReadModelCoverageStateWithResults(counts OperationReadModelIdentityCounts, pass, fail, indeterminate int) string {
	switch {
	case counts.Known == 0:
		return "no_registered_operations"
	case counts.Admitted == 0:
		return "no_admitted_operations"
	case counts.InventoryUnknownOperations > 0:
		return "partial_inventory"
	case counts.Admitted < counts.Known:
		return "partial_admission"
	case pass+fail+indeterminate < counts.Admitted:
		return "observations_incomplete"
	case indeterminate > 0:
		return "observations_indeterminate"
	case fail > 0:
		return "provider_failures_present"
	default:
		return "observed"
	}
}

func operationReadModelResultCounts(model *OperationReadModel, at time.Time) (pass, fail, indeterminate int) {
	if model == nil || at.IsZero() {
		return 0, 0, 0
	}
	model.mu.RLock()
	defer model.mu.RUnlock()
	for _, original := range model.rows {
		row := original
		refreshOperationReadModelFreshness(&row, at)
		switch row.ObservationState {
		case "current_pass":
			pass++
		case "current_fail":
			fail++
		case "current_indeterminate":
			indeterminate++
		}
	}
	return pass, fail, indeterminate
}
