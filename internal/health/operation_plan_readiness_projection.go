package health

import (
	"errors"
	"sort"
	"time"
)

// OperationPlanReadinessProjection is the bounded proof that exact legacy
// identities have transferred to the verified Registry operation lane. It
// contains aggregate freshness evidence and the small set of transferred
// public canary IDs; it never contains operation results or provider data.
type OperationPlanReadinessProjection struct {
	SchemaVersion             string     `json:"schema_version"`
	Ready                     bool       `json:"ready"`
	RegistryRevision          string     `json:"registry_revision"`
	ReleaseManifestSHA256     string     `json:"release_manifest_sha256,omitempty"`
	IndexSHA256               string     `json:"index_sha256"`
	ActivationSHA256          string     `json:"activation_sha256,omitempty"`
	CanaryConfigSHA256        string     `json:"canary_config_sha256,omitempty"`
	IdentityMappingSHA256     string     `json:"identity_mapping_sha256,omitempty"`
	RuntimePinSHA256          string     `json:"runtime_pin_sha256,omitempty"`
	KnownOperations           int        `json:"known_operations"`
	AdmittedOperations        int        `json:"admitted_operations"`
	CapacityFeasible          bool       `json:"capacity_feasible"`
	LastPassAt                *time.Time `json:"last_pass_at,omitempty"`
	EvidenceSweepAt           *time.Time `json:"evidence_sweep_at,omitempty"`
	EvidenceCheckedOperations int        `json:"evidence_checked_operations"`
	EvidenceCurrentOperations int        `json:"evidence_current_operations"`
	EvidenceMissingOperations int        `json:"evidence_missing_operations"`
	EvidenceValidUntil        *time.Time `json:"evidence_valid_until,omitempty"`
	SuppressedLegacyCanaries  []string   `json:"suppressed_legacy_canaries"`
}

// OperationPlanReadinessBinding is created only from the fully verified
// scheduler runtime bundle. The public reader uses it to validate that the
// readiness document accounts for exactly the original canary identities.
type OperationPlanReadinessBinding struct {
	registryRevision      string
	releaseManifestSHA256 string
	indexSHA256           string
	activationSHA256      string
	canaryConfigSHA256    string
	identityMappingSHA256 string
	runtimePinSHA256      string
	knownOperations       int
	admitted              int
	canaryIDs             []string
	suppressed            []string
}

func NewOperationPlanReadinessBinding(runtime *VerifiedOperationPlanRuntime) (*OperationPlanReadinessBinding, error) {
	if !validVerifiedOperationPlanRuntime(runtime) {
		return nil, errOperationPlanRuntimeUnavailable
	}
	canaryIDs := make([]string, 0, len(runtime.Canaries.Canaries))
	canarySet := make(map[string]struct{}, len(runtime.Canaries.Canaries))
	for _, canary := range runtime.Canaries.Canaries {
		if canary.OperationID == "" {
			return nil, errOperationPlanRuntimeUnavailable
		}
		if _, found := canarySet[canary.OperationID]; found {
			return nil, errOperationPlanRuntimeUnavailable
		}
		canarySet[canary.OperationID] = struct{}{}
		canaryIDs = append(canaryIDs, canary.OperationID)
	}
	suppressed := append([]string(nil), runtime.SuppressedLegacy...)
	seenSuppressed := make(map[string]struct{}, len(suppressed))
	for _, operationID := range suppressed {
		if _, found := canarySet[operationID]; !found {
			return nil, errOperationPlanRuntimeUnavailable
		}
		if _, duplicate := seenSuppressed[operationID]; duplicate {
			return nil, errOperationPlanRuntimeUnavailable
		}
		seenSuppressed[operationID] = struct{}{}
	}
	sort.Strings(canaryIDs)
	sort.Strings(suppressed)
	counts := runtime.Plan.Counts()
	return &OperationPlanReadinessBinding{
		registryRevision: runtime.Plan.RegistryRevision(), releaseManifestSHA256: runtime.IdentityMapping.ReleaseManifestSHA256,
		indexSHA256: runtime.Plan.IndexSHA256(), activationSHA256: runtime.IdentityMapping.ActivationSHA256,
		canaryConfigSHA256:    runtime.IdentityMapping.CanaryConfigSHA256,
		identityMappingSHA256: runtime.Artifacts.MappingSHA256, runtimePinSHA256: runtime.Artifacts.RuntimePinSHA256,
		knownOperations: counts.KnownOperations, admitted: len(runtime.ActiveTargets),
		canaryIDs: canaryIDs, suppressed: suppressed,
	}, nil
}

func OperationPlanReadinessProjectionFromStatus(status OperationPlanSchedulerStatus) *OperationPlanReadinessProjection {
	if status.State == "disabled" {
		return nil
	}
	projection := &OperationPlanReadinessProjection{
		SchemaVersion: "datapan.health-operation-plan-readiness.v1", Ready: status.Ready,
		RegistryRevision: status.RegistryRevision, IndexSHA256: status.IndexSHA256,
		ReleaseManifestSHA256: status.ReleaseManifestSHA256, ActivationSHA256: status.ActivationSHA256,
		CanaryConfigSHA256: status.CanaryConfigSHA256, IdentityMappingSHA256: status.IdentityMappingSHA256,
		RuntimePinSHA256: status.RuntimePinSHA256,
		KnownOperations:  status.KnownOperations, AdmittedOperations: status.AdmittedOperations,
		CapacityFeasible:          status.CapacityFeasible,
		EvidenceCheckedOperations: status.EvidenceCheckedOperations,
		EvidenceCurrentOperations: status.EvidenceCurrentOperations,
		EvidenceMissingOperations: status.EvidenceMissingOperations,
		SuppressedLegacyCanaries:  append([]string{}, status.SuppressedLegacyCanaries...),
	}
	if !status.LastPassAt.IsZero() {
		value := status.LastPassAt.UTC()
		projection.LastPassAt = &value
	}
	if !status.EvidenceSweepAt.IsZero() {
		value := status.EvidenceSweepAt.UTC()
		projection.EvidenceSweepAt = &value
	}
	if !status.EvidenceValidUntil.IsZero() {
		value := status.EvidenceValidUntil.UTC()
		projection.EvidenceValidUntil = &value
	}
	return projection
}

var errOperationPlanReadinessBinding = errors.New("operation-plan readiness binding is unavailable")

func validateOperationPlanReadinessBinding(binding *OperationPlanReadinessBinding, canaries CanaryConfig) error {
	if binding == nil || binding.registryRevision == "" || !sha256Pattern.MatchString(binding.releaseManifestSHA256) ||
		!sha256Pattern.MatchString(binding.indexSHA256) || !sha256Pattern.MatchString(binding.activationSHA256) ||
		!sha256Pattern.MatchString(binding.canaryConfigSHA256) || !sha256Pattern.MatchString(binding.identityMappingSHA256) ||
		!sha256Pattern.MatchString(binding.runtimePinSHA256) || binding.knownOperations <= 0 || binding.admitted < 0 || binding.admitted > binding.knownOperations {
		return errOperationPlanReadinessBinding
	}
	configured := make([]string, 0, len(canaries.Canaries))
	for _, canary := range canaries.Canaries {
		if canary.OperationID == "" {
			return errOperationPlanReadinessBinding
		}
		configured = append(configured, canary.OperationID)
	}
	sort.Strings(configured)
	if !equalOperationPlanIdentityLists(configured, binding.canaryIDs) || !isSortedUniqueOperationPlanIDs(binding.suppressed) {
		return errOperationPlanReadinessBinding
	}
	canarySet := make(map[string]struct{}, len(configured))
	for _, id := range configured {
		canarySet[id] = struct{}{}
	}
	for _, id := range binding.suppressed {
		if _, found := canarySet[id]; !found {
			return errOperationPlanReadinessBinding
		}
	}
	return nil
}

func equalOperationPlanIdentityLists(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func isSortedUniqueOperationPlanIDs(ids []string) bool {
	for i, id := range ids {
		if id == "" || i > 0 && ids[i-1] >= id {
			return false
		}
	}
	return true
}
