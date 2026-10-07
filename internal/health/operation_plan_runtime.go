package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const maxOperationGatusRuntimeInputBytes = 32 << 20

var errOperationPlanRuntimeUnavailable = errors.New("verified operation plan runtime is unavailable")

// OperationPlanRuntimePaths names the image-owned source inputs and generated
// Gatus receiver bundle used by one scheduler process. These paths are never
// supplied by the public HTTP request path.
type OperationPlanRuntimePaths struct {
	PlanRoot             string
	PlanPinPath          string
	CanaryConfigPath     string
	RegistryMetadataPath string
	RegistryMetadataPin  string
	BaseGatusConfigPath  string
	GeneratedConfigPath  string
	IdentityMappingPath  string
	RuntimePinPath       string
	ActivationPath       string
	ActivationSHA256     string
}

type OperationPlanWorkerTarget struct {
	Record           OperationObservationPlanRecord
	ShardSHA256      string
	GatusEndpointKey string
}

// VerifiedOperationPlanRuntime is constructed only after the Registry
// release chain, Health metadata source bytes, activation, identity map,
// generated Gatus YAML, and runtime dependency pin all agree.
type VerifiedOperationPlanRuntime struct {
	Plan             PinnedOperationObservationPlan
	Metadata         VerifiedRegistryAPIMetadata
	Canaries         CanaryConfig
	Artifacts        OperationGatusArtifacts
	IdentityMapping  OperationGatusIdentityMapping
	ActiveTargets    []OperationPlanWorkerTarget
	SuppressedLegacy []string
	verified         bool
	verificationSeal string
}

// LoadVerifiedOperationPlanRuntime verifies the exact image-owned inputs
// before any scheduler may suppress a legacy canary or start a plan child.
// It reads only the bounded release manifest/index/shards and metadata
// projection; the 139 MiB Registry source is bound by digest, not opened.
func LoadVerifiedOperationPlanRuntime(paths OperationPlanRuntimePaths) (*VerifiedOperationPlanRuntime, error) {
	if !validOperationPlanRuntimePaths(paths) {
		return nil, errOperationPlanRuntimeUnavailable
	}
	canaryRaw, err := readOperationPlanRuntimeFile(paths.CanaryConfigPath, maxOperationGatusRuntimeInputBytes)
	if err != nil {
		return nil, errOperationPlanRuntimeUnavailable
	}
	canaries, err := LoadCanaryConfig(paths.CanaryConfigPath)
	if err != nil {
		return nil, errOperationPlanRuntimeUnavailable
	}
	metadata, err := LoadRegistryAPIMetadata(paths.RegistryMetadataPath, paths.RegistryMetadataPin, canaries)
	if err != nil {
		return nil, errOperationPlanRuntimeUnavailable
	}
	verifiedMetadata, err := NewVerifiedRegistryAPIMetadata(metadata)
	if err != nil {
		return nil, errOperationPlanRuntimeUnavailable
	}
	binding, err := LoadOperationObservationPlanRuntimePin(paths.PlanPinPath)
	if err != nil {
		return nil, errOperationPlanRuntimeUnavailable
	}
	plan, err := LoadPinnedOperationObservationPlan(paths.PlanRoot, binding)
	if err != nil {
		return nil, errOperationPlanRuntimeUnavailable
	}
	return verifyOperationGatusRuntimeArtifacts(paths, canaryRaw, canaries, verifiedMetadata, plan)
}

func verifyOperationGatusRuntimeArtifacts(paths OperationPlanRuntimePaths, canaryRaw []byte, canaries CanaryConfig, metadata VerifiedRegistryAPIMetadata, plan PinnedOperationObservationPlan) (*VerifiedOperationPlanRuntime, error) {
	if !validOperationPlanRuntimePaths(paths) || len(canaryRaw) == 0 || len(canaryRaw) > maxOperationGatusRuntimeInputBytes || !verifiedGatusMetadata(metadata, canaries) || plan.state == nil || !plan.state.verified {
		return nil, errOperationPlanRuntimeUnavailable
	}
	baseConfig, err := readOperationPlanRuntimeFile(paths.BaseGatusConfigPath, maxOperationGatusRuntimeInputBytes)
	if err != nil {
		return nil, errOperationPlanRuntimeUnavailable
	}
	var activation *OperationGatusActivation
	activationSHA := ""
	if (paths.ActivationPath == "") != (paths.ActivationSHA256 == "") {
		return nil, errOperationPlanRuntimeUnavailable
	}
	if paths.ActivationPath != "" {
		if !sha256Pattern.MatchString(paths.ActivationSHA256) {
			return nil, errOperationPlanRuntimeUnavailable
		}
		activationRaw, readErr := readOperationPlanRuntimeFile(paths.ActivationPath, maxOperationGatusActivationBytes)
		if readErr != nil {
			return nil, errOperationPlanRuntimeUnavailable
		}
		loaded, sha, decodeErr := DecodeOperationGatusActivation(activationRaw, plan)
		if decodeErr != nil || sha != paths.ActivationSHA256 {
			return nil, errOperationPlanRuntimeUnavailable
		}
		activation, activationSHA = &loaded, sha
	}
	canarySHA := digestOperationGatusBytes(canaryRaw)
	artifacts, err := GenerateOperationGatusArtifacts(baseConfig, canarySHA, canaries, metadata, &plan, activation, activationSHA)
	if err != nil {
		return nil, errOperationPlanRuntimeUnavailable
	}
	generatedConfig, err := readOperationPlanRuntimeFile(paths.GeneratedConfigPath, maxOperationGatusRuntimeInputBytes)
	if err != nil || !bytes.Equal(generatedConfig, artifacts.Config) {
		return nil, errOperationPlanRuntimeUnavailable
	}
	mappingRaw, err := readOperationPlanRuntimeFile(paths.IdentityMappingPath, maxOperationGatusMappingBytes)
	if err != nil || !bytes.Equal(mappingRaw, artifacts.Mapping) || digestOperationGatusBytes(mappingRaw) != artifacts.MappingSHA256 {
		return nil, errOperationPlanRuntimeUnavailable
	}
	runtimePinRaw, err := readOperationPlanRuntimeFile(paths.RuntimePinPath, maxOperationGatusRuntimeInputBytes)
	if err != nil || !bytes.Equal(runtimePinRaw, artifacts.RuntimePin) || digestOperationGatusBytes(runtimePinRaw) != artifacts.RuntimePinSHA256 {
		return nil, errOperationPlanRuntimeUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(mappingRaw))
	decoder.DisallowUnknownFields()
	var mapping OperationGatusIdentityMapping
	if decoder.Decode(&mapping) != nil || ensureEOF(decoder) != nil || mapping.SchemaVersion != OperationGatusMappingSchemaVersion || mapping.RegistryRevision != plan.RegistryRevision() || mapping.IndexSHA256 != plan.IndexSHA256() || mapping.ReleaseManifestSHA256 != plan.binding.ReleaseManifestSHA256 || mapping.ActivatedPlanOperations != len(activationOperations(activation)) {
		return nil, errOperationPlanRuntimeUnavailable
	}
	targets, err := exactActivePlanTargets(plan, mapping)
	if err != nil || len(targets) != mapping.ActivatedPlanOperations {
		return nil, errOperationPlanRuntimeUnavailable
	}
	runtime := &VerifiedOperationPlanRuntime{
		Plan: plan, Metadata: metadata, Canaries: canaries, Artifacts: artifacts,
		IdentityMapping: mapping, ActiveTargets: targets,
		SuppressedLegacy: append([]string(nil), artifacts.LegacySuppressedHealthIDs...),
		verified: true,
	}
	runtime.verificationSeal = operationPlanRuntimeSeal(runtime)
	if runtime.verificationSeal == "" {
		return nil, errOperationPlanRuntimeUnavailable
	}
	return runtime, nil
}

type operationPlanRuntimeSealWire struct {
	RegistryRevision       string                     `json:"registry_revision"`
	ReleaseManifestSHA256 string                     `json:"release_manifest_sha256"`
	IndexSHA256            string                     `json:"index_sha256"`
	ConfigSHA256           string                     `json:"config_sha256"`
	MappingSHA256          string                     `json:"mapping_sha256"`
	RuntimePinSHA256       string                     `json:"runtime_pin_sha256"`
	Targets                []OperationPlanWorkerTarget `json:"targets"`
	SuppressedLegacy       []string                   `json:"suppressed_legacy"`
}

func operationPlanRuntimeSeal(runtime *VerifiedOperationPlanRuntime) string {
	if runtime == nil || !runtime.verified || runtime.Plan.state == nil || !runtime.Plan.state.verified {
		return ""
	}
	wire := operationPlanRuntimeSealWire{
		RegistryRevision: runtime.Plan.RegistryRevision(), ReleaseManifestSHA256: runtime.Plan.binding.ReleaseManifestSHA256,
		IndexSHA256: runtime.Plan.IndexSHA256(), ConfigSHA256: digestOperationGatusBytes(runtime.Artifacts.Config),
		MappingSHA256: digestOperationGatusBytes(runtime.Artifacts.Mapping), RuntimePinSHA256: digestOperationGatusBytes(runtime.Artifacts.RuntimePin),
		Targets: runtime.ActiveTargets, SuppressedLegacy: runtime.SuppressedLegacy,
	}
	raw, err := json.Marshal(wire)
	if err != nil || len(raw) == 0 || len(raw) > maxOperationGatusRuntimeInputBytes {
		return ""
	}
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum[:])
}

func validVerifiedOperationPlanRuntime(runtime *VerifiedOperationPlanRuntime) bool {
	return runtime != nil && runtime.verified && sha256Pattern.MatchString(runtime.verificationSeal) && operationPlanRuntimeSeal(runtime) == runtime.verificationSeal
}

func validOperationPlanRuntimePaths(paths OperationPlanRuntimePaths) bool {
	for _, path := range []string{
		paths.PlanRoot, paths.PlanPinPath, paths.CanaryConfigPath, paths.RegistryMetadataPath,
		paths.RegistryMetadataPin, paths.BaseGatusConfigPath, paths.GeneratedConfigPath,
		paths.IdentityMappingPath, paths.RuntimePinPath,
	} {
		if !filepath.IsAbs(path) {
			return false
		}
	}
	return paths.ActivationPath == "" || filepath.IsAbs(paths.ActivationPath)
}

func readOperationPlanRuntimeFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maximum {
		return nil, errOperationPlanRuntimeUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errOperationPlanRuntimeUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum {
		return nil, errOperationPlanRuntimeUnavailable
	}
	return raw, nil
}

func activationOperations(activation *OperationGatusActivation) []OperationGatusActivationEntry {
	if activation == nil {
		return nil
	}
	return activation.Operations
}

func exactActivePlanTargets(plan PinnedOperationObservationPlan, mapping OperationGatusIdentityMapping) ([]OperationPlanWorkerTarget, error) {
	if plan.state == nil || !plan.state.verified || mapping.PlanState != "verified" || mapping.KnownPlanOperations != plan.Counts().KnownOperations || mapping.ActivatedPlanOperations < 0 || mapping.ActivatedPlanOperations > mapping.KnownPlanOperations || len(mapping.Operations) > maxOperationGatusTargets {
		return nil, errOperationPlanRuntimeUnavailable
	}
	byIdentity := make(map[string]OperationGatusIdentity, len(mapping.Operations))
	for _, item := range mapping.Operations {
		key := operationReadModelIdentityKey(item.SourceID, item.RegistryOperationID)
		if !operationSourceIDPattern.MatchString(item.SourceID) || item.RegistryOperationID == "" || item.GatusEndpointKey == "" {
			return nil, errOperationPlanRuntimeUnavailable
		}
		if _, duplicate := byIdentity[key]; duplicate {
			return nil, errOperationPlanRuntimeUnavailable
		}
		byIdentity[key] = item
	}
	seen := make(map[string]bool, mapping.ActivatedPlanOperations)
	var targets []OperationPlanWorkerTarget
	for shardIndex, ref := range plan.state.index.Shards {
		records, err := plan.ReadShard(shardIndex)
		if err != nil {
			return nil, errOperationPlanRuntimeUnavailable
		}
		for _, record := range records {
			key := operationReadModelIdentityKey(record.SourceID, record.OperationID)
			item, found := byIdentity[key]
			if !found || item.PlanAdmissionState != record.AdmissionStatus || item.ObservationPeriodSecond != int64(record.ObservationPeriod/time.Second) {
				return nil, errOperationPlanRuntimeUnavailable
			}
			if !item.PlanActive {
				if item.Active && !item.LegacyActive {
					return nil, errOperationPlanRuntimeUnavailable
				}
				continue
			}
			if !item.Active || item.LegacyActive || !record.ExecutionEligible || record.TestOnly || record.AdmissionStatus != "admitted" || record.RequestPlanStatus != "complete" || record.RuntimeBindingStatus != "bound" || !record.QuotaPoliciesAdmitted {
				return nil, errOperationPlanRuntimeUnavailable
			}
			if seen[key] {
				return nil, errOperationPlanRuntimeUnavailable
			}
			seen[key] = true
			targets = append(targets, OperationPlanWorkerTarget{Record: record, ShardSHA256: ref.SHA256, GatusEndpointKey: item.GatusEndpointKey})
		}
	}
	for key, item := range byIdentity {
		if item.PlanActive != seen[key] {
			return nil, errOperationPlanRuntimeUnavailable
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].Record.SourceID != targets[j].Record.SourceID {
			return targets[i].Record.SourceID < targets[j].Record.SourceID
		}
		return targets[i].Record.OperationID < targets[j].Record.OperationID
	})
	return targets, nil
}
