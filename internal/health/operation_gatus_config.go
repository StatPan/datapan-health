package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	OperationGatusActivationSchemaVersion = "datapan.health-operation-gatus-activation.v1"
	OperationGatusMappingSchemaVersion    = "datapan.health-operation-gatus-identity-map.v1"
	OperationGatusRuntimePinSchemaVersion = "datapan.health-operation-gatus-runtime-dependencies.v1"
	maxOperationGatusActivationBytes      = 4 << 20
	maxOperationGatusMappingBytes         = 32 << 20
	maxOperationGatusConfigBytes          = 32 << 20
	maxOperationGatusTargets              = 100_000
)

var errOperationGatusConfiguration = errors.New("operation Gatus configuration is not valid for the pinned Registry identity set")

// OperationGatusActivation is an explicit Health-owned execution switch. An
// admitted Registry operation does not become an active worker or Gatus
// target until its exact source/operation identity is listed here.
type OperationGatusActivation struct {
	SchemaVersion         string                          `json:"schema_version"`
	RegistryRevision      string                          `json:"registry_revision"`
	IndexSHA256           string                          `json:"index_sha256"`
	Operations            []OperationGatusActivationEntry `json:"operations"`
	verifiedRawSHA256     string
	verifiedPayloadSHA256 string
	verifiedAbsent        bool
}

type OperationGatusActivationEntry struct {
	SourceID    string `json:"source_id"`
	OperationID string `json:"operation_id"`
}

// OperationGatusIdentity is private runtime plumbing. The full map has an
// entry for every operation in the pinned plan, including inactive rows, but
// only Active targets receive Gatus external-endpoint configuration.
type OperationGatusIdentity struct {
	SourceID                string `json:"source_id"`
	RegistryOperationID     string `json:"registry_operation_id"`
	GatusEndpointKey        string `json:"gatus_endpoint_key"`
	PlanAdmissionState      string `json:"plan_admission_state"`
	PlanActive              bool   `json:"plan_active"`
	LegacyActive            bool   `json:"legacy_active"`
	LegacyHealthOperationID string `json:"legacy_health_operation_id,omitempty"`
	ObservationPeriodSecond int64  `json:"observation_period_seconds,omitempty"`
	Active                  bool   `json:"active"`
}

type OperationGatusIdentityMapping struct {
	SchemaVersion                  string                   `json:"schema_version"`
	RegistryRevision               string                   `json:"registry_revision,omitempty"`
	ReleaseManifestSHA256          string                   `json:"release_manifest_sha256,omitempty"`
	IndexSHA256                    string                   `json:"index_sha256,omitempty"`
	PlanState                      string                   `json:"plan_state"`
	PlanMissingReason              string                   `json:"plan_missing_reason,omitempty"`
	RegistryMetadataRevision       string                   `json:"registry_metadata_revision"`
	RegistryMetadataArtifactSHA256 string                   `json:"registry_metadata_artifact_sha256"`
	RegistryMetadataSourceSHA256   string                   `json:"registry_metadata_source_sha256"`
	RegistryMetadataCatalogSHA256  string                   `json:"registry_metadata_catalog_sha256"`
	CanaryConfigSHA256             string                   `json:"canary_config_sha256"`
	BaseGatusConfigSHA256          string                   `json:"base_gatus_config_sha256"`
	ActivationSHA256               string                   `json:"activation_sha256"`
	GeneratedConfigSHA256          string                   `json:"generated_config_sha256"`
	KnownPlanOperations            int                      `json:"known_plan_operations"`
	AdmittedPlanOperations         int                      `json:"admitted_plan_operations"`
	ActivatedPlanOperations        int                      `json:"activated_plan_operations"`
	LegacyCanaries                 int                      `json:"legacy_canaries"`
	LegacyOverlapsActivated        int                      `json:"legacy_overlaps_activated"`
	ConfiguredExternalEndpoints    int                      `json:"configured_external_endpoints"`
	LegacySuppressedHealthIDs      []string                 `json:"legacy_suppressed_health_operation_ids"`
	Operations                     []OperationGatusIdentity `json:"operations"`
}

type OperationGatusRuntimeDependencies struct {
	SchemaVersion                  string `json:"schema_version"`
	RegistryRevision               string `json:"registry_revision,omitempty"`
	ReleaseManifestSHA256          string `json:"release_manifest_sha256,omitempty"`
	IndexSHA256                    string `json:"index_sha256,omitempty"`
	PlanState                      string `json:"plan_state"`
	PlanMissingReason              string `json:"plan_missing_reason,omitempty"`
	RegistryMetadataRevision       string `json:"registry_metadata_revision"`
	RegistryMetadataArtifactSHA256 string `json:"registry_metadata_artifact_sha256"`
	RegistryMetadataSourceSHA256   string `json:"registry_metadata_source_sha256"`
	RegistryMetadataCatalogSHA256  string `json:"registry_metadata_catalog_sha256"`
	CanaryConfigSHA256             string `json:"canary_config_sha256"`
	BaseGatusConfigSHA256          string `json:"base_gatus_config_sha256"`
	ActivationSHA256               string `json:"activation_sha256"`
	IdentityMappingSHA256          string `json:"identity_mapping_sha256"`
	GeneratedConfigSHA256          string `json:"generated_config_sha256"`
	KnownPlanOperations            int    `json:"known_plan_operations"`
	ActivatedPlanOperations        int    `json:"activated_plan_operations"`
	LegacyCanaries                 int    `json:"legacy_canaries"`
	ConfiguredExternalEndpoints    int    `json:"configured_external_endpoints"`
}

type OperationGatusArtifacts struct {
	Config                    []byte
	Mapping                   []byte
	RuntimePin                []byte
	ConfigSHA256              string
	MappingSHA256             string
	RuntimePinSHA256          string
	LegacySuppressedHealthIDs []string
}

type operationGatusEndpoint struct {
	key       string
	group     string
	name      string
	heartbeat time.Duration
}

// DecodeOperationGatusActivation validates a small exact-ID activation file.
// It rejects noncanonical ordering and duplicates so a pin cannot quietly
// describe a different selection after serialization.
func DecodeOperationGatusActivation(raw []byte, plan PinnedOperationObservationPlan) (OperationGatusActivation, string, error) {
	if len(raw) == 0 || len(raw) > maxOperationGatusActivationBytes || plan.state == nil || !plan.state.verified {
		return OperationGatusActivation{}, "", errOperationGatusConfiguration
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var activation OperationGatusActivation
	if decoder.Decode(&activation) != nil || ensureEOF(decoder) != nil || activation.SchemaVersion != OperationGatusActivationSchemaVersion || activation.RegistryRevision != plan.RegistryRevision() || activation.IndexSHA256 != plan.IndexSHA256() || len(activation.Operations) > maxOperationGatusTargets {
		return OperationGatusActivation{}, "", errOperationGatusConfiguration
	}
	previous := ""
	for _, entry := range activation.Operations {
		if !operationSourceIDPattern.MatchString(entry.SourceID) || entry.OperationID == "" || len(entry.OperationID) > 256 || strings.TrimSpace(entry.OperationID) != entry.OperationID || strings.ContainsAny(entry.OperationID, "\x00\r\n") {
			return OperationGatusActivation{}, "", errOperationGatusConfiguration
		}
		key := operationReadModelIdentityKey(entry.SourceID, entry.OperationID)
		if previous != "" && key <= previous {
			return OperationGatusActivation{}, "", errOperationGatusConfiguration
		}
		previous = key
	}
	sum := sha256.Sum256(raw)
	canonical, err := json.Marshal(activation)
	if err != nil {
		return OperationGatusActivation{}, "", errOperationGatusConfiguration
	}
	canonicalSum := sha256.Sum256(canonical)
	activation.verifiedRawSHA256 = hex.EncodeToString(sum[:])
	activation.verifiedPayloadSHA256 = hex.EncodeToString(canonicalSum[:])
	return activation, hex.EncodeToString(sum[:]), nil
}

// GenerateOperationGatusArtifacts produces deterministic Gatus receiver
// configuration and its private exact identity map. It never places provider
// endpoints in Gatus: all generated entries are native external endpoints
// that accept Health's single-result deliveries.
func GenerateOperationGatusArtifacts(baseConfig []byte, canaryConfigSHA256 string, canaries CanaryConfig, metadata VerifiedRegistryAPIMetadata, plan *PinnedOperationObservationPlan, activation *OperationGatusActivation, activationSHA256 string) (OperationGatusArtifacts, error) {
	if len(baseConfig) == 0 || len(baseConfig) > maxOperationGatusConfigBytes || !sha256Pattern.MatchString(canaryConfigSHA256) || !verifiedGatusMetadata(metadata, canaries) {
		return OperationGatusArtifacts{}, errOperationGatusConfiguration
	}
	baseSHA := digestOperationGatusBytes(baseConfig)
	if activation == nil {
		activationSHA256 = digestOperationGatusBytes([]byte("datapan.health-operation-gatus-activation.none.v1\n"))
	} else {
		canonical, err := json.Marshal(activation)
		if err != nil || activation.verifiedAbsent || activation.verifiedRawSHA256 == "" || activationSHA256 != activation.verifiedRawSHA256 || digestOperationGatusBytes(canonical) != activation.verifiedPayloadSHA256 {
			return OperationGatusArtifacts{}, errOperationGatusConfiguration
		}
	}
	if !sha256Pattern.MatchString(activationSHA256) {
		return OperationGatusArtifacts{}, errOperationGatusConfiguration
	}

	entries := make(map[string]OperationGatusIdentity, max(len(canaries.Canaries), 16))
	legacyByIdentity := make(map[string]Canary, len(canaries.Canaries))
	identityByGatusKey := make(map[string]string, len(canaries.Canaries))
	metadataOperations := make(map[string]struct{}, len(metadata.operations))
	for _, operation := range metadata.operations {
		metadataOperations[operation.RegistryOperationID] = struct{}{}
	}
	endpoints := make(map[string]operationGatusEndpoint, len(canaries.Canaries))
	for _, canary := range canaries.Canaries {
		link, ok := metadata.canaryLinksByHealthID[canary.OperationID]
		if !ok || link.HealthOperationID != canary.OperationID || link.RegistryOperationID == "" || link.RegistryAPIID != link.DatasetID {
			return OperationGatusArtifacts{}, errOperationGatusConfiguration
		}
		identityKey := operationReadModelIdentityKey("data_go_kr", link.RegistryOperationID)
		if _, duplicate := entries[identityKey]; duplicate {
			return OperationGatusArtifacts{}, errOperationGatusConfiguration
		}
		group, name, ok := splitOperationGatusEndpointKey(canary.GatusEndpointKey)
		if !ok || !registerOperationGatusKey(identityByGatusKey, canary.GatusEndpointKey, identityKey) {
			return OperationGatusArtifacts{}, errOperationGatusConfiguration
		}
		entries[identityKey] = OperationGatusIdentity{
			SourceID: "data_go_kr", RegistryOperationID: link.RegistryOperationID,
			GatusEndpointKey: canary.GatusEndpointKey, PlanAdmissionState: "unknown",
			LegacyActive: true, LegacyHealthOperationID: canary.OperationID, Active: true,
		}
		legacyByIdentity[identityKey] = canary
		endpoints[canary.GatusEndpointKey] = operationGatusEndpoint{key: canary.GatusEndpointKey, group: group, name: name, heartbeat: time.Duration(canary.HeartbeatMinutes) * time.Minute}
	}

	var suppressed []string
	knownPlan, admittedPlan, activatedPlan := 0, 0, 0
	var planRevision, manifestSHA, indexSHA string
	planState, planMissingReason := "unavailable", "operation_plan_not_configured"
	if plan != nil {
		if plan.state == nil || !plan.state.verified || !plan.bindsSourceInventory("data_go_kr", "data.go.kr", "data/data-go-kr.registry.json", metadata.pin.SourceSHA256, metadata.identitySetSHA256) || plan.Counts().KnownOperations > maxOperationGatusTargets {
			return OperationGatusArtifacts{}, fmt.Errorf("%w: plan_source_inventory", errOperationGatusConfiguration)
		}
		planRevision, manifestSHA, indexSHA = plan.RegistryRevision(), plan.binding.ReleaseManifestSHA256, plan.IndexSHA256()
		planState, planMissingReason = "verified", ""
		if activation == nil {
			activation = &OperationGatusActivation{SchemaVersion: OperationGatusActivationSchemaVersion, RegistryRevision: planRevision, IndexSHA256: indexSHA, verifiedRawSHA256: activationSHA256, verifiedAbsent: true}
		}
		if activation.SchemaVersion != OperationGatusActivationSchemaVersion || activation.RegistryRevision != planRevision || activation.IndexSHA256 != indexSHA {
			return OperationGatusArtifacts{}, errOperationGatusConfiguration
		}
		active := make(map[string]struct{}, len(activation.Operations))
		for _, target := range activation.Operations {
			key := operationReadModelIdentityKey(target.SourceID, target.OperationID)
			if _, duplicate := active[key]; duplicate {
				return OperationGatusArtifacts{}, errOperationGatusConfiguration
			}
			active[key] = struct{}{}
		}
		seenActive := make(map[string]struct{}, len(active))
		for shardIndex := 0; shardIndex < plan.ShardCount(); shardIndex++ {
			records, err := plan.ReadShard(shardIndex)
			if err != nil {
				return OperationGatusArtifacts{}, errOperationGatusConfiguration
			}
			for _, record := range records {
				knownPlan++
				identityKey := operationReadModelIdentityKey(record.SourceID, record.OperationID)
				if _, duplicate := entries[identityKey]; duplicate && record.SourceID != "data_go_kr" {
					return OperationGatusArtifacts{}, errOperationGatusConfiguration
				}
				legacy, overlapsLegacy := entries[identityKey]
				if overlapsLegacy && record.SourceID != "data_go_kr" {
					return OperationGatusArtifacts{}, errOperationGatusConfiguration
				}
				if record.SourceID == "data_go_kr" {
					if _, metadataHasOperation := metadataOperations[record.OperationID]; !metadataHasOperation {
						return OperationGatusArtifacts{}, errOperationGatusConfiguration
					}
				}
				if record.AdmissionStatus == "admitted" {
					admittedPlan++
				}
				_, selected := active[identityKey]
				if selected {
					if !record.ExecutionEligible || record.TestOnly || record.AdmissionStatus != "admitted" || record.RequestPlanStatus != "complete" || record.RuntimeBindingStatus != "bound" || !record.QuotaPoliciesAdmitted || record.ObservationPeriod < time.Second || record.ObservationPeriod > 365*24*time.Hour {
						return OperationGatusArtifacts{}, fmt.Errorf("%w: active_plan_identity", errOperationGatusConfiguration)
					}
					seenActive[identityKey] = struct{}{}
					activatedPlan++
				}
				entry := OperationGatusIdentity{SourceID: record.SourceID, RegistryOperationID: record.OperationID, GatusEndpointKey: stableOperationGatusEndpointKey(record.SourceID, record.OperationID), PlanAdmissionState: record.AdmissionStatus, PlanActive: selected, Active: selected}
				if record.ObservationPeriod > 0 {
					entry.ObservationPeriodSecond = int64(record.ObservationPeriod / time.Second)
				}
				if overlapsLegacy {
					entry.GatusEndpointKey = legacy.GatusEndpointKey
					entry.LegacyHealthOperationID = legacy.LegacyHealthOperationID
					entry.LegacyActive = !selected
					entry.Active = true
					if selected {
						suppressed = append(suppressed, legacy.LegacyHealthOperationID)
						group, name, ok := splitOperationGatusEndpointKey(legacy.GatusEndpointKey)
						if !ok {
							return OperationGatusArtifacts{}, errOperationGatusConfiguration
						}
						endpoints[legacy.GatusEndpointKey] = operationGatusEndpoint{key: legacy.GatusEndpointKey, group: group, name: name, heartbeat: 2 * record.ObservationPeriod}
					}
				}
				if !registerOperationGatusKey(identityByGatusKey, entry.GatusEndpointKey, identityKey) {
					return OperationGatusArtifacts{}, fmt.Errorf("%w: gatus_identity_collision", errOperationGatusConfiguration)
				}
				if selected && !overlapsLegacy {
					group, name, ok := splitOperationGatusEndpointKey(entry.GatusEndpointKey)
					if !ok {
						return OperationGatusArtifacts{}, errOperationGatusConfiguration
					}
					endpoints[entry.GatusEndpointKey] = operationGatusEndpoint{key: entry.GatusEndpointKey, group: group, name: name, heartbeat: 2 * record.ObservationPeriod}
				}
				entries[identityKey] = entry
			}
		}
		if len(seenActive) != len(active) || knownPlan != plan.Counts().KnownOperations || activatedPlan != len(active) {
			return OperationGatusArtifacts{}, fmt.Errorf("%w: activation_selection", errOperationGatusConfiguration)
		}
		// A pinned full data.go.kr operation set must include every legacy link.
		for key := range legacyByIdentity {
			if _, found := entries[key]; !found {
				return OperationGatusArtifacts{}, errOperationGatusConfiguration
			}
		}
	}
	if len(entries) > maxOperationGatusTargets || len(endpoints) > maxOperationGatusTargets {
		return OperationGatusArtifacts{}, errOperationGatusConfiguration
	}
	orderedEntries := make([]OperationGatusIdentity, 0, len(entries))
	for _, entry := range entries {
		orderedEntries = append(orderedEntries, entry)
	}
	sort.Slice(orderedEntries, func(i, j int) bool {
		if orderedEntries[i].SourceID != orderedEntries[j].SourceID {
			return orderedEntries[i].SourceID < orderedEntries[j].SourceID
		}
		return orderedEntries[i].RegistryOperationID < orderedEntries[j].RegistryOperationID
	})
	orderedEndpoints := make([]operationGatusEndpoint, 0, len(endpoints))
	for _, endpoint := range endpoints {
		orderedEndpoints = append(orderedEndpoints, endpoint)
	}
	sort.Slice(orderedEndpoints, func(i, j int) bool { return orderedEndpoints[i].key < orderedEndpoints[j].key })
	generatedConfig, err := renderOperationGatusConfig(baseConfig, orderedEndpoints)
	if err != nil {
		return OperationGatusArtifacts{}, err
	}
	configSHA := digestOperationGatusBytes(generatedConfig)
	mapDoc := OperationGatusIdentityMapping{
		SchemaVersion: OperationGatusMappingSchemaVersion, RegistryRevision: planRevision,
		ReleaseManifestSHA256: manifestSHA, IndexSHA256: indexSHA, PlanState: planState, PlanMissingReason: planMissingReason,
		RegistryMetadataRevision: metadata.pin.RegistryRevision, RegistryMetadataArtifactSHA256: metadata.pin.ArtifactSHA256,
		RegistryMetadataSourceSHA256: metadata.pin.SourceSHA256, RegistryMetadataCatalogSHA256: metadata.pin.CatalogSHA256,
		CanaryConfigSHA256: canaryConfigSHA256, BaseGatusConfigSHA256: baseSHA, ActivationSHA256: activationSHA256,
		GeneratedConfigSHA256: configSHA, KnownPlanOperations: knownPlan, AdmittedPlanOperations: admittedPlan,
		ActivatedPlanOperations: activatedPlan, LegacyCanaries: len(canaries.Canaries), LegacyOverlapsActivated: len(suppressed),
		ConfiguredExternalEndpoints: len(endpoints), LegacySuppressedHealthIDs: sortedUniqueStrings(suppressed), Operations: orderedEntries,
	}
	mapBytes, err := json.MarshalIndent(mapDoc, "", "  ")
	if err != nil || len(mapBytes)+1 > maxOperationGatusMappingBytes {
		return OperationGatusArtifacts{}, errOperationGatusConfiguration
	}
	mapBytes = append(mapBytes, '\n')
	mappingSHA := digestOperationGatusBytes(mapBytes)
	runtimePin := OperationGatusRuntimeDependencies{
		SchemaVersion: OperationGatusRuntimePinSchemaVersion, RegistryRevision: planRevision,
		ReleaseManifestSHA256: manifestSHA, IndexSHA256: indexSHA, PlanState: planState, PlanMissingReason: planMissingReason,
		RegistryMetadataRevision: metadata.pin.RegistryRevision, RegistryMetadataArtifactSHA256: metadata.pin.ArtifactSHA256,
		RegistryMetadataSourceSHA256: metadata.pin.SourceSHA256, RegistryMetadataCatalogSHA256: metadata.pin.CatalogSHA256,
		CanaryConfigSHA256: canaryConfigSHA256, BaseGatusConfigSHA256: baseSHA, ActivationSHA256: activationSHA256,
		IdentityMappingSHA256: mappingSHA, GeneratedConfigSHA256: configSHA, KnownPlanOperations: knownPlan,
		ActivatedPlanOperations: activatedPlan, LegacyCanaries: len(canaries.Canaries), ConfiguredExternalEndpoints: len(endpoints),
	}
	pinBytes, err := json.MarshalIndent(runtimePin, "", "  ")
	if err != nil {
		return OperationGatusArtifacts{}, errOperationGatusConfiguration
	}
	pinBytes = append(pinBytes, '\n')
	return OperationGatusArtifacts{Config: generatedConfig, Mapping: mapBytes, RuntimePin: pinBytes, ConfigSHA256: configSHA, MappingSHA256: mappingSHA, RuntimePinSHA256: digestOperationGatusBytes(pinBytes), LegacySuppressedHealthIDs: mapDoc.LegacySuppressedHealthIDs}, nil
}

func registerOperationGatusKey(identityByKey map[string]string, gatusKey, identityKey string) bool {
	if identityByKey == nil || gatusKey == "" || identityKey == "" {
		return false
	}
	if existing, ok := identityByKey[gatusKey]; ok {
		return existing == identityKey
	}
	identityByKey[gatusKey] = identityKey
	return true
}

func verifiedGatusMetadata(metadata VerifiedRegistryAPIMetadata, canaries CanaryConfig) bool {
	return metadata.verified && sha256Pattern.MatchString(metadata.pin.ArtifactSHA256) && sha256Pattern.MatchString(metadata.pin.SourceSHA256) && sha256Pattern.MatchString(metadata.pin.CatalogSHA256) && metadata.pin.CatalogSHA256 == canaries.CatalogSHA256 && metadata.pin.APIEntityCount > 0 && metadata.pin.OperationCount == len(metadata.operations) && len(metadata.canaryLinksByHealthID) == len(canaries.Canaries)
}

func stableOperationGatusEndpointKey(sourceID, operationID string) string {
	sum := sha256.Sum256([]byte("datapan.health-operation-gatus-key.v1\x00" + sourceID + "\x00" + operationID))
	return "registry-operations_registry-" + hex.EncodeToString(sum[:])
}

func splitOperationGatusEndpointKey(key string) (group, name string, ok bool) {
	if !gatusKeyPattern.MatchString(key) {
		return "", "", false
	}
	index := strings.IndexByte(key, '_')
	if index < 1 || index == len(key)-1 {
		return "", "", false
	}
	return key[:index], key[index+1:], true
}

func renderOperationGatusConfig(base []byte, endpoints []operationGatusEndpoint) ([]byte, error) {
	const marker = "external-endpoints:\n"
	text := string(base)
	if len(endpoints) == 0 {
		return nil, errOperationGatusConfiguration
	}
	position := -1
	for offset := 0; offset < len(text); {
		end := strings.IndexByte(text[offset:], '\n')
		if end < 0 {
			break
		}
		lineEnd := offset + end + 1
		if text[offset:lineEnd] == marker {
			if position >= 0 {
				return nil, errOperationGatusConfiguration
			}
			position = offset
		}
		offset = lineEnd
	}
	if position < 0 {
		return nil, errOperationGatusConfiguration
	}
	for _, line := range strings.Split(text[position+len(marker):], "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if len(line) == 0 || line[0] != ' ' {
			return nil, errOperationGatusConfiguration
		}
	}
	var output strings.Builder
	output.Grow(len(base) + len(endpoints)*256)
	output.WriteString(text[:position])
	output.WriteString(marker)
	for _, endpoint := range endpoints {
		if _, _, ok := splitOperationGatusEndpointKey(endpoint.key); !ok || endpoint.name == "" || endpoint.group == "" || endpoint.heartbeat < time.Second || endpoint.heartbeat > 2*365*24*time.Hour {
			return nil, errOperationGatusConfiguration
		}
		fmt.Fprintf(&output, "  - name: %s\n    group: %s\n    token: \"${GATUS_TOKEN}\"\n    heartbeat:\n      interval: %s\n    alerts:\n      - type: custom\n        description: public API observation delivery incident\n        failure-threshold: 2\n        success-threshold: 2\n        send-on-resolved: true\n", endpoint.name, endpoint.group, endpoint.heartbeat.String())
	}
	rendered := []byte(output.String())
	if len(rendered) > maxOperationGatusConfigBytes {
		return nil, errOperationGatusConfiguration
	}
	return rendered, nil
}

func digestOperationGatusBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
