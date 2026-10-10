package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

const (
	OperationObservationPlanSchemaVersion      = "datapan.operation-observation-plan.v1"
	operationObservationPlanSchemaURI          = "https://schemas.datapan.dev/datapan.operation-observation-plan.v1.schema.json"
	operationObservationPlanSchemaSHA256       = "cafa93014d7a32ef072f74df1a730f681e5b206440e4a83e9cdf426f6686e162"
	operationObservationSchemaRegistryRevision = "da02fccaee4989c5c6dcf3b60e8e627ecd477cca"
	maxOperationObservationIndexBytes          = 16 * 1024 * 1024
	maxOperationObservationManifestBytes       = 16 * 1024 * 1024
	maxOperationObservationShardBytes          = 16 * 1024 * 1024
	maxOperationObservationShards              = 4096
	maxOperationObservationOperations          = 100_000
	maxOperationObservationRequestBytes        = 1 << 20
	maxOperationObservationResponseBytes       = 1 << 20
	maxOperationObservationTimeoutMS           = 20_000
)

var (
	errOperationObservationPlanInvalid = errors.New("pinned Registry operation observation plan is invalid")
	operationPlanHostPattern           = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	soapQNameLocalNamePattern          = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]*$`)
)

// OperationObservationPlanBinding pins the exact Registry release manifest
// and full-inventory index copied into this Health release. It is distinct
// from the schema-contract revision: the plan's source revision may advance
// while the schema bytes remain unchanged.
type OperationObservationPlanBinding struct {
	RegistryRevision       string `json:"registry_revision"`
	ReleaseManifestPath    string `json:"release_manifest_path"`
	ReleaseManifestBytes   int64  `json:"release_manifest_bytes"`
	ReleaseManifestSHA256  string `json:"release_manifest_sha256"`
	IndexPath              string `json:"index_path"`
	IndexBytes             int64  `json:"index_bytes"`
	IndexSHA256            string `json:"index_sha256"`
	SchemaRegistryRevision string `json:"schema_registry_revision"`
	SchemaSHA256           string `json:"schema_sha256"`
}

type OperationObservationPlanCounts struct {
	KnownOperations        int `json:"known_operations"`
	RequestPlansComplete   int `json:"request_plans_complete"`
	RequestPlansIncomplete int `json:"request_plans_incomplete"`
	RuntimeBindingsBound   int `json:"runtime_bindings_bound"`
	RuntimeBindingsUnbound int `json:"runtime_bindings_unbound"`
	Admitted               int `json:"admitted"`
	NotAdmitted            int `json:"not_admitted"`
	InventoryUnknownScopes int `json:"inventory_unknown_scopes"`
}

type OperationObservationPlanSourceScope struct {
	SourceID             string                     `json:"source_id"`
	Provider             string                     `json:"provider"`
	AdapterID            string                     `json:"adapter_id"`
	InventoryStatus      string                     `json:"inventory_status"`
	InventoryUnknown     bool                       `json:"inventory_unknown"`
	TestOnly             bool                       `json:"test_only"`
	RegisteredOperations int                        `json:"registered_operations"`
	IdentitySetSHA256    string                     `json:"identity_set_sha256"`
	SourceArtifacts      []operationPlanArtifactRef `json:"source_artifacts"`
}

type operationPlanArtifactRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type operationPlanEvidenceRef struct {
	ArtifactPath string `json:"artifact_path"`
	SHA256       string `json:"sha256"`
	JSONPointer  string `json:"json_pointer"`
	EvidenceKind string `json:"evidence_kind"`
}

type operationObservationPlanShardRef struct {
	SourceID         string `json:"source_id"`
	ShardIndex       int    `json:"shard_index"`
	Path             string `json:"path"`
	SHA256           string `json:"sha256"`
	Bytes            int64  `json:"bytes"`
	RecordCount      int    `json:"record_count"`
	FirstOperationID string `json:"first_operation_id"`
	LastOperationID  string `json:"last_operation_id"`
}

type operationObservationPlanIndex struct {
	SchemaVersion    string                                `json:"schema_version"`
	ArtifactKind     string                                `json:"artifact_kind"`
	RegistryRevision string                                `json:"registry_revision"`
	GenerationInputs json.RawMessage                       `json:"generation_inputs"`
	InventoryContext operationPlanInventoryContext         `json:"inventory_context"`
	Summary          OperationObservationPlanCounts        `json:"summary"`
	SourceScopes     []OperationObservationPlanSourceScope `json:"source_scopes"`
	Shards           []operationObservationPlanShardRef    `json:"shards"`
}

type operationPlanInventoryContext struct {
	SeparateLinkOperations                  int  `json:"separate_link_operations"`
	ProviderIndexAdapterEntries             int  `json:"provider_index_adapter_entries"`
	ProviderIndexEntriesCountedAsOperations bool `json:"provider_index_entries_counted_as_operations"`
}

type operationObservationPlanGenerationInputs struct {
	GeneratorPath         string                     `json:"generator_path"`
	GeneratorSHA256       string                     `json:"generator_sha256"`
	OperationManifest     operationPlanArtifactRef   `json:"operation_manifest"`
	OperationDenominators []operationPlanArtifactRef `json:"operation_denominators"`
	LegacyPolicy          operationPlanArtifactRef   `json:"legacy_policy"`
	ProviderIndex         *operationPlanArtifactRef  `json:"provider_index,omitempty"`
	DocumentEvidence      []operationPlanArtifactRef `json:"document_evidence,omitempty"`
}

type operationPlanIndexState struct {
	index                operationObservationPlanIndex
	root                 string
	manifest             map[string]RegistryReleaseManifestArtifact
	byScope              map[string]OperationObservationPlanSourceScope
	verified             bool
	executableOperations int
}

// PinnedOperationObservationPlan is a small index and immutable shard list;
// operation records are loaded one bounded shard at a time with ReadShard.
type PinnedOperationObservationPlan struct {
	binding OperationObservationPlanBinding
	state   *operationPlanIndexState
}

// OperationObservationPlanRecord exposes only identity and admission fields.
// Request details, transport values, credential references, and evidence text
// stay inside the verified Registry shard and never enter public projections.
type OperationObservationPlanRecord struct {
	OperationID           string
	Protocol              string
	ResponseAssertionKind string
	DatasetID             string
	OperationName         string
	UpstreamOperationKey  string
	LegacySelectors       []string
	SourceID              string
	Provider              string
	AdapterID             string
	InventoryStatus       string
	InventoryUnknown      bool
	TestOnly              bool
	RequestPlanStatus     string
	RequestPlanMissing    []string
	RuntimeBindingStatus  string
	RuntimeBindingMissing []string
	AdmissionStatus       string
	AdmissionReasons      []string
	ObservationPeriod     time.Duration
	RequestTimeout        time.Duration
	QuotaPolicies         []OperationQuotaPolicy
	QuotaPoliciesAdmitted bool
	ExecutionEligible     bool
	ExecutionBlockReason  string
	quotaBindings         []operationQuotaPolicyBinding
}

type operationPlanRecordWire struct {
	SchemaVersion     string          `json:"schema_version"`
	ArtifactKind      string          `json:"artifact_kind"`
	SourceBinding     json.RawMessage `json:"source_binding"`
	OperationIdentity json.RawMessage `json:"operation_identity"`
	RequestPlan       json.RawMessage `json:"request_plan"`
	RuntimeBinding    json.RawMessage `json:"runtime_binding"`
	Admission         json.RawMessage `json:"admission"`
	LegacyPolicy      json.RawMessage `json:"legacy_policy,omitempty"`
}

type operationPlanSourceBindingWire struct {
	SourceID         string `json:"source_id"`
	Provider         string `json:"provider"`
	AdapterID        string `json:"adapter_id"`
	InventoryStatus  string `json:"inventory_status"`
	InventoryUnknown bool   `json:"inventory_unknown"`
	TestOnly         bool   `json:"test_only"`
}

type operationPlanIdentityWire struct {
	OperationID          string   `json:"operation_id"`
	Protocol             string   `json:"protocol"`
	DatasetID            string   `json:"dataset_id,omitempty"`
	OperationName        string   `json:"operation_name,omitempty"`
	UpstreamOperationKey string   `json:"upstream_operation_key,omitempty"`
	LegacySelectors      []string `json:"legacy_selectors,omitempty"`
}

type operationPlanRequestWire struct {
	Status          string          `json:"status"`
	MissingFields   []string        `json:"missing_fields,omitempty"`
	RequestContract json.RawMessage `json:"request_contract,omitempty"`
}

type operationPlanRuntimeWire struct {
	Status                   string                         `json:"status"`
	MissingFields            []string                       `json:"missing_fields,omitempty"`
	CredentialReference      string                         `json:"credential_reference,omitempty"`
	CredentialScopeKey       string                         `json:"credential_scope_key,omitempty"`
	ObservationPeriodSeconds int64                          `json:"observation_period_seconds,omitempty"`
	QuotaPolicies            []operationPlanQuotaPolicyWire `json:"quota_policies,omitempty"`
}

type operationPlanQuotaPolicyWire struct {
	ScopeKind              string                     `json:"scope_kind"`
	ScopeKey               string                     `json:"scope_key"`
	ScopeSHA256            string                     `json:"scope_sha256"`
	MaxConcurrent          int                        `json:"max_concurrent"`
	RequestsPerWindow      int                        `json:"requests_per_window"`
	WindowSeconds          int64                      `json:"window_seconds"`
	MinimumIntervalSeconds int64                      `json:"minimum_interval_seconds"`
	EvidenceRefs           []operationPlanEvidenceRef `json:"evidence_refs"`
}

type operationPlanAdmissionWire struct {
	Status  string   `json:"status"`
	Reasons []string `json:"reasons"`
}

type operationObservationPlanShardWire struct {
	SchemaVersion string            `json:"schema_version"`
	ArtifactKind  string            `json:"artifact_kind"`
	SourceID      string            `json:"source_id"`
	ShardIndex    int               `json:"shard_index"`
	Records       []json.RawMessage `json:"records"`
}

// LoadPinnedOperationObservationPlan verifies the release-manifest → index →
// shard chain, all source-scoped identity sets, derived counts, quota bucket
// consistency, and the exact schema pin. It holds at most one <=16 MiB shard
// at a time and does not read the 139 MiB canonical source snapshot.
func LoadPinnedOperationObservationPlan(root string, binding OperationObservationPlanBinding) (PinnedOperationObservationPlan, error) {
	if !validOperationObservationPlanBinding(binding) || schemas.OperationObservationPlanV1SchemaSHA256() != binding.SchemaSHA256 {
		return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
	}
	rootInfo, err := os.Lstat(rootAbs)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
	}
	manifestRaw, err := readPlanArtifact(rootAbs, binding.ReleaseManifestPath, binding.ReleaseManifestBytes, maxOperationObservationManifestBytes)
	if err != nil || digest(manifestRaw) != binding.ReleaseManifestSHA256 {
		return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
	}
	var release RegistryReleaseManifest
	if json.Unmarshal(manifestRaw, &release) != nil || release.SchemaVersion != "datapan.release-manifest.v1" || len(release.Artifacts) == 0 {
		return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
	}
	manifestArtifacts := make(map[string]RegistryReleaseManifestArtifact, len(release.Artifacts))
	for _, artifact := range release.Artifacts {
		if !safePlanRelativePath(artifact.Path) || artifact.Bytes <= 0 || !sha256Pattern.MatchString(artifact.SHA256) || artifact.Kind == "" {
			return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
		}
		if _, exists := manifestArtifacts[artifact.Path]; exists {
			return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
		}
		manifestArtifacts[artifact.Path] = artifact
	}
	if !releaseManifestBindsPlanArtifact(manifestArtifacts, binding.IndexPath, binding.IndexBytes, binding.IndexSHA256, "operation_observation_plan") {
		return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
	}
	indexRaw, err := readPlanArtifact(rootAbs, binding.IndexPath, binding.IndexBytes, maxOperationObservationIndexBytes)
	if err != nil || digest(indexRaw) != binding.IndexSHA256 || schemas.ValidateOperationObservationPlanV1(indexRaw) != nil {
		return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
	}
	var index operationObservationPlanIndex
	decoder := json.NewDecoder(bytes.NewReader(indexRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&index) != nil || ensureEOF(decoder) != nil || index.SchemaVersion != OperationObservationPlanSchemaVersion || index.ArtifactKind != "index" || index.RegistryRevision != binding.RegistryRevision || len(index.Shards) == 0 || len(index.Shards) > maxOperationObservationShards || index.Summary.KnownOperations < 1 || index.Summary.KnownOperations > maxOperationObservationOperations {
		return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
	}
	var generationInputs operationObservationPlanGenerationInputs
	if json.Unmarshal(index.GenerationInputs, &generationInputs) != nil || !validOperationPlanGenerationInputs(generationInputs, manifestArtifacts) {
		return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
	}
	state := &operationPlanIndexState{index: index, root: rootAbs, manifest: manifestArtifacts, byScope: make(map[string]OperationObservationPlanSourceScope, len(index.SourceScopes))}
	if len(index.SourceScopes) == 0 {
		return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
	}
	for i, scope := range index.SourceScopes {
		if scope.SourceID == "" || scope.Provider == "" || scope.AdapterID == "" || scope.RegisteredOperations < 1 || !sha256Pattern.MatchString(scope.IdentitySetSHA256) || len(scope.SourceArtifacts) == 0 || (i > 0 && index.SourceScopes[i-1].SourceID >= scope.SourceID) {
			return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
		}
		if _, duplicate := state.byScope[scope.SourceID]; duplicate {
			return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
		}
		for _, artifact := range scope.SourceArtifacts {
			if !releaseManifestBinds(manifestArtifacts, artifact.Path, artifact.Bytes, artifact.SHA256) {
				return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
			}
		}
		state.byScope[scope.SourceID] = scope
	}
	if err := state.verifyAllShards(); err != nil {
		return PinnedOperationObservationPlan{}, errOperationObservationPlanInvalid
	}
	state.verified = true
	return PinnedOperationObservationPlan{binding: binding, state: state}, nil
}

func validOperationObservationPlanBinding(binding OperationObservationPlanBinding) bool {
	return commitPattern.MatchString(binding.RegistryRevision) && safePlanRelativePath(binding.ReleaseManifestPath) && binding.ReleaseManifestBytes > 0 && binding.ReleaseManifestBytes <= maxOperationObservationManifestBytes && sha256Pattern.MatchString(binding.ReleaseManifestSHA256) && safePlanRelativePath(binding.IndexPath) && binding.IndexBytes > 0 && binding.IndexBytes <= maxOperationObservationIndexBytes && sha256Pattern.MatchString(binding.IndexSHA256) && binding.SchemaRegistryRevision == operationObservationSchemaRegistryRevision && binding.SchemaSHA256 == operationObservationPlanSchemaSHA256
}

func validOperationPlanGenerationInputs(input operationObservationPlanGenerationInputs, manifest map[string]RegistryReleaseManifestArtifact) bool {
	generator, generatorBound := manifest[input.GeneratorPath]
	if !safePlanRelativePath(input.GeneratorPath) || !sha256Pattern.MatchString(input.GeneratorSHA256) || !generatorBound || generator.SHA256 != input.GeneratorSHA256 || !releaseManifestBinds(manifest, input.OperationManifest.Path, input.OperationManifest.Bytes, input.OperationManifest.SHA256) || !releaseManifestBinds(manifest, input.LegacyPolicy.Path, input.LegacyPolicy.Bytes, input.LegacyPolicy.SHA256) || len(input.OperationDenominators) < 1 {
		return false
	}
	for _, artifact := range input.OperationDenominators {
		if !releaseManifestBinds(manifest, artifact.Path, artifact.Bytes, artifact.SHA256) {
			return false
		}
	}
	if input.ProviderIndex != nil && !releaseManifestBinds(manifest, input.ProviderIndex.Path, input.ProviderIndex.Bytes, input.ProviderIndex.SHA256) {
		return false
	}
	for _, artifact := range input.DocumentEvidence {
		if !releaseManifestBinds(manifest, artifact.Path, artifact.Bytes, artifact.SHA256) {
			return false
		}
	}
	return true
}

func releaseManifestBinds(manifest map[string]RegistryReleaseManifestArtifact, path string, size int64, sha string) bool {
	artifact, ok := manifest[path]
	return ok && artifact.Path == path && artifact.Bytes == size && artifact.SHA256 == sha
}

func releaseManifestBindsPlanArtifact(manifest map[string]RegistryReleaseManifestArtifact, path string, size int64, sha, kind string) bool {
	artifact, ok := manifest[path]
	return ok && artifact.Path == path && artifact.Bytes == size && artifact.SHA256 == sha && artifact.Schema == operationObservationPlanSchemaURI && artifact.Kind == kind
}

func (state *operationPlanIndexState) verifyAllShards() error {
	if state == nil || len(state.index.Shards) == 0 {
		return errOperationObservationPlanInvalid
	}
	counts := OperationObservationPlanCounts{}
	counts.KnownOperations = 0
	ids := make(map[string]*operationIdentitySetHash, len(state.byScope))
	for sourceID := range state.byScope {
		ids[sourceID] = newOperationIdentitySetHash()
	}
	quotaPolicies := map[string]operationQuotaPolicyBinding{}
	seenOperationIDs := make(map[string]string, state.index.Summary.KnownOperations)
	lastSource, lastIndex := "", -1
	usedPaths := map[string]bool{}
	for _, shardRef := range state.index.Shards {
		if shardRef.SourceID == "" || shardRef.ShardIndex < 0 || shardRef.RecordCount < 1 || shardRef.RecordCount > 256 || shardRef.Bytes < 1 || shardRef.Bytes > maxOperationObservationShardBytes || !sha256Pattern.MatchString(shardRef.SHA256) || shardRef.FirstOperationID == "" || shardRef.LastOperationID == "" || !safePlanRelativePath(shardRef.Path) || usedPaths[shardRef.Path] {
			return errOperationObservationPlanInvalid
		}
		if _, ok := state.byScope[shardRef.SourceID]; !ok || !releaseManifestBindsPlanArtifact(state.manifest, shardRef.Path, shardRef.Bytes, shardRef.SHA256, "operation_observation_plan_shard") {
			return errOperationObservationPlanInvalid
		}
		if shardRef.SourceID != lastSource {
			if lastSource != "" && shardRef.SourceID <= lastSource || shardRef.ShardIndex != 0 {
				return errOperationObservationPlanInvalid
			}
			lastSource, lastIndex = shardRef.SourceID, 0
		} else {
			if shardRef.ShardIndex != lastIndex+1 {
				return errOperationObservationPlanInvalid
			}
			lastIndex = shardRef.ShardIndex
		}
		usedPaths[shardRef.Path] = true
		shard, err := state.readShard(shardRef)
		if err != nil || shard.SourceID != shardRef.SourceID || shard.ShardIndex != shardRef.ShardIndex || len(shard.Records) != shardRef.RecordCount {
			return errOperationObservationPlanInvalid
		}
		setHash := ids[shardRef.SourceID]
		if len(shard.Records) == 0 {
			return errOperationObservationPlanInvalid
		}
		firstID, lastID := "", ""
		for _, rawRecord := range shard.Records {
			record, err := decodeOperationObservationPlanRecord(rawRecord)
			scope, scopeExists := state.byScope[shardRef.SourceID]
			if err != nil || !scopeExists || record.SourceID != shardRef.SourceID || record.Provider != scope.Provider || record.AdapterID != scope.AdapterID || record.InventoryStatus != scope.InventoryStatus || record.InventoryUnknown != scope.InventoryUnknown || record.TestOnly != scope.TestOnly || !allOperationPlanEvidenceBound(rawRecord, state.manifest) {
				return errOperationObservationPlanInvalid
			}
			if previousSource, duplicate := seenOperationIDs[record.OperationID]; duplicate && previousSource != record.SourceID {
				return errOperationObservationPlanInvalid
			}
			seenOperationIDs[record.OperationID] = record.SourceID
			if lastID != "" && record.OperationID <= lastID {
				return errOperationObservationPlanInvalid
			}
			if firstID == "" {
				firstID = record.OperationID
			}
			lastID = record.OperationID
			setHash.add(record.OperationID)
			counts.KnownOperations++
			if counts.KnownOperations > maxOperationObservationOperations {
				return errOperationObservationPlanInvalid
			}
			switch record.RequestPlanStatus {
			case "complete":
				counts.RequestPlansComplete++
			case "incomplete":
				counts.RequestPlansIncomplete++
			default:
				return errOperationObservationPlanInvalid
			}
			switch record.RuntimeBindingStatus {
			case "bound":
				counts.RuntimeBindingsBound++
			case "unbound":
				counts.RuntimeBindingsUnbound++
			default:
				return errOperationObservationPlanInvalid
			}
			switch record.AdmissionStatus {
			case "admitted":
				counts.Admitted++
			case "not_admitted":
				counts.NotAdmitted++
			default:
				return errOperationObservationPlanInvalid
			}
			if record.AdmissionStatus == "admitted" && (record.RequestPlanStatus != "complete" || record.RuntimeBindingStatus != "bound") {
				return errOperationObservationPlanInvalid
			}
			if record.ExecutionEligible {
				state.executableOperations++
			}
			if record.InventoryUnknown {
				// Count unknown inventory scopes once below from the index.
			}
			if err := record.checkQuotaPolicies(quotaPolicies); err != nil {
				return err
			}
		}
		if firstID != shardRef.FirstOperationID || lastID != shardRef.LastOperationID {
			return errOperationObservationPlanInvalid
		}
	}
	for sourceID, scope := range state.byScope {
		identityHash := ids[sourceID]
		if identityHash == nil || identityHash.count != scope.RegisteredOperations || identityHash.digest() != scope.IdentitySetSHA256 {
			return errOperationObservationPlanInvalid
		}
		counts.InventoryUnknownScopes += boolToInt(scope.InventoryUnknown)
	}
	if counts != state.index.Summary {
		return errOperationObservationPlanInvalid
	}
	return nil
}

// ReadShard reopens one exact immutable shard only after the complete plan
// chain was verified. It repeats the byte digest and schema checks at use time.
func (plan PinnedOperationObservationPlan) ReadShard(index int) ([]OperationObservationPlanRecord, error) {
	if plan.state == nil || !plan.state.verified || index < 0 || index >= len(plan.state.index.Shards) {
		return nil, errOperationObservationPlanInvalid
	}
	shard, err := plan.state.readShard(plan.state.index.Shards[index])
	if err != nil {
		return nil, errOperationObservationPlanInvalid
	}
	result := make([]OperationObservationPlanRecord, 0, len(shard.Records))
	for _, rawRecord := range shard.Records {
		record, err := decodeOperationObservationPlanRecord(rawRecord)
		if err != nil || record.SourceID != shard.SourceID {
			return nil, errOperationObservationPlanInvalid
		}
		result = append(result, record)
	}
	return result, nil
}

func (state *operationPlanIndexState) readShard(ref operationObservationPlanShardRef) (operationObservationPlanShardWire, error) {
	var shard operationObservationPlanShardWire
	raw, err := readPlanArtifact(state.root, ref.Path, ref.Bytes, maxOperationObservationShardBytes)
	if err != nil || digest(raw) != ref.SHA256 || schemas.ValidateOperationObservationPlanV1(raw) != nil {
		return shard, errOperationObservationPlanInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&shard) != nil || ensureEOF(decoder) != nil || shard.SchemaVersion != OperationObservationPlanSchemaVersion || shard.ArtifactKind != "shard" || len(shard.Records) == 0 || len(shard.Records) > 256 {
		return operationObservationPlanShardWire{}, errOperationObservationPlanInvalid
	}
	return shard, nil
}

func decodeOperationObservationPlanRecord(raw json.RawMessage) (OperationObservationPlanRecord, error) {
	if len(raw) == 0 || schemas.ValidateOperationObservationPlanV1(raw) != nil {
		return OperationObservationPlanRecord{}, errOperationObservationPlanInvalid
	}
	var wire operationPlanRecordWire
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || ensureEOF(decoder) != nil || wire.SchemaVersion != OperationObservationPlanSchemaVersion || wire.ArtifactKind != "operation_plan" {
		return OperationObservationPlanRecord{}, errOperationObservationPlanInvalid
	}
	var source operationPlanSourceBindingWire
	var identity operationPlanIdentityWire
	var request operationPlanRequestWire
	var runtime operationPlanRuntimeWire
	var admission operationPlanAdmissionWire
	if json.Unmarshal(wire.SourceBinding, &source) != nil || json.Unmarshal(wire.OperationIdentity, &identity) != nil || json.Unmarshal(wire.RequestPlan, &request) != nil || json.Unmarshal(wire.RuntimeBinding, &runtime) != nil || json.Unmarshal(wire.Admission, &admission) != nil || identity.OperationID == "" || source.SourceID == "" {
		return OperationObservationPlanRecord{}, errOperationObservationPlanInvalid
	}
	if admission.Status == "admitted" && (request.Status != "complete" || runtime.Status != "bound") {
		return OperationObservationPlanRecord{}, errOperationObservationPlanInvalid
	}
	record := OperationObservationPlanRecord{
		OperationID: identity.OperationID, Protocol: identity.Protocol, DatasetID: identity.DatasetID,
		OperationName: identity.OperationName, UpstreamOperationKey: identity.UpstreamOperationKey,
		LegacySelectors: append([]string(nil), identity.LegacySelectors...), SourceID: source.SourceID,
		Provider: source.Provider, AdapterID: source.AdapterID, InventoryStatus: source.InventoryStatus,
		InventoryUnknown: source.InventoryUnknown, TestOnly: source.TestOnly,
		RequestPlanStatus: request.Status, RequestPlanMissing: append([]string(nil), request.MissingFields...),
		RuntimeBindingStatus: runtime.Status, RuntimeBindingMissing: append([]string(nil), runtime.MissingFields...),
		AdmissionStatus: admission.Status, AdmissionReasons: append([]string(nil), admission.Reasons...),
	}
	if len(request.RequestContract) > 0 {
		var contract struct {
			Limits struct {
				TimeoutMS int64 `json:"timeout_ms"`
			} `json:"limits"`
			ResponseAssertion struct {
				Kind string `json:"kind"`
			} `json:"response_assertion"`
		}
		if json.Unmarshal(request.RequestContract, &contract) != nil || contract.Limits.TimeoutMS < 1 || contract.Limits.TimeoutMS > maxOperationObservationTimeoutMS {
			return OperationObservationPlanRecord{}, errOperationObservationPlanInvalid
		}
		record.RequestTimeout = time.Duration(contract.Limits.TimeoutMS) * time.Millisecond
		record.ResponseAssertionKind = contract.ResponseAssertion.Kind
	}
	if runtime.ObservationPeriodSeconds > 0 {
		if runtime.ObservationPeriodSeconds > int64((365*24*time.Hour)/time.Second) {
			return OperationObservationPlanRecord{}, errOperationObservationPlanInvalid
		}
		record.ObservationPeriod = time.Duration(runtime.ObservationPeriodSeconds) * time.Second
	}
	for _, quota := range runtime.QuotaPolicies {
		if !quotaScopeKindPattern.MatchString(quota.ScopeKind) || strings.TrimSpace(quota.ScopeKey) == "" || OperationQuotaScopeDigest(quota.ScopeKind, quota.ScopeKey) != quota.ScopeSHA256 {
			return OperationObservationPlanRecord{}, errOperationObservationPlanInvalid
		}
		policy := OperationQuotaPolicy{
			ScopeSHA256:       quota.ScopeSHA256,
			MaxConcurrent:     quota.MaxConcurrent,
			RequestsPerWindow: quota.RequestsPerWindow,
			Window:            time.Duration(quota.WindowSeconds) * time.Second,
			MinimumInterval:   time.Duration(quota.MinimumIntervalSeconds) * time.Second,
		}
		if !validOperationQuotaPolicy(policy) || len(quota.EvidenceRefs) == 0 {
			return OperationObservationPlanRecord{}, errOperationObservationPlanInvalid
		}
		for _, ref := range quota.EvidenceRefs {
			if strings.TrimSpace(ref.ArtifactPath) == "" || !sha256Pattern.MatchString(ref.SHA256) || !quotaEvidencePointerPattern.MatchString(ref.JSONPointer) || !validOperationQuotaEvidenceKind(ref.EvidenceKind) {
				return OperationObservationPlanRecord{}, errOperationObservationPlanInvalid
			}
		}
		record.quotaBindings = append(record.quotaBindings, operationQuotaPolicyBinding{Kind: quota.ScopeKind, Key: quota.ScopeKey, Policy: policy})
		if record.AdmissionStatus == "admitted" {
			policy, err := OperationQuotaPolicyFromEvidence(request.Status, runtime.Status, admission.Status,
				quota.ScopeKind, quota.ScopeKey, quota.ScopeSHA256, quota.MaxConcurrent, quota.RequestsPerWindow,
				quota.WindowSeconds, quota.MinimumIntervalSeconds, toQuotaEvidenceRefs(quota.EvidenceRefs))
			if err != nil {
				return OperationObservationPlanRecord{}, errOperationObservationPlanInvalid
			}
			record.QuotaPolicies = append(record.QuotaPolicies, policy)
		}
	}
	if record.AdmissionStatus == "admitted" {
		record.QuotaPoliciesAdmitted = true
	}
	record.ExecutionEligible, record.ExecutionBlockReason = operationPlanExecutionDecision(raw, record)
	return record, nil
}

func operationPlanExecutionDecision(raw json.RawMessage, record OperationObservationPlanRecord) (bool, string) {
	if record.RequestPlanStatus != "complete" {
		return false, "request_plan_incomplete"
	}
	if record.RuntimeBindingStatus != "bound" {
		return false, "runtime_binding_unbound"
	}
	if record.AdmissionStatus != "admitted" || !record.QuotaPoliciesAdmitted || len(record.QuotaPolicies) == 0 {
		return false, "admission_not_granted"
	}
	if record.TestOnly || operationPlanHasSyntheticEvidence(raw) || record.Provider == "synthetic-test-provider" || strings.HasPrefix(record.SourceID, "synthetic") {
		return false, "synthetic_evidence"
	}
	var root map[string]any
	if json.Unmarshal(raw, &root) != nil {
		return false, "request_contract_invalid"
	}
	identity, ok := root["operation_identity"].(map[string]any)
	if !ok {
		return false, "request_contract_invalid"
	}
	request, ok := root["request_plan"].(map[string]any)
	if !ok {
		return false, "request_contract_invalid"
	}
	contract, ok := request["request_contract"].(map[string]any)
	if !ok {
		return false, "request_contract_invalid"
	}
	effect, ok := contract["operation_effect"].(map[string]any)
	if !ok || effect["classification"] != "read_only" || !supportedContractAuthority(effect["authority"]) {
		return false, "read_only_effect_unproven"
	}
	transport, ok := contract["transport"].(map[string]any)
	if !ok || !supportedContractAuthority(transport["authority"]) {
		return false, "transport_unsupported"
	}
	protocol := stringValue(identity["protocol"])
	if protocol != "REST" && protocol != "SOAP" || stringValue(transport["protocol"]) != protocol {
		return false, "protocol_unsupported"
	}
	if stringValue(transport["scheme"]) != "https" || !safeOperationHost(stringValue(transport["host"])) || !safeOperationPath(stringValue(transport["path"])) {
		return false, "transport_unsupported"
	}
	method := stringValue(transport["http_method"])
	if protocol == "REST" && method != "GET" || protocol == "SOAP" && method != "POST" {
		return false, "transport_method_unsupported"
	}
	if protocol == "SOAP" && !validSOAPOperationTransport(transport) {
		return false, "soap_contract_unsupported"
	}
	if endpoint, ok := identity["registered_endpoint"].(map[string]any); ok {
		if stringValue(endpoint["host"]) != stringValue(transport["host"]) || stringValue(endpoint["path"]) != stringValue(transport["path"]) {
			return false, "registered_endpoint_mismatch"
		}
	}
	if !validOperationRequestLimits(contract["limits"]) || !validOperationResponseAssertion(protocol, contract["response_assertion"]) {
		return false, "request_limits_or_assertion_unsupported"
	}
	parameters, ok := contract["parameters"].([]any)
	if !ok || !validOperationParameters(protocol, parameters) {
		return false, "request_parameter_unsupported"
	}
	if !validOperationAuthentication(protocol, contract["authentication"], root["runtime_binding"], parameters) {
		return false, "credential_binding_unsupported"
	}
	return true, ""
}

func operationPlanHasSyntheticEvidence(raw json.RawMessage) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return true
	}
	var visit func(any) bool
	visit = func(node any) bool {
		switch typed := node.(type) {
		case map[string]any:
			if typed["evidence_kind"] == "synthetic_fixture" || typed["authority"] == "synthetic_fixture" {
				return true
			}
			for _, child := range typed {
				if visit(child) {
					return true
				}
			}
		case []any:
			for _, child := range typed {
				if visit(child) {
					return true
				}
			}
		}
		return false
	}
	return visit(value)
}

func supportedContractAuthority(value any) bool {
	switch stringValue(value) {
	case "operation_document", "operation_specific_declaration", "reviewed_policy":
		return true
	default:
		return false
	}
}

func safeOperationHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.ContainsAny(host, ":/@?#\\% \t\r\n") || strings.ToLower(host) != host {
		return false
	}
	return operationPlanHostPattern.MatchString(host) || net.ParseIP(host) != nil
}

func safeOperationPath(path string) bool {
	if len(path) == 0 || len(path) > 2048 || path[0] != '/' || strings.ContainsAny(path, "?#\\\x00\r\n") || strings.Contains(path, "//") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validSOAPOperationTransport(transport map[string]any) bool {
	version := stringValue(transport["soap_version"])
	envelope := stringValue(transport["envelope_namespace"])
	if version == "1.1" && envelope != "http://schemas.xmlsoap.org/soap/envelope/" || version == "1.2" && envelope != "http://www.w3.org/2003/05/soap-envelope" || version != "1.1" && version != "1.2" {
		return false
	}
	soapAction := stringValue(transport["soap_action"])
	if soapAction == "" || len(soapAction) > 2048 || strings.ContainsAny(soapAction, "\x00\r\n") {
		return false
	}
	switch stringValue(transport["body_encoding"]) {
	case "document_literal", "rpc_literal", "encoded_xml":
	default:
		return false
	}
	qname, ok := transport["operation_qname"].(map[string]any)
	namespace := stringValue(qname["namespace"])
	parsedNamespace, parseErr := url.Parse(namespace)
	if !ok || namespace == "" || parseErr != nil || parsedNamespace.Scheme == "" || strings.ContainsAny(namespace, "\x00\r\n \t") {
		return false
	}
	local := stringValue(qname["local_name"])
	return len(local) <= 128 && soapQNameLocalNamePattern.MatchString(local)
}

func validOperationRequestLimits(value any) bool {
	limits, ok := value.(map[string]any)
	if !ok {
		return false
	}
	return integerValue(limits["request_budget"]) == 1 && integerValue(limits["timeout_ms"]) >= 1 && integerValue(limits["timeout_ms"]) <= maxOperationObservationTimeoutMS && integerValue(limits["max_request_bytes"]) >= 1 && integerValue(limits["max_request_bytes"]) <= maxOperationObservationRequestBytes && integerValue(limits["max_response_bytes"]) >= 1 && integerValue(limits["max_response_bytes"]) <= maxOperationObservationResponseBytes
}

func validOperationResponseAssertion(protocol string, value any) bool {
	assertion, ok := value.(map[string]any)
	if !ok || len(anySlice(assertion["evidence_refs"])) == 0 {
		return false
	}
	kind := stringValue(assertion["kind"])
	if protocol == "REST" {
		return kind == "http_status" || kind == "json_contract" || kind == "observation_only"
	}
	return protocol == "SOAP" && (kind == "soap_fault_free" || kind == "xml_contract" || kind == "http_status" || kind == "observation_only")
}

func validOperationParameters(protocol string, parameters []any) bool {
	seen := map[string]bool{}
	for _, item := range parameters {
		parameter, ok := item.(map[string]any)
		if !ok || stringValue(parameter["name"]) == "" || stringValue(parameter["location"]) == "" || len(anySlice(parameter["evidence_refs"])) == 0 {
			return false
		}
		location := stringValue(parameter["location"])
		if location != "query" && location != "path" && location != "header" && location != "body" && location != "soap_header" {
			return false
		}
		if protocol == "REST" && (location == "body" || location == "soap_header") || protocol == "SOAP" && (location == "query" || location == "path") {
			return false
		}
		if location == "body" || location == "soap_header" {
			qualifiedName, ok := parameter["qualified_name"].(map[string]any)
			if !ok || !validOperationQName(qualifiedName) {
				return false
			}
		}
		cardinality := stringValue(parameter["cardinality"])
		if cardinality != "required_single" && cardinality != "optional_single" && cardinality != "required_repeated" && cardinality != "optional_repeated" {
			return false
		}
		identity := location + "\x00" + stringValue(parameter["name"])
		if location == "soap_header" || location == "body" {
			encoded, _ := json.Marshal(parameter["qualified_name"])
			identity += "\x00" + string(encoded)
		}
		if seen[identity] {
			return false
		}
		seen[identity] = true
		if !validOperationValueStrategy(parameter["value_strategy"]) {
			return false
		}
	}
	return true
}

func validOperationQName(qname map[string]any) bool {
	namespace := stringValue(qname["namespace"])
	parsedNamespace, err := url.Parse(namespace)
	local := stringValue(qname["local_name"])
	return err == nil && parsedNamespace.Scheme != "" && namespace != "" && !strings.ContainsAny(namespace, "\x00\r\n \t") && soapQNameLocalNamePattern.MatchString(local)
}

func validOperationValueStrategy(value any) bool {
	strategy, ok := value.(map[string]any)
	if !ok || !supportedContractAuthority(strategy["authority"]) && stringValue(strategy["authority"]) != "runtime_binding" {
		return false
	}
	switch stringValue(strategy["kind"]) {
	case "bounded_integer":
		minimum, maximum := integerValue(strategy["minimum"]), integerValue(strategy["maximum"])
		selection := stringValue(strategy["selection"])
		if minimum > maximum || selection != "minimum" && selection != "maximum" && selection != "fixed" {
			return false
		}
		selected, hasSelected := strategy["selected_value"]
		if selection == "fixed" {
			return hasSelected && integerValue(selected) >= minimum && integerValue(selected) <= maximum
		}
		return !hasSelected
	case "relative_year":
		return integerValue(strategy["minimum_year"]) <= integerValue(strategy["maximum_year"]) && integerValue(strategy["offset_years"]) >= -50 && integerValue(strategy["offset_years"]) <= 50 && stringValue(strategy["anchor"]) == "observation_calendar_year"
	case "reviewed_enum", "reviewed_literal", "opaque_reviewed_value":
		if selected, exists := strategy["selected_value"]; exists {
			switch literal := selected.(type) {
			case string:
				return literal != "" && len(literal) <= 1024
			case bool, float64:
				return true
			default:
				return false
			}
		}
		return sha256Pattern.MatchString(stringValue(strategy["value_sha256"])) && validOperationEvidenceReference(strategy["value_ref"])
	case "credential_reference":
		return stringValue(strategy["authority"]) == "runtime_binding" && stringValue(strategy["binding_field"]) == "credential_reference"
	default:
		return false
	}
}

func validOperationEvidenceReference(value any) bool {
	ref, ok := value.(map[string]any)
	if !ok || !safePlanRelativePath(stringValue(ref["artifact_path"])) || !sha256Pattern.MatchString(stringValue(ref["sha256"])) || !strings.HasPrefix(stringValue(ref["json_pointer"]), "#") {
		return false
	}
	switch stringValue(ref["evidence_kind"]) {
	case "operation_document", "operation_manifest", "source_profile", "reviewed_policy", "runtime_binding":
		return true
	default:
		return false
	}
}

func validOperationAuthentication(protocol string, authenticationValue, runtimeValue any, parameters []any) bool {
	auth, ok := authenticationValue.(map[string]any)
	runtime, runtimeOK := runtimeValue.(map[string]any)
	if !ok || !runtimeOK || len(anySlice(auth["evidence_refs"])) == 0 {
		return false
	}
	credentialParameters := 0
	for _, item := range parameters {
		parameter, ok := item.(map[string]any)
		if !ok {
			return false
		}
		strategy, _ := parameter["value_strategy"].(map[string]any)
		if stringValue(strategy["kind"]) == "credential_reference" {
			credentialParameters++
		}
	}
	requirement := stringValue(auth["requirement"])
	if requirement == "none" {
		if stringValue(auth["mechanism"]) != "none" || stringValue(auth["placement"]) != "none" || auth["credential_reference_required"] != false || stringValue(runtime["credential_reference"]) != "" || stringValue(runtime["credential_scope_key"]) != "" || credentialParameters != 0 {
			return false
		}
		for _, item := range anySlice(runtime["quota_policies"]) {
			quota, ok := item.(map[string]any)
			if ok && stringValue(quota["scope_kind"]) == "credential" {
				return false
			}
		}
		return true
	}
	if requirement != "required" || auth["credential_reference_required"] != true || stringValue(runtime["credential_reference"]) == "" || stringValue(runtime["credential_scope_key"]) == "" || credentialParameters != 1 || len(anySlice(auth["evidence_refs"])) == 0 {
		return false
	}
	mechanism := stringValue(auth["mechanism"])
	if mechanism != "service_key" && mechanism != "api_key" {
		return false
	}
	placement := stringValue(auth["placement"])
	field, location, qname := "", placement, auth["header_qname"]
	switch placement {
	case "query":
		field = stringValue(auth["parameter_name"])
	case "header":
		field = stringValue(auth["header_name"])
	case "soap_header":
		if protocol != "SOAP" {
			return false
		}
		qualifiedName, ok := qname.(map[string]any)
		if !ok || !validOperationQName(qualifiedName) {
			return false
		}
	default:
		return false
	}
	cardinality := stringValue(auth["cardinality"])
	matches := 0
	for _, item := range parameters {
		parameter, _ := item.(map[string]any)
		strategy, _ := parameter["value_strategy"].(map[string]any)
		if stringValue(strategy["kind"]) != "credential_reference" || stringValue(parameter["location"]) != location || stringValue(parameter["cardinality"]) != cardinality || stringValue(strategy["authority"]) != "runtime_binding" || stringValue(strategy["binding_field"]) != "credential_reference" {
			continue
		}
		if placement == "soap_header" {
			if equalJSON(parameter["qualified_name"], qname) {
				matches++
			}
		} else if stringValue(parameter["name"]) == field {
			matches++
		}
	}
	credentialScope := stringValue(runtime["credential_scope_key"])
	credentialQuotas := 0
	for _, item := range anySlice(runtime["quota_policies"]) {
		quota, ok := item.(map[string]any)
		if ok && stringValue(quota["scope_kind"]) == "credential" && stringValue(quota["scope_key"]) == credentialScope {
			credentialQuotas++
		}
	}
	return matches == 1 && credentialQuotas == 1
}

func equalJSON(left, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func integerValue(value any) int64 {
	number, ok := value.(float64)
	if !ok || number > 9_223_372_036_854_775_807 || number < -9_223_372_036_854_775_808 || number != float64(int64(number)) {
		return 0
	}
	return int64(number)
}

func anySlice(value any) []any {
	result, _ := value.([]any)
	return result
}

func (record OperationObservationPlanRecord) checkQuotaPolicies(bindings map[string]operationQuotaPolicyBinding) error {
	if record.RuntimeBindingStatus != "bound" {
		return nil
	}
	for _, current := range record.quotaBindings {
		key := current.Policy.ScopeSHA256
		if previous, exists := bindings[key]; exists && (previous.Kind != current.Kind || previous.Key != current.Key || operationQuotaPolicyDigest(previous.Policy) != operationQuotaPolicyDigest(current.Policy)) {
			return errOperationObservationPlanInvalid
		}
		bindings[key] = current
	}
	return nil
}

func allOperationPlanEvidenceBound(raw json.RawMessage, manifest map[string]RegistryReleaseManifestArtifact) bool {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	var visit func(any) bool
	visit = func(node any) bool {
		switch typed := node.(type) {
		case map[string]any:
			artifactPath, hasPath := typed["artifact_path"].(string)
			if hasPath {
				sha, hasSHA := typed["sha256"].(string)
				artifact, exists := manifest[artifactPath]
				if !hasSHA || !safePlanRelativePath(artifactPath) || !sha256Pattern.MatchString(sha) || !exists || artifact.SHA256 != sha {
					return false
				}
			}
			for _, child := range typed {
				if !visit(child) {
					return false
				}
			}
		case []any:
			for _, child := range typed {
				if !visit(child) {
					return false
				}
			}
		}
		return true
	}
	return visit(value)
}

type operationQuotaPolicyBinding struct {
	Kind   string
	Key    string
	Policy OperationQuotaPolicy
}

func toQuotaEvidenceRefs(refs []operationPlanEvidenceRef) []OperationQuotaEvidenceRef {
	result := make([]OperationQuotaEvidenceRef, 0, len(refs))
	for _, ref := range refs {
		result = append(result, OperationQuotaEvidenceRef{ArtifactPath: ref.ArtifactPath, SHA256: ref.SHA256, JSONPointer: ref.JSONPointer, EvidenceKind: ref.EvidenceKind})
	}
	return result
}

type operationIdentitySetHash struct {
	hash  hash.Hash
	count int
}

func newOperationIdentitySetHash() *operationIdentitySetHash {
	h := sha256.New()
	_, _ = h.Write([]byte{'['})
	return &operationIdentitySetHash{hash: h}
}

func (set *operationIdentitySetHash) add(operationID string) {
	if set.count > 0 {
		_, _ = set.hash.Write([]byte{','})
	}
	_, _ = set.hash.Write(canonicalJSONString(operationID))
	set.count++
}

func (set *operationIdentitySetHash) digest() string {
	_, _ = set.hash.Write([]byte{']'})
	return hex.EncodeToString(set.hash.Sum(nil))
}

func canonicalJSONString(value string) []byte {
	encoded := make([]byte, 0, len(value)+2)
	encoded = append(encoded, '"')
	const hexDigits = "0123456789abcdef"
	for _, character := range value {
		switch character {
		case '"', '\\':
			encoded = append(encoded, '\\', byte(character))
		case '\b':
			encoded = append(encoded, '\\', 'b')
		case '\f':
			encoded = append(encoded, '\\', 'f')
		case '\n':
			encoded = append(encoded, '\\', 'n')
		case '\r':
			encoded = append(encoded, '\\', 'r')
		case '\t':
			encoded = append(encoded, '\\', 't')
		default:
			if character < 0x20 {
				encoded = append(encoded, '\\', 'u', '0', '0', hexDigits[byte(character)>>4], hexDigits[byte(character)&0x0f])
			} else {
				encoded = append(encoded, string(character)...)
			}
		}
	}
	return append(encoded, '"')
}

func readPlanArtifact(root, relativePath string, expectedBytes int64, maximumBytes int) ([]byte, error) {
	if !safePlanRelativePath(relativePath) || expectedBytes <= 0 || expectedBytes > int64(maximumBytes) {
		return nil, errOperationObservationPlanInvalid
	}
	current := root
	for _, component := range strings.Split(filepath.FromSlash(relativePath), string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errOperationObservationPlanInvalid
		}
		if current != filepath.Join(root, filepath.FromSlash(relativePath)) && !info.IsDir() {
			return nil, errOperationObservationPlanInvalid
		}
	}
	info, err := os.Lstat(current)
	if err != nil || !info.Mode().IsRegular() || info.Size() != expectedBytes {
		return nil, errOperationObservationPlanInvalid
	}
	file, err := os.Open(current)
	if err != nil {
		return nil, errOperationObservationPlanInvalid
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, int64(maximumBytes)+1))
	if err != nil || len(data) > maximumBytes || int64(len(data)) != expectedBytes {
		return nil, errOperationObservationPlanInvalid
	}
	return data, nil
}

func safePlanRelativePath(path string) bool {
	if path == "" || strings.ContainsAny(path, "\\\x00?#") || filepath.IsAbs(filepath.FromSlash(path)) || filepath.Clean(filepath.FromSlash(path)) != filepath.FromSlash(path) {
		return false
	}
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (plan PinnedOperationObservationPlan) RegistryRevision() string {
	if plan.state == nil {
		return ""
	}
	return plan.state.index.RegistryRevision
}

func (plan PinnedOperationObservationPlan) IndexSHA256() string {
	if plan.state == nil {
		return ""
	}
	return plan.binding.IndexSHA256
}

func (plan PinnedOperationObservationPlan) Counts() OperationObservationPlanCounts {
	if plan.state == nil {
		return OperationObservationPlanCounts{}
	}
	return plan.state.index.Summary
}

func (plan PinnedOperationObservationPlan) ShardCount() int {
	if plan.state == nil {
		return 0
	}
	return len(plan.state.index.Shards)
}

func (plan PinnedOperationObservationPlan) ExecutableOperations() int {
	if plan.state == nil {
		return 0
	}
	return plan.state.executableOperations
}

func (plan PinnedOperationObservationPlan) SourceScopes() []OperationObservationPlanSourceScope {
	if plan.state == nil {
		return nil
	}
	return append([]OperationObservationPlanSourceScope(nil), plan.state.index.SourceScopes...)
}

func (ref operationObservationPlanShardRef) String() string {
	return fmt.Sprintf("%s:%d", ref.SourceID, ref.ShardIndex)
}
