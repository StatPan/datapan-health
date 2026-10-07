package health

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestOperationGatusArtifactsUseExactIdentityAndSuppressLegacyOverlap(t *testing.T) {
	planRoot, binding, sourceSHA, operationIDs := writeGatusPlanFixture(t)
	plan, err := LoadPinnedOperationObservationPlan(planRoot, binding)
	if err != nil {
		t.Fatal(err)
	}
	debugRecords, _ := plan.ReadShard(0)
	for _, record := range debugRecords {
		if !record.ExecutionEligible {
			t.Fatalf("fixture operation %s must exercise the active path, got %q", record.OperationID, record.ExecutionBlockReason)
		}
	}
	metadata, canaries := gatusTestMetadata(sourceSHA, operationIDs)
	activation := OperationGatusActivation{
		SchemaVersion:    OperationGatusActivationSchemaVersion,
		RegistryRevision: plan.RegistryRevision(), IndexSHA256: plan.IndexSHA256(),
		Operations: []OperationGatusActivationEntry{{SourceID: "data_go_kr", OperationID: operationIDs[0]}, {SourceID: "data_go_kr", OperationID: operationIDs[1]}},
	}
	activationBytes, err := json.Marshal(activation)
	if err != nil {
		t.Fatal(err)
	}
	activation, activationSHA, err := DecodeOperationGatusActivation(activationBytes, plan)
	if err != nil {
		t.Fatal(err)
	}
	base := []byte("web:\n  port: 8080\nendpoints:\n  - name: local-health\n    url: http://127.0.0.1:8080/health\nexternal-endpoints:\n  - name: old-static-entry\n")
	canarySHA := strings.Repeat("f", 64)
	first, err := GenerateOperationGatusArtifacts(base, canarySHA, canaries, metadata, &plan, &activation, activationSHA)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateOperationGatusArtifacts(base, canarySHA, canaries, metadata, &plan, &activation, activationSHA)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Config) != string(second.Config) || string(first.Mapping) != string(second.Mapping) || string(first.RuntimePin) != string(second.RuntimePin) {
		t.Fatal("identical pinned inputs generated different Gatus artifacts")
	}
	var mapping OperationGatusIdentityMapping
	if err := json.Unmarshal(first.Mapping, &mapping); err != nil {
		t.Fatal(err)
	}
	if mapping.KnownPlanOperations != 2 || mapping.AdmittedPlanOperations != 2 || mapping.ActivatedPlanOperations != 2 || mapping.LegacyCanaries != 1 || mapping.LegacyOverlapsActivated != 1 || mapping.ConfiguredExternalEndpoints != 2 || len(mapping.Operations) != 2 {
		t.Fatalf("wrong exact-operation mapping counts: %#v", mapping)
	}
	byID := make(map[string]OperationGatusIdentity)
	for _, entry := range mapping.Operations {
		byID[entry.RegistryOperationID] = entry
	}
	legacy := byID[operationIDs[0]]
	if legacy.GatusEndpointKey != "public-data_legacy-one" || !legacy.PlanActive || legacy.LegacyActive || !legacy.Active || legacy.LegacyHealthOperationID != "health-canary-one" {
		t.Fatalf("exact legacy overlap was not switched to the existing Gatus identity: %#v", legacy)
	}
	other := byID[operationIDs[1]]
	if other.GatusEndpointKey != stableOperationGatusEndpointKey("data_go_kr", operationIDs[1]) || !other.PlanActive || !other.Active || other.LegacyActive || !strings.HasPrefix(other.GatusEndpointKey, "registry-operations_registry-") {
		t.Fatalf("nonlegacy operation lacks a stable opaque target: %#v", other)
	}
	if len(first.LegacySuppressedHealthIDs) != 1 || first.LegacySuppressedHealthIDs[0] != "health-canary-one" {
		t.Fatalf("legacy execution suppression did not identify the exact overlap: %v", first.LegacySuppressedHealthIDs)
	}
	externalSection := string(first.Config[strings.Index(string(first.Config), "external-endpoints:\n"):])
	if strings.Count(externalSection, "  - name:") != 2 || strings.Contains(externalSection, "url:") || strings.Contains(externalSection, "api.example.invalid") || strings.Contains(externalSection, "soap.example.invalid") || !strings.Contains(externalSection, "name: legacy-one") || !strings.Contains(externalSection, "name: registry-") {
		t.Fatalf("Gatus config did not contain only native receivers for the two active identities: %s", externalSection)
	}
	if first.ConfigSHA256 != digestOperationGatusBytes(first.Config) || first.MappingSHA256 != digestOperationGatusBytes(first.Mapping) {
		t.Fatal("generated artifact hashes do not bind the exact output bytes")
	}
	var runtimePin OperationGatusRuntimeDependencies
	if err := json.Unmarshal(first.RuntimePin, &runtimePin); err != nil {
		t.Fatal(err)
	}
	if runtimePin.IdentityMappingSHA256 != first.MappingSHA256 || runtimePin.GeneratedConfigSHA256 != first.ConfigSHA256 || runtimePin.RegistryRevision != plan.RegistryRevision() || runtimePin.IndexSHA256 != plan.IndexSHA256() {
		t.Fatalf("runtime dependency pin does not bind the plan, map, and config: %#v", runtimePin)
	}
}

func TestObservationOnlyGatusEndpointKeepsReceiverWithoutHeartbeatOrOutageAlert(t *testing.T) {
	planRoot, binding, sourceSHA, operationIDs := writeGatusPlanFixtureWithObservationOnly(t, true)
	plan, err := LoadPinnedOperationObservationPlan(planRoot, binding)
	if err != nil {
		t.Fatal(err)
	}
	metadata, canaries := gatusTestMetadata(sourceSHA, operationIDs)
	activationBytes, err := json.Marshal(OperationGatusActivation{
		SchemaVersion:    OperationGatusActivationSchemaVersion,
		RegistryRevision: plan.RegistryRevision(), IndexSHA256: plan.IndexSHA256(),
		Operations: []OperationGatusActivationEntry{{SourceID: "data_go_kr", OperationID: operationIDs[0]}, {SourceID: "data_go_kr", OperationID: operationIDs[1]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	activation, activationSHA, err := DecodeOperationGatusActivation(activationBytes, plan)
	if err != nil {
		t.Fatal(err)
	}
	base := []byte("web:\n  port: 8080\nendpoints:\n  - name: local-health\n    url: http://127.0.0.1:8080/health\nexternal-endpoints:\n  - name: placeholder\n")
	artifacts, err := GenerateOperationGatusArtifacts(base, strings.Repeat("e", 64), canaries, metadata, &plan, &activation, activationSHA)
	if err != nil {
		t.Fatal(err)
	}
	var mapping OperationGatusIdentityMapping
	if err := json.Unmarshal(artifacts.Mapping, &mapping); err != nil {
		t.Fatal(err)
	}
	byID := make(map[string]OperationGatusIdentity, len(mapping.Operations))
	for _, item := range mapping.Operations {
		byID[item.RegistryOperationID] = item
	}
	observationOnly := byID[operationIDs[0]]
	typed := byID[operationIDs[1]]
	if observationOnly.ResponseAssertionKind != "observation_only" || !observationOnly.Active || !observationOnly.PlanActive || observationOnly.LegacyActive || typed.ResponseAssertionKind != "soap_fault_free" {
		t.Fatalf("response assertion modes were not bound to exact target identities: observation=%#v typed=%#v", observationOnly, typed)
	}
	section := string(artifacts.Config[strings.Index(string(artifacts.Config), "external-endpoints:\n"):])
	observationStart := strings.Index(section, "  - name: legacy-one\n")
	if observationStart < 0 {
		t.Fatal("observation-only receiver key/history was not retained")
	}
	observationEnd := strings.Index(section[observationStart+1:], "\n  - name:")
	if observationEnd < 0 {
		t.Fatal("typed external receiver was not emitted after the observation-only target")
	}
	observationSection := section[observationStart : observationStart+1+observationEnd]
	if strings.Contains(observationSection, "heartbeat:") || strings.Contains(observationSection, "alerts:") || !strings.Contains(observationSection, "token:") {
		t.Fatalf("observation-only target has a fabricated heartbeat/alert or lost its receiver: %s", observationSection)
	}
	typedStart := strings.Index(section, "  - name: registry-")
	if typedStart < 0 || !strings.Contains(section[typedStart:], "heartbeat:") || !strings.Contains(section[typedStart:], "alerts:") {
		t.Fatalf("typed assertion target lost its heartbeat or delivery alerts: %s", section[typedStart:])
	}
	if _, err := exactActivePlanTargets(plan, mapping); err != nil {
		t.Fatalf("verified mode-bound map did not resolve active targets: %v", err)
	}
	for i := range mapping.Operations {
		if mapping.Operations[i].RegistryOperationID == operationIDs[0] {
			mapping.Operations[i].ResponseAssertionKind = "http_status"
			break
		}
	}
	if _, err := exactActivePlanTargets(plan, mapping); err == nil {
		t.Fatal("runtime accepted an assertion mode changed independently of the immutable plan")
	}
}

func TestOperationGatusInactivePlanKeepsLegacyTargetAndMapsStableKeys(t *testing.T) {
	planRoot, binding, sourceSHA, operationIDs := writeGatusPlanFixture(t)
	plan, err := LoadPinnedOperationObservationPlan(planRoot, binding)
	if err != nil {
		t.Fatal(err)
	}
	metadata, canaries := gatusTestMetadata(sourceSHA, operationIDs)
	activationInput, err := json.Marshal(OperationGatusActivation{SchemaVersion: OperationGatusActivationSchemaVersion, RegistryRevision: plan.RegistryRevision(), IndexSHA256: plan.IndexSHA256()})
	if err != nil {
		t.Fatal(err)
	}
	activation, activationSHA, err := DecodeOperationGatusActivation(activationInput, plan)
	if err != nil {
		t.Fatal(err)
	}
	base := []byte("web:\n  port: 8080\nexternal-endpoints:\n  - name: static\n")
	generated, err := GenerateOperationGatusArtifacts(base, strings.Repeat("e", 64), canaries, metadata, &plan, &activation, activationSHA)
	if err != nil {
		t.Fatal(err)
	}
	var mapping OperationGatusIdentityMapping
	if err := json.Unmarshal(generated.Mapping, &mapping); err != nil {
		t.Fatal(err)
	}
	if mapping.ConfiguredExternalEndpoints != 1 || mapping.ActivatedPlanOperations != 0 || mapping.Operations[0].GatusEndpointKey != "public-data_legacy-one" || !mapping.Operations[0].LegacyActive || mapping.Operations[0].PlanActive || !mapping.Operations[0].Active {
		t.Fatalf("inactive admitted plan changed the legacy target: %#v", mapping)
	}
	if strings.Contains(string(generated.Config), "registry-") || !strings.Contains(string(generated.Config), "name: legacy-one") {
		t.Fatalf("inactive Registry operation was configured in Gatus: %s", generated.Config)
	}
	keyA := stableOperationGatusEndpointKey("data_go_kr", operationIDs[1])
	keyB := stableOperationGatusEndpointKey("data_go_kr", operationIDs[1])
	if keyA != keyB || keyA == stableOperationGatusEndpointKey("ecos", operationIDs[1]) || keyA == stableOperationGatusEndpointKey("data_go_kr", operationIDs[0]) {
		t.Fatal("opaque target keys are not deterministic and scoped to the exact source/operation pair")
	}
}

func TestOperationGatusActivationRejectsUnknownOrNoncanonicalTargets(t *testing.T) {
	planRoot, binding, sourceSHA, operationIDs := writeGatusPlanFixture(t)
	plan, err := LoadPinnedOperationObservationPlan(planRoot, binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, activation := range []OperationGatusActivation{
		{SchemaVersion: OperationGatusActivationSchemaVersion, RegistryRevision: plan.RegistryRevision(), IndexSHA256: plan.IndexSHA256(), Operations: []OperationGatusActivationEntry{{SourceID: "data_go_kr", OperationID: strings.Repeat("c", 64)}}},
		{SchemaVersion: OperationGatusActivationSchemaVersion, RegistryRevision: plan.RegistryRevision(), IndexSHA256: plan.IndexSHA256(), Operations: []OperationGatusActivationEntry{{SourceID: "data_go_kr", OperationID: operationIDs[1]}, {SourceID: "data_go_kr", OperationID: operationIDs[0]}}},
	} {
		raw, _ := json.Marshal(activation)
		if _, _, err := DecodeOperationGatusActivation(raw, plan); err != nil {
			// The decoder checks syntax/order only. Unknown identities and
			// admission are checked when the activation is joined to the plan.
			continue
		}
		loaded, sha, err := DecodeOperationGatusActivation(raw, plan)
		if err != nil {
			t.Fatal(err)
		}
		metadata, canaries := gatusTestMetadata(sourceSHA, operationIDs)
		_, err = GenerateOperationGatusArtifacts([]byte("web:\n  port: 8080\nexternal-endpoints:\n  - name: static\n"), strings.Repeat("e", 64), canaries, metadata, &plan, &loaded, sha)
		if err == nil {
			t.Fatal("unknown or unadmitted activation target was accepted")
		}
	}
}

func TestOperationGatusActivationDigestCannotBeReusedAfterMutation(t *testing.T) {
	planRoot, binding, sourceSHA, operationIDs := writeGatusPlanFixture(t)
	plan, err := LoadPinnedOperationObservationPlan(planRoot, binding)
	if err != nil {
		t.Fatal(err)
	}
	activationBytes, err := json.Marshal(OperationGatusActivation{
		SchemaVersion: OperationGatusActivationSchemaVersion, RegistryRevision: plan.RegistryRevision(), IndexSHA256: plan.IndexSHA256(),
		Operations: []OperationGatusActivationEntry{{SourceID: "data_go_kr", OperationID: operationIDs[0]}},
	})
	if err != nil {
		t.Fatal(err)
	}
	activation, activationSHA, err := DecodeOperationGatusActivation(activationBytes, plan)
	if err != nil {
		t.Fatal(err)
	}
	activation.Operations[0].OperationID = operationIDs[1]
	metadata, canaries := gatusTestMetadata(sourceSHA, operationIDs)
	_, err = GenerateOperationGatusArtifacts([]byte("web:\n  port: 8080\nexternal-endpoints:\n  - name: static\n"), strings.Repeat("e", 64), canaries, metadata, &plan, &activation, activationSHA)
	if err == nil {
		t.Fatal("activation payload mutation was accepted under the original byte digest")
	}
}

func TestOperationGatusRejectsDuplicateLegacyAndGeneratedReceiverKeys(t *testing.T) {
	t.Run("duplicate legacy keys", func(t *testing.T) {
		_, _, sourceSHA, operationIDs := writeGatusPlanFixture(t)
		metadata, canaries := gatusTestMetadata(sourceSHA, operationIDs)
		second := canaries.Canaries[0]
		second.OperationID = "health-canary-two"
		canaries.Canaries = append(canaries.Canaries, second)
		metadata.canaryLinksByHealthID[second.OperationID] = RegistryHealthCanaryLink{
			HealthOperationID: second.OperationID, RegistryAPIID: "api-1", RegistryOperationID: operationIDs[1], DatasetID: "api-1",
			UpstreamOperationSeq: "2", OperationName: "Read", CLIOperationKey: strings.Repeat("a", 64),
		}
		_, err := GenerateOperationGatusArtifacts([]byte("web:\n  port: 8080\nexternal-endpoints:\n  - name: static\n"), strings.Repeat("e", 64), canaries, metadata, nil, nil, "")
		if err == nil {
			t.Fatal("two legacy identities were allowed to collapse onto one Gatus receiver key")
		}
	})

	t.Run("legacy key collides with another plan identity", func(t *testing.T) {
		planRoot, binding, sourceSHA, operationIDs := writeGatusPlanFixture(t)
		plan, err := LoadPinnedOperationObservationPlan(planRoot, binding)
		if err != nil {
			t.Fatal(err)
		}
		metadata, canaries := gatusTestMetadata(sourceSHA, operationIDs)
		canaries.Canaries[0].GatusEndpointKey = stableOperationGatusEndpointKey("data_go_kr", operationIDs[1])
		activationBytes, err := json.Marshal(OperationGatusActivation{
			SchemaVersion: OperationGatusActivationSchemaVersion, RegistryRevision: plan.RegistryRevision(), IndexSHA256: plan.IndexSHA256(),
			Operations: []OperationGatusActivationEntry{{SourceID: "data_go_kr", OperationID: operationIDs[1]}},
		})
		if err != nil {
			t.Fatal(err)
		}
		activation, activationSHA, err := DecodeOperationGatusActivation(activationBytes, plan)
		if err != nil {
			t.Fatal(err)
		}
		_, err = GenerateOperationGatusArtifacts([]byte("web:\n  port: 8080\nexternal-endpoints:\n  - name: static\n"), strings.Repeat("e", 64), canaries, metadata, &plan, &activation, activationSHA)
		if err == nil {
			t.Fatal("distinct legacy and Registry identities were allowed to share a Gatus receiver key")
		}
	})
}

func TestStableOperationGatusKeysRemainUniqueAcrossKnownScale(t *testing.T) {
	const operationCount = 12_666
	seen := make(map[string]struct{}, operationCount)
	for index := 0; index < operationCount; index++ {
		id := strings.Repeat("a", 58) + strings.Repeat("0", 5) + hex.EncodeToString([]byte{byte(index >> 8), byte(index)})
		key := stableOperationGatusEndpointKey("data_go_kr", id)
		if !gatusKeyPattern.MatchString(key) {
			t.Fatalf("generated invalid private Gatus key %q", key)
		}
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("opaque Gatus key collision at synthetic operation %d", index)
		}
		seen[key] = struct{}{}
	}
}

func TestRenderOperationGatusConfigRejectsUnexpectedTopLevelAfterReceiverSection(t *testing.T) {
	base := []byte("web:\n  port: 8080\nexternal-endpoints:\n  - name: old\nnext-section:\n  key: value\n")
	_, err := renderOperationGatusConfig(base, []operationGatusEndpoint{{key: "group_name", group: "group", name: "name", heartbeat: time.Minute}})
	if err == nil {
		t.Fatal("replacement silently discarded a following top-level Gatus section")
	}
}

func gatusTestMetadata(sourceSHA string, operationIDs []string) (VerifiedRegistryAPIMetadata, CanaryConfig) {
	catalogSHA := strings.Repeat("c", 64)
	canary := Canary{OperationID: "health-canary-one", GatusEndpointKey: "public-data_legacy-one", Tier: "B", IntervalMinutes: 10, HeartbeatMinutes: 20, ConsecutiveFailuresBeforeIncident: 2, MissedSchedulesBeforeHeartbeat: 2}
	links := map[string]RegistryHealthCanaryLink{
		canary.OperationID: {HealthOperationID: canary.OperationID, RegistryAPIID: "api-1", RegistryOperationID: operationIDs[0], DatasetID: "api-1", UpstreamOperationSeq: "1", OperationName: "Search", CLIOperationKey: strings.Repeat("f", 64)},
	}
	metadata := VerifiedRegistryAPIMetadata{
		verified:          true,
		pin:               RegistryAPIMetadataPin{RegistryRevision: strings.Repeat("d", 40), SourceSHA256: sourceSHA, CatalogSHA256: catalogSHA, ArtifactSHA256: strings.Repeat("e", 64), APIEntityCount: 1, OperationCount: len(operationIDs)},
		identitySetSHA256: hashOperationIDs(operationIDs), canaryLinksByHealthID: links,
	}
	for index, operationID := range operationIDs {
		name := "Read"
		if index == 0 {
			name = "Search"
		}
		metadata.operations = append(metadata.operations, RegistryOperationMetadata{RegistryOperationID: operationID, APIID: "api-1", OperationName: name, OperationNameState: "present", Title: "API", TitleState: "present", Organization: "기관", OrganizationState: "present", Purpose: "목적", PurposeState: "present"})
	}
	canaries := CanaryConfig{CatalogSHA256: catalogSHA, Canaries: []Canary{canary}}
	return metadata, canaries
}

func hashOperationIDs(operationIDs []string) string {
	copyIDs := append([]string(nil), operationIDs...)
	sort.Strings(copyIDs)
	set := newOperationIdentitySetHash()
	for _, id := range copyIDs {
		set.add(id)
	}
	return set.digest()
}

func writeGatusPlanFixture(t *testing.T) (string, OperationObservationPlanBinding, string, []string) {
	return writeGatusPlanFixtureWithObservationOnly(t, false)
}

func writeGatusPlanFixtureWithObservationOnly(t *testing.T, observationOnly bool) (string, OperationObservationPlanBinding, string, []string) {
	t.Helper()
	root, binding, shardPath := writeSyntheticOperationObservationPlan(t, false)
	const oldSourcePath = "fixtures/operation-observation-plan/source.json"
	const sourcePath = "data/data-go-kr.registry.json"
	oldSource, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(oldSourcePath)))
	if err != nil {
		t.Fatal(err)
	}
	sourceSHA := digest(oldSource)
	if err := os.MkdirAll(filepath.Join(root, "data"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(sourcePath)), oldSource, 0o600); err != nil {
		t.Fatal(err)
	}
	operationIDs := []string{strings.Repeat("a", 63) + "1", strings.Repeat("a", 63) + "2"}
	var shard operationObservationPlanShardWire
	shardRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(shardPath)))
	if err != nil || json.Unmarshal(shardRaw, &shard) != nil {
		t.Fatalf("could not read synthetic shard: %v", err)
	}
	for index, raw := range shard.Records {
		var record map[string]any
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		source := record["source_binding"].(map[string]any)
		source["source_id"], source["provider"], source["adapter_id"], source["test_only"] = "data_go_kr", "data.go.kr", "data-go-kr", false
		identity := record["operation_identity"].(map[string]any)
		identity["operation_id"], identity["dataset_id"] = operationIDs[index], "api-1"
		if index == 0 {
			identity["operation_name"] = "Search"
		} else {
			identity["operation_name"] = "Read"
		}
		requestContract := record["request_plan"].(map[string]any)["request_contract"].(map[string]any)
		requestContract["transport"].(map[string]any)["authority"] = "operation_document"
		if observationOnly && index == 0 {
			assertion := requestContract["response_assertion"].(map[string]any)
			assertion["kind"] = "observation_only"
			assertion["empty_result_semantics"] = "not_applicable"
			assertion["assertion_ref"] = "synthetic-observation-only"
			delete(assertion, "expected_status_codes")
		}
		if index == 1 {
			parameters := requestContract["parameters"].([]any)
			parameters[0].(map[string]any)["qualified_name"] = map[string]any{"namespace": "urn:synthetic:request", "local_name": "RecordID"}
		}
		rewriteGatusEvidence(record, oldSourcePath, sourcePath, sourceSHA, int64(len(oldSource)))
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		shard.Records[index] = encoded
	}
	shard.SourceID = "data_go_kr"
	shardRaw, err = json.Marshal(shard)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(shardPath)), shardRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	shardSHA := digest(shardRaw)
	identitySet := newOperationIdentitySetHash()
	for _, id := range operationIDs {
		identitySet.add(id)
	}
	var index operationObservationPlanIndex
	indexPath := binding.IndexPath
	indexRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(indexPath)))
	if err != nil || json.Unmarshal(indexRaw, &index) != nil {
		t.Fatalf("could not read synthetic index: %v", err)
	}
	index.SourceScopes[0].SourceID = "data_go_kr"
	index.SourceScopes[0].Provider = "data.go.kr"
	index.SourceScopes[0].AdapterID = "data-go-kr"
	index.SourceScopes[0].TestOnly = false
	index.SourceScopes[0].IdentitySetSHA256 = identitySet.digest()
	index.SourceScopes[0].SourceArtifacts[0] = operationPlanArtifactRef{Path: sourcePath, Bytes: int64(len(oldSource)), SHA256: sourceSHA}
	index.Shards[0].SourceID = "data_go_kr"
	index.Shards[0].SHA256 = shardSHA
	index.Shards[0].Bytes = int64(len(shardRaw))
	index.Shards[0].FirstOperationID, index.Shards[0].LastOperationID = operationIDs[0], operationIDs[1]
	indexRaw, err = json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(indexPath)), indexRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	indexSHA := digest(indexRaw)
	var manifest RegistryReleaseManifest
	manifestRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(binding.ReleaseManifestPath)))
	if err != nil || json.Unmarshal(manifestRaw, &manifest) != nil {
		t.Fatalf("could not read synthetic release manifest: %v", err)
	}
	for index := range manifest.Artifacts {
		artifact := &manifest.Artifacts[index]
		switch artifact.Path {
		case oldSourcePath:
			artifact.Path, artifact.Bytes, artifact.SHA256 = sourcePath, int64(len(oldSource)), sourceSHA
		case shardPath:
			artifact.Bytes, artifact.SHA256 = int64(len(shardRaw)), shardSHA
		case indexPath:
			artifact.Bytes, artifact.SHA256 = int64(len(indexRaw)), indexSHA
		}
	}
	manifestRaw, err = json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(binding.ReleaseManifestPath)), manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	binding.IndexBytes, binding.IndexSHA256 = int64(len(indexRaw)), indexSHA
	binding.ReleaseManifestBytes, binding.ReleaseManifestSHA256 = int64(len(manifestRaw)), digest(manifestRaw)
	manifestByPath := make(map[string]RegistryReleaseManifestArtifact, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		manifestByPath[artifact.Path] = artifact
	}
	scopeMap := map[string]OperationObservationPlanSourceScope{index.SourceScopes[0].SourceID: index.SourceScopes[0]}
	debugState := &operationPlanIndexState{index: index, root: root, manifest: manifestByPath, byScope: scopeMap}
	debugShard, debugErr := debugState.readShard(index.Shards[0])
	if debugErr != nil {
		t.Fatalf("rewritten fixture shard bytes/schema invalid: %v", debugErr)
	}
	for i, recordRaw := range debugShard.Records {
		record, recordErr := decodeOperationObservationPlanRecord(recordRaw)
		if recordErr != nil || !allOperationPlanEvidenceBound(recordRaw, manifestByPath) {
			t.Fatalf("rewritten record %d failed semantic/evidence validation: %#v %v", i, record, recordErr)
		}
	}
	if err := debugState.verifyAllShards(); err != nil {
		t.Fatalf("rewritten fixture shard verification failed: %v; scope=%#v shard=%#v", err, index.SourceScopes[0], index.Shards[0])
	}
	return root, binding, sourceSHA, operationIDs
}

func rewriteGatusEvidence(node any, oldPath, newPath, sha string, size int64) {
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			if key == "artifact_path" && value == oldPath {
				typed[key] = newPath
			}
			if key == "evidence_kind" && value == "synthetic_fixture" {
				typed[key] = "operation_document"
			}
			if key == "authority" && value == "synthetic_fixture" {
				typed[key] = "reviewed_policy"
			}
			if key == "path" && value == oldPath {
				typed[key] = newPath
				if bytes, ok := typed["bytes"].(float64); ok && bytes > 0 {
					typed["bytes"] = size
				}
				if _, ok := typed["sha256"]; ok {
					typed["sha256"] = sha
				}
			}
			rewriteGatusEvidence(typed[key], oldPath, newPath, sha, size)
		}
	case []any:
		for _, value := range typed {
			rewriteGatusEvidence(value, oldPath, newPath, sha, size)
		}
	}
}
