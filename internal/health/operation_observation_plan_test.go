package health

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperationIdentitySetHashUsesSortedCompactUTF8JSON(t *testing.T) {
	set := newOperationIdentitySetHash()
	set.add("op<&")
	set.add("한글")
	wantBytes := []byte(`["op<&","한글"]`)
	want := sha256.Sum256(wantBytes)
	if got := set.digest(); got != hex.EncodeToString(want[:]) {
		t.Fatalf("identity set hash = %s, want hash of compact unescaped UTF-8 array", got)
	}
	if got := string(canonicalJSONString("\\u2028")); got != `"\\u2028"` {
		t.Fatalf("literal escape sequence was altered: %q", got)
	}
	if got := string(canonicalJSONString("<\u2028")); got != "\"<\u2028\"" {
		t.Fatalf("HTML or Unicode was escaped: %q", got)
	}
}

func TestLoadPinnedOperationObservationPlanVerifiesReleaseIndexShardAndIdentityChain(t *testing.T) {
	root, binding, shardPath := writeSyntheticOperationObservationPlan(t, false)
	plan, err := LoadPinnedOperationObservationPlan(root, binding)
	if err != nil {
		t.Fatalf("load valid plan: %v", err)
	}
	if plan.Counts().KnownOperations != 2 || plan.Counts().Admitted != 2 || plan.ShardCount() != 1 || plan.RegistryRevision() != binding.RegistryRevision {
		t.Fatalf("unexpected plan summary: %#v", plan.Counts())
	}
	if plan.ExecutableOperations() != 0 {
		t.Fatal("synthetic admitted fixtures were counted as executable operations")
	}
	records, err := plan.ReadShard(0)
	if err != nil || len(records) != 2 {
		t.Fatalf("read verified shard: records=%d err=%v", len(records), err)
	}
	if records[0].Protocol != "REST" || records[1].Protocol != "SOAP" || len(records[0].QuotaPolicies) != 2 || !records[0].QuotaPoliciesAdmitted {
		t.Fatalf("unexpected safe operation projection: %#v", records)
	}
	for _, record := range records {
		if !record.TestOnly || record.ExecutionEligible || record.ExecutionBlockReason != "synthetic_evidence" {
			t.Fatalf("synthetic record was not explicitly blocked from execution: %#v", record)
		}
		if strings.Contains(strings.Join([]string{record.OperationID, record.OperationName, record.DatasetID}, " "), "https://") {
			t.Fatal("safe operation projection unexpectedly contains a URL")
		}
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(shardPath)), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := plan.ReadShard(0); err == nil {
		t.Fatal("modified shard was accepted after the initial chain verification")
	}
}

func TestLoadPinnedOperationObservationPlanRejectsUnboundEvidenceAndAdmissionContradiction(t *testing.T) {
	root, binding, _ := writeSyntheticOperationObservationPlan(t, true)
	if _, err := LoadPinnedOperationObservationPlan(root, binding); err == nil {
		t.Fatal("plan whose evidence reference is absent from the release manifest was accepted")
	}

	root, binding, _ = writeSyntheticOperationObservationPlan(t, false)
	indexPath := filepath.Join(root, filepath.FromSlash(binding.IndexPath))
	indexRaw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	var index map[string]any
	if err := json.Unmarshal(indexRaw, &index); err != nil {
		t.Fatal(err)
	}
	// Rebuild a self-consistent pinned chain with the summary claiming one
	// admitted operation while both records are admitted. This must fail from
	// derived-count validation rather than trusting index status totals.
	summary := index["summary"].(map[string]any)
	summary["admitted"] = float64(1)
	newIndexRaw, _ := json.Marshal(index)
	if err := os.WriteFile(indexPath, newIndexRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	newIndexSHA := digest(newIndexRaw)
	manifestPath := filepath.Join(root, filepath.FromSlash(binding.ReleaseManifestPath))
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest RegistryReleaseManifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	for i := range manifest.Artifacts {
		if manifest.Artifacts[i].Path == binding.IndexPath {
			manifest.Artifacts[i].Bytes = int64(len(newIndexRaw))
			manifest.Artifacts[i].SHA256 = newIndexSHA
		}
	}
	newManifestRaw, _ := json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, newManifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	binding.IndexBytes = int64(len(newIndexRaw))
	binding.IndexSHA256 = newIndexSHA
	binding.ReleaseManifestBytes = int64(len(newManifestRaw))
	binding.ReleaseManifestSHA256 = digest(newManifestRaw)
	if _, err := LoadPinnedOperationObservationPlan(root, binding); err == nil {
		t.Fatal("index whose declared summary differs from its operation records was accepted")
	}
}

func writeSyntheticOperationObservationPlan(t *testing.T, omitEvidence bool) (string, OperationObservationPlanBinding, string) {
	return writeSyntheticOperationObservationPlanVersion(t, omitEvidence, strings.Repeat("a", 40), 3600)
}

func writeSyntheticOperationObservationPlanVersion(t *testing.T, omitEvidence bool, registryRevision string, observationPeriodSeconds int64) (string, OperationObservationPlanBinding, string) {
	t.Helper()
	if !commitPattern.MatchString(registryRevision) || observationPeriodSeconds < 1 {
		t.Fatal("invalid synthetic Registry plan version")
	}
	root := t.TempDir()
	const sourcePath = "fixtures/operation-observation-plan/source.json"
	sourceBytes := []byte("synthetic test source; no provider data\n")
	sourceSHA := digest(sourceBytes)
	writePlanTestFile(t, root, sourcePath, sourceBytes)

	records := make([]json.RawMessage, 0, 2)
	for _, fixture := range []string{"synthetic-rest-list.json", "synthetic-soap-read.json"} {
		raw, err := os.ReadFile(filepath.Join("../../testdata/operation-observation-plan", fixture))
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		rewritePlanTestEvidence(value, sourcePath, sourceSHA, int64(len(sourceBytes)))
		if operation, ok := value.(map[string]any); ok {
			runtimeBinding, ok := operation["runtime_binding"].(map[string]any)
			if !ok {
				t.Fatal("synthetic operation is missing runtime binding")
			}
			runtimeBinding["observation_period_seconds"] = observationPeriodSeconds
		}
		recordRaw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, recordRaw)
	}
	if omitEvidence {
		var value map[string]any
		if err := json.Unmarshal(records[0], &value); err != nil {
			t.Fatal(err)
		}
		request := value["request_plan"].(map[string]any)
		refs := request["evidence_refs"].([]any)
		refs[0].(map[string]any)["artifact_path"] = "fixtures/missing-evidence.json"
		mutated, _ := json.Marshal(value)
		records[0] = mutated
	}

	ids := []string{"synthetic-rest-list", "synthetic-soap-read"}
	identitySet := newOperationIdentitySetHash()
	identitySet.add(ids[0])
	identitySet.add(ids[1])
	shardPath := "reports/operation-observation-plan/shards/synthetic_test-0000.json"
	shard := operationObservationPlanShardWire{SchemaVersion: OperationObservationPlanSchemaVersion, ArtifactKind: "shard", SourceID: "synthetic_test", ShardIndex: 0, Records: records}
	shardRaw, err := json.Marshal(shard)
	if err != nil {
		t.Fatal(err)
	}
	writePlanTestFile(t, root, shardPath, shardRaw)
	shardSHA := digest(shardRaw)
	indexPath := "reports/operation-observation-plan/index.json"
	inputPaths := []string{"scripts/generator.py", "reports/operation-manifest.json", "policy/health-probe-canaries.json", "reports/provider-index.json"}
	for i := 0; i < 4; i++ {
		inputPaths = append(inputPaths, "reports/denominator-"+string(rune('0'+i))+".json")
	}
	refs := make([]operationPlanArtifactRef, 0, len(inputPaths))
	manifestArtifacts := make([]RegistryReleaseManifestArtifact, 0, len(inputPaths)+3)
	var operationManifestRef operationPlanArtifactRef
	var legacyPolicyRef operationPlanArtifactRef
	var providerIndexRef operationPlanArtifactRef
	for i, path := range inputPaths {
		content := []byte("synthetic release artifact " + path)
		sha := digest(content)
		writePlanTestFile(t, root, path, content)
		artifact := RegistryReleaseManifestArtifact{Path: path, Kind: "source", Schema: "text/plain", Bytes: int64(len(content)), SHA256: sha}
		manifestArtifacts = append(manifestArtifacts, artifact)
		if i == 0 {
			continue
		}
		ref := operationPlanArtifactRef{Path: path, Bytes: int64(len(content)), SHA256: sha}
		switch {
		case i == 1:
			operationManifestRef = ref
		case i == 2:
			legacyPolicyRef = ref
		case i == 3:
			providerIndexRef = ref
		case i >= 4:
			refs = append(refs, ref)
		}
	}
	generationInputsRaw, err := json.Marshal(operationObservationPlanGenerationInputs{
		GeneratorPath: inputPaths[0], GeneratorSHA256: manifestArtifacts[0].SHA256,
		OperationManifest: operationManifestRef, OperationDenominators: refs,
		LegacyPolicy: legacyPolicyRef, ProviderIndex: &providerIndexRef,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestArtifacts = append(manifestArtifacts, RegistryReleaseManifestArtifact{Path: sourcePath, Kind: "source", Schema: "application/json", Bytes: int64(len(sourceBytes)), SHA256: sourceSHA})
	index := operationObservationPlanIndex{
		SchemaVersion: OperationObservationPlanSchemaVersion, ArtifactKind: "index", RegistryRevision: registryRevision,
		GenerationInputs: generationInputsRaw, InventoryContext: operationPlanInventoryContext{},
		Summary:      OperationObservationPlanCounts{KnownOperations: 2, RequestPlansComplete: 2, RuntimeBindingsBound: 2, Admitted: 2},
		SourceScopes: []OperationObservationPlanSourceScope{{SourceID: "synthetic_test", Provider: "synthetic-test-provider", AdapterID: "synthetic-test", InventoryStatus: "source_complete", InventoryUnknown: false, TestOnly: true, RegisteredOperations: 2, IdentitySetSHA256: identitySet.digest(), SourceArtifacts: []operationPlanArtifactRef{{Path: sourcePath, Bytes: int64(len(sourceBytes)), SHA256: sourceSHA}}}},
		Shards:       []operationObservationPlanShardRef{{SourceID: "synthetic_test", ShardIndex: 0, Path: shardPath, SHA256: shardSHA, Bytes: int64(len(shardRaw)), RecordCount: 2, FirstOperationID: ids[0], LastOperationID: ids[1]}},
	}
	indexRaw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	writePlanTestFile(t, root, indexPath, indexRaw)
	indexSHA := digest(indexRaw)
	manifestArtifacts = append(manifestArtifacts,
		RegistryReleaseManifestArtifact{Path: indexPath, Kind: "operation_observation_plan", Schema: operationObservationPlanSchemaURI, Bytes: int64(len(indexRaw)), SHA256: indexSHA},
		RegistryReleaseManifestArtifact{Path: shardPath, Kind: "operation_observation_plan_shard", Schema: operationObservationPlanSchemaURI, Bytes: int64(len(shardRaw)), SHA256: shardSHA},
	)
	if omitEvidence {
		for i := range manifestArtifacts {
			if manifestArtifacts[i].Path == sourcePath {
				manifestArtifacts = append(manifestArtifacts[:i], manifestArtifacts[i+1:]...)
				break
			}
		}
	}
	manifest := RegistryReleaseManifest{SchemaVersion: "datapan.release-manifest.v1", Artifacts: manifestArtifacts}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	const manifestPath = "release/manifest.json"
	writePlanTestFile(t, root, manifestPath, manifestRaw)
	return root, OperationObservationPlanBinding{
		RegistryRevision: index.RegistryRevision, ReleaseManifestPath: manifestPath, ReleaseManifestBytes: int64(len(manifestRaw)), ReleaseManifestSHA256: digest(manifestRaw),
		IndexPath: indexPath, IndexBytes: int64(len(indexRaw)), IndexSHA256: indexSHA,
		SchemaRegistryRevision: operationObservationSchemaRegistryRevision, SchemaSHA256: operationObservationPlanSchemaSHA256,
	}, shardPath
}

func rewritePlanTestEvidence(value any, path, sha string, size int64) {
	switch typed := value.(type) {
	case map[string]any:
		if _, exists := typed["artifact_path"]; exists {
			typed["artifact_path"] = path
			typed["sha256"] = sha
		}
		if sourceArtifacts, ok := typed["source_artifacts"].([]any); ok {
			for _, item := range sourceArtifacts {
				artifact := item.(map[string]any)
				artifact["path"] = path
				artifact["sha256"] = sha
				artifact["bytes"] = size
			}
		}
		for _, child := range typed {
			rewritePlanTestEvidence(child, path, sha, size)
		}
	case []any:
		for _, child := range typed {
			rewritePlanTestEvidence(child, path, sha, size)
		}
	}
}

func writePlanTestFile(t *testing.T, root, relative string, data []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
