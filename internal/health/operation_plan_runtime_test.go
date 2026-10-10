package health

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifiedOperationPlanRuntimeRequiresExactGeneratedBundleAndBindsActiveTargets(t *testing.T) {
	planRoot, binding, sourceSHA, operationIDs := writeGatusPlanFixture(t)
	plan, err := LoadPinnedOperationObservationPlan(planRoot, binding)
	if err != nil {
		t.Fatal(err)
	}
	metadata, canaries := gatusTestMetadata(sourceSHA, operationIDs)
	activationRaw, err := json.Marshal(OperationGatusActivation{
		SchemaVersion: OperationGatusActivationSchemaVersion, RegistryRevision: plan.RegistryRevision(),
		IndexSHA256: plan.IndexSHA256(), Operations: []OperationGatusActivationEntry{
			{SourceID: "data_go_kr", OperationID: operationIDs[0]},
			{SourceID: "data_go_kr", OperationID: operationIDs[1]},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	activation, activationSHA, err := DecodeOperationGatusActivation(activationRaw, plan)
	if err != nil {
		t.Fatal(err)
	}
	base := []byte("web:\n  port: 8080\nexternal-endpoints:\n  - name: placeholder\n")
	canaryRaw := []byte("verified-canary-bytes-for-synthetic-fixture\n")
	artifacts, err := GenerateOperationGatusArtifacts(base, digestOperationGatusBytes(canaryRaw), canaries, metadata, &plan, &activation, activationSHA)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := t.TempDir()
	paths := operationPlanTestRuntimePaths(runtimeRoot)
	for path, raw := range map[string][]byte{
		paths.BaseGatusConfigPath: base, paths.GeneratedConfigPath: artifacts.Config,
		paths.IdentityMappingPath: artifacts.Mapping, paths.RuntimePinPath: artifacts.RuntimePin,
	} {
		if err := os.WriteFile(path, raw, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	paths.ActivationPath = filepath.Join(runtimeRoot, "activation.json")
	paths.ActivationSHA256 = activationSHA
	if err := os.WriteFile(paths.ActivationPath, activationRaw, 0o400); err != nil {
		t.Fatal(err)
	}
	loaded, err := verifyOperationGatusRuntimeArtifacts(paths, canaryRaw, canaries, metadata, plan)
	if err != nil {
		t.Fatalf("verified generated plan/Gatus bundle was rejected: %v", err)
	}
	if len(loaded.ActiveTargets) != 2 || len(loaded.SuppressedLegacy) != 1 || loaded.SuppressedLegacy[0] != "health-canary-one" {
		t.Fatalf("verified activation did not bind both targets and suppress the exact legacy overlap: targets=%d suppressed=%v", len(loaded.ActiveTargets), loaded.SuppressedLegacy)
	}
	if loaded.ActiveTargets[0].GatusEndpointKey != "public-data_legacy-one" || loaded.ActiveTargets[0].Record.OperationID != operationIDs[0] || loaded.ActiveTargets[0].ShardSHA256 == "" {
		t.Fatalf("legacy overlap did not retain the exact registered operation identity/key/shard: %#v", loaded.ActiveTargets[0])
	}

	mutated := append([]byte(nil), artifacts.Mapping...)
	mutated = []byte(strings.Replace(string(mutated), operationIDs[1], strings.Repeat("9", 64), 1))
	if err := os.Chmod(paths.IdentityMappingPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.IdentityMappingPath, mutated, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyOperationGatusRuntimeArtifacts(paths, canaryRaw, canaries, metadata, plan); err == nil {
		t.Fatal("runtime accepted a generated identity map whose bytes differ from the verified inputs")
	}
}

func TestVerifiedOperationPlanRuntimeRejectsActivationWithoutMatchingGeneratedBundle(t *testing.T) {
	planRoot, binding, sourceSHA, operationIDs := writeGatusPlanFixture(t)
	plan, err := LoadPinnedOperationObservationPlan(planRoot, binding)
	if err != nil {
		t.Fatal(err)
	}
	metadata, canaries := gatusTestMetadata(sourceSHA, operationIDs)
	base := []byte("web:\n  port: 8080\nexternal-endpoints:\n  - name: placeholder\n")
	canaryRaw := []byte("verified-canary-bytes-for-synthetic-fixture\n")
	artifacts, err := GenerateOperationGatusArtifacts(base, digestOperationGatusBytes(canaryRaw), canaries, metadata, &plan, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := t.TempDir()
	paths := operationPlanTestRuntimePaths(runtimeRoot)
	for path, raw := range map[string][]byte{
		paths.BaseGatusConfigPath: base, paths.GeneratedConfigPath: artifacts.Config,
		paths.IdentityMappingPath: artifacts.Mapping, paths.RuntimePinPath: artifacts.RuntimePin,
	} {
		if err := os.WriteFile(path, raw, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := verifyOperationGatusRuntimeArtifacts(paths, canaryRaw, canaries, metadata, plan)
	if err != nil || len(loaded.ActiveTargets) != 0 || len(loaded.IdentityMapping.Operations) != 2 {
		t.Fatalf("inactive generated plan was not preserved as known but unconfigured: loaded=%#v err=%v", loaded, err)
	}
	paths.ActivationPath = filepath.Join(runtimeRoot, "activation.json")
	paths.ActivationSHA256 = strings.Repeat("a", 64)
	if err := os.WriteFile(paths.ActivationPath, []byte(`{"schema_version":"placeholder"}`), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyOperationGatusRuntimeArtifacts(paths, canaryRaw, canaries, metadata, plan); err == nil {
		t.Fatal("runtime accepted an activation whose exact bytes do not match the image pin")
	}
}

func operationPlanTestRuntimePaths(root string) OperationPlanRuntimePaths {
	return OperationPlanRuntimePaths{
		PlanRoot: root, PlanPinPath: filepath.Join(root, "plan-pin.json"),
		CanaryConfigPath: filepath.Join(root, "canaries.json"), RegistryMetadataPath: filepath.Join(root, "metadata.json"),
		RegistryMetadataPin: filepath.Join(root, "metadata-pin.json"), BaseGatusConfigPath: filepath.Join(root, "base-config.yaml"),
		GeneratedConfigPath: filepath.Join(root, "generated-config.yaml"), IdentityMappingPath: filepath.Join(root, "operation-identity-map.json"),
		RuntimePinPath: filepath.Join(root, "runtime-dependencies.json"),
	}
}
