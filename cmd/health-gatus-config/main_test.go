package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGeneratePublishesPinnedLegacyOnlyConfigWhenPlanBundleIsAbsent(t *testing.T) {
	out := t.TempDir()
	err := generate(
		"../../config/gatus.yaml",
		"../../config/canaries.json",
		"../../config/registry/api-metadata.v1.json",
		"../../config/registry/api-metadata-source-pin.v1.json",
		"", "", "", "", out,
	)
	if err != nil {
		t.Fatal(err)
	}
	config, err := os.ReadFile(filepath.Join(out, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sectionIndex := strings.Index(string(config), "external-endpoints:\n")
	if sectionIndex < 0 {
		t.Fatal("generated config omitted external-endpoints section")
	}
	section := string(config[sectionIndex:])
	if strings.Count(section, "  - name:") != 10 || strings.Contains(section, "url:") || strings.Contains(section, "apis.data.go.kr") || strings.Contains(section, "serviceKey") {
		t.Fatalf("generated Gatus configuration is not a redacted legacy-only receiver list: endpoint_count=%d", strings.Count(section, "  - name:"))
	}
	var mapping struct {
		KnownPlanOperations         int    `json:"known_plan_operations"`
		ConfiguredExternalEndpoints int    `json:"configured_external_endpoints"`
		LegacyCanaries              int    `json:"legacy_canaries"`
		PlanState                   string `json:"plan_state"`
		PlanMissingReason           string `json:"plan_missing_reason"`
	}
	raw, err := os.ReadFile(filepath.Join(out, "operation-identity-map.json"))
	if err != nil || json.Unmarshal(raw, &mapping) != nil || mapping.KnownPlanOperations != 0 || mapping.LegacyCanaries != 10 || mapping.ConfiguredExternalEndpoints != 10 || mapping.PlanState != "unavailable" || mapping.PlanMissingReason != "operation_plan_not_configured" {
		t.Fatalf("missing plan bundle did not remain explicitly legacy-only: %#v %v", mapping, err)
	}
	var runtimePin struct {
		KnownPlanOperations   int    `json:"known_plan_operations"`
		IdentityMappingSHA256 string `json:"identity_mapping_sha256"`
		GeneratedConfigSHA256 string `json:"generated_config_sha256"`
	}
	pinBytes, err := os.ReadFile(filepath.Join(out, "runtime-dependencies.json"))
	if err != nil || json.Unmarshal(pinBytes, &runtimePin) != nil || runtimePin.KnownPlanOperations != 0 || runtimePin.IdentityMappingSHA256 == "" || runtimePin.GeneratedConfigSHA256 == "" {
		t.Fatalf("generated runtime pin does not bind legacy-only artifacts: %#v %v", runtimePin, err)
	}
}

func TestActivationPinMustBeCanonicalSHA256(t *testing.T) {
	for _, value := range []string{"", strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("a", 63)} {
		if validSHA256(value) {
			t.Fatalf("accepted noncanonical activation digest %q", value)
		}
	}
	if !validSHA256(strings.Repeat("a", 64)) {
		t.Fatal("rejected canonical SHA-256")
	}
}
