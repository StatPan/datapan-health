package health

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const diagnosticPinPath = "../../config/registry/diagnostic-contract-pin.json"

func TestAcceptedDiagnosticFixturesMatchExactRegistryContract(t *testing.T) {
	contract := mustLoadDiagnosticContract(t)
	wantCauses := map[string]bool{
		"approval_required": true, "approval_propagating": true,
		"credential_invalid": true, "invalid_input": true,
		"rate_limited": true, "provider_outage": true,
		"contract_drift": true, "semantic_quality": true,
		"stale_data": true, "ready": true, "unknown": true,
	}
	gotCauses := map[string]bool{}
	for _, name := range contract.FixtureNames() {
		raw, err := contract.ReadFixture(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		envelope, err := contract.Decode(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if envelope.SchemaVersion != DiagnosticSchemaVersion || envelope.OriginalSHA256 != digest(raw) {
			t.Fatalf("fixture %s did not preserve exact contract identity", name)
		}
		gotCauses[envelope.Cause.Code] = true
	}
	if len(gotCauses) != len(wantCauses) {
		t.Fatalf("accepted cause coverage differs: %#v", gotCauses)
	}
	for cause := range wantCauses {
		if !gotCauses[cause] {
			t.Fatalf("accepted fixture is missing cause %q", cause)
		}
	}
}

func TestDiagnosticDecoderFailsClosedForUnknownVersionEnumAndExtraField(t *testing.T) {
	contract := mustLoadDiagnosticContract(t)
	raw := string(mustDiagnosticFixture(t, contract, "unknown.json"))
	for name, mutation := range map[string]string{
		"version":       strings.Replace(raw, DiagnosticSchemaVersion, "datapan.diagnostic-envelope.v2", 1),
		"determination": strings.Replace(raw, `"determination": "unknown"`, `"determination": "probable"`, 1),
		"cause":         strings.Replace(raw, `"code": "unknown"`, `"code": "network_error"`, 1),
		"extra":         strings.Replace(raw, `"schema_version": "datapan.diagnostic-envelope.v1"`, `"schema_version": "datapan.diagnostic-envelope.v1", "confidence": 0.9`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := contract.Decode(strings.NewReader(mutation)); err == nil {
				t.Fatal("unsupported diagnostic envelope was accepted")
			}
		})
	}
}

func TestDiagnosticSubjectBindsExactlyOnceToConfiguredService(t *testing.T) {
	contract := mustLoadDiagnosticContract(t)
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	envelope := diagnosticEnvelopeForCanary(t, contract, canaries, 0)
	binding, err := contract.Resolve(envelope, canaries)
	if err != nil {
		t.Fatal(err)
	}
	if binding.OperationID != "dpr-op-00000001" || binding.ServiceID != "public-data_holiday-emergency-clinics" || binding.RegistryRevision != AcceptedDiagnosticRegistryRevision || binding.EnvelopeSHA256 != envelope.OriginalSHA256 {
		t.Fatalf("unexpected exact identity binding: %#v", binding)
	}
}

func TestDiagnosticSubjectRejectsUnknownCrossOperationDuplicateAndStaleRevision(t *testing.T) {
	contract := mustLoadDiagnosticContract(t)
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	base := diagnosticEnvelopeForCanary(t, contract, canaries, 0)

	tests := map[string]func(DiagnosticEnvelope, CanaryConfig, DiagnosticContract) (DiagnosticEnvelope, CanaryConfig, DiagnosticContract){
		"unknown operation": func(envelope DiagnosticEnvelope, config CanaryConfig, contract DiagnosticContract) (DiagnosticEnvelope, CanaryConfig, DiagnosticContract) {
			envelope.Subject.OperationID = "dpr-op-99999999"
			return envelope, config, contract
		},
		"cross operation dataset": func(envelope DiagnosticEnvelope, config CanaryConfig, contract DiagnosticContract) (DiagnosticEnvelope, CanaryConfig, DiagnosticContract) {
			envelope.Subject.DatasetID = config.catalog.Entries[1].Aliases.DatasetID
			return envelope, config, contract
		},
		"duplicate operation": func(envelope DiagnosticEnvelope, config CanaryConfig, contract DiagnosticContract) (DiagnosticEnvelope, CanaryConfig, DiagnosticContract) {
			config.Canaries = append(config.Canaries, config.Canaries[0])
			return envelope, config, contract
		},
		"stale registry revision": func(envelope DiagnosticEnvelope, config CanaryConfig, contract DiagnosticContract) (DiagnosticEnvelope, CanaryConfig, DiagnosticContract) {
			contract.RegistryRevision = strings.Repeat("0", 40)
			return envelope, config, contract
		},
		"stale operation catalog": func(envelope DiagnosticEnvelope, config CanaryConfig, contract DiagnosticContract) (DiagnosticEnvelope, CanaryConfig, DiagnosticContract) {
			config.CatalogSHA256 = strings.Repeat("0", 64)
			return envelope, config, contract
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			envelope, config, candidate := mutate(base, canaries, contract)
			if _, err := candidate.Resolve(envelope, config); err == nil {
				t.Fatal("unsafe or ambiguous diagnostic identity was accepted")
			}
		})
	}
}

func TestDiagnosticProducerBoundaryRejectsEveryRedactionLeakClass(t *testing.T) {
	contract := mustLoadDiagnosticContract(t)
	base := mustDiagnosticFixture(t, contract, "unknown.json")
	tests := []struct {
		name, assertion, field, value string
	}{
		{"secret value", "secret_values_present", "secret_value", "do-not-log-this-secret"},
		{"secret hash", "secret_hashes_present", "secret_hash", strings.Repeat("a", 64)},
		{"authorization header", "authorization_headers_present", "authorization_header", "Bearer do-not-log-this-token"},
		{"credential URL", "credential_bearing_urls_present", "credential_url", "https://provider.invalid/path?serviceKey=do-not-log"},
		{"provider text", "raw_provider_text_present", "raw_provider_text", "do-not-log-provider-message"},
		{"provider URL", "raw_provider_urls_present", "raw_provider_url", "https://provider.invalid/private"},
		{"response body", "response_bodies_present", "response_body", "do-not-log-response-body"},
		{"user identity", "user_identity_present", "user_id", "do-not-log-user"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal(base, &document); err != nil {
				t.Fatal(err)
			}
			document["redaction"].(map[string]any)[test.assertion] = true
			document[test.field] = test.value
			mutation, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			_, err = contract.Decode(bytes.NewReader(mutation))
			if err == nil {
				t.Fatal("sensitive producer output was accepted")
			}
			if strings.Contains(err.Error(), test.value) {
				t.Fatal("public-safe decoder error echoed sensitive evidence")
			}
		})
	}
}

func TestDiagnosticCauseCannotChangeGatusProjection(t *testing.T) {
	contract := mustLoadDiagnosticContract(t)
	if _, err := contract.Decode(bytes.NewReader(mustDiagnosticFixture(t, contract, "provider-outage.json"))); err != nil {
		t.Fatal(err)
	}
	receipt, err := DecodeReceipt(strings.NewReader(string(mustRead(t, "../../testdata/receipts/v1/unhealthy.json"))))
	if err != nil {
		t.Fatal(err)
	}
	summary := Summarize(receipt, "public-data_qnet-practical-pass-rate")
	if summary.ErrorClass != "unhealthy:timeout" || strings.Contains(summary.ErrorClass, "provider_outage") || strings.Contains(summary.EndpointKey, "provider_outage") {
		t.Fatalf("diagnostic cause changed the existing Gatus projection: %#v", summary)
	}
}

func TestDiagnosticPinRejectsRevisionAndArtifactDrift(t *testing.T) {
	original := mustRead(t, diagnosticPinPath)
	for name, mutation := range map[string][]byte{
		"revision":      bytes.Replace(original, []byte(AcceptedDiagnosticRegistryRevision), []byte(strings.Repeat("0", 40)), 1),
		"schema digest": bytes.Replace(original, []byte(AcceptedDiagnosticSchemaSHA256), []byte(strings.Repeat("0", 64)), 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pin.json")
			if err := os.WriteFile(path, mutation, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadDiagnosticContract(path); err == nil {
				t.Fatal("stale or drifted contract pin was accepted")
			}
		})
	}
}

func TestDiagnosticCompatibilityReceiptBindsHeadContractsFixturesAndServices(t *testing.T) {
	contract := mustLoadDiagnosticContract(t)
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	head := strings.Repeat("a", 40)
	testedRevision := strings.Repeat("b", 40)
	receipt, err := BuildDiagnosticCompatibilityReceipt(head, testedRevision, "../..", contract, canaries)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.SchemaVersion != DiagnosticCompatibilityReceiptVersion || receipt.Status != "consumer_compatible" || receipt.HealthHead != head || receipt.TestedRevision != testedRevision || receipt.RegistryRevision != AcceptedDiagnosticRegistryRevision {
		t.Fatalf("receipt identity is incomplete: %#v", receipt)
	}
	if receipt.Contracts.Schema.SHA256 != AcceptedDiagnosticSchemaSHA256 || receipt.Contracts.Mapping.SHA256 != AcceptedDiagnosticMappingSHA256 || receipt.Contracts.Consumer.SHA256 != AcceptedDiagnosticConsumerSHA256 {
		t.Fatalf("receipt contract pins drifted: %#v", receipt.Contracts)
	}
	if len(receipt.Fixtures) != 11 || len(receipt.Bindings) != len(canaries.Canaries) || receipt.TestProof.Count != len(receipt.TestProof.Tests) || receipt.TestProof.Count < 10 || len(receipt.TestProof.Sources) != 2 || receipt.TestProof.Manifest.SHA256 != AcceptedDiagnosticTestManifestSHA256 {
		t.Fatalf("receipt proof coverage is incomplete: fixtures=%d bindings=%d tests=%d sources=%d", len(receipt.Fixtures), len(receipt.Bindings), receipt.TestProof.Count, len(receipt.TestProof.Sources))
	}
	bindingBytes, err := json.Marshal(receipt.Bindings)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.BindingsSHA256 != digest(bindingBytes) {
		t.Fatal("receipt does not bind the exact sorted operation/service mapping")
	}
	if receipt.Boundaries.ExistingHealthProbeV1 != "preserved" || receipt.Boundaries.GatusProjection != "unchanged_enum_only" || receipt.Boundaries.PublicAPI != "not_implemented" || receipt.Boundaries.Deployment != "not_performed" {
		t.Fatalf("receipt crossed issue #19 boundaries: %#v", receipt.Boundaries)
	}
	if _, err := BuildDiagnosticCompatibilityReceipt("main", testedRevision, "../..", contract, canaries); err == nil {
		t.Fatal("non-commit Health head was accepted")
	}
	if _, err := BuildDiagnosticCompatibilityReceipt(head, "merge", "../..", contract, canaries); err == nil {
		t.Fatal("non-commit tested revision was accepted")
	}
}

func TestDiagnosticCompatibilityRejectsNonBijectiveOrIncompleteServiceMap(t *testing.T) {
	contract := mustLoadDiagnosticContract(t)
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	head := strings.Repeat("a", 40)
	tested := strings.Repeat("b", 40)
	tests := map[string]func(CanaryConfig, DiagnosticContract) (CanaryConfig, DiagnosticContract){
		"duplicate service": func(config CanaryConfig, contract DiagnosticContract) (CanaryConfig, DiagnosticContract) {
			config.Canaries[1].GatusEndpointKey = config.Canaries[0].GatusEndpointKey
			return config, contract
		},
		"missing operation": func(config CanaryConfig, contract DiagnosticContract) (CanaryConfig, DiagnosticContract) {
			config.Canaries = config.Canaries[:len(config.Canaries)-1]
			return config, contract
		},
		"extra operation": func(config CanaryConfig, contract DiagnosticContract) (CanaryConfig, DiagnosticContract) {
			config.Canaries = append(config.Canaries, config.Canaries[0])
			return config, contract
		},
		"wrong service": func(config CanaryConfig, contract DiagnosticContract) (CanaryConfig, DiagnosticContract) {
			config.Canaries[0].GatusEndpointKey = "public-data_wrong-service"
			return config, contract
		},
		"revision drift": func(config CanaryConfig, contract DiagnosticContract) (CanaryConfig, DiagnosticContract) {
			contract.RegistryRevision = strings.Repeat("0", 40)
			return config, contract
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config, candidate := mutate(canaries, contract)
			if _, err := BuildDiagnosticCompatibilityReceipt(head, tested, "../..", candidate, config); err == nil {
				t.Fatal("non-bijective or stale compatibility proof was accepted")
			}
		})
	}
}

func TestDiagnosticCompatibilityCLIRejectsNonBijectiveCanaryFiles(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	raw := mustRead(t, "../../config/canaries.json")
	var base map[string]any
	if err := json.Unmarshal(raw, &base); err != nil {
		t.Fatal(err)
	}
	catalogPath, err := filepath.Abs("../../config/registry/health-probe-catalog.json")
	if err != nil {
		t.Fatal(err)
	}
	base["catalog_path"] = catalogPath

	mutations := map[string]func(map[string]any){
		"duplicate service": func(config map[string]any) {
			canaries := config["canaries"].([]any)
			canaries[1].(map[string]any)["gatus_endpoint_key"] = canaries[0].(map[string]any)["gatus_endpoint_key"]
		},
		"missing operation": func(config map[string]any) {
			canaries := config["canaries"].([]any)
			config["canaries"] = canaries[:len(canaries)-1]
		},
		"extra operation": func(config map[string]any) {
			canaries := config["canaries"].([]any)
			config["canaries"] = append(canaries, canaries[0])
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			encoded, err := json.Marshal(base)
			if err != nil {
				t.Fatal(err)
			}
			var candidate map[string]any
			if err := json.Unmarshal(encoded, &candidate); err != nil {
				t.Fatal(err)
			}
			mutate(candidate)
			configPath := filepath.Join(t.TempDir(), "canaries.json")
			updated, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, updated, 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("go", "run", "./cmd/health-compatibility", "-pin", "config/registry/diagnostic-contract-pin.json", "-canaries", configPath, "-repo-root", ".", "-health-head", strings.Repeat("a", 40), "-tested-revision", strings.Repeat("b", 40), "-output", filepath.Join(t.TempDir(), "receipt.json"))
			command.Dir = repoRoot
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatal("compatibility CLI accepted a non-bijective canary file")
			}
			if string(output) != "health compatibility proof failed\nexit status 1\n" {
				t.Fatalf("CLI emitted an unexpected or input-bearing error: %q", output)
			}
		})
	}
}

func TestDiagnosticTestManifestRejectsSourceDriftAndReceiptIsReproducible(t *testing.T) {
	contract := mustLoadDiagnosticContract(t)
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	head := strings.Repeat("a", 40)
	tested := strings.Repeat("b", 40)
	first, err := BuildDiagnosticCompatibilityReceipt(head, tested, "../..", contract, canaries)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildDiagnosticCompatibilityReceipt(head, tested, "../..", contract, canaries)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("compatibility receipt is not reproducible")
	}

	tempRoot := t.TempDir()
	for _, source := range contract.testManifest.Sources {
		raw := mustRead(t, filepath.Join("../..", filepath.FromSlash(source.Path)))
		destination := filepath.Join(tempRoot, filepath.FromSlash(source.Path))
		if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
			t.Fatal(err)
		}
		if source.Path == "internal/health/diagnostic_test.go" {
			raw = append(raw, []byte("\n// drift\n")...)
		}
		if err := os.WriteFile(destination, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := BuildDiagnosticCompatibilityReceipt(head, tested, tempRoot, contract, canaries); err == nil {
		t.Fatal("test source drift was accepted")
	}
}

func mustLoadDiagnosticContract(t *testing.T) DiagnosticContract {
	t.Helper()
	contract, err := LoadDiagnosticContract(diagnosticPinPath)
	if err != nil {
		t.Fatal(err)
	}
	return contract
}

func mustDiagnosticFixture(t *testing.T, contract DiagnosticContract, name string) []byte {
	t.Helper()
	raw, err := contract.ReadFixture(name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func diagnosticEnvelopeForCanary(t *testing.T, contract DiagnosticContract, canaries CanaryConfig, index int) DiagnosticEnvelope {
	t.Helper()
	raw := mustDiagnosticFixture(t, contract, "ready.json")
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	canary := canaries.Canaries[index]
	entry, ok := canaries.Entry(canary)
	if !ok {
		t.Fatal("configured canary is absent from catalog")
	}
	subject := document["subject"].(map[string]any)
	subject["source_id"] = contract.SourceID
	subject["provider_id"] = contract.ProviderID
	subject["dataset_id"] = entry.Aliases.DatasetID
	subject["operation_id"] = canary.OperationID
	updated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := contract.Decode(bytes.NewReader(updated))
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
