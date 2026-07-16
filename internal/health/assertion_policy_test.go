package health

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const assertionPolicyPinPath = "../../config/registry/assertion-policy-contract-pin.json"
const assertionPolicyOperationOneRevision = "3ef6296cd2e2c0d568523f0474f8806cd607b8b6e4fd605ef491af78700793a4"

func TestAssertionPolicyLoadsExactRegistryRevisionAndCanaryBijection(t *testing.T) {
	contract, canaries := mustAssertionContract(t)
	if contract.RegistryRevision != AcceptedAssertionRegistryRevision || contract.PolicySet.ID != acceptedAssertionPolicySetID || contract.PolicySet.Version != 1 {
		t.Fatalf("unexpected exact policy identity: %#v", contract)
	}
	if len(contract.policyByOperation) != len(canaries.Canaries) || len(contract.policyByOperation) != 10 {
		t.Fatalf("policy/canary bijection changed: %d/%d", len(contract.policyByOperation), len(canaries.Canaries))
	}
	for _, operationID := range sortedOperationIDs(contract.policyByOperation) {
		if !sha256Pattern.MatchString(contract.policyByOperation[operationID].OperationRevisionSHA256) {
			t.Fatalf("operation revision is not exact: %s", operationID)
		}
	}
}

func TestAssertionPolicyContractPassFailAndEmptyArePolicyDriven(t *testing.T) {
	contract, _ := mustAssertionContract(t)
	binding := acceptedBindingForTest()
	cases := []struct {
		name   string
		fields []string
		want   string
	}{
		{"declared subset", []string{"dutyAddr"}, "pass"},
		{"undeclared field", []string{"__undeclared_field__"}, "fail"},
		{"empty payload", nil, "not_observed"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got := contract.Evaluate(AssertionEvaluationRequest{SchemaVersion: AssertionEvaluationSchemaVersion, OperationID: "dpr-op-00000001", OperationRevisionSHA256: assertionPolicyOperationOneRevision, Dimension: "contract", PolicyBinding: &binding, Observation: AssertionObservation{ResponseFields: test.fields}})
			if got.Outcome != test.want {
				t.Fatalf("got %q, want %q: %#v", got.Outcome, test.want, got)
			}
		})
	}
}

func TestAssertionPolicyUnassertedDimensionsNeverInferHealth(t *testing.T) {
	contract, _ := mustAssertionContract(t)
	binding := acceptedBindingForTest()
	for _, dimension := range []string{"transport", "presence", "semantic", "freshness"} {
		t.Run(dimension, func(t *testing.T) {
			for _, fields := range [][]string{nil, {"dutyAddr"}, {"__undeclared_field__"}} {
				got := contract.Evaluate(AssertionEvaluationRequest{SchemaVersion: AssertionEvaluationSchemaVersion, OperationID: "dpr-op-00000001", OperationRevisionSHA256: assertionPolicyOperationOneRevision, Dimension: dimension, PolicyBinding: &binding, Observation: AssertionObservation{ResponseFields: fields}})
				if got.Outcome != "not_observed" {
					t.Fatalf("%s inferred a health result from non-authoritative evidence: %#v", dimension, got)
				}
			}
		})
	}
}

func TestAssertionPolicyMissingMismatchedAndSupersededBindingsAreUnknown(t *testing.T) {
	contract, _ := mustAssertionContract(t)
	accepted := acceptedBindingForTest()
	mutations := map[string]func(*AssertionEvaluationRequest){
		"missing": func(request *AssertionEvaluationRequest) { request.PolicyBinding = nil },
		"artifact": func(request *AssertionEvaluationRequest) {
			request.PolicyBinding.ArtifactSHA256 = strings.Repeat("f", 64)
		},
		"version": func(request *AssertionEvaluationRequest) { request.PolicyBinding.PolicySetVersion = 2 },
		"vocabulary": func(request *AssertionEvaluationRequest) {
			request.PolicyBinding.DiagnosticVocabularySHA256 = strings.Repeat("e", 64)
		},
		"operation":          func(request *AssertionEvaluationRequest) { request.OperationID = "dpr-op-99999999" },
		"operation revision": func(request *AssertionEvaluationRequest) { request.OperationRevisionSHA256 = strings.Repeat("c", 64) },
		"superseded": func(request *AssertionEvaluationRequest) {
			active := accepted
			active.Path = "drafts/operation-assertion-policies/operation-assertion-policies.v2.json"
			active.PolicySetVersion = 2
			active.ArtifactSHA256 = strings.Repeat("b", 64)
			request.ActivePolicyBinding = &active
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			binding := accepted
			request := AssertionEvaluationRequest{SchemaVersion: AssertionEvaluationSchemaVersion, OperationID: "dpr-op-00000001", OperationRevisionSHA256: assertionPolicyOperationOneRevision, Dimension: "contract", PolicyBinding: &binding, Observation: AssertionObservation{ResponseFields: []string{"dutyAddr"}}}
			mutate(&request)
			if got := contract.Evaluate(request); got.Outcome != "unknown" {
				t.Fatalf("invalid or stale binding became a health result: %#v", got)
			}
		})
	}
}

func TestAssertionPolicyRequestRejectsUnsupportedEnumsAndEvidenceLeaks(t *testing.T) {
	binding := acceptedBindingForTest()
	base := AssertionEvaluationRequest{SchemaVersion: AssertionEvaluationSchemaVersion, OperationID: "dpr-op-00000001", OperationRevisionSHA256: assertionPolicyOperationOneRevision, Dimension: "contract", PolicyBinding: &binding, Observation: AssertionObservation{ResponseFields: []string{"dutyAddr"}}}
	encoded, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"version":            strings.Replace(string(encoded), AssertionEvaluationSchemaVersion, "datapan.health-assertion-evaluation.v2", 1),
		"dimension":          strings.Replace(string(encoded), `"dimension":"contract"`, `"dimension":"latency"`, 1),
		"http status":        strings.Replace(string(encoded), `"observation":{`, `"observation":{"http_status":200,`, 1),
		"freshness boundary": strings.Replace(string(encoded), `"observation":{`, `"observation":{"reference_time":"2026-07-17T00:00:00Z","actual_time":"2026-07-16T23:55:00Z","maximum_age_seconds":300,`, 1),
		"raw row":            strings.Replace(string(encoded), `"observation":{`, `"observation":{"row":{"value":"secret"},`, 1),
		"url":                strings.Replace(string(encoded), `"dutyAddr"`, `"provider_url"`, 1),
		"credential":         strings.Replace(string(encoded), `"dutyAddr"`, `"serviceKey"`, 1),
		"hash":               strings.Replace(string(encoded), `"dutyAddr"`, `"`+strings.Repeat("a", 64)+`"`, 1),
		"duplicate":          strings.Replace(string(encoded), `"dutyAddr"`, `"dutyAddr","dutyAddr"`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAssertionEvaluationRequest(bytes.NewBufferString(raw)); err == nil {
				t.Fatal("unsafe or unsupported assertion request was accepted")
			}
		})
	}
}

func TestAssertionPolicyPinnedBytesFailClosedOnDrift(t *testing.T) {
	temp := t.TempDir()
	sourceBase := filepath.Dir(assertionPolicyPinPath)
	for _, name := range []string{"assertion-policy-contract-pin.json", "assertions/datapan.operation-assertion-policies.v1.schema.json", "assertions/operation-assertion-policies.v1.json", "assertions/datapan-health-consumer-proof.v1.json", "assertions/release-candidate.v1.json"} {
		raw, err := os.ReadFile(filepath.Join(sourceBase, name))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(temp, name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(name, "operation-assertion-policies.v1.json") && !strings.Contains(name, "schema") {
			raw = append(raw, '\n')
		}
		if err := os.WriteFile(target, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadAssertionPolicyContract(filepath.Join(temp, "assertion-policy-contract-pin.json"), canaries); err == nil {
		t.Fatal("drifted Registry policy bytes were accepted")
	}
}

func TestAssertionPolicyLeavesAvailabilityProjectionUnchanged(t *testing.T) {
	receipt := Receipt{SchemaVersion: SchemaVersion, ObservedAt: time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC), Operation: Operation{OperationKey: "op"}, Observation: Observation{LatencyMS: 125}, Assessment: Assessment{Outcome: "unhealthy", Category: "provider"}}
	want := Summarize(receipt, "public-data_example")
	contract, _ := mustAssertionContract(t)
	binding := acceptedBindingForTest()
	_ = contract.Evaluate(AssertionEvaluationRequest{SchemaVersion: AssertionEvaluationSchemaVersion, OperationID: "dpr-op-00000001", OperationRevisionSHA256: assertionPolicyOperationOneRevision, Dimension: "semantic", PolicyBinding: &binding})
	got := Summarize(receipt, "public-data_example")
	if got != want {
		t.Fatalf("assertion evaluation changed availability v1 projection: %#v != %#v", got, want)
	}
}

func TestAssertionPolicyCompatibilityReceiptBindsExactCodeTestsAndBoundaries(t *testing.T) {
	contract, _ := mustAssertionContract(t)
	receipt, err := BuildAssertionCompatibilityReceipt(strings.Repeat("a", 40), strings.Repeat("b", 40), "../..", contract)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "consumer_compatible" || receipt.RegistryRevision != AcceptedAssertionRegistryRevision || len(receipt.Operations) != 10 || len(receipt.Cases) != 11 || len(receipt.SourceProof.Tests) < 7 {
		t.Fatalf("compatibility evidence is incomplete: %#v", receipt)
	}
	if receipt.Boundaries.AvailabilityV1 != "unchanged" || receipt.Boundaries.ArchiveV1 != "unchanged" || receipt.Boundaries.ProviderRuntime != "not_invoked" || receipt.Boundaries.Deployment != "not_performed" {
		t.Fatalf("compatibility boundaries expanded: %#v", receipt.Boundaries)
	}
	second, err := BuildAssertionCompatibilityReceipt(strings.Repeat("a", 40), strings.Repeat("b", 40), "../..", contract)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, _ := json.Marshal(receipt)
	secondJSON, _ := json.Marshal(second)
	if !bytes.Equal(firstJSON, secondJSON) {
		t.Fatal("compatibility receipt is not reproducible")
	}
}

func mustAssertionContract(t *testing.T) (AssertionPolicyContract, CanaryConfig) {
	t.Helper()
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	contract, err := LoadAssertionPolicyContract(assertionPolicyPinPath, canaries)
	if err != nil {
		t.Fatal(err)
	}
	return contract, canaries
}

func acceptedBindingForTest() AssertionPolicyBinding {
	return AssertionPolicyBinding{Path: acceptedAssertionPolicyPath, PolicySetID: acceptedAssertionPolicySetID, ArtifactSHA256: AcceptedAssertionPolicyArtifactSHA256, PolicySetVersion: acceptedAssertionPolicySetVersion, DiagnosticVocabularySHA256: AcceptedAssertionDiagnosticVocabularySHA}
}
