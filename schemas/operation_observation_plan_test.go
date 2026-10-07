package schemas

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestOperationObservationPlanSchemaMatchesRegistryContractPin(t *testing.T) {
	const registryRevision = "0da541ff40fdc396ab855cc92520a56403de46d9"
	const sourceSchemaDigest = "d5b441d04c642a99c320eee8355d4aa6541c3699561b64bb2bf297e207a09533"
	localDigest := sha256.Sum256(operationObservationPlanSchema)
	if hex.EncodeToString(localDigest[:]) != sourceSchemaDigest {
		t.Fatal("embedded operation-observation-plan schema differs from Registry pin")
	}
	path := filepath.Join("..", "config", "registry", "operation-observation-plan-contract-pin.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var pin struct {
		SchemaVersion    string `json:"schema_version"`
		RegistryRevision string `json:"registry_revision"`
		SchemaContract   struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"schema_contract"`
	}
	if err := json.Unmarshal(raw, &pin); err != nil {
		t.Fatal(err)
	}
	if pin.SchemaVersion != "datapan.health-operation-observation-plan-contract-pin.v1" || pin.RegistryRevision != registryRevision || pin.SchemaContract.Path != "schemas/datapan.operation-observation-plan.v1.schema.json" || pin.SchemaContract.SHA256 != sourceSchemaDigest {
		t.Fatal("Health contract pin does not match the reviewed Registry schema")
	}
}

func TestOperationObservationPlanSchemaAcceptsSyntheticRESTAndSOAPContracts(t *testing.T) {
	for _, path := range []string{
		"../testdata/operation-observation-plan/synthetic-rest-list.json",
		"../testdata/operation-observation-plan/synthetic-soap-read.json",
	} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateOperationObservationPlanV1(data); err != nil {
				t.Fatalf("synthetic operation plan rejected: %v", err)
			}
		})
	}
}

func TestOperationObservationPlanSchemaRejectsUnknownSensitiveFields(t *testing.T) {
	data, err := os.ReadFile("../testdata/operation-observation-plan/synthetic-rest-list.json")
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	runtimeBinding := value["runtime_binding"].(map[string]any)
	runtimeBinding["credential_value"] = "SYNTHETIC_SECRET"
	mutated, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateOperationObservationPlanV1(mutated); err == nil {
		t.Fatal("schema accepted an unrecognized credential-value field")
	}
}

func TestOperationObservationPlanSchemaRejectsAdmissionContradictions(t *testing.T) {
	for _, mutate := range []struct {
		name string
		fn   func(map[string]any)
	}{
		{
			name: "incomplete request plan",
			fn: func(document map[string]any) {
				request := document["request_plan"].(map[string]any)
				request["status"] = "incomplete"
				request["missing_fields"] = []any{"method_authority"}
			},
		},
		{
			name: "unbound runtime",
			fn: func(document map[string]any) {
				runtime := document["runtime_binding"].(map[string]any)
				runtime["status"] = "unbound"
				runtime["missing_fields"] = []any{"credential_entitlement_reference"}
				delete(runtime, "credential_reference")
				delete(runtime, "credential_scope_key")
				delete(runtime, "observation_period_seconds")
				delete(runtime, "quota_policies")
			},
		},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			data, err := os.ReadFile("../testdata/operation-observation-plan/synthetic-rest-list.json")
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]any
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			mutate.fn(document)
			mutated, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateOperationObservationPlanV1(mutated); err == nil {
				t.Fatal("schema accepted admitted record without a complete request plan and bound runtime")
			}
		})
	}
}
