package schemas_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
	"github.com/StatPan/datapan-health/schemas"
)

func TestHealthRegistryOperationsPageV2Schema(t *testing.T) {
	const expectedSchemaSHA256 = "3c7cb725094cf2d143c6eddce0818e87731d4c69fce14ee8aef419f552688516"
	if got := schemas.HealthRegistryOperationsPageV2SchemaSHA256(); got != expectedSchemaSHA256 {
		t.Fatalf("pinned page schema digest = %s, want %s", got, expectedSchemaSHA256)
	}
	page := health.OperationReadModelPage{
		SchemaVersion: health.RegistryOperationsPageSchemaVersion,
		GeneratedAt:   time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC), ReadModelGeneratedAt: time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC),
		RegistryRevision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReleaseManifestSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		IndexSHA256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", PlanSchemaSHA256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", PageSchemaSHA256: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		MetadataRegistryRevision: "ffffffffffffffffffffffffffffffffffffffff", MetadataSourceSHA256: "1111111111111111111111111111111111111111111111111111111111111111", MetadataCatalogSHA256: "2222222222222222222222222222222222222222222222222222222222222222", MetadataArtifactSHA256: "3333333333333333333333333333333333333333333333333333333333333333", MetadataAPIEntityCount: 1, MetadataOperationCount: 1,
		IdentityCounts: health.OperationReadModelIdentityCounts{Known: 1, InventoryUnknownScopes: 0, InventoryUnknownOperations: 0, Missing: 1}, Limit: 50, TotalAfterSearch: 1,
		Operations: []health.OperationReadModelRow{{
			SourceID: "data_go_kr", RegistryOperationID: "operation-1", Provider: "data.go.kr", AdapterID: "data-go-kr", Protocol: "REST",
			APIID: schemaStringPointer("api-1"), OperationNameState: "missing", TitleState: "missing", OrganizationState: "missing", PurposeState: "missing",
			RequestPlanState: "incomplete", RuntimeBindingState: "unbound", AdmissionState: "not_admitted", MissingReason: "request_plan_incomplete",
			AttemptState: "none", ObservationAttemptState: "none", ObservationState: "unobserved", GatusDeliveryState: "not_ready",
		}},
	}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateHealthRegistryOperationsPageV2(raw); err != nil {
		t.Fatalf("valid page rejected: %v", err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["unmodeled_endpoint"] = "omitted"
	raw, _ = json.Marshal(object)
	if err := schemas.ValidateHealthRegistryOperationsPageV2(raw); err == nil {
		t.Fatal("schema accepted an unmodeled endpoint field")
	}
	delete(object, "unmodeled_endpoint")
	operations := object["operations"].([]any)
	operation := operations[0].(map[string]any)
	operation["observation_state"] = "current_pass"
	operation["result_state"] = "unhealthy"
	operation["result_category"] = "healthy"
	raw, _ = json.Marshal(object)
	if err := schemas.ValidateHealthRegistryOperationsPageV2(raw); err == nil {
		t.Fatal("schema accepted a contradictory unhealthy/healthy result as a current pass")
	}
}

func schemaStringPointer(value string) *string { return &value }
