package schemas_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
	"github.com/StatPan/datapan-health/schemas"
)

func TestHealthRegistryOperationsPageV2Schema(t *testing.T) {
	const expectedSchemaSHA256 = "6e7459c0e7e5f92924076961f083231bfe4a899a24e2864986901a3edb4ade97"
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
			AttemptState: "none", ObservationState: "unobserved", GatusDeliveryState: "not_ready",
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
}

func schemaStringPointer(value string) *string { return &value }
