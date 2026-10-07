package schemas_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
	"github.com/StatPan/datapan-health/schemas"
)

func TestHealthRegistryOperationsPageV2Schema(t *testing.T) {
	const expectedSchemaSHA256 = "ebdcb86e114b52887fd2a34f13ae9611e8932d984f88fb1632bf0595a4918405"
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
			RequestPlanState: "incomplete", RuntimeBindingState: "unbound", AdmissionState: "not_admitted", InventoryUnknown: false, MissingReason: "request_plan_incomplete",
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
	page.Operations[0].Purpose = "안전하게 정제된 설명"
	page.Operations[0].PurposeState = "sanitized"
	raw, err = json.Marshal(page)
	if err != nil || schemas.ValidateHealthRegistryOperationsPageV2(raw) != nil {
		t.Fatalf("valid Registry-sanitized metadata state was rejected: %s (%v)", raw, err)
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	operations := object["operations"].([]any)
	operation := operations[0].(map[string]any)
	delete(operation, "inventory_unknown")
	raw, _ = json.Marshal(object)
	if err := schemas.ValidateHealthRegistryOperationsPageV2(raw); err == nil {
		t.Fatal("schema accepted an operation row without immutable inventory scope state")
	}
	operation["inventory_unknown"] = false
	object["unmodeled_endpoint"] = "omitted"
	raw, _ = json.Marshal(object)
	if err := schemas.ValidateHealthRegistryOperationsPageV2(raw); err == nil {
		t.Fatal("schema accepted an unmodeled endpoint field")
	}
	delete(object, "unmodeled_endpoint")
	operations = object["operations"].([]any)
	operation = operations[0].(map[string]any)
	operation["observation_state"] = "current_pass"
	operation["result_state"] = "unhealthy"
	operation["result_category"] = "healthy"
	raw, _ = json.Marshal(object)
	if err := schemas.ValidateHealthRegistryOperationsPageV2(raw); err == nil {
		t.Fatal("schema accepted a contradictory unhealthy/healthy result as a current pass")
	}

	operation = operations[0].(map[string]any)
	observedAt := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	receivedAt := observedAt.Add(time.Second)
	requestStarted := true
	status := 204
	page.Operations[0].AttemptState = "observed"
	page.Operations[0].ObservationAttemptState = "observed"
	page.Operations[0].RequestStarted = &requestStarted
	page.Operations[0].Attempted = true
	page.Operations[0].ObservationState = "current_indeterminate"
	page.Operations[0].ResultState = "indeterminate"
	page.Operations[0].ResultCategory = "response_semantics_unestablished"
	page.Operations[0].ProviderHTTPStatus = &status
	page.Operations[0].ProviderObservedAt = &observedAt
	page.Operations[0].HealthReceivedAt = &receivedAt
	page.Operations[0].GatusDeliveryState = "not_applicable"
	raw, err = json.Marshal(page)
	if err != nil || schemas.ValidateHealthRegistryOperationsPageV2(raw) != nil {
		t.Fatalf("valid observation-only response was rejected: %s (%v)", raw, err)
	}
	page.Operations[0].GatusDeliveryState = "readback_verified"
	raw, _ = json.Marshal(page)
	if err := schemas.ValidateHealthRegistryOperationsPageV2(raw); err == nil {
		t.Fatal("schema accepted an observation-only response as Gatus-delivered")
	}
	page.Operations[0].GatusDeliveryState = "not_applicable"
	requestNotStarted := false
	page.Operations[0].AttemptState = "deferred"
	page.Operations[0].ExecutionBlockReason = "quota_capacity"
	page.Operations[0].RequestStarted = &requestNotStarted
	raw, _ = json.Marshal(page)
	if err := schemas.ValidateHealthRegistryOperationsPageV2(raw); err != nil {
		t.Fatalf("schema rejected a prior observation after a deferred attempt: %s (%v)", raw, err)
	}
	page.Operations[0].Attempted = false
	raw, _ = json.Marshal(page)
	if err := schemas.ValidateHealthRegistryOperationsPageV2(raw); err == nil {
		t.Fatal("schema accepted an observation-only result without sticky request evidence")
	}
}

func schemaStringPointer(value string) *string { return &value }
