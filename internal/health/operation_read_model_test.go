package health

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

func TestOperationReadModelBuildsPinnedPageAndSeparatesProviderAndHealthTimes(t *testing.T) {
	root, binding, _ := writeSyntheticOperationObservationPlan(t, false)
	plan, err := LoadPinnedOperationObservationPlan(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 2, 0, 0, 0, time.UTC)
	requestStarted := true
	model, err := NewOperationReadModel(plan, testRegistryAPIMetadataPin(0, 0), nil, []OperationReadModelAttempt{{
		SourceID: "synthetic_test", OperationID: "synthetic-rest-list", AttemptState: "observed", ReceiptValidated: true, RequestStarted: &requestStarted, EverRequestStarted: true,
		ResultState: "healthy", ResultCategory: "healthy", ProviderObservedAt: now.Add(-10 * time.Minute), HealthReceivedAt: now.Add(-9 * time.Minute),
		GatusDeliveryState: "acknowledged", GatusAcknowledgedAt: now.Add(-8 * time.Minute), UpdatedAt: now,
	}}, now)
	if err != nil {
		t.Fatalf("construct read model: %v", err)
	}
	page, err := model.PageOperations(OperationPageQuery{Limit: 1}, now)
	if err != nil {
		t.Fatalf("read first page: %v", err)
	}
	if page.SchemaVersion != RegistryOperationsPageSchemaVersion || page.TotalAfterSearch != 2 || len(page.Operations) != 1 || page.NextCursor == "" {
		t.Fatalf("unexpected first page: %#v", page)
	}
	row := page.Operations[0]
	if row.RegistryOperationID != "synthetic-rest-list" || row.ObservationState != "current_pass" || row.AttemptState != "observed" || row.RequestStarted == nil || !*row.RequestStarted || row.GatusDeliveryState != "acknowledged" || row.GatusReadbackAt != nil || row.HealthReceivedAt == nil || row.ProviderObservedAt == nil || !row.HealthReceivedAt.After(*row.ProviderObservedAt) {
		t.Fatalf("provider attempt, persistence, and Gatus ack were conflated: %#v", row)
	}
	if page.IdentityCounts.Known != 2 || page.IdentityCounts.Claimed != 0 || page.IdentityCounts.Attempted != 1 || page.IdentityCounts.Persisted != 1 || page.IdentityCounts.Acknowledged != 1 || page.IdentityCounts.ReadbackVerified != 0 || page.IdentityCounts.DeliveryPending != 0 {
		t.Fatalf("unexpected identity counts: %#v", page.IdentityCounts)
	}
	encoded, err := json.Marshal(page)
	if err != nil || schemas.ValidateHealthRegistryOperationsPageV2(encoded) != nil {
		t.Fatalf("page did not satisfy pinned v2 schema: %s (%v)", encoded, err)
	}
	second, err := model.PageOperations(OperationPageQuery{Limit: 1, Cursor: page.NextCursor}, now)
	if err != nil || len(second.Operations) != 1 || second.Operations[0].RegistryOperationID != "synthetic-soap-read" || second.NextCursor != "" {
		t.Fatalf("next cursor did not advance deterministically: %#v %v", second, err)
	}
	if _, err := model.PageOperations(OperationPageQuery{Limit: 1, APIID: "different", Cursor: page.NextCursor}, now); !errors.Is(err, ErrOperationReadModelQuery) {
		t.Fatalf("cursor was not bound to its filter: %v", err)
	}
	late, err := model.PageOperations(OperationPageQuery{Limit: 50}, now.Add(2*time.Hour))
	if err != nil || late.IdentityCounts.Missing != 2 || late.IdentityCounts.Late != 1 || late.Operations[0].ObservationState != "stale" {
		t.Fatalf("stale/late identities were not derived from the explicit cadence: %#v %v", late, err)
	}
}

func TestOperationReadModelExactAPIJoinProgressAndSafeSearch(t *testing.T) {
	readNow := time.Date(2026, 10, 7, 4, 0, 0, 0, time.UTC)
	model := testOperationReadModelForAPIProgress(t, readNow)
	progress, err := model.LookupAPIProgress([]string{"api-1", "api-2"}, readNow)
	if err != nil || len(progress) != 2 {
		t.Fatalf("bounded API rollup lookup failed: %#v %v", progress, err)
	}
	if progress[0].TotalFunctions != 2 || progress[0].ConfiguredAdmitted != 1 || progress[0].CurrentPass != 1 || progress[0].Unobserved != 1 || progress[0].MissingReasons["runtime_unbound"] != 1 {
		t.Fatalf("API rollup did not use operation identities and admission evidence: %#v", progress[0])
	}
	if progress[1].TotalFunctions != 1 || progress[1].CurrentFail != 1 {
		t.Fatalf("second API progress was not isolated by exact api_id: %#v", progress[1])
	}
	tooMany := make([]string, operationReadModelMaximumAPIIDs+1)
	for i := range tooMany {
		tooMany[i] = "api-1"
	}
	if _, err := model.LookupAPIProgress(tooMany, readNow); !errors.Is(err, ErrOperationReadModelQuery) {
		t.Fatalf("more than 50 API IDs were accepted: %v", err)
	}
	first, err := model.PageOperations(OperationPageQuery{APIID: "api-1", Limit: 1}, readNow)
	if err != nil || first.TotalAfterSearch != 2 || len(first.Operations) != 1 || first.NextCursor == "" {
		t.Fatalf("API detail page was not bounded: %#v %v", first, err)
	}
	match, err := model.PageOperations(OperationPageQuery{APIID: "api-1", Query: "한글 목적", Limit: 10}, readNow)
	if err != nil || len(match.Operations) != 1 || match.Operations[0].RegistryOperationID != strings.Repeat("a", 63)+"1" {
		t.Fatalf("safe Korean purpose search failed: %#v %v", match, err)
	}
	if _, err := model.PageOperations(OperationPageQuery{Limit: 1, Query: "https://provider.example/?secret=1"}, readNow); !errors.Is(err, ErrOperationReadModelQuery) {
		t.Fatalf("URL query was accepted as a public filter: %v", err)
	}
	if _, err := model.PageOperations(OperationPageQuery{Limit: 51}, readNow); !errors.Is(err, ErrOperationReadModelQuery) {
		t.Fatalf("page larger than 50 was accepted: %v", err)
	}
}

func TestOperationReadModelOnlyJoinsDataGoKrByExactDatasetIDAndSanitizesText(t *testing.T) {
	metadata := &RegistryOperationMetadata{RegistryOperationID: strings.Repeat("a", 64), APIID: "api-1", OperationName: "조회", OperationNameState: "present", Title: "한글 제목", TitleState: "present", Organization: "기관 A", OrganizationState: "present", Purpose: "안전한 목적", PurposeState: "present"}
	record := OperationObservationPlanRecord{SourceID: "data_go_kr", DatasetID: "api-1", OperationID: strings.Repeat("a", 64), Protocol: "REST", Provider: "data.go.kr", AdapterID: "data-go-kr", RequestPlanStatus: "incomplete", RuntimeBindingStatus: "unbound", AdmissionStatus: "not_admitted"}
	row := operationReadModelRow(record, metadata)
	if row.APIID == nil || *row.APIID != "api-1" || row.Title != "한글 제목" || row.Organization != "기관 A" || row.PurposeState != "present" {
		t.Fatalf("exact Registry API metadata join failed: %#v", row)
	}
	record.SourceID = "ecos"
	if joined := operationReadModelRow(record, metadata); joined.APIID != nil || joined.TitleState != "missing" {
		t.Fatalf("non-data.go.kr scope was guessed into an API entity: %#v", joined)
	}
	for _, unsafeValue := range []string{"serviceKey=SYNTHETIC_SECRET", "https://example.org/path?token=hidden", "Use 10.1.2.3 for internal access", "GET /v1/private"} {
		metadata.Title = unsafeValue
		metadata.TitleState = "present"
		record.SourceID = "data_go_kr"
		unsafe := operationReadModelRow(record, metadata)
		if unsafe.Title != "" || unsafe.TitleState != "unsafe" {
			t.Fatalf("unsafe metadata text was projected: input=%q row=%#v", unsafeValue, unsafe)
		}
	}
}

func testOperationReadModelForAPIProgress(t *testing.T, now time.Time) *OperationReadModel {
	t.Helper()
	pass := true
	operationID1 := strings.Repeat("a", 63) + "1"
	operationID2 := strings.Repeat("a", 63) + "2"
	operationID3 := strings.Repeat("a", 63) + "3"
	rows := []OperationReadModelRow{
		{SourceID: "data_go_kr", RegistryOperationID: operationID1, APIID: stringPointer("api-1"), Provider: "data.go.kr", AdapterID: "data-go-kr", Protocol: "REST", Title: "한글 제목", TitleState: "present", OperationNameState: "present", Organization: "기관", OrganizationState: "present", Purpose: "한글 목적", PurposeState: "present", RequestPlanState: "complete", RuntimeBindingState: "bound", AdmissionState: "admitted", ObservationPeriodSeconds: int64Pointer(300), AttemptState: "none", ObservationState: "unobserved", GatusDeliveryState: "not_ready"},
		{SourceID: "data_go_kr", RegistryOperationID: operationID2, APIID: stringPointer("api-1"), Provider: "data.go.kr", AdapterID: "data-go-kr", Protocol: "REST", Title: "다른 제목", TitleState: "present", OperationNameState: "present", Organization: "기관", OrganizationState: "present", Purpose: "다른 목적", PurposeState: "present", RequestPlanState: "complete", RuntimeBindingState: "unbound", AdmissionState: "not_admitted", ObservationState: "unobserved", MissingReason: "runtime_unbound", AttemptState: "none", GatusDeliveryState: "not_ready"},
		{SourceID: "data_go_kr", RegistryOperationID: operationID3, APIID: stringPointer("api-2"), Provider: "data.go.kr", AdapterID: "data-go-kr", Protocol: "SOAP", Title: "두 번째", TitleState: "present", OperationNameState: "present", Organization: "기관", OrganizationState: "present", Purpose: "다른 목적", PurposeState: "present", RequestPlanState: "complete", RuntimeBindingState: "bound", AdmissionState: "admitted", ObservationPeriodSeconds: int64Pointer(300), AttemptState: "observed", RequestStarted: &pass, ObservationState: "current_fail", ResultCategory: "provider_failure", ProviderObservedAt: timePointer(now.Add(-30 * time.Second)), HealthReceivedAt: timePointer(now.Add(-20 * time.Second)), GatusDeliveryState: "not_ready"},
		{SourceID: "ecos", RegistryOperationID: "ecos-statistic-search-102y004", Provider: "ECOS", AdapterID: "ecos", Protocol: "REST", TitleState: "missing", OrganizationState: "missing", PurposeState: "missing", RequestPlanState: "incomplete", RuntimeBindingState: "unbound", AdmissionState: "not_admitted", ObservationState: "unobserved", MissingReason: "inventory_unknown", AttemptState: "none", GatusDeliveryState: "not_ready"},
	}
	model := &OperationReadModel{registryRevision: strings.Repeat("a", 40), manifestSHA: strings.Repeat("b", 64), indexSHA: strings.Repeat("c", 64), planSchemaSHA: strings.Repeat("d", 64), pageSchemaSHA: strings.Repeat("e", 64), metadataPin: testRegistryAPIMetadataPin(2, 3), generatedAt: now, inventoryUnknownScopes: 1, rows: rows}
	model.reindex()
	requestStarted := true
	if err := model.ApplyAttempt(OperationReadModelAttempt{SourceID: "data_go_kr", OperationID: operationID1, AttemptState: "observed", ReceiptValidated: true, RequestStarted: &requestStarted, EverRequestStarted: true, ResultState: "healthy", ResultCategory: "healthy", ProviderObservedAt: now.Add(-30 * time.Second), HealthReceivedAt: now.Add(-20 * time.Second), GatusDeliveryState: "readback_verified", GatusAcknowledgedAt: now.Add(-15 * time.Second), GatusReadbackAt: now.Add(-10 * time.Second), GatusObservedState: "healthy", UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	return model
}

func TestOperationReadModelProjectionDoesNotExposeProviderTargetsOrRows(t *testing.T) {
	now := time.Now().UTC()
	model := testOperationReadModelForAPIProgress(t, now)
	page, err := model.PageOperations(OperationPageQuery{Limit: 50}, now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"https://", "?secret=", "SYNTHETIC_SECRET", "response_body", "credential_scope", "quota_policy"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("public projection contains forbidden field/value marker %q", forbidden)
		}
	}
}

func stringPointer(value string) *string     { return &value }
func int64Pointer(value int64) *int64        { return &value }
func timePointer(value time.Time) *time.Time { return &value }

func testRegistryAPIMetadataPin(apiEntities, operations int) RegistryAPIMetadataPin {
	return RegistryAPIMetadataPin{RegistryRevision: strings.Repeat("a", 40), SourceSHA256: strings.Repeat("b", 64), CatalogSHA256: strings.Repeat("c", 64), ArtifactSHA256: strings.Repeat("d", 64), APIEntityCount: apiEntities, OperationCount: operations}
}
