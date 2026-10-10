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
	model, err := newOperationReadModel(plan, testRegistryAPIMetadataPin(0, 0), nil, nil, now)
	if err != nil {
		t.Fatalf("construct pinned read model: %v", err)
	}
	planBinding := testOperationReadModelAttemptBinding(t, model, "synthetic_test", "synthetic-rest-list")
	observationBinding := planBinding
	model, err = newOperationReadModel(plan, testRegistryAPIMetadataPin(0, 0), nil, []OperationReadModelAttempt{{
		SourceID: "synthetic_test", OperationID: "synthetic-rest-list", AttemptState: "observed", ObservationAttemptState: "observed", ReceiptValidated: true, RequestStarted: &requestStarted, EverRequestStarted: true,
		LatestPlanBinding: planBinding, ObservationPlanBinding: &observationBinding,
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

func TestOperationReadModelKeepsObservationOnlyResultAcrossNewAttemptState(t *testing.T) {
	for _, nextState := range []string{"deferred", "claimed"} {
		t.Run(nextState, func(t *testing.T) {
			now := time.Date(2026, 10, 7, 5, 0, 0, 0, time.UTC)
			model := testOperationReadModelForAPIProgress(t, now)
			operationID := strings.Repeat("a", 63) + "1"
			binding := testOperationReadModelAttemptBinding(t, model, "data_go_kr", operationID)
			started := true
			observedAt := now.Add(-2 * time.Second)
			receivedAt := now.Add(-time.Second)
			status := 200
			observation := OperationReadModelAttempt{
				SourceID: "data_go_kr", OperationID: operationID, LatestPlanBinding: binding, ObservationPlanBinding: &binding,
				AttemptState: "observed", ObservationAttemptState: "observed", ReceiptValidated: true,
				RequestStarted: &started, EverRequestStarted: true,
				ResultState: "indeterminate", ResultCategory: "response_semantics_unestablished", HTTPStatus: status,
				ProviderObservedAt: observedAt, HealthReceivedAt: receivedAt, GatusDeliveryState: "not_applicable", UpdatedAt: now,
			}
			if err := model.ApplyAttempt(observation); err != nil {
				t.Fatalf("apply validated observation A: %v", err)
			}

			latest := OperationReadModelAttempt{
				SourceID: "data_go_kr", OperationID: operationID, LatestPlanBinding: binding, ObservationPlanBinding: &binding,
				AttemptState: nextState, ObservationAttemptState: "observed", EverRequestStarted: true,
				ResultState: "indeterminate", ResultCategory: "response_semantics_unestablished", HTTPStatus: status,
				ProviderObservedAt: observedAt, HealthReceivedAt: receivedAt, GatusDeliveryState: "not_applicable", UpdatedAt: now.Add(time.Second),
			}
			if nextState == "deferred" {
				notStarted := false
				latest.RequestStarted = &notStarted
				latest.ExecutionBlockReason = "quota_capacity"
			}
			if err := model.ApplyAttempt(latest); err != nil {
				t.Fatalf("apply newer no-observation attempt B: %v", err)
			}
			page, err := model.PageOperations(OperationPageQuery{APIID: "api-1", Limit: 10}, now.Add(2*time.Second))
			if err != nil || len(page.Operations) == 0 {
				t.Fatalf("read observation after attempt B: page=%#v err=%v", page, err)
			}
			var row *OperationReadModelRow
			for index := range page.Operations {
				if page.Operations[index].RegistryOperationID == operationID {
					row = &page.Operations[index]
					break
				}
			}
			if row == nil || row.AttemptState != nextState || !row.Attempted || row.ObservationAttemptState != "observed" || row.ResultCategory != "response_semantics_unestablished" || row.ResultState != "indeterminate" || row.ProviderHTTPStatus == nil || *row.ProviderHTTPStatus != status || row.GatusDeliveryState != "not_applicable" {
				t.Fatalf("new attempt state replaced or invalidated the prior observation: %#v", row)
			}
			if nextState == "deferred" && (row.RequestStarted == nil || *row.RequestStarted || row.ExecutionBlockReason != "quota_capacity") {
				t.Fatalf("deferred attempt state was not preserved independently: %#v", row)
			}
			if nextState == "claimed" && row.RequestStarted != nil {
				t.Fatalf("claimed attempt was projected as request-started: %#v", row)
			}
			encoded, err := json.Marshal(page)
			if err != nil || schemas.ValidateHealthRegistryOperationsPageV2(encoded) != nil {
				t.Fatalf("prior observation page failed the pinned schema after %s attempt: %s (%v)", nextState, encoded, err)
			}
		})
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

func TestOperationReadModelPageAcceptsSanitizedMetadataAcrossRows(t *testing.T) {
	now := time.Date(2026, 10, 7, 4, 0, 0, 0, time.UTC)
	model := testOperationReadModelForAPIProgress(t, now)
	model.rows[1].Purpose = "안전하게 정제된 Registry 설명"
	model.rows[1].PurposeState = "sanitized"

	page, err := model.PageOperations(OperationPageQuery{Limit: 2}, now)
	if err != nil || len(page.Operations) != 2 || page.Operations[1].PurposeState != "sanitized" {
		t.Fatalf("bounded page rejected a valid sanitized Registry field state: %#v (%v)", page, err)
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
		{SourceID: "data_go_kr", RegistryOperationID: operationID1, APIID: stringPointer("api-1"), Provider: "data.go.kr", AdapterID: "data-go-kr", Protocol: "REST", Title: "한글 제목", TitleState: "present", OperationName: "함수 1", OperationNameState: "present", Organization: "기관", OrganizationState: "present", Purpose: "한글 목적", PurposeState: "present", RequestPlanState: "complete", RuntimeBindingState: "bound", AdmissionState: "admitted", ObservationPeriodSeconds: int64Pointer(300), AttemptState: "none", ObservationAttemptState: "none", ObservationState: "unobserved", GatusDeliveryState: "not_ready"},
		{SourceID: "data_go_kr", RegistryOperationID: operationID2, APIID: stringPointer("api-1"), Provider: "data.go.kr", AdapterID: "data-go-kr", Protocol: "REST", Title: "다른 제목", TitleState: "present", OperationName: "함수 2", OperationNameState: "present", Organization: "기관", OrganizationState: "present", Purpose: "다른 목적", PurposeState: "present", RequestPlanState: "complete", RuntimeBindingState: "unbound", AdmissionState: "not_admitted", ObservationPeriodSeconds: nil, AttemptState: "none", ObservationAttemptState: "none", ObservationState: "unobserved", MissingReason: "runtime_unbound", GatusDeliveryState: "not_ready"},
		{SourceID: "data_go_kr", RegistryOperationID: operationID3, APIID: stringPointer("api-2"), Provider: "data.go.kr", AdapterID: "data-go-kr", Protocol: "SOAP", Title: "두 번째", TitleState: "present", OperationName: "함수 3", OperationNameState: "present", Organization: "기관", OrganizationState: "present", Purpose: "다른 목적", PurposeState: "present", RequestPlanState: "complete", RuntimeBindingState: "bound", AdmissionState: "admitted", ObservationPeriodSeconds: int64Pointer(300), AttemptState: "observed", ObservationAttemptState: "observed", RequestStarted: &pass, Attempted: true, ObservationState: "current_fail", ResultState: "unhealthy", ResultCategory: "provider_failure", ProviderObservedAt: timePointer(now.Add(-30 * time.Second)), HealthReceivedAt: timePointer(now.Add(-20 * time.Second)), GatusDeliveryState: "not_ready"},
		{SourceID: "ecos", RegistryOperationID: "ecos-statistic-search-102y004", Provider: "ECOS", AdapterID: "ecos", Protocol: "REST", OperationNameState: "missing", TitleState: "missing", OrganizationState: "missing", PurposeState: "missing", RequestPlanState: "incomplete", RuntimeBindingState: "unbound", AdmissionState: "not_admitted", InventoryUnknown: true, ObservationPeriodSeconds: int64Pointer(300), ObservationState: "unobserved", MissingReason: "inventory_unknown", AttemptState: "none", ObservationAttemptState: "none", GatusDeliveryState: "not_ready"},
	}
	model := &OperationReadModel{registryRevision: strings.Repeat("a", 40), manifestSHA: strings.Repeat("b", 64), indexSHA: strings.Repeat("c", 64), planSchemaSHA: strings.Repeat("d", 64), pageSchemaSHA: strings.Repeat("e", 64), metadataPin: testRegistryAPIMetadataPin(2, 3), generatedAt: now, inventoryUnknownScopes: 1, rows: rows}
	model.reindex()
	model.expectedBindings = make(map[string]operationReadModelPlanBinding, len(rows))
	for _, row := range rows {
		period := time.Duration(0)
		if row.ObservationPeriodSeconds != nil {
			period = time.Duration(*row.ObservationPeriodSeconds) * time.Second
		}
		key := operationReadModelIdentityKey(row.SourceID, row.RegistryOperationID)
		model.expectedBindings[key] = operationReadModelPlanBinding{SourceID: row.SourceID, OperationID: row.RegistryOperationID, RegistryRevision: model.registryRevision, ReleaseManifestSHA: model.manifestSHA, IndexSHA: model.indexSHA, ShardSHA: strings.Repeat("f", 64), ObservationPeriod: period}
	}
	requestStarted := true
	planBinding := testOperationReadModelAttemptBinding(t, model, "data_go_kr", operationID1)
	observationBinding := planBinding
	if err := model.ApplyAttempt(OperationReadModelAttempt{SourceID: "data_go_kr", OperationID: operationID1, LatestPlanBinding: planBinding, ObservationPlanBinding: &observationBinding, AttemptState: "observed", ObservationAttemptState: "observed", ReceiptValidated: true, RequestStarted: &requestStarted, EverRequestStarted: true, ResultState: "healthy", ResultCategory: "healthy", ProviderObservedAt: now.Add(-30 * time.Second), HealthReceivedAt: now.Add(-20 * time.Second), GatusDeliveryState: "readback_verified", GatusAcknowledgedAt: now.Add(-15 * time.Second), GatusReadbackAt: now.Add(-10 * time.Second), GatusObservedState: "healthy", UpdatedAt: now}); err != nil {
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

func TestOperationReadModelKeepsUnknownInventoryScopeAfterObservation(t *testing.T) {
	now := time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)
	model := testOperationReadModelForAPIProgress(t, now)
	operationID := "ecos-statistic-search-102y004"
	binding := testOperationReadModelAttemptBinding(t, model, "ecos", operationID)
	started := true
	if err := model.ApplyAttempt(OperationReadModelAttempt{
		SourceID: "ecos", OperationID: operationID, LatestPlanBinding: binding, ObservationPlanBinding: &binding,
		AttemptState: "observed", ObservationAttemptState: "observed", ReceiptValidated: true,
		RequestStarted: &started, EverRequestStarted: true, ResultState: "healthy", ResultCategory: "healthy",
		ProviderObservedAt: now.Add(-2 * time.Minute), HealthReceivedAt: now.Add(-time.Minute),
		GatusDeliveryState: "not_ready", UpdatedAt: now,
	}); err != nil {
		t.Fatalf("apply partial-scope observation: %v", err)
	}
	page, err := model.PageOperations(OperationPageQuery{Limit: 50}, now)
	if err != nil {
		t.Fatalf("read observed partial scope: %v", err)
	}
	var partial *OperationReadModelRow
	for index := range page.Operations {
		if page.Operations[index].SourceID == "ecos" && page.Operations[index].RegistryOperationID == operationID {
			partial = &page.Operations[index]
			break
		}
	}
	if partial == nil || !partial.InventoryUnknown || partial.MissingReason != "" || page.IdentityCounts.InventoryUnknownScopes != 1 || page.IdentityCounts.InventoryUnknownOperations != 1 {
		t.Fatalf("observation erased immutable inventory-unknown scope state: row=%#v counts=%#v", partial, page.IdentityCounts)
	}
}

func TestOperationReadModelPreservesIndeterminateAndRejectsContradictoryOrFutureEvidence(t *testing.T) {
	now := time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC)
	operationID := strings.Repeat("f", 64)
	model := &OperationReadModel{
		registryRevision: strings.Repeat("a", 40), manifestSHA: strings.Repeat("b", 64), indexSHA: strings.Repeat("c", 64),
		planSchemaSHA: strings.Repeat("d", 64), pageSchemaSHA: schemas.HealthRegistryOperationsPageV2SchemaSHA256(),
		metadataPin: testRegistryAPIMetadataPin(0, 0), generatedAt: now,
		rows: []OperationReadModelRow{{
			SourceID: "data_go_kr", RegistryOperationID: operationID, APIID: stringPointer("api-indeterminate"),
			Provider: "data.go.kr", AdapterID: "data-go-kr", Protocol: "REST", OperationNameState: "missing",
			TitleState: "missing", OrganizationState: "missing", PurposeState: "missing",
			RequestPlanState: "complete", RuntimeBindingState: "bound", AdmissionState: "admitted",
			ObservationPeriodSeconds: int64Pointer(300), AttemptState: "none", ObservationAttemptState: "none",
			ObservationState: "unobserved", GatusDeliveryState: "not_ready",
		}},
	}
	model.expectedBindings = make(map[string]operationReadModelPlanBinding, 1)
	model.expectedBindings[operationReadModelIdentityKey("data_go_kr", operationID)] = operationReadModelPlanBinding{
		SourceID: "data_go_kr", OperationID: operationID, RegistryRevision: model.registryRevision,
		ReleaseManifestSHA: model.manifestSHA, IndexSHA: model.indexSHA, ShardSHA: strings.Repeat("e", 64), ObservationPeriod: 5 * time.Minute,
	}
	model.reindex()
	model.staticRows = append([]OperationReadModelRow(nil), model.rows...)
	started := true
	planBinding := testOperationReadModelAttemptBinding(t, model, "data_go_kr", operationID)
	base := OperationReadModelAttempt{
		SourceID: "data_go_kr", OperationID: operationID, AttemptState: "observed", ObservationAttemptState: "observed",
		LatestPlanBinding: planBinding,
		ReceiptValidated:  true, RequestStarted: &started, EverRequestStarted: true,
		ProviderObservedAt: now.Add(-20 * time.Second), HealthReceivedAt: now.Add(-10 * time.Second), UpdatedAt: now,
		GatusDeliveryState: "not_ready",
	}
	indeterminate := base
	observationBinding := planBinding
	indeterminate.ObservationPlanBinding = &observationBinding
	indeterminate.ResultState, indeterminate.ResultCategory = "indeterminate", "observer_failure"
	if err := model.ApplyAttempt(indeterminate); err != nil {
		t.Fatalf("apply indeterminate receipt: %v", err)
	}
	progress, err := model.LookupAPIProgress([]string{"api-indeterminate"}, now)
	if err != nil || progress[0].CurrentIndeterminate != 1 || progress[0].CurrentFail != 0 || progress[0].CoverageState != "current_indeterminate" {
		t.Fatalf("indeterminate result was misreported as a provider failure or pass: %#v %v", progress, err)
	}
	page, err := model.PageOperations(OperationPageQuery{APIID: "api-indeterminate", Limit: 10}, now)
	if err != nil || len(page.Operations) != 1 || page.Operations[0].ObservationState != "current_indeterminate" || page.Operations[0].ResultState != "indeterminate" || page.Operations[0].ResultCategory != "observer_failure" {
		t.Fatalf("indeterminate state did not survive the public projection: %#v %v", page, err)
	}

	contradictory := base
	contradictory.ObservationPlanBinding = &observationBinding
	contradictory.ResultState, contradictory.ResultCategory = "unhealthy", "healthy"
	if err := model.ApplyAttempt(contradictory); !errors.Is(err, ErrOperationReadModelUnavailable) {
		t.Fatalf("unhealthy/healthy contradictory result pair was accepted: %v", err)
	}
	unknownCategory := base
	unknownCategory.ObservationPlanBinding = &observationBinding
	unknownCategory.ResultState, unknownCategory.ResultCategory = "unhealthy", "provider-secret-description"
	if err := model.ApplyAttempt(unknownCategory); !errors.Is(err, ErrOperationReadModelUnavailable) {
		t.Fatalf("unrecognized category reached the public model: %v", err)
	}

	future := base
	future.ObservationPlanBinding = &observationBinding
	future.ProviderObservedAt = now.Add(time.Minute)
	future.HealthReceivedAt = now.Add(time.Minute + 5*time.Second)
	future.UpdatedAt = now.Add(time.Minute + 10*time.Second)
	future.ResultState, future.ResultCategory = "healthy", "healthy"
	if err := model.ApplyAttempt(future); err != nil {
		t.Fatalf("persist well-formed future timestamp for fail-closed evaluation: %v", err)
	}
	page, err = model.PageOperations(OperationPageQuery{APIID: "api-indeterminate", Limit: 10}, now)
	if err != nil || len(page.Operations) != 1 || page.Operations[0].ObservationState != "unobserved" || page.Operations[0].MissingReason != "future_observation" || page.Operations[0].NextDueAt != nil {
		t.Fatalf("future provider timestamp counted as current coverage: %#v %v", page, err)
	}
	progress, err = model.LookupAPIProgress([]string{"api-indeterminate"}, now)
	if err != nil || progress[0].CurrentPass != 0 || progress[0].CurrentFail != 0 || progress[0].CurrentIndeterminate != 0 || progress[0].Unobserved != 1 || progress[0].MissingReasons["future_observation"] != 1 {
		t.Fatalf("future observation was counted in API coverage: %#v %v", progress, err)
	}

	badAck := base
	badAck.ObservationPlanBinding = &observationBinding
	badAck.ResultState, badAck.ResultCategory = "healthy", "healthy"
	badAck.GatusDeliveryState = "acknowledged"
	badAck.GatusAcknowledgedAt = now.Add(-15 * time.Second) // earlier than Health persistence
	if err := model.ApplyAttempt(badAck); !errors.Is(err, ErrOperationReadModelUnavailable) {
		t.Fatalf("Gatus acknowledgement before Health persistence was accepted: %v", err)
	}
	badReadback := base
	badReadback.ObservationPlanBinding = &observationBinding
	badReadback.ResultState, badReadback.ResultCategory = "healthy", "healthy"
	badReadback.GatusDeliveryState = "readback_verified"
	badReadback.GatusAcknowledgedAt = now.Add(-12 * time.Second)
	badReadback.GatusReadbackAt = now.Add(-11 * time.Second)
	badReadback.GatusObservedState = "healthy"
	if err := model.ApplyAttempt(badReadback); !errors.Is(err, ErrOperationReadModelUnavailable) {
		t.Fatalf("Gatus readback before Health persistence was accepted: %v", err)
	}

	futureAck := base
	futureAck.ObservationPlanBinding = &observationBinding
	futureAck.ResultState, futureAck.ResultCategory = "healthy", "healthy"
	futureAck.GatusDeliveryState = "acknowledged"
	futureAck.GatusAcknowledgedAt = now.Add(10 * time.Second)
	futureAck.UpdatedAt = now.Add(20 * time.Second)
	if err := model.ApplyAttempt(futureAck); err != nil {
		t.Fatalf("apply a later but internally ordered acknowledgement: %v", err)
	}
	page, err = model.PageOperations(OperationPageQuery{APIID: "api-indeterminate", Limit: 10}, now)
	if err != nil || len(page.Operations) != 1 || page.Operations[0].ObservationState != "current_pass" || page.Operations[0].GatusDeliveryState != "pending" || page.Operations[0].GatusAcknowledgedAt != nil {
		t.Fatalf("future Gatus acknowledgement was projected before its evaluation time: %#v %v", page, err)
	}

	futureReadback := base
	futureReadback.ObservationPlanBinding = &observationBinding
	futureReadback.ResultState, futureReadback.ResultCategory = "healthy", "healthy"
	futureReadback.GatusDeliveryState = "readback_verified"
	futureReadback.GatusAcknowledgedAt = now.Add(-5 * time.Second)
	futureReadback.GatusReadbackAt = now.Add(10 * time.Second)
	futureReadback.GatusObservedState = "healthy"
	futureReadback.UpdatedAt = now.Add(20 * time.Second)
	if err := model.ApplyAttempt(futureReadback); err != nil {
		t.Fatalf("apply later internally ordered Gatus readback: %v", err)
	}
	page, err = model.PageOperations(OperationPageQuery{APIID: "api-indeterminate", Limit: 10}, now)
	if err != nil || len(page.Operations) != 1 || page.Operations[0].GatusDeliveryState != "acknowledged" || page.Operations[0].GatusReadbackAt != nil || page.Operations[0].GatusObservedState != "" {
		t.Fatalf("future Gatus readback was projected before its evaluation time: %#v %v", page, err)
	}

	claimed := OperationReadModelAttempt{
		SourceID: "data_go_kr", OperationID: operationID, LatestPlanBinding: planBinding,
		AttemptState: "claimed", ObservationAttemptState: "none", GatusDeliveryState: "not_ready", UpdatedAt: now.Add(time.Minute),
	}
	if err := model.ApplyAttempt(claimed); err != nil {
		t.Fatalf("replace observed state with a full no-observation claim: %v", err)
	}
	page, err = model.PageOperations(OperationPageQuery{APIID: "api-indeterminate", Limit: 10}, now.Add(time.Minute))
	if err != nil || len(page.Operations) != 1 || page.Operations[0].ObservationAttemptState != "none" || page.Operations[0].ObservationState != "unobserved" || page.Operations[0].ResultState != "" || page.Operations[0].ResultCategory != "" || page.Operations[0].ProviderObservedAt != nil || page.Operations[0].HealthReceivedAt != nil || page.Operations[0].GatusDeliveryState != "not_ready" {
		t.Fatalf("no-observation replacement retained the previous result fields: %#v %v", page, err)
	}
}

func stringPointer(value string) *string     { return &value }
func int64Pointer(value int64) *int64        { return &value }
func timePointer(value time.Time) *time.Time { return &value }

func testOperationReadModelAttemptBinding(t *testing.T, model *OperationReadModel, sourceID, operationID string) OperationAttemptBinding {
	t.Helper()
	expected, ok := model.expectedBindings[operationReadModelIdentityKey(sourceID, operationID)]
	if !ok {
		t.Fatalf("missing synthetic expected binding for %s/%s", sourceID, operationID)
	}
	return OperationAttemptBinding{
		SourceID: expected.SourceID, OperationID: expected.OperationID, RegistryRevision: expected.RegistryRevision,
		ReleaseManifestSHA: expected.ReleaseManifestSHA, IndexSHA: expected.IndexSHA, ShardSHA: expected.ShardSHA,
		GatusKey: "public-data_registry-" + strings.Repeat("e", 64), ObservationPeriod: expected.ObservationPeriod,
	}
}

func testRegistryAPIMetadataPin(apiEntities, operations int) RegistryAPIMetadataPin {
	return RegistryAPIMetadataPin{RegistryRevision: strings.Repeat("a", 40), SourceSHA256: strings.Repeat("b", 64), CatalogSHA256: strings.Repeat("c", 64), ArtifactSHA256: strings.Repeat("d", 64), APIEntityCount: apiEntities, OperationCount: operations}
}
