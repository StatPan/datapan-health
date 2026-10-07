package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

type staticPublicRegistryOperations struct {
	page     OperationReadModelPage
	progress []OperationAPIProgress
	lookup   []OperationReadModelRow
	err      error
}

func (source staticPublicRegistryOperations) PageOperations(OperationPageQuery, time.Time) (OperationReadModelPage, error) {
	return source.page, source.err
}

func (source staticPublicRegistryOperations) LookupAPIProgress([]string, time.Time) ([]OperationAPIProgress, error) {
	return source.progress, source.err
}

func (source staticPublicRegistryOperations) LookupPublicOperationRows([]RegistryOperationLookupIdentity, time.Time) ([]OperationReadModelRow, error) {
	return source.lookup, source.err
}

func TestParsePublicOperationPageQueryIsBoundedAndSafe(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{name: "defaults to bounded page"},
		{name: "safe Korean filter", query: "api_id=api-123&q=" + url.QueryEscape("기상 관측") + "&limit=25"},
		{name: "opaque cursor", query: "cursor=eyJ2IjoidjIifQ"},
		{name: "unknown parameter", query: "target=https%3A%2F%2Fprovider.example", wantErr: true},
		{name: "duplicate parameter", query: "limit=10&limit=20", wantErr: true},
		{name: "oversized page", query: "limit=51", wantErr: true},
		{name: "zero page", query: "limit=0", wantErr: true},
		{name: "credential search", query: "q=" + url.QueryEscape("service_key=secret"), wantErr: true},
		{name: "url search", query: "q=" + url.QueryEscape("https://provider.example/path?key=secret"), wantErr: true},
		{name: "invalid cursor", query: "cursor=" + url.QueryEscape("https://internal.example"), wantErr: true},
		{name: "malformed escape", query: "q=%zz", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestURL, err := url.Parse("/datapan/v2/operations")
			if err != nil {
				t.Fatal(err)
			}
			requestURL.RawQuery = test.query
			got, err := parsePublicOperationPageQuery(requestURL)
			if test.wantErr {
				if err == nil {
					t.Fatalf("query accepted: %#v", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got.Limit < 1 || got.Limit > operationReadModelMaximumPage {
				t.Fatalf("page was not bounded: %#v", got)
			}
			if test.query == "" && got.Limit != operationReadModelMaximumPage {
				t.Fatalf("default page size=%d", got.Limit)
			}
		})
	}
}

func TestParsePublicHTMLDetailCursorIsBoundedAndSafe(t *testing.T) {
	metadata := testRegistryAPIMetadata(t)
	api := metadata.APIs[0]
	valid := httptest.NewRequest(http.MethodGet, "/datapan/apis/"+url.PathEscape(api.RegistryAPIID)+"/?cursor=eyJvIjoiMSJ9&q="+url.QueryEscape("기상 관측"), nil)
	parsed, status := parsePublicHTMLRequest(valid)
	if status != http.StatusOK || parsed.kind != "detail" || parsed.apiID != api.RegistryAPIID || parsed.cursor == "" || parsed.query != "기상 관측" {
		t.Fatalf("valid bounded cursor query rejected: %#v status=%d", parsed, status)
	}
	for _, raw := range []string{
		"cursor=",
		"cursor=abc&page=2",
		"q=" + url.QueryEscape("https://provider.example/private"),
		"target=" + url.QueryEscape("localhost"),
	} {
		request := httptest.NewRequest(http.MethodGet, "/datapan/apis/"+url.PathEscape(api.RegistryAPIID)+"/?"+raw, nil)
		if _, got := parsePublicHTMLRequest(request); got != http.StatusBadRequest {
			t.Fatalf("unsafe or ambiguous detail query accepted (%q): status=%d", raw, got)
		}
	}
}

func TestPublicRegistryOperationsRouteFailsClosedAndPreservesV1(t *testing.T) {
	handler, err := NewPublicStatusHandler(staticPublicSource{document: testPublicDocument(t)}, []string{"https://datapan.statpan.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path       string
		wantStatus int
	}{
		{path: "/datapan/v2/operations", wantStatus: http.StatusServiceUnavailable},
		{path: "/datapan/v2/operations?q=" + url.QueryEscape("token=hidden"), wantStatus: http.StatusBadRequest},
		{path: "/datapan/v1/dependencies?limit=5", wantStatus: http.StatusNotFound},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
		if recorder.Code != test.wantStatus || strings.Contains(recorder.Body.String(), "hidden") {
			t.Fatalf("%s status=%d body=%s", test.path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestPublicRegistryOperationsRouteUsesBoundedModelAndSameCORS(t *testing.T) {
	root, binding, _ := writeSyntheticOperationObservationPlan(t, false)
	plan, err := LoadPinnedOperationObservationPlan(root, binding)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	model, err := newOperationReadModel(plan, testRegistryAPIMetadataPin(0, 0), nil, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := model.LookupPublicOperationRows([]RegistryOperationLookupIdentity{{SourceID: "synthetic_test", OperationID: "synthetic-rest-list"}}, now)
	if err != nil || len(rows) != 1 || rows[0].RegistryOperationID != "synthetic-rest-list" {
		t.Fatalf("exact operation identity lookup failed: %#v %v", rows, err)
	}
	if _, err := model.LookupPublicOperationRows([]RegistryOperationLookupIdentity{{SourceID: "synthetic_test", OperationID: "unknown"}}, now); !errors.Is(err, ErrOperationReadModelUnavailable) {
		t.Fatalf("unknown exact identity did not fail closed: %v", err)
	}
	tooManyIdentities := make([]RegistryOperationLookupIdentity, operationReadModelMaximumAPIIDs+1)
	for index := range tooManyIdentities {
		tooManyIdentities[index] = RegistryOperationLookupIdentity{SourceID: "synthetic_test", OperationID: "synthetic-rest-list-" + strconv.Itoa(index)}
	}
	if _, err := model.LookupPublicOperationRows(tooManyIdentities, now); !errors.Is(err, ErrOperationReadModelUnavailable) {
		t.Fatalf("lookup above its bound was accepted: %v", err)
	}
	handler, err := NewPublicStatusHandlerWithRegistryOperations(staticPublicSource{document: testPublicDocument(t)}, []string{"https://datapan.statpan.com"}, testRegistryAPIMetadata(t), nil, model)
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/datapan/v2/operations?limit=1&q="+url.QueryEscape("synthetic-rest-list"), nil)
	request.Header.Set("Origin", "https://datapan.statpan.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Access-Control-Allow-Origin") != "https://datapan.statpan.com" || recorder.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("status=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if err := schemas.ValidateHealthRegistryOperationsPageV2(recorder.Body.Bytes()); err != nil {
		t.Fatalf("v2 page schema validation: %v", err)
	}
	if !strings.Contains(recorder.Body.String(), `"limit":1`) || !strings.Contains(recorder.Body.String(), `"total_after_search":1`) {
		t.Fatalf("bounded page/search was not reflected in the result: %s", recorder.Body.String())
	}

	options := httptest.NewRequest(http.MethodOptions, "/datapan/v2/operations", nil)
	options.Header.Set("Origin", "https://datapan.statpan.com")
	options.Header.Set("Access-Control-Request-Method", http.MethodGet)
	preflight := httptest.NewRecorder()
	handler.ServeHTTP(preflight, options)
	if preflight.Code != http.StatusNoContent || preflight.Header().Get("Access-Control-Allow-Methods") != "GET, HEAD" {
		t.Fatalf("v2 preflight changed: status=%d headers=%v", preflight.Code, preflight.Header())
	}
	badOptions := httptest.NewRequest(http.MethodOptions, "/datapan/v2/operations?target="+url.QueryEscape("https://provider.example"), nil)
	badOptions.Header.Set("Origin", "https://datapan.statpan.com")
	badOptions.Header.Set("Access-Control-Request-Method", http.MethodGet)
	badPreflight := httptest.NewRecorder()
	handler.ServeHTTP(badPreflight, badOptions)
	if badPreflight.Code != http.StatusBadRequest || strings.Contains(badPreflight.Body.String(), "provider.example") {
		t.Fatalf("v2 preflight bypassed query validation: status=%d body=%s", badPreflight.Code, badPreflight.Body.String())
	}

	head := httptest.NewRequest(http.MethodHead, "/datapan/v2/operations?limit=1", nil)
	headRecorder := httptest.NewRecorder()
	handler.ServeHTTP(headRecorder, head)
	if headRecorder.Code != http.StatusOK || headRecorder.Body.Len() != 0 {
		t.Fatalf("HEAD response status=%d body=%s", headRecorder.Code, headRecorder.Body.String())
	}

	limited, err := NewPublicReadGuard(handler, PublicReadLimits{RequestsPerSecond: 1, Burst: 1, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	limited.now = func() time.Time { return limited.updated }
	first := httptest.NewRecorder()
	limited.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/datapan/v2/operations", nil))
	second := httptest.NewRecorder()
	limited.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/datapan/v2/operations", nil))
	if first.Code != http.StatusOK || second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") != "1" {
		t.Fatalf("v2 route bypassed the shared public read budget: first=%d second=%d headers=%v", first.Code, second.Code, second.Header())
	}
}

func TestPublicAPIProgressFailsClosedForPartialOrInconsistentCoverage(t *testing.T) {
	partial := OperationAPIProgress{
		APIID: "api-1", TotalFunctions: 1, CurrentPass: 1,
		CoverageState: "current", MissingReasons: map[string]int{},
	}
	if !validPublicAPIProgress(partial, 2) {
		t.Fatal("valid partial source progress was rejected")
	}
	partialView := publicHTMLAPIProgressValue(partial, 2)
	if partialView.StatusClass == "badge-good" || partialView.StatusLabel == "모든 API 기능 최근 통과" {
		t.Fatal("one planned function made a two-function API look fully healthy")
	}

	complete := OperationAPIProgress{
		APIID: "api-1", TotalFunctions: 2, CurrentPass: 2,
		CoverageState: "current", MissingReasons: map[string]int{},
	}
	if !validPublicAPIProgress(complete, 2) || publicHTMLAPIProgressValue(complete, 2).StatusClass != "badge-good" {
		t.Fatal("complete, fully observed pass did not project a positive status")
	}

	inconsistent := complete
	inconsistent.Unobserved = 1
	if validPublicAPIProgress(inconsistent, 2) {
		t.Fatal("inconsistent identity counts were accepted")
	}
	unsafeReason := partial
	unsafeReason.MissingReasons = map[string]int{"https://secret.example": 1}
	if validPublicAPIProgress(unsafeReason, 2) {
		t.Fatal("unrecognized missing reason was accepted")
	}
}

func TestPublicHTMLUsesPinnedOperationProgressAndFailsClosedOnMismatch(t *testing.T) {
	metadata := testRegistryAPIMetadata(t)
	now := time.Now().UTC().Truncate(time.Second)
	base := OperationReadModelPage{
		SchemaVersion: RegistryOperationsPageSchemaVersion, GeneratedAt: now, ReadModelGeneratedAt: now.Add(-time.Minute),
		RegistryRevision: strings.Repeat("a", 40), ReleaseManifestSHA256: strings.Repeat("b", 64),
		IndexSHA256: strings.Repeat("c", 64), PlanSchemaSHA256: operationObservationPlanSchemaSHA256, PageSchemaSHA256: schemas.HealthRegistryOperationsPageV2SchemaSHA256(),
		MetadataRegistryRevision: metadata.RegistryRevision, MetadataSourceSHA256: metadata.Source.SHA256,
		MetadataCatalogSHA256: metadata.Catalog.SHA256, MetadataArtifactSHA256: acceptedRegistryAPIMetadataSHA256,
		MetadataAPIEntityCount: metadata.Counts.APIEntities, MetadataOperationCount: metadata.Counts.APIOperations,
		IdentityCounts: OperationReadModelIdentityCounts{Known: 5, Missing: 5, InventoryUnknownScopes: 4, InventoryUnknownOperations: 4}, Limit: 1, Operations: []OperationReadModelRow{},
	}
	progress := OperationAPIProgress{APIID: "api-1", TotalFunctions: 1, CurrentPass: 1, CoverageState: "current", MissingReasons: map[string]int{}}
	partialRows := make([]OperationReadModelRow, 0, len(publicPartialRegistryOperations))
	for index, expected := range publicPartialRegistryOperations {
		row := OperationReadModelRow{
			SourceID: expected.sourceID, RegistryOperationID: expected.operationID, Provider: expected.provider,
			Protocol: "unknown", OperationNameState: "missing", TitleState: "missing", OrganizationState: "missing", PurposeState: "missing",
			RequestPlanState: "incomplete", RuntimeBindingState: "unbound", AdmissionState: "not_admitted", MissingReason: "inventory_unknown",
			InventoryUnknown: true, AttemptState: "none", ObservationAttemptState: "none", ObservationState: "unobserved", GatusDeliveryState: "not_ready",
		}
		if index == 0 {
			observedAt := now.Add(-2 * time.Minute)
			receivedAt := now.Add(-time.Minute)
			period := int64(time.Hour / time.Second)
			requestStarted := true
			row.RequestPlanState, row.RuntimeBindingState, row.AdmissionState = "complete", "bound", "admitted"
			row.MissingReason = ""
			row.AttemptState, row.ObservationAttemptState, row.RequestStarted = "observed", "observed", &requestStarted
			row.Attempted, row.ObservationState = true, "current_pass"
			row.ResultState, row.ResultCategory = "healthy", "healthy"
			row.ObservationPeriodSeconds, row.ProviderObservedAt, row.HealthReceivedAt = &period, &observedAt, &receivedAt
			row.NextDueAt = publicStatusTimePointer(observedAt.Add(time.Hour))
		}
		partialRows = append(partialRows, row)
	}
	source := staticPublicRegistryOperations{page: base, progress: []OperationAPIProgress{progress}, lookup: partialRows}
	page := publicHTMLPage{Directory: true, APIs: []publicHTMLAPI{{RegistryAPIID: "api-1", APIOperations: 2}}}
	attachPublicOperationReadModel(&page, metadata, source, []string{"api-1"}, map[string]int{"api-1": 2}, now)
	attachPublicPartialScopes(&page, source, nil, now)
	if page.OperationReadModelUnavailable || !page.OperationPlan.Available || len(page.APIs) != 1 || page.APIs[0].Progress == nil {
		t.Fatalf("valid pinned operation progress was unavailable: %#v", page)
	}
	if page.APIs[0].Progress.StatusClass == "badge-good" || page.APIs[0].Progress.PlannedFunctions != 1 || page.APIs[0].Progress.RegisteredFunctions != 2 {
		t.Fatalf("partial plan incorrectly summarized the whole API as healthy: %#v", page.APIs[0].Progress)
	}
	if page.OperationPlan.InventoryUnknownScopes != 4 || page.OperationPlan.InventoryUnknownOperations != 4 {
		t.Fatalf("partial Registry scopes disappeared from independent full-plan counts: %#v", page.OperationPlan)
	}
	if !strings.Contains(page.ConfigNote, "목록이 확인되지 않은 제공처 4곳") {
		t.Fatalf("visible Registry scope summary omitted four partial providers: %q", page.ConfigNote)
	}
	if page.PartialScopesUnavailable || len(page.PartialScopes) != 4 {
		t.Fatalf("verified partial provider operations were not rendered: %#v", page.PartialScopes)
	}
	for index, expected := range publicPartialRegistryOperations {
		row := page.PartialScopes[index]
		if row.ProviderLabel != expected.providerLabel || !strings.Contains(row.AvailabilityLabel, "제공처 전체 목록 미확인") {
			t.Fatalf("partial scope identity or state was misprojected: %#v", row)
		}
		if index == 0 {
			if row.StatusClass != "badge-good" || row.StatusLabel != "최근 검사 결과 통과" {
				t.Fatalf("validated observation was lost from immutable partial-scope identity: %#v", row)
			}
		} else if row.StatusClass == "badge-good" || row.StatusLabel != "검증된 검사 결과 없음" || !strings.Contains(row.AvailabilityLabel, "요청 조건 미확인") || !strings.Contains(row.AvailabilityLabel, "검사 실행 연결 전") || !strings.Contains(row.AvailabilityLabel, "실행 조건 확인 전") {
			t.Fatalf("unobserved partial scope status was misprojected: %#v", row)
		}
		if row.OperationName != "API 기능 이름 확인 필요" || row.Purpose != "기능 설명을 확인할 수 없습니다" || row.MetadataAction != "공식 제공처 설명과 Registry 등록 항목을 연결해야 합니다" {
			t.Fatalf("missing partial-scope metadata lacked a Korean explanation and next action: %#v", row)
		}
		if strings.Contains(row.OperationName, expected.operationID) || strings.Contains(row.Title, expected.operationID) || strings.Contains(row.Purpose, expected.operationID) {
			t.Fatalf("Registry identity leaked as metadata: %#v", row)
		}
	}

	brokenPartial := source
	brokenPartial.lookup = nil
	closedPartial := publicHTMLPage{Directory: true, OperationPlan: page.OperationPlan}
	attachPublicPartialScopes(&closedPartial, brokenPartial, nil, now)
	if !closedPartial.PartialScopesUnavailable || len(closedPartial.PartialScopes) != 0 {
		t.Fatalf("missing partial scope source did not fail closed: %#v", closedPartial)
	}

	unsafe := source
	unsafe.progress = []OperationAPIProgress{{APIID: "different-api", TotalFunctions: 1, CurrentPass: 1, CoverageState: "current"}}
	closed := publicHTMLPage{APIs: []publicHTMLAPI{{RegistryAPIID: "api-1", APIOperations: 2}}}
	attachPublicOperationReadModel(&closed, metadata, unsafe, []string{"api-1"}, map[string]int{"api-1": 2}, now)
	if !closed.OperationReadModelUnavailable || closed.OperationPlan.Available || closed.APIs[0].Progress != nil {
		t.Fatalf("mismatched API identity did not fail closed: %#v", closed)
	}

	unavailable := source
	unavailable.err = errors.New("credential-bearing source error")
	closed = publicHTMLPage{}
	attachPublicOperationReadModel(&closed, metadata, unavailable, nil, map[string]int{}, now)
	if !closed.OperationReadModelUnavailable || closed.OperationPlan.Available {
		t.Fatal("source error was accepted as operation progress")
	}
}

func TestPublicHTMLReadModelOperationStatusAndDiagnosisAreAllowlisted(t *testing.T) {
	now := time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC)
	base := OperationReadModelRow{
		SourceID: "data_go_kr", RegistryOperationID: strings.Repeat("a", 64), APIID: stringPointer("api-1"),
		Provider: "data.go.kr", AdapterID: "data-go-kr", Protocol: "REST", OperationName: "현재 대기소 조회",
		OperationNameState: "present", Title: "대기소 정보", TitleState: "present", Organization: "기관 A", OrganizationState: "present",
		Purpose: "현재 대기소 정보를 확인합니다", PurposeState: "present", RequestPlanState: "complete", RuntimeBindingState: "bound",
		AdmissionState: "admitted", ObservationAttemptState: "observed", AttemptState: "observed",
		ObservationState: "current_pass", ResultState: "healthy", ResultCategory: "healthy", GatusDeliveryState: "not_ready",
	}
	pass := publicHTMLReadModelOperation(base, now)
	if pass.StatusClass != "badge-good" || pass.ObservationLabel != "최근 검사 결과 통과" || pass.Name != "현재 대기소 조회" {
		t.Fatalf("validated pass was not localized safely: %#v", pass)
	}
	longPurpose := strings.TrimSpace(strings.Repeat("공공 API 자료 설명입니다. ", 40))
	if len(longPurpose) <= 512 {
		t.Fatal("long-purpose fixture did not exceed the former byte cutoff")
	}
	longDescription := base
	longDescription.Purpose = longPurpose
	if got := publicHTMLReadModelOperation(longDescription, now).Description; got != longPurpose {
		t.Fatalf("valid long Korean purpose was dropped or changed: %d bytes", len(got))
	}
	credentialGuidance := base
	credentialGuidance.Purpose = "API key is required after portal approval."
	if got := publicHTMLReadModelOperation(credentialGuidance, now).Description; got != credentialGuidance.Purpose {
		t.Fatalf("safe credential guidance was removed with its keyword: %q", got)
	}
	credentialValue := base
	credentialValue.Purpose = "API key=do-not-publish"
	if got := publicHTMLReadModelOperation(credentialValue, now).Description; strings.Contains(got, "do-not-publish") {
		t.Fatalf("assigned credential value reached the public projection: %q", got)
	}

	indeterminate := base
	indeterminate.ObservationState, indeterminate.ResultState, indeterminate.ResultCategory = "current_indeterminate", "indeterminate", "observer_failure"
	unknown := publicHTMLReadModelOperation(indeterminate, now)
	if unknown.StatusClass == "badge-good" || unknown.StatusClass == "badge-bad" || unknown.ObservationLabel != "현재 결과로 상태 판정 불가" {
		t.Fatalf("indeterminate result was mapped to a pass or confirmed provider failure: %#v", unknown)
	}

	semanticUnknown := base
	semanticUnknown.ObservationState, semanticUnknown.ResultState, semanticUnknown.ResultCategory = "current_indeterminate", "indeterminate", "response_semantics_unestablished"
	semanticUnknown.GatusDeliveryState = "not_applicable"
	httpOK := 204
	semanticUnknown.ProviderHTTPStatus = &httpOK
	semanticRow := publicHTMLReadModelOperation(semanticUnknown, now)
	if semanticRow.StatusClass != "badge-warn" || semanticRow.ObservationLabel != "응답 수신 · 이용 가능성 판정 근거 부족" || semanticRow.ResultLabel != "HTTP 204 응답 · 이용 가능성 판정 근거 부족" || semanticRow.DeliveryLabel != "전달 대상 아님 · 응답 의미 미판정" {
		t.Fatalf("observation-only response was presented as usable or sent to Gatus: %#v", semanticRow)
	}
	partialDetail, partialNext := publicPartialOperationDiagnosis(semanticUnknown)
	if !strings.Contains(partialDetail, "HTTP 204 응답은 받았지만") || !strings.Contains(partialNext, "공식 API 문서") {
		t.Fatalf("partial-source row omitted the observation-only limitation or next action: detail=%q next=%q", partialDetail, partialNext)
	}
	partialStatus, partialStatusClass := publicPartialOperationObservation(semanticUnknown)
	if partialStatus != "응답 수신 · 이용 가능성 판정 근거 부족" || partialStatusClass != "badge-warn" {
		t.Fatalf("partial-source response semantics were not visible without a healthy badge: status=%q class=%q", partialStatus, partialStatusClass)
	}

	httpFailure := base
	httpFailure.ObservationState, httpFailure.ResultState, httpFailure.ResultCategory = "current_fail", "unhealthy", "response_http_failure"
	httpStatus := 503
	httpFailure.ProviderHTTPStatus = &httpStatus
	httpFailureRow := publicHTMLReadModelOperation(httpFailure, now)
	if httpFailureRow.StatusClass != "badge-bad" || httpFailureRow.CauseLabel != "HTTP 응답 오류 · 상태 코드 503" || strings.Contains(httpFailureRow.NextActionLabel, "provider_failure") {
		t.Fatalf("HTTP response failure was broadened into an unsupported cause: %#v", httpFailureRow)
	}
	partialFailureDetail, partialFailureNext := publicPartialOperationDiagnosis(httpFailure)
	if !strings.Contains(partialFailureDetail, "HTTP 503 응답 오류") || !strings.Contains(partialFailureDetail, "원인은 이 기록만으로 확정할 수 없습니다") || !strings.Contains(partialFailureNext, "API 사용 조건") {
		t.Fatalf("partial-source HTTP error overstated its cause or omitted the next action: detail=%q next=%q", partialFailureDetail, partialFailureNext)
	}
	partialFailureStatus, partialFailureClass := publicPartialOperationObservation(httpFailure)
	if partialFailureStatus != "HTTP 응답 오류" || partialFailureClass != "badge-bad" {
		t.Fatalf("partial-source HTTP error was hidden behind a generic status label: status=%q class=%q", partialFailureStatus, partialFailureClass)
	}

	deferred := base
	deferred.ObservationAttemptState, deferred.AttemptState = "none", "deferred"
	deferred.ObservationState, deferred.ResultState, deferred.ResultCategory = "unobserved", "", ""
	requestStarted := false
	deferred.RequestStarted = &requestStarted
	deferred.ExecutionBlockReason = "history_capacity"
	deferredRow := publicHTMLReadModelOperation(deferred, now)
	if deferredRow.StatusClass == "badge-good" || !strings.Contains(deferredRow.AttemptLabel, "검사 요청 전 보류") || !strings.Contains(deferredRow.AttemptLabel, "결과 저장 공간") {
		t.Fatalf("pre-dispatch deferral was presented as a request or healthy result: %#v", deferredRow)
	}
	partialAttemptLabel := publicOperationAttemptLabel(deferred.AttemptState, deferred.RequestStarted, deferred.ExecutionBlockReason)
	if !strings.Contains(partialAttemptLabel, "요청 전 보류") || !strings.Contains(partialAttemptLabel, "결과 저장 공간") {
		t.Fatalf("partial-source row did not preserve the safe pre-dispatch reason: %q", partialAttemptLabel)
	}

	failed := base
	failed.ObservationState, failed.ResultState, failed.ResultCategory = "current_fail", "unhealthy", "provider_failure"
	failedRow := publicHTMLReadModelOperation(failed, now)
	if failedRow.StatusClass != "badge-bad" || !strings.Contains(failedRow.CauseLabel, "제공처 실패 결과") || strings.Contains(failedRow.CauseLabel, "provider_failure") {
		t.Fatalf("known failure category was not rendered through Korean allowlist: %#v", failedRow)
	}

	stale := base
	stale.ObservationState = "stale"
	staleRow := publicHTMLReadModelOperation(stale, now)
	if staleRow.StatusClass == "badge-good" || !strings.Contains(staleRow.ObservationLabel, "주기를 지남") {
		t.Fatalf("stale result was presented as current: %#v", staleRow)
	}

	unsafe := base
	unsafe.Title = "https://internal.example/?api_key=do-not-print"
	unsafe.ObservationState, unsafe.ResultState = "current_fail", "unhealthy"
	unsafe.ResultCategory = "credential=not-public"
	unsafeRow := publicHTMLReadModelOperation(unsafe, now)
	if strings.Contains(unsafeRow.Title, "internal.example") || strings.Contains(unsafeRow.Title, "api_key") || strings.Contains(unsafeRow.CauseLabel, "credential=") || strings.Contains(unsafeRow.NextActionLabel, "not-public") {
		t.Fatalf("raw private text reached the HTML projection: %#v", unsafeRow)
	}
}

func TestLegacyGatusHistoryStaysSeparateFromCurrentOperationPlan(t *testing.T) {
	metadata := testRegistryAPIMetadata(t)
	if len(metadata.HealthCanaryLinks) == 0 {
		t.Fatal("expected a verified Health canary mapping")
	}
	link := metadata.HealthCanaryLinks[0]
	now := time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC)
	legacyDocument := legacyGatusDocumentForOperation(t, link.HealthOperationID, true, now)
	legacyStatuses := publicStatusByRegistryOperation(metadata, legacyDocument)
	row := publicOperationPlanRowFixture(t, metadata, link, now, false)
	page := publicHTMLPage{Detail: true, DetailTitle: "검증 API"}
	source := staticPublicRegistryOperations{page: publicOperationPageFixture(metadata, link.RegistryAPIID, now, row)}
	status := attachPublicOperationDetailRows(&page, metadata, source, link.RegistryAPIID, publicHTMLRequest{kind: "detail", apiID: link.RegistryAPIID}, legacyStatuses, true, legacyDocument, now)
	if status != http.StatusOK || len(page.Operations) != 1 {
		t.Fatalf("detail rows were unavailable: status=%d page=%#v", status, page)
	}
	newResult := page.Operations[0]
	if newResult.StatusClass == "badge-good" || newResult.ObservationLabel != "아직 새 검사 기록 없음" || newResult.HealthReceivedAt != nil {
		t.Fatalf("legacy pass promoted an unobserved/incomplete current plan: %#v", newResult)
	}
	if !strings.Contains(newResult.AvailabilityLabel, "요청 조건 미완료") || !strings.Contains(newResult.AvailabilityLabel, "검사 실행 연결 전") || !strings.Contains(newResult.AvailabilityLabel, "실행 조건 확인 전") {
		t.Fatalf("current plan execution gaps were hidden: %#v", newResult)
	}
	if newResult.LegacyGatus == nil || newResult.LegacyGatus.StatusClass != "badge-good" || len(newResult.LegacyGatus.History) != 1 || newResult.LegacyGatus.DiagnosticRegistryRevision != legacyDocument.DiagnosticRegistryRevision || newResult.LegacyGatus.ObservationCatalogRevision != legacyDocument.ObservationCatalogRevision {
		t.Fatalf("legacy Gatus history/provenance was not preserved separately: %#v", newResult.LegacyGatus)
	}
	if page.OperationPlan.Available {
		t.Fatal("legacy Gatus status was counted as current-plan coverage")
	}
	var rendered bytes.Buffer
	if err := publicStatusPages.Execute(&rendered, page); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rendered.String(), "아직 새 검사 기록 없음") || !strings.Contains(rendered.String(), "기존 검사 수신 기록") || !strings.Contains(rendered.String(), "Registry 저장본 revision") {
		t.Fatalf("rendered page merged or omitted legacy status provenance: %s", rendered.String())
	}
}

func TestCurrentDurableFailureWinsWhileHealthyLegacyHistoryRemainsSeparate(t *testing.T) {
	metadata := testRegistryAPIMetadata(t)
	if len(metadata.HealthCanaryLinks) == 0 {
		t.Fatal("expected a verified Health canary mapping")
	}
	link := metadata.HealthCanaryLinks[0]
	now := time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC)
	legacyDocument := legacyGatusDocumentForOperation(t, link.HealthOperationID, true, now)
	legacyStatuses := publicStatusByRegistryOperation(metadata, legacyDocument)
	row := publicOperationPlanRowFixture(t, metadata, link, now, true)
	page := publicHTMLPage{Detail: true, DetailTitle: "검증 API"}
	source := staticPublicRegistryOperations{page: publicOperationPageFixture(metadata, link.RegistryAPIID, now, row)}
	status := attachPublicOperationDetailRows(&page, metadata, source, link.RegistryAPIID, publicHTMLRequest{kind: "detail", apiID: link.RegistryAPIID}, legacyStatuses, true, legacyDocument, now)
	if status != http.StatusOK || len(page.Operations) != 1 {
		t.Fatalf("detail rows were unavailable: status=%d page=%#v", status, page)
	}
	newResult := page.Operations[0]
	if newResult.StatusClass != "badge-bad" || newResult.ObservationLabel != "최근 검사 결과 실패" || newResult.ResultLabel != "검증된 API 결과 실패" {
		t.Fatalf("healthy legacy status overrode a new validated failure: %#v", newResult)
	}
	if newResult.HealthReceivedAt == nil || newResult.LegacyGatus == nil || newResult.LegacyGatus.StatusClass != "badge-good" || len(newResult.LegacyGatus.History) != 1 {
		t.Fatalf("new failure or separate healthy legacy history was omitted: %#v", newResult)
	}
	var rendered bytes.Buffer
	if err := publicStatusPages.Execute(&rendered, page); err != nil {
		t.Fatal(err)
	}
	html := rendered.String()
	failureIndex, legacyIndex := strings.Index(html, "최근 검사 결과 실패"), strings.Index(html, "기존 검사 수신 기록")
	if failureIndex < 0 || legacyIndex < 0 || failureIndex >= legacyIndex || !strings.Contains(html, "Registry 저장본 revision") {
		t.Fatalf("current failure did not remain primary with clearly separate legacy history: %s", html)
	}
}

func TestRegistryMetadataLoaderBindsVerifiedProjectionToArtifact(t *testing.T) {
	metadata := testRegistryAPIMetadata(t)
	if metadata.verifiedArtifactSHA256 != acceptedRegistryAPIMetadataSHA256 || metadata.verifiedSourceSHA256 != metadata.Source.SHA256 || !sha256Pattern.MatchString(metadata.verifiedProjectionSHA256) {
		t.Fatalf("loader did not retain verified source, artifact, and projection bindings: %#v", metadata)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	if hex.EncodeToString(sum[:]) != metadata.verifiedProjectionSHA256 {
		t.Fatal("loader projection digest does not cover its exported typed projection")
	}
	mutated := metadata
	mutated.APIs = append([]RegistryAPIMetadataAPI(nil), metadata.APIs...)
	mutated.APIs[0].Title = "changed after verification"
	encoded, err = json.Marshal(mutated)
	if err != nil {
		t.Fatal(err)
	}
	sum = sha256.Sum256(encoded)
	if hex.EncodeToString(sum[:]) == metadata.verifiedProjectionSHA256 {
		t.Fatal("post-load exported metadata mutation retained the verified projection digest")
	}
}

func TestPublicStatusHandlerFreezesAndVerifiesRegistryMetadata(t *testing.T) {
	metadata := testRegistryAPIMetadata(t)
	firstAPI := metadata.APIs[0]
	firstOperation := firstAPI.Operations[0]
	if _, err := cloneVerifiedRegistryAPIMetadata(metadata); err != nil {
		t.Fatalf("freezing verified Registry metadata failed: %v", err)
	}
	handler, err := NewPublicStatusHandlerWithRegistryMetadata(staticPublicSource{document: testPublicDocument(t)}, []string{"https://datapan.statpan.com"}, metadata)
	if err != nil {
		t.Fatal(err)
	}

	metadata.APIs[0].Title = "caller mutation"
	metadata.APIs[0].Operations[0].Name = "caller operation mutation"
	metadata.HealthCanaryLinks[0].OperationName = "caller canary mutation"
	if handler.registry.APIs[0].Title != firstAPI.Title || handler.registry.APIs[0].Operations[0].Name != firstOperation.Name || handler.registry.HealthCanaryLinks[0].OperationName == "caller canary mutation" {
		t.Fatal("handler retained caller-owned Registry metadata slices")
	}

	mutated := testRegistryAPIMetadata(t)
	mutated.APIs = append([]RegistryAPIMetadataAPI(nil), mutated.APIs...)
	mutated.APIs[0].Title = "changed after verification"
	if _, err := NewPublicStatusHandlerWithRegistryMetadata(staticPublicSource{document: testPublicDocument(t)}, []string{"https://datapan.statpan.com"}, mutated); err == nil {
		t.Fatal("handler accepted Registry metadata whose verified projection had changed")
	}
}

func TestPublicOperationRendererRetainsPinnedKoreanDescriptionCorpus(t *testing.T) {
	metadata := testRegistryAPIMetadata(t)
	var present, sanitized, retained, operationDetailsRetained int
	for _, api := range metadata.APIs {
		switch api.DescriptionState {
		case "present":
			present++
		case "sanitized":
			sanitized++
		}
		if api.DescriptionState != "present" && api.DescriptionState != "sanitized" {
			continue
		}
		verifiedText := safeVerifiedRegistryMetadataText(api.Description, maxPublicOperationPurposeBytes, maxPublicOperationPurposeRunes)
		listed := metadataFieldText(api.Description, api.DescriptionState, "기능 설명")
		if verifiedText {
			retained++
			if !strings.HasPrefix(listed, api.Description) {
				t.Fatalf("verified Registry description was lost by the directory renderer; present=%d sanitized=%d retained=%d", present, sanitized, retained)
			}
		} else if strings.Contains(listed, api.Description) {
			t.Fatalf("description rejected by the shared safety predicate reached HTML; present=%d sanitized=%d retained=%d", present, sanitized, retained)
		}

		if len(api.Operations) == 0 {
			continue
		}
		operation := api.Operations[0]
		name, nameState := sanitizeClassifiedMetadata(operation.Name, operation.NameState, maxPublicOperationLabelBytes, maxPublicOperationLabelRunes)
		title, titleState := sanitizeClassifiedMetadata(api.Title, api.TitleState, maxPublicOperationLabelBytes, maxPublicOperationLabelRunes)
		organization, organizationState := sanitizeClassifiedMetadata(api.Organization, api.OrganizationState, maxPublicOperationLabelBytes, maxPublicOperationLabelRunes)
		purpose, purposeState := sanitizeClassifiedMetadata(api.Description, api.DescriptionState, maxPublicOperationPurposeBytes, maxPublicOperationPurposeRunes)
		apiID := api.RegistryAPIID
		row := OperationReadModelRow{
			SourceID: "data_go_kr", RegistryOperationID: operation.RegistryOperationID, APIID: &apiID,
			OperationName: name, OperationNameState: nameState, Title: title, TitleState: titleState,
			Organization: organization, OrganizationState: organizationState, Purpose: purpose, PurposeState: purposeState,
		}
		rendered := publicHTMLReadModelOperation(row, time.Now().UTC())
		if verifiedText {
			operationDetailsRetained++
			if rendered.Description != api.Description {
				t.Fatalf("verified Registry description was lost by the operation renderer; present=%d sanitized=%d retained=%d operation_details=%d", present, sanitized, retained, operationDetailsRetained)
			}
		} else if strings.Contains(rendered.Description, api.Description) {
			t.Fatalf("unsafe Registry description reached operation HTML; present=%d sanitized=%d retained=%d operation_details=%d", present, sanitized, retained, operationDetailsRetained)
		}
	}
	if present != 5807 || sanitized != 6474 || retained != 12272 || operationDetailsRetained < 7000 {
		t.Fatalf("pinned metadata rendering coverage changed; present=%d sanitized=%d retained=%d operation_details=%d", present, sanitized, retained, operationDetailsRetained)
	}
}

func TestDirectoryExplainsLinkOnlyAndOperationlessEntities(t *testing.T) {
	metadata := testRegistryAPIMetadata(t)
	var linkOnly, operationless int
	var sampleAPIs [2]RegistryAPIMetadataAPI
	for _, api := range metadata.APIs {
		if len(api.Operations) != 0 {
			continue
		}
		if api.LinkOperationCount > 0 {
			linkOnly++
			if sampleAPIs[0].RegistryAPIID == "" {
				sampleAPIs[0] = api
			}
		} else {
			operationless++
			if sampleAPIs[1].RegistryAPIID == "" {
				sampleAPIs[1] = api
			}
		}
	}
	if linkOnly != 4222 || operationless != 473 {
		t.Fatalf("pinned Registry entity type counts changed; link_only=%d operationless=%d", linkOnly, operationless)
	}
	for index, expected := range []string{
		"외부 링크만 등록되어 API 기능별 검사 조건은 확인할 수 없습니다",
		"등록된 API 기능과 외부 링크가 없습니다",
	} {
		api := sampleAPIs[index]
		if api.RegistryAPIID == "" || !strings.Contains(apiRegistrationNote(api), expected) {
			t.Fatalf("Registry entity type %d lacks a clear inspection explanation", index)
		}
		progress := OperationAPIProgress{APIID: api.RegistryAPIID, CoverageState: "no_registered_operations", MissingReasons: map[string]int{}}
		status := publicHTMLAPIProgressValue(progress, 0)
		if status.StatusClass == "badge-good" {
			t.Fatalf("entity without API operation identities became healthy: type=%d", index)
		}
		page := buildPublicHTMLAPIDetail(metadata, api, nil, true, publicHTMLRequest{page: 1}, time.Now().UTC())
		page.DetailProgress = status
		var rendered bytes.Buffer
		if err := publicStatusPages.Execute(&rendered, page); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(rendered.String(), expected) {
			t.Fatalf("entity type %d explanation is not visible in the API detail", index)
		}
	}
}

func TestLegacyDetailFallbackLabelsGatusAndShowsSourceProvenance(t *testing.T) {
	metadata := testRegistryAPIMetadata(t)
	link := metadata.HealthCanaryLinks[0]
	legacyDocument := legacyGatusDocumentForOperation(t, link.HealthOperationID, true, time.Now().UTC())
	handler, err := NewPublicStatusHandlerWithRegistryMetadata(staticPublicSource{document: legacyDocument}, []string{"https://datapan.statpan.com"}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, buildPublicHTMLDirectoryAPIURL(link.RegistryAPIID), nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("legacy detail status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	for _, want := range []string{"기존 검사 수신 기록 (Gatus)", "Gatus에 결과가 접수된 이력", "Registry 저장본 revision", "검사 카탈로그 revision", "카탈로그 SHA-256"} {
		if !strings.Contains(recorder.Body.String(), want) {
			t.Errorf("legacy detail missing %q", want)
		}
	}
}

func legacyGatusDocumentForOperation(t *testing.T, healthOperationID string, healthy bool, now time.Time) PublicStatusDocument {
	t.Helper()
	document := testPublicDocument(t)
	resultState, availability := "failed", "degraded"
	if healthy {
		resultState, availability = "succeeded", "operational"
	}
	status := PublicOperationStatus{
		OperationID: healthOperationID, ObservedAt: publicStatusTimePointer(now.Add(-time.Minute)),
		HistoryStartedAt: publicStatusTimePointer(now.Add(-time.Hour)), History: []PublicResultHistoryPoint{{ReceivedAt: now.Add(-time.Minute), Success: healthy}},
		ObservationState: "current", RawObservationState: resultState, IncidentState: "operational",
		ConsecutiveFailureThreshold: 2, Availability: availability, Diagnosis: unknownPublicDiagnosis(),
	}
	setPublicOperationStatus(t, &document, status)
	return document
}

func publicOperationPlanRowFixture(t *testing.T, metadata RegistryAPIMetadata, link RegistryHealthCanaryLink, now time.Time, observedFailure bool) OperationReadModelRow {
	t.Helper()
	api, ok := metadata.APIByID(link.RegistryAPIID)
	if !ok {
		t.Fatal("canary API missing from pinned metadata")
	}
	var sourceOperation RegistryAPIMetadataOperation
	for _, operation := range api.Operations {
		if operation.RegistryOperationID == link.RegistryOperationID {
			sourceOperation = operation
			break
		}
	}
	if sourceOperation.RegistryOperationID == "" {
		t.Fatal("canary operation missing from pinned metadata")
	}
	apiID := link.RegistryAPIID
	name, nameState := sanitizeClassifiedMetadata(sourceOperation.Name, sourceOperation.NameState, maxPublicOperationLabelBytes, maxPublicOperationLabelRunes)
	title, titleState := sanitizeClassifiedMetadata(api.Title, api.TitleState, maxPublicOperationLabelBytes, maxPublicOperationLabelRunes)
	organization, organizationState := sanitizeClassifiedMetadata(api.Organization, api.OrganizationState, maxPublicOperationLabelBytes, maxPublicOperationLabelRunes)
	purpose, purposeState := sanitizeClassifiedMetadata(api.Description, api.DescriptionState, maxPublicOperationPurposeBytes, maxPublicOperationPurposeRunes)
	row := OperationReadModelRow{
		SourceID: "data_go_kr", RegistryOperationID: link.RegistryOperationID, APIID: &apiID,
		Provider: "data.go.kr", AdapterID: "data-go-kr", Protocol: sourceOperation.Protocol,
		OperationName: name, OperationNameState: nameState, Title: title, TitleState: titleState,
		Organization: organization, OrganizationState: organizationState, Purpose: purpose, PurposeState: purposeState,
		RequestPlanState: "incomplete", RuntimeBindingState: "unbound", AdmissionState: "not_admitted",
		MissingReason: "request_plan_incomplete", AttemptState: "none", ObservationAttemptState: "none",
		ObservationState: "unobserved", GatusDeliveryState: "not_ready",
	}
	if observedFailure {
		observedAt := now.Add(-2 * time.Minute)
		receivedAt := now.Add(-time.Minute)
		period := int64(3600)
		requestStarted := true
		row.RequestPlanState, row.RuntimeBindingState, row.AdmissionState = "complete", "bound", "admitted"
		row.MissingReason = ""
		row.AttemptState, row.ObservationAttemptState, row.RequestStarted = "observed", "observed", &requestStarted
		row.Attempted, row.ObservationState = true, "current_fail"
		row.ResultState, row.ResultCategory = "unhealthy", "provider_failure"
		row.ObservationPeriodSeconds, row.ProviderObservedAt, row.HealthReceivedAt = &period, &observedAt, &receivedAt
		row.NextDueAt = publicStatusTimePointer(observedAt.Add(time.Duration(period) * time.Second))
	}
	if err := row.ValidatePublicProjection(now); err != nil {
		t.Fatalf("invalid test projection: %v", err)
	}
	return row
}

func publicOperationPageFixture(metadata RegistryAPIMetadata, apiID string, now time.Time, row OperationReadModelRow) OperationReadModelPage {
	return OperationReadModelPage{
		SchemaVersion: RegistryOperationsPageSchemaVersion, GeneratedAt: now, ReadModelGeneratedAt: now.Add(-time.Minute),
		RegistryRevision: strings.Repeat("a", 40), ReleaseManifestSHA256: strings.Repeat("b", 64),
		IndexSHA256: strings.Repeat("c", 64), PlanSchemaSHA256: operationObservationPlanSchemaSHA256,
		PageSchemaSHA256:         schemas.HealthRegistryOperationsPageV2SchemaSHA256(),
		MetadataRegistryRevision: metadata.RegistryRevision, MetadataSourceSHA256: metadata.Source.SHA256,
		MetadataCatalogSHA256: metadata.Catalog.SHA256, MetadataArtifactSHA256: acceptedRegistryAPIMetadataSHA256,
		MetadataAPIEntityCount: metadata.Counts.APIEntities, MetadataOperationCount: metadata.Counts.APIOperations,
		IdentityCounts: OperationReadModelIdentityCounts{Known: 5, Missing: 5, InventoryUnknownScopes: 4, InventoryUnknownOperations: 4},
		APIID:          apiID, Limit: operationReadModelMaximumPage, TotalAfterSearch: 1, Operations: []OperationReadModelRow{row},
	}
}
