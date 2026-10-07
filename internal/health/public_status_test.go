package health

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

var publicNow = time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)

func TestFormatPublicCount(t *testing.T) {
	for value, want := range map[int]string{0: "0", 10: "10", 999: "999", 1000: "1,000", 12652: "12,652", 12282: "12,282"} {
		if got := formatPublicCount(value); got != want {
			t.Errorf("formatPublicCount(%d) = %q, want %q", value, got, want)
		}
	}
}

func TestUnknownHTMLDiagnosisStatesEvidenceLimitAndSafeNextStep(t *testing.T) {
	cause, next := publicHTMLDiagnosis(unknownPublicDiagnosis())
	if cause != "현재 기록만으로는 실패 원인을 확인할 수 없습니다." || next != "추가 검사 결과와 공급처 공지, API 사용 조건을 확인하세요." {
		t.Fatalf("unknown diagnosis copy = (%q, %q)", cause, next)
	}
}

func TestPublicHTMLGuardErrorsAreKoreanAndRetryable(t *testing.T) {
	handler, err := NewPublicStatusHandler(staticPublicSource{}, []string{"https://datapan.statpan.com"})
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewPublicReadGuard(handler, PublicReadLimits{RequestsPerSecond: 1, Burst: 1, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	first := httptest.NewRecorder()
	guard.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/datapan/", nil))
	if first.Code != http.StatusServiceUnavailable || first.Header().Get("Content-Type") != "text/html; charset=utf-8" || first.Header().Get("Retry-After") != "1" || !strings.Contains(first.Body.String(), "상태 페이지를 잠시 사용할 수 없습니다.") {
		t.Fatalf("HTML unavailable response: status=%d headers=%v body=%s", first.Code, first.Header(), first.Body.String())
	}
	second := httptest.NewRecorder()
	guard.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/datapan/", nil))
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Content-Type") != "text/html; charset=utf-8" || second.Header().Get("Retry-After") != "1" || !strings.Contains(second.Body.String(), "1초 후 다시 시도해 주세요.") || strings.Contains(second.Body.String(), `{"error"`) {
		t.Fatalf("HTML overload response: status=%d headers=%v body=%s", second.Code, second.Header(), second.Body.String())
	}
}

type staticPublicSource struct {
	document PublicStatusDocument
	err      error
}

func (s staticPublicSource) Snapshot(context.Context) (PublicStatusDocument, error) {
	return s.document, s.err
}

func testPublicDocument(t *testing.T) PublicStatusDocument {
	t.Helper()
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	operations := make([]PublicOperationStatus, 0, len(config.Canaries))
	for _, canary := range config.Canaries {
		operations = append(operations, PublicOperationStatus{OperationID: canary.OperationID, ObservationState: "not_observed", RawObservationState: "unknown", IncidentState: "unknown", ConsecutiveFailureThreshold: canary.ConsecutiveFailuresBeforeIncident, Availability: "unknown", Diagnosis: unknownPublicDiagnosis()})
	}
	return PublicStatusDocument{SchemaVersion: PublicStatusSchemaVersion, GeneratedAt: publicNow, DiagnosticRegistryRevision: AcceptedDiagnosticRegistryRevision, ObservationCatalogRevision: config.ConsumptionProvenance.RegistryDatasetRevision, Operations: operations}
}

func testRegistryAPIMetadata(t *testing.T) RegistryAPIMetadata {
	t.Helper()
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := LoadRegistryAPIMetadata("../../config/registry/api-metadata.v1.json", "../../config/registry/api-metadata-source-pin.v1.json", canaries)
	if err != nil {
		t.Fatal(err)
	}
	return metadata
}

func TestPublicStatusHandlerBrowserAndCacheContract(t *testing.T) {
	handler, err := NewPublicStatusHandler(staticPublicSource{document: testPublicDocument(t)}, []string{"https://datapan.statpan.com"})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "https://health.example/datapan/v1/dependencies", nil)
	request.Header.Set("Origin", "https://datapan.statpan.com")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != "https://datapan.statpan.com" {
		t.Fatalf("origin=%q", got)
	}
	if recorder.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("credentialed CORS must never be enabled")
	}
	if recorder.Header().Get("Vary") != "Origin" || !strings.Contains(recorder.Header().Get("Cache-Control"), "max-age=30") || recorder.Header().Get("ETag") == "" {
		t.Fatal("cache/CORS headers missing")
	}
	if err := schemas.ValidateDependencyObservationV1(recorder.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(recorder.Body.String()), "dataset_id") || strings.Contains(strings.ToLower(recorder.Body.String()), "endpoint") || strings.Contains(strings.ToLower(recorder.Body.String()), "credential") {
		t.Fatal("private identity leaked")
	}

	etag := recorder.Header().Get("ETag")
	conditional := httptest.NewRequest(http.MethodGet, "/datapan/v1/dependencies", nil)
	conditional.Header.Set("If-None-Match", etag)
	conditionalRecorder := httptest.NewRecorder()
	handler.ServeHTTP(conditionalRecorder, conditional)
	if conditionalRecorder.Code != http.StatusNotModified || conditionalRecorder.Body.Len() != 0 {
		t.Fatal("conditional GET did not return empty 304")
	}

	head := httptest.NewRequest(http.MethodHead, "/datapan/v1/dependencies", nil)
	headRecorder := httptest.NewRecorder()
	handler.ServeHTTP(headRecorder, head)
	if headRecorder.Code != http.StatusOK || headRecorder.Body.Len() != 0 || headRecorder.Header().Get("Content-Length") == "" {
		t.Fatal("HEAD contract mismatch")
	}
}

func TestInstalledProxyStatusAliasPreservesHTTPContract(t *testing.T) {
	handler, err := NewPublicStatusHandler(staticPublicSource{document: testPublicDocument(t)}, []string{"https://datapan.statpan.com"})
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			var canonical *httptest.ResponseRecorder
			for _, path := range []string{"/datapan/v1/status", "/v1/status"} {
				r := httptest.NewRequest(method, path, nil)
				r.Header.Set("Origin", "https://datapan.statpan.com")
				r.Header.Set("Access-Control-Request-Method", "GET")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, r)
				if canonical == nil {
					canonical = response
					continue
				}
				if response.Code != canonical.Code || response.Body.String() != canonical.Body.String() {
					t.Fatal("private proxy alias changed status representation")
				}
				for _, header := range []string{"Content-Type", "Content-Length", "Cache-Control", "ETag", "Vary", "Deprecation", "Sunset", "Link", "Access-Control-Allow-Origin", "Access-Control-Allow-Methods"} {
					if response.Header().Get(header) != canonical.Header().Get(header) {
						t.Fatalf("private proxy alias changed %s", header)
					}
				}
			}
		})
	}
	for _, path := range []string{"/v1/status?run=1", "/v1/services", "/v1/dependencies", "/v1/execute"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Fatal("private alias opened another path or query")
		}
	}
	denied := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	denied.Header.Set("Origin", "https://unapproved.example")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, denied)
	if response.Code != http.StatusForbidden {
		t.Fatal("private alias bypassed origin policy")
	}
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	conditional := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	conditional.Header.Set("If-None-Match", get.Header().Get("ETag"))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, conditional)
	if get.Code != http.StatusOK || response.Code != http.StatusNotModified || response.Body.Len() != 0 {
		t.Fatal("private alias lost conditional status semantics")
	}
}

func TestInstalledProxyAliasSharesPublicAdmission(t *testing.T) {
	handler, err := NewPublicStatusHandler(staticPublicSource{document: testPublicDocument(t)}, []string{"https://datapan.statpan.com"})
	if err != nil {
		t.Fatal(err)
	}
	guard, err := NewPublicReadGuard(handler, PublicReadLimits{RequestsPerSecond: 1, Burst: 1, MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	guard.now = func() time.Time { return guard.updated }
	canonical := httptest.NewRecorder()
	guard.ServeHTTP(canonical, httptest.NewRequest(http.MethodGet, "/datapan/v1/status", nil))
	alias := httptest.NewRequest(http.MethodGet, "/v1/status", nil)
	alias.Header.Set("Origin", "https://datapan.statpan.com")
	alias.Header.Set("X-Forwarded-For", "new-client")
	response := httptest.NewRecorder()
	guard.ServeHTTP(response, alias)
	if canonical.Code != http.StatusOK || response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "1" || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Access-Control-Allow-Origin") != "https://datapan.statpan.com" {
		t.Fatal("private alias expanded the shared budget or changed overload policy")
	}
}

func TestPublicStatusHandlerCORSMatrix(t *testing.T) {
	handler, err := NewPublicStatusHandler(staticPublicSource{document: testPublicDocument(t)}, []string{"https://datapan.statpan.com"})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, method, origin, requestedMethod, requestedHeaders string
		want                                                    int
	}{
		{"no-origin", http.MethodGet, "", "", "", 200},
		{"approved", http.MethodGet, "https://datapan.statpan.com", "", "", 200},
		{"denied", http.MethodGet, "https://evil.example", "", "", 403},
		{"preflight", http.MethodOptions, "https://datapan.statpan.com", http.MethodGet, "", 204},
		{"preflight-head", http.MethodOptions, "https://datapan.statpan.com", http.MethodHead, "", 204},
		{"preflight-no-origin", http.MethodOptions, "", http.MethodGet, "", 403},
		{"preflight-method", http.MethodOptions, "https://datapan.statpan.com", http.MethodPost, "", 403},
		{"preflight-header", http.MethodOptions, "https://datapan.statpan.com", http.MethodGet, "Authorization", 403},
		{"post", http.MethodPost, "", "", "", 405},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(test.method, "/datapan/v1/dependencies", nil)
			req.Header.Set("Origin", test.origin)
			req.Header.Set("Access-Control-Request-Method", test.requestedMethod)
			req.Header.Set("Access-Control-Request-Headers", test.requestedHeaders)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, req)
			if recorder.Code != test.want {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if test.want >= 400 && !strings.Contains(recorder.Body.String(), `"status_unavailable"`) {
				t.Fatal("error is not bounded")
			}
			if test.want == 204 && (recorder.Header().Get("Access-Control-Allow-Origin") != test.origin || recorder.Header().Get("Access-Control-Allow-Methods") != "GET, HEAD") {
				t.Fatal("preflight headers mismatch")
			}
		})
	}
}

func TestPublicStatusPreflightVaryCacheDimensions(t *testing.T) {
	handler, err := NewPublicStatusHandler(staticPublicSource{document: testPublicDocument(t)}, []string{"https://datapan.statpan.com"})
	if err != nil {
		t.Fatal(err)
	}
	const wantVary = "Accept-Encoding, Origin, Access-Control-Request-Method, Access-Control-Request-Headers"
	tests := []struct {
		name, origin, requestedMethod, requestedHeaders string
		wantStatus                                      int
	}{
		{"get-empty-headers", "https://datapan.statpan.com", http.MethodGet, "", http.StatusNoContent},
		{"head-empty-headers", "https://datapan.statpan.com", http.MethodHead, "", http.StatusNoContent},
		{"post-empty-headers", "https://datapan.statpan.com", http.MethodPost, "", http.StatusForbidden},
		{"get-authorization", "https://datapan.statpan.com", http.MethodGet, "Authorization", http.StatusForbidden},
		{"no-origin", "", http.MethodGet, "", http.StatusForbidden},
		{"denied-origin", "https://evil.example", http.MethodGet, "", http.StatusForbidden},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, "/datapan/v1/dependencies", nil)
			req.Header.Set("Origin", test.origin)
			req.Header.Set("Access-Control-Request-Method", test.requestedMethod)
			req.Header.Set("Access-Control-Request-Headers", test.requestedHeaders)
			recorder := httptest.NewRecorder()
			recorder.Header().Set("Vary", "Accept-Encoding, origin")
			handler.ServeHTTP(recorder, req)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			if got := recorder.Header().Get("Vary"); got != wantVary {
				t.Fatalf("Vary=%q want=%q", got, wantVary)
			}
		})
	}
}

func TestPublicStatusSourceProjectsExactIdentityAndFreshness(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	currentKey := config.Canaries[0].GatusEndpointKey
	staleKey := config.Canaries[1].GatusEndpointKey
	fixtures := map[string]any{
		currentKey: []map[string]any{{
			"status": 200, "hostname": "private-host-must-not-project", "duration": int64(time.Millisecond),
			"conditionResults": []map[string]any{{"condition": "secret-condition", "success": true}},
			"success":          true, "timestamp": publicNow.Add(-time.Minute), "errors": []string{"secret-provider-message"}, "name": "private-result-name",
		}},
		staleKey: []map[string]any{{"success": false, "timestamp": publicNow.Add(-time.Hour)}},
	}
	var requestedKeys atomic.Int64
	var aggregateRequests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/endpoints/statuses" {
			aggregateRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`["aggregate should never be read"]`))
			return
		}
		key := testGatusEndpointKeyFromPath(r.URL.Path)
		requestedKeys.Add(1)
		if r.URL.RawQuery != "page=1&pageSize=50" {
			t.Errorf("per-key query=%q", r.URL.RawQuery)
		}
		results, ok := fixtures[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeTestGatusEndpointStatus(t, w, key, results)
	}))
	defer server.Close()
	source, err := NewGatusPublicStatusSource(server.URL, config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return publicNow }
	document, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(document.Operations) != 10 {
		t.Fatalf("operations=%d", len(document.Operations))
	}
	byID := map[string]PublicOperationStatus{}
	for _, operation := range document.Operations {
		byID[operation.OperationID] = operation
	}
	if got := byID[config.Canaries[0].OperationID]; got.Availability != "operational" || got.ObservationState != "current" || got.RawObservationState != "succeeded" || got.IncidentState != "operational" || got.PendingCount != 0 {
		t.Fatalf("current=%+v", got)
	}
	if got := byID[config.Canaries[1].OperationID]; got.Availability != "unknown" || got.ObservationState != "stale" || got.RawObservationState != "unknown" || got.IncidentState != "unknown" || got.PendingCount != 0 {
		t.Fatalf("stale=%+v", got)
	}
	if aggregateRequests.Load() != 0 || requestedKeys.Load() != int64(len(config.Canaries)) {
		t.Fatalf("Gatus reads were not limited to the configured per-key paths: aggregate=%d per_key=%d", aggregateRequests.Load(), requestedKeys.Load())
	}
	encoded, _ := json.Marshal(document)
	for _, forbidden := range []string{"private-name", "private-host", "private-result-name", "secret-provider-message", "secret-condition", currentKey, "dataset_id", "endpoint_host", "query", "events"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("forbidden %q projected", forbidden)
		}
	}
}

func TestPublicStatusSourceSeparatesRawObservationIncidentAndRecovery(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		SchemaVersion      string `json:"schema_version"`
		MissingCanaryIndex int    `json:"missing_canary_index"`
		Cases              []struct {
			CanaryIndex int                 `json:"canary_index"`
			Results     []gatusPublicResult `json:"results"`
			Expected    struct {
				ObservationState    string `json:"observation_state"`
				RawObservationState string `json:"raw_observation_state"`
				IncidentState       string `json:"incident_state"`
				PendingCount        int    `json:"pending_count"`
				Availability        string `json:"availability"`
			} `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(mustRead(t, "../../testdata/public-status/incident-policy-v1.json"), &fixture); err != nil || fixture.SchemaVersion != "datapan.health-public-status-incident-fixture.v1" || len(fixture.Cases) != 5 {
		t.Fatalf("invalid fixture: %v", err)
	}
	resultsByKey := make(map[string]any, len(fixture.Cases))
	for _, testCase := range fixture.Cases {
		key := config.Canaries[testCase.CanaryIndex].GatusEndpointKey
		resultsByKey[key] = testCase.Results
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := testGatusEndpointKeyFromPath(r.URL.Path)
		results, ok := resultsByKey[key]
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeTestGatusEndpointStatus(t, w, key, results)
	}))
	defer server.Close()
	source, err := NewGatusPublicStatusSource(server.URL, config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return publicNow }
	document, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]PublicOperationStatus{}
	for _, operation := range document.Operations {
		byID[operation.OperationID] = operation
	}
	for _, testCase := range fixture.Cases {
		got := byID[config.Canaries[testCase.CanaryIndex].OperationID]
		if got.ObservationState != testCase.Expected.ObservationState || got.RawObservationState != testCase.Expected.RawObservationState || got.IncidentState != testCase.Expected.IncidentState || got.PendingCount != testCase.Expected.PendingCount || got.Availability != testCase.Expected.Availability || !isUnknownPublicDiagnosis(got.Diagnosis) {
			t.Fatalf("case %d=%+v", testCase.CanaryIndex, got)
		}
	}
	missing := byID[config.Canaries[fixture.MissingCanaryIndex].OperationID]
	if missing.ObservationState != "not_observed" || missing.RawObservationState != "unknown" || missing.IncidentState != "unknown" || missing.PendingCount != 0 || !isUnknownPublicDiagnosis(missing.Diagnosis) {
		t.Fatalf("missing=%+v", missing)
	}
}

func isUnknownPublicDiagnosis(diagnosis PublicDiagnosis) bool {
	return diagnosis.Code == "unknown" && diagnosis.Determination == "unknown" && diagnosis.AccountableParty == "unknown" && len(diagnosis.RecommendedActionIDs) == 0 && len(diagnosis.AvoidActionIDs) == 0
}

func TestPublicStatusSourceRejectsUnsafeUpstream(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		handler http.Handler
	}{
		{"redirect", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://evil.example", http.StatusFound)
		})},
		{"wrong-type", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`{"key":"public-data_holiday-emergency-clinics","results":[]}`))
		})},
		{"oversized", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.Repeat(" ", maxGatusEndpointStatusBytes+1)))
		})},
		{"duplicate", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"key":"public-data_holiday-emergency-clinics","results":[],"key":"public-data_holiday-emergency-clinics"}`))
		})},
		{"wrong-key", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			writeTestGatusEndpointStatus(t, w, "public-data_other-endpoint", []any{})
		})},
		{"invalid-result-time", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			key := testGatusEndpointKeyFromPath(r.URL.Path)
			writeTestGatusEndpointStatus(t, w, key, []map[string]any{{"success": true, "timestamp": "not-a-time"}})
		})},
		{"missing-result-time", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			key := testGatusEndpointKeyFromPath(r.URL.Path)
			writeTestGatusEndpointStatus(t, w, key, []map[string]any{{"success": true}})
		})},
		{"missing-result-success", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			key := testGatusEndpointKeyFromPath(r.URL.Path)
			writeTestGatusEndpointStatus(t, w, key, []map[string]any{{"timestamp": publicNow.Add(-time.Minute)}})
		})},
		{"null-result-success", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			key := testGatusEndpointKeyFromPath(r.URL.Path)
			writeTestGatusEndpointStatus(t, w, key, []map[string]any{{"success": nil, "timestamp": publicNow.Add(-time.Minute)}})
		})},
		{"case-alias-success", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			key := testGatusEndpointKeyFromPath(r.URL.Path)
			_, _ = w.Write([]byte(`{"key":"` + key + `","results":[{"success":false,"Success":true,"timestamp":"` + publicNow.Add(-time.Minute).Format(time.RFC3339Nano) + `"}]}`))
		})},
		{"case-alias-key", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			key := testGatusEndpointKeyFromPath(r.URL.Path)
			_, _ = w.Write([]byte(`{"key":"` + key + `","Key":"public-data_other-endpoint","results":[]}`))
		})},
		{"too-many-results", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			key := testGatusEndpointKeyFromPath(r.URL.Path)
			results := make([]map[string]any, maxGatusEndpointStatusResults+1)
			for index := range results {
				results[index] = map[string]any{"success": true, "timestamp": publicNow.Add(-time.Duration(index+1) * time.Minute)}
			}
			writeTestGatusEndpointStatus(t, w, key, results)
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/v1/endpoints/statuses" {
					t.Errorf("aggregate Gatus route was requested")
					return
				}
				test.handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			source, err := NewGatusPublicStatusSource(server.URL+"/api/v1/endpoints/statuses", config, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.Snapshot(context.Background()); err == nil || err.Error() != "public status source unavailable" {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func testGatusEndpointKeyFromPath(path string) string {
	const routePrefix = "/api/v1/endpoints/"
	const routeSuffix = "/statuses"
	if !strings.HasPrefix(path, routePrefix) || !strings.HasSuffix(path, routeSuffix) {
		return ""
	}
	key := strings.TrimSuffix(strings.TrimPrefix(path, routePrefix), routeSuffix)
	if key == "" || strings.ContainsAny(key, "/%") {
		return ""
	}
	return key
}

func writeTestGatusEndpointStatus(t *testing.T, w http.ResponseWriter, key string, results any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	body, err := json.Marshal(map[string]any{
		"name":    "private-endpoint-name",
		"group":   "private-group-name",
		"key":     key,
		"results": results,
		"events":  []map[string]any{{"type": "START", "timestamp": publicNow.Add(-time.Hour)}},
	})
	if err != nil {
		t.Errorf("encode native Gatus fixture: %v", err)
		return
	}
	_, _ = w.Write(body)
}

func TestGatusPublicStatusPerKey404KeepsOnlyObservedCanaries(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Run("all missing before first push", func(t *testing.T) {
		var requests atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if testGatusEndpointKeyFromPath(r.URL.Path) == "" {
				t.Errorf("unexpected Gatus path %q", r.URL.Path)
			}
			requests.Add(1)
			http.NotFound(w, r)
		}))
		defer server.Close()
		source, err := NewGatusPublicStatusSource(server.URL+"/api/v1/endpoints/statuses", config, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		source.now = func() time.Time { return publicNow }
		document, err := source.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if requests.Load() != int64(len(config.Canaries)) || len(document.Operations) != len(config.Canaries) {
			t.Fatalf("all configured keys were not read: requests=%d operations=%d", requests.Load(), len(document.Operations))
		}
		for _, operation := range document.Operations {
			if operation.ObservationState != "not_observed" || operation.Availability != "unknown" || operation.ObservedAt != nil || len(operation.History) != 0 {
				t.Fatalf("missing Gatus key became observed or healthy: %+v", operation)
			}
		}
	})

	t.Run("missing key does not erase other results", func(t *testing.T) {
		missingKey := config.Canaries[1].GatusEndpointKey
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := testGatusEndpointKeyFromPath(r.URL.Path)
			if key == missingKey {
				http.NotFound(w, r)
				return
			}
			writeTestGatusEndpointStatus(t, w, key, []map[string]any{{"success": true, "timestamp": publicNow.Add(-time.Minute)}})
		}))
		defer server.Close()
		source, err := NewGatusPublicStatusSource(server.URL, config, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		source.now = func() time.Time { return publicNow }
		document, err := source.Snapshot(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		byID := make(map[string]PublicOperationStatus, len(document.Operations))
		for _, operation := range document.Operations {
			byID[operation.OperationID] = operation
		}
		for index, canary := range config.Canaries {
			operation := byID[canary.OperationID]
			if index == 1 {
				if operation.ObservationState != "not_observed" || operation.Availability != "unknown" {
					t.Fatalf("404 key should remain unobserved: %+v", operation)
				}
				continue
			}
			if operation.ObservationState != "current" || operation.Availability != "operational" {
				t.Fatalf("healthy per-key result was lost beside 404: %+v", operation)
			}
		}
	})
}

func TestGatusPublicStatusUsesBoundedPerKeyReadsAndIgnoresHugeAggregate(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	knownKeys := make(map[string]struct{}, len(config.Canaries))
	for _, canary := range config.Canaries {
		knownKeys[canary.GatusEndpointKey] = struct{}{}
	}
	largeAggregate := bytes.Repeat([]byte{'x'}, 3_950_831)
	var aggregateRequests atomic.Int64
	var perKeyRequests atomic.Int64
	var active atomic.Int32
	var maximumActive atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/endpoints/statuses" {
			aggregateRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(largeAggregate)
			return
		}
		key := testGatusEndpointKeyFromPath(r.URL.Path)
		if _, ok := knownKeys[key]; !ok {
			t.Errorf("unexpected/unconfigured Gatus status key %q", key)
			http.NotFound(w, r)
			return
		}
		if r.URL.RawQuery != "page=1&pageSize=50" {
			t.Errorf("unexpected Gatus page query %q", r.URL.RawQuery)
		}
		perKeyRequests.Add(1)
		current := active.Add(1)
		for observed := maximumActive.Load(); current > observed && !maximumActive.CompareAndSwap(observed, current); observed = maximumActive.Load() {
		}
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)
		writeTestGatusEndpointStatus(t, w, key, []map[string]any{{
			"status": 200, "hostname": "private-upstream-host", "duration": int64(5 * time.Millisecond),
			"conditionResults": []map[string]any{{"condition": "private-condition", "success": true}},
			"success":          true, "timestamp": publicNow.Add(-time.Minute), "errors": []string{"private-upstream-error"},
		}})
	}))
	defer server.Close()

	configuredKey := config.Canaries[0].GatusEndpointKey
	source, err := NewGatusPublicStatusSource(server.URL+"/api/v1/endpoints/statuses", config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating caller-owned config after construction must not redirect requests.
	config.Canaries[0].GatusEndpointKey = "public-data_replaced-key"
	source.now = func() time.Time { return publicNow }
	document, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if aggregateRequests.Load() != 0 || perKeyRequests.Load() != int64(len(knownKeys)) {
		t.Fatalf("aggregate/per-key requests=%d/%d; want 0/%d", aggregateRequests.Load(), perKeyRequests.Load(), len(knownKeys))
	}
	if maximumActive.Load() > maxGatusStatusReadConcurrency || maximumActive.Load() < 1 {
		t.Fatalf("per-key read concurrency=%d; want 1..%d", maximumActive.Load(), maxGatusStatusReadConcurrency)
	}
	for _, operation := range document.Operations {
		if operation.Availability != "operational" || operation.ObservationState != "current" {
			t.Fatalf("per-key native result was not projected: %+v", operation)
		}
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{configuredKey, "private-upstream-host", "private-condition", "private-upstream-error", "events", "results"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("internal Gatus field %q reached public v1 JSON", forbidden)
		}
	}
}

func TestGatusPublicStatusUsesOneSharedDeadlineForPerKeyReads(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if testGatusEndpointKeyFromPath(r.URL.Path) == "" {
			t.Errorf("unexpected Gatus path %q", r.URL.Path)
			return
		}
		requests.Add(1)
		<-r.Context().Done()
	}))
	defer server.Close()
	source, err := NewGatusPublicStatusSource(server.URL, config, 80*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := source.Snapshot(context.Background()); err == nil || err.Error() != "public status source unavailable" {
		t.Fatalf("blocked shared-deadline snapshot error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > 400*time.Millisecond {
		t.Fatalf("snapshot exceeded its shared deadline by too much: %s", elapsed)
	}
	if got := requests.Load(); got == 0 || got > maxGatusStatusReadConcurrency {
		t.Fatalf("requests started after the shared deadline: %d", got)
	}
}

func TestProjectPublicDiagnosisAllowlistAndFallback(t *testing.T) {
	contract, err := LoadDiagnosticContract("../../config/registry/diagnostic-contract-pin.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := contract.ReadFixture("provider-outage.json")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := contract.Decode(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	projected := ProjectPublicDiagnosis(envelope)
	if projected.Code != "provider_outage" || projected.Determination != "inferred" || projected.AccountableParty != "provider" || strings.Join(projected.RecommendedActionIDs, ",") != "check_provider_status" || strings.Join(projected.AvoidActionIDs, ",") != "reissue_credential" {
		t.Fatalf("projection=%+v", projected)
	}

	envelope.SchemaVersion = "datapan.diagnostic-envelope.v2"
	if got := ProjectPublicDiagnosis(envelope); got.Code != "unknown" || got.Determination != "unknown" || got.AccountableParty != "unknown" || len(got.RecommendedActionIDs) != 0 || len(got.AvoidActionIDs) != 0 {
		t.Fatalf("unknown version did not fail closed: %+v", got)
	}
	envelope.SchemaVersion = DiagnosticSchemaVersion
	envelope.Cause.Code = "future_cause"
	if got := ProjectPublicDiagnosis(envelope); got.Code != "unknown" || len(got.RecommendedActionIDs) != 0 {
		t.Fatalf("unsupported cause did not fail closed: %+v", got)
	}
	envelope.Cause.Code = "provider_outage"
	envelope.Actions = json.RawMessage(`{"recommended":[{"action_id":"https://secret.example"}],"avoid":[]}`)
	if got := ProjectPublicDiagnosis(envelope); got.Code != "unknown" || got.AccountableParty != "unknown" {
		t.Fatalf("unsafe action did not fail closed: %+v", got)
	}
}

func TestPublicStatusHandlerSourceFailureIsBounded(t *testing.T) {
	handler, err := NewPublicStatusHandler(staticPublicSource{err: errors.New("secret credential query response")}, []string{"https://datapan.statpan.com"})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/datapan/v1/dependencies", nil))
	if recorder.Code != 503 || recorder.Header().Get("Cache-Control") != "no-store" || strings.Contains(recorder.Body.String(), "secret") {
		t.Fatalf("unsafe error: %s", recorder.Body.String())
	}

	queryRecorder := httptest.NewRecorder()
	handler.ServeHTTP(queryRecorder, httptest.NewRequest(http.MethodGet, "/datapan/v1/dependencies?secret=1", nil))
	if queryRecorder.Code != 404 || queryRecorder.Header().Get("Cache-Control") != "no-store" || !strings.Contains(queryRecorder.Body.String(), `"status_unavailable"`) || strings.Contains(queryRecorder.Body.String(), "secret") {
		t.Fatalf("query-bearing public route was not rejected safely: %s", queryRecorder.Body.String())
	}
}

func TestDatapanStatusRoutesKeepServicesAndDependenciesSeparate(t *testing.T) {
	handler, err := NewPublicStatusHandlerWithRegistryMetadata(staticPublicSource{document: testPublicDocument(t)}, []string{"https://datapan.statpan.com"}, testRegistryAPIMetadata(t))
	if err != nil {
		t.Fatal(err)
	}
	services := []PublicServiceStatus{
		{ServiceID: "dataset-api", Owner: "datapan-data", SurfaceKind: "dataset_api", State: "operational", ObservedAt: publicNow, CheckID: "dataset-api-immutable-deployment", PublicSurface: "https://api.example.test", DeploymentIdentity: strings.Repeat("a", 40)},
		{ServiceID: "registry-distribution", Owner: "datapan-registry", SurfaceKind: "registry_distribution", State: "unknown", ObservedAt: publicNow, CheckID: "registry-distribution-artifact", UnknownReason: "deployment_identity_unavailable"},
		{ServiceID: "datapan-web-atlas", Owner: "datapan", SurfaceKind: "web_delivery", State: "unknown", ObservedAt: publicNow, CheckID: "datapan-web-immutable-release", UnknownReason: "public_surface_unavailable"},
		{ServiceID: "datapan-health", Owner: "datapan-health", SurfaceKind: "health_self", State: "unknown", ObservedAt: publicNow, CheckID: "health-self-immutable-deployment", UnknownReason: "deployment_identity_unavailable"},
	}
	handler.services = &OwnedServiceStatusSource{checks: []OwnedServiceCheck{
		OwnedServiceCheckFunc(func(context.Context, time.Time) PublicServiceStatus { return services[0] }),
		OwnedServiceCheckFunc(func(context.Context, time.Time) PublicServiceStatus { return services[1] }),
		OwnedServiceCheckFunc(func(context.Context, time.Time) PublicServiceStatus { return services[2] }),
		OwnedServiceCheckFunc(func(context.Context, time.Time) PublicServiceStatus { return services[3] }),
	}, now: func() time.Time { return publicNow }}

	serviceRecorder := httptest.NewRecorder()
	handler.ServeHTTP(serviceRecorder, httptest.NewRequest(http.MethodGet, "/datapan/v1/services", nil))
	if serviceRecorder.Code != http.StatusOK || schemas.ValidateServiceStatusV1(serviceRecorder.Body.Bytes()) != nil || strings.Contains(serviceRecorder.Body.String(), "dpr-op-") {
		t.Fatalf("services=%d %s", serviceRecorder.Code, serviceRecorder.Body.String())
	}
	dependencyRecorder := httptest.NewRecorder()
	handler.ServeHTTP(dependencyRecorder, httptest.NewRequest(http.MethodGet, "/datapan/v1/dependencies", nil))
	if dependencyRecorder.Code != http.StatusOK || schemas.ValidateDependencyObservationV1(dependencyRecorder.Body.Bytes()) != nil || strings.Contains(dependencyRecorder.Body.String(), "dataset-api") {
		t.Fatalf("dependencies=%d %s", dependencyRecorder.Code, dependencyRecorder.Body.String())
	}
	legacyRecorder := httptest.NewRecorder()
	handler.ServeHTTP(legacyRecorder, httptest.NewRequest(http.MethodGet, "/datapan/v1/status", nil))
	if legacyRecorder.Code != http.StatusOK || schemas.ValidateLegacyDependencyStatusV1(legacyRecorder.Body.Bytes()) != nil || legacyRecorder.Header().Get("Deprecation") != "true" || legacyRecorder.Header().Get("Sunset") != "Thu, 31 Dec 2026 23:59:59 GMT" || legacyRecorder.Header().Get("Link") != "</datapan/v1/dependencies>; rel=\"successor-version\", </datapan/dependencies/>; rel=\"alternate\"; type=\"text/html\"" {
		t.Fatalf("legacy headers/body=%v %s", legacyRecorder.Header(), legacyRecorder.Body.String())
	}
	for _, route := range []struct{ path, heading string }{{"/datapan/", "Datapan API 상태"}, {"/datapan/services/", "Datapan 관제 상태"}, {"/datapan/dependencies/", "검사 결과"}} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route.path, nil))
		if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/html; charset=utf-8" || recorder.Header().Get("ETag") == "" || !strings.Contains(recorder.Body.String(), route.heading) {
			t.Fatalf("html %s=%d %s", route.path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestRegistryAPIMetadataHTMLDirectoryIsCompleteForPinnedSourceAndBounded(t *testing.T) {
	metadata := testRegistryAPIMetadata(t)
	if metadata.Scope.RegistryWideMetadataComplete || metadata.Scope.Provider != "data.go.kr" || !metadata.Scope.SourceSnapshotComplete {
		t.Fatalf("incorrectly broad Registry scope: %+v", metadata.Scope)
	}
	if metadata.Counts.APIEntities != 12282 || metadata.Counts.APIOperations != 12662 || metadata.Counts.LinkOperations != 8871 || metadata.Counts.Institutions != 416 || metadata.Counts.MatchedHealthCanaries != 10 {
		t.Fatalf("unexpected pinned source counts: %+v", metadata.Counts)
	}
	items, total := metadata.APIPage("", 1, publicAPIsPageSize)
	if total != metadata.Counts.APIEntities || len(items) != publicAPIsPageSize {
		t.Fatalf("directory page is not bounded or complete: total=%d rows=%d", total, len(items))
	}
	if len(metadata.APIs) <= 10 {
		t.Fatalf("inventory only contains canary sample: %d APIs", len(metadata.APIs))
	}

	handler, err := NewPublicStatusHandlerWithRegistryMetadata(staticPublicSource{document: testPublicDocument(t)}, []string{"https://datapan.statpan.com"}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	firstAPI := items[0]
	for _, test := range []struct {
		path      string
		wantTitle string
	}{
		{path: "/datapan/"},
		{path: "/datapan/?page=2"},
		{path: "/datapan/?q=" + url.QueryEscape(firstAPI.Title), wantTitle: firstAPI.Title},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
		if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "공공데이터포털(data.go.kr) API의 Datapan Registry 저장본") || !strings.Contains(recorder.Body.String(), "다른 제공처 전체 API 목록은 포함하지 않습니다") {
			t.Fatalf("bounded inventory route %s=%d", test.path, recorder.Code)
		}
		if test.path == "/datapan/" && strings.Count(recorder.Body.String(), `<article class="status-item">`) != publicAPIsPageSize {
			t.Fatalf("first API page is not exactly bounded: cards=%d", strings.Count(recorder.Body.String(), `<article class="status-item">`))
		}
		if test.path == "/datapan/" && (!strings.Contains(recorder.Body.String(), "최근 수신 기록") || strings.Contains(recorder.Body.String(), "최근 유효 결과")) {
			t.Fatal("legacy Gatus receipt counts imply validated API results")
		}
		if test.path == "/datapan/" && !strings.Contains(recorder.Body.String(), "전체 API 기능별 검사 현황을 확인할 수 없습니다") {
			t.Fatal("directory omitted the unavailable full-operation status warning")
		}
		if test.path == "/datapan/?page=2" && !strings.Contains(recorder.Body.String(), "페이지 2 /") {
			t.Fatalf("second inventory page missing: %s", recorder.Body.String()[:min(300, recorder.Body.Len())])
		}
		if test.wantTitle != "" && !strings.Contains(recorder.Body.String(), test.wantTitle) {
			t.Fatalf("Korean API title search did not find the source record")
		}
	}
	for _, value := range []string{
		"arbitrarysecret/query/localhosttext",
		"https://private.example/path?token=hidden",
		"service_key=do-not-reflect",
		"localhosttext",
	} {
		recorder := httptest.NewRecorder()
		path := "/datapan/?q=" + url.QueryEscape(value)
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusBadRequest || strings.Contains(recorder.Body.String(), value) {
			t.Fatalf("unsafe search was not rejected without reflection (%q): status=%d", value, recorder.Code)
		}
	}
	jsonQuery := httptest.NewRecorder()
	handler.ServeHTTP(jsonQuery, httptest.NewRequest(http.MethodGet, "/datapan/v1/dependencies?secret=1", nil))
	if jsonQuery.Code != http.StatusNotFound || strings.Contains(jsonQuery.Body.String(), "secret") {
		t.Fatalf("query was allowed on the JSON contract: %d %s", jsonQuery.Code, jsonQuery.Body.String())
	}
}

func TestRegistryAPIMetadataHTMLShowsOnlyPerOperationObservationState(t *testing.T) {
	metadata := testRegistryAPIMetadata(t)
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	document := testPublicDocument(t)
	statuses := []PublicOperationStatus{
		{ObservationState: "current", RawObservationState: "succeeded", IncidentState: "operational", Availability: "operational", ObservedAt: publicStatusTimePointer(now.Add(-time.Minute)), HistoryStartedAt: publicStatusTimePointer(now.Add(-24 * time.Hour))},
		{ObservationState: "current", RawObservationState: "failed", IncidentState: "pending", PendingCount: 1, Availability: "degraded", ObservedAt: publicStatusTimePointer(now.Add(-2 * time.Minute))},
		{ObservationState: "current", RawObservationState: "failed", IncidentState: "confirmed", Availability: "degraded", ObservedAt: publicStatusTimePointer(now.Add(-3 * time.Minute))},
		{ObservationState: "stale", RawObservationState: "unknown", IncidentState: "unknown", Availability: "unknown", ObservedAt: publicStatusTimePointer(now.Add(-time.Hour))},
		{ObservationState: "not_observed", RawObservationState: "unknown", IncidentState: "unknown", Availability: "unknown"},
		{ObservationState: "current", RawObservationState: "succeeded", IncidentState: "recovering", Availability: "operational", ObservedAt: publicStatusTimePointer(now.Add(-4 * time.Minute))},
	}
	for index, status := range statuses {
		if index >= len(metadata.HealthCanaryLinks) || index >= len(canaries.Canaries) {
			break
		}
		status.OperationID = metadata.HealthCanaryLinks[index].HealthOperationID
		status.ConsecutiveFailureThreshold = 2
		status.Diagnosis = unknownPublicDiagnosis()
		setPublicOperationStatus(t, &document, status)
	}
	handler, err := NewPublicStatusHandlerWithRegistryMetadata(staticPublicSource{document: document}, []string{"https://datapan.statpan.com"}, metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path  string
		wants []string
	}{
		{path: "/datapan/", wants: []string{"4 / 10개 연결 기능", "검사 연결 전인 API 기능", "API 설명 출처 revision"}},
		{path: "/datapan/dependencies/", wants: []string{"최근 검사 결과 통과", "최근 검사 결과 실패 · 연속 기준 확인 중", "연속 실패 기준 충족", "최근 검사 결과가 오래됨", "검사 연결됨 · 결과 기록 없음", "검사 결과 통과 후 연속 회복 확인 중", "기존 검사 수신 기록 출처", "Registry 저장본 revision", "검사 카탈로그 SHA-256"}},
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status=%d: %s", test.path, recorder.Code, recorder.Body.String())
		}
		for _, want := range test.wants {
			if !strings.Contains(recorder.Body.String(), want) {
				t.Errorf("%s missing %q", test.path, want)
			}
		}
		if strings.Contains(recorder.Body.String(), "API 전체 상태: 정상") || strings.Contains(recorder.Body.String(), "모든 API 정상") {
			t.Fatalf("one operation observation promoted the parent API: %s", test.path)
		}
	}
	failedLink := metadata.HealthCanaryLinks[1]
	failedAPI, ok := metadata.APIByID(failedLink.RegistryAPIID)
	if !ok {
		t.Fatal("pending canary API missing")
	}
	search := "/datapan/?q=" + url.QueryEscape(failedAPI.Title)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, search, nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "최근 검사 결과 실패 · 연속 기준 확인 중") {
		t.Fatalf("current failed raw observation was not shown yellow: %d %s", recorder.Code, recorder.Body.String())
	}
}

func publicStatusTimePointer(value time.Time) *time.Time { return &value }

func setPublicOperationStatus(t *testing.T, document *PublicStatusDocument, replacement PublicOperationStatus) {
	t.Helper()
	for index := range document.Operations {
		if document.Operations[index].OperationID == replacement.OperationID {
			document.Operations[index] = replacement
			return
		}
	}
	t.Fatalf("operation %s missing from test document", replacement.OperationID)
}

func TestExternalDependencyObservationCannotPromoteOwnedService(t *testing.T) {
	document := testPublicDocument(t)
	document.Operations[0] = PublicOperationStatus{
		OperationID:                 document.Operations[0].OperationID,
		ObservedAt:                  &publicNow,
		ObservationState:            "current",
		RawObservationState:         "succeeded",
		IncidentState:               "operational",
		ConsecutiveFailureThreshold: 2,
		Availability:                "operational",
		Diagnosis:                   unknownPublicDiagnosis(),
	}
	handler, err := NewPublicStatusHandler(staticPublicSource{document: document}, []string{"https://datapan.statpan.com"})
	if err != nil {
		t.Fatal(err)
	}

	dependencies := httptest.NewRecorder()
	handler.ServeHTTP(dependencies, httptest.NewRequest(http.MethodGet, "/datapan/v1/dependencies", nil))
	if dependencies.Code != http.StatusOK || !strings.Contains(dependencies.Body.String(), `"availability":"operational"`) {
		t.Fatalf("dependency observation was not retained: %d %s", dependencies.Code, dependencies.Body.String())
	}

	services := httptest.NewRecorder()
	handler.ServeHTTP(services, httptest.NewRequest(http.MethodGet, "/datapan/v1/services", nil))
	if services.Code != http.StatusOK || schemas.ValidateServiceStatusV1(services.Body.Bytes()) != nil {
		t.Fatalf("services=%d %s", services.Code, services.Body.String())
	}
	var serviceDocument ServiceStatusDocument
	if err := json.Unmarshal(services.Body.Bytes(), &serviceDocument); err != nil {
		t.Fatal(err)
	}
	if len(serviceDocument.Services) != 4 {
		t.Fatalf("services=%d", len(serviceDocument.Services))
	}
	for _, service := range serviceDocument.Services {
		if service.State != "unknown" || service.DeploymentIdentity != "" || service.UnknownReason != "deployment_identity_unavailable" {
			t.Fatalf("external observation promoted owned service: %+v", service)
		}
	}
}

func TestOwnedServiceChecksRequireOwnImmutableIdentity(t *testing.T) {
	valid := []OwnedServiceCheck{
		OwnedServiceCheckFunc(func(context.Context, time.Time) PublicServiceStatus {
			return PublicServiceStatus{ServiceID: "dataset-api", Owner: "datapan-data", SurfaceKind: "dataset_api", State: "operational", ObservedAt: publicNow, CheckID: "dataset-api-immutable-deployment", PublicSurface: "https://api.example.test", DeploymentIdentity: strings.Repeat("a", 40)}
		}),
		OwnedServiceCheckFunc(func(context.Context, time.Time) PublicServiceStatus {
			return PublicServiceStatus{ServiceID: "registry-distribution", Owner: "datapan-registry", SurfaceKind: "registry_distribution", State: "degraded", ObservedAt: publicNow, CheckID: "registry-distribution-artifact", PublicSurface: "https://registry.example.test", DeploymentIdentity: strings.Repeat("b", 40)}
		}),
		OwnedServiceCheckFunc(func(context.Context, time.Time) PublicServiceStatus {
			return PublicServiceStatus{ServiceID: "datapan-web-atlas", Owner: "datapan", SurfaceKind: "web_delivery", State: "unknown", ObservedAt: publicNow, CheckID: "datapan-web-immutable-release", UnknownReason: "configuration_unavailable"}
		}),
		OwnedServiceCheckFunc(func(context.Context, time.Time) PublicServiceStatus {
			return PublicServiceStatus{ServiceID: "datapan-health", Owner: "datapan-health", SurfaceKind: "health_self", State: "unknown", ObservedAt: publicNow, CheckID: "health-self-immutable-deployment", UnknownReason: "deployment_identity_unavailable"}
		}),
	}
	source, err := NewOwnedServiceStatusSource(valid)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return publicNow }
	document, err := source.Snapshot(context.Background())
	if err != nil || schemas.ValidateServiceStatusV1(mustJSON(t, document)) != nil {
		t.Fatalf("valid owned checks failed: document=%+v err=%v", document, err)
	}
	encoded := mustJSON(t, document)
	var projected map[string]any
	_ = json.Unmarshal(encoded, &projected)
	for _, service := range projected["services"].([]any) {
		entry := service.(map[string]any)
		if entry["service_id"] == "dataset-api" {
			entry["owner"] = "datapan"
		}
	}
	wrongOwner, _ := json.Marshal(projected)
	if schemas.ValidateServiceStatusV1(wrongOwner) == nil {
		t.Fatal("service schema accepted a mismatched owner")
	}

	invalid := append([]OwnedServiceCheck(nil), valid...)
	invalid[0] = OwnedServiceCheckFunc(func(context.Context, time.Time) PublicServiceStatus {
		return PublicServiceStatus{ServiceID: "dataset-api", Owner: "datapan-data", SurfaceKind: "dataset_api", State: "operational", ObservedAt: publicNow, CheckID: "dataset-api-immutable-deployment", PublicSurface: "https://api.example.test"}
	})
	bad, err := NewOwnedServiceStatusSource(invalid)
	if err != nil {
		t.Fatal(err)
	}
	bad.now = func() time.Time { return publicNow }
	if _, err := bad.Snapshot(context.Background()); err == nil {
		t.Fatal("operational service without immutable deployment identity was accepted")
	}
}

func TestPublicStatusDoctorSeparatesContractScopes(t *testing.T) {
	report, err := BuildPublicStatusDoctorReport(context.Background(), DefaultOwnedServiceStatusSource(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != PublicStatusDoctorSchemaVersion || report.ServiceContract != ServiceStatusSchemaVersion || report.DependencyContract != DependencyObservationSchemaVersion || report.DependencyCanaryCount != 10 || report.ExternalObservationMeaning != "external_dependency_observations_not_datapan_service_incidents" {
		t.Fatalf("doctor scope=%+v", report)
	}
	for _, service := range report.OwnedServiceStatus {
		if service.State != "unknown" || service.UnknownReason != "deployment_identity_unavailable" {
			t.Fatalf("doctor did not retain explicit unknown: %+v", service)
		}
	}
	if _, err := BuildPublicStatusDoctorReport(context.Background(), DefaultOwnedServiceStatusSource(), 9); err == nil {
		t.Fatal("doctor accepted a non-canonical dependency scope")
	}
}

func TestPublicStatusDoctorIncludesOnlyValueFreeDurableScheduleReadiness(t *testing.T) {
	at := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	plan, queue := fullSchedulePlan(t, at, 64)
	authority, err := OpenScheduleCoverageAuthority(filepath.Join(t.TempDir(), "schedule-state.json"), plan, queue)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RecordCoverage(at); err != nil {
		t.Fatal(err)
	}
	report, err := BuildPublicStatusDoctorReportWithSchedule(context.Background(), DefaultOwnedServiceStatusSource(), 10, authority.Doctor(at, 20*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if report.ScheduleCoverage.ReceiptState != "current" || report.ScheduleCoverage.Registry != plan.Registry || report.ScheduleCoverage.ShardCount != 64 || report.ScheduleCoverage.Counts.Missing != 12385 {
		t.Fatalf("public doctor omitted durable schedule status: %#v", report.ScheduleCoverage)
	}
	encoded := string(mustJSON(t, report))
	if strings.Contains(encoded, queue[0].Subject) || strings.Contains(encoded, "endpoint") || strings.Contains(encoded, "provider") {
		t.Fatalf("public doctor leaked private schedule input: %s", encoded)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestPublicStatusSchemaRejectsPrivateFields(t *testing.T) {
	document := testPublicDocument(t)
	data, _ := json.Marshal(document)
	var value map[string]any
	_ = json.Unmarshal(data, &value)
	value["credential"] = "redacted-is-still-forbidden"
	tampered, _ := json.Marshal(value)
	if schemas.ValidateHealthPublicStatusV1(tampered) == nil {
		t.Fatal("schema accepted an extra private field")
	}

	document.Operations[0].Diagnosis = PublicDiagnosis{Code: "unknown", Determination: "inferred", AccountableParty: "provider", RecommendedActionIDs: []string{"check_provider_status"}, AvoidActionIDs: []string{}}
	inconsistent, _ := json.Marshal(document)
	if schemas.ValidateHealthPublicStatusV1(inconsistent) == nil {
		t.Fatal("schema accepted a fabricated unknown diagnosis")
	}

	document = testPublicDocument(t)
	document.Operations[0].ObservationState = "stale"
	document.Operations[0].Availability = "operational"
	inconsistent, _ = json.Marshal(document)
	if schemas.ValidateHealthPublicStatusV1(inconsistent) == nil {
		t.Fatal("schema accepted operational availability from a stale observation")
	}

	document = testPublicDocument(t)
	document.Operations[0].RawObservationState = "failed"
	document.Operations[0].IncidentState = "confirmed"
	document.Operations[0].PendingCount = 1
	inconsistent, _ = json.Marshal(document)
	if schemas.ValidateHealthPublicStatusV1(inconsistent) == nil {
		t.Fatal("schema accepted pending count for a confirmed incident")
	}

	document = testPublicDocument(t)
	document.Operations[0].OperationID = document.Operations[1].OperationID
	duplicateIdentity, _ := json.Marshal(document)
	if schemas.ValidateHealthPublicStatusV1(duplicateIdentity) == nil {
		t.Fatal("schema accepted a duplicate public operation identity")
	}

	legacy, _ := json.Marshal(legacyDependencyDocument(testPublicDocument(t)))
	var legacyValue map[string]any
	_ = json.Unmarshal(legacy, &legacyValue)
	legacyOperations := legacyValue["operations"].([]any)
	legacyOperations[0].(map[string]any)["endpoint"] = "private.example"
	unsafeLegacy, _ := json.Marshal(legacyValue)
	if schemas.ValidateLegacyDependencyStatusV1(unsafeLegacy) == nil {
		t.Fatal("legacy schema accepted a private operation field")
	}
}
