package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

var publicNow = time.Date(2026, 7, 17, 0, 0, 0, 0, time.UTC)

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
		operations = append(operations, PublicOperationStatus{OperationID: canary.OperationID, ObservationState: "not_observed", Availability: "unknown", Diagnosis: unknownPublicDiagnosis()})
	}
	return PublicStatusDocument{SchemaVersion: PublicStatusSchemaVersion, GeneratedAt: publicNow, DiagnosticRegistryRevision: AcceptedDiagnosticRegistryRevision, ObservationCatalogRevision: config.ConsumptionProvenance.RegistryDatasetRevision, Operations: operations}
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
	body, _ := json.Marshal([]map[string]any{
		{"key": currentKey, "name": "private-name-must-not-project", "results": []map[string]any{
			{"success": true, "timestamp": publicNow.Add(-time.Minute), "errors": []string{"secret-provider-message"}},
		}},
		{"key": staleKey, "results": []map[string]any{
			{"success": false, "timestamp": publicNow.Add(-time.Hour)},
		}},
		{"key": "system_extra", "results": []map[string]any{
			{"success": true, "timestamp": publicNow},
		}},
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
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
	if got := byID[config.Canaries[0].OperationID]; got.Availability != "operational" || got.ObservationState != "current" {
		t.Fatalf("current=%+v", got)
	}
	if got := byID[config.Canaries[1].OperationID]; got.Availability != "unknown" || got.ObservationState != "stale" {
		t.Fatalf("stale=%+v", got)
	}
	encoded, _ := json.Marshal(document)
	for _, forbidden := range []string{"private-name", "secret-provider-message", currentKey, "dataset_id", "endpoint_host", "query"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("forbidden %q projected", forbidden)
		}
	}
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
		{"redirect", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, &http.Request{}, "https://evil.example", http.StatusFound)
		})},
		{"wrong-type", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte("[]"))
		})},
		{"oversized", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.Repeat(" ", maxGatusStatusBytes+1)))
		})},
		{"duplicate", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"key":"public-data_x","results":[]},{"key":"public-data_x","results":[]}]`))
		})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			source, err := NewGatusPublicStatusSource(server.URL, config, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.Snapshot(context.Background()); err == nil || err.Error() != "public status source unavailable" {
				t.Fatalf("err=%v", err)
			}
		})
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
	handler, err := NewPublicStatusHandler(staticPublicSource{document: testPublicDocument(t)}, []string{"https://datapan.statpan.com"})
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
	for _, path := range []string{"/datapan/", "/datapan/services/", "/datapan/dependencies/"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/html; charset=utf-8" || recorder.Header().Get("ETag") == "" || !strings.Contains(recorder.Body.String(), "Datapan") {
			t.Fatalf("html %s=%d %s", path, recorder.Code, recorder.Body.String())
		}
	}
}

func TestExternalDependencyObservationCannotPromoteOwnedService(t *testing.T) {
	document := testPublicDocument(t)
	document.Operations[0] = PublicOperationStatus{
		OperationID:      document.Operations[0].OperationID,
		ObservedAt:       &publicNow,
		ObservationState: "current",
		Availability:     "operational",
		Diagnosis:        unknownPublicDiagnosis(),
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
