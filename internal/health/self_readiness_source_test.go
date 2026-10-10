package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func readySelfReadinessDocument(t *testing.T, config CanaryConfig, now time.Time) schedulerReadinessDocument {
	t.Helper()
	canaries := make([]CanaryProgress, 0, len(config.Canaries))
	for _, canary := range config.Canaries {
		started, accepted := now.Add(-20*time.Second), now.Add(-10*time.Second)
		delivered, observed := now.Add(-5*time.Second), now.Add(-15*time.Second)
		canaries = append(canaries, CanaryProgress{OperationID: canary.OperationID, LastStarted: &started, LastAccepted: &accepted, LastDelivered: &delivered, OriginalObservedAt: &observed, State: "ready", Reason: "delivered"})
	}
	lastLoop := now.Add(-time.Second)
	return schedulerReadinessDocument{SchemaVersion: "datapan.health-self-readiness.v1", Ready: true, State: "ready", Reason: "pipeline_current", LastLoop: &lastLoop, StateFailures: 3, Canaries: canaries, PublicReadback: "not_checked", DeploymentIdentity: "not_checked"}
}

func readinessHTTPFixture(t *testing.T, report schedulerReadinessDocument, status int, contentType string) *httptest.Server {
	t.Helper()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
}

func TestSchedulerHealthSelfReadinessSourceProjectsOnlySafeAggregate(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	server := readinessHTTPFixture(t, readySelfReadinessDocument(t, config, now), http.StatusOK, "application/json; charset=utf-8")
	defer server.Close()
	source, err := NewSchedulerHealthSelfReadinessSource(server.URL+"/status", config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	value, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !value.Ready || value.State != "ready" || value.Reason != "pipeline_current" || value.LastLoop == nil || value.ValidUntil == nil || value.ValidUntil.Sub(now) != 4*time.Second {
		t.Fatalf("aggregate=%+v", value)
	}
	encoded, _ := json.Marshal(value)
	if strings.Contains(string(encoded), "operation_id") || strings.Contains(string(encoded), "dpr-op-") || strings.Contains(string(encoded), "deployment_identity") || strings.Contains(string(encoded), "state_failures") {
		t.Fatalf("private fields escaped aggregate: %s", encoded)
	}
}

func TestSchedulerHealthSelfReadinessAcceptsBoundedDegradedStatus(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	report := readySelfReadinessDocument(t, config, now)
	report.Ready, report.State, report.Reason = false, "degraded", "delivery_stale"
	stale := now.Add(-24 * time.Hour)
	report.Canaries[0].State, report.Canaries[0].Reason, report.Canaries[0].LastDelivered = "degraded", "delivery_stale", &stale
	server := readinessHTTPFixture(t, report, http.StatusServiceUnavailable, "application/json")
	defer server.Close()
	source, err := NewSchedulerHealthSelfReadinessSource(server.URL+"/status", config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	value, err := source.Snapshot(context.Background())
	if err != nil || value.Ready || value.State != "degraded" || value.Reason != "delivery_stale" {
		t.Fatalf("valid 503 readiness was not safely projected: value=%+v err=%v", value, err)
	}
}

func TestSchedulerHealthSelfReadinessAcceptsOperationPlanUnavailableReason(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	report := readySelfReadinessDocument(t, config, now)
	report.Ready, report.State, report.Reason = false, "degraded", "operation_plan_unavailable"
	server := readinessHTTPFixture(t, report, http.StatusServiceUnavailable, "application/json")
	defer server.Close()
	source, err := NewSchedulerHealthSelfReadinessSource(server.URL+"/status", config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	value, err := source.Snapshot(context.Background())
	if err != nil || value.Ready || value.State != "degraded" || value.Reason != "operation_plan_unavailable" {
		t.Fatalf("canonical operation-plan degradation was not projected safely: value=%+v err=%v", value, err)
	}
}

func TestSchedulerHealthSelfReadinessRejectsInvalidReportsAndSources(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	base := readySelfReadinessDocument(t, config, now)
	stale, future := now.Add(-24*time.Hour), now.Add(time.Minute)
	tests := []struct {
		name   string
		mutate func(*schedulerReadinessDocument)
		status int
	}{
		{"ready without delivery", func(v *schedulerReadinessDocument) { v.Canaries[0].LastDelivered = nil }, http.StatusOK},
		{"stale delivery", func(v *schedulerReadinessDocument) { v.Canaries[0].LastDelivered = &stale }, http.StatusOK},
		{"future timestamp", func(v *schedulerReadinessDocument) { v.Canaries[0].LastAccepted = &future }, http.StatusOK},
		{"duplicate identity", func(v *schedulerReadinessDocument) { v.Canaries[1].OperationID = v.Canaries[0].OperationID }, http.StatusOK},
		{"unknown reason", func(v *schedulerReadinessDocument) { v.Reason = "secret_internal_host_token" }, http.StatusOK},
		{"status mismatch", func(v *schedulerReadinessDocument) { v.Ready = false }, http.StatusOK},
		{"stale loop", func(v *schedulerReadinessDocument) { old := now.Add(-time.Minute); v.LastLoop = &old }, http.StatusOK},
		{"503 claims ready", func(*schedulerReadinessDocument) {}, http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := base
			report.Canaries = append([]CanaryProgress(nil), base.Canaries...)
			test.mutate(&report)
			server := readinessHTTPFixture(t, report, test.status, "application/json")
			defer server.Close()
			source, err := NewSchedulerHealthSelfReadinessSource(server.URL+"/status", config, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			source.now = func() time.Time { return now }
			value, err := source.Snapshot(context.Background())
			if err == nil || value.Ready || err.Error() != errHealthSelfReadinessUnavailable.Error() {
				t.Fatalf("unsafe report accepted or raw error surfaced: %+v %v", value, err)
			}
		})
	}
	for _, rawURL := range []string{"https://scheduler:8081/status", "http://scheduler/status", "http://scheduler:8081/status?target=127.0.0.1", "http://user:pass@scheduler:8081/status", "http://example.com:8081/status", "http://0.0.0.0:8081/status"} {
		if _, err := NewSchedulerHealthSelfReadinessSource(rawURL, config, time.Second); err == nil {
			t.Errorf("unsafe readiness URL accepted: %q", rawURL)
		}
	}
}

func TestSchedulerHealthSelfReadinessBoundsResponseAndTimeout(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	report := readySelfReadinessDocument(t, config, now)
	body, _ := json.Marshal(report)
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"wrong content type", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(body)
		}},
		{"redirect", func(w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, httptest.NewRequest(http.MethodGet, "/", nil), "http://127.0.0.1:1/status", http.StatusFound)
		}},
		{"oversized body", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.Repeat("x", maxHealthSelfReadinessBytes+1)))
		}},
		{"unknown field", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(append(body[:len(body)-1], []byte(`,"private_url":"secret"}`)...))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			source, err := NewSchedulerHealthSelfReadinessSource(server.URL+"/status", config, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.Snapshot(context.Background()); err == nil || err.Error() != errHealthSelfReadinessUnavailable.Error() {
				t.Fatalf("invalid response accepted or leaked: %v", err)
			}
		})
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer slow.Close()
	source, err := NewSchedulerHealthSelfReadinessSource(slow.URL+"/status", config, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Snapshot(context.Background()); err == nil || err.Error() != errHealthSelfReadinessUnavailable.Error() {
		t.Fatalf("timeout did not fail closed: %v", err)
	}
}

func TestCachedHealthSelfReadinessCoalescesAndExpiresFreshness(t *testing.T) {
	var clockMu sync.Mutex
	now := time.Now().UTC()
	clock := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	setNow := func(value time.Time) { clockMu.Lock(); now = value; clockMu.Unlock() }
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	source := HealthSelfReadinessSourceFunc(func(context.Context) (HealthSelfReadiness, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		validUntil := clock().Add(3 * time.Second)
		return HealthSelfReadiness{Ready: true, State: "ready", Reason: "pipeline_current", ValidUntil: &validUntil}, nil
	})
	cached, err := NewCachedHealthSelfReadinessSource(source, 30*time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cached.now = clock
	const readers = 12
	results := make(chan error, readers)
	for range readers {
		go func() { _, err := cached.Snapshot(context.Background()); results <- err }()
	}
	<-started
	close(release)
	for range readers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent requests=%d", calls.Load())
	}
	setNow(clock().Add(4 * time.Second))
	if _, err := cached.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expired ready snapshot reused: calls=%d", calls.Load())
	}

	var timeoutCalls atomic.Int32
	timeoutSource := HealthSelfReadinessSourceFunc(func(ctx context.Context) (HealthSelfReadiness, error) {
		timeoutCalls.Add(1)
		<-ctx.Done()
		return HealthSelfReadiness{}, ctx.Err()
	})
	timeoutCache, err := NewCachedHealthSelfReadinessSource(timeoutSource, time.Second, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_, err = timeoutCache.Snapshot(context.Background())
		if err == nil || err.Error() != errHealthSelfReadinessUnavailable.Error() || strings.Contains(err.Error(), "deadline") {
			t.Fatalf("timeout error=%v", err)
		}
	}
	if timeoutCalls.Load() != 1 {
		t.Fatalf("cached timeout calls=%d", timeoutCalls.Load())
	}
	secret := errors.New("credential=https://internal.example/path")
	failedCache, err := NewCachedHealthSelfReadinessSource(HealthSelfReadinessSourceFunc(func(context.Context) (HealthSelfReadiness, error) { return HealthSelfReadiness{}, secret }), time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = failedCache.Snapshot(context.Background())
	if err == nil || err.Error() != errHealthSelfReadinessUnavailable.Error() || strings.Contains(err.Error(), "internal.example") {
		t.Fatalf("source error leaked: %v", err)
	}
}

func TestPublicHTMLReadinessDiagnosisAndHistoryAreAllowlisted(t *testing.T) {
	now := time.Now().UTC()
	projected := projectPublicHTMLReadiness(HealthSelfReadiness{State: "degraded", Reason: "secret_hostname_token"}, true, now)
	if projected.StatusLabel != "점검 필요" || strings.Contains(projected.Summary, "secret") || strings.Contains(projected.Summary, "hostname") {
		t.Fatalf("untrusted readiness reflected: %+v", projected)
	}
	projected = projectPublicHTMLReadiness(HealthSelfReadiness{}, false, now)
	if projected.StatusLabel != "확인 실패" || !strings.Contains(projected.Summary, "API 기능 응답과 별개의 관제 문제") {
		t.Fatalf("readiness failure was conflated: %+v", projected)
	}
	projected = projectPublicHTMLReadiness(HealthSelfReadiness{State: "degraded", Reason: "operation_plan_unavailable"}, true, now)
	if projected.StatusLabel != "점검 필요" || !strings.Contains(projected.Summary, "전체 검사 계획") {
		t.Fatalf("operation-plan readiness reason was not explained in Korean: %+v", projected)
	}
	status := PublicOperationStatus{ObservationState: "current", RawObservationState: "failed", IncidentState: "pending", Diagnosis: PublicDiagnosis{Code: "provider_outage", Determination: "observed", RecommendedActionIDs: []string{"check_provider_status", "https://secret.example"}}, History: []PublicResultHistoryPoint{{ReceivedAt: now.Add(-time.Minute), Success: true}, {ReceivedAt: now, Success: false}}}
	row := addPublicStatusLabels(publicHTMLOperation{}, status, now, true)
	if row.CauseLabel != "공급처 장애가 확인됐습니다." || row.NextActionLabel != "공급처 공지와 서비스 상태를 확인하세요." || len(row.History) != 2 || row.History[0].Class != "history-point-good" || row.History[1].Class != "history-point-bad" {
		t.Fatalf("projection=%+v", row)
	}
	for _, value := range []string{row.CauseLabel, row.NextActionLabel, row.History[0].FullKST, row.History[1].FullKST} {
		if strings.Contains(value, "secret") || strings.Contains(value, "https://") {
			t.Fatalf("private output leaked: %q", value)
		}
	}
}

func TestGatusReceiptHistoryIsBoundedInternalAndRendered(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	results := make([]map[string]any, 75)
	for index := range results {
		results[index] = map[string]any{"timestamp": now.Add(-time.Duration(75-index) * time.Minute), "success": index%2 == 0}
	}
	body, err := json.Marshal([]map[string]any{{"key": config.Canaries[0].GatusEndpointKey, "results": results}})
	if err != nil {
		t.Fatal(err)
	}
	gatus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer gatus.Close()
	source, err := NewGatusPublicStatusSource(gatus.URL, config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	document, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var selected PublicOperationStatus
	for _, operation := range document.Operations {
		if operation.OperationID == config.Canaries[0].OperationID {
			selected = operation
			break
		}
	}
	if len(selected.History) != maxPublicHistoryPoints || selected.History[0].ReceivedAt != now.Add(-50*time.Minute) || selected.History[len(selected.History)-1].ReceivedAt != now.Add(-time.Minute) || selected.HistoryStartedAt == nil || !selected.HistoryStartedAt.Equal(selected.History[0].ReceivedAt) {
		t.Fatalf("history was not recent, ordered, and bounded: len=%d history=%+v", len(selected.History), selected.History)
	}
	jsonWire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(jsonWire), "history") || strings.Contains(string(jsonWire), "received_at") {
		t.Fatalf("internal history changed v1 JSON: %s", jsonWire)
	}

	metadata := testRegistryAPIMetadata(t)
	publicDocument := testPublicDocument(t)
	link := metadata.HealthCanaryLinks[0]
	status := PublicOperationStatus{OperationID: link.HealthOperationID, ObservationState: "current", RawObservationState: "failed", IncidentState: "pending", Availability: "degraded", ObservedAt: timePointer(now.Add(-time.Minute)), Diagnosis: PublicDiagnosis{Code: "provider_outage", Determination: "inferred", RecommendedActionIDs: []string{"check_provider_status"}}, History: []PublicResultHistoryPoint{{ReceivedAt: now.Add(-2 * time.Minute), Success: true}, {ReceivedAt: now.Add(-time.Minute), Success: false}}}
	setPublicOperationStatus(t, &publicDocument, status)
	readiness := HealthSelfReadinessSourceFunc(func(context.Context) (HealthSelfReadiness, error) {
		return HealthSelfReadiness{Ready: false, State: "degraded", Reason: "delivery_stale"}, nil
	})
	handler, err := NewPublicStatusHandlerWithRegistryMetadataAndSelfReadiness(staticPublicSource{document: publicDocument}, []string{"https://datapan.statpan.com"}, metadata, readiness)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/datapan/dependencies/", nil))
	output := recorder.Body.String()
	for _, want := range []string{"Datapan 관제", "점검 필요", "최근 검사 결과 실패 · 연속 기준 확인 중", "공급처 장애로 추정됩니다.", "공급처 공지와 서비스 상태를 확인하세요.", "검사 결과 수신 이력 · 최근 2건", "history-point-good", "history-point-bad"} {
		if recorder.Code != http.StatusOK || !strings.Contains(output, want) {
			t.Errorf("public history/readiness missing %q (status %d)", want, recorder.Code)
		}
	}
	if strings.Contains(output, "dpr-op-") || strings.Contains(output, link.RegistryOperationID) || strings.Contains(output, "https://") || strings.Contains(output, "delivery_stale") {
		t.Fatal("private operation identity, raw reason, or endpoint leaked in HTML")
	}
}
