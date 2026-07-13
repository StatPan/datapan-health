package health

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const healthy = `{"schema_version":"datapan.health-probe.v1","probe_id":"kosis-population","observed_at":"2026-07-13T00:00:00Z","status":"healthy","duration_ms":142}`

func TestDecodeAndSummarizeHealthy(t *testing.T) {
	receipt, err := DecodeReceipt(strings.NewReader(healthy))
	if err != nil {
		t.Fatal(err)
	}
	summary := Summarize(receipt)
	if !summary.Success || summary.Duration != 142*time.Millisecond || summary.EndpointKey != "public-data_kosis-population" {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestUnhealthyMapsOnlyPublicClass(t *testing.T) {
	receipt, err := DecodeReceipt(strings.NewReader(`{"schema_version":"datapan.health-probe.v1","probe_id":"data-go-kr-weather","observed_at":"2026-07-13T00:00:00Z","status":"unhealthy","duration_ms":5000,"error_class":"timeout"}`))
	if err != nil {
		t.Fatal(err)
	}
	summary := Summarize(receipt)
	if summary.Success || summary.ErrorClass != "timeout" {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestRejectsSensitiveOrUnknownFields(t *testing.T) {
	for _, field := range []string{"credential", "query_url", "rows", "response_body", "api_key"} {
		payload := strings.TrimSuffix(healthy, "}") + `,"` + field + `":"secret"}`
		if _, err := DecodeReceipt(strings.NewReader(payload)); err == nil {
			t.Fatalf("accepted forbidden field %q", field)
		}
	}
}

func TestValidationFailures(t *testing.T) {
	cases := []string{
		`{"schema_version":"v2","probe_id":"x","observed_at":"2026-07-13T00:00:00Z","status":"healthy","duration_ms":1}`,
		`{"schema_version":"datapan.health-probe.v1","probe_id":"x","observed_at":"2026-07-13T00:00:00Z","status":"broken","duration_ms":1}`,
		`{"schema_version":"datapan.health-probe.v1","probe_id":"x","observed_at":"2026-07-13T00:00:00Z","status":"unhealthy","duration_ms":1,"error_class":"database_password"}`,
	}
	for _, payload := range cases {
		if _, err := DecodeReceipt(strings.NewReader(payload)); err == nil {
			t.Fatalf("accepted invalid receipt: %s", payload)
		}
	}
}

func TestPushRequest(t *testing.T) {
	var gotAuth, gotPath string
	var gotQuery url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotQuery = r.Header.Get("Authorization"), r.URL.Path, r.URL.Query()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	pusher := NewGatusPusher(server.URL, "test-token", time.Second)
	err := pusher.Push(context.Background(), Summary{EndpointKey: "public-data_kosis-population", Success: false, Duration: 5 * time.Second, ErrorClass: "timeout"})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer test-token" || gotPath != "/api/v1/endpoints/public-data_kosis-population/external" || gotQuery.Get("success") != "false" || gotQuery.Get("duration") != "5s" || gotQuery.Get("error") != "timeout" {
		t.Fatalf("unexpected request: auth=%q path=%q query=%v", gotAuth, gotPath, gotQuery)
	}
	encoded, _ := json.Marshal(gotQuery)
	if strings.Contains(string(encoded), "test-token") {
		t.Fatal("token leaked into query")
	}
}
