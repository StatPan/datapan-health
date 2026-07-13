package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const localSchemaSHA256 = "0ea4dc0cbcbd2387a47e098a362fcdd136591d45d6a4f8e51b52b1acb2cedf2b"

func TestPinnedSchemaAndCLIStyleFixturesAreCompatible(t *testing.T) {
	schemaBytes := mustRead(t, "../../schemas/datapan.health-probe.v1.schema.json")
	sum := sha256.Sum256(schemaBytes)
	if got := hex.EncodeToString(sum[:]); got != localSchemaSHA256 {
		t.Fatalf("pinned schema changed: %s", got)
	}
	var document any
	if err := json.Unmarshal(schemaBytes, &document); err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("https://schemas.datapan.dev/datapan.health-probe.v1.schema.json", document); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("https://schemas.datapan.dev/datapan.health-probe.v1.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"healthy.json", "unhealthy.json"} {
		raw := mustRead(t, "../../testdata/receipts/v1/"+name)
		var instance any
		if err := json.Unmarshal(raw, &instance); err != nil {
			t.Fatal(err)
		}
		if err := schema.Validate(instance); err != nil {
			t.Fatalf("%s violates pinned CLI schema: %v", name, err)
		}
	}
}

func TestCLIStyleReceiptMapsThroughConfiguredCanaryAndPushes(t *testing.T) {
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		name, endpoint, errorClass string
		success                    bool
		duration                   time.Duration
	}{
		{"healthy.json", "public-data_holiday-emergency-clinics", "healthy:healthy", true, 142 * time.Millisecond},
		{"unhealthy.json", "public-data_qnet-practical-pass-rate", "unhealthy:timeout", false, 5 * time.Second},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			receipt, err := DecodeReceipt(strings.NewReader(string(mustRead(t, "../../testdata/receipts/v1/"+fixture.name))))
			if err != nil {
				t.Fatal(err)
			}
			endpoint, err := canaries.Resolve(receipt)
			if err != nil {
				t.Fatal(err)
			}
			summary := Summarize(receipt, endpoint)
			if summary.EndpointKey != fixture.endpoint || summary.Success != fixture.success || summary.ErrorClass != fixture.errorClass || summary.Duration != fixture.duration {
				t.Fatalf("unexpected summary: %#v", summary)
			}
			assertPushContainsOnlyPublicSummary(t, summary)
		})
	}
}

func TestUnknownCanaryDoesNotUseProbeID(t *testing.T) {
	receipt, err := DecodeReceipt(strings.NewReader(string(mustRead(t, "../../testdata/receipts/v1/healthy.json"))))
	if err != nil {
		t.Fatal(err)
	}
	receipt.ProbeID = "7b8ce434-e662-4f17-a239-0b8ad0d6a29c"
	receipt.Operation.OperationKey = strings.Repeat("f", 64)
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := canaries.Resolve(receipt); err == nil {
		t.Fatal("unmapped operation was accepted")
	}
}

func TestCanaryMappingsMatchConfiguredGatusExternalEndpoints(t *testing.T) {
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	gatus := string(mustRead(t, "../../config/gatus.yaml"))
	for _, canary := range canaries.Canaries {
		parts := strings.SplitN(canary.GatusEndpointKey, "_", 2)
		if len(parts) != 2 || !strings.Contains(gatus, "group: "+parts[0]) || !strings.Contains(gatus, "name: "+parts[1]) {
			t.Fatalf("canary does not resolve to a configured Gatus endpoint: %q", canary.GatusEndpointKey)
		}
		if !strings.Contains(gatus, "interval: "+strconv.Itoa(canary.HeartbeatMinutes)+"m") || !strings.Contains(gatus, "failure-threshold: "+strconv.Itoa(canary.ConsecutiveFailuresBeforeIncident)) {
			t.Fatalf("Gatus cadence or incident threshold is missing for %q", canary.GatusEndpointKey)
		}
	}
}

func TestCanaryConfigRejectsUnboundedOrUnsynchronizedCadence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "canaries.json")
	invalid := `{"canaries":[{"operation_key":"1111111111111111111111111111111111111111111111111111111111111111","gatus_endpoint_key":"public-data_example","tier":"A","interval_minutes":5,"heartbeat_minutes":5,"consecutive_failures_before_incident":1,"missed_schedules_before_heartbeat":1}]}`
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCanaryConfig(path); err == nil {
		t.Fatal("unsafe cadence was accepted")
	}
}

func TestGatusUsesInjectedPostgresWithBoundedRetention(t *testing.T) {
	gatus := string(mustRead(t, "../../config/gatus.yaml"))
	for _, required := range []string{"type: postgres", "path: \"${GATUS_DATABASE_URL}\"", "maximum-number-of-results: 2016", "maximum-number-of-events: 100"} {
		if !strings.Contains(gatus, required) {
			t.Fatalf("missing Gatus storage contract: %s", required)
		}
	}
	if strings.Contains(gatus, "sqlite") {
		t.Fatal("SQLite remains in Gatus configuration")
	}
}

func TestRejectsUnredactedOrUnknownSensitiveFields(t *testing.T) {
	raw := string(mustRead(t, "../../testdata/receipts/v1/unhealthy.json"))
	for _, mutation := range []string{
		strings.Replace(raw, `"credentials_removed": true`, `"credentials_removed": false`, 1),
		strings.Replace(raw, `"endpoint_path": "/api/service/rest/InquiryStatSVC/getGradSiPassList"`, `"endpoint_path": "/api/service/rest/InquiryStatSVC/getGradSiPassList", "query_url": "https://secret.example/?key=secret"`, 1),
		strings.Replace(raw, `"provider_message_class": "timeout"`, `"provider_message_class": "timeout", "response_rows": ["secret"]`, 1),
	} {
		if _, err := DecodeReceipt(strings.NewReader(mutation)); err == nil {
			t.Fatal("unsafe receipt was accepted")
		}
	}
}

func TestRuntimeDecoderRejectsSchemaIncompatibleCLIReceipt(t *testing.T) {
	raw := string(mustRead(t, "../../testdata/receipts/v1/healthy.json"))
	invalid := strings.Replace(raw, `"probe_id": "7b8ce434-e662-4f17-a239-0b8ad0d6a29b"`, `"probe_id": "not-a-uuid"`, 1)
	if _, err := DecodeReceipt(strings.NewReader(invalid)); err == nil {
		t.Fatal("schema-incompatible receipt was accepted")
	}
}

func TestLocalSinkPreservesOnlyDetailedRedactedReceipt(t *testing.T) {
	receipt, err := DecodeReceipt(strings.NewReader(string(mustRead(t, "../../testdata/receipts/v1/unhealthy.json"))))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	if err := NewLocalSink(path).Store(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	stored := string(mustRead(t, path))
	if !strings.Contains(stored, `"dataset_id":"15025329"`) || !strings.Contains(stored, `"endpoint_path":"/api/service/rest/InquiryStatSVC/getGradSiPassList"`) {
		t.Fatal("sink did not preserve the redacted detail")
	}
}

func assertPushContainsOnlyPublicSummary(t *testing.T, summary Summary) {
	t.Helper()
	var gotAuth, gotPath string
	var gotQuery url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath, gotQuery = r.Header.Get("Authorization"), r.URL.Path, r.URL.Query()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	if err := NewGatusPusher(server.URL, "test-token", time.Second).Push(context.Background(), summary); err != nil {
		t.Fatal(err)
	}
	wantSuccess := "false"
	if summary.Success {
		wantSuccess = "true"
	}
	if gotAuth != "Bearer test-token" || gotPath != "/api/v1/endpoints/"+summary.EndpointKey+"/external" || gotQuery.Get("success") != wantSuccess || gotQuery.Get("duration") != summary.Duration.String() {
		t.Fatalf("unexpected push: auth=%q path=%q query=%v", gotAuth, gotPath, gotQuery)
	}
	if !summary.Success && gotQuery.Get("error") != summary.ErrorClass {
		t.Fatalf("wrong public error: %q", gotQuery.Get("error"))
	}
	encoded, _ := json.Marshal(gotQuery)
	for _, forbidden := range []string{"test-token", "dataset", "endpoint_path", "provider_message", "next_actions", "query", "row"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("Gatus query leaked %q: %s", forbidden, encoded)
		}
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
