package health

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestOperationPlanGatusDeliveryUsesBoundedPerKeyPushAndReadback(t *testing.T) {
	key := stableOperationGatusEndpointKey("data_go_kr", strings.Repeat("a", 64))
	var acknowledgedAt time.Time
	var acknowledgedAtMu sync.Mutex
	result := OperationObservationResult{
		State: "healthy", Category: "healthy", ObservedAt: time.Now().UTC().Add(-time.Second),
		ReceivedAt: time.Now().UTC(), ReceiptSHA: strings.Repeat("b", 64), LatencyMS: 123,
	}
	var getCalls, postCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-token" {
			t.Errorf("Gatus authorization header was not passed")
		}
		switch r.Method {
		case http.MethodPost:
			postCalls++
			if r.URL.Path != "/api/v1/endpoints/"+key+"/external" || r.URL.Query().Get("success") != "true" || r.URL.Query().Get("duration") != "123ms" || r.URL.Query().Has("error") {
				t.Errorf("unexpected bounded external push: method=%s path_matches=%t query=%v", r.Method, r.URL.Path == "/api/v1/endpoints/"+key+"/external", r.URL.Query())
			}
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			getCalls++
			if r.URL.Path != "/api/v1/endpoints/"+key+"/statuses" || r.URL.Query().Get("page") != "1" || r.URL.Query().Get("pageSize") != "1" || len(r.URL.Query()) != 2 {
				t.Errorf("operation readback did not use the exact per-key status path")
			}
			// Gatus records the native result before the POST response reaches
			// Health. Its result timestamp can therefore precede the HTTP ACK.
			acknowledgedAtMu.Lock()
			resultAt := acknowledgedAt.Add(-100 * time.Millisecond)
			acknowledgedAtMu.Unlock()
			fmt.Fprintf(w, `{"name":"fixture","group":"registry-operations","key":%q,"results":[{"status":200,"hostname":"fixture.invalid","duration":123000000,"errors":[],"conditionResults":[],"success":true,"timestamp":%q}],"events":[]}`, key, resultAt.Format(time.RFC3339Nano))
		default:
			t.Errorf("unexpected Gatus method %s", r.Method)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	delivery, err := NewOperationPlanGatusDelivery(server.URL, "synthetic-token", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenOperationAttemptStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	startedAt := result.ObservedAt.Add(-time.Second)
	binding := OperationAttemptBinding{
		SourceID: "data_go_kr", OperationID: strings.Repeat("a", 64), RegistryRevision: strings.Repeat("1", 40),
		ReleaseManifestSHA: strings.Repeat("2", 64), IndexSHA: strings.Repeat("3", 64), ShardSHA: strings.Repeat("4", 64),
		GatusKey: key, ObservationPeriod: time.Minute,
	}
	claim, err := store.BeginAttempt(binding, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", startedAt, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CompleteAttempt(claim, result, result.ReceivedAt); err != nil {
		t.Fatal(err)
	}
	deliveryClaim, err := store.ClaimDelivery(binding.SourceID, binding.OperationID, claim.AttemptID, claim.Generation, result.ReceivedAt.Add(time.Millisecond), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ackTime, err := delivery.Push(ctx, key, result)
	if err != nil || ackTime.IsZero() {
		t.Fatalf("bounded external result was not acknowledged: at=%v err=%v", ackTime, err)
	}
	acknowledgedAtMu.Lock()
	acknowledgedAt = ackTime
	acknowledgedAtMu.Unlock()
	readbackAt, state, err := delivery.Readback(ctx, key, result, ackTime)
	if err != nil || readbackAt.IsZero() || state != "healthy" || postCalls != 1 || getCalls != 1 {
		t.Fatalf("per-key readback did not verify the pushed identity/state: at=%v state=%s post=%d get=%d err=%v", readbackAt, state, postCalls, getCalls, err)
	}
	if readbackAt.Before(ackTime) {
		t.Fatalf("GET completion was confused with the older native result timestamp: ack=%v readback=%v", ackTime, readbackAt)
	}
	if err := store.AcknowledgeDelivery(deliveryClaim, ackTime); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordGatusReadback(binding.SourceID, binding.OperationID, claim.AttemptID, claim.Generation, readbackAt, state); err != nil {
		t.Fatalf("verified GET completion must satisfy the durable ACK ordering: %v", err)
	}
}

func TestDecodeOperationGatusStatusRequiresUnambiguousNativeFields(t *testing.T) {
	key := stableOperationGatusEndpointKey("data_go_kr", strings.Repeat("a", 64))
	at := time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)
	valid := fmt.Sprintf(`{"key":%q,"results":[{"success":true,"duration":123000000,"timestamp":%q}]}`, key, at)
	cases := []struct {
		name string
		body string
	}{
		{name: "missing key", body: fmt.Sprintf(`{"results":[{"success":true,"duration":123000000,"timestamp":%q}]}`, at)},
		{name: "null key", body: fmt.Sprintf(`{"key":null,"results":[{"success":true,"duration":123000000,"timestamp":%q}]}`, at)},
		{name: "missing success", body: fmt.Sprintf(`{"key":%q,"results":[{"duration":123000000,"timestamp":%q}]}`, key, at)},
		{name: "null success", body: fmt.Sprintf(`{"key":%q,"results":[{"success":null,"duration":123000000,"timestamp":%q}]}`, key, at)},
		{name: "wrong success type", body: fmt.Sprintf(`{"key":%q,"results":[{"success":1,"duration":123000000,"timestamp":%q}]}`, key, at)},
		{name: "missing duration", body: fmt.Sprintf(`{"key":%q,"results":[{"success":true,"timestamp":%q}]}`, key, at)},
		{name: "null duration", body: fmt.Sprintf(`{"key":%q,"results":[{"success":true,"duration":null,"timestamp":%q}]}`, key, at)},
		{name: "wrong duration type", body: fmt.Sprintf(`{"key":%q,"results":[{"success":true,"duration":"123000000","timestamp":%q}]}`, key, at)},
		{name: "missing timestamp", body: fmt.Sprintf(`{"key":%q,"results":[{"success":true,"duration":123000000}]}`, key)},
		{name: "null timestamp", body: fmt.Sprintf(`{"key":%q,"results":[{"success":true,"duration":123000000,"timestamp":null}]}`, key)},
		{name: "duplicate success", body: fmt.Sprintf(`{"key":%q,"results":[{"success":true,"success":false,"duration":123000000,"timestamp":%q}]}`, key, at)},
		{name: "case alias", body: fmt.Sprintf(`{"key":%q,"results":[{"success":true,"Success":false,"duration":123000000,"timestamp":%q}]}`, key, at)},
		{name: "unknown top-level field", body: fmt.Sprintf(`{"key":%q,"unexpected":true,"results":[{"success":true,"duration":123000000,"timestamp":%q}]}`, key, at)},
		{name: "two results despite page size one", body: fmt.Sprintf(`{"key":%q,"results":[{"success":true,"duration":123000000,"timestamp":%q},{"success":true,"duration":123000000,"timestamp":%q}]}`, key, at, at)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, _, _, err := decodeOperationGatusStatus([]byte(test.body), key); err == nil {
				t.Fatal("ambiguous or incomplete native Gatus result was accepted")
			}
		})
	}
	if _, success, duration, err := decodeOperationGatusStatus([]byte(valid), key); err != nil || !success || duration != 123000000 {
		t.Fatalf("valid pinned native status failed: success=%v duration=%d err=%v", success, duration, err)
	}
	nativeOptional := fmt.Sprintf(`{"name":"probe","group":"registry-operations","key":%q,"results":[{"status":200,"hostname":"fixture.invalid","duration":123000000,"errors":[],"conditionResults":[{"condition":"[STATUS] == 200","success":true}],"success":true,"timestamp":%q}],"events":[{"type":"HEALTHY","timestamp":%q}]}`, key, at, at)
	if _, success, duration, err := decodeOperationGatusStatus([]byte(nativeOptional), key); err != nil || !success || duration != 123000000 {
		t.Fatalf("valid pinned optional native fields failed: success=%v duration=%d err=%v", success, duration, err)
	}
}

func TestOperationPlanGatusReadbackRejectsWrongKeyDurationAndOversizedBody(t *testing.T) {
	key := stableOperationGatusEndpointKey("data_go_kr", strings.Repeat("c", 64))
	otherKey := stableOperationGatusEndpointKey("data_go_kr", strings.Repeat("d", 64))
	at := time.Now().UTC()
	cases := []struct {
		name string
		body string
	}{
		{name: "wrong identity", body: fmt.Sprintf(`{"key":%q,"results":[{"success":true,"duration":1,"timestamp":%q}]}`, otherKey, at.Format(time.RFC3339Nano))},
		{name: "wrong duration", body: fmt.Sprintf(`{"key":%q,"results":[{"success":true,"duration":1,"timestamp":%q}]}`, key, at.Format(time.RFC3339Nano))},
		{name: "future result timestamp", body: fmt.Sprintf(`{"key":%q,"results":[{"success":true,"duration":123000000,"timestamp":%q}]}`, key, at.Add(time.Hour).Format(time.RFC3339Nano))},
		{name: "too many results", body: fmt.Sprintf(`{"key":%q,"results":[%s]}`, key, strings.TrimSuffix(strings.Repeat(fmt.Sprintf(`{"success":true,"duration":1,"timestamp":%q},`, at.Format(time.RFC3339Nano)), maxOperationGatusHistoryRows+1), ","))},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			delivery, err := NewOperationPlanGatusDelivery(server.URL, "synthetic-token", 3*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			result := OperationObservationResult{State: "healthy", Category: "healthy", ObservedAt: at.Add(-time.Second), ReceivedAt: at, ReceiptSHA: strings.Repeat("e", 64), LatencyMS: 123}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, _, err := delivery.Readback(ctx, key, result, at); err == nil {
				t.Fatal("mismatched per-key readback was accepted")
			}
		})
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxOperationGatusReadbackBytes+1)))
	}))
	defer server.Close()
	delivery, err := NewOperationPlanGatusDelivery(server.URL, "synthetic-token", 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	result := OperationObservationResult{State: "healthy", Category: "healthy", ObservedAt: at.Add(-time.Second), ReceivedAt: at, ReceiptSHA: strings.Repeat("f", 64), LatencyMS: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := delivery.Readback(ctx, key, result, at); err == nil {
		t.Fatal("oversized per-key status body was accepted")
	}
}

func TestOperationPlanGatusDeliveryRejectsInvalidTarget(t *testing.T) {
	for _, target := range []string{"/api/v1/endpoints/statuses", "other_group_key", "registry-operations_registry-../../credential"} {
		if validPlanGatusEndpointKey(target) {
			t.Fatalf("invalid per-key Gatus target %q was accepted", target)
		}
	}
	if _, err := NewOperationPlanGatusDelivery("https://user:secret@gatus.example", "token", time.Second); err == nil {
		t.Fatal("userinfo-bearing Gatus base URL was accepted")
	}
}
