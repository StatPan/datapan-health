package health

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOperationPlanGatusDeliveryUsesBoundedPerKeyPushAndReadback(t *testing.T) {
	key := stableOperationGatusEndpointKey("data_go_kr", strings.Repeat("a", 64))
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
			if r.URL.Path != "/api/v1/endpoints/"+key+"/statuses" {
				t.Errorf("operation readback did not use the exact per-key status path")
			}
			fmt.Fprintf(w, `{"key":%q,"results":[{"success":true,"duration":123000000,"timestamp":%q,"errors":[]}]}`, key, time.Now().UTC().Format(time.RFC3339Nano))
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
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	acknowledgedAt, err := delivery.Push(ctx, key, result)
	if err != nil || acknowledgedAt.IsZero() {
		t.Fatalf("bounded external result was not acknowledged: at=%v err=%v", acknowledgedAt, err)
	}
	readbackAt, state, err := delivery.Readback(ctx, key, result, acknowledgedAt)
	if err != nil || readbackAt.IsZero() || state != "healthy" || postCalls != 1 || getCalls != 1 {
		t.Fatalf("per-key readback did not verify the pushed identity/state: at=%v state=%s post=%d get=%d err=%v", readbackAt, state, postCalls, getCalls, err)
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
