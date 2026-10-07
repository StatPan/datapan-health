package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxOperationGatusReadbackBytes = 256 << 10
	maxOperationGatusHistoryRows   = 512
	operationGatusReadbackPolls    = 3
	operationGatusReadbackDelay    = 100 * time.Millisecond
)

var errOperationGatusDeliveryUnavailable = errors.New("operation Gatus delivery is unavailable")

type operationGatusStatusResult struct {
	Success   bool   `json:"success"`
	Duration  int64  `json:"duration"`
	Timestamp string `json:"timestamp"`
}

type operationGatusStatusResponse struct {
	Key     string                       `json:"key"`
	Results []operationGatusStatusResult `json:"results"`
}

// OperationPlanGatusDelivery sends only the Health-owned outcome and reads
// back one configured endpoint. The aggregate Gatus status route is
// deliberately not accepted by this adapter.
type OperationPlanGatusDelivery struct {
	baseURL *url.URL
	token   string
	client  *http.Client
}

func NewOperationPlanGatusDelivery(baseURL, token string, timeout time.Duration) (*OperationPlanGatusDelivery, error) {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(baseURL), "/"))
	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.TrimSpace(token) == "" || len(token) > 16*1024 || timeout < time.Second || timeout > 30*time.Second {
		return nil, errOperationGatusDeliveryUnavailable
	}
	return &OperationPlanGatusDelivery{
		baseURL: parsed,
		token:   token,
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Push posts one redacted Health result to the exact opaque key. The returned
// time marks only the HTTP acknowledgement; it is not Gatus readback proof.
func (delivery *OperationPlanGatusDelivery) Push(ctx context.Context, key string, result OperationObservationResult) (time.Time, error) {
	if delivery == nil || ctx == nil || !validPlanGatusEndpointKey(key) || !validOperationObservationResult(result) {
		return time.Time{}, errOperationGatusDeliveryUnavailable
	}
	values := url.Values{}
	values.Set("success", fmt.Sprintf("%t", result.State == "healthy"))
	values.Set("duration", (time.Duration(result.LatencyMS) * time.Millisecond).String())
	if result.State != "healthy" {
		// This is a fixed Health classification; provider text never reaches Gatus.
		values.Set("error", result.Category)
	}
	endpoint := delivery.endpoint("/api/v1/endpoints/" + url.PathEscape(key) + "/external")
	endpoint.RawQuery = values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), nil)
	if err != nil {
		return time.Time{}, errOperationGatusDeliveryUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+delivery.token)
	response, err := delivery.client.Do(req)
	if err != nil {
		return time.Time{}, errOperationGatusDeliveryUnavailable
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return time.Time{}, errOperationGatusDeliveryUnavailable
	}
	return time.Now().UTC(), nil
}

// Readback verifies the latest result for one exact Gatus key after the HTTP
// acknowledgement. It requires the status, duration, and observation time to
// agree. It never retrieves the aggregate statuses document.
func (delivery *OperationPlanGatusDelivery) Readback(ctx context.Context, key string, expected OperationObservationResult, acknowledgedAt time.Time) (time.Time, string, error) {
	if delivery == nil || ctx == nil || !validPlanGatusEndpointKey(key) || !validOperationObservationResult(expected) || acknowledgedAt.IsZero() {
		return time.Time{}, "", errOperationGatusDeliveryUnavailable
	}
	wantSuccess := expected.State == "healthy"
	wantDuration := (time.Duration(expected.LatencyMS) * time.Millisecond).Nanoseconds()
	endpoint := delivery.endpoint("/api/v1/endpoints/" + url.PathEscape(key) + "/statuses")
	var latestAt time.Time
	for attempt := 0; attempt < operationGatusReadbackPolls; attempt++ {
		response, err := delivery.get(ctx, endpoint)
		if err == nil {
			observedAt, success, duration, parseErr := decodeOperationGatusStatus(response, key)
			readbackAt := time.Now().UTC()
			// Gatus timestamps the native result before the external POST response
			// reaches Health. The timestamp above identifies the result being
			// matched; readbackAt records when this GET verified it and is the time
			// persisted by OperationAttemptStore.RecordGatusReadback.
			if parseErr == nil && !observedAt.Before(acknowledgedAt.Add(-2*time.Second)) && !observedAt.After(acknowledgedAt.Add(2*time.Second)) && !observedAt.After(readbackAt) && success == wantSuccess && duration == wantDuration {
				state := "unhealthy"
				if success {
					state = "healthy"
				}
				return readbackAt, state, nil
			}
			if observedAt.After(latestAt) {
				latestAt = observedAt
			}
		}
		if attempt+1 < operationGatusReadbackPolls {
			timer := time.NewTimer(operationGatusReadbackDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return time.Time{}, "", errOperationGatusDeliveryUnavailable
			case <-timer.C:
			}
		}
	}
	return time.Time{}, "", errOperationGatusDeliveryUnavailable
}

func (delivery *OperationPlanGatusDelivery) get(ctx context.Context, endpoint *url.URL) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, errOperationGatusDeliveryUnavailable
	}
	req.Header.Set("Authorization", "Bearer "+delivery.token)
	response, err := delivery.client.Do(req)
	if err != nil {
		return nil, errOperationGatusDeliveryUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
		return nil, errOperationGatusDeliveryUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxOperationGatusReadbackBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxOperationGatusReadbackBytes {
		return nil, errOperationGatusDeliveryUnavailable
	}
	return raw, nil
}

func (delivery *OperationPlanGatusDelivery) endpoint(path string) *url.URL {
	copy := *delivery.baseURL
	copy.Path = strings.TrimRight(copy.Path, "/") + path
	copy.RawPath = ""
	return &copy
}

func decodeOperationGatusStatus(raw []byte, expectedKey string) (time.Time, bool, int64, error) {
	if len(raw) == 0 || len(raw) > maxOperationGatusReadbackBytes || !validPlanGatusEndpointKey(expectedKey) {
		return time.Time{}, false, 0, errOperationGatusDeliveryUnavailable
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	var status operationGatusStatusResponse
	if decoder.Decode(&status) != nil || decoder.Decode(new(any)) != io.EOF || status.Key != expectedKey || len(status.Results) == 0 || len(status.Results) > maxOperationGatusHistoryRows {
		return time.Time{}, false, 0, errOperationGatusDeliveryUnavailable
	}
	var newest operationGatusStatusResult
	var newestAt time.Time
	for _, item := range status.Results {
		at, err := time.Parse(time.RFC3339Nano, item.Timestamp)
		if err != nil || item.Duration < 0 {
			return time.Time{}, false, 0, errOperationGatusDeliveryUnavailable
		}
		if at.After(newestAt) {
			newest, newestAt = item, at.UTC()
		} else if at.Equal(newestAt) && (item.Success != newest.Success || item.Duration != newest.Duration) {
			return time.Time{}, false, 0, errOperationGatusDeliveryUnavailable
		}
	}
	if newestAt.IsZero() {
		return time.Time{}, false, 0, errOperationGatusDeliveryUnavailable
	}
	return newestAt, newest.Success, newest.Duration, nil
}

func validPlanGatusEndpointKey(key string) bool {
	_, _, ok := splitOperationGatusEndpointKey(key)
	return ok && operationGatusKeyPattern.MatchString(key)
}
