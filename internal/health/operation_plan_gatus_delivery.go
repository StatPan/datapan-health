package health

import (
	"bytes"
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
	maxOperationGatusHistoryRows   = 1
	operationGatusReadbackPolls    = 3
	operationGatusReadbackDelay    = 100 * time.Millisecond
)

var errOperationGatusDeliveryUnavailable = errors.New("operation Gatus delivery is unavailable")

type operationGatusStatusResult struct {
	HTTPStatus       *int                             `json:"status,omitempty"`
	Hostname         *string                          `json:"hostname,omitempty"`
	Duration         *int64                           `json:"duration"`
	Errors           []string                         `json:"errors,omitempty"`
	ConditionResults []*operationGatusConditionResult `json:"conditionResults,omitempty"`
	Success          *bool                            `json:"success"`
	Timestamp        *time.Time                       `json:"timestamp"`
	Name             *string                          `json:"name,omitempty"`
}

type operationGatusStatusResponse struct {
	Name    *string                       `json:"name,omitempty"`
	Group   *string                       `json:"group,omitempty"`
	Key     *string                       `json:"key"`
	Results []*operationGatusStatusResult `json:"results"`
	Events  []*operationGatusEvent        `json:"events,omitempty"`
}

type operationGatusConditionResult struct {
	Condition *string `json:"condition"`
	Success   *bool   `json:"success"`
}

type operationGatusEvent struct {
	Type      *string    `json:"type"`
	Timestamp *time.Time `json:"timestamp"`
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
	query := endpoint.Query()
	query.Set("page", "1")
	query.Set("pageSize", "1")
	endpoint.RawQuery = query.Encode()
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
	if len(raw) == 0 || len(raw) > maxOperationGatusReadbackBytes || !validPlanGatusEndpointKey(expectedKey) || validateOperationGatusJSONMembers(raw) != nil {
		return time.Time{}, false, 0, errOperationGatusDeliveryUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var status operationGatusStatusResponse
	if decoder.Decode(&status) != nil || decoder.Decode(new(any)) != io.EOF || status.Key == nil || *status.Key != expectedKey || len(status.Results) != maxOperationGatusHistoryRows || status.Results[0] == nil {
		return time.Time{}, false, 0, errOperationGatusDeliveryUnavailable
	}
	result := status.Results[0]
	if result.Duration == nil || result.Success == nil || result.Timestamp == nil || result.Timestamp.IsZero() || *result.Duration < 0 || *result.Duration > int64((365*24*time.Hour)) {
		return time.Time{}, false, 0, errOperationGatusDeliveryUnavailable
	}
	if result.HTTPStatus != nil && (*result.HTTPStatus < 0 || *result.HTTPStatus > 599) {
		return time.Time{}, false, 0, errOperationGatusDeliveryUnavailable
	}
	for _, item := range result.ConditionResults {
		if item == nil || item.Condition == nil || item.Success == nil {
			return time.Time{}, false, 0, errOperationGatusDeliveryUnavailable
		}
	}
	for _, item := range status.Events {
		if item == nil || item.Type == nil || item.Timestamp == nil || item.Timestamp.IsZero() || (*item.Type != "START" && *item.Type != "HEALTHY" && *item.Type != "UNHEALTHY") {
			return time.Time{}, false, 0, errOperationGatusDeliveryUnavailable
		}
	}
	return result.Timestamp.UTC(), *result.Success, *result.Duration, nil
}

// validateOperationGatusJSONMembers rejects duplicate JSON members and
// case-folded aliases before encoding/json can apply its last-value-wins or
// case-insensitive struct matching behavior. Object shapes are restricted to
// the native DTO fields emitted by the pinned Gatus v5.36.0 API.
func validateOperationGatusJSONMembers(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	first, err := decoder.Token()
	if err != nil || consumeOperationGatusJSONValue(decoder, first, "status") != nil {
		return errOperationGatusDeliveryUnavailable
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errOperationGatusDeliveryUnavailable
	}
	return nil
}

func consumeOperationGatusJSONValue(decoder *json.Decoder, token json.Token, shape string) error {
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		allowed := operationGatusAllowedFields(shape)
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return errOperationGatusDeliveryUnavailable
			}
			folded := strings.ToLower(key)
			if _, duplicate := seen[folded]; duplicate {
				return errOperationGatusDeliveryUnavailable
			}
			seen[folded] = struct{}{}
			if allowed != nil {
				if _, accepted := allowed[key]; !accepted {
					return errOperationGatusDeliveryUnavailable
				}
			}
			value, err := decoder.Token()
			if err != nil || consumeOperationGatusJSONValue(decoder, value, operationGatusChildShape(shape, key)) != nil {
				return errOperationGatusDeliveryUnavailable
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errOperationGatusDeliveryUnavailable
		}
	case '[':
		childShape := operationGatusArrayItemShape(shape)
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil || consumeOperationGatusJSONValue(decoder, value, childShape) != nil {
				return errOperationGatusDeliveryUnavailable
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errOperationGatusDeliveryUnavailable
		}
	default:
		return errOperationGatusDeliveryUnavailable
	}
	return nil
}

func operationGatusAllowedFields(shape string) map[string]struct{} {
	fields := []string(nil)
	switch shape {
	case "status":
		fields = []string{"name", "group", "key", "results", "events"}
	case "result":
		fields = []string{"status", "hostname", "duration", "errors", "conditionResults", "success", "timestamp", "name"}
	case "condition":
		fields = []string{"condition", "success"}
	case "event":
		fields = []string{"type", "timestamp"}
	default:
		return nil
	}
	allowed := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		allowed[field] = struct{}{}
	}
	return allowed
}

func operationGatusChildShape(parent, field string) string {
	switch {
	case parent == "status" && field == "results":
		return "results"
	case parent == "status" && field == "events":
		return "events"
	case parent == "result" && field == "conditionResults":
		return "conditions"
	default:
		return "any"
	}
}

func operationGatusArrayItemShape(shape string) string {
	switch shape {
	case "results":
		return "result"
	case "events":
		return "event"
	case "conditions":
		return "condition"
	default:
		return "any"
	}
}

func validPlanGatusEndpointKey(key string) bool {
	_, _, ok := splitOperationGatusEndpointKey(key)
	return ok && operationGatusKeyPattern.MatchString(key)
}
