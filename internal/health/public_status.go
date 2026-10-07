package health

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/StatPan/datapan-health/schemas"
)

const (
	PublicStatusSchemaVersion     = "datapan.health-public-status.v1"
	maxGatusEndpointStatusBytes   = 128 * 1024
	maxGatusEndpointStatusResults = 50
	maxGatusEndpointStatusEvents  = 100
	maxGatusStatusReadConcurrency = 2
	maxGatusStatusCanaries        = 32
	maxPublicHistoryPoints        = 50
)

var (
	publicActionIDPattern        = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,95}$`)
	publicOperationCursorPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

func parsePublicOperationPageQuery(parsed *url.URL) (OperationPageQuery, error) {
	if parsed == nil || len(parsed.RawQuery) > maxPublicHTMLRawQueryBytes {
		return OperationPageQuery{}, ErrOperationReadModelQuery
	}
	values, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return OperationPageQuery{}, ErrOperationReadModelQuery
	}
	query := OperationPageQuery{Limit: operationReadModelMaximumPage}
	for key, entries := range values {
		if len(entries) != 1 {
			return OperationPageQuery{}, ErrOperationReadModelQuery
		}
		value := entries[0]
		switch key {
		case "api_id":
			if !operationReadModelAPIIDPattern.MatchString(value) {
				return OperationPageQuery{}, ErrOperationReadModelQuery
			}
			query.APIID = value
		case "cursor":
			if len(value) > 1024 || !publicOperationCursorPattern.MatchString(value) {
				return OperationPageQuery{}, ErrOperationReadModelQuery
			}
			query.Cursor = value
		case "limit":
			limit, parseErr := strconv.Atoi(value)
			if parseErr != nil || limit < 1 || limit > operationReadModelMaximumPage {
				return OperationPageQuery{}, ErrOperationReadModelQuery
			}
			query.Limit = limit
		case "q":
			if len(value) > operationReadModelMaximumQueryBytes || !utf8.ValidString(value) || unsafePublicHTMLSearch(value) {
				return OperationPageQuery{}, ErrOperationReadModelQuery
			}
			query.Query = strings.TrimSpace(value)
		default:
			return OperationPageQuery{}, ErrOperationReadModelQuery
		}
	}
	return query, nil
}

type PublicStatusDocument struct {
	SchemaVersion              string                  `json:"schema_version"`
	GeneratedAt                time.Time               `json:"generated_at"`
	DiagnosticRegistryRevision string                  `json:"diagnostic_registry_revision"`
	ObservationCatalogRevision string                  `json:"observation_catalog_revision"`
	Operations                 []PublicOperationStatus `json:"operations"`
}

type PublicOperationStatus struct {
	OperationID                 string                     `json:"operation_id"`
	ObservedAt                  *time.Time                 `json:"observed_at,omitempty"`
	HistoryStartedAt            *time.Time                 `json:"-"`
	History                     []PublicResultHistoryPoint `json:"-"`
	ObservationState            string                     `json:"observation_state"`
	RawObservationState         string                     `json:"raw_observation_state"`
	IncidentState               string                     `json:"incident_state"`
	ConsecutiveFailureThreshold int                        `json:"consecutive_failure_threshold"`
	PendingCount                int                        `json:"pending_count"`
	Availability                string                     `json:"availability"`
	Diagnosis                   PublicDiagnosis            `json:"diagnosis"`
}

// PublicResultHistoryPoint keeps only the timestamp Gatus assigned when a
// result reached the monitor and the boolean outcome. It intentionally omits
// provider receipt times, response data, errors, and endpoint identity.
type PublicResultHistoryPoint struct {
	ReceivedAt time.Time
	Success    bool
}

type PublicDiagnosis struct {
	Code                 string   `json:"code"`
	Determination        string   `json:"determination"`
	AccountableParty     string   `json:"accountable_party"`
	RecommendedActionIDs []string `json:"recommended_action_ids"`
	AvoidActionIDs       []string `json:"avoid_action_ids"`
}

type publicAction struct {
	ActionID    string `json:"action_id"`
	Actor       string `json:"actor"`
	RationaleID string `json:"rationale_id"`
}

func unknownPublicDiagnosis() PublicDiagnosis {
	return PublicDiagnosis{Code: "unknown", Determination: "unknown", AccountableParty: "unknown", RecommendedActionIDs: []string{}, AvoidActionIDs: []string{}}
}

func ProjectPublicDiagnosis(envelope DiagnosticEnvelope) PublicDiagnosis {
	if envelope.SchemaVersion != DiagnosticSchemaVersion || !validPublicCause(envelope.Cause.Code) || !validDetermination(envelope.Cause.Determination) {
		return unknownPublicDiagnosis()
	}
	var ownership struct {
		AccountableParty   string `json:"accountable_party"`
		SupportReferenceID string `json:"support_reference_id,omitempty"`
	}
	var actions struct {
		Recommended []publicAction `json:"recommended"`
		Avoid       []publicAction `json:"avoid"`
	}
	if decodeStrictJSON(envelope.Ownership, &ownership) != nil || decodeStrictJSON(envelope.Actions, &actions) != nil || !validAccountableParty(ownership.AccountableParty) {
		return unknownPublicDiagnosis()
	}
	recommended, ok := publicActionIDs(actions.Recommended)
	if !ok {
		return unknownPublicDiagnosis()
	}
	avoid, ok := publicActionIDs(actions.Avoid)
	if !ok {
		return unknownPublicDiagnosis()
	}
	return PublicDiagnosis{Code: envelope.Cause.Code, Determination: envelope.Cause.Determination, AccountableParty: ownership.AccountableParty, RecommendedActionIDs: recommended, AvoidActionIDs: avoid}
}

func publicActionIDs(items []publicAction) ([]string, bool) {
	if len(items) > 8 {
		return nil, false
	}
	ids := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		id := item.ActionID
		if !publicActionIDPattern.MatchString(id) || seen[id] {
			return nil, false
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, true
}

func decodeStrictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return ensureEOF(decoder)
}

func validPublicCause(value string) bool {
	switch value {
	case "ready", "approval_required", "approval_propagating", "credential_invalid", "invalid_input", "rate_limited", "provider_outage", "contract_drift", "semantic_quality", "stale_data", "unknown":
		return true
	default:
		return false
	}
}

func validDetermination(value string) bool {
	return value == "observed" || value == "inferred" || value == "unknown"
}
func validAccountableParty(value string) bool {
	switch value {
	case "user", "datapan", "data_go_kr", "provider", "shared", "unknown":
		return true
	default:
		return false
	}
}

type PublicStatusSource interface {
	Snapshot(context.Context) (PublicStatusDocument, error)
}

type GatusPublicStatusSource struct {
	statusBaseURL *url.URL
	client        *http.Client
	timeout       time.Duration
	canaries      CanaryConfig
	now           func() time.Time
}

func NewGatusPublicStatusSource(statusURL string, canaries CanaryConfig, timeout time.Duration) (*GatusPublicStatusSource, error) {
	parsed, err := url.Parse(statusURL)
	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" || timeout <= 0 || len(canaries.Canaries) == 0 || len(canaries.Canaries) > maxGatusStatusCanaries {
		return nil, errors.New("invalid Gatus status URL")
	}
	basePath, ok := gatusStatusBasePath(parsed.Path)
	if !ok {
		return nil, errors.New("invalid Gatus status URL")
	}
	canaryCopy := canaries
	canaryCopy.Canaries = append([]Canary(nil), canaries.Canaries...)
	seenKeys := make(map[string]struct{}, len(canaryCopy.Canaries))
	seenOperations := make(map[string]struct{}, len(canaryCopy.Canaries))
	for _, canary := range canaryCopy.Canaries {
		if !catalogOperationIDPattern.MatchString(canary.OperationID) || !gatusKeyPattern.MatchString(canary.GatusEndpointKey) || !validCadence(canary) {
			return nil, errors.New("invalid Gatus status URL")
		}
		if _, duplicate := seenKeys[canary.GatusEndpointKey]; duplicate {
			return nil, errors.New("invalid Gatus status URL")
		}
		if _, duplicate := seenOperations[canary.OperationID]; duplicate {
			return nil, errors.New("invalid Gatus status URL")
		}
		seenKeys[canary.GatusEndpointKey] = struct{}{}
		seenOperations[canary.OperationID] = struct{}{}
	}
	baseURL := *parsed
	baseURL.Path = basePath
	baseURL.RawPath = ""
	baseURL.RawQuery = ""
	baseURL.Fragment = ""
	client := &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return &GatusPublicStatusSource{statusBaseURL: &baseURL, client: client, timeout: timeout, canaries: canaryCopy, now: time.Now}, nil
}

func gatusStatusBasePath(path string) (string, bool) {
	const aggregateRoute = "/api/v1/endpoints/statuses"
	if path == "" || path == "/" {
		return "", true
	}
	if !strings.HasSuffix(path, aggregateRoute) {
		return "", false
	}
	prefix := strings.TrimSuffix(path, aggregateRoute)
	if prefix == "" {
		return "", true
	}
	if !strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") {
		return "", false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(prefix, "/"), "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", false
		}
		for _, r := range segment {
			if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' {
				return "", false
			}
		}
	}
	return prefix, true
}

type gatusPublicEndpoint struct {
	Name    string          `json:"name,omitempty"`
	Group   string          `json:"group,omitempty"`
	Key     string          `json:"key"`
	Results json.RawMessage `json:"results"`
	Events  json.RawMessage `json:"events,omitempty"`
}

type gatusPublicResult struct {
	Status           int                    `json:"status,omitempty"`
	Hostname         string                 `json:"hostname,omitempty"`
	Duration         int64                  `json:"duration"`
	Errors           []string               `json:"errors,omitempty"`
	ConditionResults []gatusPublicCondition `json:"conditionResults,omitempty"`
	Success          bool                   `json:"success"`
	Timestamp        time.Time              `json:"timestamp"`
	Name             string                 `json:"name,omitempty"`
}

type gatusPublicCondition struct {
	Condition string `json:"condition"`
	Success   bool   `json:"success"`
}

type gatusPublicEvent struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
}

func exactGatusJSONMember(member string) bool {
	switch member {
	case "name", "group", "key", "results", "events", "status", "hostname", "duration", "errors", "conditionResults", "success", "timestamp", "condition", "type":
		return true
	default:
		return false
	}
}

func (s *GatusPublicStatusSource) Snapshot(ctx context.Context) (PublicStatusDocument, error) {
	if s == nil || s.statusBaseURL == nil || s.client == nil || s.timeout <= 0 {
		return PublicStatusDocument{}, errors.New("public status source unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	snapshotCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	resultsByCanary := make([][]gatusPublicResult, len(s.canaries.Canaries))
	jobs := make(chan int)
	var workers sync.WaitGroup
	var firstErr error
	var firstErrOnce sync.Once
	workerCount := min(maxGatusStatusReadConcurrency, len(s.canaries.Canaries))
	for range workerCount {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				canary := s.canaries.Canaries[index]
				results, err := s.readEndpointStatus(snapshotCtx, canary.GatusEndpointKey)
				if err != nil {
					firstErrOnce.Do(func() {
						firstErr = err
						cancel()
					})
					continue
				}
				resultsByCanary[index] = results
			}
		}()
	}

	for index := range s.canaries.Canaries {
		select {
		case jobs <- index:
		case <-snapshotCtx.Done():
			break
		}
		if snapshotCtx.Err() != nil {
			break
		}
	}
	close(jobs)
	workers.Wait()
	if firstErr != nil || snapshotCtx.Err() != nil {
		return PublicStatusDocument{}, errors.New("public status source unavailable")
	}
	now := s.now().UTC()
	if now.IsZero() || now.Year() < 2020 {
		return PublicStatusDocument{}, errors.New("public status source unavailable")
	}
	operations := make([]PublicOperationStatus, 0, len(s.canaries.Canaries))
	for index, canary := range s.canaries.Canaries {
		operation := PublicOperationStatus{OperationID: canary.OperationID, ObservationState: "not_observed", RawObservationState: "unknown", IncidentState: "unknown", ConsecutiveFailureThreshold: canary.ConsecutiveFailuresBeforeIncident, Availability: "unknown", Diagnosis: unknownPublicDiagnosis()}
		results := resultsByCanary[index]
		operation.History = boundedPublicResultHistory(results, now)
		if len(operation.History) > 0 {
			started := operation.History[0].ReceivedAt
			operation.HistoryStartedAt = &started
		}
		if result, ok := latestGatusPublicResult(results); ok {
			observed := result.Timestamp.UTC()
			operation.ObservedAt = &observed
			age := now.Sub(observed)
			if age >= -30*time.Second && age <= time.Duration(canary.HeartbeatMinutes)*time.Minute {
				operation.ObservationState = "current"
				operation.RawObservationState, operation.IncidentState, operation.PendingCount = projectIncidentState(results, canary.ConsecutiveFailuresBeforeIncident)
				if result.Success {
					operation.Availability = "operational"
				} else {
					operation.Availability = "degraded"
				}
			} else {
				operation.ObservationState = "stale"
			}
		}
		operations = append(operations, operation)
	}
	sort.Slice(operations, func(i, j int) bool { return operations[i].OperationID < operations[j].OperationID })
	document := PublicStatusDocument{SchemaVersion: PublicStatusSchemaVersion, GeneratedAt: now.Truncate(30 * time.Second), DiagnosticRegistryRevision: AcceptedDiagnosticRegistryRevision, ObservationCatalogRevision: s.canaries.ConsumptionProvenance.RegistryDatasetRevision, Operations: operations}
	encoded, err := json.Marshal(document)
	if err != nil || schemas.ValidateHealthPublicStatusV1(encoded) != nil {
		return PublicStatusDocument{}, errors.New("public status source unavailable")
	}
	return document, nil
}

func (s *GatusPublicStatusSource) readEndpointStatus(ctx context.Context, key string) ([]gatusPublicResult, error) {
	if !gatusKeyPattern.MatchString(key) {
		return nil, errors.New("public status source unavailable")
	}
	target := *s.statusBaseURL
	target.Path = strings.TrimSuffix(target.Path, "/") + "/api/v1/endpoints/" + url.PathEscape(key) + "/statuses"
	target.RawQuery = "page=1&pageSize=50"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return nil, errors.New("public status source unavailable")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, errors.New("public status source unavailable")
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxGatusEndpointStatusBytes+1))
	if err != nil || len(data) > maxGatusEndpointStatusBytes {
		return nil, errors.New("public status source unavailable")
	}
	if resp.StatusCode == http.StatusNotFound {
		return []gatusPublicResult{}, nil
	}
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") || validateUniqueJSONMembers(data) != nil {
		return nil, errors.New("public status source unavailable")
	}
	var endpoint gatusPublicEndpoint
	if err := decodeStrictJSON(data, &endpoint); err != nil || endpoint.Key != key || len(endpoint.Results) == 0 {
		return nil, errors.New("public status source unavailable")
	}
	var rawResults []json.RawMessage
	if err := decodeStrictJSON(endpoint.Results, &rawResults); err != nil || rawResults == nil || len(rawResults) > maxGatusEndpointStatusResults {
		return nil, errors.New("public status source unavailable")
	}
	results := make([]gatusPublicResult, len(rawResults))
	for index, rawResult := range rawResults {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(rawResult, &fields); err != nil {
			return nil, errors.New("public status source unavailable")
		}
		successValue, present := fields["success"]
		if !present || len(successValue) == 0 || string(successValue) == "null" {
			return nil, errors.New("public status source unavailable")
		}
		var success bool
		if err := json.Unmarshal(successValue, &success); err != nil {
			return nil, errors.New("public status source unavailable")
		}
		if err := decodeStrictJSON(rawResult, &results[index]); err != nil || results[index].Timestamp.IsZero() {
			return nil, errors.New("public status source unavailable")
		}
		results[index].Success = success
	}
	if len(endpoint.Events) > 0 && string(endpoint.Events) != "null" {
		var events []gatusPublicEvent
		if err := decodeStrictJSON(endpoint.Events, &events); err != nil || events == nil || len(events) > maxGatusEndpointStatusEvents {
			return nil, errors.New("public status source unavailable")
		}
		for _, event := range events {
			if event.Timestamp.IsZero() || (event.Type != "START" && event.Type != "HEALTHY" && event.Type != "UNHEALTHY") {
				return nil, errors.New("public status source unavailable")
			}
		}
	}
	return results, nil
}

func validateUniqueJSONMembers(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanUniqueJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("invalid JSON document")
	}
	return nil
}

func scanUniqueJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || !exactGatusJSONMember(key) {
				return errors.New("invalid JSON object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			if err := scanUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanUniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func boundedPublicResultHistory(results []gatusPublicResult, now time.Time) []PublicResultHistoryPoint {
	ordered := make([]gatusPublicResult, 0, len(results))
	for _, result := range results {
		if !result.Timestamp.IsZero() && !result.Timestamp.After(now.Add(30*time.Second)) {
			ordered = append(ordered, result)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Timestamp.Before(ordered[j].Timestamp) })
	if len(ordered) > maxPublicHistoryPoints {
		ordered = ordered[len(ordered)-maxPublicHistoryPoints:]
	}
	history := make([]PublicResultHistoryPoint, 0, len(ordered))
	for _, result := range ordered {
		history = append(history, PublicResultHistoryPoint{ReceivedAt: result.Timestamp.UTC(), Success: result.Success})
	}
	return history
}

func latestGatusPublicResult(results []gatusPublicResult) (gatusPublicResult, bool) {
	var latest gatusPublicResult
	for _, result := range results {
		if !result.Timestamp.IsZero() && result.Timestamp.After(latest.Timestamp) {
			latest = result
		}
	}
	return latest, !latest.Timestamp.IsZero()
}

func oldestGatusPublicResult(results []gatusPublicResult) (gatusPublicResult, bool) {
	var oldest gatusPublicResult
	for _, result := range results {
		if !result.Timestamp.IsZero() && (oldest.Timestamp.IsZero() || result.Timestamp.Before(oldest.Timestamp)) {
			oldest = result
		}
	}
	return oldest, !oldest.Timestamp.IsZero()
}

// projectIncidentState replays the most recent contiguous result runs against
// the same threshold used by the pinned Gatus alert policy. A current failed
// observation is pending until the failure threshold is met; a current
// successful observation is recovering only when it follows a confirmed
// failure run and has not yet met the matching success threshold.
func projectIncidentState(results []gatusPublicResult, threshold int) (rawState, incidentState string, pendingCount int) {
	ordered := make([]gatusPublicResult, 0, len(results))
	for _, result := range results {
		if !result.Timestamp.IsZero() {
			ordered = append(ordered, result)
		}
	}
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Timestamp.After(ordered[j].Timestamp) })
	if len(ordered) == 0 || threshold < 2 {
		return "unknown", "unknown", 0
	}
	latest := ordered[0]
	run := 0
	for _, result := range ordered {
		if result.Success != latest.Success {
			break
		}
		run++
	}
	if !latest.Success {
		if run >= threshold {
			return "failed", "confirmed", 0
		}
		return "failed", "pending", run
	}
	if run < threshold && run < len(ordered) {
		priorFailedRun := 0
		for _, result := range ordered[run:] {
			if result.Success {
				break
			}
			priorFailedRun++
		}
		if priorFailedRun >= threshold {
			return "succeeded", "recovering", 0
		}
	}
	return "succeeded", "operational", 0
}

type PublicStatusHandler struct {
	source     PublicStatusSource
	services   PublicServiceStatusSource
	readiness  HealthSelfReadinessSource
	origins    map[string]bool
	registry   *RegistryAPIMetadata
	operations PublicRegistryOperationsSource
	display    *PublicOperationDisplayMetadata
}

// PublicRegistryOperationsSource serves a bounded page over the already
// verified in-memory operation projection. Implementations must not call
// providers, Gatus, or scan durable state during a request.
type PublicRegistryOperationsSource interface {
	LookupAPIProgress(apiIDs []string, at time.Time) ([]OperationAPIProgress, error)
	PageOperations(query OperationPageQuery, at time.Time) (OperationReadModelPage, error)
}

type RegistryOperationLookupIdentity struct {
	SourceID    string
	OperationID string
}

// PublicRegistryOperationLookupSource performs a bounded exact-identity lookup
// against the same verified in-memory plan used by the public page reader.
type PublicRegistryOperationLookupSource interface {
	LookupPublicOperationRows(identities []RegistryOperationLookupIdentity, at time.Time) ([]OperationReadModelRow, error)
}

func NewPublicStatusHandler(source PublicStatusSource, origins []string) (*PublicStatusHandler, error) {
	if source == nil || len(origins) == 0 {
		return nil, errors.New("public status source and allowed origins are required")
	}
	allowed := map[string]bool{}
	for _, origin := range origins {
		parsed, err := url.Parse(origin)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || strings.Contains(parsed.Host, "*") || origin != parsed.Scheme+"://"+parsed.Host {
			return nil, errors.New("invalid public status origin")
		}
		allowed[origin] = true
	}
	return &PublicStatusHandler{source: source, services: DefaultOwnedServiceStatusSource(), origins: allowed}, nil
}

func NewPublicStatusHandlerWithRegistryMetadata(source PublicStatusSource, origins []string, metadata RegistryAPIMetadata) (*PublicStatusHandler, error) {
	return NewPublicStatusHandlerWithRegistryMetadataAndSelfReadiness(source, origins, metadata, nil)
}

func NewPublicStatusHandlerWithRegistryMetadataAndSelfReadiness(source PublicStatusSource, origins []string, metadata RegistryAPIMetadata, readiness HealthSelfReadinessSource) (*PublicStatusHandler, error) {
	handler, err := NewPublicStatusHandler(source, origins)
	if err != nil {
		return nil, err
	}
	frozenMetadata, err := cloneVerifiedRegistryAPIMetadata(metadata)
	if err != nil {
		return nil, errors.New("verified Registry API metadata is required")
	}
	handler.registry = &frozenMetadata
	handler.readiness = readiness
	return handler, nil
}

// NewPublicStatusHandlerWithRegistryOperations composes the current ten-canary
// v1 views with a separately pinned, bounded full-operation read model.
func NewPublicStatusHandlerWithRegistryOperations(source PublicStatusSource, origins []string, metadata RegistryAPIMetadata, readiness HealthSelfReadinessSource, operations PublicRegistryOperationsSource) (*PublicStatusHandler, error) {
	handler, err := NewPublicStatusHandlerWithRegistryMetadataAndSelfReadiness(source, origins, metadata, readiness)
	if err != nil {
		return nil, err
	}
	handler.operations = operations
	return handler, nil
}

// NewPublicStatusHandlerWithOperationDisplay adds a separately pinned,
// operator-authored identity label and verified source-document facts for the
// partial Registry scopes. It leaves the underlying operation read model
// unchanged.
func NewPublicStatusHandlerWithOperationDisplay(source PublicStatusSource, origins []string, metadata RegistryAPIMetadata, readiness HealthSelfReadinessSource, operations PublicRegistryOperationsSource, display PublicOperationDisplayMetadata) (*PublicStatusHandler, error) {
	frozenDisplay, err := clonePublicOperationDisplayMetadata(display)
	if err != nil {
		return nil, err
	}
	handler, err := NewPublicStatusHandlerWithRegistryOperations(source, origins, metadata, readiness, operations)
	if err != nil {
		return nil, err
	}
	handler.display = &frozenDisplay
	return handler, nil
}

func (h *PublicStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isDatapanHTMLRoute(r.URL.Path) {
		h.serveDatapanHTML(w, r)
		return
	}
	operationPageRoute := r.URL.Path == "/datapan/v2/operations"
	if r.URL.RawQuery != "" && !operationPageRoute {
		writePublicError(w, http.StatusNotFound)
		return
	}
	if !isDatapanJSONRoute(r.URL.Path) {
		writePublicError(w, http.StatusNotFound)
		return
	}
	mergeVary(w.Header(), "Origin")
	if r.Method == http.MethodOptions {
		mergeVary(w.Header(), "Access-Control-Request-Method", "Access-Control-Request-Headers")
	}
	origin := r.Header.Get("Origin")
	if origin != "" && !h.origins[origin] {
		writePublicError(w, http.StatusForbidden)
		return
	}
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	var operationQuery OperationPageQuery
	if operationPageRoute {
		var queryErr error
		operationQuery, queryErr = parsePublicOperationPageQuery(r.URL)
		if queryErr != nil {
			writePublicError(w, http.StatusBadRequest)
			return
		}
	}
	if r.Method == http.MethodOptions {
		if origin == "" || (r.Header.Get("Access-Control-Request-Method") != http.MethodGet && r.Header.Get("Access-Control-Request-Method") != http.MethodHead) || r.Header.Get("Access-Control-Request-Headers") != "" {
			writePublicError(w, http.StatusForbidden)
			return
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD")
		w.Header().Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		writePublicError(w, http.StatusMethodNotAllowed)
		return
	}
	var data []byte
	var err error
	switch r.URL.Path {
	case "/datapan/v2/operations":
		if h.operations == nil {
			err = ErrOperationReadModelUnavailable
		} else {
			var document OperationReadModelPage
			document, err = h.operations.PageOperations(operationQuery, time.Now().UTC())
			if err == nil {
				data, err = json.Marshal(document)
				if err == nil && schemas.ValidateHealthRegistryOperationsPageV2(data) != nil {
					err = errors.New("Registry operations page invalid")
				}
			}
		}
	case "/datapan/v1/services":
		var document ServiceStatusDocument
		document, err = h.services.Snapshot(r.Context())
		if err == nil {
			data, err = json.Marshal(document)
			if schemas.ValidateServiceStatusV1(data) != nil {
				err = errors.New("service status invalid")
			}
		}
	case "/datapan/v1/dependencies", "/datapan/v1/status", "/v1/status":
		var document PublicStatusDocument
		document, err = h.source.Snapshot(r.Context())
		if err == nil && r.URL.Path == "/datapan/v1/dependencies" {
			data, err = json.Marshal(dependencyDocument(document))
			if schemas.ValidateDependencyObservationV1(data) != nil {
				err = errors.New("dependency status invalid")
			}
		}
		if err == nil && (r.URL.Path == "/datapan/v1/status" || r.URL.Path == "/v1/status") {
			data, err = json.Marshal(legacyDependencyDocument(document))
			if schemas.ValidateLegacyDependencyStatusV1(data) != nil {
				err = errors.New("legacy dependency status invalid")
			}
			w.Header().Set("Deprecation", "true")
			w.Header().Set("Sunset", "Thu, 31 Dec 2026 23:59:59 GMT")
			w.Header().Set("Link", "</datapan/v1/dependencies>; rel=\"successor-version\", </datapan/dependencies/>; rel=\"alternate\"; type=\"text/html\"")
		}
	}
	if err != nil {
		writePublicError(w, http.StatusServiceUnavailable)
		return
	}
	data = append(data, '\n')
	sum := sha256.Sum256(data)
	etag := `"sha256-` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("Cache-Control", "public, max-age=30, stale-if-error=60, no-transform")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("ETag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func isDatapanJSONRoute(path string) bool {
	// The installed Infra adapter strips /datapan before forwarding this
	// existing status route. Keep that private contract on the same read-only
	// handler and admission budget; public ingress still owns its allowlist.
	return path == "/datapan/v1/services" || path == "/datapan/v1/dependencies" || path == "/datapan/v1/status" || path == "/v1/status" || path == "/datapan/v2/operations"
}

func isDatapanHTMLRoute(path string) bool {
	return path == "/datapan/" || path == "/datapan/apis/" || path == "/datapan/services/" || path == "/datapan/dependencies/" || (strings.HasPrefix(path, "/datapan/apis/") && strings.HasSuffix(path, "/"))
}

func mergeVary(header http.Header, fields ...string) {
	values := make([]string, 0, len(header.Values("Vary"))+len(fields))
	seen := map[string]bool{}
	for _, line := range header.Values("Vary") {
		for _, value := range strings.Split(line, ",") {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			key := strings.ToLower(value)
			if !seen[key] {
				seen[key] = true
				values = append(values, http.CanonicalHeaderKey(value))
			}
		}
	}
	for _, value := range fields {
		key := strings.ToLower(value)
		if !seen[key] {
			seen[key] = true
			values = append(values, http.CanonicalHeaderKey(value))
		}
	}
	header.Set("Vary", strings.Join(values, ", "))
}

func writePublicError(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"status_unavailable"}`+"\n")
}
