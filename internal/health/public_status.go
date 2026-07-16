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
	"strings"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

const (
	PublicStatusSchemaVersion = "datapan.health-public-status.v1"
	maxGatusStatusBytes       = 2 * 1024 * 1024
)

var publicActionIDPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,95}$`)

type PublicStatusDocument struct {
	SchemaVersion              string                  `json:"schema_version"`
	GeneratedAt                time.Time               `json:"generated_at"`
	DiagnosticRegistryRevision string                  `json:"diagnostic_registry_revision"`
	ObservationCatalogRevision string                  `json:"observation_catalog_revision"`
	Operations                 []PublicOperationStatus `json:"operations"`
}

type PublicOperationStatus struct {
	OperationID      string          `json:"operation_id"`
	ObservedAt       *time.Time      `json:"observed_at,omitempty"`
	ObservationState string          `json:"observation_state"`
	Availability     string          `json:"availability"`
	Diagnosis        PublicDiagnosis `json:"diagnosis"`
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
	statusURL string
	client    *http.Client
	canaries  CanaryConfig
	now       func() time.Time
}

func NewGatusPublicStatusSource(statusURL string, canaries CanaryConfig, timeout time.Duration) (*GatusPublicStatusSource, error) {
	parsed, err := url.Parse(statusURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid Gatus status URL")
	}
	client := &http.Client{Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	return &GatusPublicStatusSource{statusURL: statusURL, client: client, canaries: canaries, now: time.Now}, nil
}

type gatusPublicEndpoint struct {
	Key     string              `json:"key"`
	Results []gatusPublicResult `json:"results"`
}
type gatusPublicResult struct {
	Success   bool      `json:"success"`
	Timestamp time.Time `json:"timestamp"`
}

func (s *GatusPublicStatusSource) Snapshot(ctx context.Context) (PublicStatusDocument, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.statusURL, nil)
	if err != nil {
		return PublicStatusDocument{}, errors.New("public status source unavailable")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return PublicStatusDocument{}, errors.New("public status source unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		return PublicStatusDocument{}, errors.New("public status source unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxGatusStatusBytes+1))
	if err != nil || len(data) > maxGatusStatusBytes {
		return PublicStatusDocument{}, errors.New("public status source unavailable")
	}
	var endpoints []gatusPublicEndpoint
	if err := json.Unmarshal(data, &endpoints); err != nil {
		return PublicStatusDocument{}, errors.New("public status source unavailable")
	}
	latest := map[string]gatusPublicResult{}
	seen := map[string]bool{}
	for _, endpoint := range endpoints {
		if seen[endpoint.Key] {
			return PublicStatusDocument{}, errors.New("public status source unavailable")
		}
		seen[endpoint.Key] = true
		for _, result := range endpoint.Results {
			if result.Timestamp.After(latest[endpoint.Key].Timestamp) {
				latest[endpoint.Key] = result
			}
		}
	}
	now := s.now().UTC()
	if now.IsZero() || now.Year() < 2020 {
		return PublicStatusDocument{}, errors.New("public status source unavailable")
	}
	operations := make([]PublicOperationStatus, 0, len(s.canaries.Canaries))
	for _, canary := range s.canaries.Canaries {
		operation := PublicOperationStatus{OperationID: canary.OperationID, ObservationState: "not_observed", Availability: "unknown", Diagnosis: unknownPublicDiagnosis()}
		if result, ok := latest[canary.GatusEndpointKey]; ok && !result.Timestamp.IsZero() {
			observed := result.Timestamp.UTC()
			operation.ObservedAt = &observed
			age := now.Sub(observed)
			if age >= -30*time.Second && age <= time.Duration(canary.HeartbeatMinutes)*time.Minute {
				operation.ObservationState = "current"
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

type PublicStatusHandler struct {
	source  PublicStatusSource
	origins map[string]bool
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
	return &PublicStatusHandler{source: source, origins: allowed}, nil
}

func (h *PublicStatusHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	mergeVary(w.Header(), "Origin")
	if r.Method == http.MethodOptions {
		mergeVary(w.Header(), "Access-Control-Request-Method", "Access-Control-Request-Headers")
	}
	if r.URL.Path != "/v1/status" || r.URL.RawQuery != "" {
		writePublicError(w, http.StatusNotFound)
		return
	}
	origin := r.Header.Get("Origin")
	if origin != "" && !h.origins[origin] {
		writePublicError(w, http.StatusForbidden)
		return
	}
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
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
	document, err := h.source.Snapshot(r.Context())
	if err != nil {
		writePublicError(w, http.StatusServiceUnavailable)
		return
	}
	data, err := json.Marshal(document)
	if err != nil || schemas.ValidateHealthPublicStatusV1(data) != nil {
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
