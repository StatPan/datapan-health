package health

import (
	"context"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

const maxHealthSelfReadinessBytes = 64 * 1024

var errHealthSelfReadinessUnavailable = errors.New("Health self-readiness unavailable")

// HealthSelfReadiness is the safe aggregate projected from the scheduler's
// private readiness report. It intentionally contains no operation identities
// or per-canary progress rows.
type HealthSelfReadiness struct {
	Ready      bool
	State      string
	Reason     string
	LastLoop   *time.Time
	ValidUntil *time.Time
}

type HealthSelfReadinessSource interface {
	Snapshot(context.Context) (HealthSelfReadiness, error)
}

type HealthSelfReadinessSourceFunc func(context.Context) (HealthSelfReadiness, error)

func (f HealthSelfReadinessSourceFunc) Snapshot(ctx context.Context) (HealthSelfReadiness, error) {
	return f(ctx)
}

type schedulerReadinessDocument struct {
	SchemaVersion      string                            `json:"schema_version"`
	Ready              bool                              `json:"ready"`
	State              string                            `json:"state"`
	Reason             string                            `json:"reason"`
	LastLoop           *time.Time                        `json:"last_loop,omitempty"`
	StateFailures      uint64                            `json:"state_failures"`
	Canaries           []CanaryProgress                  `json:"canaries"`
	OperationPlan      *OperationPlanReadinessProjection `json:"operation_plan,omitempty"`
	PublicReadback     string                            `json:"public_readback"`
	DeploymentIdentity string                            `json:"deployment_identity"`
}

type SchedulerHealthSelfReadinessSource struct {
	endpoint      string
	client        *http.Client
	canaries      map[string]Canary
	operationPlan *OperationPlanReadinessBinding
	now           func() time.Time
}

func NewSchedulerHealthSelfReadinessSource(rawURL string, canaries CanaryConfig, timeout time.Duration) (*SchedulerHealthSelfReadinessSource, error) {
	return NewSchedulerHealthSelfReadinessSourceWithOperationPlanBinding(rawURL, canaries, timeout, nil)
}

func NewSchedulerHealthSelfReadinessSourceWithOperationPlanBinding(rawURL string, canaries CanaryConfig, timeout time.Duration, binding *OperationPlanReadinessBinding) (*SchedulerHealthSelfReadinessSource, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.Path != "/status" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" || !validSchedulerReadinessHost(parsed) || len(canaries.Canaries) == 0 || len(canaries.Canaries) > 100 || timeout <= 0 || timeout > 5*time.Second {
		return nil, errors.New("invalid Health self-readiness source")
	}
	if binding != nil && validateOperationPlanReadinessBinding(binding, canaries) != nil {
		return nil, errors.New("invalid Health self-readiness source")
	}
	canaryMap := make(map[string]Canary, len(canaries.Canaries))
	for _, canary := range canaries.Canaries {
		if canary.OperationID == "" || canaryMap[canary.OperationID].OperationID != "" || canary.HeartbeatMinutes <= 0 {
			return nil, errors.New("invalid Health self-readiness source")
		}
		canaryMap[canary.OperationID] = canary
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &SchedulerHealthSelfReadinessSource{endpoint: parsed.String(), client: client, canaries: canaryMap, operationPlan: binding, now: time.Now}, nil
}

func validSchedulerReadinessHost(parsed *url.URL) bool {
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if host == "scheduler" {
		return port == "8081"
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && port != ""
}

func (s *SchedulerHealthSelfReadinessSource) Snapshot(ctx context.Context) (HealthSelfReadiness, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return HealthSelfReadiness{}, errHealthSelfReadinessUnavailable
	}
	response, err := s.client.Do(request)
	if err != nil {
		return HealthSelfReadiness{}, errHealthSelfReadinessUnavailable
	}
	defer response.Body.Close()
	mediaType, _, mediaTypeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if (response.StatusCode != http.StatusOK && response.StatusCode != http.StatusServiceUnavailable) || mediaTypeErr != nil || strings.ToLower(mediaType) != "application/json" {
		return HealthSelfReadiness{}, errHealthSelfReadinessUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxHealthSelfReadinessBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxHealthSelfReadinessBytes || schemas.ValidateHealthSelfReadinessV1(data) != nil {
		return HealthSelfReadiness{}, errHealthSelfReadinessUnavailable
	}
	var report schedulerReadinessDocument
	if decodeStrictJSON(data, &report) != nil || !s.validReport(report, response.StatusCode) {
		return HealthSelfReadiness{}, errHealthSelfReadinessUnavailable
	}
	var lastLoop *time.Time
	if report.LastLoop != nil {
		value := report.LastLoop.UTC()
		lastLoop = &value
	}
	var validUntil *time.Time
	if report.Ready {
		validUntil = readinessValidUntil(report, s.canaries)
		if report.OperationPlan != nil && report.OperationPlan.LastPassAt != nil {
			value := report.OperationPlan.LastPassAt.Add(3 * time.Second).UTC()
			if validUntil == nil || value.Before(*validUntil) {
				validUntil = &value
			}
		}
		if report.OperationPlan != nil && report.OperationPlan.EvidenceValidUntil != nil && (validUntil == nil || report.OperationPlan.EvidenceValidUntil.Before(*validUntil)) {
			value := report.OperationPlan.EvidenceValidUntil.UTC()
			validUntil = &value
		}
	}
	return HealthSelfReadiness{Ready: report.Ready, State: report.State, Reason: report.Reason, LastLoop: lastLoop, ValidUntil: validUntil}, nil
}

func (s *SchedulerHealthSelfReadinessSource) validReport(report schedulerReadinessDocument, statusCode int) bool {
	now := s.now().UTC()
	if report.SchemaVersion != "datapan.health-self-readiness.v1" || report.PublicReadback != "not_checked" || report.DeploymentIdentity != "not_checked" || !validSchedulerReadinessReason(report.Reason) || (report.Ready && (report.State != "ready" || report.Reason != "pipeline_current" || statusCode != http.StatusOK || report.LastLoop == nil)) || (!report.Ready && (report.State == "ready" || statusCode != http.StatusServiceUnavailable)) {
		return false
	}
	expectedLegacy := len(s.canaries)
	if s.operationPlan == nil {
		if report.OperationPlan != nil {
			return false
		}
	} else {
		if !validOperationPlanReadinessProjection(report.OperationPlan, s.operationPlan, now) || report.Ready && !report.OperationPlan.Ready {
			return false
		}
		expectedLegacy -= len(s.operationPlan.suppressed)
	}
	if expectedLegacy < 0 || len(report.Canaries) != expectedLegacy {
		return false
	}
	if !report.Ready && ((report.State == "startup" && report.Reason != "awaiting_first_delivery" && report.Reason != "awaiting_first_loop") || (report.State == "degraded" && (report.Reason == "pipeline_current" || report.Reason == "delivered" || report.Reason == "awaiting_first_delivery" || report.Reason == "awaiting_first_loop"))) {
		return false
	}
	seen := make(map[string]bool, len(report.Canaries))
	allReady := true
	for _, canary := range report.Canaries {
		configured, configuredOK := s.canaries[canary.OperationID]
		if !configuredOK || s.isSuppressedCanary(canary.OperationID) || seen[canary.OperationID] || canary.State == "" || !validSchedulerReadinessReason(canary.Reason) || !validCanaryProgressTimes(canary, now) {
			return false
		}
		seen[canary.OperationID] = true
		heartbeat := time.Duration(configured.HeartbeatMinutes) * time.Minute
		switch canary.State {
		case "ready":
			if canary.Reason != "delivered" || canary.LastDelivered == nil || now.Sub(*canary.LastDelivered) > heartbeat || canary.LastAccepted == nil || canary.OriginalObservedAt == nil || now.Sub(*canary.OriginalObservedAt) > receiptMaxAge+receiptClockSkew {
				return false
			}
		case "startup":
			if canary.Reason != "awaiting_first_delivery" || canary.LastDelivered != nil {
				return false
			}
		case "degraded":
			if canary.Reason == "delivery_stale" && (canary.LastDelivered == nil || now.Sub(*canary.LastDelivered) <= heartbeat) {
				return false
			}
		default:
			return false
		}
		if canary.State != "ready" {
			allReady = false
		}
	}
	if len(seen) != expectedLegacy || (report.Ready && !allReady) {
		return false
	}
	if report.LastLoop != nil && report.LastLoop.After(now.Add(receiptClockSkew)) {
		return false
	}
	if report.Ready && (report.LastLoop == nil || now.Sub(*report.LastLoop) > schedulerLoopMaxAge) {
		return false
	}
	return true
}

func (s *SchedulerHealthSelfReadinessSource) isSuppressedCanary(operationID string) bool {
	if s.operationPlan == nil {
		return false
	}
	index := sort.SearchStrings(s.operationPlan.suppressed, operationID)
	return index < len(s.operationPlan.suppressed) && s.operationPlan.suppressed[index] == operationID
}

func validOperationPlanReadinessProjection(projection *OperationPlanReadinessProjection, binding *OperationPlanReadinessBinding, now time.Time) bool {
	if projection == nil || binding == nil || projection.SchemaVersion != "datapan.health-operation-plan-readiness.v1" ||
		projection.RegistryRevision != binding.registryRevision || projection.ReleaseManifestSHA256 != binding.releaseManifestSHA256 ||
		projection.IndexSHA256 != binding.indexSHA256 || projection.ActivationSHA256 != binding.activationSHA256 ||
		projection.CanaryConfigSHA256 != binding.canaryConfigSHA256 || projection.IdentityMappingSHA256 != binding.identityMappingSHA256 ||
		projection.RuntimePinSHA256 != binding.runtimePinSHA256 ||
		projection.KnownOperations != binding.knownOperations || projection.AdmittedOperations != binding.admitted ||
		!equalOperationPlanIdentityLists(projection.SuppressedLegacyCanaries, binding.suppressed) ||
		projection.EvidenceCheckedOperations < 0 || projection.EvidenceCheckedOperations > binding.admitted ||
		projection.EvidenceCurrentOperations < 0 || projection.EvidenceCurrentOperations > projection.EvidenceCheckedOperations ||
		projection.EvidenceMissingOperations < 0 || projection.EvidenceMissingOperations > binding.admitted {
		return false
	}
	if binding.admitted == 0 && projection.Ready {
		return false
	}
	for _, value := range []*time.Time{projection.LastPassAt, projection.EvidenceSweepAt} {
		if value != nil && (value.IsZero() || value.After(now.Add(receiptClockSkew))) {
			return false
		}
	}
	if projection.EvidenceValidUntil != nil && projection.EvidenceValidUntil.IsZero() {
		return false
	}
	if !projection.Ready {
		return true
	}
	return projection.CapacityFeasible && projection.EvidenceCheckedOperations == binding.admitted &&
		projection.EvidenceCurrentOperations == binding.admitted && projection.EvidenceMissingOperations == 0 &&
		projection.LastPassAt != nil && !now.Before(*projection.LastPassAt) && now.Sub(*projection.LastPassAt) <= 3*time.Second &&
		projection.EvidenceSweepAt != nil && !projection.EvidenceSweepAt.After(projection.LastPassAt.Add(receiptClockSkew)) &&
		projection.EvidenceValidUntil != nil && now.Before(*projection.EvidenceValidUntil) &&
		!projection.EvidenceValidUntil.Before(*projection.EvidenceSweepAt)
}

func validSchedulerReadinessReason(reason string) bool {
	switch reason {
	case "pipeline_current", "awaiting_first_delivery", "delivery_stale", "awaiting_first_loop", "scheduler_loop_stale", "scheduler_state_unavailable", "runtime_dependencies_unavailable", "delivery_failed", "cli_receipt_missing", "receipt_storage_unavailable", "receipt_unavailable", "scheduled_identity", "release_binding", "operation_identity", "catalog_identity", "registry_identity", "policy_identity", "policy_ceiling", "future_observation", "stale_observation", "receipt_contract", "delivered", "operation_plan_unavailable":
		return true
	default:
		return false
	}
}

func validCanaryProgressTimes(canary CanaryProgress, now time.Time) bool {
	times := []*time.Time{canary.LastStarted, canary.LastAccepted, canary.LastDelivered, canary.OriginalObservedAt}
	for _, value := range times {
		if value != nil && (value.IsZero() || value.After(now.Add(receiptClockSkew))) {
			return false
		}
	}
	if (canary.LastAccepted == nil) != (canary.OriginalObservedAt == nil) {
		return false
	}
	if canary.LastDelivered != nil && (canary.LastStarted == nil || canary.LastAccepted == nil || canary.OriginalObservedAt == nil) {
		return false
	}
	if canary.OriginalObservedAt != nil && canary.LastAccepted != nil && canary.OriginalObservedAt.After(canary.LastAccepted.Add(receiptClockSkew)) {
		return false
	}
	return true
}

func readinessValidUntil(report schedulerReadinessDocument, canaries map[string]Canary) *time.Time {
	if report.LastLoop == nil {
		return nil
	}
	until := report.LastLoop.Add(schedulerLoopMaxAge)
	for _, progress := range report.Canaries {
		if progress.LastDelivered == nil {
			return nil
		}
		candidate := progress.LastDelivered.Add(time.Duration(canaries[progress.OperationID].HeartbeatMinutes) * time.Minute)
		if candidate.Before(until) {
			until = candidate
		}
	}
	return &until
}

type cachedHealthSelfReadiness struct {
	done    chan struct{}
	value   HealthSelfReadiness
	err     error
	expires time.Time
}

type CachedHealthSelfReadinessSource struct {
	source  HealthSelfReadinessSource
	ttl     time.Duration
	timeout time.Duration
	mu      sync.Mutex
	cached  *cachedHealthSelfReadiness
	flight  *cachedHealthSelfReadiness
	now     func() time.Time
}

func NewCachedHealthSelfReadinessSource(source HealthSelfReadinessSource, ttl, timeout time.Duration) (*CachedHealthSelfReadinessSource, error) {
	if source == nil || ttl <= 0 || ttl > 30*time.Second || timeout <= 0 || timeout > 5*time.Second {
		return nil, errors.New("invalid Health self-readiness cache")
	}
	return &CachedHealthSelfReadinessSource{source: source, ttl: ttl, timeout: timeout, now: time.Now}, nil
}

func (s *CachedHealthSelfReadinessSource) Snapshot(ctx context.Context) (HealthSelfReadiness, error) {
	if err := ctx.Err(); err != nil {
		return HealthSelfReadiness{}, err
	}
	s.mu.Lock()
	if s.cached != nil && s.now().Before(s.cached.expires) && (s.cached.value.ValidUntil == nil || s.now().Before(*s.cached.value.ValidUntil)) {
		value, err := s.cached.value, s.cached.err
		s.mu.Unlock()
		return value, err
	}
	if s.cached != nil && s.cached.value.ValidUntil != nil && !s.now().Before(*s.cached.value.ValidUntil) {
		s.cached = nil
	}
	flight := s.flight
	if flight == nil {
		flight = &cachedHealthSelfReadiness{done: make(chan struct{})}
		s.flight = flight
		go s.refresh(flight)
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return HealthSelfReadiness{}, ctx.Err()
	case <-flight.done:
		return flight.value, flight.err
	}
}

func (s *CachedHealthSelfReadinessSource) refresh(flight *cachedHealthSelfReadiness) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	value, err := s.source.Snapshot(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		flight.value = HealthSelfReadiness{}
		flight.err = errHealthSelfReadinessUnavailable
		flight.expires = s.now().Add(time.Second)
	} else {
		flight.value = value
		flight.expires = s.now().Add(s.ttl)
	}
	s.cached, s.flight = flight, nil
	close(flight.done)
}
