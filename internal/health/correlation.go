package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	CorrelationRuleSchemaVersion    = "datapan.health-correlation-rule.v1"
	CorrelationReplaySchemaVersion  = "datapan.health-correlation-replay.v1"
	CorrelationReceiptSchemaVersion = "datapan.health-correlation-receipt.v1"
	HealthObservationSchemaVersion  = "datapan.health-observation.v1"
	ProviderNoticeSchemaVersion     = "datapan.provider-notice-projection.v1"
	AcceptedCorrelationRuleID       = "data-go-kr-provider-outage-bounded-v1"
	maxCorrelationReplayBytes       = 1024 * 1024
)

var (
	immutableObservationRefPattern = regexp.MustCompile(`^health-observation:sha256:[0-9a-f]{64}$`)
	noticeIDPattern                = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,95}$`)
	credentialScopePattern         = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,95}$`)
	dependencyClassPattern         = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// CorrelationRule is an offline inference policy. It deliberately does not
// reuse Canary.ConsecutiveFailuresBeforeIncident: alerting and diagnosis are
// separate authorities.
type CorrelationRule struct {
	SchemaVersion             string   `json:"schema_version"`
	RuleID                    string   `json:"rule_id"`
	Version                   int      `json:"version"`
	Provider                  string   `json:"provider"`
	RegistryRevision          string   `json:"registry_revision"`
	CatalogSHA256             string   `json:"catalog_sha256"`
	WindowSeconds             int      `json:"window_seconds"`
	FutureSkewSeconds         int      `json:"future_skew_seconds"`
	NoticeMaxAgeSeconds       int      `json:"notice_max_age_seconds"`
	MinimumAffectedOperations int      `json:"minimum_affected_operations"`
	MinimumControlOperations  int      `json:"minimum_control_operations"`
	AffectedCategories        []string `json:"affected_categories"`
	ControlCategories         []string `json:"control_categories"`
	NoticeAuthorities         []string `json:"notice_authorities"`
	NoticeHosts               []string `json:"notice_hosts"`
	SHA256                    string   `json:"-"`
}

type CorrelationReplay struct {
	SchemaVersion   string              `json:"schema_version"`
	AssessedAt      time.Time           `json:"assessed_at"`
	Scope           CorrelationScope    `json:"scope"`
	Observations    []HealthObservation `json:"observations"`
	ProviderNotices []ProviderNotice    `json:"provider_notices"`
}

type CorrelationScope struct {
	Provider          string `json:"provider"`
	DependencyClass   string `json:"dependency_class"`
	CredentialScopeID string `json:"credential_scope_id"`
}

// HealthObservation contains only minimized, already-redacted evidence. The
// reference points to the immutable original receipt; no response body, URL,
// credential identity, or provider text is accepted here.
type HealthObservation struct {
	SchemaVersion      string               `json:"schema_version"`
	ObservationRef     string               `json:"observation_ref"`
	ObservedAt         time.Time            `json:"observed_at"`
	OperationID        string               `json:"operation_id"`
	DependencyClass    string               `json:"dependency_class"`
	ProbePolicyKey     string               `json:"probe_policy_key"`
	ProbePolicyVersion int                  `json:"probe_policy_version"`
	CredentialScopeID  string               `json:"credential_scope_id"`
	Outcome            string               `json:"outcome"`
	Category           string               `json:"category"`
	HTTPStatus         int                  `json:"http_status,omitempty"`
	Redaction          CorrelationRedaction `json:"redaction"`
}

type CorrelationRedaction struct {
	CredentialsRemoved     bool `json:"credentials_removed"`
	QueryValuesRemoved     bool `json:"query_values_removed"`
	ResponseRowsRemoved    bool `json:"response_rows_removed"`
	RawProviderTextRemoved bool `json:"raw_provider_text_removed"`
}

// ProviderNotice is a reviewed projection, not scraped prose. Revisions are
// append-only; a correction or withdrawal names the immediately prior version.
type ProviderNotice struct {
	SchemaVersion     string    `json:"schema_version"`
	NoticeID          string    `json:"notice_id"`
	Version           int       `json:"version"`
	Authority         string    `json:"authority"`
	ObservedAt        time.Time `json:"observed_at"`
	EffectiveFrom     time.Time `json:"effective_from"`
	EffectiveUntil    time.Time `json:"effective_until"`
	State             string    `json:"state"`
	Effect            string    `json:"effect,omitempty"`
	DependencyClass   string    `json:"dependency_class"`
	OperationIDs      []string  `json:"operation_ids"`
	SourceRef         string    `json:"source_ref"`
	ContentSHA256     string    `json:"content_sha256"`
	SupersedesVersion int       `json:"supersedes_version,omitempty"`
}

type CorrelationReceipt struct {
	SchemaVersion             string                      `json:"schema_version"`
	AssessedAt                time.Time                   `json:"assessed_at"`
	Rule                      CorrelationRuleReference    `json:"rule"`
	Scope                     CorrelationScope            `json:"scope"`
	Result                    CorrelationResult           `json:"result"`
	AffectedEvidence          []CorrelationObservationRef `json:"affected_evidence"`
	ControlEvidence           []CorrelationObservationRef `json:"control_evidence"`
	HealthObservationEvidence []CorrelationHealthEvidence `json:"health_observation_evidence"`
	NoticeEvidence            NoticeEvidence              `json:"notice_evidence"`
	Boundaries                CorrelationBoundaries       `json:"boundaries"`
}

type CorrelationRuleReference struct {
	RuleID  string `json:"rule_id"`
	Version int    `json:"version"`
	SHA256  string `json:"sha256"`
}

type CorrelationResult struct {
	Cause         string `json:"cause"`
	Determination string `json:"determination"`
	State         string `json:"state"`
	AffectedCount int    `json:"affected_count"`
	ControlCount  int    `json:"control_count"`
}

type CorrelationObservationRef struct {
	OperationID    string `json:"operation_id"`
	ObservationRef string `json:"observation_ref"`
}

type CorrelationHealthEvidence struct {
	Kind                    string                    `json:"kind"`
	RefID                   string                    `json:"ref_id"`
	Authority               string                    `json:"authority"`
	Version                 string                    `json:"version"`
	Scope                   CorrelationEvidenceScope  `json:"scope"`
	HealthCorrelation       HealthCorrelationEvidence `json:"health_correlation"`
	ImmutableObservationRef string                    `json:"immutable_observation_ref"`
	Supports                []string                  `json:"supports"`
	Timing                  CorrelationEvidenceTiming `json:"timing"`
}

type CorrelationEvidenceScope struct {
	Level           string `json:"level"`
	OperationID     string `json:"operation_id"`
	DependencyClass string `json:"dependency_class"`
}

type HealthCorrelationEvidence struct {
	State              string `json:"state"`
	RuleID             string `json:"rule_id"`
	RuleVersion        int    `json:"rule_version"`
	ProbePolicyKey     string `json:"probe_policy_key"`
	ProbePolicyVersion int    `json:"probe_policy_version"`
	AffectedCount      int    `json:"affected_count"`
	ControlCount       int    `json:"control_count"`
}

type CorrelationEvidenceTiming struct {
	ObservedAt               time.Time `json:"observed_at"`
	AssessedAt               time.Time `json:"assessed_at"`
	WindowSeconds            int       `json:"window_seconds"`
	RemainingValiditySeconds int       `json:"remaining_validity_seconds"`
}

type NoticeEvidence struct {
	LinkedNoticeRef      string   `json:"linked_notice_ref,omitempty"`
	ConsideredNoticeRefs []string `json:"considered_notice_refs"`
	SupersededNoticeRefs []string `json:"superseded_notice_refs"`
}

type CorrelationBoundaries struct {
	AlertPolicy      string `json:"alert_policy"`
	PublicProjection string `json:"public_projection"`
	RuntimeMutation  string `json:"runtime_mutation"`
	Redaction        string `json:"redaction"`
}

func LoadCorrelationRule(path string) (CorrelationRule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return CorrelationRule{}, err
	}
	var rule CorrelationRule
	if err := decodeStrict(bytes.NewReader(raw), &rule); err != nil {
		return CorrelationRule{}, errors.New("invalid correlation rule")
	}
	if rule.SchemaVersion != CorrelationRuleSchemaVersion || rule.RuleID != AcceptedCorrelationRuleID || rule.Version != 1 || rule.Provider != "data.go.kr" || rule.RegistryRevision != AcceptedDiagnosticRegistryRevision || rule.CatalogSHA256 != AcceptedHealthProbeCatalogSHA256 {
		return CorrelationRule{}, errors.New("unsupported correlation rule identity")
	}
	if rule.WindowSeconds < 60 || rule.WindowSeconds > 900 || rule.FutureSkewSeconds < 0 || rule.FutureSkewSeconds > 30 || rule.NoticeMaxAgeSeconds < rule.WindowSeconds || rule.NoticeMaxAgeSeconds > 86400 || rule.MinimumAffectedOperations < 2 || rule.MinimumControlOperations < 1 {
		return CorrelationRule{}, errors.New("unsafe correlation rule bounds")
	}
	if !exactStrings(rule.AffectedCategories, []string{"provider_failure", "timeout", "transport_failure"}) || !exactStrings(rule.ControlCategories, []string{"healthy"}) || !exactStrings(rule.NoticeAuthorities, []string{"provider", "provider_portal"}) || !exactStrings(rule.NoticeHosts, []string{"data.go.kr", "www.data.go.kr"}) {
		return CorrelationRule{}, errors.New("unsupported correlation rule semantics")
	}
	rule.SHA256 = digest(raw)
	return rule, nil
}

func DecodeCorrelationReplay(r io.Reader) (CorrelationReplay, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxCorrelationReplayBytes+1))
	if err != nil || len(data) > maxCorrelationReplayBytes {
		return CorrelationReplay{}, errors.New("correlation replay exceeds 1 MiB")
	}
	var replay CorrelationReplay
	if err := decodeStrict(bytes.NewReader(data), &replay); err != nil {
		return CorrelationReplay{}, errors.New("invalid correlation replay")
	}
	if replay.SchemaVersion != CorrelationReplaySchemaVersion || replay.AssessedAt.IsZero() || replay.Scope.Provider != "data.go.kr" || !dependencyClassPattern.MatchString(replay.Scope.DependencyClass) || !credentialScopePattern.MatchString(replay.Scope.CredentialScopeID) || len(replay.Observations) > 1000 || len(replay.ProviderNotices) > 100 {
		return CorrelationReplay{}, errors.New("invalid correlation replay identity")
	}
	return replay, nil
}

func CorrelateProviderOutage(rule CorrelationRule, canaries CanaryConfig, replay CorrelationReplay) (CorrelationReceipt, error) {
	if rule.SHA256 == "" || rule.CatalogSHA256 != canaries.CatalogSHA256 || replay.SchemaVersion != CorrelationReplaySchemaVersion || replay.Scope.Provider != rule.Provider {
		return CorrelationReceipt{}, errors.New("correlation inputs are not bound to the accepted rule")
	}
	entries := make(map[string]CatalogEntry, len(canaries.Canaries))
	for _, canary := range canaries.Canaries {
		entry, ok := canaries.Entry(canary)
		if !ok {
			return CorrelationReceipt{}, errors.New("correlation catalog is incomplete")
		}
		entries[canary.OperationID] = entry
	}

	latest := map[string]HealthObservation{}
	seenObservationRefs := map[string]bool{}
	for _, observation := range replay.Observations {
		if seenObservationRefs[observation.ObservationRef] {
			return CorrelationReceipt{}, errors.New("duplicate immutable observation reference")
		}
		seenObservationRefs[observation.ObservationRef] = true
		eligible, err := validateCorrelationObservation(observation, replay, rule, entries)
		if err != nil {
			return CorrelationReceipt{}, err
		}
		if !eligible {
			continue
		}
		if observation.DependencyClass != replay.Scope.DependencyClass || observation.CredentialScopeID != replay.Scope.CredentialScopeID {
			continue
		}
		current, exists := latest[observation.OperationID]
		if !exists || observation.ObservedAt.After(current.ObservedAt) {
			latest[observation.OperationID] = observation
		} else if observation.ObservedAt.Equal(current.ObservedAt) && observation.ObservationRef != current.ObservationRef {
			return CorrelationReceipt{}, errors.New("conflicting observations share operation and timestamp")
		}
	}
	affected, controls := []HealthObservation{}, []HealthObservation{}
	for _, observation := range latest {
		if observation.Outcome == "unhealthy" && contains(rule.AffectedCategories, observation.Category) {
			affected = append(affected, observation)
		}
		if observation.Outcome == "healthy" && contains(rule.ControlCategories, observation.Category) {
			controls = append(controls, observation)
		}
	}
	sortObservations(affected)
	sortObservations(controls)

	receipt := CorrelationReceipt{
		SchemaVersion:    CorrelationReceiptSchemaVersion,
		AssessedAt:       replay.AssessedAt.UTC(),
		Rule:             CorrelationRuleReference{RuleID: rule.RuleID, Version: rule.Version, SHA256: rule.SHA256},
		Scope:            replay.Scope,
		Result:           CorrelationResult{Cause: "unknown", Determination: "unknown", State: "insufficient_evidence", AffectedCount: len(affected), ControlCount: len(controls)},
		AffectedEvidence: observationRefs(affected), ControlEvidence: observationRefs(controls),
		HealthObservationEvidence: []CorrelationHealthEvidence{},
		NoticeEvidence:            NoticeEvidence{ConsideredNoticeRefs: []string{}, SupersededNoticeRefs: []string{}},
		Boundaries:                CorrelationBoundaries{AlertPolicy: "unchanged", PublicProjection: "unchanged", RuntimeMutation: "not_performed", Redaction: "minimized_refs_only"},
	}
	active, considered, superseded, err := selectActiveNotices(rule, replay, entries)
	if err != nil {
		return CorrelationReceipt{}, err
	}
	receipt.NoticeEvidence.ConsideredNoticeRefs = considered
	receipt.NoticeEvidence.SupersededNoticeRefs = superseded
	if len(affected) < rule.MinimumAffectedOperations || len(controls) < rule.MinimumControlOperations {
		return receipt, nil
	}
	receipt.Result = CorrelationResult{Cause: "provider_outage", Determination: "inferred", State: "degraded", AffectedCount: len(affected), ControlCount: len(controls)}
	receipt.HealthObservationEvidence = buildHealthCorrelationEvidence(rule, replay, affected, controls)
	for _, notice := range active {
		if noticeCoversIncident(notice, replay.Scope.DependencyClass, affected) {
			receipt.Result.Determination = "observed"
			receipt.NoticeEvidence.LinkedNoticeRef = providerNoticeRef(notice)
			break
		}
	}
	return receipt, nil
}

func validateCorrelationObservation(observation HealthObservation, replay CorrelationReplay, rule CorrelationRule, entries map[string]CatalogEntry) (bool, error) {
	entry, exists := entries[observation.OperationID]
	if observation.SchemaVersion != HealthObservationSchemaVersion || !exists || !immutableObservationRefPattern.MatchString(observation.ObservationRef) || observation.ObservedAt.IsZero() || observation.DependencyClass != entry.Endpoint.DependencyClass || observation.ProbePolicyKey != entry.Policy.Key || observation.ProbePolicyVersion != entry.Policy.Version || !credentialScopePattern.MatchString(observation.CredentialScopeID) {
		return false, errors.New("health observation is not bound to an exact accepted operation")
	}
	age := replay.AssessedAt.Sub(observation.ObservedAt)
	if age < -time.Duration(rule.FutureSkewSeconds)*time.Second || age > time.Duration(rule.WindowSeconds)*time.Second {
		return false, nil
	}
	if !observation.Redaction.CredentialsRemoved || !observation.Redaction.QueryValuesRemoved || !observation.Redaction.ResponseRowsRemoved || !observation.Redaction.RawProviderTextRemoved {
		return false, errors.New("health observation redaction assertions are required")
	}
	if observation.Outcome == "healthy" {
		if observation.Category != "healthy" || observation.HTTPStatus < 200 || observation.HTTPStatus > 299 {
			return false, errors.New("healthy control observation is inconsistent")
		}
	} else if observation.Outcome == "unhealthy" {
		if !contains(rule.AffectedCategories, observation.Category) || observation.HTTPStatus < 0 || observation.HTTPStatus > 599 {
			return false, errors.New("affected health observation is unsupported")
		}
		if observation.Category == "provider_failure" && (observation.HTTPStatus < 500 || observation.HTTPStatus > 599) {
			return false, errors.New("provider failure observation lacks an exact 5xx status")
		}
		if observation.Category == "transport_failure" && observation.HTTPStatus != 0 {
			return false, errors.New("transport failure observation has an HTTP status")
		}
		if observation.Category == "timeout" && observation.HTTPStatus != 0 && observation.HTTPStatus != 408 && observation.HTTPStatus != 504 {
			return false, errors.New("timeout observation has an unrelated HTTP status")
		}
	} else {
		return false, errors.New("health observation outcome is unsupported")
	}
	return true, nil
}

func selectActiveNotices(rule CorrelationRule, replay CorrelationReplay, entries map[string]CatalogEntry) ([]ProviderNotice, []string, []string, error) {
	byID := map[string][]ProviderNotice{}
	for _, notice := range replay.ProviderNotices {
		if err := validateProviderNotice(rule, notice, entries); err != nil {
			return nil, nil, nil, err
		}
		byID[notice.NoticeID] = append(byID[notice.NoticeID], notice)
	}
	active := []ProviderNotice{}
	considered, superseded := []string{}, []string{}
	for _, versions := range byID {
		sort.Slice(versions, func(i, j int) bool { return versions[i].Version < versions[j].Version })
		for index, notice := range versions {
			considered = append(considered, providerNoticeRef(notice))
			if index == 0 {
				if notice.Version != 1 || notice.SupersedesVersion != 0 {
					return nil, nil, nil, errors.New("provider notice revision chain is incomplete")
				}
			} else if notice.Version != versions[index-1].Version+1 || notice.SupersedesVersion != versions[index-1].Version {
				return nil, nil, nil, errors.New("provider notice revision chain is not contiguous")
			}
			if index < len(versions)-1 {
				superseded = append(superseded, providerNoticeRef(notice))
			}
		}
		latest := versions[len(versions)-1]
		age := replay.AssessedAt.Sub(latest.ObservedAt)
		current := age >= -time.Duration(rule.FutureSkewSeconds)*time.Second && age <= time.Duration(rule.NoticeMaxAgeSeconds)*time.Second
		if latest.State != "withdrawn" && current {
			active = append(active, latest)
		}
	}
	sort.Strings(considered)
	sort.Strings(superseded)
	sort.Slice(active, func(i, j int) bool { return providerNoticeRef(active[i]) < providerNoticeRef(active[j]) })
	return active, considered, superseded, nil
}

func validateProviderNotice(rule CorrelationRule, notice ProviderNotice, entries map[string]CatalogEntry) error {
	if notice.SchemaVersion != ProviderNoticeSchemaVersion || !noticeIDPattern.MatchString(notice.NoticeID) || notice.Version < 1 || !contains(rule.NoticeAuthorities, notice.Authority) || notice.ObservedAt.IsZero() || notice.EffectiveFrom.IsZero() || notice.EffectiveUntil.IsZero() || notice.EffectiveUntil.Before(notice.EffectiveFrom) || !dependencyClassPattern.MatchString(notice.DependencyClass) || !sha256Pattern.MatchString(notice.ContentSHA256) {
		return errors.New("invalid provider notice projection")
	}
	parsed, err := url.Parse(notice.SourceRef)
	if err != nil || parsed.Scheme != "https" || parsed.Host != parsed.Hostname() || !contains(rule.NoticeHosts, strings.ToLower(parsed.Hostname())) || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path == "" {
		return errors.New("provider notice source is not an authoritative safe reference")
	}
	if notice.EffectiveUntil.Sub(notice.EffectiveFrom) > time.Duration(rule.NoticeMaxAgeSeconds)*time.Second {
		return errors.New("provider notice effective window is unbounded")
	}
	if notice.State != "active" && notice.State != "corrected" && notice.State != "withdrawn" {
		return errors.New("unsupported provider notice state")
	}
	if notice.State == "active" && notice.SupersedesVersion != 0 {
		return errors.New("active provider notice cannot supersede a prior version")
	}
	if notice.State == "corrected" && notice.SupersedesVersion < 1 {
		return errors.New("corrected provider notice must supersede a prior version")
	}
	if notice.State == "withdrawn" {
		if notice.Effect != "" || notice.SupersedesVersion < 1 {
			return errors.New("withdrawn provider notice is inconsistent")
		}
	} else if notice.Effect != "service_suspended" && notice.Effect != "degraded" {
		return errors.New("provider notice does not assert an outage effect")
	}
	seen := map[string]bool{}
	for index, operationID := range notice.OperationIDs {
		entry, ok := entries[operationID]
		if !ok || entry.Endpoint.DependencyClass != notice.DependencyClass || seen[operationID] || (index > 0 && notice.OperationIDs[index-1] >= operationID) {
			return errors.New("provider notice operation scope is invalid")
		}
		seen[operationID] = true
	}
	return nil
}

func noticeCoversIncident(notice ProviderNotice, dependency string, affected []HealthObservation) bool {
	if notice.DependencyClass != dependency {
		return false
	}
	scope := map[string]bool{}
	for _, operationID := range notice.OperationIDs {
		scope[operationID] = true
	}
	for _, observation := range affected {
		if observation.ObservedAt.Before(notice.EffectiveFrom) || observation.ObservedAt.After(notice.EffectiveUntil) || (len(scope) > 0 && !scope[observation.OperationID]) {
			return false
		}
	}
	return true
}

func providerNoticeRef(notice ProviderNotice) string {
	return fmt.Sprintf("provider-notice:%s:v%d:sha256:%s", notice.NoticeID, notice.Version, notice.ContentSHA256)
}

func buildHealthCorrelationEvidence(rule CorrelationRule, replay CorrelationReplay, affected, controls []HealthObservation) []CorrelationHealthEvidence {
	evidence := make([]CorrelationHealthEvidence, 0, len(affected))
	affectedRefs, controlRefs := observationRefs(affected), observationRefs(controls)
	for _, observation := range affected {
		identity, _ := json.Marshal(struct {
			RuleSHA256  string                      `json:"rule_sha256"`
			AssessedAt  time.Time                   `json:"assessed_at"`
			Scope       CorrelationScope            `json:"scope"`
			OperationID string                      `json:"operation_id"`
			Affected    []CorrelationObservationRef `json:"affected"`
			Controls    []CorrelationObservationRef `json:"controls"`
		}{rule.SHA256, replay.AssessedAt.UTC(), replay.Scope, observation.OperationID, affectedRefs, controlRefs})
		age := int(replay.AssessedAt.Sub(observation.ObservedAt) / time.Second)
		remaining := rule.WindowSeconds - age
		if remaining < 0 {
			remaining = 0
		} else if remaining > rule.WindowSeconds {
			remaining = rule.WindowSeconds
		}
		evidence = append(evidence, CorrelationHealthEvidence{
			Kind: "health_observation", RefID: "health-correlation:sha256:" + digest(identity), Authority: "datapan_health",
			Version:                 fmt.Sprintf("%s@v%d", rule.RuleID, rule.Version),
			Scope:                   CorrelationEvidenceScope{Level: "operation", OperationID: observation.OperationID, DependencyClass: observation.DependencyClass},
			HealthCorrelation:       HealthCorrelationEvidence{State: "degraded", RuleID: rule.RuleID, RuleVersion: rule.Version, ProbePolicyKey: observation.ProbePolicyKey, ProbePolicyVersion: observation.ProbePolicyVersion, AffectedCount: len(affected), ControlCount: len(controls)},
			ImmutableObservationRef: observation.ObservationRef,
			Supports:                []string{"cause", "determination", "ownership", "action"},
			Timing:                  CorrelationEvidenceTiming{ObservedAt: observation.ObservedAt.UTC(), AssessedAt: replay.AssessedAt.UTC(), WindowSeconds: rule.WindowSeconds, RemainingValiditySeconds: remaining},
		})
	}
	return evidence
}

func observationRefs(observations []HealthObservation) []CorrelationObservationRef {
	refs := make([]CorrelationObservationRef, 0, len(observations))
	for _, observation := range observations {
		refs = append(refs, CorrelationObservationRef{OperationID: observation.OperationID, ObservationRef: observation.ObservationRef})
	}
	return refs
}

func sortObservations(observations []HealthObservation) {
	sort.Slice(observations, func(i, j int) bool {
		if observations[i].OperationID == observations[j].OperationID {
			return observations[i].ObservationRef < observations[j].ObservationRef
		}
		return observations[i].OperationID < observations[j].OperationID
	})
}

func decodeStrict(r io.Reader, target any) error {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return ensureEOF(decoder)
}

func exactStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range want {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
