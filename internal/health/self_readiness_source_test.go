package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

func readySelfReadinessDocument(t *testing.T, config CanaryConfig, now time.Time) schedulerReadinessDocument {
	t.Helper()
	canaries := make([]CanaryProgress, 0, len(config.Canaries))
	for _, canary := range config.Canaries {
		started, accepted := now.Add(-20*time.Second), now.Add(-10*time.Second)
		delivered, observed := now.Add(-5*time.Second), now.Add(-15*time.Second)
		canaries = append(canaries, CanaryProgress{OperationID: canary.OperationID, LastStarted: &started, LastAccepted: &accepted, LastDelivered: &delivered, OriginalObservedAt: &observed, State: "ready", Reason: "delivered"})
	}
	lastLoop := now.Add(-time.Second)
	return schedulerReadinessDocument{SchemaVersion: "datapan.health-self-readiness.v1", Ready: true, State: "ready", Reason: "pipeline_current", LastLoop: &lastLoop, StateFailures: 3, Canaries: canaries, PublicReadback: "not_checked", DeploymentIdentity: "not_checked"}
}

func readinessHTTPFixture(t *testing.T, report schedulerReadinessDocument, status int, contentType string) *httptest.Server {
	t.Helper()
	body, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
}

func TestSchedulerHealthSelfReadinessSourceProjectsOnlySafeAggregate(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	server := readinessHTTPFixture(t, readySelfReadinessDocument(t, config, now), http.StatusOK, "application/json; charset=utf-8")
	defer server.Close()
	source, err := NewSchedulerHealthSelfReadinessSource(server.URL+"/status", config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	value, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !value.Ready || value.State != "ready" || value.Reason != "pipeline_current" || value.LastLoop == nil || value.ValidUntil == nil || value.ValidUntil.Sub(now) != 4*time.Second {
		t.Fatalf("aggregate=%+v", value)
	}
	encoded, _ := json.Marshal(value)
	if strings.Contains(string(encoded), "operation_id") || strings.Contains(string(encoded), "dpr-op-") || strings.Contains(string(encoded), "deployment_identity") || strings.Contains(string(encoded), "state_failures") {
		t.Fatalf("private fields escaped aggregate: %s", encoded)
	}
}

func TestSchedulerHealthSelfReadinessAcceptsBoundedDegradedStatus(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	report := readySelfReadinessDocument(t, config, now)
	report.Ready, report.State, report.Reason = false, "degraded", "delivery_stale"
	stale := now.Add(-24 * time.Hour)
	report.Canaries[0].State, report.Canaries[0].Reason, report.Canaries[0].LastDelivered = "degraded", "delivery_stale", &stale
	server := readinessHTTPFixture(t, report, http.StatusServiceUnavailable, "application/json")
	defer server.Close()
	source, err := NewSchedulerHealthSelfReadinessSource(server.URL+"/status", config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	value, err := source.Snapshot(context.Background())
	if err != nil || value.Ready || value.State != "degraded" || value.Reason != "delivery_stale" {
		t.Fatalf("valid 503 readiness was not safely projected: value=%+v err=%v", value, err)
	}
}

func TestSchedulerHealthSelfReadinessAcceptsOperationPlanUnavailableReason(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	report := readySelfReadinessDocument(t, config, now)
	report.Ready, report.State, report.Reason = false, "degraded", "operation_plan_unavailable"
	server := readinessHTTPFixture(t, report, http.StatusServiceUnavailable, "application/json")
	defer server.Close()
	source, err := NewSchedulerHealthSelfReadinessSource(server.URL+"/status", config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	value, err := source.Snapshot(context.Background())
	if err != nil || value.Ready || value.State != "degraded" || value.Reason != "operation_plan_unavailable" {
		t.Fatalf("canonical operation-plan degradation was not projected safely: value=%+v err=%v", value, err)
	}
}

func TestSchedulerHealthSelfReadinessUsesVerifiedOwnershipForTransferredCanaries(t *testing.T) {
	binding, config := selfReadinessOperationPlanBindingFixture(t, false, false)
	now := time.Now().UTC().Truncate(time.Second)
	base := readySelfReadinessDocument(t, config, now)
	legacyRows := make([]CanaryProgress, 0, len(base.Canaries))
	for _, progress := range base.Canaries {
		if progress.OperationID != binding.suppressed[0] {
			legacyRows = append(legacyRows, progress)
		}
	}
	base.Canaries = legacyRows
	lastPass, sweep, validUntil := now.Add(-time.Second), now.Add(-2*time.Second), now.Add(time.Minute)
	base.OperationPlan = &OperationPlanReadinessProjection{
		SchemaVersion: "datapan.health-operation-plan-readiness.v1", Ready: true,
		RegistryRevision: binding.registryRevision, ReleaseManifestSHA256: binding.releaseManifestSHA256,
		IndexSHA256: binding.indexSHA256, ActivationSHA256: binding.activationSHA256,
		CanaryConfigSHA256: binding.canaryConfigSHA256, IdentityMappingSHA256: binding.identityMappingSHA256,
		RuntimePinSHA256: binding.runtimePinSHA256,
		KnownOperations:  binding.knownOperations, AdmittedOperations: binding.admitted,
		CapacityFeasible: true, LastPassAt: &lastPass, EvidenceSweepAt: &sweep,
		EvidenceCheckedOperations: binding.admitted, EvidenceCurrentOperations: binding.admitted,
		EvidenceMissingOperations: 0, EvidenceValidUntil: &validUntil,
		SuppressedLegacyCanaries: append([]string(nil), binding.suppressed...),
	}
	encoded, _ := json.Marshal(base)
	if schemaErr := schemas.ValidateHealthSelfReadinessV1(encoded); schemaErr != nil {
		t.Fatalf("ownership projection schema validation failed: %v body=%s", schemaErr, encoded)
	}
	server := readinessHTTPFixture(t, base, http.StatusOK, "application/json")
	defer server.Close()
	source, err := NewSchedulerHealthSelfReadinessSourceWithOperationPlanBinding(server.URL+"/status", config, time.Second, binding)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	if !source.validReport(base, http.StatusOK) {
		t.Fatalf("validReport rejected fixture projection: binding=%+v projection=%+v canaries=%+v", binding, base.OperationPlan, base.Canaries)
	}
	value, err := source.Snapshot(context.Background())
	if err != nil || !value.Ready || value.ValidUntil == nil || !value.ValidUntil.Equal(lastPass.Add(3*time.Second)) {
		t.Fatalf("all-transferred-canary report did not preserve the exact plan evidence boundary: value=%+v err=%v", value, err)
	}

	mutations := []struct {
		name   string
		mutate func(*schedulerReadinessDocument)
	}{
		{"missing ownership IDs", func(v *schedulerReadinessDocument) { v.OperationPlan.SuppressedLegacyCanaries = []string{} }},
		{"unexpected transferred ID", func(v *schedulerReadinessDocument) {
			v.OperationPlan.SuppressedLegacyCanaries = []string{"dpr-op-99999999"}
		}},
		{"wrong plan revision", func(v *schedulerReadinessDocument) { v.OperationPlan.RegistryRevision = strings.Repeat("e", 40) }},
		{"wrong plan index", func(v *schedulerReadinessDocument) { v.OperationPlan.IndexSHA256 = strings.Repeat("f", 64) }},
		{"same count but different activation", func(v *schedulerReadinessDocument) { v.OperationPlan.ActivationSHA256 = strings.Repeat("a", 64) }},
		{"same count but different mapping", func(v *schedulerReadinessDocument) { v.OperationPlan.IdentityMappingSHA256 = strings.Repeat("b", 64) }},
		{"future pass", func(v *schedulerReadinessDocument) {
			future := now.Add(time.Minute)
			v.OperationPlan.LastPassAt = &future
		}},
		{"stale evidence", func(v *schedulerReadinessDocument) {
			expired := now.Add(-time.Second)
			v.OperationPlan.EvidenceValidUntil = &expired
		}},
		{"partial sweep", func(v *schedulerReadinessDocument) { v.OperationPlan.EvidenceCurrentOperations-- }},
		{"plan not ready but report ready", func(v *schedulerReadinessDocument) { v.OperationPlan.Ready = false }},
		{"transferred ID also claims legacy delivery", func(v *schedulerReadinessDocument) {
			v.Canaries = []CanaryProgress{{OperationID: binding.suppressed[0], State: "startup", Reason: "awaiting_first_delivery"}}
		}},
		{"missing ownership projection", func(v *schedulerReadinessDocument) { v.OperationPlan = nil }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			report := base
			report.Canaries = append([]CanaryProgress(nil), base.Canaries...)
			projection := *base.OperationPlan
			projection.SuppressedLegacyCanaries = append([]string(nil), base.OperationPlan.SuppressedLegacyCanaries...)
			report.OperationPlan = &projection
			test.mutate(&report)
			server := readinessHTTPFixture(t, report, http.StatusOK, "application/json")
			defer server.Close()
			source, err := NewSchedulerHealthSelfReadinessSourceWithOperationPlanBinding(server.URL+"/status", config, time.Second, binding)
			if err != nil {
				t.Fatal(err)
			}
			source.now = func() time.Time { return now }
			if _, err := source.Snapshot(context.Background()); err == nil || err.Error() != errHealthSelfReadinessUnavailable.Error() {
				t.Fatalf("unbound operation-plan ownership report was accepted: %v", err)
			}
		})
	}
	wrongConfig := config
	wrongConfig.Canaries = append([]Canary(nil), config.Canaries...)
	wrongConfig.Canaries[0].OperationID = "dpr-op-99999999"
	if _, err := NewSchedulerHealthSelfReadinessSourceWithOperationPlanBinding("http://scheduler:8081/status", wrongConfig, time.Second, binding); err == nil {
		t.Fatal("binding accepted a different original canary identity set")
	}
}

func TestSchedulerHealthSelfReadinessCacheExpiresAtPlanPassFreshness(t *testing.T) {
	binding, config := selfReadinessOperationPlanBindingFixture(t, true, false)
	now := time.Now().UTC().Truncate(time.Second)
	var clockMu sync.Mutex
	clock := now
	currentTime := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return clock }
	setTime := func(value time.Time) { clockMu.Lock(); clock = value; clockMu.Unlock() }
	report := readySelfReadinessDocument(t, config, now)
	report.Canaries = []CanaryProgress{}
	lastPass, sweep, evidenceValidUntil := now.Add(-2900*time.Millisecond), now.Add(-3*time.Second), now.Add(time.Minute)
	report.OperationPlan = &OperationPlanReadinessProjection{
		SchemaVersion: "datapan.health-operation-plan-readiness.v1", Ready: true,
		RegistryRevision: binding.registryRevision, ReleaseManifestSHA256: binding.releaseManifestSHA256,
		IndexSHA256: binding.indexSHA256, ActivationSHA256: binding.activationSHA256,
		CanaryConfigSHA256: binding.canaryConfigSHA256, IdentityMappingSHA256: binding.identityMappingSHA256,
		RuntimePinSHA256: binding.runtimePinSHA256,
		KnownOperations:  binding.knownOperations, AdmittedOperations: binding.admitted,
		CapacityFeasible: true, LastPassAt: &lastPass, EvidenceSweepAt: &sweep,
		EvidenceCheckedOperations: binding.admitted, EvidenceCurrentOperations: binding.admitted,
		EvidenceValidUntil: &evidenceValidUntil, SuppressedLegacyCanaries: append([]string(nil), binding.suppressed...),
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded)
	}))
	defer server.Close()
	source, err := NewSchedulerHealthSelfReadinessSourceWithOperationPlanBinding(server.URL+"/status", config, time.Second, binding)
	if err != nil {
		t.Fatal(err)
	}
	source.now = currentTime
	cached, err := NewCachedHealthSelfReadinessSource(source, 30*time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cached.now = currentTime
	value, err := cached.Snapshot(context.Background())
	expectedExpiry := lastPass.Add(3 * time.Second)
	if err != nil || !value.Ready || value.ValidUntil == nil || !value.ValidUntil.Equal(expectedExpiry) {
		t.Fatalf("cached plan readiness omitted the pass freshness boundary: value=%+v err=%v", value, err)
	}
	setTime(expectedExpiry.Add(time.Millisecond))
	if value, err := cached.Snapshot(context.Background()); err == nil || value.Ready || err.Error() != errHealthSelfReadinessUnavailable.Error() {
		t.Fatalf("cache served plan readiness beyond the pass freshness boundary: value=%+v err=%v", value, err)
	}
	if requests.Load() != 2 {
		t.Fatalf("expired plan cache did not refresh from the source: requests=%d", requests.Load())
	}
}

func TestSchedulerHealthSelfReadinessAcceptsAllTransferredCanaries(t *testing.T) {
	binding, config := selfReadinessOperationPlanBindingFixture(t, true, false)
	now := time.Now().UTC().Truncate(time.Second)
	report := readySelfReadinessDocument(t, config, now)
	report.Canaries = []CanaryProgress{}
	lastPass, sweep, validUntil := now.Add(-time.Second), now.Add(-2*time.Second), now.Add(time.Minute)
	report.OperationPlan = &OperationPlanReadinessProjection{
		SchemaVersion: "datapan.health-operation-plan-readiness.v1", Ready: true,
		RegistryRevision: binding.registryRevision, ReleaseManifestSHA256: binding.releaseManifestSHA256,
		IndexSHA256: binding.indexSHA256, ActivationSHA256: binding.activationSHA256,
		CanaryConfigSHA256: binding.canaryConfigSHA256, IdentityMappingSHA256: binding.identityMappingSHA256,
		RuntimePinSHA256: binding.runtimePinSHA256,
		KnownOperations:  binding.knownOperations, AdmittedOperations: binding.admitted,
		CapacityFeasible: true, LastPassAt: &lastPass, EvidenceSweepAt: &sweep,
		EvidenceCheckedOperations: binding.admitted, EvidenceCurrentOperations: binding.admitted,
		EvidenceValidUntil: &validUntil, SuppressedLegacyCanaries: append([]string(nil), binding.suppressed...),
	}
	server := readinessHTTPFixture(t, report, http.StatusOK, "application/json")
	defer server.Close()
	source, err := NewSchedulerHealthSelfReadinessSourceWithOperationPlanBinding(server.URL+"/status", config, time.Second, binding)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	if value, err := source.Snapshot(context.Background()); err != nil || !value.Ready {
		t.Fatalf("exact all-transferred partition was rejected: value=%+v err=%v", value, err)
	}
}

func TestSchedulerHealthSelfReadinessKeepsZeroAdmittedPlanDegraded(t *testing.T) {
	binding, config := selfReadinessOperationPlanBindingFixture(t, false, true)
	if binding.admitted != 0 || len(binding.suppressed) != 0 {
		t.Fatalf("empty activation fixture has unexpected admission: %+v", binding)
	}
	now := time.Now().UTC().Truncate(time.Second)
	report := readySelfReadinessDocument(t, config, now)
	report.Ready, report.State, report.Reason = false, "degraded", "operation_plan_unavailable"
	report.OperationPlan = &OperationPlanReadinessProjection{
		SchemaVersion: "datapan.health-operation-plan-readiness.v1", Ready: false,
		RegistryRevision: binding.registryRevision, ReleaseManifestSHA256: binding.releaseManifestSHA256,
		IndexSHA256: binding.indexSHA256, ActivationSHA256: binding.activationSHA256,
		CanaryConfigSHA256: binding.canaryConfigSHA256, IdentityMappingSHA256: binding.identityMappingSHA256,
		RuntimePinSHA256: binding.runtimePinSHA256,
		KnownOperations:  binding.knownOperations, AdmittedOperations: 0,
		CapacityFeasible: false, EvidenceCheckedOperations: 0, EvidenceCurrentOperations: 0,
		EvidenceMissingOperations: 0, SuppressedLegacyCanaries: []string{},
	}
	server := readinessHTTPFixture(t, report, http.StatusServiceUnavailable, "application/json")
	defer server.Close()
	source, err := NewSchedulerHealthSelfReadinessSourceWithOperationPlanBinding(server.URL+"/status", config, time.Second, binding)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	value, err := source.Snapshot(context.Background())
	if err != nil || value.Ready || value.Reason != "operation_plan_unavailable" {
		t.Fatalf("zero-admitted plan did not fail readiness safely: value=%+v err=%v", value, err)
	}
}

func selfReadinessOperationPlanBindingFixture(t *testing.T, suppressAll, zeroAdmitted bool) (*OperationPlanReadinessBinding, CanaryConfig) {
	t.Helper()
	planRoot, planBinding, sourceSHA, operationIDs := writeGatusPlanFixture(t)
	plan, err := LoadPinnedOperationObservationPlan(planRoot, planBinding)
	if err != nil {
		t.Fatal(err)
	}
	metadata, canaries := gatusTestMetadata(sourceSHA, operationIDs)
	legacyID := "dpr-op-00000001"
	secondLegacyID := "dpr-op-00000002"
	legacyCanary := canaries.Canaries[0]
	legacyCanary.OperationID = legacyID
	canaries.Canaries[0] = legacyCanary
	secondCanary := legacyCanary
	secondCanary.OperationID = secondLegacyID
	secondCanary.GatusEndpointKey = "public-data_legacy-two"
	canaries.Canaries = append(canaries.Canaries, secondCanary)
	legacyLink := metadata.canaryLinksByHealthID["health-canary-one"]
	legacyLink.HealthOperationID = legacyID
	secondLink := legacyLink
	secondLink.HealthOperationID = secondLegacyID
	secondLink.RegistryOperationID = operationIDs[1]
	secondLink.UpstreamOperationSeq = "2"
	secondLink.CLIOperationKey = strings.Repeat("e", 64)
	metadata.canaryLinksByHealthID = map[string]RegistryHealthCanaryLink{legacyID: legacyLink, secondLegacyID: secondLink}
	var activationTargets []OperationGatusActivationEntry
	if !zeroAdmitted {
		activationTargets = append(activationTargets, OperationGatusActivationEntry{SourceID: "data_go_kr", OperationID: operationIDs[0]})
	}
	if suppressAll {
		activationTargets = append(activationTargets, OperationGatusActivationEntry{SourceID: "data_go_kr", OperationID: operationIDs[1]})
	}
	activationRaw, err := json.Marshal(OperationGatusActivation{
		SchemaVersion: OperationGatusActivationSchemaVersion, RegistryRevision: plan.RegistryRevision(),
		IndexSHA256: plan.IndexSHA256(), Operations: activationTargets,
	})
	if err != nil {
		t.Fatal(err)
	}
	activation, activationSHA, err := DecodeOperationGatusActivation(activationRaw, plan)
	if err != nil {
		t.Fatal(err)
	}
	base := []byte("web:\n  port: 8080\nendpoints:\n  - name: local-health\n    url: http://127.0.0.1:8080/health\n    conditions:\n      - \"[STATUS] == 200\"\nexternal-endpoints:\n  - name: placeholder\n")
	canaryRaw := []byte("verified-canary-bytes-for-readiness-fixture\n")
	artifacts, err := GenerateOperationGatusArtifacts(base, digestOperationGatusBytes(canaryRaw), canaries, metadata, &plan, &activation, activationSHA)
	if err != nil {
		t.Fatal(err)
	}
	runtimeRoot := t.TempDir()
	paths := operationPlanTestRuntimePaths(runtimeRoot)
	paths.PlanRoot = planRoot
	for path, raw := range map[string][]byte{
		paths.BaseGatusConfigPath: base, paths.GeneratedConfigPath: artifacts.Config,
		paths.IdentityMappingPath: artifacts.Mapping, paths.RuntimePinPath: artifacts.RuntimePin,
	} {
		if err := os.WriteFile(path, raw, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	paths.ActivationPath = filepath.Join(runtimeRoot, "activation.json")
	paths.ActivationSHA256 = activationSHA
	if err := os.WriteFile(paths.ActivationPath, activationRaw, 0o400); err != nil {
		t.Fatal(err)
	}
	runtime, err := verifyOperationGatusRuntimeArtifacts(paths, canaryRaw, canaries, metadata, plan)
	if err != nil {
		t.Fatal(err)
	}
	readinessBinding, err := NewOperationPlanReadinessBinding(runtime)
	if err != nil {
		t.Fatal(err)
	}
	return readinessBinding, canaries
}

func TestSchedulerHealthSelfReadinessRejectsInvalidReportsAndSources(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	base := readySelfReadinessDocument(t, config, now)
	stale, future := now.Add(-24*time.Hour), now.Add(time.Minute)
	tests := []struct {
		name   string
		mutate func(*schedulerReadinessDocument)
		status int
	}{
		{"ready without delivery", func(v *schedulerReadinessDocument) { v.Canaries[0].LastDelivered = nil }, http.StatusOK},
		{"stale delivery", func(v *schedulerReadinessDocument) { v.Canaries[0].LastDelivered = &stale }, http.StatusOK},
		{"future timestamp", func(v *schedulerReadinessDocument) { v.Canaries[0].LastAccepted = &future }, http.StatusOK},
		{"duplicate identity", func(v *schedulerReadinessDocument) { v.Canaries[1].OperationID = v.Canaries[0].OperationID }, http.StatusOK},
		{"unknown reason", func(v *schedulerReadinessDocument) { v.Reason = "secret_internal_host_token" }, http.StatusOK},
		{"status mismatch", func(v *schedulerReadinessDocument) { v.Ready = false }, http.StatusOK},
		{"stale loop", func(v *schedulerReadinessDocument) { old := now.Add(-time.Minute); v.LastLoop = &old }, http.StatusOK},
		{"503 claims ready", func(*schedulerReadinessDocument) {}, http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report := base
			report.Canaries = append([]CanaryProgress(nil), base.Canaries...)
			test.mutate(&report)
			server := readinessHTTPFixture(t, report, test.status, "application/json")
			defer server.Close()
			source, err := NewSchedulerHealthSelfReadinessSource(server.URL+"/status", config, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			source.now = func() time.Time { return now }
			value, err := source.Snapshot(context.Background())
			if err == nil || value.Ready || err.Error() != errHealthSelfReadinessUnavailable.Error() {
				t.Fatalf("unsafe report accepted or raw error surfaced: %+v %v", value, err)
			}
		})
	}
	for _, rawURL := range []string{"https://scheduler:8081/status", "http://scheduler/status", "http://scheduler:8081/status?target=127.0.0.1", "http://user:pass@scheduler:8081/status", "http://example.com:8081/status", "http://0.0.0.0:8081/status"} {
		if _, err := NewSchedulerHealthSelfReadinessSource(rawURL, config, time.Second); err == nil {
			t.Errorf("unsafe readiness URL accepted: %q", rawURL)
		}
	}
}

func TestSchedulerHealthSelfReadinessBoundsResponseAndTimeout(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	report := readySelfReadinessDocument(t, config, now)
	body, _ := json.Marshal(report)
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
	}{
		{"wrong content type", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(body)
		}},
		{"redirect", func(w http.ResponseWriter, _ *http.Request) {
			http.Redirect(w, httptest.NewRequest(http.MethodGet, "/", nil), "http://127.0.0.1:1/status", http.StatusFound)
		}},
		{"oversized body", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(strings.Repeat("x", maxHealthSelfReadinessBytes+1)))
		}},
		{"unknown field", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(append(body[:len(body)-1], []byte(`,"private_url":"secret"}`)...))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			source, err := NewSchedulerHealthSelfReadinessSource(server.URL+"/status", config, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.Snapshot(context.Background()); err == nil || err.Error() != errHealthSelfReadinessUnavailable.Error() {
				t.Fatalf("invalid response accepted or leaked: %v", err)
			}
		})
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer slow.Close()
	source, err := NewSchedulerHealthSelfReadinessSource(slow.URL+"/status", config, 5*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Snapshot(context.Background()); err == nil || err.Error() != errHealthSelfReadinessUnavailable.Error() {
		t.Fatalf("timeout did not fail closed: %v", err)
	}
}

func TestCachedHealthSelfReadinessCoalescesAndExpiresFreshness(t *testing.T) {
	var clockMu sync.Mutex
	now := time.Now().UTC()
	clock := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	setNow := func(value time.Time) { clockMu.Lock(); now = value; clockMu.Unlock() }
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	source := HealthSelfReadinessSourceFunc(func(context.Context) (HealthSelfReadiness, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		validUntil := clock().Add(3 * time.Second)
		return HealthSelfReadiness{Ready: true, State: "ready", Reason: "pipeline_current", ValidUntil: &validUntil}, nil
	})
	cached, err := NewCachedHealthSelfReadinessSource(source, 30*time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cached.now = clock
	const readers = 12
	results := make(chan error, readers)
	for range readers {
		go func() { _, err := cached.Snapshot(context.Background()); results <- err }()
	}
	<-started
	close(release)
	for range readers {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent requests=%d", calls.Load())
	}
	setNow(clock().Add(4 * time.Second))
	if _, err := cached.Snapshot(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("expired ready snapshot reused: calls=%d", calls.Load())
	}

	var timeoutCalls atomic.Int32
	timeoutSource := HealthSelfReadinessSourceFunc(func(ctx context.Context) (HealthSelfReadiness, error) {
		timeoutCalls.Add(1)
		<-ctx.Done()
		return HealthSelfReadiness{}, ctx.Err()
	})
	timeoutCache, err := NewCachedHealthSelfReadinessSource(timeoutSource, time.Second, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_, err = timeoutCache.Snapshot(context.Background())
		if err == nil || err.Error() != errHealthSelfReadinessUnavailable.Error() || strings.Contains(err.Error(), "deadline") {
			t.Fatalf("timeout error=%v", err)
		}
	}
	if timeoutCalls.Load() != 1 {
		t.Fatalf("cached timeout calls=%d", timeoutCalls.Load())
	}
	secret := errors.New("credential=https://internal.example/path")
	failedCache, err := NewCachedHealthSelfReadinessSource(HealthSelfReadinessSourceFunc(func(context.Context) (HealthSelfReadiness, error) { return HealthSelfReadiness{}, secret }), time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = failedCache.Snapshot(context.Background())
	if err == nil || err.Error() != errHealthSelfReadinessUnavailable.Error() || strings.Contains(err.Error(), "internal.example") {
		t.Fatalf("source error leaked: %v", err)
	}
}

func TestPublicHTMLReadinessDiagnosisAndHistoryAreAllowlisted(t *testing.T) {
	now := time.Now().UTC()
	projected := projectPublicHTMLReadiness(HealthSelfReadiness{State: "degraded", Reason: "secret_hostname_token"}, true, now)
	if projected.StatusLabel != "점검 필요" || strings.Contains(projected.Summary, "secret") || strings.Contains(projected.Summary, "hostname") {
		t.Fatalf("untrusted readiness reflected: %+v", projected)
	}
	projected = projectPublicHTMLReadiness(HealthSelfReadiness{}, false, now)
	if projected.StatusLabel != "확인 실패" || !strings.Contains(projected.Summary, "API 기능 응답과 별개의 관제 문제") {
		t.Fatalf("readiness failure was conflated: %+v", projected)
	}
	projected = projectPublicHTMLReadiness(HealthSelfReadiness{State: "degraded", Reason: "operation_plan_unavailable"}, true, now)
	if projected.StatusLabel != "점검 필요" || !strings.Contains(projected.Summary, "전체 검사 계획") {
		t.Fatalf("operation-plan readiness reason was not explained in Korean: %+v", projected)
	}
	status := PublicOperationStatus{ObservationState: "current", RawObservationState: "failed", IncidentState: "pending", Diagnosis: PublicDiagnosis{Code: "provider_outage", Determination: "observed", RecommendedActionIDs: []string{"check_provider_status", "https://secret.example"}}, History: []PublicResultHistoryPoint{{ReceivedAt: now.Add(-time.Minute), Success: true}, {ReceivedAt: now, Success: false}}}
	row := addPublicStatusLabels(publicHTMLOperation{}, status, now, true)
	if row.CauseLabel != "공급처 장애가 확인됐습니다." || row.NextActionLabel != "공급처 공지와 서비스 상태를 확인하세요." || len(row.History) != 2 || row.History[0].Class != "history-point-good" || row.History[1].Class != "history-point-bad" {
		t.Fatalf("projection=%+v", row)
	}
	for _, value := range []string{row.CauseLabel, row.NextActionLabel, row.History[0].FullKST, row.History[1].FullKST} {
		if strings.Contains(value, "secret") || strings.Contains(value, "https://") {
			t.Fatalf("private output leaked: %q", value)
		}
	}
}

func TestGatusReceiptHistoryIsBoundedInternalAndRendered(t *testing.T) {
	config, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	results := make([]map[string]any, maxGatusEndpointStatusResults)
	for index := range results {
		results[index] = map[string]any{"timestamp": now.Add(-time.Duration(len(results)-index) * time.Minute), "success": index%2 == 0}
	}
	gatus := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		const prefix = "/api/v1/endpoints/"
		const suffix = "/statuses"
		if !strings.HasPrefix(request.URL.Path, prefix) || !strings.HasSuffix(request.URL.Path, suffix) {
			http.NotFound(w, request)
			return
		}
		key := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, prefix), suffix)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"key": key, "results": results})
	}))
	defer gatus.Close()
	source, err := NewGatusPublicStatusSource(gatus.URL, config, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	document, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var selected PublicOperationStatus
	for _, operation := range document.Operations {
		if operation.OperationID == config.Canaries[0].OperationID {
			selected = operation
			break
		}
	}
	if len(selected.History) != maxPublicHistoryPoints || selected.History[0].ReceivedAt != now.Add(-50*time.Minute) || selected.History[len(selected.History)-1].ReceivedAt != now.Add(-time.Minute) || selected.HistoryStartedAt == nil || !selected.HistoryStartedAt.Equal(selected.History[0].ReceivedAt) {
		t.Fatalf("history was not recent, ordered, and bounded: len=%d history=%+v", len(selected.History), selected.History)
	}
	jsonWire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(jsonWire), "history") || strings.Contains(string(jsonWire), "received_at") {
		t.Fatalf("internal history changed v1 JSON: %s", jsonWire)
	}

	metadata := testRegistryAPIMetadata(t)
	publicDocument := testPublicDocument(t)
	link := metadata.HealthCanaryLinks[0]
	status := PublicOperationStatus{OperationID: link.HealthOperationID, ObservationState: "current", RawObservationState: "failed", IncidentState: "pending", Availability: "degraded", ObservedAt: timePointer(now.Add(-time.Minute)), Diagnosis: PublicDiagnosis{Code: "provider_outage", Determination: "inferred", RecommendedActionIDs: []string{"check_provider_status"}}, History: []PublicResultHistoryPoint{{ReceivedAt: now.Add(-2 * time.Minute), Success: true}, {ReceivedAt: now.Add(-time.Minute), Success: false}}}
	setPublicOperationStatus(t, &publicDocument, status)
	readiness := HealthSelfReadinessSourceFunc(func(context.Context) (HealthSelfReadiness, error) {
		return HealthSelfReadiness{Ready: false, State: "degraded", Reason: "delivery_stale"}, nil
	})
	handler, err := NewPublicStatusHandlerWithRegistryMetadataAndSelfReadiness(staticPublicSource{document: publicDocument}, []string{"https://datapan.statpan.com"}, metadata, readiness)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/datapan/dependencies/", nil))
	output := recorder.Body.String()
	for _, want := range []string{"Datapan 관제", "점검 필요", "최근 검사 결과 실패 · 연속 기준 확인 중", "공급처 장애로 추정됩니다.", "공급처 공지와 서비스 상태를 확인하세요.", "검사 결과 수신 이력 · 최근 2건", "history-point-good", "history-point-bad"} {
		if recorder.Code != http.StatusOK || !strings.Contains(output, want) {
			t.Errorf("public history/readiness missing %q (status %d)", want, recorder.Code)
		}
	}
	if strings.Contains(output, "dpr-op-") || strings.Contains(output, link.RegistryOperationID) || strings.Contains(output, "https://") || strings.Contains(output, "delivery_stale") {
		t.Fatal("private operation identity, raw reason, or endpoint leaked in HTML")
	}
}
