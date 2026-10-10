package main

import (
	"encoding/json"
	"github.com/StatPan/datapan-health/internal/health"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScheduleCoverageLifecycleFromSchedulerEnvironmentIsDryRunOnly(t *testing.T) {
	t.Setenv("SCHEDULE_COVERAGE_STATE", filepath.Join(t.TempDir(), "coverage-state.json"))
	t.Setenv("SCHEDULE_COVERAGE_MANIFEST", "../../testdata/registry/data-go-kr-operation-manifest.v1.json")
	t.Setenv("SCHEDULE_COVERAGE_RELEASE_MANIFEST", "../../testdata/registry/release-manifest.v1.json")
	t.Setenv("SCHEDULE_COVERAGE_RECEIPT", "../../config/registry/operation-manifest-receipt.json")
	t.Setenv("SCHEDULE_COVERAGE_DRY_RUN", "true")
	coverage, err := scheduleCoverageLifecycle()
	if err != nil || coverage == nil {
		t.Fatalf("scheduler did not accept bounded dry-run coverage: coverage=%#v err=%v", coverage, err)
	}
	t.Setenv("SCHEDULE_COVERAGE_DRY_RUN", "false")
	if coverage, err := scheduleCoverageLifecycle(); err == nil || coverage != nil {
		t.Fatalf("scheduler accepted provider-capable coverage: coverage=%#v err=%v", coverage, err)
	}
}

func TestScheduleCoverageDryRunDeclarationFailsClosedWithoutCoverageState(t *testing.T) {
	t.Setenv("SCHEDULE_COVERAGE_STATE", "")
	t.Setenv("SCHEDULE_COVERAGE_DRY_RUN", "false")
	if coverage, err := scheduleCoverageLifecycle(); err == nil || coverage != nil {
		t.Fatalf("explicit false dry-run declaration allowed legacy scheduler startup: coverage=%#v err=%v", coverage, err)
	}
	t.Setenv("SCHEDULE_COVERAGE_DRY_RUN", "not-a-bool")
	if coverage, err := scheduleCoverageLifecycle(); err == nil || coverage != nil {
		t.Fatalf("invalid dry-run declaration allowed legacy scheduler startup: coverage=%#v err=%v", coverage, err)
	}
}

func TestSelfHTTPDistinguishesLiveReadyAndSafeStatus(t *testing.T) {
	config, err := health.LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := health.NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), health.CLIProcess{Path: "/missing-cli"}, health.AdapterProcess{Path: "/missing-adapter"})
	if err != nil {
		t.Fatal(err)
	}
	h := healthSchedulerHandler(s, func() string { return "cli_unavailable" })
	for _, test := range []struct {
		path string
		code int
	}{{"/live", 200}, {"/ready", 503}, {"/status", 503}, {"/metrics", 200}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", test.path, nil))
		if w.Code != test.code {
			t.Fatalf("%s returned %d", test.path, w.Code)
		}
		if test.path == "/status" {
			if !strings.Contains(w.Body.String(), "cli_unavailable") || !strings.Contains(w.Body.String(), "not_checked") {
				t.Fatal("status missing bounded evidence")
			}
		}
		if test.path == "/metrics" {
			if !strings.Contains(w.Body.String(), "canary_last_delivery_timestamp_seconds") || !strings.Contains(w.Body.String(), "scheduler_ready 0") {
				t.Fatal("progress gauges missing")
			}
		}
		if strings.Contains(w.Body.String(), "/missing") || strings.Contains(w.Body.String(), "endpoint_host") {
			t.Fatal("self status leaked details")
		}
	}
}

func TestImageBundleFailureKeepsReadinessClosed(t *testing.T) {
	config, err := health.LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("RUNTIME_DEPENDENCY_LOCK", filepath.Join(t.TempDir(), "missing-lock.json"))
	runner := health.CLIProcess{Path: "/opt/datapan-cli/datapan"}
	reason := runtimeDependencyPreflight(config, runner)
	if reason != "runtime_dependencies_unavailable" {
		t.Fatal("missing bundle did not block provider execution")
	}
	s, err := health.NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), runner, health.AdapterProcess{})
	if err != nil {
		t.Fatal(err)
	}
	h := healthSchedulerHandler(s, func() string { return reason })
	for _, test := range []struct {
		path   string
		status int
	}{{"/live", 200}, {"/ready", 503}, {"/status", 503}} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", test.path, nil))
		if w.Code != test.status || strings.Contains(w.Body.String(), "missing-lock") {
			t.Fatal("bundle failure readiness or redaction regressed")
		}
	}
}

func TestOperationPlanReadinessIsSeparateAndDisabledDefaultDoesNotChangeLegacyCanaries(t *testing.T) {
	config, err := health.LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HEALTH_OPERATION_GATUS_ACTIVATION", "")
	t.Setenv("HEALTH_OPERATION_GATUS_ACTIVATION_SHA256", "")
	control := loadOperationPlanControl("../../config/canaries.json", config, health.CLIProcess{Path: "/missing-cli"})
	if control.required || !control.legacySafe || control.failure != "" || control.scheduler != nil || len(control.legacyConfig.Canaries) != len(config.Canaries) || control.status.State != "disabled" {
		t.Fatalf("default-off generic plan setup changed the legacy selection: %#v", control)
	}
	s, err := health.NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), health.CLIProcess{Path: "/missing-cli"}, health.AdapterProcess{Path: "/missing-adapter"})
	if err != nil {
		t.Fatal(err)
	}
	h := healthSchedulerHandlerWithOperationPlan(s, func() string { return "" }, control.currentStatus)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/operation-plan/status", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"state":"disabled"`) || strings.Contains(w.Body.String(), "missing-cli") {
		t.Fatalf("disabled operation-plan status was not a safe separate state: code=%d body=%s", w.Code, w.Body.String())
	}
}

func TestOperationPlanCLISourcePinAcceptsOnlyReviewedEquivalentSources(t *testing.T) {
	for _, sourceSHA := range []string{
		"acf060e71e2329b6a04ad4ab0abf669fbbfe9dac",
		"668efcb5254df2bc4bcaac9ef405d1bfaea1a0d9",
	} {
		if !operationPlanCLISourceAllowed(sourceSHA) {
			t.Errorf("reviewed CLI source SHA %q was rejected", sourceSHA)
		}
	}
	for _, sourceSHA := range []string{
		"acf060e71e2329b6a04ad4ab0abf669fbbfe9da0",     // one-character near match
		"1111111111111111111111111111111111111111",     // arbitrary full-length SHA
		"668efcb5254df2bc4bcaac9ef405d1bfaea1a0d"[:39], // truncated SHA
		"89d1164ac8c910e18e50fc1c3a3961977c4d4f2e",     // pre-fix merged CLI source
		"752e995c1fc030e139cac90e3796e69884365383",     // pre-fix reviewed CLI source
		"5982d4dab287c7ec8c9935e3a617d79bf60e9c26",     // reviewed source before SOAP schema fixes
		"56604403120dad08cea351428dd3a6934066bed6",     // reviewed source before SOAP schema fixes
		"5780916201611c1612ccafa2d7212c2e16bfdd04",     // reviewed prior CLI source
		"397a68f5bf0bf895ee4c81db694d0c29d7deea98",     // reviewed earlier CLI source
		"a6414063bb69495b00b752b3a6c35bb0b52e14d5",     // merged older REST-only CLI
	} {
		if operationPlanCLISourceAllowed(sourceSHA) {
			t.Errorf("unreviewed CLI source SHA %q was accepted", sourceSHA)
		}
	}
}

func TestCanonicalReadinessCombinesLegacyAndOperationPlanWithoutPromotion(t *testing.T) {
	now := time.Now().UTC()
	legacyReady := health.SchedulerReadiness{Ready: true, State: "ready", Reason: "pipeline_current"}
	planUnavailable := health.OperationPlanSchedulerStatus{State: "degraded", Ready: false, Reason: "private target https://internal.example/v1?token=secret"}
	got, _ := canonicalSchedulerReadiness(func(time.Time) health.SchedulerReadiness { return legacyReady }, nil, func(time.Time) health.OperationPlanSchedulerStatus { return planUnavailable }, now)
	if got.Ready || got.State != "degraded" || got.Reason != "operation_plan_unavailable" {
		t.Fatalf("active unready plan did not close canonical readiness safely: %+v", got)
	}

	legacyUnready := health.SchedulerReadiness{Ready: false, State: "degraded", Reason: "delivery_stale"}
	planReady := health.OperationPlanSchedulerStatus{State: "ready", Ready: true}
	got, _ = canonicalSchedulerReadiness(func(time.Time) health.SchedulerReadiness { return legacyUnready }, nil, func(time.Time) health.OperationPlanSchedulerStatus { return planReady }, now)
	if got.Ready || got.State != "degraded" || got.Reason != "delivery_stale" {
		t.Fatalf("healthy operation-plan lane promoted stale legacy readiness: %+v", got)
	}

	planDisabled := health.OperationPlanSchedulerStatus{State: "disabled", Ready: false}
	got, _ = canonicalSchedulerReadiness(func(time.Time) health.SchedulerReadiness { return legacyReady }, nil, func(time.Time) health.OperationPlanSchedulerStatus { return planDisabled }, now)
	if !got.Ready || got.State != "ready" || got.Reason != "pipeline_current" {
		t.Fatalf("disabled operation-plan lane changed healthy legacy readiness: %+v", got)
	}
}

func TestDisabledOperationPlanKeepsHealthyLegacyHTTPRoutesReady(t *testing.T) {
	config, err := health.LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := health.NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), health.CLIProcess{Path: "/missing-cli"}, health.AdapterProcess{Path: "/missing-adapter"})
	if err != nil {
		t.Fatal(err)
	}
	legacyReady := health.SchedulerReadiness{Ready: true, State: "ready", Reason: "pipeline_current"}
	planDisabled := health.OperationPlanSchedulerStatus{State: "disabled", Ready: false, Reason: "activation_not_configured"}
	h := healthSchedulerHandlerWithReadiness(s, func(time.Time) health.SchedulerReadiness { return legacyReady }, func() string { return "" }, func(time.Time) health.OperationPlanSchedulerStatus { return planDisabled })
	for _, path := range []string{"/ready", "/status"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 {
			t.Fatalf("disabled operation-plan lane changed %s: code=%d body=%s", path, w.Code, w.Body.String())
		}
		if path == "/status" {
			var report health.SchedulerReadiness
			if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil || !report.Ready || report.Reason != "pipeline_current" {
				t.Fatalf("disabled operation-plan lane changed legacy report: %+v err=%v", report, err)
			}
		}
	}
}

func TestActiveOperationPlanUnavailableClosesCanonicalHTTPAndMetricOncePerRequest(t *testing.T) {
	config, err := health.LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := health.NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), health.CLIProcess{Path: "/missing-cli"}, health.AdapterProcess{Path: "/missing-adapter"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	legacyReady := health.SchedulerReadiness{SchemaVersion: "datapan.health-self-readiness.v1", Ready: true, State: "ready", Reason: "pipeline_current", LastLoop: timePointer(now.Add(-time.Second)), PublicReadback: "not_checked", DeploymentIdentity: "not_checked"}
	for _, canary := range config.Canaries {
		started, accepted := now.Add(-20*time.Second), now.Add(-10*time.Second)
		delivered, observed := now.Add(-5*time.Second), now.Add(-15*time.Second)
		legacyReady.Canaries = append(legacyReady.Canaries, health.CanaryProgress{OperationID: canary.OperationID, LastStarted: &started, LastAccepted: &accepted, LastDelivered: &delivered, OriginalObservedAt: &observed, State: "ready", Reason: "delivered"})
	}
	const privatePlanReason = "private target https://internal.example/v1?token=secret"
	planUnavailable := health.OperationPlanSchedulerStatus{SchemaVersion: "datapan.health-operation-plan-scheduler-status.v1", State: "degraded", Ready: false, Reason: privatePlanReason}
	callbackCalls := 0
	h := healthSchedulerHandlerWithReadiness(s, func(time.Time) health.SchedulerReadiness { return legacyReady }, func() string { return "" }, func(time.Time) health.OperationPlanSchedulerStatus {
		callbackCalls++
		return planUnavailable
	})
	for _, path := range []string{"/status", "/ready", "/metrics"} {
		before := callbackCalls
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if callbackCalls != before+1 {
			t.Fatalf("%s sampled operation-plan state %d times", path, callbackCalls-before)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s changed no-store response policy", path)
		}
		if strings.Contains(w.Body.String(), privatePlanReason) || strings.Contains(w.Body.String(), "internal.example") || strings.Contains(w.Body.String(), "token=secret") {
			t.Fatalf("%s exposed private operation-plan details: %s", path, w.Body.String())
		}
		switch path {
		case "/status":
			if w.Code != 503 {
				t.Fatalf("%s status=%d body=%s", path, w.Code, w.Body.String())
			}
			if w.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("status content type=%q", w.Header().Get("Content-Type"))
			}
			var report health.SchedulerReadiness
			if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil || report.Ready || report.State != "degraded" || report.Reason != "operation_plan_unavailable" {
				t.Fatalf("canonical status=%+v err=%v body=%s", report, err, w.Body.String())
			}
		case "/ready":
			if w.Code != 503 {
				t.Fatalf("%s status=%d body=%s", path, w.Code, w.Body.String())
			}
			if w.Body.String() != "not ready\n" {
				t.Fatalf("unexpected ready body: %q", w.Body.String())
			}
		case "/metrics":
			if w.Code != 200 {
				t.Fatalf("metrics status=%d body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "datapan_health_scheduler_ready 0\n") {
				t.Fatalf("main scheduler readiness metric stayed ready: %s", w.Body.String())
			}
		}
	}
	for _, test := range []struct {
		path string
		code int
	}{{"/status", 503}, {"/ready", 503}, {"/metrics", 200}} {
		before := callbackCalls
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("HEAD", test.path, nil))
		if w.Code != test.code || w.Body.Len() != 0 || w.Header().Get("Cache-Control") != "no-store" || callbackCalls != before+1 {
			t.Fatalf("HEAD %s changed status, body, cache, or callback behavior: code=%d body=%q cache=%q calls=%d", test.path, w.Code, w.Body.String(), w.Header().Get("Cache-Control"), callbackCalls-before)
		}
	}
}

func TestHealthyOperationPlanDoesNotPromoteStaleLegacyHTTPReadiness(t *testing.T) {
	config, err := health.LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	s, err := health.NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), health.CLIProcess{Path: "/missing-cli"}, health.AdapterProcess{Path: "/missing-adapter"})
	if err != nil {
		t.Fatal(err)
	}
	legacyStale := health.SchedulerReadiness{Ready: false, State: "degraded", Reason: "delivery_stale"}
	planReady := health.OperationPlanSchedulerStatus{State: "ready", Ready: true}
	h := healthSchedulerHandlerWithReadiness(s, func(time.Time) health.SchedulerReadiness { return legacyStale }, func() string { return "" }, func(time.Time) health.OperationPlanSchedulerStatus { return planReady })
	for _, path := range []string{"/ready", "/status", "/metrics"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if path == "/metrics" {
			if w.Code != 200 {
				t.Fatalf("metrics returned status %d", w.Code)
			}
			if !strings.Contains(w.Body.String(), "datapan_health_scheduler_ready 0\n") {
				t.Fatalf("legacy failure was promoted by the new lane: %s", w.Body.String())
			}
			continue
		}
		if w.Code != 503 {
			t.Fatalf("%s promoted stale legacy readiness: code=%d body=%s", path, w.Code, w.Body.String())
		}
		if path == "/status" {
			var report health.SchedulerReadiness
			if err := json.Unmarshal(w.Body.Bytes(), &report); err != nil || report.Reason != "delivery_stale" {
				t.Fatalf("legacy failure reason changed: %+v err=%v", report, err)
			}
		}
	}
}

func timePointer(value time.Time) *time.Time { return &value }

func TestOperationPlanActivationWithoutPinBlocksLegacyAndReportsGenericReadiness(t *testing.T) {
	config, err := health.LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HEALTH_OPERATION_GATUS_ACTIVATION", "/image/activation.json")
	t.Setenv("HEALTH_OPERATION_GATUS_ACTIVATION_SHA256", "")
	control := loadOperationPlanControl("../../config/canaries.json", config, health.CLIProcess{Path: "/missing-cli"})
	if !control.required || control.legacySafe || control.failure != "activation_pin_unavailable" || control.status.Reason != "activation_pin_unavailable" {
		t.Fatalf("unverified generic activation did not fail closed before legacy execution: %#v", control)
	}
	s, err := health.NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), health.CLIProcess{Path: "/missing-cli"}, health.AdapterProcess{Path: "/missing-adapter"})
	if err != nil {
		t.Fatal(err)
	}
	h := healthSchedulerHandlerWithOperationPlan(s, func() string { return "operation_plan_activation_unavailable" }, control.currentStatus)
	for _, route := range []string{"/operation-plan/status", "/operation-plan/ready"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", route, nil))
		if w.Code != 503 || !strings.Contains(w.Body.String(), "activation_pin_unavailable") && route == "/operation-plan/status" {
			t.Fatalf("invalid activation did not report its bounded readiness reason: route=%s code=%d body=%s", route, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "/image/") || strings.Contains(w.Body.String(), "missing-cli") {
			t.Fatal("operation-plan status exposed runtime paths")
		}
		if route == "/operation-plan/status" {
			var decoded health.OperationPlanSchedulerStatus
			if err := json.Unmarshal(w.Body.Bytes(), &decoded); err != nil || decoded.Reason != "activation_pin_unavailable" || decoded.Ready {
				t.Fatalf("status did not preserve typed generic readiness: %#v err=%v", decoded, err)
			}
		}
	}
}

func TestLegacySuppressionRequiresExactKnownCanaryIDs(t *testing.T) {
	config, err := health.LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	filtered, err := filterSuppressedLegacyCanaries(config, []string{config.Canaries[0].OperationID})
	if err != nil || len(filtered.Canaries) != len(config.Canaries)-1 {
		t.Fatalf("exact verified overlap was not suppressed: remaining=%d err=%v", len(filtered.Canaries), err)
	}
	if _, err := filterSuppressedLegacyCanaries(config, []string{"unregistered-health-id"}); err == nil {
		t.Fatal("runtime suppressed an ID that was not a configured legacy canary")
	}
	if _, err := filterSuppressedLegacyCanaries(config, []string{config.Canaries[0].OperationID, config.Canaries[0].OperationID}); err == nil {
		t.Fatal("runtime accepted a repeated legacy suppression identity")
	}
}
