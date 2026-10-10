package main

import (
	"encoding/json"
	"github.com/StatPan/datapan-health/internal/health"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
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
