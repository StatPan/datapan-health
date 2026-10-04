package main

import (
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
