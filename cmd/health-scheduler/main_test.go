package main

import (
	"path/filepath"
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
