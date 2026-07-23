package health

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScheduleAuthorityPersistsClaimsAcrossRestartAndFencesStaleWorkers(t *testing.T) {
	at := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	plan, queue := fullSchedulePlan(t, at, 64)
	path := filepath.Join(t.TempDir(), "schedule-state.json")
	authority, err := OpenScheduleCoverageAuthority(path, plan, queue)
	if err != nil {
		t.Fatal(err)
	}
	first, err := authority.Claim(queue[0].Subject, at, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := LoadScheduleCoverageAuthority(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := restarted.Claim(queue[0].Subject, at.Add(2*time.Minute), 20*time.Minute)
	if err != nil || second.Generation != first.Generation+1 {
		t.Fatalf("restart did not persist/recover fenced lease: claim=%#v err=%v", second, err)
	}
	if err := restarted.Complete(first, at.Add(2*time.Minute)); !errors.Is(err, ErrScheduleFenced) {
		t.Fatalf("pre-restart claim completed authoritatively: %v", err)
	}
	if err := restarted.Complete(second, at.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	receipt, err := restarted.RecordCoverage(at.Add(3 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Aggregate != (ScheduleCoverageCounts{Expected: 12385, Assigned: 12385, Attempted: 1, Completed: 1, Late: 0, Missing: 12384}) {
		t.Fatalf("durable coverage receipt lost authoritative state: %#v", receipt.Aggregate)
	}
	reloaded, err := LoadScheduleCoverageAuthority(path)
	if err != nil {
		t.Fatal(err)
	}
	report := reloaded.Doctor(at.Add(4*time.Minute), 20*time.Minute)
	if report.ReceiptState != "current" || report.Registry != plan.Registry || report.ShardCount != 64 || report.LatestInterval != at || report.Counts != receipt.Aggregate {
		t.Fatalf("operator receipt did not survive restart: %#v", report)
	}
}

func TestScheduleAuthorityRequiresBoundaryForRebalanceAndRetainsOldReceipt(t *testing.T) {
	at := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	plan, queue := fullSchedulePlan(t, at, 64)
	path := filepath.Join(t.TempDir(), "schedule-state.json")
	authority, err := OpenScheduleCoverageAuthority(path, plan, queue)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.Claim(queue[0].Subject, at, 20*time.Minute); err != nil {
		t.Fatal(err)
	}
	blockedAt := at.Add(10 * time.Minute)
	blocked, blockedQueue := fullSchedulePlan(t, blockedAt, 127)
	if err := authority.Rebalance(blocked, blockedQueue, blockedAt); !errors.Is(err, ErrSchedulePlanTransition) {
		t.Fatalf("active lease allowed a rebalance: %v", err)
	}
	if _, err := authority.RecordCoverage(at); err != nil {
		t.Fatal(err)
	}
	// The active lease expires at the next boundary, so a candidate transition
	// there is safe and preserves a missing-work receipt for the old interval.
	nextAt := at.Add(20 * time.Minute)
	next, nextQueue := fullSchedulePlan(t, nextAt, 127)
	if err := authority.Rebalance(next, nextQueue, nextAt); err != nil {
		t.Fatal(err)
	}
	restarted, err := LoadScheduleCoverageAuthority(path)
	if err != nil {
		t.Fatal(err)
	}
	report := restarted.Doctor(nextAt, 20*time.Minute)
	if report.ShardCount != 127 || report.ReceiptState != "missing" || report.Counts.Missing != 12385 {
		t.Fatalf("rebalance did not durably expose new missing receipt state: %#v", report)
	}
	state, found, err := readScheduleCoverageAuthorityState(path)
	if err != nil || !found || state.Previous == nil || state.Previous.Aggregate.Missing != 12385 || state.Previous.Scheduler.ShardCount != 64 {
		t.Fatalf("rebalance did not retain the old interval receipt: found=%t state=%#v err=%v", found, state.Previous, err)
	}
}

func TestScheduleAuthorityDoctorIsValueFreeAndReportsMissingStaleInvalid(t *testing.T) {
	at := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	missing := ReadScheduleCoverageDoctorReport(filepath.Join(t.TempDir(), "missing.json"), at, time.Minute)
	if missing.ReceiptState != "missing" || missing.ShardCount != 0 {
		t.Fatalf("missing authority state was not explicit: %#v", missing)
	}
	plan, queue := fullSchedulePlan(t, at, 64)
	path := filepath.Join(t.TempDir(), "schedule-state.json")
	authority, err := OpenScheduleCoverageAuthority(path, plan, queue)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RecordCoverage(at); err != nil {
		t.Fatal(err)
	}
	stale := ReadScheduleCoverageDoctorReport(path, at.Add(21*time.Minute), 20*time.Minute)
	if stale.ReceiptState != "stale" || stale.Counts.Missing != 12385 {
		t.Fatalf("stale receipt was not explicit: %#v", stale)
	}
	encoded, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), queue[0].Subject) || strings.Contains(string(encoded), "endpoint") || strings.Contains(string(encoded), "provider") {
		t.Fatalf("operator report leaked private schedule input: %s", encoded)
	}
}
