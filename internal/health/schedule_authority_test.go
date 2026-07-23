package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
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

func TestScheduleAuthorityIndependentProcessesAllowOnlyOneClaim(t *testing.T) {
	at := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	plan, queue := fullSchedulePlan(t, at, 64)
	path := filepath.Join(t.TempDir(), "schedule-state.json")
	if _, err := OpenScheduleCoverageAuthority(path, plan, queue); err != nil {
		t.Fatal(err)
	}
	start := filepath.Join(t.TempDir(), "start")
	commands := []*exec.Cmd{scheduleAuthorityHelper(t, "claim", path, start), scheduleAuthorityHelper(t, "claim", path, start)}
	results := make([][]byte, len(commands))
	errs := make([]error, len(commands))
	var wait sync.WaitGroup
	for index, command := range commands {
		wait.Add(1)
		go func(index int, command *exec.Cmd) {
			defer wait.Done()
			results[index], errs[index] = command.CombinedOutput()
		}(index, command)
	}
	time.Sleep(20 * time.Millisecond)
	if err := os.WriteFile(start, []byte("go"), 0o600); err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	claimed, failed := 0, 0
	for index := range commands {
		if errs[index] != nil {
			t.Fatalf("authority helper failed: %v: %s", errs[index], results[index])
		}
		switch {
		case strings.Contains(string(results[index]), "claimed"):
			claimed++
		case strings.Contains(string(results[index]), "fenced"):
			failed++
		default:
			t.Fatalf("unexpected authority helper result: %q", results[index])
		}
	}
	if claimed != 1 || failed != 1 {
		t.Fatalf("independent processes both accepted stale claim: claimed=%d fenced=%d", claimed, failed)
	}
}

func TestScheduleAuthorityCASRejectsStaleGeneration(t *testing.T) {
	at := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	plan, queue := fullSchedulePlan(t, at, 64)
	path := filepath.Join(t.TempDir(), "schedule-state.json")
	if _, err := OpenScheduleCoverageAuthority(path, plan, queue); err != nil {
		t.Fatal(err)
	}
	state, found, err := readScheduleCoverageAuthorityState(path)
	if err != nil || !found || state.Generation != 1 {
		t.Fatalf("unexpected initial generation: found=%t generation=%d err=%v", found, state.Generation, err)
	}
	if err := commitScheduleCoverageAuthorityState(path, 0, state); !errors.Is(err, ErrScheduleAuthorityConflict) {
		t.Fatalf("stale generation commit was accepted: %v", err)
	}
	current, found, err := readScheduleCoverageAuthorityState(path)
	if err != nil || !found || current.Generation != 1 {
		t.Fatalf("stale CAS changed state: found=%t generation=%d err=%v", found, current.Generation, err)
	}
}

func TestScheduleAuthorityClaimVsRebalanceCannotOverwriteNewPlan(t *testing.T) {
	at := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	plan, queue := fullSchedulePlan(t, at, 64)
	path := filepath.Join(t.TempDir(), "schedule-state.json")
	claimant, err := OpenScheduleCoverageAuthority(path, plan, queue)
	if err != nil {
		t.Fatal(err)
	}
	rebalancer, err := LoadScheduleCoverageAuthority(path)
	if err != nil {
		t.Fatal(err)
	}
	nextAt := at.Add(10 * time.Minute)
	next, nextQueue := fullSchedulePlan(t, nextAt, 127)
	start := make(chan struct{})
	claimResult := make(chan error, 1)
	rebalanceResult := make(chan error, 1)
	go func() {
		<-start
		_, err := claimant.Claim(queue[0].Subject, at, 20*time.Minute)
		claimResult <- err
	}()
	go func() {
		<-start
		rebalanceResult <- rebalancer.Rebalance(next, nextQueue, nextAt)
	}()
	close(start)
	claimErr, rebalanceErr := <-claimResult, <-rebalanceResult
	if claimErr == nil && rebalanceErr == nil {
		t.Fatal("claim and rebalance both committed")
	}
	if claimErr != nil && !errors.Is(claimErr, ErrSchedulePlanTransition) {
		t.Fatalf("claim failed for an unexpected reason: %v", claimErr)
	}
	if rebalanceErr != nil && !errors.Is(rebalanceErr, ErrSchedulePlanTransition) {
		t.Fatalf("rebalance failed for an unexpected reason: %v", rebalanceErr)
	}
	state, found, err := readScheduleCoverageAuthorityState(path)
	if err != nil || !found {
		t.Fatalf("missing durable state after race: found=%t err=%v", found, err)
	}
	ledger, err := restoreScheduleCoverageAuthorityState(state)
	if err != nil {
		t.Fatal(err)
	}
	if rebalanceErr == nil {
		if ledger.plan.Scheduler.ShardCount != 127 {
			t.Fatalf("stale claim overwrote rebalance plan: %#v", ledger.plan.Scheduler)
		}
		if _, err := claimant.RecordCoverage(at); !errors.Is(err, ErrSchedulePlanTransition) {
			t.Fatalf("stale authority wrote after rebalance: %v", err)
		}
	} else if ledger.plan.Scheduler.ShardCount != 64 {
		t.Fatalf("failed rebalance changed live plan: %#v", ledger.plan.Scheduler)
	}
}

func TestScheduleAuthorityCrashReleasesProcessLockWithoutPartialCommit(t *testing.T) {
	at := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
	plan, queue := fullSchedulePlan(t, at, 64)
	path := filepath.Join(t.TempDir(), "schedule-state.json")
	authority, err := OpenScheduleCoverageAuthority(path, plan, queue)
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "locked")
	command := scheduleAuthorityHelper(t, "hold-lock", path, ready)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = command.Process.Kill()
			t.Fatal("helper did not acquire process lock")
		}
		time.Sleep(time.Millisecond)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	claim, err := authority.Claim(queue[0].Subject, at, time.Minute)
	if err != nil || claim.Generation != 1 {
		t.Fatalf("crashed lock holder left partial or blocked authority state: claim=%#v err=%v", claim, err)
	}
	state, found, err := readScheduleCoverageAuthorityState(path)
	if err != nil || !found || state.Generation != 2 {
		t.Fatalf("post-crash commit was not generation checked: found=%t generation=%d err=%v", found, state.Generation, err)
	}
}

func scheduleAuthorityHelper(t *testing.T, mode, path string, marker ...string) *exec.Cmd {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestScheduleAuthorityProcessHelper$", "-test.v")
	command.Env = append(os.Environ(), "SCHEDULE_AUTHORITY_HELPER="+mode, "SCHEDULE_AUTHORITY_PATH="+path)
	if len(marker) > 0 {
		command.Env = append(command.Env, "SCHEDULE_AUTHORITY_MARKER="+marker[0])
	}
	return command
}

func TestScheduleAuthorityProcessHelper(t *testing.T) {
	mode := os.Getenv("SCHEDULE_AUTHORITY_HELPER")
	if mode == "" {
		return
	}
	path := os.Getenv("SCHEDULE_AUTHORITY_PATH")
	switch mode {
	case "claim":
		at := time.Date(2026, 7, 23, 0, 0, 0, 0, time.UTC)
		plan, queue := fullSchedulePlan(t, at, 64)
		authority, err := OpenScheduleCoverageAuthority(path, plan, queue)
		if err != nil {
			t.Fatal(err)
		}
		marker := os.Getenv("SCHEDULE_AUTHORITY_MARKER")
		for deadline := time.Now().Add(2 * time.Second); ; time.Sleep(time.Millisecond) {
			if _, err := os.Stat(marker); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("helper start barrier did not open")
			}
		}
		if _, err := authority.Claim(queue[0].Subject, at, time.Minute); err == nil {
			fmt.Print("claimed")
		} else if errors.Is(err, ErrScheduleLeaseHeld) {
			fmt.Print("fenced")
		} else {
			t.Fatal(err)
		}
	case "hold-lock":
		marker := os.Getenv("SCHEDULE_AUTHORITY_MARKER")
		if err := withScheduleCoverageAuthorityLock(path, func() error {
			if err := os.WriteFile(marker, []byte("locked"), 0o600); err != nil {
				return err
			}
			select {}
		}); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}
