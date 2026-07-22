package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBoundedObservationRunnerProducesEightRedactedArtifactsWithinConcurrencyBound(t *testing.T) {
	runner := testBoundedObservationRunner(t, observationCommand(t, "true"))

	receipt, err := runner.Run(context.Background(), "health-run-fixture-0001", testObservationPlans())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Aggregate.TerminalState != "verified" || receipt.Aggregate.Completeness != "complete" || receipt.Run.MaxParallel != 2 {
		t.Fatalf("unexpected bounded result: %#v", receipt.Aggregate)
	}
	aggregate, err := os.ReadFile(filepath.Join(runner.OutputRoot, receipt.Run.RunID, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	published, err := DecodeBoundedObservationRun(strings.NewReader(string(aggregate)))
	if err != nil || !reflect.DeepEqual(published, receipt) {
		t.Fatalf("batch receipt was not safely published: %v", err)
	}
	for _, shard := range receipt.Shards {
		if !shard.ReceiptAvailable || !shard.Completed {
			t.Fatalf("shard %d is not admittable", shard.Index)
		}
		raw, err := os.ReadFile(filepath.Join(runner.OutputRoot, receipt.Run.RunID, shard.ReceiptPath))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != shard.ReceiptSHA256 {
			t.Fatalf("digest mismatch for shard %d", shard.Index)
		}
		for _, forbidden := range []string{"fixture-secret", "serviceKey=", "authorization", "response_body", "user_identity"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatalf("artifact leaked %q", forbidden)
			}
		}
	}
}

func TestBoundedObservationRunnerBindsEveryValidatedPlanToTheChild(t *testing.T) {
	markers := t.TempDir()
	runner := testBoundedObservationRunner(t, helperPlanCommand(markers))
	plans := testObservationPlans()
	if _, err := runner.Run(context.Background(), "health-run-fixture-0010", plans); err != nil {
		t.Fatal(err)
	}
	for _, plan := range plans {
		value, err := os.ReadFile(filepath.Join(markers, strconv.Itoa(plan.Index)))
		if err != nil {
			t.Fatalf("plan %d did not reach child: %v", plan.Index, err)
		}
		if got, want := string(value), plan.ShardDigest+":"+strconv.Itoa(plan.OperationCount); got != want {
			t.Fatalf("plan %d binding mismatch: got %q want %q", plan.Index, got, want)
		}
	}
}

func TestBoundedObservationRunnerTimeoutAndCancellationAreUnavailablePartial(t *testing.T) {
	runner := testBoundedObservationRunner(t, ObservationCommandSpec{Path: commandPath(t, "sleep"), Args: []string{"5"}})
	startedAt := time.Now()
	receipt, err := runner.Run(context.Background(), "health-run-fixture-0002", testObservationPlans())
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Aggregate.Completeness != "partial" || receipt.Aggregate.TerminalState != "unknown" {
		t.Fatalf("timeout was promoted: %#v", receipt.Aggregate)
	}
	for _, shard := range receipt.Shards {
		if !shard.TimedOut || shard.ReceiptAvailable || shard.TerminalState != "unknown" {
			t.Fatalf("timeout shard was admitted: %#v", shard)
		}
	}
	// Eight 1-second deadline waves may only run two children at once. A
	// shorter-than-four-wave completion would prove a concurrency breach.
	if elapsed := time.Since(startedAt); elapsed < 3500*time.Millisecond {
		t.Fatalf("more than two timed-out children ran concurrently: %s", elapsed)
	}

	started := filepath.Join(t.TempDir(), "started")
	runner = testBoundedObservationRunner(t, helperCommand(started, "", "block"))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan BoundedObservationRun, 1)
	go func() { got, _ := runner.Run(ctx, "health-run-fixture-0003", testObservationPlans()); done <- got }()
	waitForFile(t, started)
	cancel()
	got := <-done
	if got.Aggregate.Completeness != "partial" || got.Aggregate.TerminalState != "unknown" {
		t.Fatalf("cancellation was promoted: %#v", got.Aggregate)
	}
	if matches, err := filepath.Glob(filepath.Join(runner.OutputRoot, got.Run.RunID, "shards", "*", "receipt.json")); err != nil || len(matches) != 0 {
		t.Fatalf("late cancellation wrote artifacts: %v %v", matches, err)
	}
}

func TestBoundedObservationRunnerRetainsSkippedAndFailedTerminalStates(t *testing.T) {
	for _, test := range []struct {
		name, mode, shardState, aggregate string
		available                         bool
	}{
		{name: "skipped", mode: "skip", shardState: "skipped", aggregate: "skipped", available: true},
		{name: "failed", mode: "fail", shardState: "failed", aggregate: "unknown", available: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			runner := testBoundedObservationRunner(t, helperCommand("", "", test.mode))
			receipt, err := runner.Run(context.Background(), "health-run-fixture-0009", testObservationPlans())
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Aggregate.TerminalState != test.aggregate {
				t.Fatalf("terminal state was erased: %#v", receipt.Aggregate)
			}
			for _, shard := range receipt.Shards {
				if shard.TerminalState != test.shardState || shard.ReceiptAvailable != test.available {
					t.Fatalf("unexpected terminal shard: %#v", shard)
				}
			}
		})
	}
}

func TestBoundedObservationRunnerKillsDescendantsAndDoesNotLateWrite(t *testing.T) {
	if _, err := os.Stat("/proc"); err != nil { // Process-tree assertion is Linux-specific.
		t.Skip("process group assertion requires Linux")
	}
	childMarker := filepath.Join(t.TempDir(), "late-child")
	runner := testBoundedObservationRunner(t, helperCommand("", childMarker, "parent"))
	_, err := runner.Run(context.Background(), "health-run-fixture-0006", testObservationPlans())
	if err != nil {
		t.Fatal(err)
	}
	// The child would write after 1.5s if it survived the parent deadline.
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(childMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("timed-out descendant survived or wrote late: %v", err)
	}
}

func TestBoundedObservationRunnerFailsClosedBeforeExecutionAndForUnsafeOutput(t *testing.T) {
	runner := testBoundedObservationRunner(t, observationCommand(t, "true"))
	bad := testObservationPlans()
	bad[7].Index = 0
	if _, err := runner.Run(context.Background(), "health-run-fixture-0004", bad); err == nil {
		t.Fatal("duplicate plan accepted")
	}
	if _, err := os.Stat(filepath.Join(runner.OutputRoot, "health-run-fixture-0004")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid plans reached output boundary: %v", err)
	}
	if _, err := runner.Run(context.Background(), "../health-run-fixture-0004", testObservationPlans()); err == nil {
		t.Fatal("traversal run id accepted")
	}
	if err := os.Mkdir(filepath.Join(runner.OutputRoot, "health-run-fixture-0004"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), "health-run-fixture-0004", testObservationPlans()); err == nil {
		t.Fatal("run collision accepted")
	}
	runner.Registry.ManifestSHA256 = "not-a-digest"
	if _, err := runner.Run(context.Background(), "health-run-fixture-0005", testObservationPlans()); err == nil {
		t.Fatal("invalid policy binding accepted")
	}

	outside := t.TempDir()
	link := filepath.Join(t.TempDir(), "output")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	runner.OutputRoot = link
	if _, err := runner.Run(context.Background(), "health-run-fixture-0004", testObservationPlans()); err == nil {
		t.Fatal("symlink output root accepted")
	}
}

func TestBoundedObservationRunnerRejectsStaleFutureAndMismatchedBindingBeforeCommandStart(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*BoundedObservationRunner)
	}{
		{
			name: "stale binding",
			mutate: func(r *BoundedObservationRunner) {
				r.Binding.ReferenceAt = r.Binding.BindingVerifiedAt.Add(2 * time.Minute)
				r.Binding.MaxAge = time.Minute
			},
		},
		{
			name: "future binding",
			mutate: func(r *BoundedObservationRunner) {
				r.Binding.ReferenceAt = r.Binding.BindingVerifiedAt.Add(-time.Second)
			},
		},
		{
			name: "mismatched policy digest",
			mutate: func(r *BoundedObservationRunner) {
				r.Binding.Expected.PolicySHA256 = strings.Repeat("f", 64)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := filepath.Join(t.TempDir(), "started")
			runner := testBoundedObservationRunner(t, helperCommand(started, "", "block"))
			test.mutate(&runner)
			if _, err := runner.Run(context.Background(), "health-run-fixture-0007", testObservationPlans()); err == nil {
				t.Fatal("unsafe binding reached runner")
			}
			time.Sleep(100 * time.Millisecond)
			if _, err := os.Stat(started); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid binding started a command: %v", err)
			}
			if _, err := os.Stat(filepath.Join(runner.OutputRoot, "health-run-fixture-0007")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid binding reached output boundary: %v", err)
			}
		})
	}
}

func TestBoundedObservationRunnerRejectsReservedEnvironmentOverrideBeforeCommandStart(t *testing.T) {
	started := filepath.Join(t.TempDir(), "started")
	runner := testBoundedObservationRunner(t, helperCommand(started, "", "block"))
	runner.Command.Environment = append(runner.Command.Environment, "DATAPAN_HEALTH_OBSERVATION_SHARD_INDEX=forged")
	if _, err := runner.Run(context.Background(), "health-run-fixture-0011", testObservationPlans()); err == nil {
		t.Fatal("reserved plan binding override was accepted")
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(started); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("reserved override started a command: %v", err)
	}
}

func TestBoundedObservationRunnerRejectsBoundsOutsideTheEightByHundredByTwoContract(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*BoundedObservationRunner, []ObservationShardPlan)
	}{
		{name: "batch above 100", mutate: func(r *BoundedObservationRunner, _ []ObservationShardPlan) { r.BatchSize = 101 }},
		{name: "parallel above 2", mutate: func(r *BoundedObservationRunner, _ []ObservationShardPlan) { r.MaxParallel = 3 }},
		{name: "timeout above 20 seconds", mutate: func(r *BoundedObservationRunner, _ []ObservationShardPlan) { r.Timeout = 21 * time.Second }},
		{name: "operation above batch", mutate: func(_ *BoundedObservationRunner, plans []ObservationShardPlan) { plans[0].OperationCount = 101 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := filepath.Join(t.TempDir(), "started")
			runner := testBoundedObservationRunner(t, helperCommand(started, "", "block"))
			plans := testObservationPlans()
			test.mutate(&runner, plans)
			if _, err := runner.Run(context.Background(), "health-run-fixture-0008", plans); err == nil {
				t.Fatal("out-of-contract runner input was accepted")
			}
			time.Sleep(100 * time.Millisecond)
			if _, err := os.Stat(started); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("out-of-contract input started a command: %v", err)
			}
		})
	}
}

func TestBoundedObservationCommandRejectsShellAndSymlink(t *testing.T) {
	if validObservationCommand(ObservationCommandSpec{Path: "/bin/sh"}) {
		t.Fatal("shell command accepted")
	}
	target := commandPath(t, "true")
	link := filepath.Join(t.TempDir(), "runner")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if validObservationCommand(ObservationCommandSpec{Path: link}) {
		t.Fatal("symlink executable accepted")
	}
}

func TestBoundedObservationArtifactWriteRejectsSymlinkEscapeAndCollision(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "shards")); err != nil {
		t.Fatal(err)
	}
	if _, err := writeBoundedObservationArtifact(root, 0, []byte("safe")); err == nil {
		t.Fatal("shard symlink escape accepted")
	}

	root = t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "shards", "0"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "shards", "0", "receipt.json"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := writeBoundedObservationArtifact(root, 0, []byte("new")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("collision was not rejected: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(root, "shards", "0", "receipt.json")); err != nil || string(got) != "old" {
		t.Fatalf("existing artifact changed: %q %v", got, err)
	}

	root = t.TempDir()
	var writes, collisions atomic.Int32
	var workers sync.WaitGroup
	for range 8 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if _, err := writeBoundedObservationArtifact(root, 0, []byte("atomic")); err == nil {
				writes.Add(1)
			} else if errors.Is(err, os.ErrExist) {
				collisions.Add(1)
			} else {
				t.Errorf("unexpected publish error: %v", err)
			}
		}()
	}
	workers.Wait()
	if writes.Load() != 1 || collisions.Load() != 7 {
		t.Fatalf("no-replace publish was not collision safe: writes=%d collisions=%d", writes.Load(), collisions.Load())
	}
	if got, err := os.ReadFile(filepath.Join(root, "shards", "0", "receipt.json")); err != nil || string(got) != "atomic" {
		t.Fatalf("atomic artifact was partial: %q %v", got, err)
	}
}

func TestBoundedObservationBatchPublishRejectsCollisionAndSymlink(t *testing.T) {
	directory := t.TempDir()
	if _, err := publishBoundedObservationFile(directory, "receipt.json", []byte("first")); err != nil {
		t.Fatal(err)
	}
	if _, err := publishBoundedObservationFile(directory, "receipt.json", []byte("second")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("batch collision was not rejected: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(directory, "receipt.json")); err != nil || string(got) != "first" {
		t.Fatalf("batch receipt was overwritten: %q %v", got, err)
	}

	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "receipt.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := publishBoundedObservationFile(root, "receipt.json", []byte("safe")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("batch symlink collision was not rejected: %v", err)
	}
}

func TestBoundedObservationRunnerHelperProcess(t *testing.T) {
	mode := os.Getenv("BOUNDED_OBSERVATION_HELPER_MODE")
	if mode == "" {
		return
	}
	if path := os.Getenv("BOUNDED_OBSERVATION_STARTED"); path != "" {
		_ = os.WriteFile(path, []byte("started"), 0o600)
	}
	switch mode {
	case "block":
		time.Sleep(5 * time.Second)
	case "skip":
		os.Exit(75)
	case "fail":
		os.Exit(2)
	case "bind":
		markerRoot := os.Getenv("BOUNDED_OBSERVATION_PLAN_MARKERS")
		index := os.Getenv("DATAPAN_HEALTH_OBSERVATION_SHARD_INDEX")
		digest := os.Getenv("DATAPAN_HEALTH_OBSERVATION_SHARD_DIGEST")
		count := os.Getenv("DATAPAN_HEALTH_OBSERVATION_OPERATION_COUNT")
		if markerRoot == "" || index == "" || digest == "" || count == "" || os.WriteFile(filepath.Join(markerRoot, index), []byte(digest+":"+count), 0o600) != nil {
			os.Exit(2)
		}
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=^TestBoundedObservationRunnerHelperProcess$", "--")
		child.Env = append(os.Environ(), "BOUNDED_OBSERVATION_HELPER_MODE=child")
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		time.Sleep(5 * time.Second)
	case "child":
		time.Sleep(1500 * time.Millisecond)
		if path := os.Getenv("BOUNDED_OBSERVATION_CHILD_MARKER"); path != "" {
			_ = os.WriteFile(path, []byte("late"), 0o600)
		}
	}
	os.Exit(0)
}

func testBoundedObservationRunner(t *testing.T, command ObservationCommandSpec) BoundedObservationRunner {
	t.Helper()
	registry := ObservationRunRegistry{SourceRevision: strings.Repeat("b", 40), SourceSHA256: strings.Repeat("c", 64), ManifestSHA256: strings.Repeat("d", 64), PolicySHA256: strings.Repeat("e", 64)}
	verifiedAt := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	return BoundedObservationRunner{Producer: ObservationRunProducer{Repository: "StatPan/datapan-health", Revision: strings.Repeat("a", 40)}, Registry: registry, Binding: ObservationBindingGuard{Expected: registry, BindingVerifiedAt: verifiedAt, ReferenceAt: verifiedAt.Add(30 * time.Second), MaxAge: time.Minute}, BatchSize: 100, MaxParallel: 2, Timeout: time.Second, OutputRoot: t.TempDir(), Command: command, Now: func() time.Time { return time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC) }}
}

func observationCommand(t *testing.T, name string) ObservationCommandSpec {
	t.Helper()
	return ObservationCommandSpec{Path: commandPath(t, name)}
}

func commandPath(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	path, err = filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func helperCommand(started, childMarker, mode string) ObservationCommandSpec {
	environment := []string{"BOUNDED_OBSERVATION_HELPER_MODE=" + mode}
	if started != "" {
		environment = append(environment, "BOUNDED_OBSERVATION_STARTED="+started)
	}
	if childMarker != "" {
		environment = append(environment, "BOUNDED_OBSERVATION_CHILD_MARKER="+childMarker)
	}
	return ObservationCommandSpec{Path: os.Args[0], Args: []string{"-test.run=^TestBoundedObservationRunnerHelperProcess$", "--"}, Environment: environment}
}

func helperPlanCommand(markers string) ObservationCommandSpec {
	command := helperCommand("", "", "bind")
	command.Environment = append(command.Environment, "BOUNDED_OBSERVATION_PLAN_MARKERS="+markers)
	return command
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("helper did not start: %s", path)
}

func testObservationPlans() []ObservationShardPlan {
	plans := make([]ObservationShardPlan, 8)
	for index := range plans {
		plans[index] = ObservationShardPlan{Index: index, ShardDigest: strings.Repeat(string(rune('0'+index)), 64), OperationCount: 100}
	}
	return plans
}
