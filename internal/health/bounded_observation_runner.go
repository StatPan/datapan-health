package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var boundedObservationRunIDPattern = regexp.MustCompile(`^health-run-[a-z0-9][a-z0-9-]{7,63}$`)

const boundedObservationReservedEnvironmentPrefix = "DATAPAN_HEALTH_OBSERVATION_"

type ObservationShardPlan struct {
	Index          int
	ShardDigest    string
	OperationCount int
}

// observationCommandSpec is the internal execution primitive. The runner,
// not a callback factory, creates the child after validating this direct
// executable boundary. Shell interpreters are forbidden. Environment entries
// cannot use the reserved typed shard-binding prefix.
type observationCommandSpec struct {
	Path        string
	Args        []string
	Environment []string
}

// ObservationBindingGuard is caller-owned authorization for a single run. It
// makes the accepted Registry binding and its freshness policy explicit before
// the runner can start a child process; the runner never chooses max age.
type ObservationBindingGuard struct {
	Expected          ObservationRunRegistry
	BindingVerifiedAt time.Time
	ReferenceAt       time.Time
	MaxAge            time.Duration
}

// boundedObservationRunner owns the low-level process, timeout, and artifact
// mechanics. It is deliberately not an operational entry point: callers must
// use DataGoKRObservationWorker, which binds this primitive to the fixed
// Health-owned data.go.kr observer contract.
type boundedObservationRunner struct {
	Producer    ObservationRunProducer
	Registry    ObservationRunRegistry
	BatchSize   int
	MaxParallel int
	Timeout     time.Duration
	OutputRoot  string
	command     observationCommandSpec
	Binding     ObservationBindingGuard
	Cleanup     *BoundedObservationCleanupReceipt
	Now         func() time.Time
}

func (r boundedObservationRunner) Run(ctx context.Context, runID string, plans []ObservationShardPlan) (BoundedObservationRun, error) {
	if err := r.validate(runID, plans); err != nil {
		return BoundedObservationRun{}, err
	}
	runRoot, err := prepareBoundedObservationRunRoot(r.OutputRoot, runID)
	if err != nil {
		return BoundedObservationRun{}, errors.New("bounded observation output is unsafe")
	}
	now := r.Now
	if now == nil {
		now = time.Now
	}
	started := now().UTC()
	plans = append([]ObservationShardPlan(nil), plans...)
	sort.Slice(plans, func(i, j int) bool { return plans[i].Index < plans[j].Index })

	jobs := make(chan ObservationShardPlan, len(plans))
	results := make(chan ObservationRunShard, len(plans))
	for _, plan := range plans {
		jobs <- plan
	}
	close(jobs)

	var workers sync.WaitGroup
	for range r.MaxParallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for plan := range jobs {
				results <- r.observe(ctx, runRoot, plan, now)
			}
		}()
	}
	workers.Wait()
	close(results)

	shards := make([]ObservationRunShard, 0, len(plans))
	for shard := range results {
		shards = append(shards, shard)
	}
	sort.Slice(shards, func(i, j int) bool { return shards[i].Index < shards[j].Index })
	completed := now().UTC()
	run := BoundedObservationRun{
		SchemaVersion: BoundedObservationRunSchemaVersion,
		Producer:      r.Producer,
		Registry:      r.Registry,
		Run:           ObservationRunScope{RunID: runID, StartedAt: started, CompletedAt: completed, ShardCount: 8, BatchSize: r.BatchSize, MaxParallel: r.MaxParallel, TimeoutMS: r.Timeout.Milliseconds()},
		Shards:        shards,
		Redaction:     completeObservationRunRedaction(),
		Cleanup:       r.Cleanup,
	}
	states := make([]string, 0, len(shards))
	partial, timedOut := false, false
	for _, shard := range shards {
		states = append(states, shard.TerminalState)
		partial = partial || !shard.ReceiptAvailable
		timedOut = timedOut || shard.TimedOut
	}
	run.Aggregate = ObservationRunAggregate{TerminalState: aggregateObservationRunState(states, partial), Completeness: "complete", TimedOut: timedOut}
	if partial {
		run.Aggregate.Completeness = "partial"
	}
	if err := run.Validate(); err != nil {
		return BoundedObservationRun{}, errors.New("bounded observation runner produced invalid receipt")
	}
	encoded, err := json.Marshal(run)
	if err != nil {
		return BoundedObservationRun{}, errors.New("bounded observation runner could not encode receipt")
	}
	if _, err := publishBoundedObservationFile(runRoot, "receipt.json", append(encoded, '\n')); err != nil {
		return BoundedObservationRun{}, errors.New("bounded observation runner could not publish receipt")
	}
	return run, nil
}

func (r boundedObservationRunner) observe(parent context.Context, root string, plan ObservationShardPlan, now func() time.Time) ObservationRunShard {
	shard := ObservationRunShard{Index: plan.Index, ShardDigest: plan.ShardDigest, Scope: ObservationRunShardScope{Provider: "data_go_kr", Subject: "runtime_freshness_rotating_shard"}, ManifestSHA256: r.Registry.ManifestSHA256, PolicySHA256: r.Registry.PolicySHA256, TerminalState: "unknown", Redaction: completeObservationRunRedaction()}
	if parent.Err() != nil {
		return shard
	}
	command := exec.Command(r.command.Path, r.command.Args...)
	command.Env = append(append([]string(nil), r.command.Environment...), typedObservationPlanEnvironment(plan)...)
	if err := configureBoundedObservationProcess(command); err != nil {
		shard.TerminalState = "failed"
		return shard
	}
	command.Stdout, command.Stderr, command.Stdin = io.Discard, io.Discard, nil
	if err := command.Start(); err != nil {
		shard.TerminalState = "failed"
		return shard
	}
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	ctx, cancel := context.WithTimeout(parent, r.Timeout)
	defer cancel()
	var waitErr error
	select {
	case waitErr = <-wait:
	case <-ctx.Done():
		// Process.Kill and the subsequent Wait make timeout/cancellation a
		// hard process boundary, rather than trusting an in-process callback.
		terminateBoundedObservationProcess(command)
		<-wait
		shard.TimedOut = errors.Is(ctx.Err(), context.DeadlineExceeded)
		return shard
	}
	state := "verified"
	if waitErr != nil {
		switch {
		case command.ProcessState != nil && command.ProcessState.ExitCode() == 75:
			state = "skipped"
		case command.ProcessState != nil && command.ProcessState.ExitCode() == 76:
			// Unknown is deliberately non-admittable: a Health-owned observer
			// could not establish a typed outcome, so no shard receipt exists.
			return shard
		default:
			shard.TerminalState = "failed"
			return shard
		}
	}
	if state == "skipped" {
		// A deterministic reserved exit code carries only the typed skipped
		// state; no child error text is retained or emitted.
	}
	artifact := canonicalObservationShardArtifact(plan.Index, state)
	digest, err := writeBoundedObservationArtifact(root, plan.Index, artifact)
	if err != nil {
		return shard
	}
	shard.TerminalState, shard.Completed, shard.ReceiptAvailable = state, true, true
	shard.ReceiptPath, shard.ReceiptSHA256, shard.ObservedAt = fmt.Sprintf("shards/%d/receipt.json", plan.Index), digest, now().UTC()
	return shard
}

func (r boundedObservationRunner) validate(runID string, plans []ObservationShardPlan) error {
	if r.OutputRoot == "" || !boundedObservationRunIDPattern.MatchString(runID) || !commitPattern.MatchString(r.Producer.Revision) || r.Producer.Repository != "StatPan/datapan-health" || !validObservationRunRegistry(r.Registry) || !validObservationBindingGuard(r.Registry, r.Binding) || !supportsBoundedObservationProcess() || r.BatchSize < 1 || r.BatchSize > 100 || r.MaxParallel < 1 || r.MaxParallel > 2 || r.Timeout < time.Second || r.Timeout > 20*time.Second || len(plans) != 8 || !validBoundedObservationCommand(r.command) {
		return errors.New("bounded observation runner input is invalid")
	}
	seen := map[int]bool{}
	for _, plan := range plans {
		if plan.Index < 0 || plan.Index >= 8 || seen[plan.Index] || plan.OperationCount < 1 || plan.OperationCount > r.BatchSize || !sha256Pattern.MatchString(plan.ShardDigest) {
			return errors.New("bounded observation runner input is invalid")
		}
		seen[plan.Index] = true
	}
	return nil
}

func validObservationBindingGuard(actual ObservationRunRegistry, guard ObservationBindingGuard) bool {
	if !validObservationRunRegistry(guard.Expected) || guard.BindingVerifiedAt.IsZero() || guard.ReferenceAt.IsZero() || guard.MaxAge <= 0 {
		return false
	}
	if actual.SourceRevision != guard.Expected.SourceRevision || actual.SourceSHA256 != guard.Expected.SourceSHA256 || actual.ManifestSHA256 != guard.Expected.ManifestSHA256 || actual.PolicySHA256 != guard.Expected.PolicySHA256 {
		return false
	}
	reference := guard.ReferenceAt.UTC()
	verified := guard.BindingVerifiedAt.UTC()
	return !verified.After(reference) && reference.Sub(verified) <= guard.MaxAge
}

func validBoundedObservationCommand(command observationCommandSpec) bool {
	if !filepath.IsAbs(command.Path) {
		return false
	}
	info, err := os.Lstat(command.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode()&0o111 == 0 {
		return false
	}
	switch filepath.Base(command.Path) {
	case "sh", "bash", "dash", "zsh", "fish":
		return false
	}
	for _, value := range command.Args {
		if strings.Contains(value, "\x00") {
			return false
		}
	}
	seenEnvironment := make(map[string]bool, len(command.Environment))
	for _, value := range command.Environment {
		name, _, found := strings.Cut(value, "=")
		if !found || name == "" || strings.Contains(value, "\x00") || strings.HasPrefix(name, boundedObservationReservedEnvironmentPrefix) || seenEnvironment[name] {
			return false
		}
		seenEnvironment[name] = true
	}
	return true
}

func typedObservationPlanEnvironment(plan ObservationShardPlan) []string {
	return []string{
		boundedObservationReservedEnvironmentPrefix + "SHARD_INDEX=" + strconv.Itoa(plan.Index),
		boundedObservationReservedEnvironmentPrefix + "SHARD_DIGEST=" + plan.ShardDigest,
		boundedObservationReservedEnvironmentPrefix + "OPERATION_COUNT=" + strconv.Itoa(plan.OperationCount),
	}
}

func completeObservationRunRedaction() ObservationRunRedaction {
	return ObservationRunRedaction{SecretValuesRemoved: true, SecretHashesRemoved: true, AuthorizationHeadersRemoved: true, CredentialBearingURLsRemoved: true, RawProviderTextRemoved: true, RawProviderURLsRemoved: true, ResponseBodiesRemoved: true, ResponseRowsRemoved: true, UserIdentityRemoved: true}
}

func canonicalObservationShardArtifact(index int, state string) []byte {
	data, _ := json.Marshal(struct {
		SchemaVersion string `json:"schema_version"`
		ShardIndex    int    `json:"shard_index"`
		TerminalState string `json:"terminal_state"`
		Redaction     string `json:"redaction"`
	}{"datapan.health-bounded-observation-shard.v1", index, state, "complete"})
	return append(data, '\n')
}

func prepareBoundedObservationRunRoot(root, runID string) (string, error) {
	if filepath.IsAbs(runID) || filepath.Base(runID) != runID {
		return "", os.ErrPermission
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", os.ErrPermission
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	runRoot := filepath.Join(resolved, runID)
	if err := os.Mkdir(runRoot, 0o700); err != nil {
		return "", err
	}
	return runRoot, nil
}

func writeBoundedObservationArtifact(root string, index int, data []byte) (string, error) {
	shardsRoot := filepath.Join(root, "shards")
	if err := os.Mkdir(shardsRoot, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	if info, err := os.Lstat(shardsRoot); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", os.ErrPermission
	}
	directory := filepath.Join(shardsRoot, fmt.Sprint(index))
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", os.ErrPermission
	}
	return publishBoundedObservationFile(directory, "receipt.json", data)
}

// publishBoundedObservationFile durably publishes a single receipt by an
// atomic no-replace link. A collision, symlink, partial write, or directory
// sync failure is an error; callers must never promote it to success.
func publishBoundedObservationFile(directory, filename string, data []byte) (string, error) {
	if filename != "receipt.json" {
		return "", os.ErrPermission
	}
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", os.ErrPermission
	}
	target := filepath.Join(directory, filename)
	if _, err := os.Lstat(target); err == nil || !errors.Is(err, os.ErrNotExist) {
		return "", os.ErrExist
	}
	temporary, err := os.CreateTemp(directory, ".receipt-*")
	if err != nil {
		return "", err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	// Link is an atomic no-replace publish on one filesystem. Unlike Rename it
	// cannot overwrite a receipt created by a concurrent/colliding run.
	if err := os.Link(name, target); err != nil {
		return "", err
	}
	if err := syncBoundedObservationDirectory(directory); err != nil {
		return "", err
	}
	if err := os.Remove(name); err != nil {
		return "", err
	}
	if err := syncBoundedObservationDirectory(directory); err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func syncBoundedObservationDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
