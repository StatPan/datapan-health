package health

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

const maxPinnedDataGoKRInputBytes = 64 * 1024

// PinnedDataGoKRObservationInputs is the only source of observation scope.
// Registry binds both opaque byte streams by digest; callers cannot supply
// operations, endpoints, commands, or arguments to Run.
type PinnedDataGoKRObservationInputs struct {
	Registry ObservationRunRegistry
	Catalog  []byte
	Policy   []byte
}

// DataGoKROperation deliberately carries only the allowlisted numerical
// operation identity. A fixture transport never receives a provider URL,
// credential, request, or response body.
type DataGoKROperation struct {
	ID int
}

type dataGoKRFixtureTransport interface {
	Observe(context.Context, DataGoKROperation) string
}

// DataGoKRObservationWorker is an offline-only Health-owned worker. Its
// transport seam is intentionally private: production code cannot inject a
// provider client through this API, and this task does not add one.
type DataGoKRObservationWorker struct {
	Producer    ObservationRunProducer
	Inputs      PinnedDataGoKRObservationInputs
	BatchSize   int
	MaxParallel int
	Timeout     time.Duration
	OutputRoot  string
	Now         func() time.Time

	fixtureTransport dataGoKRFixtureTransport
}

type pinnedDataGoKRCatalog struct {
	Operations []pinnedDataGoKROperation `json:"operations"`
}

type pinnedDataGoKROperation struct {
	ID int `json:"id"`
}

type pinnedDataGoKRPolicy struct {
	Shards []pinnedDataGoKRPolicyShard `json:"shards"`
}

type pinnedDataGoKRPolicyShard struct {
	Index        int   `json:"index"`
	OperationIDs []int `json:"operation_ids"`
}

type reconstructedDataGoKRShard struct {
	plan       ObservationShardPlan
	operations []DataGoKROperation
}

func (w DataGoKRObservationWorker) Run(ctx context.Context, runID string) (BoundedObservationRun, error) {
	if !validDataGoKRObservationWorker(w) {
		return BoundedObservationRun{}, errors.New("data.go.kr observation worker input is invalid")
	}
	shards, err := reconstructPinnedDataGoKRShards(w.Inputs, w.BatchSize)
	if err != nil {
		return BoundedObservationRun{}, errors.New("data.go.kr observation inputs are invalid")
	}
	now := w.Now
	if now == nil {
		now = time.Now
	}
	cleanup, err := CleanupExpiredBoundedObservationRuns(w.OutputRoot, now().UTC(), BoundedObservationRetentionTTL)
	if err != nil {
		return BoundedObservationRun{}, errors.New("data.go.kr observation cleanup is unsafe")
	}
	runRoot, err := prepareBoundedObservationRunRoot(w.OutputRoot, runID)
	if err != nil {
		return BoundedObservationRun{}, errors.New("data.go.kr observation output is unsafe")
	}
	started := now().UTC()
	jobs := make(chan reconstructedDataGoKRShard, len(shards))
	results := make(chan ObservationRunShard, len(shards))
	for _, shard := range shards {
		jobs <- shard
	}
	close(jobs)

	var workers sync.WaitGroup
	for range w.MaxParallel {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for shard := range jobs {
				results <- w.observeFixtureShard(ctx, runRoot, shard, now)
			}
		}()
	}
	workers.Wait()
	close(results)

	runShards := make([]ObservationRunShard, 0, len(shards))
	for shard := range results {
		runShards = append(runShards, shard)
	}
	sort.Slice(runShards, func(i, j int) bool { return runShards[i].Index < runShards[j].Index })
	completed := now().UTC()
	states := make([]string, 0, len(runShards))
	for _, shard := range runShards {
		states = append(states, shard.TerminalState)
	}
	run := BoundedObservationRun{
		SchemaVersion: BoundedObservationRunSchemaVersion,
		Producer:      w.Producer,
		Registry:      w.Inputs.Registry,
		Run:           ObservationRunScope{RunID: runID, StartedAt: started, CompletedAt: completed, ShardCount: 8, BatchSize: w.BatchSize, MaxParallel: w.MaxParallel, TimeoutMS: w.Timeout.Milliseconds()},
		Shards:        runShards,
		Aggregate:     ObservationRunAggregate{TerminalState: aggregateObservationRunState(states, false), Completeness: "complete"},
		Redaction:     completeObservationRunRedaction(),
		Cleanup:       &cleanup,
	}
	if err := run.Validate(); err != nil {
		return BoundedObservationRun{}, errors.New("data.go.kr observation worker produced invalid receipt")
	}
	encoded, err := json.Marshal(run)
	if err != nil {
		return BoundedObservationRun{}, errors.New("data.go.kr observation worker could not encode receipt")
	}
	if _, err := publishBoundedObservationFile(runRoot, "receipt.json", append(encoded, '\n')); err != nil {
		return BoundedObservationRun{}, errors.New("data.go.kr observation worker could not publish receipt")
	}
	return run, nil
}

func (w DataGoKRObservationWorker) observeFixtureShard(parent context.Context, root string, shard reconstructedDataGoKRShard, now func() time.Time) ObservationRunShard {
	receipt := ObservationRunShard{
		Index:          shard.plan.Index,
		ShardDigest:    shard.plan.ShardDigest,
		Scope:          ObservationRunShardScope{Provider: "data_go_kr", Subject: "runtime_freshness_rotating_shard"},
		ManifestSHA256: w.Inputs.Registry.ManifestSHA256,
		PolicySHA256:   w.Inputs.Registry.PolicySHA256,
		Redaction:      completeObservationRunRedaction(),
	}
	states := make([]string, 0, len(shard.operations))
	for _, operation := range shard.operations {
		states = append(states, observePinnedDataGoKROperation(parent, w.Timeout, w.fixtureTransport, operation))
	}
	state := aggregateFixtureOperationStates(states)
	artifact := canonicalObservationShardArtifact(shard.plan.Index, state)
	digest, err := writeBoundedObservationArtifact(root, shard.plan.Index, artifact)
	if err != nil {
		receipt.TerminalState = "unknown"
		return receipt
	}
	receipt.TerminalState = state
	receipt.Completed = true
	receipt.ReceiptAvailable = true
	receipt.ReceiptPath = fmt.Sprintf("shards/%d/receipt.json", shard.plan.Index)
	receipt.ReceiptSHA256 = digest
	receipt.ObservedAt = now().UTC()
	return receipt
}

func observePinnedDataGoKROperation(parent context.Context, timeout time.Duration, transport dataGoKRFixtureTransport, operation DataGoKROperation) string {
	operationContext, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	result := make(chan string, 1)
	go func() { result <- transport.Observe(operationContext, operation) }()
	select {
	case state := <-result:
		if validObservationRunState(state) {
			return state
		}
	case <-operationContext.Done():
	}
	return "unknown"
}

func validDataGoKRObservationWorker(w DataGoKRObservationWorker) bool {
	return w.Producer.Repository == "StatPan/datapan-health" && commitPattern.MatchString(w.Producer.Revision) && validObservationRunRegistry(w.Inputs.Registry) && w.fixtureTransport != nil && w.OutputRoot != "" && w.BatchSize >= 1 && w.BatchSize <= 100 && w.MaxParallel >= 1 && w.MaxParallel <= 2 && w.Timeout >= time.Second && w.Timeout <= 20*time.Second
}

func reconstructPinnedDataGoKRShards(inputs PinnedDataGoKRObservationInputs, batchSize int) ([]reconstructedDataGoKRShard, error) {
	if !validObservationRunRegistry(inputs.Registry) || len(inputs.Catalog) == 0 || len(inputs.Catalog) > maxPinnedDataGoKRInputBytes || len(inputs.Policy) == 0 || len(inputs.Policy) > maxPinnedDataGoKRInputBytes || digestPinnedDataGoKRBytes(inputs.Catalog) != inputs.Registry.SourceSHA256 || digestPinnedDataGoKRBytes(inputs.Catalog) != inputs.Registry.ManifestSHA256 || digestPinnedDataGoKRBytes(inputs.Policy) != inputs.Registry.PolicySHA256 {
		return nil, errors.New("pinned input digest mismatch")
	}
	var catalog pinnedDataGoKRCatalog
	var policy pinnedDataGoKRPolicy
	if !decodePinnedDataGoKRJSON(inputs.Catalog, &catalog) || !decodePinnedDataGoKRJSON(inputs.Policy, &policy) || len(policy.Shards) != 8 {
		return nil, errors.New("pinned input shape is invalid")
	}
	allowed := make(map[int]bool, len(catalog.Operations))
	for _, operation := range catalog.Operations {
		if operation.ID < 1 || operation.ID > 100 || allowed[operation.ID] {
			return nil, errors.New("pinned catalog allowlist is invalid")
		}
		allowed[operation.ID] = true
	}
	seenShards := make(map[int]bool, len(policy.Shards))
	seenOperations := make(map[int]bool, len(catalog.Operations))
	result := make([]reconstructedDataGoKRShard, 8)
	for _, shard := range policy.Shards {
		if shard.Index < 0 || shard.Index >= 8 || seenShards[shard.Index] || len(shard.OperationIDs) < 1 || len(shard.OperationIDs) > batchSize {
			return nil, errors.New("pinned shard policy is invalid")
		}
		seenShards[shard.Index] = true
		ids := append([]int(nil), shard.OperationIDs...)
		sort.Ints(ids)
		operations := make([]DataGoKROperation, 0, len(ids))
		for index, id := range ids {
			if id < 1 || id > 100 || !allowed[id] || seenOperations[id] || (index > 0 && ids[index-1] == id) {
				return nil, errors.New("pinned shard operation is invalid")
			}
			seenOperations[id] = true
			operations = append(operations, DataGoKROperation{ID: id})
		}
		result[shard.Index] = reconstructedDataGoKRShard{plan: ObservationShardPlan{Index: shard.Index, ShardDigest: pinnedDataGoKRShardDigest(shard.Index, ids), OperationCount: len(ids)}, operations: operations}
	}
	if len(seenShards) != 8 || len(seenOperations) != len(allowed) {
		return nil, errors.New("pinned inputs do not cover exactly eight shards")
	}
	return result, nil
}

func decodePinnedDataGoKRJSON(data []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return false
	}
	return decoder.Decode(&struct{}{}) == io.EOF
}

func pinnedDataGoKRShardDigest(index int, operationIDs []int) string {
	data, _ := json.Marshal(struct {
		Index        int   `json:"index"`
		OperationIDs []int `json:"operation_ids"`
	}{Index: index, OperationIDs: operationIDs})
	return digestPinnedDataGoKRBytes(data)
}

func digestPinnedDataGoKRBytes(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func aggregateFixtureOperationStates(states []string) string {
	for _, state := range states {
		if state == "unknown" {
			return "unknown"
		}
	}
	for _, state := range states {
		if state == "failed" {
			return "failed"
		}
	}
	for _, state := range states {
		if state == "verified" {
			return "verified"
		}
	}
	return "skipped"
}
