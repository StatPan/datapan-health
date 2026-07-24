package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDataGoKRObservationWorkerRejectsUnpinnedInputsBeforeFixtureTransport(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*PinnedDataGoKRObservationInputs)
	}{
		{name: "catalog digest mismatch", mutate: func(inputs *PinnedDataGoKRObservationInputs) { inputs.Catalog = append(inputs.Catalog, ' ') }},
		{name: "incomplete policy coverage", mutate: func(inputs *PinnedDataGoKRObservationInputs) {
			var policy testDataGoKRPolicy
			if err := json.Unmarshal(inputs.Policy, &policy); err != nil {
				t.Fatal(err)
			}
			policy.Shards = policy.Shards[:7]
			var err error
			inputs.Policy, err = json.Marshal(policy)
			if err != nil {
				t.Fatal(err)
			}
			inputs.Registry.PolicySHA256 = testSHA256(inputs.Policy)
		}},
		{name: "unallowlisted operation", mutate: func(inputs *PinnedDataGoKRObservationInputs) {
			var catalog testDataGoKRCatalog
			if err := json.Unmarshal(inputs.Catalog, &catalog); err != nil {
				t.Fatal(err)
			}
			catalog.Operations[0].ID = 101
			var err error
			inputs.Catalog, err = json.Marshal(catalog)
			if err != nil {
				t.Fatal(err)
			}
			inputs.Registry.SourceSHA256 = testSHA256(inputs.Catalog)
			inputs.Registry.ManifestSHA256 = inputs.Registry.SourceSHA256
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			inputs := testPinnedDataGoKRInputs(t, nil)
			test.mutate(&inputs)
			transport := &recordingDataGoKRFixtureTransport{outcome: "verified"}
			worker := testDataGoKRObservationWorker(t, inputs, transport)
			if _, err := worker.Run(context.Background(), "health-run-fixture-0056"); err == nil {
				t.Fatal("invalid pinned input was accepted")
			}
			if transport.callCount() != 0 {
				t.Fatalf("fixture transport was called before input validation: %d", transport.callCount())
			}
			if _, err := os.Stat(filepath.Join(worker.OutputRoot, "health-run-fixture-0056")); !os.IsNotExist(err) {
				t.Fatalf("invalid input reached artifact boundary: %v", err)
			}
		})
	}
}

func TestDataGoKRObservationWorkerReconstructsEightPinnedShardsAndRedactsReceipts(t *testing.T) {
	inputs := testPinnedDataGoKRInputs(t, nil)
	transport := &recordingDataGoKRFixtureTransport{outcome: "verified"}
	worker := testDataGoKRObservationWorker(t, inputs, transport)

	run, err := worker.Run(context.Background(), "health-run-fixture-0057")
	if err != nil {
		t.Fatal(err)
	}
	if run.Aggregate.TerminalState != "verified" || run.Aggregate.Completeness != "complete" || len(run.Shards) != 8 {
		t.Fatalf("unexpected reconstructed run: %#v", run)
	}
	for index, shard := range run.Shards {
		if shard.Index != index || shard.TerminalState != "verified" || !shard.Completed || !shard.ReceiptAvailable || shard.ShardDigest != pinnedDataGoKRShardDigest(index, []int{index + 1}) {
			t.Fatalf("shard %d was not deterministically reconstructed: %#v", index, shard)
		}
	}
	if got := transport.operationIDs(); strings.Join(got, ",") != "1,2,3,4,5,6,7,8" {
		t.Fatalf("fixture observed an operation outside the reconstructed allowlist: %v", got)
	}
	receipt, err := os.ReadFile(filepath.Join(worker.OutputRoot, run.Run.RunID, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"serviceKey", "https://", "http://", "Authorization", "fixture-secret", "raw-body"} {
		if strings.Contains(string(receipt), forbidden) {
			t.Fatalf("receipt leaked %q: %s", forbidden, receipt)
		}
	}
}

func TestDataGoKRObservationWorkerProvesAllTypedOutcomesWithoutProviderNetwork(t *testing.T) {
	for _, outcome := range []string{"verified", "failed", "skipped", "unknown"} {
		t.Run(outcome, func(t *testing.T) {
			transport := &recordingDataGoKRFixtureTransport{outcome: outcome}
			worker := testDataGoKRObservationWorker(t, testPinnedDataGoKRInputs(t, nil), transport)
			run, err := worker.Run(context.Background(), "health-run-fixture-0058")
			if err != nil {
				t.Fatal(err)
			}
			if run.Aggregate.TerminalState != outcome || run.Aggregate.Completeness != "complete" {
				t.Fatalf("unexpected %s aggregate: %#v", outcome, run.Aggregate)
			}
			for _, shard := range run.Shards {
				if shard.TerminalState != outcome || !shard.Completed || !shard.ReceiptAvailable {
					t.Fatalf("typed outcome was not retained as a redacted receipt: %#v", shard)
				}
			}
		})
	}
}

func TestDataGoKRObservationWorkerRejectsBoundsBeforeFixtureTransport(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*DataGoKRObservationWorker)
	}{
		{name: "batch above 100", mutate: func(worker *DataGoKRObservationWorker) { worker.BatchSize = 101 }},
		{name: "parallel above two", mutate: func(worker *DataGoKRObservationWorker) { worker.MaxParallel = 3 }},
		{name: "timeout above twenty seconds", mutate: func(worker *DataGoKRObservationWorker) { worker.Timeout = 21 * time.Second }},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &recordingDataGoKRFixtureTransport{outcome: "verified"}
			worker := testDataGoKRObservationWorker(t, testPinnedDataGoKRInputs(t, nil), transport)
			test.mutate(&worker)
			if _, err := worker.Run(context.Background(), "health-run-fixture-0059"); err == nil {
				t.Fatal("out-of-bound worker was accepted")
			}
			if transport.callCount() != 0 {
				t.Fatalf("out-of-bound worker reached fixture transport: %d", transport.callCount())
			}
		})
	}
}

type testDataGoKRCatalog struct {
	Operations []testDataGoKROperation `json:"operations"`
}

type testDataGoKROperation struct {
	ID int `json:"id"`
}

type testDataGoKRPolicy struct {
	Shards []testDataGoKRShard `json:"shards"`
}

type testDataGoKRShard struct {
	Index        int   `json:"index"`
	OperationIDs []int `json:"operation_ids"`
}

func testPinnedDataGoKRInputs(t *testing.T, mutate func(*testDataGoKRCatalog)) PinnedDataGoKRObservationInputs {
	t.Helper()
	catalog := testDataGoKRCatalog{Operations: make([]testDataGoKROperation, 8)}
	policy := testDataGoKRPolicy{Shards: make([]testDataGoKRShard, 8)}
	for index := 0; index < 8; index++ {
		catalog.Operations[index] = testDataGoKROperation{ID: index + 1}
		policy.Shards[index] = testDataGoKRShard{Index: index, OperationIDs: []int{index + 1}}
	}
	if mutate != nil {
		mutate(&catalog)
	}
	catalogBytes, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	catalogDigest := testSHA256(catalogBytes)
	policyDigest := testSHA256(policyBytes)
	return PinnedDataGoKRObservationInputs{
		Registry: ObservationRunRegistry{
			SourceRevision: strings.Repeat("a", 40),
			SourceSHA256:   catalogDigest,
			ManifestSHA256: catalogDigest,
			PolicySHA256:   policyDigest,
		},
		Catalog: catalogBytes,
		Policy:  policyBytes,
	}
}

func testDataGoKRObservationWorker(t *testing.T, inputs PinnedDataGoKRObservationInputs, transport *recordingDataGoKRFixtureTransport) DataGoKRObservationWorker {
	t.Helper()
	now := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	return DataGoKRObservationWorker{
		Producer:         ObservationRunProducer{Repository: "StatPan/datapan-health", Revision: strings.Repeat("b", 40)},
		Inputs:           inputs,
		BatchSize:        100,
		MaxParallel:      2,
		Timeout:          time.Second,
		OutputRoot:       t.TempDir(),
		fixtureTransport: transport,
		Now:              func() time.Time { return now },
	}
}

type recordingDataGoKRFixtureTransport struct {
	mu      sync.Mutex
	outcome string
	ids     []int
}

func (t *recordingDataGoKRFixtureTransport) Observe(_ context.Context, operation DataGoKROperation) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ids = append(t.ids, operation.ID)
	return t.outcome
}

func (t *recordingDataGoKRFixtureTransport) callCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.ids)
}

func (t *recordingDataGoKRFixtureTransport) operationIDs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	values := append([]int(nil), t.ids...)
	sort.Ints(values)
	ids := make([]string, len(values))
	for index, id := range values {
		ids[index] = string(rune('0' + id))
	}
	return ids
}

func testSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
