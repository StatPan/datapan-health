package health

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDataGoKRObservationWorkerUsesOnlyFixedBinaryAndRecordsIdentity(t *testing.T) {
	t.Setenv("DATAPAN_TEST_OBSERVER_CREDENTIAL", "synthetic-observer-credential")
	binary := buildDataGoKRObserver(t)
	digest, err := digestDataGoKRObserverBinary(binary)
	if err != nil {
		t.Fatal(err)
	}
	registry := ObservationRunRegistry{SourceRevision: strings.Repeat("b", 40), SourceSHA256: strings.Repeat("c", 64), ManifestSHA256: strings.Repeat("d", 64), PolicySHA256: strings.Repeat("e", 64)}
	revision := strings.Repeat("a", 40)
	verifiedAt := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	worker := DataGoKRObservationWorker{
		Producer:            ObservationRunProducer{Repository: "StatPan/datapan-health", Revision: revision},
		Registry:            registry,
		Binding:             ObservationBindingGuard{Expected: registry, BindingVerifiedAt: verifiedAt, ReferenceAt: verifiedAt.Add(time.Second), MaxAge: time.Minute},
		BatchSize:           100,
		MaxParallel:         2,
		Timeout:             time.Second,
		OutputRoot:          t.TempDir(),
		BinarySHA256:        digest,
		BinaryBuildRevision: revision,
		CredentialEnvNames:  []string{"DATAPAN_TEST_OBSERVER_CREDENTIAL"},
		Now:                 func() time.Time { return verifiedAt },
		observerPath:        binary,
	}

	run, err := worker.Run(context.Background(), "health-run-fixture-0037", testObservationPlans())
	if err != nil {
		t.Fatal(err)
	}
	if run.Aggregate.TerminalState != "unknown" || run.Aggregate.Completeness != "partial" {
		t.Fatalf("unimplemented live transport was promoted: %#v", run.Aggregate)
	}
	if run.Producer.Observer == nil || run.Producer.Observer.BinarySHA256 != digest || run.Producer.Observer.BuildRevision != revision {
		t.Fatalf("immutable observer identity missing: %#v", run.Producer)
	}
	if run.Cleanup == nil || !validBoundedObservationCleanupReceipt(*run.Cleanup) {
		t.Fatalf("redacted cleanup receipt missing: %#v", run.Cleanup)
	}
	for _, shard := range run.Shards {
		if shard.TerminalState != "unknown" || shard.ReceiptAvailable || shard.Completed {
			t.Fatalf("typed unknown was promoted: %#v", shard)
		}
	}
	aggregate, err := os.ReadFile(filepath.Join(worker.OutputRoot, run.Run.RunID, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{binary, "DATAPAN_HEALTH_OBSERVATION", "GATUS_TOKEN", "synthetic-observer-credential", "serviceKey=", "http://", "https://"} {
		if strings.Contains(string(aggregate), forbidden) {
			t.Fatalf("receipt leaked execution detail %q", forbidden)
		}
	}
}

func TestDataGoKRObservationWorkerRejectsMutableOrDisallowedEntrypointsBeforeOutput(t *testing.T) {
	binary := buildDataGoKRObserver(t)
	digest, err := digestDataGoKRObserverBinary(binary)
	if err != nil {
		t.Fatal(err)
	}
	base := testDataGoKRObservationWorker(t, binary, digest)
	for _, test := range []struct {
		name   string
		mutate func(*DataGoKRObservationWorker)
	}{
		{name: "wrong binary digest", mutate: func(w *DataGoKRObservationWorker) { w.BinarySHA256 = strings.Repeat("f", 64) }},
		{name: "wrong binary name", mutate: func(w *DataGoKRObservationWorker) { w.observerPath = filepath.Join(t.TempDir(), "arbitrary-command") }},
		{name: "build revision mismatch", mutate: func(w *DataGoKRObservationWorker) { w.BinaryBuildRevision = strings.Repeat("f", 40) }},
		{name: "reserved environment name", mutate: func(w *DataGoKRObservationWorker) {
			w.CredentialEnvNames = []string{"DATAPAN_HEALTH_OBSERVATION_SHARD_INDEX"}
		}},
		{name: "gatus environment name", mutate: func(w *DataGoKRObservationWorker) { w.CredentialEnvNames = []string{"GATUS_TOKEN"} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			worker := base
			test.mutate(&worker)
			if _, err := worker.Run(context.Background(), "health-run-fixture-0038", testObservationPlans()); err == nil {
				t.Fatal("unsafe observer entrypoint was accepted")
			}
			if _, err := os.Stat(filepath.Join(worker.OutputRoot, "health-run-fixture-0038")); !os.IsNotExist(err) {
				t.Fatalf("unsafe observer entrypoint reached output boundary: %v", err)
			}
		})
	}
}

func testDataGoKRObservationWorker(t *testing.T, binary, digest string) DataGoKRObservationWorker {
	t.Helper()
	registry := ObservationRunRegistry{SourceRevision: strings.Repeat("b", 40), SourceSHA256: strings.Repeat("c", 64), ManifestSHA256: strings.Repeat("d", 64), PolicySHA256: strings.Repeat("e", 64)}
	verifiedAt := time.Date(2026, 7, 22, 0, 0, 0, 0, time.UTC)
	return DataGoKRObservationWorker{
		Producer:            ObservationRunProducer{Repository: "StatPan/datapan-health", Revision: strings.Repeat("a", 40)},
		Registry:            registry,
		Binding:             ObservationBindingGuard{Expected: registry, BindingVerifiedAt: verifiedAt, ReferenceAt: verifiedAt.Add(time.Second), MaxAge: time.Minute},
		BatchSize:           100,
		MaxParallel:         2,
		Timeout:             time.Second,
		OutputRoot:          t.TempDir(),
		BinarySHA256:        digest,
		BinaryBuildRevision: strings.Repeat("a", 40),
		Now:                 func() time.Time { return verifiedAt },
		observerPath:        binary,
	}
}

func buildDataGoKRObserver(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), dataGoKRObserverBinaryName)
	command := exec.Command("go", "build", "-o", path, "../../cmd/data-go-kr-observer")
	command.Dir = "."
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build fixed observer: %v: %s", err, output)
	}
	return path
}
