package health

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadinessRequiresEveryCanaryAndFreshLoop(t *testing.T) {
	config := schedulerConfig(t, 2)
	s, err := NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), &fakeProbeRunner{}, &fakeDeliverer{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if r := s.Readiness(now); r.Ready || r.State != "startup" || r.PublicReadback != "not_checked" || r.DeploymentIdentity != "not_checked" {
		t.Fatal("startup fabricated evidence")
	}
	if err := s.ProcessDue(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	s.recordProgress(config.Canaries[0].OperationID, "delivered", "", time.Time{})
	if s.Readiness(now).Ready {
		t.Fatal("one canary concealed missing observations")
	}
	for _, c := range config.Canaries {
		s.recordProgress(c.OperationID, "delivered", "", time.Time{})
	}
	if !s.Readiness(now).Ready {
		t.Fatal("current pipeline not ready")
	}
	if s.Readiness(now.Add(6 * time.Second)).Ready {
		t.Fatal("stopped loop reported ready")
	}
	stale := now.Add(-time.Hour)
	s.mu.Lock()
	p := s.progress[config.Canaries[1].OperationID]
	p.LastDelivered = &stale
	s.progress[config.Canaries[1].OperationID] = p
	s.mu.Unlock()
	if r := s.Readiness(now); r.Ready || r.Reason != "delivery_stale" {
		t.Fatal("partial stale delivery concealed")
	}
	s.recordProgress(config.Canaries[1].OperationID, "delivered", "", time.Time{})
	if !s.Readiness(now).Ready {
		t.Fatal("delivery recovery not observed")
	}
}

func TestReadinessTracksStateFailureAndRecovery(t *testing.T) {
	config := schedulerConfig(t, 1)
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := NewScheduler(config, path, &fakeProbeRunner{}, &fakeDeliverer{})
	if err != nil {
		t.Fatal(err)
	}
	blocker := filepath.Join(t.TempDir(), "blocker")
	_ = os.WriteFile(blocker, []byte("x"), 0600)
	s.statePath = filepath.Join(blocker, "state.json")
	now := time.Now().UTC()
	if s.ProcessDue(context.Background(), now) == nil {
		t.Fatal("state fault not reproduced")
	}
	if r := s.Readiness(now); r.Ready || r.StateFailures != 1 || r.Reason != "scheduler_state_unavailable" {
		t.Fatal("state fault not exposed")
	}
	s.statePath = path
	if err := s.ProcessDue(context.Background(), now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if r := s.Readiness(now.Add(time.Second)); r.Reason == "scheduler_state_unavailable" || r.StateFailures != 1 {
		t.Fatal("state recovery erased history or retained fault")
	}
}

func TestWrongCanaryReceiptCannotAdvanceReadiness(t *testing.T) {
	config := schedulerConfig(t, 1)
	expected := config.Canaries[0]
	entry, _ := config.Entry(expected)
	other, _ := config.Entry(config.Canaries[1])
	s, err := NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), wrongCanaryRunner{entry: other}, &fakeDeliverer{})
	if err != nil {
		t.Fatal(err)
	}
	s.run(context.Background(), expected, entry)
	for _, progress := range s.Readiness(time.Now().UTC()).Canaries {
		if progress.LastAccepted != nil || progress.LastDelivered != nil || progress.OriginalObservedAt != nil {
			t.Fatal("wrong invocation generated progress evidence")
		}
		if progress.OperationID == expected.OperationID && progress.Reason != "scheduled_identity" {
			t.Fatal("wrong invocation did not degrade the scheduled canary")
		}
	}
}

func TestReadinessSeparatesDeliveryFailureFromProviderFailure(t *testing.T) {
	config := schedulerConfig(t, 1)
	config.Canaries = config.Canaries[:1]
	runner := &fakeProbeRunner{file: "../../testdata/receipts/v1/unhealthy.json"}
	delivery := &fakeDeliverer{fail: os.ErrPermission}
	s, err := NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), runner, delivery)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	_ = s.ProcessDue(context.Background(), now)
	entry, _ := config.Entry(config.Canaries[0])
	s.run(context.Background(), config.Canaries[0], entry)
	if r := s.Readiness(now); r.Ready || r.Reason != "delivery_failed" {
		t.Fatal("delivery failure reported ready")
	}
	delivery.fail = nil
	s.run(context.Background(), config.Canaries[0], entry)
	if !s.Readiness(now).Ready {
		t.Fatal("valid provider failure made Health unready")
	}
	runner.file = "missing"
	s.run(context.Background(), config.Canaries[0], entry)
	if r := s.Readiness(time.Now()); r.Ready || r.Reason != "cli_receipt_missing" {
		t.Fatal("missing CLI output reported ready")
	}
}
