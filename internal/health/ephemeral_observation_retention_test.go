package health

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupExpiredBoundedObservationRunsUsesTenMinute0700Boundary(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 7, 22, 1, 0, 0, 0, time.UTC)
	expired := filepath.Join(root, "health-run-fixture-0040")
	fresh := filepath.Join(root, "health-run-fixture-0041")
	for _, run := range []string{expired, fresh} {
		if err := os.Mkdir(run, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(run, "receipt.json"), []byte("redacted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := now.Add(-BoundedObservationRetentionTTL - time.Second)
	if err := os.Chtimes(expired, old, old); err != nil {
		t.Fatal(err)
	}
	receipt, err := CleanupExpiredBoundedObservationRuns(root, now, BoundedObservationRetentionTTL)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TerminalState != "verified" || receipt.ExpiredRunsRemoved != 1 || receipt.RetentionSeconds != 600 || !validObservationRunRedaction(receipt.Redaction) {
		t.Fatalf("unexpected cleanup receipt: %#v", receipt)
	}
	if _, err := os.Stat(expired); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired run retained: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh run removed: %v", err)
	}
}

func TestCleanupExpiredBoundedObservationRunsRejectsUnsafeRetentionTargets(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 7, 22, 1, 0, 0, 0, time.UTC)
	outside := t.TempDir()
	unsafe := filepath.Join(root, "health-run-fixture-0042")
	if err := os.Symlink(outside, unsafe); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupExpiredBoundedObservationRuns(root, now, BoundedObservationRetentionTTL); err == nil {
		t.Fatal("symlink retention target accepted")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("cleanup escaped root: %v", err)
	}
	if _, err := CleanupExpiredBoundedObservationRuns(root, now, BoundedObservationRetentionTTL-time.Second); err == nil {
		t.Fatal("non-ten-minute retention was accepted")
	}
}
