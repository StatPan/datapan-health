package health

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCleanupExpiredBoundedObservationRunsKeepsRetentionEphemeralAndRedacted(t *testing.T) {
	root := t.TempDir()
	now := time.Date(2026, 7, 24, 1, 0, 0, 0, time.UTC)
	expired := filepath.Join(root, "health-run-fixture-0060")
	fresh := filepath.Join(root, "health-run-fixture-0061")
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
	if !validBoundedObservationCleanupReceipt(receipt) || receipt.ExpiredRunsRemoved != 1 {
		t.Fatalf("unexpected cleanup receipt: %#v", receipt)
	}
	if _, err := os.Stat(expired); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired run retained: %v", err)
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Fatalf("fresh run removed: %v", err)
	}
}

func TestCleanupExpiredBoundedObservationRunsRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	unsafe := filepath.Join(root, "health-run-fixture-0062")
	if err := os.Symlink(outside, unsafe); err != nil {
		t.Fatal(err)
	}
	if _, err := CleanupExpiredBoundedObservationRuns(root, time.Now().UTC(), BoundedObservationRetentionTTL); err == nil {
		t.Fatal("cleanup accepted a symlink target")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("cleanup escaped its root: %v", err)
	}
}
