package health

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const BoundedObservationRetentionTTL = 10 * time.Minute

// BoundedObservationCleanupReceipt is deliberately path-free and contains no
// provider or credential material. It is the only durable cleanup evidence.
type BoundedObservationCleanupReceipt struct {
	SchemaVersion      string                  `json:"schema_version"`
	CleanedAt          time.Time               `json:"cleaned_at"`
	RetentionSeconds   int64                   `json:"retention_seconds"`
	ExpiredRunsRemoved int                     `json:"expired_runs_removed"`
	TerminalState      string                  `json:"terminal_state"`
	Redaction          ObservationRunRedaction `json:"redaction"`
}

func validBoundedObservationCleanupReceipt(receipt BoundedObservationCleanupReceipt) bool {
	return receipt.SchemaVersion == "datapan.health-bounded-observation-cleanup.v1" && !receipt.CleanedAt.IsZero() && receipt.RetentionSeconds == int64(BoundedObservationRetentionTTL.Seconds()) && receipt.ExpiredRunsRemoved >= 0 && receipt.TerminalState == "verified" && validObservationRunRedaction(receipt.Redaction)
}

func CleanupExpiredBoundedObservationRuns(root string, reference time.Time, ttl time.Duration) (BoundedObservationCleanupReceipt, error) {
	receipt := BoundedObservationCleanupReceipt{SchemaVersion: "datapan.health-bounded-observation-cleanup.v1", CleanedAt: reference.UTC(), RetentionSeconds: int64(ttl.Seconds()), TerminalState: "failed", Redaction: completeObservationRunRedaction()}
	if reference.IsZero() || ttl != BoundedObservationRetentionTTL || !validBoundedObservationRetentionRoot(root) {
		return receipt, errors.New("bounded observation cleanup input is invalid")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return receipt, errors.New("bounded observation cleanup input is invalid")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if !boundedObservationRunIDPattern.MatchString(entry.Name()) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
			return receipt, errors.New("bounded observation cleanup root is unsafe")
		}
		if info.ModTime().UTC().Add(ttl).After(reference.UTC()) {
			continue
		}
		if err := removeBoundedObservationRunTree(path); err != nil {
			return receipt, errors.New("bounded observation cleanup root is unsafe")
		}
		receipt.ExpiredRunsRemoved++
	}
	receipt.TerminalState = "verified"
	return receipt, nil
}

func validBoundedObservationRetentionRoot(root string) bool {
	info, err := os.Lstat(root)
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}

func removeBoundedObservationRunTree(path string) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		child := filepath.Join(path, entry.Name())
		info, err := os.Lstat(child)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return os.ErrPermission
		}
		if info.IsDir() {
			if err := removeBoundedObservationRunTree(child); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return os.ErrPermission
		}
		if err := os.Remove(child); err != nil {
			return err
		}
	}
	return os.Remove(path)
}
