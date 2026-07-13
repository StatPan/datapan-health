package archive

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

var ErrPublicationUnavailable = errors.New("Hugging Face publication unavailable")

// Publisher is deliberately batch-only. Export always completes before a
// publisher is called; callers must treat publication failure as non-live work.
type Publisher interface {
	Publish(context.Context, string, string) error
}

type HFCLI struct{ Command string }

func (p HFCLI) Publish(ctx context.Context, datasetRepo, archiveDir string) error {
	if os.Getenv("HF_TOKEN") == "" {
		return ErrPublicationUnavailable
	}
	command := p.Command
	if command == "" {
		command = "hf"
	}
	if _, err := exec.LookPath(command); err != nil {
		return ErrPublicationUnavailable
	}
	stage, err := stagePublication(archiveDir)
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	// hf upload creates the dataset repository when the authenticated account has
	// permission; it receives the token through the environment, never argv/logs.
	cmd := exec.CommandContext(ctx, command, "upload", datasetRepo, stage, ".", "--repo-type", "dataset", "--commit-message", "Publish minimized Datapan health archive")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

// stagePublication deliberately excludes checkpoints and partial files. The
// public dataset consists of Parquet data plus its safe manifest and card.
func stagePublication(root string) (string, error) {
	stage, err := os.MkdirTemp("", "datapan-health-publish-*")
	if err != nil {
		return "", err
	}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == "checkpoints" {
				return filepath.SkipDir
			}
			return nil
		}
		name := entry.Name()
		if name != "manifest.json" && name != "README.md" && !strings.HasSuffix(name, ".parquet") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(stage, relative)
		if err := os.MkdirAll(filepath.Dir(destination), 0o750); err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(destination, data, 0o640)
	})
	if err != nil {
		os.RemoveAll(stage)
		return "", err
	}
	return stage, nil
}

// PublishWithRetry retries only the asynchronous upload. Archive file names and
// contents are deterministic, so an interrupted upload can safely be retried.
// It intentionally does not call the runner or Gatus.
func PublishWithRetry(ctx context.Context, publisher Publisher, datasetRepo, archiveDir string, attempts int, delay time.Duration) error {
	if attempts < 1 {
		return errors.New("publication attempts must be positive")
	}
	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		last = publisher.Publish(ctx, datasetRepo, archiveDir)
		if last == nil || errors.Is(last, ErrPublicationUnavailable) {
			return last
		}
		if attempt+1 < attempts {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return last
}
