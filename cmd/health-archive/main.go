package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/StatPan/datapan-health/internal/archive"
)

func main() {
	var input, output, config, canaries, card string
	var publish bool
	flag.StringVar(&input, "input", "", "local redacted receipt JSONL input")
	flag.StringVar(&output, "output", "archive", "archive output directory")
	flag.StringVar(&config, "config", "config/archive.json", "archive provenance configuration")
	flag.StringVar(&canaries, "canaries", "config/canaries.json", "public canary mapping")
	flag.StringVar(&card, "dataset-card", "dataset-card/README.md", "dataset card copied before publication")
	flag.BoolVar(&publish, "publish", false, "asynchronously publish completed archive through the hf CLI")
	flag.Parse()
	if input == "" {
		fail(errors.New("input is required"))
	}
	manifest, err := archive.Export(context.Background(), input, output, config, canaries)
	if err != nil {
		fail(err)
	}
	if publish {
		if err := copyDatasetCard(card, filepath.Join(output, "README.md")); err != nil {
			fail(err)
		}
		if err := archive.PublishWithRetry(context.Background(), archive.HFCLI{}, manifest.Provenance.DatasetRepo, output, 3, 2*time.Second); err != nil {
			if errors.Is(err, archive.ErrPublicationUnavailable) {
				fmt.Fprintln(os.Stderr, "SKIPPED: Hugging Face authenticated publication unavailable")
				return
			}
			fail(err)
		}
	}
}
func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

func copyDatasetCard(source, destination string) error {
	data, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, data, 0o644)
}
