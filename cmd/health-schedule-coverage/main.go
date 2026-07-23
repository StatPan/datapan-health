package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
)

func main() {
	manifestPath := flag.String("manifest", "testdata/registry/data-go-kr-operation-manifest.v1.json", "pinned Registry operation manifest fixture")
	releaseManifestPath := flag.String("release-manifest", "testdata/registry/release-manifest.v1.json", "pinned Registry release manifest fixture")
	receiptPath := flag.String("receipt", "config/registry/operation-manifest-receipt.json", "redacted Health manifest receipt")
	atValue := flag.String("at", "", "required RFC3339 schedule observation time")
	shards := flag.Int("shards", 64, "deterministic scheduler shard count")
	statePath := flag.String("state", "", "required private durable scheduler-authority state path")
	rebalance := flag.Bool("rebalance", false, "allow only a next-interval durable shard-count transition")
	dryRun := flag.Bool("dry-run", true, "required no-provider-call scheduling mode")
	output := flag.String("output", "", "optional coverage receipt path; stdout when empty")
	flag.Parse()
	if !*dryRun || *statePath == "" {
		fail()
	}
	at, err := time.Parse(time.RFC3339, *atValue)
	if err != nil {
		fail()
	}
	manifest, manifestReceipt, err := health.LoadPinnedOperationManifest(*manifestPath, *releaseManifestPath, *receiptPath)
	if err != nil {
		fail()
	}
	plan, queue, err := health.BuildScheduleCoveragePlan(manifest, manifestReceipt, at, *shards)
	if err != nil {
		fail()
	}
	var authority *health.ScheduleCoverageAuthority
	if *rebalance {
		authority, err = health.LoadScheduleCoverageAuthority(*statePath)
		if err == nil {
			err = authority.Rebalance(plan, queue, at)
		}
	} else {
		authority, err = health.OpenScheduleCoverageAuthority(*statePath, plan, queue)
	}
	if err != nil {
		fail()
	}
	coverage, err := authority.RecordCoverage(plan.Interval.Start)
	if err != nil {
		fail()
	}
	encoded, err := json.MarshalIndent(coverage, "", "  ")
	if err != nil {
		fail()
	}
	encoded = append(encoded, '\n')
	if *output == "" {
		_, err = os.Stdout.Write(encoded)
	} else {
		err = os.WriteFile(*output, encoded, 0o600)
	}
	if err != nil {
		fail()
	}
}

func fail() {
	fmt.Fprintln(os.Stderr, "health schedule coverage rejected input")
	os.Exit(1)
}
