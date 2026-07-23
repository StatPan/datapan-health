package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/StatPan/datapan-health/internal/health"
)

func main() {
	manifestPath := flag.String("manifest", "testdata/registry/data-go-kr-operation-manifest.v1.json", "pinned Registry operation manifest fixture")
	releaseManifestPath := flag.String("release-manifest", "testdata/registry/release-manifest.v1.json", "pinned Registry release manifest fixture")
	receiptPath := flag.String("receipt", "config/registry/operation-manifest-receipt.json", "redacted Health manifest receipt")
	flag.Parse()
	manifest, receipt, err := health.LoadPinnedOperationManifest(*manifestPath, *releaseManifestPath, *receiptPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "health manifest verification rejected input")
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(health.BuildOperationManifestVerification(manifest, receipt), "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "health manifest verification could not encode receipt")
		os.Exit(1)
	}
	fmt.Println(string(encoded))
}
