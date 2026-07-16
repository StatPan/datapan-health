package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/StatPan/datapan-health/internal/health"
)

func main() {
	pinPath := flag.String("pin", "config/registry/diagnostic-contract-pin.json", "exact diagnostic contract pin")
	canaryPath := flag.String("canaries", "config/canaries.json", "configured canary map")
	healthHead := flag.String("health-head", "", "exact tested Health commit")
	testedRevision := flag.String("tested-revision", "", "exact CI checkout revision; defaults to Health head")
	output := flag.String("output", "", "receipt output path; stdout when empty")
	flag.Parse()

	contract, err := health.LoadDiagnosticContract(*pinPath)
	if err != nil {
		fatal(err)
	}
	canaries, err := health.LoadCanaryConfig(*canaryPath)
	if err != nil {
		fatal(err)
	}
	if *testedRevision == "" {
		*testedRevision = *healthHead
	}
	receipt, err := health.BuildDiagnosticCompatibilityReceipt(*healthHead, *testedRevision, contract, canaries)
	if err != nil {
		fatal(err)
	}
	data, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		fatal(err)
	}
	data = append(data, '\n')
	if *output == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			fatal(err)
		}
		return
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o750); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*output, data, 0o600); err != nil {
		fatal(err)
	}
}

func fatal(_ error) {
	fmt.Fprintln(os.Stderr, "health compatibility proof failed")
	os.Exit(1)
}
