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
	pinPath := flag.String("pin", "config/registry/assertion-policy-contract-pin.json", "exact Registry assertion policy pin")
	canaryPath := flag.String("canaries", "config/canaries.json", "exact Health canary configuration")
	repoRoot := flag.String("repo-root", ".", "Health repository root")
	healthHead := flag.String("health-head", "", "exact Health head commit")
	testedRevision := flag.String("tested-revision", "", "exact tested commit")
	output := flag.String("output", "out/assertion-policy-compatibility.json", "receipt output path")
	flag.Parse()

	canaries, err := health.LoadCanaryConfig(*canaryPath)
	if err != nil {
		fail()
	}
	contract, err := health.LoadAssertionPolicyContract(*pinPath, canaries)
	if err != nil {
		fail()
	}
	receipt, err := health.BuildAssertionCompatibilityReceipt(*healthHead, *testedRevision, *repoRoot, contract)
	if err != nil {
		fail()
	}
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		fail()
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		fail()
	}
	if err := os.WriteFile(*output, encoded, 0o644); err != nil {
		fail()
	}
}

func fail() {
	fmt.Fprintln(os.Stderr, "assertion policy compatibility proof failed")
	os.Exit(1)
}
