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
	snapshotPath := flag.String("snapshot", "out/public-diagnosis-snapshot.json", "reviewed diagnosis snapshot")
	canaryPath := flag.String("canaries", "config/canaries.json", "exact Health canary catalog")
	assertionPin := flag.String("assertion-pin", "config/registry/assertion-policy-contract-pin.json", "exact assertion policy contract")
	atValue := flag.String("at", "", "required RFC3339 evaluation time")
	flag.Parse()
	at, err := time.Parse(time.RFC3339, *atValue)
	if err != nil {
		fail()
	}
	canaries, err := health.LoadCanaryConfig(*canaryPath)
	if err != nil {
		fail()
	}
	contract, err := health.LoadAssertionPolicyContract(*assertionPin, canaries)
	if err != nil {
		fail()
	}
	snapshot, counts, err := health.ReadDiagnosisSnapshot(*snapshotPath, at, contract)
	if err != nil {
		fail()
	}
	result := struct {
		SchemaVersion   string                 `json:"schema_version"`
		SnapshotVersion string                 `json:"snapshot_version"`
		Status          string                 `json:"status"`
		Counts          health.DiagnosisCounts `json:"counts"`
	}{"datapan.health-diagnosis-doctor.v1", snapshot.SchemaVersion, "accepted", counts}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fail()
	}
}

func fail() {
	fmt.Fprintln(os.Stderr, "health diagnosis doctor rejected snapshot")
	os.Exit(1)
}
