package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
)

func main() {
	rulePath := flag.String("rule", "config/correlation/provider-outage.v1.json", "exact correlation rule")
	canaryPath := flag.String("canaries", "config/canaries.json", "exact Health canary catalog")
	diagnosticPin := flag.String("diagnostic-pin", "config/registry/diagnostic-contract-pin.json", "exact diagnostic contract")
	assertionPin := flag.String("assertion-pin", "config/registry/assertion-policy-contract-pin.json", "exact assertion policy contract")
	replayPath := flag.String("correlation-replay", "", "optional redacted correlation replay")
	assertionsPath := flag.String("assertions", "", "optional exact assertion evaluation request array")
	generatedAtValue := flag.String("generated-at", "", "RFC3339 projection time; defaults to replay assessed_at")
	output := flag.String("output", "out/public-diagnosis-snapshot.json", "atomic snapshot output")
	receiptOutput := flag.String("receipt-output", "out/diagnosis-projector-receipt.json", "projection receipt output")
	healthHead := flag.String("health-head", "", "exact Health head commit")
	testedRevision := flag.String("tested-revision", "", "exact tested commit")
	repoRoot := flag.String("repo-root", ".", "Health repository root")
	flag.Parse()

	canaries, err := health.LoadCanaryConfig(*canaryPath)
	if err != nil {
		fail()
	}
	diagnostic, err := health.LoadDiagnosticContract(*diagnosticPin)
	if err != nil {
		fail()
	}
	assertionContract, err := health.LoadAssertionPolicyContract(*assertionPin, canaries)
	if err != nil {
		fail()
	}
	var correlations []health.CorrelationReceipt
	var generatedAt time.Time
	if *replayPath != "" {
		rule, err := health.LoadCorrelationRule(*rulePath)
		if err != nil {
			fail()
		}
		file, err := os.Open(*replayPath)
		if err != nil {
			fail()
		}
		replay, err := health.DecodeCorrelationReplay(file)
		_ = file.Close()
		if err != nil {
			fail()
		}
		correlation, err := health.CorrelateProviderOutage(rule, canaries, replay)
		if err != nil {
			fail()
		}
		correlations = append(correlations, correlation)
		generatedAt = replay.AssessedAt
	}
	if *generatedAtValue != "" {
		generatedAt, err = time.Parse(time.RFC3339, *generatedAtValue)
		if err != nil {
			fail()
		}
	}
	assertions, err := readAssertions(*assertionsPath)
	if err != nil {
		fail()
	}
	snapshot, receipt, err := health.ProjectDiagnosisSnapshot(generatedAt, correlations, assertions, canaries, diagnostic, assertionContract)
	if err != nil {
		fail()
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		fail()
	}
	if err := health.BindDiagnosisProjectionEvidence(&receipt, *healthHead, *testedRevision, *repoRoot); err != nil {
		fail()
	}
	if err := health.WriteDiagnosisSnapshotAtomic(*output, snapshot, assertionContract); err != nil {
		fail()
	}
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		fail()
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*receiptOutput, encoded, 0o644); err != nil {
		fail()
	}
}

func readAssertions(path string) ([]health.AssertionEvaluationRequest, error) {
	if path == "" {
		return []health.AssertionEvaluationRequest{}, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 1024*1024+1))
	if err != nil || len(raw) > 1024*1024 {
		return nil, fmt.Errorf("assertions input unavailable")
	}
	var assertions []health.AssertionEvaluationRequest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&assertions); err != nil || len(assertions) > 1000 {
		return nil, fmt.Errorf("assertions input invalid")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, fmt.Errorf("assertions input invalid")
	}
	return assertions, nil
}

func fail() {
	fmt.Fprintln(os.Stderr, "health diagnosis projection failed")
	os.Exit(1)
}
