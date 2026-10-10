package health

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/internal/runtimebundle"
)

func testOperationPlanProbeExpectation(now time.Time) OperationPlanProbeExpectation {
	return OperationPlanProbeExpectation{
		AttemptID: "817c7c1d-f844-4b79-bdad-891a273c1a4e", CLIVersion: "v0.1.41", CLIBinarySHA256: strings.Repeat("a", 64),
		DatasetID: "StatPan/datapan-registry", Distribution: "huggingface_dataset", DistributionDatasetRevision: strings.Repeat("c", 40),
		RegistrySHA256: strings.Repeat("d", 64), RegistryRevision: strings.Repeat("b", 40), ReleaseManifestSHA256: strings.Repeat("e", 64),
		OperationManifestSHA256: strings.Repeat("f", 64), ProviderIndexSHA256: strings.Repeat("1", 64), PlanSchemaSHA256: strings.Repeat("2", 64),
		IndexSHA256: strings.Repeat("3", 64), ShardSHA256: strings.Repeat("4", 64), SourceIdentitySetSHA256: strings.Repeat("5", 64),
		SourceID: "data_go_kr", OperationID: strings.Repeat("6", 64), Provider: "data.go.kr", AdapterID: "data-go-kr", Protocol: "REST", ResponseAssertionKind: "json_contract",
		RequestTimeout: 5 * time.Second, StartedAt: now.UTC(),
	}
}

func testOperationPlanProbeReceipt(expected OperationPlanProbeExpectation, observedAt time.Time, outcome, reason, assertionStatus string, requestStarted, responseObserved bool, requestBudget, httpStatus int) operationPlanProbeReceipt {
	observed := ""
	if !observedAt.IsZero() {
		observed = observedAt.UTC().Format(time.RFC3339Nano)
	}
	return operationPlanProbeReceipt{
		SchemaVersion: OperationPlanProbeReceiptSchemaVersion, AttemptID: expected.AttemptID,
		CLI: operationPlanProbeCLI{Version: expected.CLIVersion, BinarySHA256: expected.CLIBinarySHA256},
		Registry: operationPlanProbeRegistry{
			DatasetID: expected.DatasetID, RegistryRevision: expected.RegistryRevision, Distribution: expected.Distribution,
			DistributionDatasetRevision: expected.DistributionDatasetRevision, RegistrySHA256: expected.RegistrySHA256,
			ManifestSHA256: expected.ReleaseManifestSHA256, OperationManifestSHA256: expected.OperationManifestSHA256,
			ProviderIndexSHA256: expected.ProviderIndexSHA256, PlanSchemaSHA256: expected.PlanSchemaSHA256,
			IndexSHA256: expected.IndexSHA256, ShardSHA256: expected.ShardSHA256,
			SourceIdentitySetSHA256: expected.SourceIdentitySetSHA256,
		},
		Operation:   operationPlanProbeOperation{OperationID: expected.OperationID, SourceID: expected.SourceID, Provider: expected.Provider, AdapterID: expected.AdapterID, Protocol: expected.Protocol},
		Execution:   operationPlanProbeExecution{RequestStarted: requestStarted, RequestBudget: requestBudget, TimeoutMS: expected.RequestTimeout.Milliseconds(), DurationMS: 1},
		Observation: operationPlanProbeObservation{ResponseObserved: responseObserved, ObservedAt: observed, HTTPStatus: httpStatus, Outcome: outcome, ReasonCode: reason, AssertionKind: expected.ResponseAssertionKind, AssertionStatus: assertionStatus},
		Redaction:   operationPlanProbeRedaction{CredentialValuesRemoved: true, CredentialReferencesRemoved: true, CredentialEnvNamesRemoved: true, QueryValuesRemoved: true, RequestBodyRemoved: true, ResponseBodyRemoved: true, ResponseRowsRemoved: true, EndpointDetailsRemoved: true, QuotaDetailsRemoved: true},
	}
}

func marshalOperationPlanProbeReceipt(t *testing.T, receipt operationPlanProbeReceipt) []byte {
	t.Helper()
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return append(data, '\n')
}

func TestValidateOperationPlanProbeReceiptRequiresCanonicalIdentityAndState(t *testing.T) {
	started := time.Now().UTC().Add(-2 * time.Second)
	received := time.Now().UTC()
	expected := testOperationPlanProbeExpectation(started)
	observed := received.Add(-time.Second)
	receipt := testOperationPlanProbeReceipt(expected, observed, "healthy", "response_assertion_passed", "passed", true, true, 1, 200)
	raw := marshalOperationPlanProbeReceipt(t, receipt)
	parsed, err := ValidateOperationPlanProbeReceipt(raw, expected, started, received, 0)
	if err != nil || parsed.Outcome != "healthy" || parsed.ObservedAt.IsZero() || parsed.ReceiptSHA256 != digest(raw) || len(parsed.ReceiptBytes) != len(raw) {
		t.Fatalf("valid receipt rejected or projected incorrectly: %v", err)
	}

	tests := []struct {
		name     string
		raw      []byte
		expected OperationPlanProbeExpectation
		exitCode int
	}{
		{name: "wrong operation", raw: func() []byte {
			copy := receipt
			copy.Operation.OperationID = strings.Repeat("7", 64)
			return marshalOperationPlanProbeReceipt(t, copy)
		}(), expected: expected, exitCode: 0},
		{name: "request count mismatch", raw: func() []byte {
			copy := receipt
			copy.Execution.RequestBudget = 0
			return marshalOperationPlanProbeReceipt(t, copy)
		}(), expected: expected, exitCode: 0},
		{name: "exit mismatch", raw: raw, expected: expected, exitCode: 4},
		{name: "changed plan pin", raw: raw, expected: func() OperationPlanProbeExpectation {
			copy := expected
			copy.IndexSHA256 = strings.Repeat("8", 64)
			return copy
		}(), exitCode: 0},
		{name: "duplicate JSON key", raw: []byte(strings.Replace(string(raw), `"outcome":"healthy"`, `"outcome":"healthy","outcome":"healthy"`, 1)), expected: expected, exitCode: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ValidateOperationPlanProbeReceipt(test.raw, test.expected, started, received, test.exitCode); err == nil {
				t.Fatal("invalid receipt accepted")
			}
		})
	}

	observationOnly := expected
	observationOnly.ResponseAssertionKind = "observation_only"
	semanticsReceipt := marshalOperationPlanProbeReceipt(t, testOperationPlanProbeReceipt(observationOnly, observed, "indeterminate", "response_semantics_unestablished", "not_run", true, true, 1, 204))
	if parsed, err := ValidateOperationPlanProbeReceipt(semanticsReceipt, observationOnly, started, received, 4); err != nil || parsed.Outcome != "indeterminate" || parsed.HTTPStatus != 204 {
		t.Fatalf("reviewed observation-only 2xx tuple rejected: %#v (%v)", parsed, err)
	}
	httpFailure := marshalOperationPlanProbeReceipt(t, testOperationPlanProbeReceipt(observationOnly, observed, "unhealthy", "response_http_failure", "failed", true, true, 1, 503))
	if parsed, err := ValidateOperationPlanProbeReceipt(httpFailure, observationOnly, started, received, 4); err != nil || parsed.Outcome != "unhealthy" || parsed.HTTPStatus != 503 {
		t.Fatalf("reviewed observation-only HTTP failure tuple rejected: %#v (%v)", parsed, err)
	}
	for name, invalid := range map[string][]byte{
		"2xx cannot assert healthy":     marshalOperationPlanProbeReceipt(t, testOperationPlanProbeReceipt(observationOnly, observed, "healthy", "response_assertion_passed", "passed", true, true, 1, 204)),
		"semantic unknown requires 2xx": marshalOperationPlanProbeReceipt(t, testOperationPlanProbeReceipt(observationOnly, observed, "indeterminate", "response_semantics_unestablished", "not_run", true, true, 1, 503)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ValidateOperationPlanProbeReceipt(invalid, observationOnly, started, received, 4); err == nil {
				t.Fatal("incoherent observation-only receipt accepted")
			}
		})
	}
}

func TestOperationPlanProbeRunnerUsesBoundedDirectChildAndCanonicalReceipt(t *testing.T) {
	root := t.TempDir()
	started := time.Now().UTC().Add(-time.Second)
	expected := testOperationPlanProbeExpectation(started)
	credentialPath := filepath.Join(root, "bindings.json")
	if err := os.WriteFile(credentialPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	argumentLog := filepath.Join(root, "args.txt")
	workingDirectoryLog := filepath.Join(root, "cwd.txt")
	templatePath := filepath.Join(root, "receipt-template.json")
	scriptPath := filepath.Join(root, "synthetic-cli")
	script := []byte("#!/bin/sh\npwd > \"$CWD_LOG\"\nprintf '%s\\n' \"$@\" > \"$ARG_LOG\"\nout=\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--output\" ]; then shift; out=$1; fi\n  shift\ndone\n/bin/cat \"$RECEIPT_TEMPLATE\" > \"$out\"\n/bin/chmod 600 \"$out\"\n/bin/cat \"$out\"\n")
	if err := os.WriteFile(scriptPath, script, 0o700); err != nil {
		t.Fatal(err)
	}
	binarySum := sha256.Sum256(script)
	expected.CLIBinarySHA256 = hex.EncodeToString(binarySum[:])
	observed := time.Now().UTC().Add(-500 * time.Millisecond)
	receipt := testOperationPlanProbeReceipt(expected, observed, "healthy", "response_assertion_passed", "passed", true, true, 1, 200)
	if err := os.WriteFile(templatePath, marshalOperationPlanProbeReceipt(t, receipt), 0o600); err != nil {
		t.Fatal(err)
	}
	config := OperationPlanProbeConfig{
		ExecutablePath: scriptPath, ExecutableSHA256: expected.CLIBinarySHA256, CLIVersion: expected.CLIVersion,
		RegistryIndexPath: filepath.Join(root, "reports", "operation-observation-plan", "index.json"), CredentialBindings: credentialPath, ReceiptDirectory: filepath.Join(root, "receipts"),
		EnvironmentNames: []string{"ARG_LOG", "CWD_LOG", "RECEIPT_TEMPLATE", "UNDECLARED_SECRET"},
	}
	t.Setenv("ARG_LOG", argumentLog)
	t.Setenv("CWD_LOG", workingDirectoryLog)
	t.Setenv("RECEIPT_TEMPLATE", templatePath)
	t.Setenv("UNDECLARED_SECRET", "DO_NOT_PASS")
	runner, err := NewOperationPlanProbeRunner(config)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().UTC().Add(10 * time.Second)
	result, exitCode, err := runner.Run(t.Context(), expected, deadline)
	if err != nil || exitCode != 0 || result.Outcome != "healthy" || result.ReceiptSHA256 != digest(result.ReceiptBytes) {
		t.Fatalf("synthetic direct child did not validate: exit=%d err=%v", exitCode, err)
	}
	args, err := os.ReadFile(argumentLog)
	if err != nil {
		t.Fatal(err)
	}
	argText := string(args)
	for _, flag := range []string{"verify", "--health", "--json", "--health-plan-index", "--health-operation-id", "--health-registry-revision", "--health-credential-bindings", "--health-attempt-id", "--health-cli-version", "--health-deadline", "--output"} {
		if !strings.Contains(argText, flag) {
			t.Fatalf("required child selector missing from argv: %s", flag)
		}
	}
	if strings.Contains(argText, "DO_NOT_PASS") || strings.Contains(argText, "RECEIPT_TEMPLATE") || strings.Contains(argText, "ARG_LOG") || strings.Contains(argText, "endpoint") || strings.Contains(argText, "query=") {
		t.Fatal("child argv contains unrelated environment or request values")
	}
	workingDirectory, err := os.ReadFile(workingDirectoryLog)
	if err != nil || filepath.Clean(strings.TrimSpace(string(workingDirectory))) != filepath.Clean(root) {
		t.Fatalf("actual child did not use the installed plan root independent of the parent process CWD: cwd=%q err=%v", strings.TrimSpace(string(workingDirectory)), err)
	}
}

func TestOperationPlanProbeRunnerFailsClosedOnCredentialFileMode(t *testing.T) {
	root := t.TempDir()
	credential := filepath.Join(root, "bindings.json")
	if err := os.WriteFile(credential, []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkOperationCredentialBindingFile(credential); err == nil {
		t.Fatal("group/world-readable credential binding file accepted")
	}
}

func TestOperationPlanProbeExpectationUsesLoaderVerifiedGenerationInputPins(t *testing.T) {
	planRoot, binding, _, _ := writeGatusPlanFixture(t)
	plan, err := LoadPinnedOperationObservationPlan(planRoot, binding)
	if err != nil {
		t.Fatal("could not load the pinned probe plan:", err)
	}
	var inputs operationObservationPlanGenerationInputs
	if err := json.Unmarshal(plan.state.index.GenerationInputs, &inputs); err != nil || inputs.ProviderIndex == nil {
		t.Fatal("fixture must contain the already-validated operation-manifest and provider-index references")
	}
	if plan.state.operationManifestRef != inputs.OperationManifest || !plan.state.providerIndexRefExists || plan.state.providerIndexRef != *inputs.ProviderIndex {
		t.Fatal("plan loader did not retain the exact validated generation-input artifact references")
	}
	records, err := plan.ReadShard(0)
	if err != nil || len(records) == 0 {
		t.Fatal("could not read the pinned operation record:", err)
	}
	lock := testOperationPlanRuntimeLock(strings.Repeat("9", 64))
	expected, err := operationPlanProbeExpected(plan, records[0], plan.state.index.Shards[0].SHA256, "817c7c1d-f844-4b79-bdad-891a273c1a4e", lock, "amd64", time.Unix(1, 0).UTC())
	if err != nil || expected.OperationManifestSHA256 != inputs.OperationManifest.SHA256 || expected.ProviderIndexSHA256 != inputs.ProviderIndex.SHA256 {
		t.Fatalf("probe identity did not use the loader-verified input pins: %#v (%v)", expected, err)
	}

	t.Run("tampered cached manifest pin", func(t *testing.T) {
		mutated := plan
		state := *plan.state
		mutated.state = &state
		mutated.state.operationManifestRef.SHA256 = strings.Repeat("f", 64)
		if _, err := operationPlanProbeExpected(mutated, records[0], mutated.state.index.Shards[0].SHA256, expected.AttemptID, lock, "amd64", expected.StartedAt); err == nil {
			t.Fatal("probe expectation accepted a cached manifest pin outside the verified release manifest")
		}
	})
	t.Run("missing optional provider index remains non-executable", func(t *testing.T) {
		mutated := plan
		state := *plan.state
		mutated.state = &state
		mutated.state.providerIndexRef = operationPlanArtifactRef{}
		mutated.state.providerIndexRefExists = false
		if _, err := operationPlanProbeExpected(mutated, records[0], mutated.state.index.Shards[0].SHA256, expected.AttemptID, lock, "amd64", expected.StartedAt); err == nil {
			t.Fatal("probe expectation accepted a plan with no provider-index reference")
		}
	})
	t.Run("resolver binds cached refs to exact generation inputs", func(t *testing.T) {
		for _, field := range []string{"operation manifest", "provider index"} {
			t.Run(field, func(t *testing.T) {
				mutated := plan
				state := *plan.state
				state.manifest = make(map[string]RegistryReleaseManifestArtifact, len(plan.state.manifest)+1)
				for path, artifact := range plan.state.manifest {
					state.manifest[path] = artifact
				}
				var original operationPlanArtifactRef
				if field == "operation manifest" {
					original = state.operationManifestRef
				} else {
					original = state.providerIndexRef
				}
				alternate := original
				alternate.Path = "reports/alternate-" + filepath.Base(original.Path)
				artifact := state.manifest[original.Path]
				artifact.Path = alternate.Path
				state.manifest[alternate.Path] = artifact
				if !releaseManifestBinds(state.manifest, alternate.Path, alternate.Bytes, alternate.SHA256) {
					t.Fatal("fixture did not create an alternate reference bound by the release manifest")
				}
				if field == "operation manifest" {
					state.operationManifestRef = alternate
				} else {
					state.providerIndexRef = alternate
				}
				mutated.state = &state
				if !validOperationPlanProbeGenerationInputPins(mutated.state) {
					t.Fatal("alternate fixture reference must pass the O(1) manifest-membership guard")
				}
				if _, err := NewPinnedOperationPlanProbeExpectationResolver(mutated, lock, "amd64"); err == nil {
					t.Fatal("resolver accepted a cached pin different from the signed generation-input bytes")
				}
			})
		}
	})
}

func BenchmarkOperationPlanProbeExpectedCachedGenerationInputs(b *testing.B) {
	for _, documentRefs := range []int{1, 12666} {
		b.Run("document_refs="+strconv.Itoa(documentRefs), func(b *testing.B) {
			plan, record, lock := benchmarkOperationPlanProbePlan(documentRefs)
			shardSHA := strings.Repeat("4", 64)
			started := time.Unix(1, 0).UTC()
			b.ReportAllocs()
			b.ReportMetric(float64(len(plan.state.index.GenerationInputs)), "generation_input_bytes")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := operationPlanProbeExpected(plan, record, shardSHA, "817c7c1d-f844-4b79-bdad-891a273c1a4e", lock, "amd64", started); err != nil {
					b.Fatal("cached probe expectation failed:", err)
				}
			}
		})
	}
}

func benchmarkOperationPlanProbePlan(documentRefs int) (PinnedOperationObservationPlan, OperationObservationPlanRecord, runtimebundle.Lock) {
	manifestRef := operationPlanArtifactRef{Path: "reports/operation-manifest.json", Bytes: 1, SHA256: strings.Repeat("a", 64)}
	providerRef := operationPlanArtifactRef{Path: "reports/provider-index.json", Bytes: 1, SHA256: strings.Repeat("b", 64)}
	documents := make([]operationPlanArtifactRef, documentRefs)
	for index := range documents {
		documents[index] = operationPlanArtifactRef{Path: fmt.Sprintf("reports/documents/%05d.json", index), Bytes: 1, SHA256: strings.Repeat("c", 64)}
	}
	generationInputs, _ := json.Marshal(operationObservationPlanGenerationInputs{
		GeneratorPath: "reports/generator.py", GeneratorSHA256: strings.Repeat("d", 64),
		OperationManifest: manifestRef, LegacyPolicy: operationPlanArtifactRef{Path: "reports/legacy-policy.json", Bytes: 1, SHA256: strings.Repeat("e", 64)},
		ProviderIndex: &providerRef, DocumentEvidence: documents,
	})
	manifest := map[string]RegistryReleaseManifestArtifact{
		manifestRef.Path: {Path: manifestRef.Path, Bytes: manifestRef.Bytes, SHA256: manifestRef.SHA256},
		providerRef.Path: {Path: providerRef.Path, Bytes: providerRef.Bytes, SHA256: providerRef.SHA256},
	}
	const sourceID = "data_go_kr"
	state := &operationPlanIndexState{
		index:    operationObservationPlanIndex{RegistryRevision: strings.Repeat("1", 40), GenerationInputs: generationInputs},
		manifest: manifest, byScope: map[string]OperationObservationPlanSourceScope{
			sourceID: {SourceID: sourceID, Provider: "data.go.kr", AdapterID: "data-go-kr", IdentitySetSHA256: strings.Repeat("2", 64)},
		}, operationManifestRef: manifestRef, providerIndexRef: providerRef, providerIndexRefExists: true, verified: true,
	}
	plan := PinnedOperationObservationPlan{binding: OperationObservationPlanBinding{
		RegistryRevision: strings.Repeat("1", 40), ReleaseManifestSHA256: strings.Repeat("3", 64), IndexSHA256: strings.Repeat("4", 64),
	}, state: state}
	record := OperationObservationPlanRecord{
		SourceID: sourceID, OperationID: strings.Repeat("5", 64), Provider: "data.go.kr", AdapterID: "data-go-kr",
		Protocol: "REST", ResponseAssertionKind: "observation_only", RequestTimeout: time.Second, ExecutionEligible: true,
	}
	return plan, record, testOperationPlanRuntimeLock(strings.Repeat("6", 64))
}
