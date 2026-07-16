package health

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

func TestDiagnosisSnapshotCrossContractProviderOutageInferredAndObserved(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	for _, test := range []struct{ name, fixture, determination string }{{"inferred", "inferred.json", "inferred"}, {"observed", "observed-notice.json", "observed"}} {
		t.Run(test.name, func(t *testing.T) {
			replay := mustCorrelationReplay(t, test.fixture)
			receipt, err := CorrelateProviderOutage(inputs.rule, inputs.canaries, replay)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, proof, err := ProjectDiagnosisSnapshot(replay.AssessedAt, []CorrelationReceipt{receipt}, nil, inputs.canaries, inputs.diagnostic, inputs.assertion)
			if err != nil {
				t.Fatal(err)
			}
			if proof.Counts.Accepted != 2 || proof.Boundaries.AvailabilityV1 != "unchanged" || proof.Boundaries.ArchiveV1 != "unchanged" {
				t.Fatalf("proof=%#v", proof)
			}
			for _, id := range []string{"dpr-op-00000001", "dpr-op-00000002"} {
				entry := diagnosisEntryByID(t, snapshot, id)
				if entry.Diagnosis.Code != "provider_outage" || entry.Diagnosis.Determination != test.determination || entry.Diagnosis.AccountableParty != "provider" || entry.Correlation == nil || entry.Correlation.NoticeLinked != (test.determination == "observed") || entry.Source == nil || entry.Source.SHA256 == "" {
					t.Fatalf("entry=%#v", entry)
				}
			}
			encoded, _ := json.Marshal(snapshot)
			for _, forbidden := range []string{"observation_ref", "dataset_id", "provider-notice:", "source_ref", "http_status", "response_body", "credential_hash", "credential_fingerprint"} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatalf("snapshot leaked %q", forbidden)
				}
			}
		})
	}
}

func TestDiagnosisSnapshotCrossContractAssertionFailPassAndNotObserved(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	now := time.Date(2026, 7, 17, 0, 15, 0, 0, time.UTC)
	fail := assertionRequestFor(t, inputs.assertion, now, "dpr-op-00000001", "contract", []string{"__undeclared_field__"})
	pass := assertionRequestFor(t, inputs.assertion, now, "dpr-op-00000002", "contract", []string{inputs.assertion.policyByOperation["dpr-op-00000002"].Dimensions.Contract.DeclaredResponseFields[0]})
	notObserved := assertionRequestFor(t, inputs.assertion, now, "dpr-op-00000003", "semantic", []string{"safeField"})
	snapshot, proof, err := ProjectDiagnosisSnapshot(now, []CorrelationReceipt{}, []AssertionEvaluationRequest{fail, pass, notObserved}, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	failed := diagnosisEntryByID(t, snapshot, "dpr-op-00000001")
	if failed.Diagnosis.Code != "contract_drift" || failed.Diagnosis.Determination != "inferred" || failed.Assertion == nil || failed.Assertion.Outcome != "fail" {
		t.Fatalf("fail=%#v", failed)
	}
	passed := diagnosisEntryByID(t, snapshot, "dpr-op-00000002")
	if passed.EvidenceState != "accepted" || passed.Diagnosis.Code != "unknown" || passed.Assertion.Outcome != "pass" {
		t.Fatalf("pass=%#v", passed)
	}
	semantic := diagnosisEntryByID(t, snapshot, "dpr-op-00000003")
	if semantic.EvidenceState != "not_observed" || semantic.Diagnosis.Code != "unknown" || semantic.Assertion.Outcome != "not_observed" || semantic.Assertion.ObservedFieldCount != 1 {
		t.Fatalf("semantic=%#v", semantic)
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := WriteDiagnosisSnapshotAtomic(path, snapshot, inputs.assertion); err != nil {
		t.Fatalf("writer rejected policy-consistent not_asserted evidence: %v", err)
	}
	read, _, err := ReadDiagnosisSnapshot(path, now, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	if entry := diagnosisEntryByID(t, read, "dpr-op-00000003"); entry.EvidenceState != "not_observed" || entry.Assertion == nil || entry.Assertion.ObservedFieldCount != 1 {
		t.Fatalf("reader contradicted the pinned evaluator: %#v", entry)
	}
	if proof.Counts.Accepted != 2 || proof.Counts.NotObserved != 1 || proof.Counts.Unknown != 7 {
		t.Fatalf("counts=%#v", proof.Counts)
	}
}

func TestDiagnosisSnapshotHTTPOnlyEvidenceRemainsUnknown(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	replay := mustCorrelationReplay(t, "single-timeout.json")
	receipt, err := CorrelateProviderOutage(inputs.rule, inputs.canaries, replay)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, proof, err := ProjectDiagnosisSnapshot(replay.AssessedAt, []CorrelationReceipt{receipt}, nil, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	entry := diagnosisEntryByID(t, snapshot, replay.Observations[0].OperationID)
	if entry.EvidenceState != "unknown" || entry.Diagnosis.Code != "unknown" || proof.Counts.Accepted != 0 || proof.Counts.Rejected != 0 {
		t.Fatalf("HTTP-only evidence was promoted: %#v %#v", entry, proof.Counts)
	}
}

func TestDiagnosisSnapshotProjectorRejectsRuleNoticePolicyIdentityAndConflicts(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	replay := mustCorrelationReplay(t, "observed-notice.json")
	base, err := CorrelateProviderOutage(inputs.rule, inputs.canaries, replay)
	if err != nil {
		t.Fatal(err)
	}
	correlationCases := map[string]func(*CorrelationReceipt){
		"rule digest":           func(receipt *CorrelationReceipt) { receipt.Rule.SHA256 = strings.Repeat("f", 64) },
		"notice not considered": func(receipt *CorrelationReceipt) { receipt.NoticeEvidence.ConsideredNoticeRefs = []string{} },
		"binding operation": func(receipt *CorrelationReceipt) {
			receipt.HealthObservationBindings[0].OperationID = "dpr-op-00000003"
		},
	}
	for name, mutate := range correlationCases {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var receipt CorrelationReceipt
			_ = json.Unmarshal(raw, &receipt)
			mutate(&receipt)
			snapshot, _, err := ProjectDiagnosisSnapshot(replay.AssessedAt, []CorrelationReceipt{receipt}, nil, inputs.canaries, inputs.diagnostic, inputs.assertion)
			if err != nil {
				t.Fatal(err)
			}
			if entry := diagnosisEntryByID(t, snapshot, "dpr-op-00000001"); entry.EvidenceState != "rejected" || entry.Diagnosis.Code != "unknown" {
				t.Fatalf("drifted correlation was promoted: %#v", entry)
			}
		})
	}

	fail := assertionRequestFor(t, inputs.assertion, replay.AssessedAt, "dpr-op-00000001", "contract", []string{"__undeclared_field__"})
	drifted := fail
	driftedBinding := *drifted.PolicyBinding
	driftedBinding.PolicySetVersion = 2
	drifted.PolicyBinding = &driftedBinding
	snapshot, _, err := ProjectDiagnosisSnapshot(replay.AssessedAt, nil, []AssertionEvaluationRequest{drifted}, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	if entry := diagnosisEntryByID(t, snapshot, "dpr-op-00000001"); entry.EvidenceState != "rejected" {
		t.Fatalf("superseded assertion was accepted: %#v", entry)
	}

	snapshot, _, err = ProjectDiagnosisSnapshot(replay.AssessedAt, []CorrelationReceipt{base}, []AssertionEvaluationRequest{fail}, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	if entry := diagnosisEntryByID(t, snapshot, "dpr-op-00000001"); entry.EvidenceState != "rejected" || entry.Diagnosis.Code != "unknown" {
		t.Fatalf("conflicting diagnoses were arbitrarily selected: %#v", entry)
	}
}

func TestDiagnosisSnapshotRejectedEvidenceIsTerminalAcrossSourceOrder(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	replay := mustCorrelationReplay(t, "observed-notice.json")
	validCorrelation, err := CorrelateProviderOutage(inputs.rule, inputs.canaries, replay)
	if err != nil {
		t.Fatal(err)
	}
	invalidCorrelation := validCorrelation
	invalidCorrelation.Rule.SHA256 = strings.Repeat("f", 64)
	declared := inputs.assertion.policyByOperation["dpr-op-00000001"].Dimensions.Contract.DeclaredResponseFields[0]
	validAssertion := assertionRequestFor(t, inputs.assertion, replay.AssessedAt, "dpr-op-00000001", "contract", []string{declared})
	invalidAssertion := validAssertion
	invalidBinding := *invalidAssertion.PolicyBinding
	invalidBinding.PolicySetVersion = 2
	invalidAssertion.PolicyBinding = &invalidBinding

	cases := []struct {
		name         string
		correlations []CorrelationReceipt
		assertions   []AssertionEvaluationRequest
	}{
		{"invalid correlation before valid assertion", []CorrelationReceipt{invalidCorrelation}, []AssertionEvaluationRequest{validAssertion}},
		{"valid correlation before invalid assertion", []CorrelationReceipt{validCorrelation}, []AssertionEvaluationRequest{invalidAssertion}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			snapshot, _, err := ProjectDiagnosisSnapshot(replay.AssessedAt, test.correlations, test.assertions, inputs.canaries, inputs.diagnostic, inputs.assertion)
			if err != nil {
				t.Fatal(err)
			}
			if entry := diagnosisEntryByID(t, snapshot, "dpr-op-00000001"); entry.EvidenceState != "rejected" || entry.Diagnosis.Code != "unknown" {
				t.Fatalf("valid evidence overwrote a terminal rejection: %#v", entry)
			}
		})
	}

	accepted := DiagnosisSnapshotEntry{OperationID: "dpr-op-00000001", OperationRevisionSHA256: assertionPolicyOperationOneRevision, EvidenceState: "accepted", Diagnosis: unknownPublicDiagnosis()}
	rejected := unknownDiagnosisEntry(accepted.OperationID, accepted.OperationRevisionSHA256, "rejected")
	for _, pair := range [][2]DiagnosisSnapshotEntry{{rejected, accepted}, {accepted, rejected}} {
		if got := mergeDiagnosisCandidate(pair[0], pair[1]); got.EvidenceState != "rejected" {
			t.Fatalf("merge order made rejection non-terminal: %#v", got)
		}
	}
}

func TestDiagnosisSnapshotReadFailsClosedPerOperationForLeakDigestDuplicateAndTime(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	now := time.Date(2026, 7, 17, 0, 15, 0, 0, time.UTC)
	fail := assertionRequestFor(t, inputs.assertion, now, "dpr-op-00000001", "contract", []string{"__undeclared_field__"})
	notObserved := assertionRequestFor(t, inputs.assertion, now, "dpr-op-00000002", "semantic", nil)
	base, _, err := ProjectDiagnosisSnapshot(now, nil, []AssertionEvaluationRequest{fail, notObserved}, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		mutate func(map[string]any)
		want   string
	}{
		"malicious leak": {mutate: func(value map[string]any) {
			value["operations"].([]any)[0].(map[string]any)["provider_url"] = "https://data.go.kr/?serviceKey=secret"
		}, want: "rejected"},
		"digest mismatch": {mutate: func(value map[string]any) {
			value["operations"].([]any)[0].(map[string]any)["projection_sha256"] = strings.Repeat("f", 64)
		}, want: "rejected"},
		"duplicate": {mutate: func(value map[string]any) {
			operations := value["operations"].([]any)
			value["operations"] = append(operations, operations[0])
		}, want: "rejected"},
		"future": {mutate: func(value map[string]any) {
			mutateSnapshotTime(t, value["operations"].([]any)[0].(map[string]any), now.Add(time.Minute), now.Add(2*time.Minute))
		}, want: "rejected"},
		"stale": {mutate: func(value map[string]any) {
			mutateSnapshotTime(t, value["operations"].([]any)[0].(map[string]any), now.Add(-16*time.Minute), now.Add(-time.Minute))
		}, want: "rejected"},
		"missing": {mutate: func(value map[string]any) {
			value["operations"] = value["operations"].([]any)[1:]
		}, want: "unknown"},
		"operation revision mismatch": {mutate: func(value map[string]any) {
			value["operations"].([]any)[0].(map[string]any)["operation_revision_sha256"] = strings.Repeat("c", 64)
		}, want: "rejected"},
		"unsupported state": {mutate: func(value map[string]any) {
			value["operations"].([]any)[0].(map[string]any)["evidence_state"] = "future_state"
		}, want: "rejected"},
		"out of operation": {mutate: func(value map[string]any) {
			operations := value["operations"].([]any)
			clone := map[string]any{}
			for key, item := range operations[0].(map[string]any) {
				clone[key] = item
			}
			clone["operation_id"] = "dpr-op-99999999"
			value["operations"] = append(operations, clone)
		}, want: "accepted"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var value map[string]any
			_ = json.Unmarshal(raw, &value)
			test.mutate(value)
			tampered, _ := json.Marshal(value)
			path := filepath.Join(t.TempDir(), "snapshot.json")
			if err := os.WriteFile(path, tampered, 0o600); err != nil {
				t.Fatal(err)
			}
			got, counts, err := ReadDiagnosisSnapshot(path, now, inputs.assertion)
			if err != nil {
				t.Fatal(err)
			}
			if entry := diagnosisEntryByID(t, got, "dpr-op-00000001"); (test.want != "accepted" && entry.Diagnosis.Code != "unknown") || entry.EvidenceState != test.want {
				t.Fatalf("tampered operation did not fail closed: got=%#v want_state=%s", entry, test.want)
			}
			if entry := diagnosisEntryByID(t, got, "dpr-op-00000002"); entry.EvidenceState != "not_observed" {
				t.Fatalf("unaffected operation disappeared: %#v", entry)
			}
			if test.want != "unknown" && counts.Rejected < 1 {
				t.Fatalf("doctor did not count rejection: %#v", counts)
			}
		})
	}
}

func TestDiagnosisSnapshotReadRejectsGlobalVersionPolicyAndOversize(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	now := time.Date(2026, 7, 17, 0, 15, 0, 0, time.UTC)
	snapshot, _, err := ProjectDiagnosisSnapshot(now, nil, nil, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(snapshot)
	cases := map[string][]byte{
		"version":        []byte(strings.Replace(string(raw), DiagnosisSnapshotSchemaVersion, "datapan.health-public-diagnosis-snapshot.v2", 1)),
		"policy version": []byte(strings.Replace(string(raw), `"policy_set_version":1`, `"policy_set_version":2`, 1)),
		"oversize":       append(raw, make([]byte, maxDiagnosisSnapshotBytes)...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "snapshot.json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ReadDiagnosisSnapshot(path, now, inputs.assertion); err == nil {
				t.Fatal("unsafe global snapshot was accepted")
			}
		})
	}
}

func TestDiagnosisSnapshotReaderRejectsRehashedUnreviewedTuplesAndNegativeCounts(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	now := time.Date(2026, 7, 17, 0, 15, 0, 0, time.UTC)
	request := assertionRequestFor(t, inputs.assertion, now, "dpr-op-00000001", "contract", []string{"__undeclared_field__"})
	base, _, err := ProjectDiagnosisSnapshot(now, nil, []AssertionEvaluationRequest{request}, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*DiagnosisSnapshotEntry){
		"accountable party": func(entry *DiagnosisSnapshotEntry) { entry.Diagnosis.AccountableParty = "provider" },
		"recommended action": func(entry *DiagnosisSnapshotEntry) {
			entry.Diagnosis.RecommendedActionIDs = []string{"check_provider_status"}
		},
		"avoid action":               func(entry *DiagnosisSnapshotEntry) { entry.Diagnosis.AvoidActionIDs = nil },
		"determination":              func(entry *DiagnosisSnapshotEntry) { entry.Diagnosis.Determination = "observed" },
		"negative count":             func(entry *DiagnosisSnapshotEntry) { entry.Assertion.ObservedFieldCount = -1 },
		"count above schema maximum": func(entry *DiagnosisSnapshotEntry) { entry.Assertion.ObservedFieldCount = 1025 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var candidate DiagnosisSnapshot
			_ = json.Unmarshal(raw, &candidate)
			entry := &candidate.Operations[0]
			mutate(entry)
			entry.ProjectionSHA256 = diagnosisEntryDigest(*entry)
			path := filepath.Join(t.TempDir(), "snapshot.json")
			raw, err = json.Marshal(candidate)
			if err != nil || os.WriteFile(path, raw, 0o600) != nil {
				t.Fatal("could not write adversarial snapshot")
			}
			got, counts, err := ReadDiagnosisSnapshot(path, now, inputs.assertion)
			if err != nil {
				t.Fatal(err)
			}
			entry = func() *DiagnosisSnapshotEntry { value := diagnosisEntryByID(t, got, "dpr-op-00000001"); return &value }()
			if entry.EvidenceState != "rejected" || entry.Diagnosis.Code != "unknown" || counts.Rejected < 1 {
				t.Fatalf("self-rehashed unreviewed projection was accepted: %#v %#v", entry, counts)
			}
		})
	}
}

func TestDiagnosisSnapshotReaderRejectsRehashedCorrelationCountsAboveSchemaMaximum(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	replay := mustCorrelationReplay(t, "observed-notice.json")
	receipt, err := CorrelateProviderOutage(inputs.rule, inputs.canaries, replay)
	if err != nil {
		t.Fatal(err)
	}
	base, _, err := ProjectDiagnosisSnapshot(replay.AssessedAt, []CorrelationReceipt{receipt}, nil, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*DiagnosisCorrelationBoundary)
	}{
		{"affected above maximum", func(boundary *DiagnosisCorrelationBoundary) { boundary.AffectedCount = 11 }},
		{"control above maximum", func(boundary *DiagnosisCorrelationBoundary) { boundary.ControlCount = 11 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			raw, _ := json.Marshal(base)
			var candidate DiagnosisSnapshot
			_ = json.Unmarshal(raw, &candidate)
			entry := &candidate.Operations[0]
			if entry.Correlation == nil {
				t.Fatal("expected correlation projection")
			}
			test.mutate(entry.Correlation)
			entry.ProjectionSHA256 = diagnosisEntryDigest(*entry)
			path := filepath.Join(t.TempDir(), "snapshot.json")
			raw, _ = json.Marshal(candidate)
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			got, counts, err := ReadDiagnosisSnapshot(path, replay.AssessedAt, inputs.assertion)
			if err != nil {
				t.Fatal(err)
			}
			if gotEntry := diagnosisEntryByID(t, got, entry.OperationID); gotEntry.EvidenceState != "rejected" || counts.Rejected < 1 {
				t.Fatalf("self-rehashed out-of-range correlation was accepted: %#v %#v", gotEntry, counts)
			}
		})
	}
}

func TestDiagnosisSnapshotProjectorEvaluatesExactAssessedRequest(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	now := time.Date(2026, 7, 17, 0, 15, 0, 0, time.UTC)
	request := assertionRequestFor(t, inputs.assertion, now, "dpr-op-00000001", "contract", []string{"__undeclared_field__"})
	first, _, err := ProjectDiagnosisSnapshot(now, nil, []AssertionEvaluationRequest{request}, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	entry := diagnosisEntryByID(t, first, request.OperationID)
	if entry.Assertion == nil || entry.Assertion.Outcome != "fail" || entry.Assertion.ObservedFieldCount != 1 || entry.AssessedAt == nil || !entry.AssessedAt.Equal(now) {
		t.Fatalf("request was not evaluated by the pinned policy: %#v", entry)
	}
	repackaged := request
	repackaged.AssessedAt = now.Add(-time.Minute)
	second, _, err := ProjectDiagnosisSnapshot(now, nil, []AssertionEvaluationRequest{repackaged}, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	secondEntry := diagnosisEntryByID(t, second, request.OperationID)
	if secondEntry.Source == nil || entry.Source == nil || secondEntry.Source.SHA256 == entry.Source.SHA256 || secondEntry.AssessedAt == nil || !secondEntry.AssessedAt.Equal(repackaged.AssessedAt) {
		t.Fatalf("assessed_at was not bound into the exact source request: first=%#v second=%#v", entry, secondEntry)
	}
}

func TestDiagnosisSnapshotReceiptDigestsExactStoredArtifactBytes(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	now := time.Date(2026, 7, 17, 0, 15, 0, 0, time.UTC)
	snapshot, receipt, err := ProjectDiagnosisSnapshot(now, nil, nil, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := WriteDiagnosisSnapshotAtomic(path, snapshot, inputs.assertion); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	compact, _ := json.Marshal(snapshot)
	if receipt.SnapshotDigestAlgorithm != "sha256" || receipt.SnapshotCanonicalization != DiagnosisSnapshotCanonicalization || receipt.SnapshotBytes != len(raw) || receipt.SnapshotSHA256 != digest(raw) || receipt.SnapshotSHA256 == digest(compact) || len(raw) == 0 || raw[len(raw)-1] != '\n' || !bytes.Contains(raw, []byte("\n  \"generated_at\"")) {
		t.Fatalf("receipt does not bind exact indented+LF artifact bytes: %#v", receipt)
	}
}

func TestDiagnosisSnapshotAtomicUpdateNeverExposesPartialJSON(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	now := time.Date(2026, 7, 17, 0, 15, 0, 0, time.UTC)
	unknown, _, _ := ProjectDiagnosisSnapshot(now, nil, nil, inputs.canaries, inputs.diagnostic, inputs.assertion)
	fail := assertionRequestFor(t, inputs.assertion, now, "dpr-op-00000001", "contract", []string{"__undeclared_field__"})
	diagnosed, _, _ := ProjectDiagnosisSnapshot(now, nil, []AssertionEvaluationRequest{fail}, inputs.canaries, inputs.diagnostic, inputs.assertion)
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := WriteDiagnosisSnapshotAtomic(path, unknown, inputs.assertion); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 1)
	wait.Add(2)
	go func() {
		defer wait.Done()
		for index := 0; index < 50; index++ {
			candidate := unknown
			if index%2 == 0 {
				candidate = diagnosed
			}
			if err := WriteDiagnosisSnapshotAtomic(path, candidate, inputs.assertion); err != nil {
				errorsSeen <- err
				return
			}
		}
	}()
	go func() {
		defer wait.Done()
		for index := 0; index < 100; index++ {
			if _, _, err := ReadDiagnosisSnapshot(path, now, inputs.assertion); err != nil {
				errorsSeen <- err
				return
			}
		}
	}()
	wait.Wait()
	select {
	case err := <-errorsSeen:
		t.Fatal(err)
	default:
	}
}

func TestDiagnosisOverlayPreservesAvailabilityAndPublicContract(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	now := publicNow
	fail := assertionRequestFor(t, inputs.assertion, now, "dpr-op-00000001", "contract", []string{"__undeclared_field__"})
	snapshot, _, err := ProjectDiagnosisSnapshot(now, nil, []AssertionEvaluationRequest{fail}, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.json")
	if err := WriteDiagnosisSnapshotAtomic(path, snapshot, inputs.assertion); err != nil {
		t.Fatal(err)
	}
	document := testPublicDocument(t)
	observed := now
	document.Operations[0].ObservedAt = &observed
	document.Operations[0].ObservationState = "current"
	document.Operations[0].Availability = "operational"
	source, err := NewDiagnosisOverlaySource(staticPublicSource{document: document}, path, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	source.now = func() time.Time { return now }
	got, err := source.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got.Operations[0].Availability != "operational" || got.Operations[0].ObservationState != "current" || got.Operations[0].Diagnosis.Code != "contract_drift" {
		t.Fatalf("overlay changed availability or lost diagnosis: %#v", got.Operations[0])
	}
	encoded, _ := json.Marshal(got)
	if err := schemas.ValidateHealthPublicStatusV1(encoded); err != nil {
		t.Fatalf("%v: %s", err, encoded)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":"evil","credential":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = source.Snapshot(context.Background())
	if err != nil || got.Operations[0].Availability != "operational" || got.Operations[0].Diagnosis.Code != "unknown" {
		t.Fatalf("invalid diagnosis altered availability: %#v err=%v", got.Operations[0], err)
	}
}

func TestDiagnosisSnapshotSchemaAndDoctorRemainValueFree(t *testing.T) {
	inputs := mustDiagnosisInputs(t)
	now := time.Date(2026, 7, 17, 0, 15, 0, 0, time.UTC)
	snapshot, proof, err := ProjectDiagnosisSnapshot(now, nil, nil, inputs.canaries, inputs.diagnostic, inputs.assertion)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(snapshot)
	if err := schemas.ValidateHealthPublicDiagnosisSnapshotV1(raw); err != nil {
		t.Fatal(err)
	}
	if proof.Counts.String() != "accepted=0 not_observed=0 unknown=10 rejected=0" {
		t.Fatalf("doctor counts=%s", proof.Counts.String())
	}
	for _, forbidden := range []string{"dataset_id", "operation_name", "endpoint", "servicekey", "provider_url", "response_body", "observation_ref"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("schema output leaked %q", forbidden)
		}
	}
}

type diagnosisInputs struct {
	rule       CorrelationRule
	canaries   CanaryConfig
	diagnostic DiagnosticContract
	assertion  AssertionPolicyContract
}

func mustDiagnosisInputs(t *testing.T) diagnosisInputs {
	t.Helper()
	rule, canaries := mustCorrelationInputs(t)
	diagnostic, err := LoadDiagnosticContract("../../config/registry/diagnostic-contract-pin.json")
	if err != nil {
		t.Fatal(err)
	}
	assertion, err := LoadAssertionPolicyContract("../../config/registry/assertion-policy-contract-pin.json", canaries)
	if err != nil {
		t.Fatal(err)
	}
	return diagnosisInputs{rule, canaries, diagnostic, assertion}
}

func assertionRequestFor(t *testing.T, contract AssertionPolicyContract, assessedAt time.Time, operationID, dimension string, fields []string) AssertionEvaluationRequest {
	t.Helper()
	policy := contract.policyByOperation[operationID]
	binding := acceptedDiagnosisAssertionBinding()
	return AssertionEvaluationRequest{SchemaVersion: AssertionEvaluationSchemaVersion, AssessedAt: assessedAt, OperationID: operationID, OperationRevisionSHA256: policy.OperationRevisionSHA256, Dimension: dimension, PolicyBinding: &binding, Observation: AssertionObservation{ResponseFields: fields}}
}

func diagnosisEntryByID(t *testing.T, snapshot DiagnosisSnapshot, id string) DiagnosisSnapshotEntry {
	t.Helper()
	for _, entry := range snapshot.Operations {
		if entry.OperationID == id {
			return entry
		}
	}
	t.Fatalf("missing operation %s", id)
	return DiagnosisSnapshotEntry{}
}

func mutateSnapshotTime(t *testing.T, entry map[string]any, assessed, valid time.Time) {
	t.Helper()
	entry["assessed_at"], entry["valid_until"] = assessed.Format(time.RFC3339), valid.Format(time.RFC3339)
	entry["projection_sha256"] = ""
	raw, _ := json.Marshal(entry)
	var typed DiagnosisSnapshotEntry
	if err := json.Unmarshal(raw, &typed); err != nil {
		t.Fatal(err)
	}
	entry["projection_sha256"] = diagnosisEntryDigest(typed)
}
