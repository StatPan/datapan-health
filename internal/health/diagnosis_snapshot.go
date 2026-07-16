package health

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

const (
	DiagnosisSnapshotSchemaVersion    = "datapan.health-public-diagnosis-snapshot.v1"
	DiagnosisSnapshotSchemaSHA256     = "570d85372ca4a137162887182cf4b63928ba5354f0aa1bbc041735153c996274"
	DiagnosisProjectionReceiptVersion = "datapan.health-diagnosis-projector-receipt.v1"
	maxDiagnosisSnapshotBytes         = 512 * 1024
	maxDiagnosisEvidenceAge           = 15 * time.Minute
	diagnosisFutureSkew               = 30 * time.Second
)

var linkedNoticeRefPattern = regexp.MustCompile(`^provider-notice:[a-z][a-z0-9.-]{0,95}:v[1-9][0-9]*:sha256:[0-9a-f]{64}$`)
var correlationEvidenceRefPattern = regexp.MustCompile(`^health:correlation:[0-9a-f]{64}$`)

type DiagnosisSnapshot struct {
	SchemaVersion              string                   `json:"schema_version"`
	GeneratedAt                time.Time                `json:"generated_at"`
	RegistryRevision           string                   `json:"registry_revision"`
	DiagnosticVocabularySHA256 string                   `json:"diagnostic_vocabulary_sha256"`
	CorrelationRule            CorrelationRuleReference `json:"correlation_rule"`
	AssertionPolicy            AssertionPolicyBinding   `json:"assertion_policy"`
	Operations                 []DiagnosisSnapshotEntry `json:"operations"`
}

type DiagnosisSnapshotEntry struct {
	OperationID             string                        `json:"operation_id"`
	OperationRevisionSHA256 string                        `json:"operation_revision_sha256"`
	ProjectionSHA256        string                        `json:"projection_sha256"`
	EvidenceState           string                        `json:"evidence_state"`
	AssessedAt              *time.Time                    `json:"assessed_at,omitempty"`
	ValidUntil              *time.Time                    `json:"valid_until,omitempty"`
	Source                  *DiagnosisSnapshotSourceRef   `json:"source,omitempty"`
	Correlation             *DiagnosisCorrelationBoundary `json:"correlation,omitempty"`
	Assertion               *DiagnosisAssertionBoundary   `json:"assertion,omitempty"`
	Diagnosis               PublicDiagnosis               `json:"diagnosis"`
}

type DiagnosisSnapshotSourceRef struct {
	Kind          string `json:"kind"`
	SchemaVersion string `json:"schema_version"`
	SHA256        string `json:"sha256"`
}

type DiagnosisCorrelationBoundary struct {
	AffectedCount int  `json:"affected_count"`
	ControlCount  int  `json:"control_count"`
	NoticeLinked  bool `json:"notice_linked"`
}

type DiagnosisAssertionBoundary struct {
	Dimension string `json:"dimension"`
	Outcome   string `json:"outcome"`
}

type AssessedAssertionEvaluation struct {
	AssessedAt time.Time           `json:"assessed_at"`
	Evaluation AssertionEvaluation `json:"evaluation"`
}

type DiagnosisProjectionReceipt struct {
	SchemaVersion        string                   `json:"schema_version"`
	GeneratedAt          time.Time                `json:"generated_at"`
	HealthHead           string                   `json:"health_head,omitempty"`
	TestedRevision       string                   `json:"tested_revision,omitempty"`
	SnapshotSchemaSHA256 string                   `json:"snapshot_schema_sha256,omitempty"`
	SnapshotSHA256       string                   `json:"snapshot_sha256"`
	CorrelationRule      CorrelationRuleReference `json:"correlation_rule"`
	AssertionPolicy      AssertionPolicyBinding   `json:"assertion_policy"`
	SourceProof          *DiagnosisSourceProof    `json:"source_proof,omitempty"`
	Counts               DiagnosisCounts          `json:"counts"`
	Boundaries           struct {
		AvailabilityV1  string `json:"availability_v1"`
		ArchiveV1       string `json:"archive_v1"`
		ProviderRuntime string `json:"provider_runtime"`
		Deployment      string `json:"deployment"`
	} `json:"boundaries"`
}

type DiagnosisCounts struct {
	Accepted    int `json:"accepted"`
	NotObserved int `json:"not_observed"`
	Unknown     int `json:"unknown"`
	Rejected    int `json:"rejected"`
}

func ProjectDiagnosisSnapshot(generatedAt time.Time, correlations []CorrelationReceipt, assertions []AssessedAssertionEvaluation, canaries CanaryConfig, diagnostic DiagnosticContract, assertionContract AssertionPolicyContract) (DiagnosisSnapshot, DiagnosisProjectionReceipt, error) {
	generatedAt = generatedAt.UTC()
	if generatedAt.IsZero() || len(correlations) > 100 || len(assertions) > 1000 || len(assertionContract.policyByOperation) != len(canaries.Canaries) {
		return DiagnosisSnapshot{}, DiagnosisProjectionReceipt{}, errors.New("invalid diagnosis projection input")
	}
	binding := acceptedDiagnosisAssertionBinding()
	snapshot := DiagnosisSnapshot{
		SchemaVersion: DiagnosisSnapshotSchemaVersion, GeneratedAt: generatedAt,
		RegistryRevision:           AcceptedAssertionRegistryRevision,
		DiagnosticVocabularySHA256: AcceptedAssertionDiagnosticVocabularySHA,
		CorrelationRule:            CorrelationRuleReference{RuleID: AcceptedCorrelationRuleID, Version: 1, SHA256: AcceptedCorrelationRuleSHA256},
		AssertionPolicy:            binding,
		Operations:                 make([]DiagnosisSnapshotEntry, 0, len(canaries.Canaries)),
	}
	entries := map[string]DiagnosisSnapshotEntry{}
	seenKinds := map[string]map[string]bool{}
	for _, canary := range canaries.Canaries {
		policy, ok := assertionContract.policyByOperation[canary.OperationID]
		if !ok {
			return DiagnosisSnapshot{}, DiagnosisProjectionReceipt{}, errors.New("assertion contract does not cover public operation")
		}
		entries[canary.OperationID] = unknownDiagnosisEntry(canary.OperationID, policy.OperationRevisionSHA256, "unknown")
		seenKinds[canary.OperationID] = map[string]bool{}
	}

	providerOutage, err := diagnosisTemplate(diagnostic, "provider-outage.json")
	if err != nil {
		return DiagnosisSnapshot{}, DiagnosisProjectionReceipt{}, err
	}
	contractDrift, err := diagnosisTemplate(diagnostic, "contract-drift.json")
	if err != nil {
		return DiagnosisSnapshot{}, DiagnosisProjectionReceipt{}, err
	}

	for _, receipt := range correlations {
		raw, err := json.Marshal(receipt)
		if err != nil {
			return DiagnosisSnapshot{}, DiagnosisProjectionReceipt{}, err
		}
		if validInsufficientCorrelationReceipt(receipt, generatedAt, canaries) {
			continue
		}
		validUntilByOperation, valid := validateCorrelationReceiptForSnapshot(receipt, generatedAt, canaries)
		for _, affected := range receipt.AffectedEvidence {
			current, known := entries[affected.OperationID]
			if !known {
				continue
			}
			if seenKinds[affected.OperationID]["correlation_receipt"] {
				entries[affected.OperationID] = unknownDiagnosisEntry(current.OperationID, current.OperationRevisionSHA256, "rejected")
				continue
			}
			seenKinds[affected.OperationID]["correlation_receipt"] = true
			if !valid {
				entries[affected.OperationID] = unknownDiagnosisEntry(current.OperationID, current.OperationRevisionSHA256, "rejected")
				continue
			}
			validUntil, ok := validUntilByOperation[affected.OperationID]
			if !ok || generatedAt.After(validUntil) {
				entries[affected.OperationID] = unknownDiagnosisEntry(current.OperationID, current.OperationRevisionSHA256, "unknown")
				continue
			}
			diagnosis := providerOutage
			diagnosis.Determination = receipt.Result.Determination
			assessed := receipt.AssessedAt.UTC()
			candidate := DiagnosisSnapshotEntry{OperationID: affected.OperationID, OperationRevisionSHA256: current.OperationRevisionSHA256, EvidenceState: "accepted", AssessedAt: &assessed, ValidUntil: &validUntil,
				Source:      &DiagnosisSnapshotSourceRef{Kind: "correlation_receipt", SchemaVersion: CorrelationReceiptSchemaVersion, SHA256: digest(raw)},
				Correlation: &DiagnosisCorrelationBoundary{AffectedCount: receipt.Result.AffectedCount, ControlCount: receipt.Result.ControlCount, NoticeLinked: receipt.NoticeEvidence.LinkedNoticeRef != ""}, Diagnosis: diagnosis}
			candidate.ProjectionSHA256 = diagnosisEntryDigest(candidate)
			entries[affected.OperationID] = mergeDiagnosisCandidate(current, candidate)
		}
	}

	for _, record := range assertions {
		evaluation := record.Evaluation
		current, known := entries[evaluation.OperationID]
		if !known {
			continue
		}
		if seenKinds[evaluation.OperationID]["assertion_evaluation"] {
			entries[evaluation.OperationID] = unknownDiagnosisEntry(current.OperationID, current.OperationRevisionSHA256, "rejected")
			continue
		}
		seenKinds[evaluation.OperationID]["assertion_evaluation"] = true
		raw, err := json.Marshal(record)
		if err != nil {
			return DiagnosisSnapshot{}, DiagnosisProjectionReceipt{}, err
		}
		state, valid := validateAssertionForSnapshot(record, generatedAt, assertionContract)
		if !valid {
			entries[evaluation.OperationID] = unknownDiagnosisEntry(current.OperationID, current.OperationRevisionSHA256, "rejected")
			continue
		}
		assessed := record.AssessedAt.UTC()
		validUntil := assessed.Add(maxDiagnosisEvidenceAge)
		candidate := DiagnosisSnapshotEntry{OperationID: evaluation.OperationID, OperationRevisionSHA256: evaluation.OperationRevisionSHA256, EvidenceState: state, AssessedAt: &assessed, ValidUntil: &validUntil,
			Source: &DiagnosisSnapshotSourceRef{Kind: "assertion_evaluation", SchemaVersion: AssertionEvaluationSchemaVersion, SHA256: digest(raw)}, Assertion: &DiagnosisAssertionBoundary{Dimension: evaluation.Dimension, Outcome: evaluation.Outcome}, Diagnosis: unknownPublicDiagnosis()}
		if evaluation.Dimension == "contract" && evaluation.Outcome == "fail" {
			candidate.Diagnosis = contractDrift
		}
		candidate.ProjectionSHA256 = diagnosisEntryDigest(candidate)
		entries[evaluation.OperationID] = mergeDiagnosisCandidate(current, candidate)
	}

	for _, id := range sortedOperationIDs(assertionContract.policyByOperation) {
		entry := entries[id]
		if entry.ProjectionSHA256 == "" {
			entry.ProjectionSHA256 = diagnosisEntryDigest(entry)
		}
		snapshot.Operations = append(snapshot.Operations, entry)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || schemas.ValidateHealthPublicDiagnosisSnapshotV1(encoded) != nil {
		return DiagnosisSnapshot{}, DiagnosisProjectionReceipt{}, errors.New("projected diagnosis snapshot is invalid")
	}
	receipt := DiagnosisProjectionReceipt{SchemaVersion: DiagnosisProjectionReceiptVersion, GeneratedAt: generatedAt, SnapshotSHA256: digest(encoded), Counts: countDiagnosisEntries(snapshot.Operations)}
	receipt.CorrelationRule = snapshot.CorrelationRule
	receipt.AssertionPolicy = snapshot.AssertionPolicy
	receipt.Boundaries.AvailabilityV1, receipt.Boundaries.ArchiveV1 = "unchanged", "unchanged"
	receipt.Boundaries.ProviderRuntime, receipt.Boundaries.Deployment = "not_invoked", "not_performed"
	return snapshot, receipt, nil
}

func validInsufficientCorrelationReceipt(receipt CorrelationReceipt, generatedAt time.Time, canaries CanaryConfig) bool {
	if receipt.SchemaVersion != CorrelationReceiptSchemaVersion || receipt.AssessedAt.IsZero() || receipt.AssessedAt.After(generatedAt.Add(diagnosisFutureSkew)) || generatedAt.Sub(receipt.AssessedAt) > maxDiagnosisEvidenceAge || receipt.Rule != (CorrelationRuleReference{RuleID: AcceptedCorrelationRuleID, Version: 1, SHA256: AcceptedCorrelationRuleSHA256}) || receipt.Scope.Provider != "data.go.kr" || receipt.Scope.CanaryScopeAlias != AcceptedCanaryScopeAlias || receipt.Result.Cause != "unknown" || receipt.Result.Determination != "unknown" || receipt.Result.State != "insufficient_evidence" || receipt.Result.AffectedCount != len(receipt.AffectedEvidence) || receipt.Result.ControlCount != len(receipt.ControlEvidence) || len(receipt.HealthObservationEvidence) != 0 || len(receipt.HealthObservationBindings) != 0 || receipt.NoticeEvidence.LinkedNoticeRef != "" || receipt.Boundaries.AlertPolicy != "unchanged" || receipt.Boundaries.RuntimeMutation != "not_performed" || receipt.Boundaries.Redaction != "minimized_refs_only" {
		return false
	}
	known := map[string]bool{}
	for _, canary := range canaries.Canaries {
		known[canary.OperationID] = true
	}
	seen := map[string]bool{}
	for _, ref := range append(append([]CorrelationObservationRef{}, receipt.AffectedEvidence...), receipt.ControlEvidence...) {
		if !known[ref.OperationID] || seen[ref.OperationID] || !immutableObservationRefPattern.MatchString(ref.ObservationRef) {
			return false
		}
		seen[ref.OperationID] = true
	}
	return true
}

func validateCorrelationReceiptForSnapshot(receipt CorrelationReceipt, generatedAt time.Time, canaries CanaryConfig) (map[string]time.Time, bool) {
	if receipt.SchemaVersion != CorrelationReceiptSchemaVersion || receipt.AssessedAt.IsZero() || receipt.AssessedAt.After(generatedAt.Add(diagnosisFutureSkew)) || generatedAt.Sub(receipt.AssessedAt) > maxDiagnosisEvidenceAge || receipt.Rule.RuleID != AcceptedCorrelationRuleID || receipt.Rule.Version != 1 || receipt.Rule.SHA256 != AcceptedCorrelationRuleSHA256 || receipt.Scope.Provider != "data.go.kr" || receipt.Scope.CanaryScopeAlias != AcceptedCanaryScopeAlias || receipt.Result.Cause != "provider_outage" || (receipt.Result.Determination != "inferred" && receipt.Result.Determination != "observed") || receipt.Result.State != "degraded" || receipt.Result.AffectedCount != len(receipt.AffectedEvidence) || receipt.Result.ControlCount != len(receipt.ControlEvidence) || receipt.Result.AffectedCount < 2 || receipt.Result.ControlCount < 1 || receipt.Boundaries.AlertPolicy != "unchanged" || receipt.Boundaries.RuntimeMutation != "not_performed" || receipt.Boundaries.Redaction != "minimized_refs_only" {
		return nil, false
	}
	if (receipt.Result.Determination == "observed") != linkedNoticeRefPattern.MatchString(receipt.NoticeEvidence.LinkedNoticeRef) {
		return nil, false
	}
	considered := map[string]bool{}
	for _, ref := range receipt.NoticeEvidence.ConsideredNoticeRefs {
		if !linkedNoticeRefPattern.MatchString(ref) || considered[ref] {
			return nil, false
		}
		considered[ref] = true
	}
	superseded := map[string]bool{}
	for _, ref := range receipt.NoticeEvidence.SupersededNoticeRefs {
		if !considered[ref] || superseded[ref] {
			return nil, false
		}
		superseded[ref] = true
	}
	if receipt.NoticeEvidence.LinkedNoticeRef != "" && (!considered[receipt.NoticeEvidence.LinkedNoticeRef] || superseded[receipt.NoticeEvidence.LinkedNoticeRef]) {
		return nil, false
	}
	entries := map[string]CatalogEntry{}
	for _, canary := range canaries.Canaries {
		entry, ok := canaries.Entry(canary)
		if !ok {
			return nil, false
		}
		entries[canary.OperationID] = entry
	}
	affected := map[string]string{}
	controls := map[string]bool{}
	for _, ref := range receipt.AffectedEvidence {
		if affected[ref.OperationID] != "" || !immutableObservationRefPattern.MatchString(ref.ObservationRef) || entries[ref.OperationID].OperationID == "" {
			return nil, false
		}
		affected[ref.OperationID] = ref.ObservationRef
	}
	for _, ref := range receipt.ControlEvidence {
		if controls[ref.OperationID] || affected[ref.OperationID] != "" || !immutableObservationRefPattern.MatchString(ref.ObservationRef) || entries[ref.OperationID].OperationID == "" {
			return nil, false
		}
		controls[ref.OperationID] = true
	}
	if len(receipt.HealthObservationEvidence) != len(affected) || len(receipt.HealthObservationBindings) != len(affected) {
		return nil, false
	}
	evidenceByID := map[string]CorrelationHealthEvidence{}
	for _, evidence := range receipt.HealthObservationEvidence {
		if evidenceByID[evidence.RefID].RefID != "" || !correlationEvidenceRefPattern.MatchString(evidence.RefID) || evidence.Kind != "health_observation" || evidence.Authority != "datapan_health" || evidence.Version != AcceptedCorrelationRuleID || evidence.Scope.Level != "operation" || evidence.Scope.SubjectRef != "envelope_subject" || !exactStrings(evidence.Supports, []string{"cause", "determination", "ownership", "action"}) || evidence.HealthCorrelation.State != "degraded" || !validCorrelationSnapshotTiming(evidence.Timing) {
			return nil, false
		}
		evidenceByID[evidence.RefID] = evidence
	}
	validUntil := map[string]time.Time{}
	seenBindings := map[string]bool{}
	for _, binding := range receipt.HealthObservationBindings {
		entry, ok := entries[binding.OperationID]
		evidence, evidenceOK := evidenceByID[binding.EvidenceRefID]
		if !ok || !evidenceOK || affected[binding.OperationID] == "" || seenBindings[binding.OperationID] || binding.DatasetID != entry.Aliases.DatasetID || binding.DependencyClass != entry.Endpoint.DependencyClass || binding.ImmutableObservationRef != affected[binding.OperationID] || evidence.Scope.DetailID != "dependency:"+binding.DependencyClass || evidence.HealthCorrelation.ProbePolicyVersion != fmt.Sprintf("%s.v%d", entry.Policy.Key, entry.Policy.Version) {
			return nil, false
		}
		seenBindings[binding.OperationID] = true
		validUntil[binding.OperationID] = receipt.AssessedAt.UTC().Add(time.Duration(evidence.Timing.RemainingValiditySeconds) * time.Second)
	}
	return validUntil, len(seenBindings) == len(affected)
}

func validCorrelationSnapshotTiming(timing CorrelationEvidenceTiming) bool {
	if timing.Basis != "relative_to_assessed_at" || timing.Validity != "current_at_assessment" || timing.ValidityPolicyVersion != AcceptedCorrelationRuleID || timing.ObservedAgeSeconds < 0 || timing.ObservedAgeSeconds > 900 || timing.RemainingValiditySeconds < 1 || timing.RemainingValiditySeconds > 900 {
		return false
	}
	return timing.ObservedAgeSeconds+timing.RemainingValiditySeconds == 900 || (timing.ObservedAgeSeconds == 900 && timing.RemainingValiditySeconds == 1)
}

func validateAssertionForSnapshot(record AssessedAssertionEvaluation, generatedAt time.Time, contract AssertionPolicyContract) (string, bool) {
	evaluation := record.Evaluation
	policy, ok := contract.policyByOperation[evaluation.OperationID]
	if !ok || record.AssessedAt.IsZero() || record.AssessedAt.After(generatedAt.Add(diagnosisFutureSkew)) || generatedAt.Sub(record.AssessedAt) > maxDiagnosisEvidenceAge || evaluation.SchemaVersion != AssertionEvaluationSchemaVersion || evaluation.RegistryRevision != AcceptedAssertionRegistryRevision || evaluation.OperationRevisionSHA256 != policy.OperationRevisionSHA256 || evaluation.PolicySetID != acceptedAssertionPolicySetID || evaluation.PolicySetVersion != acceptedAssertionPolicySetVersion || evaluation.PolicyArtifactSHA256 != AcceptedAssertionPolicyArtifactSHA256 || evaluation.DiagnosticVocabularySHA256 != AcceptedAssertionDiagnosticVocabularySHA || !validAssertionDimension(evaluation.Dimension) {
		return "rejected", false
	}
	dimension := assertionDimension(policy, evaluation.Dimension)
	if dimension.State == "not_asserted" {
		return "not_observed", evaluation.Outcome == "not_observed" && evaluation.ReasonCode == dimension.ReasonCode
	}
	if evaluation.Dimension != "contract" || dimension.State != "asserted" {
		return "rejected", false
	}
	switch evaluation.Outcome {
	case "pass":
		return "accepted", evaluation.ReasonCode == "declared_response_fields_match"
	case "fail":
		return "accepted", evaluation.ReasonCode == "undeclared_response_field"
	case "not_observed":
		return "not_observed", evaluation.ReasonCode == "empty_payload_without_contract_observation"
	case "unknown":
		return "unknown", evaluation.ReasonCode == "invalid_or_stale_policy_binding" || evaluation.ReasonCode == "unsupported_or_unsafe_observation"
	default:
		return "rejected", false
	}
}

func diagnosisTemplate(contract DiagnosticContract, fixture string) (PublicDiagnosis, error) {
	raw, err := contract.ReadFixture(fixture)
	if err != nil {
		return PublicDiagnosis{}, err
	}
	envelope, err := contract.Decode(bytes.NewReader(raw))
	if err != nil {
		return PublicDiagnosis{}, err
	}
	projected := ProjectPublicDiagnosis(envelope)
	if projected.Code == "unknown" {
		return PublicDiagnosis{}, errors.New("accepted diagnosis template failed closed")
	}
	return projected, nil
}

func mergeDiagnosisCandidate(current, candidate DiagnosisSnapshotEntry) DiagnosisSnapshotEntry {
	currentDiagnoses := current.Diagnosis.Code != "unknown"
	candidateDiagnoses := candidate.Diagnosis.Code != "unknown"
	if currentDiagnoses && candidateDiagnoses {
		return unknownDiagnosisEntry(current.OperationID, current.OperationRevisionSHA256, "rejected")
	}
	if currentDiagnoses {
		return current
	}
	if candidateDiagnoses {
		return candidate
	}
	if current.EvidenceState == "rejected" {
		return current
	}
	if candidate.EvidenceState == "accepted" || (candidate.EvidenceState == "not_observed" && current.EvidenceState == "unknown") {
		return candidate
	}
	return current
}

func unknownDiagnosisEntry(operationID, revision, state string) DiagnosisSnapshotEntry {
	entry := DiagnosisSnapshotEntry{OperationID: operationID, OperationRevisionSHA256: revision, EvidenceState: state, Diagnosis: unknownPublicDiagnosis()}
	entry.ProjectionSHA256 = diagnosisEntryDigest(entry)
	return entry
}

func diagnosisEntryDigest(entry DiagnosisSnapshotEntry) string {
	entry.ProjectionSHA256 = ""
	raw, _ := json.Marshal(entry)
	return digest(raw)
}

func acceptedDiagnosisAssertionBinding() AssertionPolicyBinding {
	return AssertionPolicyBinding{Path: acceptedAssertionPolicyPath, PolicySetID: acceptedAssertionPolicySetID, ArtifactSHA256: AcceptedAssertionPolicyArtifactSHA256, PolicySetVersion: acceptedAssertionPolicySetVersion, DiagnosticVocabularySHA256: AcceptedAssertionDiagnosticVocabularySHA}
}

func countDiagnosisEntries(entries []DiagnosisSnapshotEntry) DiagnosisCounts {
	var counts DiagnosisCounts
	for _, entry := range entries {
		switch entry.EvidenceState {
		case "accepted":
			counts.Accepted++
		case "not_observed":
			counts.NotObserved++
		case "rejected":
			counts.Rejected++
		default:
			counts.Unknown++
		}
	}
	return counts
}

func WriteDiagnosisSnapshotAtomic(path string, snapshot DiagnosisSnapshot, contract AssertionPolicyContract) error {
	if !validDiagnosisSnapshotDocument(snapshot, contract) {
		return errors.New("diagnosis snapshot is invalid")
	}
	raw, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil || schemas.ValidateHealthPublicDiagnosisSnapshotV1(raw) != nil {
		return errors.New("diagnosis snapshot is invalid")
	}
	raw = append(raw, '\n')
	directory := filepath.Dir(path)
	temp, err := os.CreateTemp(directory, ".diagnosis-snapshot-*")
	if err != nil {
		return errors.New("diagnosis snapshot update failed")
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o644); err != nil {
		temp.Close()
		return errors.New("diagnosis snapshot update failed")
	}
	if _, err := temp.Write(raw); err != nil {
		temp.Close()
		return errors.New("diagnosis snapshot update failed")
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return errors.New("diagnosis snapshot update failed")
	}
	if err := temp.Close(); err != nil {
		return errors.New("diagnosis snapshot update failed")
	}
	if err := os.Rename(tempPath, path); err != nil {
		return errors.New("diagnosis snapshot update failed")
	}
	dir, err := os.Open(directory)
	if err == nil {
		err = dir.Sync()
		_ = dir.Close()
	}
	if err != nil {
		return errors.New("diagnosis snapshot update failed")
	}
	return nil
}

func validDiagnosisSnapshotDocument(snapshot DiagnosisSnapshot, contract AssertionPolicyContract) bool {
	if snapshot.SchemaVersion != DiagnosisSnapshotSchemaVersion || snapshot.GeneratedAt.IsZero() || snapshot.RegistryRevision != AcceptedAssertionRegistryRevision || snapshot.DiagnosticVocabularySHA256 != AcceptedAssertionDiagnosticVocabularySHA || snapshot.CorrelationRule != (CorrelationRuleReference{RuleID: AcceptedCorrelationRuleID, Version: 1, SHA256: AcceptedCorrelationRuleSHA256}) || !acceptedAssertionBinding(snapshot.AssertionPolicy) || len(snapshot.Operations) != len(contract.policyByOperation) {
		return false
	}
	ids := sortedOperationIDs(contract.policyByOperation)
	for index, entry := range snapshot.Operations {
		if index >= len(ids) || entry.OperationID != ids[index] || !validSnapshotEntry(entry, snapshot.GeneratedAt, contract) {
			return false
		}
	}
	return true
}

type rawDiagnosisSnapshot struct {
	SchemaVersion              string                   `json:"schema_version"`
	GeneratedAt                time.Time                `json:"generated_at"`
	RegistryRevision           string                   `json:"registry_revision"`
	DiagnosticVocabularySHA256 string                   `json:"diagnostic_vocabulary_sha256"`
	CorrelationRule            CorrelationRuleReference `json:"correlation_rule"`
	AssertionPolicy            AssertionPolicyBinding   `json:"assertion_policy"`
	Operations                 []json.RawMessage        `json:"operations"`
}

func ReadDiagnosisSnapshot(path string, now time.Time, contract AssertionPolicyContract) (DiagnosisSnapshot, DiagnosisCounts, error) {
	file, err := os.Open(path)
	if err != nil {
		return DiagnosisSnapshot{}, DiagnosisCounts{}, errors.New("diagnosis snapshot unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxDiagnosisSnapshotBytes {
		return DiagnosisSnapshot{}, DiagnosisCounts{}, errors.New("diagnosis snapshot unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxDiagnosisSnapshotBytes+1))
	if err != nil || len(raw) > maxDiagnosisSnapshotBytes {
		return DiagnosisSnapshot{}, DiagnosisCounts{}, errors.New("diagnosis snapshot unavailable")
	}
	var decoded rawDiagnosisSnapshot
	if decodeStrictBytes(raw, &decoded) != nil || decoded.SchemaVersion != DiagnosisSnapshotSchemaVersion || decoded.GeneratedAt.IsZero() || decoded.GeneratedAt.After(now.UTC().Add(diagnosisFutureSkew)) || decoded.RegistryRevision != AcceptedAssertionRegistryRevision || decoded.DiagnosticVocabularySHA256 != AcceptedAssertionDiagnosticVocabularySHA || decoded.CorrelationRule != (CorrelationRuleReference{RuleID: AcceptedCorrelationRuleID, Version: 1, SHA256: AcceptedCorrelationRuleSHA256}) || !acceptedAssertionBinding(decoded.AssertionPolicy) || len(decoded.Operations) > 20 {
		return DiagnosisSnapshot{}, DiagnosisCounts{}, errors.New("diagnosis snapshot unavailable")
	}
	byID := map[string]DiagnosisSnapshotEntry{}
	rejectedIDs := map[string]bool{}
	unknownRejected := 0
	for _, item := range decoded.Operations {
		var probe struct {
			OperationID string `json:"operation_id"`
		}
		_ = json.Unmarshal(item, &probe)
		var entry DiagnosisSnapshotEntry
		if decodeStrictBytes(item, &entry) != nil || !validSnapshotEntry(entry, now.UTC(), contract) {
			if _, known := contract.policyByOperation[probe.OperationID]; known {
				rejectedIDs[probe.OperationID] = true
			} else {
				unknownRejected++
			}
			continue
		}
		if _, duplicate := byID[entry.OperationID]; duplicate {
			rejectedIDs[entry.OperationID] = true
			delete(byID, entry.OperationID)
			continue
		}
		byID[entry.OperationID] = entry
	}
	snapshot := DiagnosisSnapshot{SchemaVersion: decoded.SchemaVersion, GeneratedAt: decoded.GeneratedAt, RegistryRevision: decoded.RegistryRevision, DiagnosticVocabularySHA256: decoded.DiagnosticVocabularySHA256, CorrelationRule: decoded.CorrelationRule, AssertionPolicy: decoded.AssertionPolicy}
	for _, id := range sortedOperationIDs(contract.policyByOperation) {
		policy := contract.policyByOperation[id]
		entry, ok := byID[id]
		if !ok || rejectedIDs[id] {
			state := "unknown"
			if rejectedIDs[id] {
				state = "rejected"
			}
			entry = unknownDiagnosisEntry(id, policy.OperationRevisionSHA256, state)
		}
		snapshot.Operations = append(snapshot.Operations, entry)
	}
	counts := countDiagnosisEntries(snapshot.Operations)
	counts.Rejected += unknownRejected
	return snapshot, counts, nil
}

func validSnapshotEntry(entry DiagnosisSnapshotEntry, now time.Time, contract AssertionPolicyContract) bool {
	policy, ok := contract.policyByOperation[entry.OperationID]
	if !ok || entry.OperationRevisionSHA256 != policy.OperationRevisionSHA256 || entry.ProjectionSHA256 != diagnosisEntryDigest(entry) || !validSnapshotState(entry.EvidenceState) || !validSnapshotDiagnosis(entry.Diagnosis) {
		return false
	}
	if entry.Source == nil {
		return entry.EvidenceState == "unknown" || entry.EvidenceState == "rejected"
	}
	if entry.AssessedAt == nil || entry.ValidUntil == nil || entry.AssessedAt.IsZero() || entry.ValidUntil.Before(*entry.AssessedAt) || entry.ValidUntil.Sub(*entry.AssessedAt) > maxDiagnosisEvidenceAge || entry.AssessedAt.After(now.Add(diagnosisFutureSkew)) {
		return false
	}
	if now.After(*entry.ValidUntil) {
		return false
	}
	if !sha256Pattern.MatchString(entry.Source.SHA256) {
		return false
	}
	if entry.Source.Kind == "correlation_receipt" {
		return entry.EvidenceState == "accepted" && entry.Source.SchemaVersion == CorrelationReceiptSchemaVersion && entry.Correlation != nil && entry.Assertion == nil && entry.Correlation.AffectedCount >= 2 && entry.Correlation.ControlCount >= 1 && entry.Diagnosis.Code == "provider_outage" && (entry.Diagnosis.Determination == "inferred" || entry.Diagnosis.Determination == "observed") && (entry.Diagnosis.Determination == "observed") == entry.Correlation.NoticeLinked
	}
	if entry.Source.Kind == "assertion_evaluation" {
		if entry.Source.SchemaVersion != AssertionEvaluationSchemaVersion || entry.Assertion == nil || entry.Correlation != nil || !validAssertionDimension(entry.Assertion.Dimension) {
			return false
		}
		switch entry.Assertion.Outcome {
		case "fail":
			return entry.EvidenceState == "accepted" && entry.Assertion.Dimension == "contract" && entry.Diagnosis.Code == "contract_drift"
		case "pass":
			return entry.EvidenceState == "accepted" && entry.Assertion.Dimension == "contract" && entry.Diagnosis.Code == "unknown"
		case "not_observed":
			return entry.EvidenceState == "not_observed" && entry.Diagnosis.Code == "unknown"
		case "unknown":
			return entry.EvidenceState == "unknown" && entry.Diagnosis.Code == "unknown"
		default:
			return false
		}
	}
	return false
}

func validSnapshotState(value string) bool {
	return value == "accepted" || value == "not_observed" || value == "unknown" || value == "rejected"
}
func validSnapshotDiagnosis(value PublicDiagnosis) bool {
	if value.Code == "unknown" {
		return value.Determination == "unknown" && value.AccountableParty == "unknown" && len(value.RecommendedActionIDs) == 0 && len(value.AvoidActionIDs) == 0
	}
	if value.Code != "provider_outage" && value.Code != "contract_drift" {
		return false
	}
	return validDetermination(value.Determination) && validAccountableParty(value.AccountableParty) && publicIDsValid(value.RecommendedActionIDs) && publicIDsValid(value.AvoidActionIDs)
}
func publicIDsValid(values []string) bool {
	_, ok := publicActionIDs(func() []publicAction {
		result := make([]publicAction, len(values))
		for i, id := range values {
			result[i].ActionID = id
		}
		return result
	}())
	return ok
}

type DiagnosisOverlaySource struct {
	base     PublicStatusSource
	path     string
	contract AssertionPolicyContract
	now      func() time.Time
}

func NewDiagnosisOverlaySource(base PublicStatusSource, path string, contract AssertionPolicyContract) (*DiagnosisOverlaySource, error) {
	if base == nil || path == "" {
		return nil, errors.New("availability source and diagnosis snapshot path are required")
	}
	return &DiagnosisOverlaySource{base: base, path: path, contract: contract, now: time.Now}, nil
}

func (s *DiagnosisOverlaySource) Snapshot(ctx context.Context) (PublicStatusDocument, error) {
	document, err := s.base.Snapshot(ctx)
	if err != nil {
		return PublicStatusDocument{}, err
	}
	document.Operations = append([]PublicOperationStatus(nil), document.Operations...)
	for index := range document.Operations {
		document.Operations[index].Diagnosis.RecommendedActionIDs = append([]string{}, document.Operations[index].Diagnosis.RecommendedActionIDs...)
		document.Operations[index].Diagnosis.AvoidActionIDs = append([]string{}, document.Operations[index].Diagnosis.AvoidActionIDs...)
	}
	snapshot, _, err := ReadDiagnosisSnapshot(s.path, s.now().UTC(), s.contract)
	if err != nil {
		return document, nil
	}
	byID := map[string]DiagnosisSnapshotEntry{}
	for _, entry := range snapshot.Operations {
		byID[entry.OperationID] = entry
	}
	for index := range document.Operations {
		entry, ok := byID[document.Operations[index].OperationID]
		if ok && entry.EvidenceState == "accepted" {
			document.Operations[index].Diagnosis = entry.Diagnosis
		}
	}
	return document, nil
}

func (c DiagnosisCounts) String() string {
	return fmt.Sprintf("accepted=%d not_observed=%d unknown=%d rejected=%d", c.Accepted, c.NotObserved, c.Unknown, c.Rejected)
}
