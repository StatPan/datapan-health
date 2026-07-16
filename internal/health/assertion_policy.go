package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	AssertionPolicyPinVersion                = "datapan.health-assertion-policy-contract-pin.v1"
	AssertionPolicySchemaVersion             = "datapan.operation-assertion-policies.v1"
	AssertionEvaluationSchemaVersion         = "datapan.health-assertion-evaluation.v1"
	AcceptedAssertionRegistryRevision        = "f90d2d62258e50d562ff08b993c75bc0a4dad6fa"
	AcceptedAssertionSchemaSHA256            = "a934fe244eeedbed23914ba1230d612b68656f9dc97803c747cf9f29c46c0446"
	AcceptedAssertionPolicyFileSHA256        = "62d54df23a55dc529b60947c944bebef82f6697f44472ae0f20c2a06781704e6"
	AcceptedAssertionPolicyArtifactSHA256    = "d9b39f40e2068180cf46ebf8eca2037aeff19523b76f648bb06666758ed8c1d3"
	AcceptedAssertionReferenceProofSHA256    = "edd7ab5c63c39c30801bd145e5dfc521f9910542da2f3b766ef2928e1a5841d2"
	AcceptedAssertionReleaseCandidateSHA256  = "82bc523016abfa356f931e5786af9714ca544d83a26a515830471f242705a466"
	AcceptedAssertionDiagnosticVocabularySHA = "aa03c42960a59725b829b934ad07548dacb8f149c7a920a35a9e32c0459b49fc"
	acceptedAssertionPolicyPath              = "drafts/operation-assertion-policies/operation-assertion-policies.v1.json"
	acceptedAssertionPolicySetID             = "datapan-health-canary-assertions"
	acceptedAssertionPolicySetVersion        = 1
	maxAssertionEvaluationBytes              = 64 * 1024
)

var safeResponseFieldPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)

type AssertionPolicyContract struct {
	RegistryRevision  string
	Schema            ArtifactPin
	Policy            ArtifactPin
	ReferenceProof    ArtifactPin
	ReleaseCandidate  ArtifactPin
	PolicySet         AssertionPolicySet
	policyByOperation map[string]AssertionOperationPolicy
}

type assertionPolicyContractPin struct {
	SchemaVersion    string      `json:"schema_version"`
	RegistryRevision string      `json:"registry_revision"`
	SchemaContract   ArtifactPin `json:"schema_contract"`
	PolicyContract   ArtifactPin `json:"policy_contract"`
	ReferenceProof   ArtifactPin `json:"reference_proof"`
	ReleaseCandidate ArtifactPin `json:"release_candidate"`
}

type assertionPolicyDocument struct {
	SchemaVersion string             `json:"schema_version"`
	GeneratedAt   string             `json:"generated_at"`
	Authority     string             `json:"authority"`
	PolicySet     AssertionPolicySet `json:"policy_set"`
	Bindings      struct {
		Registry           ArtifactPin `json:"registry"`
		HealthProbeCatalog ArtifactPin `json:"health_probe_catalog"`
	} `json:"bindings"`
	DiagnosticVocabulary struct {
		SchemaVersion string `json:"schema_version"`
		Path          string `json:"path"`
		SHA256        string `json:"sha256"`
	} `json:"diagnostic_vocabulary"`
	Operations     []AssertionOperationPolicy `json:"operations"`
	ArtifactSHA256 string                     `json:"artifact_sha256"`
}

type AssertionPolicySet struct {
	ID         string                     `json:"id"`
	Version    int                        `json:"version"`
	Supersedes *AssertionPolicySupersedes `json:"supersedes"`
}

type AssertionPolicySupersedes struct {
	PolicySetVersion int    `json:"policy_set_version"`
	ArtifactSHA256   string `json:"artifact_sha256"`
}

type AssertionOperationPolicy struct {
	OperationID             string `json:"operation_id"`
	OperationRevisionSHA256 string `json:"operation_revision_sha256"`
	Dimensions              struct {
		Transport AssertionDimensionPolicy `json:"transport"`
		Contract  AssertionDimensionPolicy `json:"contract"`
		Presence  AssertionDimensionPolicy `json:"presence"`
		Semantic  AssertionDimensionPolicy `json:"semantic"`
		Freshness AssertionDimensionPolicy `json:"freshness"`
	} `json:"dimensions"`
}

type AssertionDimensionPolicy struct {
	State                  string             `json:"state"`
	ReasonCode             string             `json:"reason_code,omitempty"`
	AssertionType          string             `json:"assertion_type,omitempty"`
	ProjectionInput        string             `json:"projection_input,omitempty"`
	DeclaredResponseFields []string           `json:"declared_response_fields,omitempty"`
	UnknownFieldPolicy     string             `json:"unknown_field_policy,omitempty"`
	EmptyPayloadPolicy     string             `json:"empty_payload_policy,omitempty"`
	Evidence               *AssertionEvidence `json:"evidence"`
}

type AssertionEvidence struct {
	Kind          string `json:"kind"`
	RationaleCode string `json:"rationale_code"`
	Path          string `json:"path"`
	SHA256        string `json:"sha256"`
	Selector      struct {
		DatasetID            string `json:"dataset_id"`
		OperationName        string `json:"operation_name"`
		UpstreamOperationSeq string `json:"upstream_operation_seq"`
	} `json:"selector"`
}

type AssertionPolicyBinding struct {
	Path                       string `json:"path"`
	PolicySetID                string `json:"policy_set_id"`
	ArtifactSHA256             string `json:"artifact_sha256"`
	PolicySetVersion           int    `json:"policy_set_version"`
	DiagnosticVocabularySHA256 string `json:"diagnostic_vocabulary_sha256"`
}

type AssertionEvaluationRequest struct {
	SchemaVersion           string                  `json:"schema_version"`
	OperationID             string                  `json:"operation_id"`
	OperationRevisionSHA256 string                  `json:"operation_revision_sha256"`
	Dimension               string                  `json:"dimension"`
	PolicyBinding           *AssertionPolicyBinding `json:"policy_binding"`
	ActivePolicyBinding     *AssertionPolicyBinding `json:"active_policy_binding,omitempty"`
	Observation             AssertionObservation    `json:"observation"`
}

// AssertionObservation deliberately contains field names only. Provider rows,
// values, URLs, status codes, timestamps, and credentials are not accepted.
type AssertionObservation struct {
	ResponseFields []string `json:"response_fields,omitempty"`
}

type AssertionEvaluation struct {
	SchemaVersion              string `json:"schema_version"`
	RegistryRevision           string `json:"registry_revision"`
	OperationID                string `json:"operation_id"`
	OperationRevisionSHA256    string `json:"operation_revision_sha256,omitempty"`
	Dimension                  string `json:"dimension"`
	PolicySetID                string `json:"policy_set_id"`
	PolicySetVersion           int    `json:"policy_set_version"`
	PolicyArtifactSHA256       string `json:"policy_artifact_sha256"`
	DiagnosticVocabularySHA256 string `json:"diagnostic_vocabulary_sha256"`
	Outcome                    string `json:"outcome"`
	ReasonCode                 string `json:"reason_code"`
	ObservedFieldCount         int    `json:"observed_field_count,omitempty"`
}

func LoadAssertionPolicyContract(path string, canaries CanaryConfig) (AssertionPolicyContract, error) {
	var pin assertionPolicyContractPin
	if err := decodeStrictFile(path, &pin); err != nil {
		return AssertionPolicyContract{}, errors.New("invalid assertion policy contract pin")
	}
	if pin.SchemaVersion != AssertionPolicyPinVersion || pin.RegistryRevision != AcceptedAssertionRegistryRevision {
		return AssertionPolicyContract{}, errors.New("unsupported assertion policy contract pin")
	}
	wants := []struct {
		pin  ArtifactPin
		want string
	}{
		{pin.SchemaContract, AcceptedAssertionSchemaSHA256},
		{pin.PolicyContract, AcceptedAssertionPolicyFileSHA256},
		{pin.ReferenceProof, AcceptedAssertionReferenceProofSHA256},
		{pin.ReleaseCandidate, AcceptedAssertionReleaseCandidateSHA256},
	}
	base := filepath.Dir(path)
	artifacts := make([][]byte, 0, len(wants))
	for _, item := range wants {
		if item.pin.SHA256 != item.want || !safeRelativePath(item.pin.Path) {
			return AssertionPolicyContract{}, errors.New("unsupported assertion policy artifact pin")
		}
		raw, err := os.ReadFile(filepath.Join(base, item.pin.Path))
		if err != nil || digest(raw) != item.want {
			return AssertionPolicyContract{}, errors.New("assertion policy artifact digest does not match pin")
		}
		artifacts = append(artifacts, raw)
	}

	var schemaDocument any
	if err := json.Unmarshal(artifacts[0], &schemaDocument); err != nil {
		return AssertionPolicyContract{}, errors.New("invalid assertion policy schema")
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource("https://schemas.datapan.dev/datapan.operation-assertion-policies.v1.schema.json", schemaDocument); err != nil {
		return AssertionPolicyContract{}, errors.New("invalid assertion policy schema")
	}
	schema, err := compiler.Compile("https://schemas.datapan.dev/datapan.operation-assertion-policies.v1.schema.json")
	if err != nil {
		return AssertionPolicyContract{}, errors.New("invalid assertion policy schema")
	}
	var policyValue any
	if err := json.Unmarshal(artifacts[1], &policyValue); err != nil || schema.Validate(policyValue) != nil {
		return AssertionPolicyContract{}, errors.New("policy does not match the pinned schema")
	}
	var policy assertionPolicyDocument
	if err := decodeStrictBytes(artifacts[1], &policy); err != nil {
		return AssertionPolicyContract{}, errors.New("invalid assertion policy document")
	}
	if err := validateAssertionPolicyDocument(policy, canaries); err != nil {
		return AssertionPolicyContract{}, err
	}
	if err := validateAssertionReferenceProof(artifacts[2]); err != nil {
		return AssertionPolicyContract{}, err
	}
	if err := validateAssertionReleaseCandidate(artifacts[3]); err != nil {
		return AssertionPolicyContract{}, err
	}
	byOperation := make(map[string]AssertionOperationPolicy, len(policy.Operations))
	for _, operation := range policy.Operations {
		byOperation[operation.OperationID] = operation
	}
	return AssertionPolicyContract{
		RegistryRevision: pin.RegistryRevision, Schema: pin.SchemaContract, Policy: pin.PolicyContract,
		ReferenceProof: pin.ReferenceProof, ReleaseCandidate: pin.ReleaseCandidate,
		PolicySet: policy.PolicySet, policyByOperation: byOperation,
	}, nil
}

func validateAssertionPolicyDocument(policy assertionPolicyDocument, canaries CanaryConfig) error {
	if policy.SchemaVersion != AssertionPolicySchemaVersion || policy.Authority != "datapan-registry" || policy.ArtifactSHA256 != AcceptedAssertionPolicyArtifactSHA256 || policy.PolicySet.ID != acceptedAssertionPolicySetID || policy.PolicySet.Version != acceptedAssertionPolicySetVersion || policy.PolicySet.Supersedes != nil || policy.Bindings.Registry.SHA256 != "eeda72ee8590f458de8d75703662578e80edf3e61282f0e5e67547c4f6e5f644" || policy.Bindings.HealthProbeCatalog.SHA256 != AcceptedHealthProbeCatalogSHA256 || policy.Bindings.HealthProbeCatalog.SHA256 != canaries.CatalogSHA256 || policy.DiagnosticVocabulary.SHA256 != AcceptedAssertionDiagnosticVocabularySHA {
		return errors.New("unsupported assertion policy document")
	}
	if len(policy.Operations) != len(canaries.Canaries) {
		return errors.New("assertion policy does not cover the exact canary set")
	}
	seen := make(map[string]bool, len(policy.Operations))
	for _, operation := range policy.Operations {
		if seen[operation.OperationID] || !sha256Pattern.MatchString(operation.OperationRevisionSHA256) {
			return errors.New("invalid assertion operation identity")
		}
		seen[operation.OperationID] = true
		var canary Canary
		found := false
		for _, candidate := range canaries.Canaries {
			if candidate.OperationID == operation.OperationID {
				canary, found = candidate, true
				break
			}
		}
		entry, ok := canaries.Entry(canary)
		if !found || !ok || !validAssertionDimensions(operation.Dimensions, entry) {
			return errors.New("assertion policy operation does not match the exact Health catalog")
		}
	}
	return nil
}

func validAssertionDimensions(dimensions struct {
	Transport AssertionDimensionPolicy `json:"transport"`
	Contract  AssertionDimensionPolicy `json:"contract"`
	Presence  AssertionDimensionPolicy `json:"presence"`
	Semantic  AssertionDimensionPolicy `json:"semantic"`
	Freshness AssertionDimensionPolicy `json:"freshness"`
}, entry CatalogEntry) bool {
	for _, item := range []struct {
		policy AssertionDimensionPolicy
		reason string
	}{
		{dimensions.Transport, "provider_transport_expectation_not_reviewed"},
		{dimensions.Presence, "record_presence_expectation_not_reviewed"},
		{dimensions.Semantic, "domain_semantics_not_reviewed"},
		{dimensions.Freshness, "upstream_timestamp_contract_not_reviewed"},
	} {
		if item.policy.State != "not_asserted" || item.policy.ReasonCode != item.reason || item.policy.Evidence != nil {
			return false
		}
	}
	contract := dimensions.Contract
	if contract.State != "asserted" || contract.AssertionType != "declared_response_field_vocabulary" || contract.ProjectionInput != "normalized_leaf_field_names" || contract.UnknownFieldPolicy != "fail" || contract.EmptyPayloadPolicy != "not_observed" || len(contract.DeclaredResponseFields) == 0 || contract.Evidence == nil {
		return false
	}
	if contract.Evidence.Kind != "registry_operation_contract" || contract.Evidence.Path != "data/data-go-kr.registry.json" || contract.Evidence.SHA256 != "eeda72ee8590f458de8d75703662578e80edf3e61282f0e5e67547c4f6e5f644" || contract.Evidence.Selector.DatasetID != entry.Aliases.DatasetID || contract.Evidence.Selector.OperationName != entry.Aliases.OperationName {
		return false
	}
	return uniqueSafeFields(contract.DeclaredResponseFields)
}

func validateAssertionReferenceProof(raw []byte) error {
	var proof struct {
		SchemaVersion  string                 `json:"schema_version"`
		ProofKind      string                 `json:"proof_kind"`
		Producer       string                 `json:"producer"`
		ConsumerStatus string                 `json:"consumer_status"`
		PolicyBinding  AssertionPolicyBinding `json:"policy_binding"`
		Cases          []json.RawMessage      `json:"cases"`
	}
	if err := json.Unmarshal(raw, &proof); err != nil || proof.SchemaVersion != "datapan.operation-assertion-policy-reference-model.v1" || proof.ProofKind != "reference_model_only" || proof.Producer != "datapan-registry" || proof.ConsumerStatus != "not_executed_by_datapan_health" || len(proof.Cases) != 7 || !acceptedAssertionBinding(proof.PolicyBinding) {
		return errors.New("unsupported assertion policy reference proof")
	}
	return nil
}

func validateAssertionReleaseCandidate(raw []byte) error {
	var candidate struct {
		SchemaVersion  string                                      `json:"schema_version"`
		Status         string                                      `json:"status"`
		Authority      struct{ Release, Runtime, Publishing bool } `json:"authority"`
		PolicySet      AssertionPolicySet                          `json:"policy_set"`
		ArtifactSHA256 string                                      `json:"artifact_sha256"`
		Bindings       []ArtifactPin                               `json:"bindings"`
		NextGate       string                                      `json:"next_gate"`
	}
	if err := json.Unmarshal(raw, &candidate); err != nil || candidate.SchemaVersion != "datapan.operation-assertion-policy-release-candidate.v1" || candidate.Status != "ready_for_health_implementation_review" || candidate.Authority.Release || candidate.Authority.Runtime || candidate.Authority.Publishing || candidate.PolicySet.ID != acceptedAssertionPolicySetID || candidate.PolicySet.Version != 1 || candidate.PolicySet.Supersedes != nil || candidate.ArtifactSHA256 != AcceptedAssertionPolicyArtifactSHA256 || len(candidate.Bindings) != 4 || candidate.NextGate != "datapan_health_exact_revision_compatibility_proof" {
		return errors.New("unsupported assertion policy release candidate")
	}
	expected := map[string]string{
		"drafts/operation-assertion-policies/datapan.operation-assertion-policies.v1.schema.json": AcceptedAssertionSchemaSHA256,
		acceptedAssertionPolicyPath: AcceptedAssertionPolicyFileSHA256,
		"fixtures/operation-assertion-policies/datapan-health-consumer-proof.v1.json": AcceptedAssertionReferenceProofSHA256,
		"drafts/operation-assertion-policies/release-manifest.v1.json":                "282b17459c91c9c3a921eaed3eebf85c59bfca02057e44f36269ba3c59545338",
	}
	for _, binding := range candidate.Bindings {
		if expected[binding.Path] != binding.SHA256 {
			return errors.New("unsupported assertion policy release candidate binding")
		}
		delete(expected, binding.Path)
	}
	if len(expected) != 0 {
		return errors.New("incomplete assertion policy release candidate bindings")
	}
	return nil
}

func DecodeAssertionEvaluationRequest(reader io.Reader) (AssertionEvaluationRequest, error) {
	limited := io.LimitReader(reader, maxAssertionEvaluationBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) > maxAssertionEvaluationBytes {
		return AssertionEvaluationRequest{}, errors.New("assertion evaluation request could not be read")
	}
	var request AssertionEvaluationRequest
	if err := decodeStrictBytes(raw, &request); err != nil || request.SchemaVersion != AssertionEvaluationSchemaVersion || request.OperationID == "" || !sha256Pattern.MatchString(request.OperationRevisionSHA256) || !validAssertionDimension(request.Dimension) || !uniqueSafeFields(request.Observation.ResponseFields) {
		return AssertionEvaluationRequest{}, errors.New("unsupported assertion evaluation request")
	}
	return request, nil
}

func (c AssertionPolicyContract) Evaluate(request AssertionEvaluationRequest) AssertionEvaluation {
	result := AssertionEvaluation{
		SchemaVersion: AssertionEvaluationSchemaVersion, RegistryRevision: c.RegistryRevision,
		OperationID: request.OperationID, Dimension: request.Dimension,
		PolicySetID: c.PolicySet.ID, PolicySetVersion: c.PolicySet.Version,
		PolicyArtifactSHA256:       AcceptedAssertionPolicyArtifactSHA256,
		DiagnosticVocabularySHA256: AcceptedAssertionDiagnosticVocabularySHA,
		Outcome:                    "unknown", ReasonCode: "invalid_or_stale_policy_binding",
	}
	if request.SchemaVersion != AssertionEvaluationSchemaVersion || !sha256Pattern.MatchString(request.OperationRevisionSHA256) || !validAssertionDimension(request.Dimension) || !uniqueSafeFields(request.Observation.ResponseFields) {
		result.ReasonCode = "unsupported_or_unsafe_observation"
		return result
	}
	policy, ok := c.policyByOperation[request.OperationID]
	if !ok || request.OperationRevisionSHA256 != policy.OperationRevisionSHA256 || request.PolicyBinding == nil || !acceptedAssertionBinding(*request.PolicyBinding) || (request.ActivePolicyBinding != nil && !sameAssertionBinding(*request.PolicyBinding, *request.ActivePolicyBinding)) {
		return result
	}
	result.OperationRevisionSHA256 = policy.OperationRevisionSHA256
	dimension := assertionDimension(policy, request.Dimension)
	if dimension.State == "not_asserted" {
		result.Outcome, result.ReasonCode = "not_observed", dimension.ReasonCode
		return result
	}
	if request.Dimension != "contract" || dimension.State != "asserted" {
		return result
	}
	result.ObservedFieldCount = len(request.Observation.ResponseFields)
	if len(request.Observation.ResponseFields) == 0 {
		result.Outcome, result.ReasonCode = "not_observed", "empty_payload_without_contract_observation"
		return result
	}
	declared := make(map[string]bool, len(dimension.DeclaredResponseFields))
	for _, field := range dimension.DeclaredResponseFields {
		declared[field] = true
	}
	for _, field := range request.Observation.ResponseFields {
		if !declared[field] {
			result.Outcome, result.ReasonCode = "fail", "undeclared_response_field"
			return result
		}
	}
	result.Outcome, result.ReasonCode = "pass", "declared_response_fields_match"
	return result
}

func assertionDimension(policy AssertionOperationPolicy, dimension string) AssertionDimensionPolicy {
	switch dimension {
	case "transport":
		return policy.Dimensions.Transport
	case "contract":
		return policy.Dimensions.Contract
	case "presence":
		return policy.Dimensions.Presence
	case "semantic":
		return policy.Dimensions.Semantic
	case "freshness":
		return policy.Dimensions.Freshness
	default:
		return AssertionDimensionPolicy{}
	}
}

func acceptedAssertionBinding(binding AssertionPolicyBinding) bool {
	return binding.Path == acceptedAssertionPolicyPath && binding.PolicySetID == acceptedAssertionPolicySetID && binding.ArtifactSHA256 == AcceptedAssertionPolicyArtifactSHA256 && binding.PolicySetVersion == acceptedAssertionPolicySetVersion && binding.DiagnosticVocabularySHA256 == AcceptedAssertionDiagnosticVocabularySHA
}

func sameAssertionBinding(left, right AssertionPolicyBinding) bool { return left == right }

func validAssertionDimension(value string) bool {
	switch value {
	case "transport", "contract", "presence", "semantic", "freshness":
		return true
	}
	return false
}

func uniqueSafeFields(fields []string) bool {
	seen := make(map[string]bool, len(fields))
	for _, field := range fields {
		lower := strings.ToLower(field)
		if !safeResponseFieldPattern.MatchString(field) || secretHashPattern.MatchString(field) || strings.Contains(lower, "secret") || strings.Contains(lower, "token") || strings.Contains(lower, "password") || strings.Contains(lower, "authorization") || strings.Contains(lower, "servicekey") || strings.Contains(lower, "url") || seen[field] {
			return false
		}
		seen[field] = true
	}
	return true
}

func decodeStrictFile(path string, target any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return decodeStrictBytes(raw, target)
}

func decodeStrictBytes(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return ensureEOF(decoder)
}

func sortedOperationIDs(values map[string]AssertionOperationPolicy) []string {
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
