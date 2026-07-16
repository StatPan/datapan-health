package health

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
)

const AssertionCompatibilityReceiptVersion = "datapan.health-assertion-policy-compatibility-receipt.v1"

type AssertionCompatibilityReceipt struct {
	SchemaVersion    string                           `json:"schema_version"`
	Status           string                           `json:"status"`
	HealthHead       string                           `json:"health_head"`
	TestedRevision   string                           `json:"tested_revision"`
	RegistryRevision string                           `json:"registry_revision"`
	Contracts        AssertionCompatibilityPins       `json:"contracts"`
	Policy           AssertionPolicyBinding           `json:"policy"`
	Operations       []AssertionOperationProof        `json:"operations"`
	Cases            []AssertionCompatibilityCase     `json:"cases"`
	SourceProof      AssertionSourceProof             `json:"source_proof"`
	Boundaries       AssertionCompatibilityBoundaries `json:"boundaries"`
}

type AssertionCompatibilityPins struct {
	Schema           ArtifactPin `json:"schema"`
	Policy           ArtifactPin `json:"policy"`
	ReferenceProof   ArtifactPin `json:"reference_proof"`
	ReleaseCandidate ArtifactPin `json:"release_candidate"`
}

type AssertionOperationProof struct {
	OperationID             string `json:"operation_id"`
	OperationRevisionSHA256 string `json:"operation_revision_sha256"`
	Contract                string `json:"contract"`
	Presence                string `json:"presence"`
	Semantic                string `json:"semantic"`
	Freshness               string `json:"freshness"`
}

type AssertionCompatibilityCase struct {
	Name      string `json:"name"`
	Dimension string `json:"dimension"`
	Expected  string `json:"expected"`
	Observed  string `json:"observed"`
}

type AssertionSourceProof struct {
	Sources []ArtifactPin `json:"sources"`
	Tests   []string      `json:"tests"`
}

type AssertionCompatibilityBoundaries struct {
	AvailabilityV1    string `json:"availability_v1"`
	ArchiveV1         string `json:"archive_v1"`
	SensitiveEvidence string `json:"sensitive_evidence"`
	ProviderRuntime   string `json:"provider_runtime"`
	Deployment        string `json:"deployment"`
}

func BuildAssertionCompatibilityReceipt(healthHead, testedRevision, repoRoot string, contract AssertionPolicyContract) (AssertionCompatibilityReceipt, error) {
	if !commitPattern.MatchString(healthHead) || !commitPattern.MatchString(testedRevision) {
		return AssertionCompatibilityReceipt{}, errors.New("health head and tested revision must be exact commits")
	}
	binding := AssertionPolicyBinding{Path: acceptedAssertionPolicyPath, PolicySetID: acceptedAssertionPolicySetID, ArtifactSHA256: AcceptedAssertionPolicyArtifactSHA256, PolicySetVersion: acceptedAssertionPolicySetVersion, DiagnosticVocabularySHA256: AcceptedAssertionDiagnosticVocabularySHA}
	operations := make([]AssertionOperationProof, 0, len(contract.policyByOperation))
	for _, id := range sortedOperationIDs(contract.policyByOperation) {
		operation := contract.policyByOperation[id]
		operations = append(operations, AssertionOperationProof{OperationID: id, OperationRevisionSHA256: operation.OperationRevisionSHA256, Contract: operation.Dimensions.Contract.State, Presence: operation.Dimensions.Presence.State, Semantic: operation.Dimensions.Semantic.State, Freshness: operation.Dimensions.Freshness.State})
	}
	if len(operations) != 10 {
		return AssertionCompatibilityReceipt{}, errors.New("compatibility receipt requires the exact operation set")
	}
	cases := buildAssertionCompatibilityCases(contract, binding)
	for _, item := range cases {
		if item.Observed != item.Expected {
			return AssertionCompatibilityReceipt{}, errors.New("assertion compatibility case failed")
		}
	}
	sourceProof, err := buildAssertionSourceProof(repoRoot)
	if err != nil {
		return AssertionCompatibilityReceipt{}, err
	}
	return AssertionCompatibilityReceipt{
		SchemaVersion: AssertionCompatibilityReceiptVersion, Status: "consumer_compatible",
		HealthHead: healthHead, TestedRevision: testedRevision, RegistryRevision: contract.RegistryRevision,
		Contracts: AssertionCompatibilityPins{Schema: contract.Schema, Policy: contract.Policy, ReferenceProof: contract.ReferenceProof, ReleaseCandidate: contract.ReleaseCandidate},
		Policy:    binding, Operations: operations, Cases: cases, SourceProof: sourceProof,
		Boundaries: AssertionCompatibilityBoundaries{AvailabilityV1: "unchanged", ArchiveV1: "unchanged", SensitiveEvidence: "field_names_only_strict_decoder", ProviderRuntime: "not_invoked", Deployment: "not_performed"},
	}, nil
}

func buildAssertionCompatibilityCases(contract AssertionPolicyContract, binding AssertionPolicyBinding) []AssertionCompatibilityCase {
	base := AssertionEvaluationRequest{SchemaVersion: AssertionEvaluationSchemaVersion, OperationID: "dpr-op-00000001", OperationRevisionSHA256: contract.policyByOperation["dpr-op-00000001"].OperationRevisionSHA256, Dimension: "contract", PolicyBinding: &binding}
	caseFor := func(name, dimension, expected string, fields []string, mutate func(*AssertionEvaluationRequest)) AssertionCompatibilityCase {
		request := base
		request.Dimension = dimension
		request.Observation.ResponseFields = fields
		bindingCopy := binding
		request.PolicyBinding = &bindingCopy
		if mutate != nil {
			mutate(&request)
		}
		return AssertionCompatibilityCase{Name: name, Dimension: dimension, Expected: expected, Observed: contract.Evaluate(request).Outcome}
	}
	return []AssertionCompatibilityCase{
		caseFor("contract_match", "contract", "pass", []string{"dutyAddr"}, nil),
		caseFor("contract_mismatch", "contract", "fail", []string{"__undeclared_field__"}, nil),
		caseFor("empty_contract_observation", "contract", "not_observed", nil, nil),
		caseFor("presence_not_asserted", "presence", "not_observed", nil, nil),
		caseFor("semantic_not_asserted", "semantic", "not_observed", nil, nil),
		caseFor("freshness_not_asserted", "freshness", "not_observed", nil, nil),
		caseFor("missing_binding", "contract", "unknown", []string{"dutyAddr"}, func(request *AssertionEvaluationRequest) { request.PolicyBinding = nil }),
		caseFor("stale_artifact", "contract", "unknown", []string{"dutyAddr"}, func(request *AssertionEvaluationRequest) {
			request.PolicyBinding.ArtifactSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}),
		caseFor("unsupported_version", "contract", "unknown", []string{"dutyAddr"}, func(request *AssertionEvaluationRequest) { request.PolicyBinding.PolicySetVersion = 2 }),
		caseFor("vocabulary_mismatch", "contract", "unknown", []string{"dutyAddr"}, func(request *AssertionEvaluationRequest) {
			request.PolicyBinding.DiagnosticVocabularySHA256 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
		}),
		caseFor("superseded_binding", "contract", "unknown", []string{"dutyAddr"}, func(request *AssertionEvaluationRequest) {
			active := binding
			active.PolicySetVersion = 2
			active.ArtifactSHA256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			request.ActivePolicyBinding = &active
		}),
	}
}

func buildAssertionSourceProof(repoRoot string) (AssertionSourceProof, error) {
	paths := []string{"internal/health/assertion_policy.go", "internal/health/assertion_policy_test.go"}
	sources := make([]ArtifactPin, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(filepath.Join(repoRoot, path))
		if err != nil {
			return AssertionSourceProof{}, err
		}
		sources = append(sources, ArtifactPin{Path: path, SHA256: digest(raw)})
	}
	testPath := filepath.Join(repoRoot, "internal/health/assertion_policy_test.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), testPath, nil, 0)
	if err != nil {
		return AssertionSourceProof{}, errors.New("assertion tests cannot be parsed")
	}
	var tests []string
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv == nil && len(function.Name.Name) > len("TestAssertionPolicy") && function.Name.Name[:len("TestAssertionPolicy")] == "TestAssertionPolicy" {
			tests = append(tests, function.Name.Name)
		}
	}
	sort.Strings(tests)
	if len(tests) < 7 {
		return AssertionSourceProof{}, errors.New("assertion compatibility test proof is incomplete")
	}
	return AssertionSourceProof{Sources: sources, Tests: tests}, nil
}
