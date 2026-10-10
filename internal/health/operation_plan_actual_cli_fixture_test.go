package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/internal/runtimebundle"
	"github.com/StatPan/datapan-health/schemas"
)

const (
	actualCLIPolicyPath                      = "policy/operation-observation-policies.v1.json"
	actualCLIPlanIndexPath                   = "reports/operation-observation-plan/index.json"
	actualCLISourceRegistryPath              = "data/data-go-kr.registry.json"
	actualCLIRuntimeBindingPath              = "r.json"
	actualCLISourceCapturePath               = "c.txt"
	actualCLIAssertionPrefix                 = "reports/operation-response-assertions/"
	actualCLIDocumentPrefix                  = "d/"
	actualCLIFixtureProviderIP               = "45.77.0.2"
	actualCLIFixturePort                     = 8080
	actualCLIFixtureRequestTimeoutMS         = int64(1000)
	actualCLIFixtureProcessOverheadSeconds   = int64(5)
	actualCLIFixtureConcurrencyLimit         = int64(8)
	actualCLIFixtureObservationPeriodSeconds = int64(14400)
)

const actualCLIFixtureTimestamp = "2026-10-10T00:00:00Z"

type actualCLIManifest struct {
	SchemaVersion  string                            `json:"schema_version"`
	GeneratedAt    string                            `json:"generated_at"`
	DatapanVersion string                            `json:"datapan_version"`
	Provider       string                            `json:"provider"`
	SourceRegistry string                            `json:"source_registry"`
	OutputDir      string                            `json:"output_dir"`
	ArtifactCount  int                               `json:"artifact_count"`
	Artifacts      []RegistryReleaseManifestArtifact `json:"artifacts"`
}

type actualCLIDocumentArtifact struct {
	path  string
	sha   string
	bytes int64
}

func TestOperationPlanActualCLIEvidenceFixtureLoads(t *testing.T) {
	if os.Getenv("HEALTH_OPERATION_ACTUAL_CLI_FIXTURE_TEST") != "1" {
		t.Skip("set HEALTH_OPERATION_ACTUAL_CLI_FIXTURE_TEST=1 for bounded full-population fixture closure validation")
	}
	sourceRoot := strings.TrimSpace(os.Getenv("HEALTH_OPERATION_ACTUAL_CLI_SOURCE"))
	if !filepath.IsAbs(sourceRoot) {
		t.Fatal("HEALTH_OPERATION_ACTUAL_CLI_SOURCE must name the exact clean pinned CLI source checkout")
	}
	metadata, _, basePlan, planRoot, identities := loadManifestDerivedPopulationPlan(t)
	plan := bindActualCLIEvidenceFixture(t, sourceRoot, planRoot, basePlan, metadata, identities)
	lock := actualCLIRuntimeLock(strings.Repeat("a", 64), actualCLIExpectedSourceRevision, plan)
	if err := lock.Validate(); err != nil {
		t.Fatalf("actual-CLI fixture runtime lock does not validate: %v", err)
	}
	t.Logf("actual-CLI fixture closure validated: identities=%d executable=%d manifest_sha=%s index_sha=%s", len(identities), plan.ExecutableOperations(), plan.binding.ReleaseManifestSHA256, plan.IndexSHA256())
}

// bindActualCLIEvidenceFixture creates a credential-free, source-QA-only
// closure around the exact pinned Registry identity population. All request
// targets resolve to the local synthetic provider; no captured provider data,
// credentials, or provider behavior claims are included.
func bindActualCLIEvidenceFixture(t *testing.T, sourceRoot, planRoot string, basePlan PinnedOperationObservationPlan, metadata VerifiedRegistryAPIMetadata, identities []operationPlanPopulationIdentity) PinnedOperationObservationPlan {
	t.Helper()
	if sourceRoot == "" || planRoot == "" || basePlan.state == nil || !basePlan.state.verified || !metadata.verified || len(identities) != 12666 {
		t.Fatal("actual-CLI fixture requires the verified full population and pinned source inputs")
	}
	const expectedRevision = actualCLIExpectedSourceRevision
	output, err := exec.Command("git", "-C", sourceRoot, "rev-parse", "HEAD").Output()
	if err != nil || strings.TrimSpace(string(output)) != expectedRevision {
		t.Fatal("actual-CLI fixture source schemas are not from the exact pinned CLI revision")
	}
	status, err := exec.Command("git", "-C", sourceRoot, "status", "--porcelain", "--untracked-files=all").Output()
	if err != nil || len(status) != 0 {
		t.Fatal("actual-CLI fixture source schema checkout must be clean")
	}
	if filepath.Clean(basePlan.state.root) != filepath.Clean(planRoot) {
		t.Fatal("actual-CLI fixture plan root differs from its verified base plan")
	}
	if metadata.pin.OperationCount != 12662 {
		t.Fatalf("actual-CLI fixture metadata has %d Gov operations; expected the pinned 12,662", metadata.pin.OperationCount)
	}

	identitiesByKey := make(map[string]operationPlanPopulationIdentity, len(identities))
	identitiesBySource := make(map[string][]operationPlanPopulationIdentity, 5)
	registryProtocolCounts := map[string]int{}
	unknownCount := 0
	for _, identity := range identities {
		key := operationReadModelIdentityKey(identity.SourceID, identity.OperationID)
		if _, duplicate := identitiesByKey[key]; duplicate {
			t.Fatalf("actual-CLI fixture received duplicate identity %q", key)
		}
		identitiesByKey[key] = identity
		identitiesBySource[identity.SourceID] = append(identitiesBySource[identity.SourceID], identity)
		if identity.SourceID == "data_go_kr" {
			registryProtocolCounts[identity.Protocol]++
		}
		if identity.InventoryUnknown {
			unknownCount++
		}
	}
	if len(identitiesBySource) != 5 || registryProtocolCounts["REST"] != 12627 || registryProtocolCounts["SOAP"] != 35 || unknownCount != 4 {
		t.Fatalf("actual-CLI fixture input identity counts differ from the exact source population: sources=%d REST=%d SOAP=%d unknown=%d", len(identitiesBySource), registryProtocolCounts["REST"], registryProtocolCounts["SOAP"], unknownCount)
	}
	identityOrdinals := make(map[string]int, len(identities))
	sourceIDs := make([]string, 0, len(identitiesBySource))
	for sourceID := range identitiesBySource {
		sourceIDs = append(sourceIDs, sourceID)
	}
	sort.Strings(sourceIDs)
	ordinal := 0
	for _, sourceID := range sourceIDs {
		scoped := append([]operationPlanPopulationIdentity(nil), identitiesBySource[sourceID]...)
		sort.Slice(scoped, func(i, j int) bool { return scoped[i].OperationID < scoped[j].OperationID })
		for _, identity := range scoped {
			ordinal++
			identityOrdinals[operationReadModelIdentityKey(identity.SourceID, identity.OperationID)] = ordinal
		}
	}
	for _, id := range []string{actualCLIGovRESTObservationOK, actualCLIGovRESTObservation503, actualCLIGovSOAPObservationOK, actualCLIGovSOAPObservation503, actualCLIGovRESTTypedSuccess, actualCLIGovRESTTypedFailure, actualCLIGovSOAPTypedSuccess, actualCLIGovSOAPTypedFailure} {
		identity, ok := identitiesByKey[operationReadModelIdentityKey("data_go_kr", id)]
		if !ok || identity.DatasetID == "" || identity.UpstreamOperationKey == "" || identity.InventoryUnknown {
			t.Fatalf("actual-CLI typed/observation smoke identity %q is not an exact Gov Registry identity", id)
		}
	}

	baseManifestRaw, err := os.ReadFile(filepath.Join(planRoot, filepath.FromSlash(basePlan.binding.ReleaseManifestPath)))
	if err != nil || digest(baseManifestRaw) != basePlan.binding.ReleaseManifestSHA256 {
		t.Fatal("actual-CLI fixture base release manifest is unavailable or altered")
	}
	var baseManifest RegistryReleaseManifest
	if json.Unmarshal(baseManifestRaw, &baseManifest) != nil {
		t.Fatal("actual-CLI fixture base release manifest could not be decoded")
	}
	oldArtifacts := make(map[string]RegistryReleaseManifestArtifact, len(baseManifest.Artifacts))
	for _, artifact := range baseManifest.Artifacts {
		oldArtifacts[artifact.Path] = artifact
	}
	for _, artifact := range baseManifest.Artifacts {
		if artifact.Kind == "operation_observation_plan" || artifact.Kind == "operation_observation_plan_shard" {
			_ = os.Remove(filepath.Join(planRoot, filepath.FromSlash(artifact.Path)))
			delete(oldArtifacts, artifact.Path)
		}
	}

	profiles := actualCLIProfiles()
	policyRaw, err := json.Marshal(map[string]any{
		"schema_version":  "datapan.operation-observation-policy.v1",
		"artifact_kind":   "operation_observation_policy_set",
		"policies":        []any{},
		"profiles":        profiles,
		"effect_profiles": []any{},
	})
	if err != nil {
		t.Fatal("actual-CLI fixture policy could not be encoded")
	}
	policySHA := digest(policyRaw)

	canonicalSchemas := []struct {
		sourcePath string
		path       string
		sha        string
	}{
		{"testdata/operation-observation-plan/schema.json", "schemas/datapan.operation-observation-plan.v1.schema.json", operationObservationPlanSchemaSHA256},
		{"testdata/operation-observation-plan/operation-observation-policy.schema.json", "schemas/datapan.operation-observation-policy.v1.schema.json", "acd9e80d3f41e4a0f16b010975fc716bf1ead5c5a3b128c12d03dd51b025f31d"},
		{"testdata/operation-observation-plan/operation-response-assertion.schema.json", "schemas/datapan.operation-response-assertion.v2.schema.json", "bba64ddd581b41b77f1b3ae2de36f66261d25d7606e1c13c8146e5030787172d"},
		{"testdata/operation-observation-plan/operation-document-evidence.schema.json", "schemas/datapan.operation-document-evidence.v1.schema.json", "0b4a5a7ab10eeccb523d2af8a8e62e76f14a6243eea00558ac49e9959e7a3d1d"},
		{"testdata/operation-observation-plan/operation-document-evidence-v2.schema.json", "schemas/datapan.operation-document-evidence.v2.schema.json", "d6edb7dad63b9d7cdac6753fc02cba962cb8d96d7c01119c031935abfc973108"},
	}
	newArtifacts := make([]RegistryReleaseManifestArtifact, 0, len(identities)*2+len(canonicalSchemas)+8)
	var documentSchemaBytes []byte
	addArtifact := func(path, kind, schema string, raw []byte) {
		t.Helper()
		if int64(len(raw)) <= 0 {
			t.Fatalf("actual-CLI fixture artifact %q is empty", path)
		}
		if err := actualCLIWriteFile(planRoot, path, raw); err != nil {
			t.Fatalf("actual-CLI fixture artifact %q could not be written", path)
		}
		newArtifacts = append(newArtifacts, RegistryReleaseManifestArtifact{Path: path, Kind: kind, Schema: schema, Bytes: int64(len(raw)), SHA256: digest(raw)})
	}
	for _, schema := range canonicalSchemas {
		raw, err := os.ReadFile(filepath.Join(sourceRoot, "internal/cli", filepath.FromSlash(schema.sourcePath)))
		if err != nil || digest(raw) != schema.sha {
			t.Fatalf("actual-CLI schema %q differs from its canonical source pin", schema.sourcePath)
		}
		var envelope struct {
			ID string `json:"$id"`
		}
		if json.Unmarshal(raw, &envelope) != nil || envelope.ID == "" {
			t.Fatalf("actual-CLI schema %q has no canonical $id", schema.sourcePath)
		}
		if schema.path == "schemas/datapan.operation-document-evidence.v2.schema.json" {
			documentSchemaBytes = append([]byte(nil), raw...)
		}
		addArtifact(schema.path, "schema", envelope.ID, raw)
	}
	if len(documentSchemaBytes) == 0 {
		t.Fatal("actual-CLI canonical v2 operation-document schema is missing")
	}
	policySchema := "https://schemas.datapan.dev/datapan.operation-observation-policy.v1.schema.json"
	responseSchema := "https://schemas.datapan.dev/datapan.operation-response-assertion.v2.schema.json"
	documentSchema := "https://schemas.datapan.dev/datapan.operation-document-evidence.v2.schema.json"
	addArtifact(actualCLIPolicyPath, "operation_observation_policy", policySchema, policyRaw)

	captureRaw := []byte("Synthetic local source-QA capture. No provider request was sent; no provider response, credential, or provider behavior claim is represented.\n")
	addArtifact(actualCLISourceCapturePath, "source", "text/plain", captureRaw)
	captureSHA := digest(captureRaw)
	runtimeRaw, err := json.Marshal(map[string]any{
		"schema_version": "datapan.health-actual-cli-synthetic-runtime-binding.v1",
		"fixture_scope":  "synthetic local source-QA only",
		"p": map[string]any{
			"observation_period_seconds": actualCLIFixtureObservationPeriodSeconds,
			"scope":                      "closed_synthetic_local_source_qa_fixture_only",
			"review": map[string]any{
				"review_ref":  "https://example.invalid/synthetic-local-source-qa",
				"reviewed_by": "Datapan Health synthetic fixture",
				"rationale":   "The 14,400-second fixture window fits the full local QA population at one-second request timeout plus five-second process overhead; this is not provider policy.",
			},
		},
		"g": map[string]any{"scope_kind": "global", "scope_key": "actual-cli-synthetic-full-population", "max_concurrent": 32, "requests_per_window": 1000000, "window_seconds": 600, "minimum_interval_seconds": 0},
		"q": map[string]any{"scope_kind": "provider", "scope_key": "provider-local-source-qa-only", "max_concurrent": 32, "requests_per_window": 1000000, "window_seconds": 600, "minimum_interval_seconds": 0},
	})
	if err != nil {
		t.Fatal("actual-CLI fixture runtime binding could not be encoded")
	}
	addArtifact(actualCLIRuntimeBindingPath, "runtime_binding", "application/json", runtimeRaw)
	runtimeSHA := digest(runtimeRaw)

	profilesByID := map[string]int{}
	for index, raw := range profiles {
		var profile struct {
			ProfileID string `json:"profile_id"`
		}
		encoded, _ := json.Marshal(raw)
		if json.Unmarshal(encoded, &profile) != nil || profile.ProfileID == "" {
			t.Fatal("actual-CLI fixture profile identity is invalid")
		}
		profilesByID[profile.ProfileID] = index
	}
	profileIndex := func(identity operationPlanPopulationIdentity, protocol string) (int, bool) {
		profileID := ""
		if identity.SourceID == "data_go_kr" {
			switch protocol {
			case "REST":
				profileID = "gov-rest-observation"
			case "SOAP":
				profileID = "gov-soap-observation"
			}
			switch identity.OperationID {
			case actualCLIGovRESTTypedSuccess, actualCLIGovRESTTypedFailure:
				profileID = "gov-rest-typed"
			case actualCLIGovSOAPTypedSuccess, actualCLIGovSOAPTypedFailure:
				profileID = "gov-soap-typed"
			}
		} else {
			profileID = identity.SourceID + "-rest-observation"
		}
		index, ok := profilesByID[profileID]
		return index, ok
	}

	newDocRefs := make([]operationPlanArtifactRef, 0, len(identities))
	newDocByKey := make(map[string]actualCLIDocumentArtifact, len(identities))
	assertionRefs := make(map[string]actualCLIDocumentArtifact, len(identities))
	protocolsByIdentity := make(map[string]string, len(identities))
	validatedDocumentShapes := make(map[string]bool, 6)
	for _, identity := range identities {
		protocol := identity.Protocol
		if identity.SourceID != "data_go_kr" {
			if identity.DatasetID != "" || identity.UpstreamOperationKey != "" {
				t.Fatalf("partial source %q unexpectedly contains Gov identifiers", identity.SourceID)
			}
			protocol = "REST"
		}
		if protocol != "REST" && protocol != "SOAP" {
			t.Fatalf("actual-CLI fixture cannot bind unsupported Registry protocol %q", protocol)
		}
		profile, ok := profileIndex(identity, protocol)
		if !ok {
			t.Fatalf("actual-CLI fixture has no reviewed request profile for source %q protocol %q", identity.SourceID, protocol)
		}
		profileID := ""
		for id, index := range profilesByID {
			if index == profile {
				profileID = id
				break
			}
		}
		typed := profileID == "gov-rest-typed" || profileID == "gov-soap-typed"
		operationName := identity.OperationName
		if operationName == "" {
			operationName = "Synthetic QA operation"
		}
		pathPrefix := "rest"
		method := "GET"
		if protocol == "SOAP" {
			pathPrefix, method = "soap", "POST"
		}
		requestPath := fmt.Sprintf("/%s/%s/%s", pathPrefix, identity.SourceID, identity.OperationID)
		ordinal := identityOrdinals[operationReadModelIdentityKey(identity.SourceID, identity.OperationID)]
		docPath := actualCLIDocumentPrefix + strconv.FormatInt(int64(ordinal), 36)
		docRaw := actualCLIBuildDocument(identity, protocol, operationName, requestPath, method, captureRaw, captureSHA)
		shapeKey := identity.SourceID + "/" + protocol
		if !validatedDocumentShapes[shapeKey] {
			if err := schemas.ValidateRegistryOperationDocumentEvidenceV2(docRaw, documentSchemaBytes); err != nil {
				t.Fatalf("actual-CLI synthetic source-QA document for %s/%s violates the pinned v2 schema: %v", identity.SourceID, protocol, err)
			}
			validatedDocumentShapes[shapeKey] = true
		}
		docSHA := digest(docRaw)
		addArtifact(docPath, "operation_document_evidence", documentSchema, docRaw)
		docArtifact := actualCLIDocumentArtifact{path: docPath, sha: docSHA, bytes: int64(len(docRaw))}
		key := operationReadModelIdentityKey(identity.SourceID, identity.OperationID)
		newDocByKey[key] = docArtifact
		newDocRefs = append(newDocRefs, operationPlanArtifactRef{Path: docPath, SHA256: docSHA, Bytes: int64(len(docRaw))})
		protocolsByIdentity[key] = protocol

		assertionPath := actualCLIAssertionPrefix + identity.OperationID + ".json"
		assertionRaw := actualCLIBuildAssertion(identity, protocol, operationName, typed, profile, policySHA, docArtifact)
		assertionSHA := digest(assertionRaw)
		addArtifact(assertionPath, "operation_response_assertion", responseSchema, assertionRaw)
		assertionRefs[key] = actualCLIDocumentArtifact{path: assertionPath, sha: assertionSHA, bytes: int64(len(assertionRaw))}
	}
	sort.Slice(newDocRefs, func(i, j int) bool { return newDocRefs[i].Path < newDocRefs[j].Path })

	globalQuotaKey := "actual-cli-synthetic-full-population"
	providerQuotaKey := "provider-local-source-qa-only"
	globalQuotaSHA := OperationQuotaScopeDigest("global", globalQuotaKey)
	providerQuotaSHA := OperationQuotaScopeDigest("provider", providerQuotaKey)
	runtimeRef := func(pointer string) operationPlanEvidenceRef {
		return operationPlanEvidenceRef{ArtifactPath: actualCLIRuntimeBindingPath, SHA256: runtimeSHA, JSONPointer: pointer, EvidenceKind: "runtime_binding"}
	}
	policyRef := func(index int, suffix string) operationPlanEvidenceRef {
		pointer := fmt.Sprintf("#/profiles/%d", index)
		if suffix != "" {
			pointer += "/" + suffix
		}
		return operationPlanEvidenceRef{ArtifactPath: actualCLIPolicyPath, SHA256: policySHA, JSONPointer: pointer, EvidenceKind: "reviewed_policy"}
	}
	docRef := func(doc actualCLIDocumentArtifact, pointer string) operationPlanEvidenceRef {
		return operationPlanEvidenceRef{ArtifactPath: doc.path, SHA256: doc.sha, JSONPointer: pointer, EvidenceKind: "operation_document"}
	}

	identitiesBySourceIDs := make([]string, 0, len(identitiesBySource))
	for sourceID := range identitiesBySource {
		identitiesBySourceIDs = append(identitiesBySourceIDs, sourceID)
	}
	sort.Strings(identitiesBySourceIDs)
	newShardRefs := make([]operationObservationPlanShardRef, 0, len(identities)/256+len(identitiesBySourceIDs))
	for _, sourceID := range identitiesBySourceIDs {
		scoped := identitiesBySource[sourceID]
		sort.Slice(scoped, func(i, j int) bool { return scoped[i].OperationID < scoped[j].OperationID })
		records := make([]json.RawMessage, 0, len(scoped))
		for _, identity := range scoped {
			protocol := protocolsByIdentity[operationReadModelIdentityKey(identity.SourceID, identity.OperationID)]
			profile, _ := profileIndex(identity, protocol)
			profileID := ""
			for id, index := range profilesByID {
				if index == profile {
					profileID = id
					break
				}
			}
			typed := profileID == "gov-rest-typed" || profileID == "gov-soap-typed"
			key := operationReadModelIdentityKey(identity.SourceID, identity.OperationID)
			doc, assertion := newDocByKey[key], assertionRefs[key]
			operationName := identity.OperationName
			if operationName == "" {
				operationName = "Synthetic local source-QA operation"
			}
			method, route := "GET", "rest"
			if protocol == "SOAP" {
				method, route = "POST", "soap"
			}
			transportRefs := []operationPlanEvidenceRef{
				docRef(doc, "#/transport/protocol"), docRef(doc, "#/transport/scheme"), docRef(doc, "#/transport/host"),
				docRef(doc, "#/transport/path"), docRef(doc, "#/transport/http_method"), docRef(doc, "#/transport/port"),
			}
			transport := map[string]any{
				"protocol": protocol, "scheme": "https", "host": actualCLIFixtureProviderIP, "port": actualCLIFixturePort,
				"path": fmt.Sprintf("/%s/%s/%s", route, identity.SourceID, identity.OperationID), "http_method": method,
				"authority": "operation_document", "evidence_refs": transportRefs,
			}
			if protocol == "SOAP" {
				transport["soap_action"] = "urn:synthetic:Read"
				transport["soap_version"] = "1.1"
				transport["envelope_namespace"] = "http://schemas.xmlsoap.org/soap/envelope/"
				transport["operation_qname"] = map[string]any{"namespace": "urn:synthetic:operation", "local_name": "Read"}
				transport["body_encoding"] = "document_literal"
				for _, field := range []string{"soap_action", "soap_version", "envelope_namespace", "operation_qname", "body_encoding"} {
					transportRefs = append(transportRefs, docRef(doc, "#/transport/"+field))
				}
				transport["evidence_refs"] = transportRefs
			}
			responseKind, emptySemantics := "observation_only", "not_applicable"
			var statuses []int
			if typed {
				statuses = []int{200}
				emptySemantics = "not_applicable"
				if protocol == "REST" {
					responseKind = "json_contract"
				} else {
					responseKind = "soap_fault_free"
				}
			}
			profileEvidence := []operationPlanEvidenceRef{
				policyRef(profile, ""),
			}
			if typed {
				profileEvidence = append(profileEvidence, policyRef(profile, "request/response/branches/0"), policyRef(profile, "request/response/branches/1"))
			}
			assertionEvidence := []operationPlanEvidenceRef{docRef(doc, "#/identity"), {
				ArtifactPath: assertion.path, SHA256: assertion.sha, JSONPointer: "#/assertion", EvidenceKind: "reviewed_policy",
			}}
			responseAssertion := map[string]any{"kind": responseKind, "empty_result_semantics": emptySemantics, "assertion_ref": assertion.path + "#/assertion", "evidence_refs": assertionEvidence}
			if typed {
				responseAssertion["expected_status_codes"] = statuses
			}
			contract := map[string]any{
				"transport":                         transport,
				"operation_effect":                  map[string]any{"classification": "read_only", "authority": "operation_document", "evidence_refs": []operationPlanEvidenceRef{docRef(doc, "#/effect")}},
				"parameter_inventory_evidence_refs": []operationPlanEvidenceRef{docRef(doc, "#/parameters")},
				"parameters":                        []any{},
				"authentication":                    map[string]any{"requirement": "none", "mechanism": "none", "placement": "none", "credential_reference_required": false, "evidence_refs": []operationPlanEvidenceRef{policyRef(profile, "selector/authentication")}},
				"limits":                            map[string]any{"request_budget": 1, "timeout_ms": actualCLIFixtureRequestTimeoutMS, "max_request_bytes": 4096, "max_response_bytes": 16384, "evidence_refs": []operationPlanEvidenceRef{policyRef(profile, "request/limits")}},
				"response_assertion":                responseAssertion,
			}
			quotaEvidence := []operationPlanEvidenceRef{runtimeRef("#/g")}
			quotaProviderEvidence := []operationPlanEvidenceRef{runtimeRef("#/q")}
			operationIdentity := map[string]any{"operation_id": identity.OperationID, "protocol": protocol, "operation_name": operationName, "registered_endpoint": map[string]any{"host": actualCLIFixtureProviderIP, "port": actualCLIFixturePort, "path": fmt.Sprintf("/%s/%s/%s", route, identity.SourceID, identity.OperationID)}}
			if identity.DatasetID != "" {
				operationIdentity["dataset_id"] = identity.DatasetID
			}
			if identity.UpstreamOperationKey != "" {
				operationIdentity["upstream_operation_key"] = identity.UpstreamOperationKey
			}
			record := map[string]any{
				"schema_version": OperationObservationPlanSchemaVersion, "artifact_kind": "operation_plan",
				"source_binding":     map[string]any{"source_id": identity.SourceID, "provider": identity.Provider, "adapter_id": identity.AdapterID, "inventory_status": identity.InventoryStatus, "inventory_unknown": identity.InventoryUnknown, "test_only": false},
				"operation_identity": operationIdentity,
				"request_plan":       map[string]any{"status": "complete", "evidence_refs": profileEvidence, "request_contract": contract},
				"runtime_binding": map[string]any{"status": "bound", "observation_period_seconds": actualCLIFixtureObservationPeriodSeconds, "evidence_refs": []operationPlanEvidenceRef{runtimeRef("#/p")}, "quota_policies": []any{
					map[string]any{"scope_kind": "global", "scope_key": globalQuotaKey, "scope_sha256": globalQuotaSHA, "max_concurrent": 32, "requests_per_window": 1000000, "window_seconds": int64(600), "minimum_interval_seconds": int64(0), "evidence_refs": quotaEvidence},
					map[string]any{"scope_kind": "provider", "scope_key": providerQuotaKey, "scope_sha256": providerQuotaSHA, "max_concurrent": 32, "requests_per_window": 1000000, "window_seconds": int64(600), "minimum_interval_seconds": int64(0), "evidence_refs": quotaProviderEvidence},
				}},
				"admission": map[string]any{"status": "admitted", "reasons": []string{}, "evidence_refs": []operationPlanEvidenceRef{runtimeRef("#/fixture_scope")}},
			}
			encoded, err := json.Marshal(record)
			if err != nil {
				t.Fatal("actual-CLI fixture operation plan could not be encoded")
			}
			records = append(records, encoded)
		}
		for offset, shardIndex := 0, 0; offset < len(records); offset, shardIndex = offset+256, shardIndex+1 {
			end := min(offset+256, len(records))
			path := fmt.Sprintf("reports/operation-observation-plan/shards/%s-%04d.json", sourceID, shardIndex)
			raw, err := json.Marshal(operationObservationPlanShardWire{SchemaVersion: OperationObservationPlanSchemaVersion, ArtifactKind: "shard", SourceID: sourceID, ShardIndex: shardIndex, Records: append([]json.RawMessage(nil), records[offset:end]...)})
			if err != nil {
				t.Fatal("actual-CLI fixture plan shard could not be encoded")
			}
			if err := actualCLIWriteFile(planRoot, path, raw); err != nil {
				t.Fatal("actual-CLI fixture plan shard could not be written")
			}
			newShardRefs = append(newShardRefs, operationObservationPlanShardRef{SourceID: sourceID, ShardIndex: shardIndex, Path: path, SHA256: digest(raw), Bytes: int64(len(raw)), RecordCount: end - offset, FirstOperationID: scoped[offset].OperationID, LastOperationID: scoped[end-1].OperationID})
			newArtifacts = append(newArtifacts, RegistryReleaseManifestArtifact{Path: path, Kind: "operation_observation_plan_shard", Schema: operationObservationPlanSchemaURI, Bytes: int64(len(raw)), SHA256: digest(raw)})
		}
	}

	sort.Slice(newArtifacts, func(i, j int) bool { return newArtifacts[i].Path < newArtifacts[j].Path })
	artifacts := make([]RegistryReleaseManifestArtifact, 0, len(oldArtifacts)+len(newArtifacts)+1)
	for _, artifact := range oldArtifacts {
		artifacts = append(artifacts, artifact)
	}
	artifacts = append(artifacts, newArtifacts...)
	const indexPath = actualCLIPlanIndexPath
	var generation operationObservationPlanGenerationInputs
	if json.Unmarshal(basePlan.state.index.GenerationInputs, &generation) != nil {
		t.Fatal("actual-CLI fixture base generation inputs could not be decoded")
	}
	generation.DocumentEvidence = newDocRefs
	generationRaw, err := json.Marshal(generation)
	if err != nil {
		t.Fatal("actual-CLI fixture generation inputs could not be encoded")
	}
	sourceScopes := append([]OperationObservationPlanSourceScope(nil), basePlan.state.index.SourceScopes...)
	for _, scope := range sourceScopes {
		if len(identitiesBySource[scope.SourceID]) != scope.RegisteredOperations {
			t.Fatalf("actual-CLI fixture changed source scope %q identity count", scope.SourceID)
		}
		set := newOperationIdentitySetHash()
		for _, identity := range identitiesBySource[scope.SourceID] {
			set.add(identity.OperationID)
		}
		if set.digest() != scope.IdentitySetSHA256 {
			t.Fatalf("actual-CLI fixture changed source scope %q identity set", scope.SourceID)
		}
	}
	index := operationObservationPlanIndex{
		SchemaVersion: OperationObservationPlanSchemaVersion, ArtifactKind: "index", RegistryRevision: basePlan.RegistryRevision(),
		GenerationInputs: generationRaw,
		InventoryContext: basePlan.state.index.InventoryContext,
		Summary:          OperationObservationPlanCounts{KnownOperations: len(identities), RequestPlansComplete: len(identities), RuntimeBindingsBound: len(identities), Admitted: len(identities), InventoryUnknownScopes: 4},
		SourceScopes:     sourceScopes, Shards: newShardRefs,
	}
	indexRaw, err := json.Marshal(index)
	if err != nil {
		t.Fatal("actual-CLI fixture operation-plan index could not be encoded")
	}
	if int64(len(indexRaw)) > 8<<20 || actualCLICountJSONTokens(indexRaw) > 500000 {
		t.Fatal("actual-CLI fixture operation-plan index exceeds its pinned resource guards")
	}
	if err := actualCLIWriteFile(planRoot, indexPath, indexRaw); err != nil {
		t.Fatal("actual-CLI fixture operation-plan index could not be written")
	}
	indexSHA := digest(indexRaw)
	artifacts = append(artifacts, RegistryReleaseManifestArtifact{Path: indexPath, Kind: "operation_observation_plan", Schema: operationObservationPlanSchemaURI, Bytes: int64(len(indexRaw)), SHA256: indexSHA})
	sort.Slice(artifacts, func(i, j int) bool { return artifacts[i].Path < artifacts[j].Path })
	if len(artifacts) > 32000 {
		t.Fatalf("actual-CLI fixture has %d release artifact refs, above the 32,000 ceiling", len(artifacts))
	}
	manifest := actualCLIManifest{SchemaVersion: "datapan.release-manifest.v1", GeneratedAt: actualCLIFixtureTimestamp, DatapanVersion: actualCLIExpectedVersion, Provider: "datapan-registry", SourceRegistry: actualCLISourceRegistryPath, OutputDir: ".", ArtifactCount: len(artifacts), Artifacts: artifacts}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal("actual-CLI fixture release manifest could not be encoded")
	}
	if int64(len(manifestRaw)) > maxOperationObservationManifestBytes || actualCLICountJSONTokens(manifestRaw) > 500000 {
		t.Fatal("actual-CLI fixture release manifest exceeds its 16 MiB or 500,000-token guard")
	}
	if err := actualCLIWriteFile(planRoot, basePlan.binding.ReleaseManifestPath, manifestRaw); err != nil {
		t.Fatal("actual-CLI fixture release manifest could not be written")
	}
	manifestSHA := digest(manifestRaw)
	binding := basePlan.binding
	binding.ReleaseManifestBytes, binding.ReleaseManifestSHA256 = int64(len(manifestRaw)), manifestSHA
	binding.IndexPath, binding.IndexBytes, binding.IndexSHA256 = indexPath, int64(len(indexRaw)), indexSHA
	if err := actualCLICheckClosureSize(t, planRoot, artifacts); err != nil {
		t.Fatalf("actual-CLI fixture install projection exceeds its closure guard: %v", err)
	}
	if err := schemas.ValidateOperationObservationPlanV1(indexRaw); err != nil {
		t.Fatalf("actual-CLI fixture generated an invalid production plan index: %v", err)
	}
	plan, err := LoadPinnedOperationObservationPlan(planRoot, binding)
	if err != nil {
		t.Fatalf("production pinned operation-plan loader rejected the actual-CLI evidence fixture: %v", err)
	}
	counts := plan.Counts()
	if counts.KnownOperations != 12666 || counts.RequestPlansComplete != 12666 || counts.RuntimeBindingsBound != 12666 || counts.Admitted != 12666 || counts.InventoryUnknownScopes != 4 || plan.ExecutableOperations() != 12666 {
		t.Fatalf("production loader did not admit the exact source-QA population: known=%d complete=%d bound=%d admitted=%d unknown_scopes=%d executable=%d", counts.KnownOperations, counts.RequestPlansComplete, counts.RuntimeBindingsBound, counts.Admitted, counts.InventoryUnknownScopes, plan.ExecutableOperations())
	}
	for path, kind := range map[string]string{
		actualCLIPlanIndexPath: "operation_observation_plan",
		actualCLIPolicyPath:    "operation_observation_policy",
		"schemas/datapan.operation-observation-plan.v1.schema.json":   "schema",
		"schemas/datapan.operation-observation-policy.v1.schema.json": "schema",
		"schemas/datapan.operation-response-assertion.v2.schema.json": "schema",
		"schemas/datapan.operation-document-evidence.v1.schema.json":  "schema",
		"schemas/datapan.operation-document-evidence.v2.schema.json":  "schema",
	} {
		artifact, ok := plan.state.manifest[path]
		if !ok || artifact.Kind != kind {
			t.Fatalf("loader-only source-QA static CLI artifact path %q is missing or has kind %q, expected %q", path, artifact.Kind, kind)
		}
	}
	if _, ok := plan.state.manifest[actualCLISourceRegistryPath]; !ok {
		t.Fatal("loader-only source-QA fixture manifest is missing the canonical CLI source-registry artifact")
	}
	transportCounts := map[string]int{}
	for _, shardRef := range plan.state.index.Shards {
		shard, err := plan.state.readShard(shardRef)
		if err != nil {
			t.Fatal("production loader could not read an actual-CLI fixture shard")
		}
		for _, rawRecord := range shard.Records {
			record, err := decodeOperationObservationPlanRecord(rawRecord)
			if err != nil {
				t.Fatal("production loader could not decode an actual-CLI fixture record")
			}
			var wire operationPlanRecordWire
			if err := json.Unmarshal(rawRecord, &wire); err != nil {
				t.Fatal("loader-only source-QA assertion reference check could not decode a record")
			}
			var request operationPlanRequestWire
			if err := json.Unmarshal(wire.RequestPlan, &request); err != nil {
				t.Fatal("loader-only source-QA assertion reference check could not decode the request plan")
			}
			var contract struct {
				ResponseAssertion struct {
					AssertionRef string                     `json:"assertion_ref"`
					EvidenceRefs []operationPlanEvidenceRef `json:"evidence_refs"`
				} `json:"response_assertion"`
			}
			if err := json.Unmarshal(request.RequestContract, &contract); err != nil {
				t.Fatal("loader-only source-QA assertion reference check could not decode the request contract")
			}
			allRefs, err := actualCLICollectEvidenceRefs(rawRecord)
			if err != nil {
				t.Fatal("loader-only source-QA fixture could not scan operation evidence references")
			}
			assertionPath := actualCLIAssertionPrefix + record.OperationID + ".json"
			expectedAssertionRef := assertionPath + "#/assertion"
			if contract.ResponseAssertion.AssertionRef != expectedAssertionRef {
				t.Fatalf("loader-only source-QA fixture has a non-canonical response assertion reference for %s/%s", record.SourceID, record.OperationID)
			}
			assertionBindings := 0
			for _, ref := range contract.ResponseAssertion.EvidenceRefs {
				if ref.EvidenceKind == "reviewed_policy" && ref.ArtifactPath+ref.JSONPointer == expectedAssertionRef {
					assertionBindings++
				}
			}
			if assertionBindings != 1 {
				t.Fatalf("loader-only source-QA fixture has %d canonical assertion evidence bindings for %s/%s", assertionBindings, record.SourceID, record.OperationID)
			}
			policyBindings := 0
			for _, ref := range allRefs {
				switch ref.EvidenceKind {
				case "reviewed_policy":
					if ref.ArtifactPath == assertionPath {
						if ref.JSONPointer != "#/assertion" && ref.JSONPointer != "#/review" {
							t.Fatalf("loader-only source-QA fixture has a non-canonical assertion evidence pointer for %s/%s", record.SourceID, record.OperationID)
						}
						continue
					}
					if ref.ArtifactPath != actualCLIPolicyPath || !strings.HasPrefix(ref.JSONPointer, "#/profiles/") {
						t.Fatalf("loader-only source-QA fixture has a non-canonical reviewed-policy reference for %s/%s", record.SourceID, record.OperationID)
					}
					policyBindings++
				case "operation_document":
					if !strings.HasPrefix(ref.ArtifactPath, actualCLIDocumentPrefix) {
						t.Fatalf("loader-only source-QA fixture has a non-fixture operation-document path for %s/%s", record.SourceID, record.OperationID)
					}
				}
			}
			if policyBindings == 0 {
				t.Fatalf("loader-only source-QA fixture has no canonical reviewed-policy binding for %s/%s", record.SourceID, record.OperationID)
			}
			artifact, ok := plan.state.manifest[assertionPath]
			if !ok || artifact.Kind != "operation_response_assertion" {
				t.Fatalf("loader-only source-QA fixture is missing the canonical assertion artifact for %s/%s", record.SourceID, record.OperationID)
			}
			transportCounts[record.Protocol]++
			if record.ObservationPeriod != time.Duration(actualCLIFixtureObservationPeriodSeconds)*time.Second || record.RequestTimeout != time.Duration(actualCLIFixtureRequestTimeoutMS)*time.Millisecond {
				t.Fatalf("loader-only source-QA capacity assessment found an unbound per-operation period or timeout for %s/%s", record.SourceID, record.OperationID)
			}
		}
	}
	if transportCounts["REST"] != 12631 || transportCounts["SOAP"] != 35 {
		t.Fatalf("synthetic source-QA transport assignment differs from fixture decisions: REST=%d SOAP=%d", transportCounts["REST"], transportCounts["SOAP"])
	}
	requestTimeoutSeconds := (actualCLIFixtureRequestTimeoutMS + 999) / 1000
	serviceSeconds := requestTimeoutSeconds + actualCLIFixtureProcessOverheadSeconds
	capacityConcurrency := (int64(counts.KnownOperations)*serviceSeconds + actualCLIFixtureObservationPeriodSeconds - 1) / actualCLIFixtureObservationPeriodSeconds
	if capacityConcurrency > actualCLIFixtureConcurrencyLimit {
		t.Fatalf("loader-only source-QA capacity assessment is infeasible: required_concurrency=%d configured_limit=%d period_seconds=%d", capacityConcurrency, actualCLIFixtureConcurrencyLimit, actualCLIFixtureObservationPeriodSeconds)
	}
	t.Logf("loader-only source-QA capacity assessment: identities=%d period_seconds=%d timeout_ms=%d process_overhead_seconds=%d required_concurrency=%d configured_limit=%d", counts.KnownOperations, actualCLIFixtureObservationPeriodSeconds, actualCLIFixtureRequestTimeoutMS, actualCLIFixtureProcessOverheadSeconds, capacityConcurrency, actualCLIFixtureConcurrencyLimit)
	return plan
}

func actualCLIRuntimeLock(binarySHA, sourceRevision string, plan PinnedOperationObservationPlan) runtimebundle.Lock {
	lock := runtimebundle.Lock{SchemaVersion: runtimebundle.Schema}
	lock.CLI.SourceSHA, lock.CLI.Release = sourceRevision, actualCLIExpectedVersion
	lock.CLI.Binaries = make(map[string]runtimebundle.Binary, 2)
	for _, arch := range []string{"amd64", "arm64"} {
		lock.CLI.Binaries[arch] = runtimebundle.Binary{ArchiveSHA256: digest([]byte("synthetic local actual-CLI archive identity:" + arch + ":" + binarySHA)), BinarySHA256: binarySHA}
	}
	revision := plan.RegistryRevision()
	lock.Registry.DatasetRevision, lock.Registry.DistributionRevision = revision, revision
	lock.Registry.DistributionSHA256 = digest([]byte("synthetic local Registry distribution manifest:" + revision))
	lock.Registry.SourceSHA = revision
	lock.Registry.SourceRegistrySHA256 = plan.state.manifest["data/data-go-kr.registry.json"].SHA256
	lock.Registry.ManifestSHA256 = plan.binding.ReleaseManifestSHA256
	lock.Registry.CatalogSHA256 = digest([]byte("synthetic local Registry health catalog:" + revision))
	lock.Registry.ReleaseTag = revision
	lock.Registry.AcquiredAt = actualCLIFixtureTimestamp
	return lock
}

func actualCLIProfiles() []any {
	profiles := []any{
		actualCLIProfile("gov-rest-observation", "data_go_kr", "data.go.kr", "REST", "GET", map[string]any{"mode": "observation_only"}),
		actualCLIProfile("gov-rest-typed", "data_go_kr", "data.go.kr", "REST", "GET", actualCLIProfileResponse("json", false)),
		actualCLIProfile("gov-soap-observation", "data_go_kr", "data.go.kr", "SOAP", "POST", map[string]any{"mode": "observation_only"}),
		actualCLIProfile("gov-soap-typed", "data_go_kr", "data.go.kr", "SOAP", "POST", actualCLIProfileResponse("soap_xml", true)),
		actualCLIProfile("ecos-rest-observation", "ecos", "ECOS", "REST", "GET", map[string]any{"mode": "observation_only"}),
		actualCLIProfile("kosis-rest-observation", "kosis", "KOSIS", "REST", "GET", map[string]any{"mode": "observation_only"}),
		actualCLIProfile("open_assembly-rest-observation", "open_assembly", "open.assembly.go.kr", "REST", "GET", map[string]any{"mode": "observation_only"}),
		actualCLIProfile("seoul_open_data-rest-observation", "seoul_open_data", "data.seoul.go.kr", "REST", "GET", map[string]any{"mode": "observation_only"}),
	}
	return profiles
}

func actualCLIProfile(id, source, provider, protocol, method string, response map[string]any) map[string]any {
	review := actualCLIReview()
	return map[string]any{
		"profile_id": id,
		"selector":   map[string]any{"source_id": source, "provider": provider, "protocol": protocol, "effect": "read_only", "method": method, "authentication": map[string]any{"requirement": "none", "mechanism": "none", "placement": "none", "parameter_name": nil}},
		"review":     review,
		"request":    map[string]any{"parameter_strategies": []any{}, "omit_unmapped_optional_parameters": true, "limits": map[string]any{"request_budget": 1, "timeout_ms": actualCLIFixtureRequestTimeoutMS, "max_request_bytes": 4096, "max_response_bytes": 16384}, "response": response},
	}
}

func actualCLIProfileResponse(payload string, soap bool) map[string]any {
	root := "object"
	rootQName := map[string]any(nil)
	var successPath, errorPath map[string]any
	if soap {
		root = "xml_element"
		rootQName = map[string]any{"namespace": "http://schemas.xmlsoap.org/soap/envelope/", "local_name": "Envelope"}
		successPath = actualCLIXMLPath("http://schemas.xmlsoap.org/soap/envelope/", "Envelope", "http://schemas.xmlsoap.org/soap/envelope/", "Body", "urn:synthetic:operation", "ReadResponse")
		errorPath = actualCLIXMLPath("http://schemas.xmlsoap.org/soap/envelope/", "Envelope", "http://schemas.xmlsoap.org/soap/envelope/", "Body", "http://schemas.xmlsoap.org/soap/envelope/", "Fault")
	} else {
		successPath = map[string]any{"kind": "json_pointer", "value": "#/synthetic"}
		errorPath = map[string]any{"kind": "json_pointer", "value": "#/synthetic"}
	}
	successSelector := map[string]any{"accepted_http_status_codes": []int{200}, "root_kind": root, "discriminators": []any{actualCLIProfileDiscriminator(successPath, soap, true)}}
	errorSelector := map[string]any{"accepted_http_status_codes": []int{200}, "root_kind": root, "discriminators": []any{actualCLIProfileDiscriminator(errorPath, soap, false)}}
	if soap {
		successSelector["root_qname"], errorSelector["root_qname"] = rootQName, rootQName
	}
	branches := []any{
		map[string]any{"branch_id": "synthetic-success", "classification": "success", "selector": successSelector, "empty_result_semantics": "not_applicable", "code_mode": "none", "code_mode_rationale": "Synthetic local source-QA response only; no provider result-code semantics are asserted.", "required_fields": []any{}},
		map[string]any{"branch_id": "synthetic-provider-error", "classification": "provider_error", "selector": errorSelector, "empty_result_semantics": "not_applicable", "code_mode": "none", "code_mode_rationale": "Synthetic local source-QA response only; no provider result-code semantics are asserted.", "required_fields": []any{}},
	}
	return map[string]any{"payload_kind": payload, "branches": branches}
}

func actualCLIProfileDiscriminator(path map[string]any, soap, success bool) map[string]any {
	if soap {
		return map[string]any{"path": path, "predicate": "present"}
	}
	value := false
	if success {
		value = true
	}
	return map[string]any{"path": path, "predicate": "equals_any", "value_type": "boolean", "values": []any{value}}
}

func actualCLIXMLPath(parts ...string) map[string]any {
	segments := make([]any, 0, len(parts)/2)
	for i := 0; i+1 < len(parts); i += 2 {
		segments = append(segments, map[string]any{"namespace": parts[i], "local_name": parts[i+1]})
	}
	return map[string]any{"kind": "xml_qname_path", "segments": segments}
}

func actualCLIBuildDocument(identity operationPlanPopulationIdentity, protocol, operationName, requestPath, method string, capture []byte, captureSHA string) []byte {
	captureRef := func(kind string) []any {
		return []any{map[string]any{"evidence_kind": kind, "locator": map[string]any{"source_id": "q", "kind": "html_byte_range", "byte_start": 0, "byte_end": 1}}}
	}
	emptyRefs := []any{}
	fact := func(value any, status, kind string) map[string]any {
		return map[string]any{"value": value, "status": status, "source_refs": captureRef(kind)}
	}
	sourceHost := map[string]string{"data_go_kr": "www.data.go.kr", "ecos": "ecos.bok.or.kr", "kosis": "kosis.kr", "open_assembly": "open.assembly.go.kr", "seoul_open_data": "data.seoul.go.kr"}[identity.SourceID]
	if sourceHost == "" {
		sourceHost = "www.data.go.kr"
	}
	operationID, sourceID, provider := identity.OperationID, identity.SourceID, identity.Provider
	identityObject := map[string]any{"source_id": sourceID, "operation_id": operationID, "provider": provider, "protocol": protocol, "operation_name": operationName, "source_refs": emptyRefs}
	if sourceID == "data_go_kr" {
		identityObject["dataset_id"] = identity.DatasetID
		identityObject["source_system"] = "data.go.kr"
		identityObject["upstream_operation_key"] = identity.UpstreamOperationKey
	} else {
		identityObject["operation_name"] = "Synthetic QA operation"
	}
	protocolStatus := "documented"
	if sourceID == "data_go_kr" {
		protocolStatus = "registered_manifest"
	}
	soapAction, soapVersion, envelope, qname, bodyEncoding := any(nil), any(nil), any(nil), any(nil), any(nil)
	soapStatus := "not_applicable"
	if protocol == "SOAP" {
		soapStatus = "documented"
		soapAction, soapVersion = "urn:synthetic:Read", "1.1"
		envelope, qname, bodyEncoding = "http://schemas.xmlsoap.org/soap/envelope/", "{urn:synthetic:operation}Read", "document_literal"
	}
	transport := map[string]any{
		"protocol":              map[string]any{"value": protocol, "status": protocolStatus, "source_refs": emptyRefs},
		"scheme":                map[string]any{"value": "https", "status": "documented", "source_refs": emptyRefs},
		"host":                  map[string]any{"value": actualCLIFixtureProviderIP, "status": "documented", "source_refs": emptyRefs},
		"port":                  actualCLIFixturePort,
		"port_source_refs":      captureRef("fixture_port"),
		"path":                  map[string]any{"value": requestPath, "status": "documented", "source_refs": emptyRefs},
		"http_method":           map[string]any{"value": method, "status": "documented", "authority_scope": "operation_specific", "source_refs": captureRef("operation_http_method")},
		"soap_action":           fact(soapAction, soapStatus, "operation_endpoint"),
		"soap_version":          fact(soapVersion, soapStatus, "operation_endpoint"),
		"envelope_namespace":    fact(envelope, soapStatus, "operation_endpoint"),
		"operation_qname":       fact(qname, soapStatus, "operation_endpoint"),
		"body_encoding":         fact(bodyEncoding, soapStatus, "operation_endpoint"),
		"fixed_query_selectors": []any{},
	}
	if protocol != "SOAP" {
		for _, field := range []string{"soap_action", "soap_version", "envelope_namespace", "operation_qname", "body_encoding"} {
			transport[field] = map[string]any{"value": nil, "status": "not_applicable", "source_refs": emptyRefs}
		}
	}
	unknowns := []string{}
	if sourceID != "data_go_kr" {
		unknowns = append(unknowns, "Registry protocol unknown (source value "+identity.Protocol+"); synthetic REST only.")
	}
	var operationTitle map[string]any
	if sourceID == "data_go_kr" {
		operationTitle = map[string]any{"value": operationName, "status": "registered_manifest", "source_refs": emptyRefs}
	} else {
		operationTitle = map[string]any{"value": nil, "status": "unknown", "source_refs": []any{}}
	}
	unknownResponse := actualCLIUnknownResponseContract()
	doc := map[string]any{
		"schema_version": "datapan.operation-document-evidence.v2",
		"parser":         map[string]any{"id": "registered-operation-document-parser", "version": "2.0.0"},
		"identity":       identityObject,
		"source_bindings": []any{map[string]any{
			"source_id":  "q",
			"origin":     map[string]any{"scheme": "https", "host": sourceHost, "path": "/q", "method": "GET", "query_values_stored": false, "body_values_stored": false},
			"media_type": "text/plain", "bytes": len(capture), "sha256": captureSHA, "retrieved_at": actualCLIFixtureTimestamp, "capture_role": "synthetic_no_provider_claim",
			"parser": map[string]any{"id": "synthetic", "version": "1"},
		}},
		"parse_status":       "parsed_with_unknowns",
		"transport":          transport,
		"effect":             map[string]any{"classification": "read_only", "status": "documented", "authority": "operation_document", "source_refs": captureRef("operation_effect")},
		"parameters":         []any{},
		"authentication":     map[string]any{"requirement": nil, "status": "unknown", "mechanism": nil, "parameter_names": []any{}, "placement": nil, "source_refs": []any{}},
		"limits":             map[string]any{"provider_quota": map[string]any{"account_tier": map[string]any{"source_refs": []any{}, "status": "unknown", "value": nil}, "scope": map[string]any{"source_refs": []any{}, "status": "unknown", "value": nil}, "source_refs": []any{}, "status": "not_parsed", "unit": nil, "value": nil}, "request_budget": map[string]any{"source_refs": []any{}, "status": "not_a_provider_fact", "value": nil}},
		"response_assertion": map[string]any{"kind": "unknown", "fields": []any{}, "empty_result_semantics": map[string]any{"source_refs": []any{}, "status": "unknown", "value": nil}, "source_refs": []any{}},
		"response_contract":  unknownResponse,
		"explicit_unknowns":  unknowns,
		"operation_document": map[string]any{"title": operationTitle, "purpose": map[string]any{"source_refs": []any{}, "status": "unknown", "value": nil}},
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		panic("fixed actual-CLI document fixture encoding failed")
	}
	return encoded
}

func actualCLIUnknownResponseContract() map[string]any {
	refs := []any{}
	return map[string]any{
		"accepted_http_status_codes":   map[string]any{"status": "unknown", "values": []any{}, "source_refs": refs},
		"payload":                      map[string]any{"status": "unknown", "kind": "unknown", "media_types": []any{}, "source_refs": refs},
		"schema_shape":                 map[string]any{"status": "unknown", "source_refs": refs},
		"coded_result_field_inventory": map[string]any{"status": "unknown", "candidates": []any{}, "source_refs": refs},
		"success_branches":             []any{}, "documented_http_error_branches": []any{}, "documented_fields": []any{}, "required_fields": []any{},
		"provider_result_codes":     map[string]any{"status": "unknown", "evidence_strength": "unknown", "path": nil, "value_type": nil, "success_values": map[string]any{"status": "unknown", "values": []any{}, "source_refs": refs}, "error_values": map[string]any{"status": "unknown", "values": []any{}, "source_refs": refs}, "source_refs": refs},
		"result_collection":         map[string]any{"status": "unknown", "path": nil, "container_path": nil, "item_path": nil, "container_cardinality": map[string]any{"status": "unknown", "minimum": nil, "maximum": nil, "source_refs": refs}, "value_type": nil, "source_refs": refs},
		"declared_output_fields":    []any{},
		"documented_error_contract": map[string]any{"status": "unknown", "format": "unknown", "code_path": nil, "message_path": nil, "codes": []any{}, "source_refs": refs},
	}
}

func actualCLIBuildAssertion(identity operationPlanPopulationIdentity, protocol, operationName string, typed bool, profile int, policySHA string, document actualCLIDocumentArtifact) []byte {
	refDoc := operationPlanEvidenceRef{ArtifactPath: document.path, SHA256: document.sha, JSONPointer: "#/identity", EvidenceKind: "operation_document"}
	assertion := map[string]any{"mode": "observation_only"}
	if typed {
		soap := protocol == "SOAP"
		payload := "json"
		if soap {
			payload = "soap_xml"
		}
		branches := []any{
			actualCLIAssertionBranch("synthetic-success", "success", protocol, true, profile, 0, policySHA, refDoc),
			actualCLIAssertionBranch("synthetic-provider-error", "provider_error", protocol, false, profile, 1, policySHA, refDoc),
		}
		assertion = map[string]any{"payload_kind": payload, "branches": branches}
	}
	operationIdentity := map[string]any{"operation_id": identity.OperationID, "operation_name": operationName}
	if identity.DatasetID != "" {
		operationIdentity["dataset_id"] = identity.DatasetID
	}
	if identity.UpstreamOperationKey != "" {
		operationIdentity["upstream_operation_key"] = identity.UpstreamOperationKey
	}
	if identity.SourceID != "data_go_kr" {
		operationIdentity["operation_name"] = "Synthetic local source-QA operation"
	}
	artifact := map[string]any{
		"schema_version": "datapan.operation-response-assertion.v2", "artifact_kind": "operation_response_assertion",
		"source_binding":     map[string]any{"source_id": identity.SourceID, "provider": identity.Provider, "protocol": protocol},
		"operation_identity": operationIdentity,
		"document_evidence":  map[string]any{"path": document.path, "sha256": document.sha, "bytes": document.bytes},
		"review":             actualCLIReview(), "assertion": assertion,
	}
	encoded, err := json.Marshal(artifact)
	if err != nil {
		panic("fixed actual-CLI assertion fixture encoding failed")
	}
	return encoded
}

func actualCLIAssertionBranch(id, classification, protocol string, success bool, profile, branch int, policySHA string, documentRef operationPlanEvidenceRef) map[string]any {
	rootKind := "object"
	rootQName := map[string]any(nil)
	var discriminator map[string]any
	if protocol == "SOAP" {
		rootKind = "xml_element"
		rootQName = map[string]any{"namespace": "http://schemas.xmlsoap.org/soap/envelope/", "local_name": "Envelope"}
		path := actualCLIXMLPath("http://schemas.xmlsoap.org/soap/envelope/", "Envelope", "http://schemas.xmlsoap.org/soap/envelope/", "Body", "urn:synthetic:operation", "ReadResponse")
		if !success {
			path = actualCLIXMLPath("http://schemas.xmlsoap.org/soap/envelope/", "Envelope", "http://schemas.xmlsoap.org/soap/envelope/", "Body", "http://schemas.xmlsoap.org/soap/envelope/", "Fault")
		}
		discriminator = map[string]any{"path": path, "predicate": "present", "source_refs": []any{documentRef}}
	} else {
		value := false
		if success {
			value = true
		}
		discriminator = map[string]any{"path": map[string]any{"kind": "json_pointer", "value": "#/synthetic"}, "predicate": "equals_any", "value_type": "boolean", "values": []any{value}, "source_refs": []any{documentRef}}
	}
	branchPointer := fmt.Sprintf("#/profiles/%d/request/response/branches/%d", profile, branch)
	branchRef := operationPlanEvidenceRef{ArtifactPath: actualCLIPolicyPath, SHA256: policySHA, JSONPointer: branchPointer, EvidenceKind: "reviewed_policy"}
	selector := map[string]any{"accepted_http_status_codes": []int{200}, "root_kind": rootKind, "discriminators": []any{discriminator}}
	if protocol == "SOAP" {
		selector["root_qname"] = rootQName
	}
	return map[string]any{
		"branch_id": id, "classification": classification,
		"selector":               selector,
		"empty_result_semantics": "not_applicable", "http_status_source_refs": []any{documentRef},
		"required_fields": []any{}, "provider_result_code_status": "none_by_policy", "provider_result_code_evidence_refs": []any{},
		"source_refs": []any{documentRef}, "review_refs": []any{branchRef},
	}
}

func actualCLIReview() map[string]any {
	return map[string]any{"review_ref": "https://example.invalid/q", "reviewed_by": "synthetic QA", "rationale": "Synthetic QA; no provider truth or response claims."}
}

func actualCLICollectEvidenceRefs(raw json.RawMessage) ([]operationPlanEvidenceRef, error) {
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, err
	}
	refs := make([]operationPlanEvidenceRef, 0, 16)
	var walk func(any)
	walk = func(value any) {
		switch current := value.(type) {
		case map[string]any:
			path, hasPath := current["artifact_path"].(string)
			sha, hasSHA := current["sha256"].(string)
			pointer, hasPointer := current["json_pointer"].(string)
			kind, hasKind := current["evidence_kind"].(string)
			if hasPath && hasSHA && hasPointer && hasKind {
				refs = append(refs, operationPlanEvidenceRef{ArtifactPath: path, SHA256: sha, JSONPointer: pointer, EvidenceKind: kind})
			}
			for _, child := range current {
				walk(child)
			}
		case []any:
			for _, child := range current {
				walk(child)
			}
		}
	}
	walk(root)
	return refs, nil
}

func actualCLIWriteFile(root, relative string, raw []byte) error {
	if !safePlanRelativePath(relative) || len(raw) == 0 {
		return errors.New("invalid fixture path or empty content")
	}
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o400)
}

func actualCLICountJSONTokens(raw []byte) int {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	count := 0
	for {
		_, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return count
		}
		if err != nil {
			return int(^uint(0) >> 1)
		}
		count++
	}
}

func actualCLICheckClosureSize(t *testing.T, root string, artifacts []RegistryReleaseManifestArtifact) error {
	t.Helper()
	var total int64
	byKind := make(map[string]int64)
	for _, artifact := range artifacts {
		if artifact.Path == "data/data-go-kr.registry.json" {
			continue
		}
		total += artifact.Bytes
		byKind[artifact.Kind] += artifact.Bytes
		path := filepath.Join(root, filepath.FromSlash(artifact.Path))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != artifact.Bytes {
			return fmt.Errorf("local projected artifact %q is missing or differs from its manifest size", artifact.Path)
		}
		raw, err := os.ReadFile(path)
		if err != nil || digest(raw) != artifact.SHA256 {
			return fmt.Errorf("local projected artifact %q differs from its manifest digest", artifact.Path)
		}
	}
	if total > 128<<20 {
		return fmt.Errorf("bound local artifact projection totals %d bytes, above 128 MiB (by kind: %v)", total, byKind)
	}
	if total <= 0 {
		return errors.New("empty local artifact projection")
	}
	t.Logf("actual-CLI fixture bound-artifact projection: bytes=%d artifacts=%d", total, len(artifacts))
	return nil
}
