package health

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	pinnedOperationManifestFixture = "../../testdata/registry/data-go-kr-operation-manifest.v1.json"
	pinnedReleaseManifestFixture   = "../../testdata/registry/release-manifest.v1.json"
	pinnedOperationManifestReceipt = "../../config/registry/operation-manifest-receipt.json"
)

func TestPinnedOperationManifestReproducesAcceptedOperationDenominator(t *testing.T) {
	manifest, receipt, err := LoadPinnedOperationManifest(pinnedOperationManifestFixture, pinnedReleaseManifestFixture, pinnedOperationManifestReceipt)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Operations) != 12385 || manifest.Summary.Protocols["REST"] != 12350 || manifest.Summary.Protocols["SOAP"] != 35 || receipt.Denominator.APIMetadataCount != 7365 {
		t.Fatalf("unexpected operation denominator: %#v", manifest.Summary)
	}
	verification := BuildOperationManifestVerification(manifest, receipt)
	if verification.Integrity != "verified" || verification.Denominator.OperationStatusSubjects != 12385 || verification.ServiceCanaries.Count != 10 || verification.ServiceCanaries.IncludedInOperationDenominator {
		t.Fatalf("unexpected verification receipt: %#v", verification)
	}
}

func TestOperationStatusSubjectCannotBeDeduplicatedByMetadataGrouping(t *testing.T) {
	manifest, _, err := LoadPinnedOperationManifest(pinnedOperationManifestFixture, pinnedReleaseManifestFixture, pinnedOperationManifestReceipt)
	if err != nil {
		t.Fatal(err)
	}
	groups := map[string]func(ManifestOperation) string{
		"api":     func(operation ManifestOperation) string { return operation.Provenance.SourceURL },
		"dataset": func(operation ManifestOperation) string { return operation.Provenance.DatasetID },
		"host":    func(operation ManifestOperation) string { return endpointHost(operation) },
		"endpoint": func(operation ManifestOperation) string {
			if operation.Transport.Endpoint == nil {
				return ""
			}
			return *operation.Transport.Endpoint
		},
	}
	for name, key := range groups {
		t.Run(name, func(t *testing.T) {
			metadataSubjects := map[string]bool{}
			operationSubjects := map[string]bool{}
			for _, operation := range manifest.Operations {
				metadataSubjects[key(operation)] = true
				operationSubjects[operation.StatusSubject()] = true
			}
			if len(metadataSubjects) >= len(manifest.Operations) || len(operationSubjects) != 12385 {
				t.Fatalf("%s grouping was allowed to replace operation subjects: metadata=%d operations=%d", name, len(metadataSubjects), len(operationSubjects))
			}
		})
	}
}

func TestSOAPStatusSubjectIncludesAction(t *testing.T) {
	manifest, _, err := LoadPinnedOperationManifest(pinnedOperationManifestFixture, pinnedReleaseManifestFixture, pinnedOperationManifestReceipt)
	if err != nil {
		t.Fatal(err)
	}
	byEndpoint := map[string][]ManifestOperation{}
	for _, operation := range manifest.Operations {
		if operation.Protocol == "SOAP" && operation.Transport.Endpoint != nil {
			byEndpoint[*operation.Transport.Endpoint] = append(byEndpoint[*operation.Transport.Endpoint], operation)
		}
	}
	for endpoint, operations := range byEndpoint {
		if len(operations) < 2 {
			continue
		}
		for left := range operations {
			for right := left + 1; right < len(operations); right++ {
				if *operations[left].Transport.Action != *operations[right].Transport.Action && operations[left].StatusSubject() != operations[right].StatusSubject() {
					return
				}
			}
		}
		_ = endpoint
	}
	t.Fatal("fixture does not prove SOAP action identity")
}

func TestPinnedOperationManifestRejectsDigestAndIdentityDrift(t *testing.T) {
	raw := mustRead(t, pinnedOperationManifestFixture)
	path := filepath.Join(t.TempDir(), "operation-manifest.json")
	if err := os.WriteFile(path, append([]byte(nil), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPinnedOperationManifest(path, pinnedReleaseManifestFixture, pinnedOperationManifestReceipt); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPinnedOperationManifest(path, pinnedReleaseManifestFixture, pinnedOperationManifestReceipt); err == nil {
		t.Fatal("digest drift was accepted")
	}
	var fixture map[string]any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	first := fixture["operations"].([]any)[0].(map[string]any)
	first["operation_id"] = strings.Repeat("f", 64)
	mutated, err := json.Marshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	receipt := mustRead(t, pinnedOperationManifestReceipt)
	var receiptDocument map[string]any
	if err := json.Unmarshal(receipt, &receiptDocument); err != nil {
		t.Fatal(err)
	}
	receiptDocument["manifest"].(map[string]any)["bytes"] = len(mutated)
	receiptDocument["manifest"].(map[string]any)["sha256"] = digest(mutated)
	encoded, err := json.Marshal(receiptDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, mutated, 0o600); err != nil || os.WriteFile(receiptPath, encoded, 0o600) != nil {
		t.Fatal("could not write drift fixture")
	}
	if _, _, err := LoadPinnedOperationManifest(path, pinnedReleaseManifestFixture, receiptPath); err == nil {
		t.Fatal("identity drift with a matching digest was accepted")
	}
	releasePath := filepath.Join(t.TempDir(), "release-manifest.json")
	if err := os.WriteFile(releasePath, append(mustRead(t, pinnedReleaseManifestFixture), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadPinnedOperationManifest(pinnedOperationManifestFixture, releasePath, pinnedOperationManifestReceipt); err == nil {
		t.Fatal("release manifest drift was accepted")
	}
}

func TestNonHistoricalOperationManifestDenominatorIsReceiptDriven(t *testing.T) {
	manifest, receipt := smallNonHistoricalOperationManifest(t)
	if !validOperationManifestReceipt(receipt) {
		t.Fatal("valid non-historical denominator was rejected")
	}
	if err := manifest.Validate(receipt); err != nil {
		t.Fatalf("valid non-historical manifest was rejected: %v", err)
	}
	verification := BuildOperationManifestVerification(manifest, receipt)
	if verification.Denominator.OperationStatusSubjects != 3 || verification.Denominator.Protocols["REST"] != 2 || verification.Denominator.Protocols["SOAP"] != 1 || verification.Denominator.APIMetadataCount != 2 {
		t.Fatalf("verification did not preserve derived denominator: %#v", verification.Denominator)
	}
}

func TestOperationManifestSupportsSingleProtocolAndEligibilityState(t *testing.T) {
	tests := map[string]struct {
		eligibility                string
		requiredApproval, excluded int
	}{
		"REST only and approval required": {eligibility: "approval_required", requiredApproval: 3, excluded: 0},
		"all operations excluded":         {eligibility: "excluded", requiredApproval: 0, excluded: 3},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			manifest, receipt := smallNonHistoricalOperationManifest(t)
			receipt.Denominator.Protocols = map[string]int{"REST": 3, "SOAP": 0}
			receipt.Denominator.Exclusions["required_parameter_approval"] = test.requiredApproval
			receipt.Denominator.Exclusions["endpoint_missing"] = test.excluded
			manifest.Summary.Protocols = copyCounts(receipt.Denominator.Protocols)
			manifest.Summary.Eligibility = map[string]int{"approval_required": test.requiredApproval, "excluded": test.excluded}
			endpoint := "https://api.example.test/v1"
			if test.eligibility == "excluded" {
				endpoint = ""
			}
			manifest.Operations = []ManifestOperation{
				smallManifestOperation("dataset-a", "source-a", "operation-a", "REST", test.eligibility, endpoint),
				smallManifestOperation("dataset-a", "source-a", "operation-b", "REST", test.eligibility, endpoint),
				smallManifestOperation("dataset-b", "source-b", "operation-c", "REST", test.eligibility, endpoint),
			}
			if !validOperationManifestReceipt(receipt) {
				t.Fatal("valid single-state receipt was rejected")
			}
			if err := manifest.Validate(receipt); err != nil {
				t.Fatalf("valid single-state manifest was rejected: %v", err)
			}
		})
	}
}

func TestOperationManifestReceiptRejectsInvalidDynamicCounts(t *testing.T) {
	_, base := smallNonHistoricalOperationManifest(t)
	tests := map[string]func(*OperationManifestReceipt){
		"protocol sum mismatch": func(receipt *OperationManifestReceipt) {
			receipt.Denominator.Protocols = map[string]int{"REST": 2, "SOAP": 2}
		},
		"negative protocol count": func(receipt *OperationManifestReceipt) {
			receipt.Denominator.Protocols = map[string]int{"REST": -1, "SOAP": 4}
		},
		"unknown protocol": func(receipt *OperationManifestReceipt) {
			receipt.Denominator.Protocols = map[string]int{"REST": 2, "SOAP": 1, "GRPC": 0}
		},
		"unknown zero protocol": func(receipt *OperationManifestReceipt) {
			receipt.Denominator.Protocols = map[string]int{"REST": 3, "GRPC": 0}
		},
		"missing protocol": func(receipt *OperationManifestReceipt) {
			receipt.Denominator.Protocols = map[string]int{"REST": 3}
		},
		"negative exclusion": func(receipt *OperationManifestReceipt) {
			receipt.Denominator.Exclusions["link_operations"] = -1
		},
		"missing exclusion": func(receipt *OperationManifestReceipt) {
			delete(receipt.Denominator.Exclusions, "endpoint_missing")
		},
		"unknown exclusion": func(receipt *OperationManifestReceipt) {
			delete(receipt.Denominator.Exclusions, "endpoint_missing")
			receipt.Denominator.Exclusions["unknown"] = 0
		},
		"unknown zero exclusion": func(receipt *OperationManifestReceipt) {
			delete(receipt.Denominator.Exclusions, "filedata_catalog_entries")
			receipt.Denominator.Exclusions["unknown"] = 0
		},
		"eligibility counts do not cover operations": func(receipt *OperationManifestReceipt) {
			receipt.Denominator.Exclusions["required_parameter_approval"] = 0
		},
		"zero operation denominator": func(receipt *OperationManifestReceipt) {
			receipt.Denominator.OperationStatusSubjects = 0
		},
		"zero API metadata count": func(receipt *OperationManifestReceipt) {
			receipt.Denominator.APIMetadataCount = 0
		},
		"API metadata exceeds operation count": func(receipt *OperationManifestReceipt) {
			receipt.Denominator.APIMetadataCount = 4
		},
		"protocol sum overflows int": func(receipt *OperationManifestReceipt) {
			maxInt := int(^uint(0) >> 1)
			receipt.Denominator.OperationStatusSubjects = maxInt
			receipt.Denominator.Protocols = map[string]int{"REST": maxInt, "SOAP": 1}
		},
		"eligibility sum overflows int": func(receipt *OperationManifestReceipt) {
			maxInt := int(^uint(0) >> 1)
			receipt.Denominator.OperationStatusSubjects = maxInt
			receipt.Denominator.Protocols = map[string]int{"REST": maxInt, "SOAP": 0}
			receipt.Denominator.Exclusions["endpoint_missing"] = maxInt
			receipt.Denominator.Exclusions["required_parameter_approval"] = 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			receipt := cloneOperationManifestReceipt(base)
			mutate(&receipt)
			if validOperationManifestReceipt(receipt) {
				t.Fatal("invalid receipt counts were accepted")
			}
		})
	}
}

func TestOperationManifestRejectsDerivedIdentityAndMetadataMismatches(t *testing.T) {
	manifest, receipt := smallNonHistoricalOperationManifest(t)
	tests := map[string]func(*OperationManifest, *OperationManifestReceipt){
		"duplicate identity": func(manifest *OperationManifest, _ *OperationManifestReceipt) {
			manifest.Operations[2] = manifest.Operations[0]
		},
		"identity hash mismatch": func(manifest *OperationManifest, _ *OperationManifestReceipt) {
			manifest.Operations[0].OperationID = strings.Repeat("f", 64)
		},
		"protocol counts mismatch": func(_ *OperationManifest, receipt *OperationManifestReceipt) {
			receipt.Denominator.Protocols = map[string]int{"REST": 1, "SOAP": 2}
		},
		"API metadata count mismatch": func(_ *OperationManifest, receipt *OperationManifestReceipt) {
			receipt.Denominator.APIMetadataCount = 3
		},
		"source snapshot hash mismatch": func(manifest *OperationManifest, _ *OperationManifestReceipt) {
			manifest.SourceSnapshot.SHA256 = strings.Repeat("f", 64)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			manifest := cloneOperationManifest(manifest)
			receipt := cloneOperationManifestReceipt(receipt)
			mutate(&manifest, &receipt)
			if err := manifest.Validate(receipt); err == nil {
				t.Fatal("manifest and receipt mismatch was accepted")
			}
		})
	}
}

func TestOperationManifestRejectsSwappedZeroSummaryKeys(t *testing.T) {
	manifest, receipt := smallNonHistoricalOperationManifest(t)
	receipt.Denominator.Protocols = map[string]int{"REST": 3, "SOAP": 0}
	receipt.Denominator.Exclusions["endpoint_missing"] = 0
	receipt.Denominator.Exclusions["required_parameter_approval"] = 3
	manifest.Summary.Protocols = copyCounts(receipt.Denominator.Protocols)
	manifest.Summary.Eligibility = expectedEligibilityCounts(receipt.Denominator.Exclusions)
	manifest.Operations = []ManifestOperation{
		smallManifestOperation("dataset-a", "source-a", "operation-a", "REST", "approval_required", "https://api.example.test/v1"),
		smallManifestOperation("dataset-a", "source-a", "operation-b", "REST", "approval_required", "https://api.example.test/v1"),
		smallManifestOperation("dataset-b", "source-b", "operation-c", "REST", "approval_required", "https://api.example.test/v1"),
	}
	if !validOperationManifestReceipt(receipt) {
		t.Fatal("single-state receipt was rejected")
	}
	if err := manifest.Validate(receipt); err != nil {
		t.Fatalf("single-state manifest was rejected: %v", err)
	}
	mutations := map[string]func(*OperationManifest){
		"protocol summary": func(manifest *OperationManifest) {
			manifest.Summary.Protocols = map[string]int{"REST": 3, "GRPC": 0}
		},
		"eligibility summary": func(manifest *OperationManifest) {
			manifest.Summary.Eligibility = map[string]int{"approval_required": 3, "unknown": 0}
		},
		"exclusion summary": func(manifest *OperationManifest) {
			manifest.Summary.Exclusions = map[string]int{"link_operations": 11, "operationless_catalog_entries": 4, "unknown": 0}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := cloneOperationManifest(manifest)
			mutate(&candidate)
			if err := candidate.Validate(receipt); err == nil {
				t.Fatal("summary with a swapped zero-count key was accepted")
			}
		})
	}
}

func smallNonHistoricalOperationManifest(t *testing.T) (OperationManifest, OperationManifestReceipt) {
	t.Helper()
	receipt, err := LoadOperationManifestReceipt(pinnedOperationManifestReceipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Denominator.OperationStatusSubjects = 3
	receipt.Denominator.Protocols = map[string]int{"REST": 2, "SOAP": 1}
	receipt.Denominator.APIMetadataCount = 2
	receipt.Denominator.Exclusions = map[string]int{
		"link_operations":               11,
		"operationless_catalog_entries": 4,
		"filedata_catalog_entries":      0,
		"endpoint_missing":              2,
		"required_parameter_approval":   1,
	}
	manifest := OperationManifest{
		SchemaVersion: receipt.Manifest.SchemaVersion,
		Authority:     "datapan-registry",
		SourceSnapshot: ManifestSourceSnapshot{
			Path: receipt.SourceSnapshot.Path, Bytes: receipt.SourceSnapshot.Bytes, SHA256: receipt.SourceSnapshot.SHA256,
		},
		IdentityContract: ManifestIdentityContract{Algorithm: "sha256-length-prefixed-utf8-v1", Fields: append([]string(nil), operationIdentityFields...)},
		Summary: ManifestSummary{
			APIOperations:      3,
			Protocols:          map[string]int{"REST": 2, "SOAP": 1},
			Eligibility:        map[string]int{"approval_required": 1, "excluded": 2},
			Exclusions:         sourceExclusions(receipt.Denominator.Exclusions),
			IdentityCollisions: 0,
			IdentityOmissions:  0,
		},
		Operations: []ManifestOperation{
			smallManifestOperation("dataset-a", "source-a", "operation-a", "REST", "approval_required", "https://api.example.test/v1"),
			smallManifestOperation("dataset-a", "source-a", "operation-b", "REST", "excluded", ""),
			smallManifestOperation("dataset-b", "source-b", "operation-c", "SOAP", "excluded", ""),
		},
	}
	return manifest, receipt
}

func smallManifestOperation(datasetID, sourceSystem, upstreamKey, protocol, eligibility, endpoint string) ManifestOperation {
	operation := ManifestOperation{}
	operation.Protocol = protocol
	operation.Provenance.Provider = "data.go.kr"
	operation.Provenance.DatasetID = datasetID
	operation.Provenance.OperationName = "operation " + upstreamKey
	operation.Provenance.SourceSystem = sourceSystem
	operation.Provenance.UpstreamOperationKey = upstreamKey
	operation.Provenance.SourceURL = "https://api.example.test/datasets/" + datasetID
	if endpoint != "" {
		operation.Transport.Endpoint = &endpoint
	}
	methodOrAction := "GET"
	if protocol == "REST" {
		operation.Transport.Method = &methodOrAction
		operation.Transport.MethodEvidence = "registry_default_get"
	} else {
		methodOrAction = "urn:example:" + upstreamKey
		operation.Transport.Action = &methodOrAction
		operation.Transport.MethodEvidence = "soap_action"
	}
	operation.Eligibility.Status = eligibility
	fields := []string{operation.Provenance.Provider, operation.Provenance.DatasetID, protocol, sourceSystem, upstreamKey, endpoint, methodOrAction, operation.Provenance.OperationName}
	operation.OperationID = lengthPrefixedSHA256(fields)
	return operation
}

func cloneOperationManifestReceipt(receipt OperationManifestReceipt) OperationManifestReceipt {
	receipt.Denominator.Protocols = copyCounts(receipt.Denominator.Protocols)
	receipt.Denominator.Exclusions = copyCounts(receipt.Denominator.Exclusions)
	return receipt
}

func cloneOperationManifest(manifest OperationManifest) OperationManifest {
	manifest.IdentityContract.Fields = append([]string(nil), manifest.IdentityContract.Fields...)
	manifest.Summary.Protocols = copyCounts(manifest.Summary.Protocols)
	manifest.Summary.Eligibility = copyCounts(manifest.Summary.Eligibility)
	manifest.Summary.Exclusions = copyCounts(manifest.Summary.Exclusions)
	manifest.Operations = append([]ManifestOperation(nil), manifest.Operations...)
	return manifest
}

func endpointHost(operation ManifestOperation) string {
	if operation.Transport.Endpoint == nil {
		return ""
	}
	endpoint := *operation.Transport.Endpoint
	withoutScheme := strings.SplitN(endpoint, "://", 2)
	if len(withoutScheme) != 2 {
		return ""
	}
	return strings.SplitN(withoutScheme[1], "/", 2)[0]
}
