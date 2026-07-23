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
