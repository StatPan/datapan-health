package archive

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/StatPan/datapan-health/internal/health"
	"github.com/parquet-go/parquet-go"
)

func TestArchiveExportsUnmodifiedCLIReceiptWithActiveRelease(t *testing.T) {
	current := currentSISULReceipt(t)
	root := t.TempDir()
	manifest, err := Export(context.Background(), writeInput(t, []string{current}), root, "../../config/archive.json", "../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig("../../config/archive.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.InputCatalogs) != 1 || manifest.InputCatalogs[0] != config.ActiveRegistry || manifest.Provenance.DatapanRegistry.CatalogRevision == config.ActiveRegistry.RegistryDatasetRevision {
		t.Fatal("active input release and historical contract authority were not separated")
	}
	rows, err := readObservations(filepath.Join(root, "observations", "date=2026-10-04", "part-00000.parquet"))
	if err != nil || len(rows) != 1 || rows[0].RegistryRevision != config.ActiveRegistry.RegistryDatasetRevision || rows[0].ServiceID != "public-data_bus-depot-status" {
		t.Fatalf("current CLI receipt projection failed: rows=%d err=%v", len(rows), err)
	}
	services, err := parquet.ReadFile[Service](filepath.Join(root, "services", "services.parquet"))
	if err != nil || len(services) != 10 {
		t.Fatalf("service projection failed: %v", err)
	}
	for _, service := range services {
		if service.CatalogRevision != config.ActiveRegistry.RegistryDatasetRevision {
			t.Fatal("service mapping claimed historical contract revision as the active release")
		}
	}
}

func TestArchivePreservesHistoricalPolicyAndOperationLineage(t *testing.T) {
	current := currentSISULReceipt(t)
	previous := historicalSISULFixture(t, 1)
	legacy := historicalSISULFixture(t, 0)
	var legacyDocument map[string]any
	if err := json.Unmarshal([]byte(legacy), &legacyDocument); err != nil {
		t.Fatal(err)
	}
	delete(legacyDocument, "policy") // Only the original v1 release permits absence.
	legacyBytes, err := json.Marshal(legacyDocument)
	if err != nil {
		t.Fatal(err)
	}
	input := writeInput(t, []string{current, previous, legacy, string(legacyBytes)})
	root := t.TempDir()
	manifest, err := Export(context.Background(), input, root, "../../config/archive.json", "../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.InputCatalogs) != 3 {
		t.Fatal("mixed inputs did not retain all three exact catalog bindings")
	}
	rows, err := readObservations(filepath.Join(root, "observations", "date=2026-10-04", "part-00000.parquet"))
	if err != nil || len(rows) != 3 { // Two legacy policy representations have one safe projection.
		t.Fatalf("historical projection/deduplication failed: rows=%d err=%v", len(rows), err)
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if row.ServiceID != "public-data_bus-depot-status" {
			t.Fatal("stable historical service mapping changed")
		}
		seen[row.RegistryRevision] = true
	}
	for _, binding := range manifest.InputCatalogs {
		if !seen[binding.RegistryDatasetRevision] {
			t.Fatal("historical observation was rewritten to the current Registry revision")
		}
	}
	canaries, err := health.LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	oldReceipt, err := health.DecodeReceipt(strings.NewReader(previous))
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range canaries.Canaries {
		if canary.OperationID == "dpr-op-00000009" {
			if _, err := canaries.AdmitScheduledReceipt(oldReceipt, canary, oldReceipt.ObservedAt, oldReceipt.ObservedAt); err == nil {
				t.Fatal("archive compatibility admitted historical SISUL evidence into the live pipeline")
			}
		}
	}
}

func TestArchiveRejectsUnreviewedReceiptBeforeWriting(t *testing.T) {
	for _, test := range []struct {
		name   string
		input  string
		mutate func(map[string]any)
	}{
		{"unknown_revision", currentSISULReceipt(t), func(d map[string]any) { d["registry"].(map[string]any)["dataset_revision"] = strings.Repeat("a", 40) }},
		{"wrong_manifest", historicalSISULFixture(t, 1), func(d map[string]any) { d["registry"].(map[string]any)["manifest_sha256"] = strings.Repeat("b", 64) }},
		{"wrong_source", historicalSISULFixture(t, 0), func(d map[string]any) { d["registry"].(map[string]any)["registry_sha256"] = strings.Repeat("c", 64) }},
		{"wrong_distribution", currentSISULReceipt(t), func(d map[string]any) { d["registry"].(map[string]any)["dataset_id"] = "15158559" }},
		{"old_policy_on_current", currentSISULReceipt(t), func(d map[string]any) { d["policy"].(map[string]any)["version"] = 1 }},
		{"missing_current_policy", currentSISULReceipt(t), func(d map[string]any) { delete(d, "policy") }},
		{"missing_previous_policy", historicalSISULFixture(t, 1), func(d map[string]any) { delete(d, "policy") }},
		{"wrong_historical_alias", historicalSISULFixture(t, 1), func(d map[string]any) { d["operation"].(map[string]any)["dataset_id"] = "15158559" }},
		{"wrong_historical_operation", historicalSISULFixture(t, 0), func(d map[string]any) { d["operation"].(map[string]any)["operation_key"] = strings.Repeat("d", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var document map[string]any
			if err := json.Unmarshal([]byte(test.input), &document); err != nil {
				t.Fatal(err)
			}
			test.mutate(document)
			data, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(t.TempDir(), "must-not-exist")
			if _, err := Export(context.Background(), writeInput(t, []string{string(data)}), root, "../../config/archive.json", "../../config/canaries.json"); err == nil {
				t.Fatal("unreviewed receipt was accepted")
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatal("rejected input wrote output")
			}
		})
	}
}

func TestArchiveRejectsConfigAndHistoricalCatalogDriftBeforeWriting(t *testing.T) {
	for _, name := range []string{"missing_active", "active_drift", "missing_history", "history_binding", "history_bytes", "contract_authority"} {
		t.Run(name, func(t *testing.T) {
			config, err := LoadConfig("../../config/archive.json")
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			copyArchiveCatalogs(t, root)
			switch name {
			case "contract_authority":
				config.DatapanRegistry.CatalogRevision = config.ActiveRegistry.RegistryDatasetRevision
			case "missing_active":
				config.ActiveRegistry = RegistryBinding{}
			case "active_drift":
				config.ActiveRegistry.CatalogSHA256 = strings.Repeat("a", 64)
			case "missing_history":
				config.HistoricalRegistryCatalogs = nil
			case "history_binding":
				config.HistoricalRegistryCatalogs[0].ReleaseManifestSHA256 = strings.Repeat("b", 64)
			case "history_bytes":
				if err := os.WriteFile(filepath.Join(root, config.HistoricalRegistryCatalogs[0].Path), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			configPath := filepath.Join(root, "archive.json")
			if err := writeJSONAtomic(configPath, config); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(root, "must-not-exist")
			if _, err := Export(context.Background(), writeInput(t, []string{currentSISULReceipt(t)}), output, configPath, "../../config/canaries.json"); err == nil {
				t.Fatal("archive configuration/catalog drift was accepted")
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("rejected config wrote output")
			}
		})
	}
}

func TestArchiveIncrementalExportRetainsMixedCatalogBindings(t *testing.T) {
	root := t.TempDir()
	if _, err := Export(context.Background(), writeInput(t, []string{historicalSISULFixture(t, 0)}), root, "../../config/archive.json", "../../config/canaries.json"); err != nil {
		t.Fatal(err)
	}
	input := writeInput(t, []string{currentSISULReceipt(t)})
	manifest, err := Export(context.Background(), input, root, "../../config/archive.json", "../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.InputCatalogs) != 2 {
		t.Fatal("manifest omitted retained historical observations' catalog binding")
	}
	rows, err := readObservations(filepath.Join(root, "observations", "date=2026-10-04", "part-00000.parquet"))
	if err != nil || len(rows) != 2 {
		t.Fatalf("incremental export lost or duplicated history: %v", err)
	}
	retry, err := Export(context.Background(), input, root, "../../config/archive.json", "../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	if retry.BatchID != manifest.BatchID || !retry.CreatedAt.Equal(manifest.CreatedAt) || !sameJSON(retry.InputCatalogs, manifest.InputCatalogs) {
		t.Fatal("completed checkpoint did not return the persisted manifest")
	}
}

func TestArchiveCheckpointDoesNotReuseOldProvenance(t *testing.T) {
	input := writeInput(t, []string{currentSISULReceipt(t)})
	root := t.TempDir()
	first, err := Export(context.Background(), input, root, "../../config/archive.json", "../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig("../../config/archive.json")
	if err != nil {
		t.Fatal(err)
	}
	config.DatasetRepo = "StatPan/datapan-health-observations-qa"
	configRoot := t.TempDir()
	copyArchiveCatalogs(t, configRoot)
	configPath := filepath.Join(configRoot, "archive.json")
	if err := writeJSONAtomic(configPath, config); err != nil {
		t.Fatal(err)
	}
	second, err := Export(context.Background(), input, root, configPath, "../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	if second.BatchID == first.BatchID {
		t.Fatal("changed provenance reused the old batch checkpoint")
	}
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var persisted Manifest
	if err := json.Unmarshal(data, &persisted); err != nil {
		t.Fatal(err)
	}
	if persisted.Provenance.DatasetRepo != config.DatasetRepo || persisted.BatchID != second.BatchID || len(persisted.InputCatalogs) != 1 {
		t.Fatal("changed provenance was not persisted")
	}
	rows, err := readObservations(filepath.Join(root, "observations", "date=2026-10-04", "part-00000.parquet"))
	if err != nil || len(rows) != 1 {
		t.Fatalf("provenance migration duplicated rows: %v", err)
	}
}

func currentSISULReceipt(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../testdata/receipts/cli-catalog/v0.1.40-sisul-gateway-candidate.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Synthetic historical inputs preserve each pinned catalog's original aliases
// and policy. They are compatibility tests, not historical CLI execution proof.
func historicalSISULFixture(t *testing.T, index int) string {
	t.Helper()
	receipt, err := health.DecodeReceipt(strings.NewReader(currentSISULReceipt(t)))
	if err != nil {
		t.Fatal(err)
	}
	record := acceptedHistoricalCatalogs()[index]
	catalog, err := health.LoadCatalog(filepath.Join("../../config", record.Path), record.CatalogSHA256)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range catalog.Entries {
		if entry.OperationID != "dpr-op-00000009" {
			continue
		}
		receipt.Registry = health.Registry{DatasetID: "StatPan/datapan-registry", DatasetRevision: record.RegistryDatasetRevision, RegistrySHA256: record.SourceRegistrySHA256, ManifestSHA256: record.ReleaseManifestSHA256}
		receipt.Operation = health.Operation{OperationKey: entry.Aliases.CLIOperationKey, DatasetID: entry.Aliases.DatasetID, OperationName: entry.Aliases.OperationName, Provider: entry.Provider, EndpointHost: entry.Endpoint.Host, EndpointPath: entry.Endpoint.Path, DependencyClass: entry.Endpoint.DependencyClass}
		receipt.Policy = &health.Policy{Key: entry.Policy.Key, Version: entry.Policy.Version, Authority: entry.Policy.Authority, MaxLevel: entry.Policy.MaxLevel}
		data, err := json.Marshal(receipt)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	t.Fatal("historical SISUL operation missing")
	return ""
}

func copyArchiveCatalogs(t *testing.T, root string) {
	t.Helper()
	for _, record := range acceptedHistoricalCatalogs() {
		data, err := os.ReadFile(filepath.Join("../../config", record.Path))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, record.Path)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
