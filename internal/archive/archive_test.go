package archive

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/schemas"
	_ "github.com/marcboeker/go-duckdb"
	"github.com/parquet-go/parquet-go"
	"github.com/parquet-go/parquet-go/format"
)

func TestArchiveProjectionMinimizationIdempotencyAndParquet(t *testing.T) {
	input := writeInput(t, cliStyleRows(t))
	root := t.TempDir()
	manifest, err := Export(context.Background(), input, root, "../../config/archive.json", "../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != SchemaVersion || len(manifest.Files) != 5 {
		t.Fatalf("unexpected archive manifest: %#v", manifest)
	}
	observations := filepath.Join(root, "observations", "date=2026-07-13", "part-00000.parquet")
	rows, err := readObservations(observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("got %d observations", len(rows))
	}
	for _, row := range rows {
		encoded, _ := json.Marshal(row)
		if err := schemas.ValidateHealthArchiveV1(encoded); err != nil {
			t.Fatalf("safe projection did not validate: %v", err)
		}
		for _, forbidden := range []string{"dataset_id", "endpoint_path", "provider_message", "reason_code", "next_actions", "query", "credential", "response_rows"} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatalf("public projection leaked %q: %s", forbidden, encoded)
			}
		}
	}
	var invalid map[string]any
	encoded, _ := json.Marshal(rows[0])
	if err := json.Unmarshal(encoded, &invalid); err != nil {
		t.Fatal(err)
	}
	invalid["dataset_id"] = "must-not-publish"
	encoded, _ = json.Marshal(invalid)
	if err := schemas.ValidateHealthArchiveV1(encoded); err == nil {
		t.Fatal("strict archive schema accepted forbidden dataset identifier")
	}
	for _, path := range []string{
		observations,
		filepath.Join(root, "incidents", "date=2026-07-13", "part-00000.parquet"),
		filepath.Join(root, "daily_rollups", "date=2026-07-13", "part-00000.parquet"),
		filepath.Join(root, "services", "services.parquet"),
	} {
		assertZstd(t, path)
	}
	if _, err := Export(context.Background(), input, root, "../../config/archive.json", "../../config/canaries.json"); err != nil {
		t.Fatal(err)
	}
	rows, err = readObservations(observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("re-run duplicated logical rows: %d", len(rows))
	}
	if err := os.Remove(filepath.Join(root, "checkpoints", manifest.BatchID+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := Export(context.Background(), input, root, "../../config/archive.json", "../../config/canaries.json"); err != nil {
		t.Fatal(err)
	}
	rows, err = readObservations(observations)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("checkpoint retry duplicated logical rows: %d", len(rows))
	}
}

func TestArchiveProvenancePinsMergedCLIAndRegistryContracts(t *testing.T) {
	config, err := LoadConfig("../../config/archive.json")
	if err != nil {
		t.Fatal(err)
	}
	if config.DatapanCLI.Issue != "https://github.com/StatPan/datapan-cli/pull/150" || config.DatapanCLI.Commit != "2fc8343993b7704b50f7d50fcba2642fca439c7f" || config.DatapanCLI.ReceiptSchemaSHA256 != "b755a5af33152bcb36dc7c2382b94857953d0a9359b6b77cd8b2cb093d0a820d" {
		t.Fatalf("unexpected datapan-cli #150 provenance: %#v", config.DatapanCLI)
	}
	if config.DatapanRegistry.Issue != "https://github.com/StatPan/datapan-registry/issues/550" || config.DatapanRegistry.CatalogRevision != "2186f9b447fdd72c2292aaa8b18d64b2eff5eb38" || config.DatapanRegistry.CatalogSHA256 != "5ca3a6c353c558c5a333fac25238a9db3fe3adadc212c8fa144a2970da43d7e3" {
		t.Fatalf("unexpected datapan-registry #550 provenance: %#v", config.DatapanRegistry)
	}
}

func TestMonthlyCompactionAndDuckDBQueries(t *testing.T) {
	rows := cliStyleRows(t)
	rows = append(rows, strings.Replace(rows[0], "2026-07-13T00:00:00Z", "2026-07-14T00:00:00Z", 1))
	root := t.TempDir()
	if _, err := Export(context.Background(), writeInput(t, rows), root, "../../config/archive.json", "../../config/canaries.json"); err != nil {
		t.Fatal(err)
	}
	monthly, err := CompactMonth(root, "2026-07")
	if err != nil {
		t.Fatal(err)
	}
	assertZstd(t, monthly)
	count, healthy, p50, p95, err := DuckDBMetrics(monthly, "public-data_holiday-emergency-clinics")
	if err != nil {
		t.Fatal(err)
	}
	if count != 4 || healthy != 2 || p50 <= 0 || p95 <= 0 {
		t.Fatalf("unexpected DuckDB projection/filter query: count=%d healthy=%d p50=%f p95=%f", count, healthy, p50, p95)
	}
	assertDuckDBPushdown(t, monthly)
}

func TestPublicationUnavailableIsFailureIsolated(t *testing.T) {
	t.Setenv("HF_TOKEN", "")
	if err := (HFCLI{}).Publish(context.Background(), "StatPan/datapan-health-observations", t.TempDir()); err != ErrPublicationUnavailable {
		t.Fatalf("got %v", err)
	}
}

func TestPublicationRetriesOutsideTheLivePath(t *testing.T) {
	publisher := &retryPublisher{failures: 2}
	if err := PublishWithRetry(context.Background(), publisher, "StatPan/datapan-health-observations", t.TempDir(), 3, 0); err != nil {
		t.Fatal(err)
	}
	if publisher.calls != 3 {
		t.Fatalf("got %d publication calls, want 3", publisher.calls)
	}
	publisher = &retryPublisher{err: ErrPublicationUnavailable}
	if err := PublishWithRetry(context.Background(), publisher, "StatPan/datapan-health-observations", t.TempDir(), 3, time.Millisecond); err != ErrPublicationUnavailable || publisher.calls != 1 {
		t.Fatalf("unavailable publisher should not retry: calls=%d err=%v", publisher.calls, err)
	}
}

func TestPublicationStageExcludesCheckpoints(t *testing.T) {
	root := t.TempDir()
	for path, value := range map[string]string{
		"observations/date=2026-07-13/part-00000.parquet": "parquet",
		"checkpoints/retry.json":                          "not public",
		"README.md":                                       "# card",
		"manifest.json":                                   "{}",
	} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stage, err := stagePublication(root)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stage)
	if _, err := os.Stat(filepath.Join(stage, "checkpoints", "retry.json")); !os.IsNotExist(err) {
		t.Fatalf("checkpoint reached publication stage: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stage, "observations", "date=2026-07-13", "part-00000.parquet")); err != nil {
		t.Fatal(err)
	}
}

type retryPublisher struct {
	calls    int
	failures int
	err      error
}

func (p *retryPublisher) Publish(context.Context, string, string) error {
	p.calls++
	if p.err != nil {
		return p.err
	}
	if p.calls <= p.failures {
		return errors.New("temporary Hugging Face outage")
	}
	return nil
}

func assertZstd(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	file, err := parquet.OpenFile(f, stat.Size())
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Metadata().RowGroups) == 0 || len(file.Metadata().RowGroups[0].Columns) == 0 || file.Metadata().RowGroups[0].Columns[0].MetaData.Codec != format.Zstd {
		t.Fatal("archive is not ZSTD Parquet")
	}
}

func assertDuckDBPushdown(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("duckdb", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("EXPLAIN SELECT service_id, outcome FROM " + readParquet(quoteSQL(path)) + " WHERE service_id = 'public-data_holiday-emergency-clinics'")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(key)
		plan.WriteString(value)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if (!strings.Contains(plan.String(), "PARQUET_SCAN") && !strings.Contains(plan.String(), "READ_PARQUET")) || !strings.Contains(plan.String(), "Projections") || !strings.Contains(plan.String(), "Filters") || !strings.Contains(plan.String(), "service_id") {
		t.Fatalf("DuckDB did not explain Parquet projection/filter pushdown: %s", plan.String())
	}
}

func writeInput(t *testing.T, rows []string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "receipts.jsonl")
	lines := make([]string, 0, len(rows))
	for _, row := range rows {
		var document any
		if err := json.Unmarshal([]byte(row), &document); err != nil {
			t.Fatal(err)
		}
		compact, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(compact))
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func cliStyleRows(t *testing.T) []string {
	t.Helper()
	healthy, err := os.ReadFile("../../testdata/receipts/v1/healthy.json")
	if err != nil {
		t.Fatal(err)
	}
	unhealthy, err := os.ReadFile("../../testdata/receipts/v1/unhealthy.json")
	if err != nil {
		t.Fatal(err)
	}
	indeterminate := mutateAssessment(t, string(healthy), "indeterminate", "indeterminate", "7b8ce434-e662-4f17-a239-0b8ad0d6a29d")
	skipped := mutateAssessment(t, string(healthy), "skipped", "skipped", "7b8ce434-e662-4f17-a239-0b8ad0d6a29c")
	return []string{string(healthy), string(unhealthy), indeterminate, skipped}
}

func mutateAssessment(t *testing.T, receipt, outcome, category, probeID string) string {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal([]byte(receipt), &document); err != nil {
		t.Fatal(err)
	}
	document["probe_id"] = probeID
	assessment := document["assessment"].(map[string]any)
	assessment["outcome"], assessment["category"], assessment["reason_code"] = outcome, category, category
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
