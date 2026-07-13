package archive

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/marcboeker/go-duckdb"
)

// CompactMonth rewrites completed UTC daily observation shards into one ZSTD
// Parquet file and proves row/count equivalence with DuckDB before publishing.
func CompactMonth(root, month string) (string, error) {
	daily, err := filepath.Glob(filepath.Join(root, "observations", "date="+month+"-*", "part-00000.parquet"))
	if err != nil {
		return "", err
	}
	if len(daily) == 0 {
		return "", fmt.Errorf("no completed daily shards for %s", month)
	}
	sort.Strings(daily)
	output := filepath.Join(root, "observations", "month="+month, "observations.parquet")
	if err := os.MkdirAll(filepath.Dir(output), 0o750); err != nil {
		return "", err
	}
	temporary := output + ".partial"
	_ = os.Remove(temporary)
	db, err := sql.Open("duckdb", "")
	if err != nil {
		return "", err
	}
	defer db.Close()
	files := parquetList(daily)
	copySQL := "COPY (SELECT * FROM " + readParquet(files) + " ORDER BY observed_at, service_id, observation_id) TO " + quoteSQL(temporary) + " (FORMAT PARQUET, COMPRESSION ZSTD)"
	if _, err := db.Exec(copySQL); err != nil {
		return "", err
	}
	if err := verifyEquivalent(db, files, quoteSQL(temporary)); err != nil {
		return "", err
	}
	if err := os.Rename(temporary, output); err != nil {
		return "", err
	}
	return output, nil
}

func DuckDBMetrics(parquetPath, serviceID string) (count int64, healthy int64, p50, p95 float64, err error) {
	db, err := sql.Open("duckdb", "")
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer db.Close()
	err = db.QueryRow("SELECT count(*), count(*) FILTER (WHERE outcome = 'healthy'), quantile_cont(latency_ms, 0.5), quantile_cont(latency_ms, 0.95) FROM "+readParquet(quoteSQL(parquetPath))+" WHERE service_id = "+quoteSQL(serviceID)).Scan(&count, &healthy, &p50, &p95)
	return
}

func verifyEquivalent(db *sql.DB, daily, monthly string) error {
	for _, query := range []string{
		"SELECT count(*) FROM (SELECT * FROM " + readParquet(daily) + " EXCEPT ALL SELECT * FROM " + readParquet(monthly) + ") AS missing_from_monthly",
		"SELECT count(*) FROM (SELECT * FROM " + readParquet(monthly) + " EXCEPT ALL SELECT * FROM " + readParquet(daily) + ") AS missing_from_daily",
	} {
		var difference int64
		if err := db.QueryRow(query).Scan(&difference); err != nil {
			return err
		}
		if difference != 0 {
			return fmt.Errorf("monthly compaction changed logical rows")
		}
	}
	return nil
}

func parquetList(paths []string) string {
	values := make([]string, 0, len(paths))
	for _, path := range paths {
		values = append(values, quoteSQL(path))
	}
	return "[" + strings.Join(values, ",") + "]"
}
func readParquet(paths string) string { return "read_parquet(" + paths + ", hive_partitioning=false)" }
func quoteSQL(value string) string    { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
