// Package archive creates the asynchronous public history. It is not used by
// health-runner and therefore cannot participate in live Gatus delivery.
package archive

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
	"github.com/StatPan/datapan-health/schemas"
)

const SchemaVersion = "datapan.health-archive.v1"

type Config struct {
	SchemaVersion string `json:"schema_version"`
	DatasetRepo   string `json:"dataset_repo"`
	DatapanCLI    struct {
		Issue               string `json:"issue"`
		Commit              string `json:"commit"`
		ReceiptSchemaSHA256 string `json:"receipt_schema_sha256"`
	} `json:"datapan_cli"`
	DatapanRegistry struct {
		Issue           string `json:"issue"`
		CatalogRevision string `json:"catalog_revision"`
		CatalogSHA256   string `json:"catalog_sha256"`
	} `json:"datapan_registry"`
}

type Observation struct {
	ObservationID    string    `parquet:"observation_id" json:"observation_id"`
	ObservedAt       time.Time `parquet:"observed_at,timestamp(microsecond:utc)" json:"observed_at"`
	ServiceID        string    `parquet:"service_id" json:"service_id"`
	RegistryRevision string    `parquet:"registry_revision" json:"registry_revision"`
	Outcome          string    `parquet:"outcome" json:"outcome"`
	Category         string    `parquet:"category" json:"category"`
	LatencyMS        int64     `parquet:"latency_ms" json:"latency_ms"`
	DataPresence     string    `parquet:"data_presence" json:"data_presence"`
	SchemaStatus     string    `parquet:"schema_status" json:"schema_status"`
	FreshnessStatus  string    `parquet:"freshness_status" json:"freshness_status"`
	ScheduleTier     string    `parquet:"schedule_tier" json:"schedule_tier"`
}

type Incident struct {
	ObservedAt       time.Time `parquet:"observed_at,timestamp(microsecond:utc)" json:"observed_at"`
	ServiceID        string    `parquet:"service_id" json:"service_id"`
	RegistryRevision string    `parquet:"registry_revision" json:"registry_revision"`
	Outcome          string    `parquet:"outcome" json:"outcome"`
	Category         string    `parquet:"category" json:"category"`
	ScheduleTier     string    `parquet:"schedule_tier" json:"schedule_tier"`
}

type DailyRollup struct {
	DateUTC          string  `parquet:"date_utc" json:"date_utc"`
	ServiceID        string  `parquet:"service_id" json:"service_id"`
	RegistryRevision string  `parquet:"registry_revision" json:"registry_revision"`
	ScheduleTier     string  `parquet:"schedule_tier" json:"schedule_tier"`
	Observations     int64   `parquet:"observations" json:"observations"`
	Healthy          int64   `parquet:"healthy" json:"healthy"`
	Unhealthy        int64   `parquet:"unhealthy" json:"unhealthy"`
	Skipped          int64   `parquet:"skipped" json:"skipped"`
	Indeterminate    int64   `parquet:"indeterminate" json:"indeterminate"`
	P50LatencyMS     float64 `parquet:"p50_latency_ms" json:"p50_latency_ms"`
	P95LatencyMS     float64 `parquet:"p95_latency_ms" json:"p95_latency_ms"`
}

type Service struct {
	ServiceID                string `parquet:"service_id" json:"service_id"`
	CatalogOperationID       string `parquet:"catalog_operation_id" json:"catalog_operation_id"`
	CatalogRevision          string `parquet:"catalog_revision" json:"catalog_revision"`
	ScheduleTier             string `parquet:"schedule_tier" json:"schedule_tier"`
	IntervalMinutes          int64  `parquet:"interval_minutes" json:"interval_minutes"`
	HeartbeatMinutes         int64  `parquet:"heartbeat_minutes" json:"heartbeat_minutes"`
	IncidentFailureThreshold int64  `parquet:"incident_failure_threshold" json:"incident_failure_threshold"`
}

type Manifest struct {
	SchemaVersion string            `json:"schema_version"`
	BatchID       string            `json:"batch_id"`
	CreatedAt     time.Time         `json:"created_at"`
	Provenance    Config            `json:"provenance"`
	Files         map[string]string `json:"files"`
}

type Checkpoint struct {
	BatchID string            `json:"batch_id"`
	Files   map[string]string `json:"files"`
	Done    bool              `json:"done"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, errors.New("invalid archive configuration")
	}
	if config.SchemaVersion != SchemaVersion || config.DatasetRepo == "" || len(config.DatapanCLI.Commit) != 40 || len(config.DatapanCLI.ReceiptSchemaSHA256) != 64 || len(config.DatapanRegistry.CatalogRevision) != 40 || len(config.DatapanRegistry.CatalogSHA256) != 64 {
		return Config{}, errors.New("invalid archive provenance")
	}
	return config, nil
}

func Export(ctx context.Context, inputPath, outputDir, configPath, canaryPath string) (Manifest, error) {
	config, err := LoadConfig(configPath)
	if err != nil {
		return Manifest{}, err
	}
	canaries, err := health.LoadCanaryConfig(canaryPath)
	if err != nil {
		return Manifest{}, err
	}
	observations, err := projectInput(ctx, inputPath, canaries)
	if err != nil {
		return Manifest{}, err
	}
	batchID := hashObservations(observations)
	checkpointPath := filepath.Join(outputDir, "checkpoints", batchID+".json")
	if checkpoint, err := loadCheckpoint(checkpointPath); err == nil && checkpoint.Done && filesMatch(outputDir, checkpoint.Files) {
		return Manifest{SchemaVersion: SchemaVersion, BatchID: batchID, Provenance: config, Files: checkpoint.Files}, nil
	}
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return Manifest{}, err
	}
	files := map[string]string{}
	byDate := map[string][]Observation{}
	for _, observation := range observations {
		date := observation.ObservedAt.UTC().Format("2006-01-02")
		byDate[date] = append(byDate[date], observation)
	}
	for date, current := range byDate {
		path := filepath.Join(outputDir, "observations", "date="+date, "part-00000.parquet")
		existing, err := readObservations(path)
		if err != nil && !os.IsNotExist(err) {
			return Manifest{}, err
		}
		merged := dedupeObservations(append(existing, current...))
		if err := writeParquet(path, merged); err != nil {
			return Manifest{}, err
		}
		files[relative(outputDir, path)] = fileDigest(path)
		incidents := incidentsFor(merged)
		incidentPath := filepath.Join(outputDir, "incidents", "date="+date, "part-00000.parquet")
		if err := writeParquet(incidentPath, incidents); err != nil {
			return Manifest{}, err
		}
		files[relative(outputDir, incidentPath)] = fileDigest(incidentPath)
		rollups := rollupsFor(date, merged)
		rollupPath := filepath.Join(outputDir, "daily_rollups", "date="+date, "part-00000.parquet")
		if err := writeParquet(rollupPath, rollups); err != nil {
			return Manifest{}, err
		}
		files[relative(outputDir, rollupPath)] = fileDigest(rollupPath)
	}
	services := servicesFor(canaries, config)
	servicePath := filepath.Join(outputDir, "services", "services.parquet")
	if err := writeParquet(servicePath, services); err != nil {
		return Manifest{}, err
	}
	files[relative(outputDir, servicePath)] = fileDigest(servicePath)
	manifest := Manifest{SchemaVersion: SchemaVersion, BatchID: batchID, CreatedAt: time.Now().UTC(), Provenance: config, Files: files}
	if err := writeJSONAtomic(filepath.Join(outputDir, "manifest.json"), manifest); err != nil {
		return Manifest{}, err
	}
	files["manifest.json"] = fileDigest(filepath.Join(outputDir, "manifest.json"))
	if err := writeJSONAtomic(checkpointPath, Checkpoint{BatchID: batchID, Files: files, Done: true}); err != nil {
		return Manifest{}, err
	}
	manifest.Files = files
	return manifest, nil
}

func projectInput(ctx context.Context, path string, canaries health.CanaryConfig) ([]Observation, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rows []Observation
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		receipt, err := health.DecodeReceipt(strings.NewReader(scanner.Text()))
		if err != nil {
			return nil, errors.New("archive input contains invalid health receipt")
		}
		canary, err := canaries.CanaryFor(receipt)
		if err != nil {
			return nil, err
		}
		row := Observation{ObservedAt: receipt.ObservedAt.UTC(), ServiceID: canary.GatusEndpointKey, RegistryRevision: receipt.Registry.DatasetRevision, Outcome: receipt.Assessment.Outcome, Category: receipt.Assessment.Category, LatencyMS: receipt.Observation.LatencyMS, DataPresence: receipt.Observation.DataPresence, SchemaStatus: receipt.Observation.SchemaStatus, FreshnessStatus: receipt.Observation.FreshnessStatus, ScheduleTier: canary.Tier}
		row.ObservationID = observationID(row)
		encoded, err := json.Marshal(row)
		if err != nil || schemas.ValidateHealthArchiveV1(encoded) != nil {
			return nil, errors.New("archive projection is invalid")
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return dedupeObservations(rows), nil
}

func observationID(row Observation) string {
	data, _ := json.Marshal(row)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func hashObservations(rows []Observation) string {
	data, _ := json.Marshal(rows)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func relative(root, path string) string {
	value, _ := filepath.Rel(root, path)
	return filepath.ToSlash(value)
}

func dedupeObservations(rows []Observation) []Observation {
	set := map[string]Observation{}
	for _, row := range rows {
		set[row.ObservationID] = row
	}
	result := make([]Observation, 0, len(set))
	for _, row := range set {
		result = append(result, row)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ObservedAt.Equal(result[j].ObservedAt) {
			return result[i].ObservationID < result[j].ObservationID
		}
		return result[i].ObservedAt.Before(result[j].ObservedAt)
	})
	return result
}

func incidentsFor(rows []Observation) []Incident {
	result := []Incident{}
	for _, row := range rows {
		if row.Outcome != "healthy" {
			result = append(result, Incident{row.ObservedAt, row.ServiceID, row.RegistryRevision, row.Outcome, row.Category, row.ScheduleTier})
		}
	}
	return result
}
func servicesFor(config health.CanaryConfig, archive Config) []Service {
	result := make([]Service, 0, len(config.Canaries))
	for _, c := range config.Canaries {
		result = append(result, Service{c.GatusEndpointKey, c.OperationID, archive.DatapanRegistry.CatalogRevision, c.Tier, int64(c.IntervalMinutes), int64(c.HeartbeatMinutes), int64(c.ConsecutiveFailuresBeforeIncident)})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ServiceID < result[j].ServiceID })
	return result
}

func rollupsFor(date string, rows []Observation) []DailyRollup {
	groups := map[string][]Observation{}
	for _, row := range rows {
		groups[row.ServiceID+"\x00"+row.RegistryRevision] = append(groups[row.ServiceID+"\x00"+row.RegistryRevision], row)
	}
	result := []DailyRollup{}
	for _, group := range groups {
		first := group[0]
		rollup := DailyRollup{DateUTC: date, ServiceID: first.ServiceID, RegistryRevision: first.RegistryRevision, ScheduleTier: first.ScheduleTier, Observations: int64(len(group))}
		latency := []int64{}
		for _, row := range group {
			switch row.Outcome {
			case "healthy":
				rollup.Healthy++
			case "unhealthy":
				rollup.Unhealthy++
			case "skipped":
				rollup.Skipped++
			case "indeterminate":
				rollup.Indeterminate++
			}
			latency = append(latency, row.LatencyMS)
		}
		sort.Slice(latency, func(i, j int) bool { return latency[i] < latency[j] })
		rollup.P50LatencyMS = percentile(latency, .5)
		rollup.P95LatencyMS = percentile(latency, .95)
		result = append(result, rollup)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ServiceID < result[j].ServiceID })
	return result
}
func percentile(values []int64, q float64) float64 {
	if len(values) == 0 {
		return 0
	}
	index := int(float64(len(values)-1) * q)
	return float64(values[index])
}

func loadCheckpoint(path string) (Checkpoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Checkpoint{}, err
	}
	var c Checkpoint
	err = json.Unmarshal(data, &c)
	return c, err
}
func filesMatch(root string, files map[string]string) bool {
	for path, want := range files {
		if fileDigest(filepath.Join(root, path)) != want {
			return false
		}
	}
	return true
}
func fileDigest(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
func writeJSONAtomic(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, data)
}
func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".partial-*")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if _, err = temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
func validateManifest(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaVersion || manifest.BatchID == "" {
		return fmt.Errorf("invalid archive manifest")
	}
	return nil
}
