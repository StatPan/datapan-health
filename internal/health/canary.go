package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

var gatusKeyPattern = regexp.MustCompile(`^[a-z0-9-]+_[a-z0-9-]+$`)

// CanaryConfig is deliberately an allowlist of Registry operation IDs, not a
// second operation catalog. The detailed probe policy remains Registry-owned.
type CanaryConfig struct {
	CatalogPath       string   `json:"catalog_path"`
	CatalogSHA256     string   `json:"catalog_sha256"`
	GlobalConcurrency int      `json:"global_concurrency"`
	JitterSeconds     int      `json:"jitter_seconds"`
	Canaries          []Canary `json:"canaries"`
	catalog           Catalog
}

type Canary struct {
	OperationID                       string `json:"operation_id"`
	GatusEndpointKey                  string `json:"gatus_endpoint_key"`
	Tier                              string `json:"tier"`
	IntervalMinutes                   int    `json:"interval_minutes"`
	HeartbeatMinutes                  int    `json:"heartbeat_minutes"`
	ConsecutiveFailuresBeforeIncident int    `json:"consecutive_failures_before_incident"`
	MissedSchedulesBeforeHeartbeat    int    `json:"missed_schedules_before_heartbeat"`
}

func LoadCanaryConfig(path string) (CanaryConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return CanaryConfig{}, err
	}
	var config CanaryConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return CanaryConfig{}, errors.New("invalid canary configuration")
	}
	if config.GlobalConcurrency < 1 || config.GlobalConcurrency > 32 || config.JitterSeconds < 0 || !sha256Pattern.MatchString(config.CatalogSHA256) || config.CatalogPath == "" {
		return CanaryConfig{}, errors.New("invalid canary configuration")
	}
	catalogPath := config.CatalogPath
	if !filepath.IsAbs(catalogPath) {
		catalogPath = filepath.Join(filepath.Dir(path), catalogPath)
	}
	catalog, err := LoadCatalog(catalogPath, config.CatalogSHA256)
	if err != nil {
		return CanaryConfig{}, errors.New("invalid canary configuration")
	}
	seen := map[string]bool{}
	for _, canary := range config.Canaries {
		if !catalogOperationIDPattern.MatchString(canary.OperationID) || !gatusKeyPattern.MatchString(canary.GatusEndpointKey) || !validCadence(canary) || seen[canary.OperationID] || config.JitterSeconds >= canary.IntervalMinutes*60 {
			return CanaryConfig{}, errors.New("invalid canary configuration")
		}
		entry, ok := catalog.ByID(canary.OperationID)
		if !ok || !entry.Probeable() {
			return CanaryConfig{}, errors.New("invalid canary configuration")
		}
		seen[canary.OperationID] = true
	}
	if len(config.Canaries) == 0 {
		return CanaryConfig{}, errors.New("invalid canary configuration")
	}
	config.CatalogPath, config.catalog = catalogPath, catalog
	return config, nil
}

func validCadence(canary Canary) bool {
	if canary.ConsecutiveFailuresBeforeIncident != 2 || canary.MissedSchedulesBeforeHeartbeat != 2 || canary.HeartbeatMinutes != canary.IntervalMinutes*canary.MissedSchedulesBeforeHeartbeat {
		return false
	}
	switch canary.Tier {
	case "A":
		return canary.IntervalMinutes == 5
	case "B":
		return canary.IntervalMinutes == 10
	case "C":
		return canary.IntervalMinutes == 15
	default:
		return false
	}
}

func (c CanaryConfig) Resolve(receipt Receipt) (string, error) {
	canary, err := c.CanaryFor(receipt)
	if err != nil {
		return "", err
	}
	return canary.GatusEndpointKey, nil
}

func (c CanaryConfig) CanaryFor(receipt Receipt) (Canary, error) {
	for _, canary := range c.Canaries {
		entry, ok := c.catalog.ByID(canary.OperationID)
		if ok && entry.Aliases.CLIOperationKey == receipt.Operation.OperationKey {
			return canary, nil
		}
	}
	return Canary{}, errors.New("receipt operation is not a configured public canary")
}

func (c CanaryConfig) Entry(canary Canary) (CatalogEntry, bool) {
	return c.catalog.ByID(canary.OperationID)
}

// Catalog is the small, immutable projection that the composition layer needs.
// It never contains provider credentials or generated parameter values.
type Catalog struct {
	SchemaVersion   string          `json:"schema_version"`
	Authority       string          `json:"authority"`
	ReceiptContract ReceiptContract `json:"receipt_contract"`
	Entries         []CatalogEntry  `json:"entries"`
	byID            map[string]CatalogEntry
}

type ReceiptContract struct {
	Schema                string `json:"schema"`
	OperationKeyAlgorithm string `json:"operation_key_algorithm"`
	PolicyAuthority       string `json:"policy_authority"`
}

type CatalogEntry struct {
	OperationID string `json:"operation_id"`
	Policy      struct {
		Key       string `json:"key"`
		Version   int    `json:"version"`
		Authority string `json:"authority"`
	} `json:"policy"`
	Aliases struct {
		DatasetID       string `json:"dataset_id"`
		OperationName   string `json:"operation_name"`
		CLIOperationKey string `json:"cli_operation_key"`
	} `json:"aliases"`
	Endpoint struct {
		DependencyClass string `json:"dependency_class"`
	} `json:"endpoint"`
	Eligibility struct {
		Status string `json:"status"`
	} `json:"eligibility"`
	Execution struct {
		TimeoutCeilingMS int `json:"timeout_ceiling_ms"`
		RequestBudget    int `json:"request_budget"`
		SafeParameters   []struct {
			Name string `json:"name"`
		} `json:"safe_parameters"`
	} `json:"execution"`
}

func LoadCatalog(path, wantSHA256 string) (Catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Catalog{}, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != wantSHA256 {
		return Catalog{}, errors.New("catalog digest does not match pin")
	}
	var catalog Catalog
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&catalog); err != nil {
		return Catalog{}, err
	}
	if catalog.SchemaVersion != "datapan.health-probe-catalog.v1" || catalog.Authority != "datapan-registry" || catalog.ReceiptContract.Schema != "https://schemas.datapan.dev/datapan.health-probe.v1.schema.json" || catalog.ReceiptContract.OperationKeyAlgorithm != "datapan-cli-health-operation-key-v1" || catalog.ReceiptContract.PolicyAuthority != "datapan-registry" {
		return Catalog{}, errors.New("unsupported catalog contract")
	}
	catalog.byID = make(map[string]CatalogEntry, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		if entry.OperationID == "" || entry.Policy.Key != entry.OperationID || entry.Policy.Version < 1 || entry.Policy.Authority != "datapan-registry" || !sha256Pattern.MatchString(entry.Aliases.CLIOperationKey) || entry.Aliases.DatasetID == "" || entry.Aliases.OperationName == "" || entry.Endpoint.DependencyClass == "" || !entry.Probeable() || entry.Execution.TimeoutCeilingMS < 1000 || entry.Execution.TimeoutCeilingMS > 30000 || entry.Execution.RequestBudget != 1 || len(entry.Execution.SafeParameters) == 0 {
			return Catalog{}, errors.New("invalid catalog entry")
		}
		if _, duplicate := catalog.byID[entry.OperationID]; duplicate {
			return Catalog{}, errors.New("duplicate catalog operation")
		}
		names := make([]string, 0, len(entry.Execution.SafeParameters))
		for _, parameter := range entry.Execution.SafeParameters {
			if parameter.Name == "" {
				return Catalog{}, errors.New("invalid catalog parameter")
			}
			names = append(names, parameter.Name)
		}
		sort.Strings(names)
		for i := 1; i < len(names); i++ {
			if names[i] == names[i-1] {
				return Catalog{}, errors.New("duplicate catalog parameter")
			}
		}
		catalog.byID[entry.OperationID] = entry
	}
	return catalog, nil
}

func (e CatalogEntry) Probeable() bool {
	return e.Eligibility.Status == "eligible" || e.Eligibility.Status == "credential_required"
}
func (c Catalog) ByID(id string) (CatalogEntry, bool) { entry, ok := c.byID[id]; return entry, ok }
