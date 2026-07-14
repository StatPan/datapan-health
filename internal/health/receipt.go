package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

const SchemaVersion = "datapan.health-probe.v1"

var (
	uuidPattern               = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	sha256Pattern             = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern             = regexp.MustCompile(`^[0-9a-f]{40}$`)
	catalogOperationIDPattern = regexp.MustCompile(`^dpr-op-[0-9]{8}$`)
	releaseTagPattern         = regexp.MustCompile(`^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}$`)
)

// Receipt is the canonical datapan.health-probe.v1 contract from datapan-cli.
// Its detailed, already-redacted fields are sink-only; Gatus never receives them.
type Receipt struct {
	SchemaVersion string      `json:"schema_version"`
	ProbeID       string      `json:"probe_id"`
	ObservedAt    time.Time   `json:"observed_at"`
	Operation     Operation   `json:"operation"`
	Registry      Registry    `json:"registry"`
	Policy        *Policy     `json:"policy,omitempty"`
	Execution     Execution   `json:"execution"`
	Observation   Observation `json:"observation"`
	Assessment    Assessment  `json:"assessment"`
	Redaction     Redaction   `json:"redaction"`
}

type Operation struct {
	OperationKey    string `json:"operation_key"`
	DatasetID       string `json:"dataset_id"`
	OperationName   string `json:"operation_name"`
	Provider        string `json:"provider"`
	EndpointHost    string `json:"endpoint_host,omitempty"`
	EndpointPath    string `json:"endpoint_path,omitempty"`
	DependencyClass string `json:"dependency_class"`
}

type Registry struct {
	DatasetID       string `json:"dataset_id"`
	DatasetRevision string `json:"dataset_revision"`
	RegistrySHA256  string `json:"registry_sha256"`
	ManifestSHA256  string `json:"manifest_sha256,omitempty"`
}

type Policy struct {
	Key       string `json:"key"`
	Version   int    `json:"version"`
	Authority string `json:"authority"`
	MaxLevel  string `json:"max_level"`
}

type Execution struct {
	CLIVersion         string   `json:"cli_version"`
	Attempted          bool     `json:"attempted"`
	TimeoutMS          int64    `json:"timeout_ms"`
	RequestBudget      int      `json:"request_budget"`
	SafeParameterNames []string `json:"safe_parameter_names,omitempty"`
}

type Observation struct {
	MaxLevel             string `json:"max_level"`
	LatencyMS            int64  `json:"latency_ms,omitempty"`
	HTTPStatus           int    `json:"http_status,omitempty"`
	ProviderCode         string `json:"provider_code,omitempty"`
	ProviderMessageClass string `json:"provider_message_class,omitempty"`
	SemanticStatus       string `json:"semantic_status,omitempty"`
	BodyShape            string `json:"body_shape,omitempty"`
	DataPresence         string `json:"data_presence"`
	SchemaStatus         string `json:"schema_status"`
	FreshnessStatus      string `json:"freshness_status"`
}

type Assessment struct {
	Outcome     string   `json:"outcome"`
	Category    string   `json:"category"`
	Retryable   bool     `json:"retryable"`
	ReasonCode  string   `json:"reason_code"`
	NextActions []string `json:"next_actions,omitempty"`
}

type Redaction struct {
	CredentialsRemoved  bool `json:"credentials_removed"`
	QueryValuesRemoved  bool `json:"query_values_removed"`
	ResponseRowsRemoved bool `json:"response_rows_removed"`
}

func ReadReceipt(path string) (Receipt, error) {
	f, err := os.Open(path)
	if err != nil {
		return Receipt{}, err
	}
	defer f.Close()
	return DecodeReceipt(f)
}

func DecodeReceipt(r io.Reader) (Receipt, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64*1024+1))
	if err != nil {
		return Receipt{}, err
	}
	if len(data) > 64*1024 {
		return Receipt{}, errors.New("receipt exceeds 64 KiB")
	}
	if err := schemas.ValidateHealthProbeV1(data); err != nil {
		return Receipt{}, err
	}
	var receipt Receipt
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return Receipt{}, fmt.Errorf("invalid health receipt: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Receipt{}, err
	}
	if err := receipt.Validate(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("receipt must contain exactly one JSON object")
	}
	return nil
}

func (r Receipt) Validate() error {
	if r.SchemaVersion != SchemaVersion || !uuidPattern.MatchString(r.ProbeID) || r.ObservedAt.IsZero() {
		return errors.New("receipt identity is invalid")
	}
	if !sha256Pattern.MatchString(r.Operation.OperationKey) || r.Operation.DatasetID == "" || r.Operation.OperationName == "" || r.Operation.Provider == "" || r.Operation.DependencyClass == "" {
		return errors.New("receipt operation is invalid")
	}
	if r.Registry.DatasetID == "" || !sha256Pattern.MatchString(r.Registry.RegistrySHA256) || r.Execution.CLIVersion == "" || r.Execution.TimeoutMS < 1 || r.Execution.RequestBudget < 0 || r.Observation.LatencyMS < 0 {
		return errors.New("receipt execution or provenance is invalid")
	}
	if !validOutcome(r.Assessment.Outcome) || !validCategory(r.Assessment.Category) || r.Assessment.ReasonCode == "" {
		return errors.New("receipt assessment is invalid")
	}
	if !r.Redaction.CredentialsRemoved || !r.Redaction.QueryValuesRemoved || !r.Redaction.ResponseRowsRemoved {
		return errors.New("receipt redaction assertions are required")
	}
	return nil
}

func validOutcome(value string) bool {
	return value == "healthy" || value == "unhealthy" || value == "skipped" || value == "indeterminate"
}

func validCategory(value string) bool {
	switch value {
	case "healthy", "transport_failure", "timeout", "rate_limited", "credential_missing", "credential_rejected", "parameter_blocked", "provider_failure", "semantic_failure", "schema_drift", "unsupported", "skipped", "indeterminate":
		return true
	default:
		return false
	}
}
