package health

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/StatPan/datapan-health/internal/runtimebundle"
	"github.com/StatPan/datapan-health/schemas"
)

const (
	OperationPlanProbeReceiptSchemaVersion = "datapan.health-operation-plan-probe.v1"
	OperationPlanProbeReceiptSchemaURI     = "https://schemas.datapan.dev/datapan.health-operation-plan-probe.v1.schema.json"
	OperationPlanProbeReceiptSchemaSHA256  = "23fcac6ae7b47852f36e47fea24dd5d0dbeb795bef279529998233a835eefad9"
	maxOperationPlanProbeReceiptBytes      = 64 << 10
	maxOperationPlanProbeStderrBytes       = 8 << 10
	maxOperationPlanProbeBinaryBytes       = 128 << 20
	maxOperationPlanProbeProcessOverhead   = 5 * time.Second
	maxOperationPlanProbeDeadline          = 30 * time.Second
)

var errOperationPlanProbeUnavailable = errors.New("operation-plan probe is unavailable")

type operationPlanProbeReceipt struct {
	SchemaVersion string                        `json:"schema_version"`
	AttemptID     string                        `json:"attempt_id"`
	CLI           operationPlanProbeCLI         `json:"cli"`
	Registry      operationPlanProbeRegistry    `json:"registry"`
	Operation     operationPlanProbeOperation   `json:"operation"`
	Execution     operationPlanProbeExecution   `json:"execution"`
	Observation   operationPlanProbeObservation `json:"observation"`
	Redaction     operationPlanProbeRedaction   `json:"redaction"`
}

type operationPlanProbeCLI struct {
	Version      string `json:"version"`
	BinarySHA256 string `json:"binary_sha256"`
}

type operationPlanProbeRegistry struct {
	DatasetID                   string `json:"dataset_id"`
	RegistryRevision            string `json:"registry_revision"`
	Distribution                string `json:"distribution"`
	DistributionDatasetRevision string `json:"distribution_dataset_revision,omitempty"`
	RegistrySHA256              string `json:"registry_sha256"`
	ManifestSHA256              string `json:"manifest_sha256"`
	OperationManifestSHA256     string `json:"operation_manifest_sha256"`
	ProviderIndexSHA256         string `json:"provider_index_sha256"`
	PlanSchemaSHA256            string `json:"plan_schema_sha256"`
	IndexSHA256                 string `json:"index_sha256"`
	ShardSHA256                 string `json:"shard_sha256"`
	SourceIdentitySetSHA256     string `json:"source_identity_set_sha256"`
}

type operationPlanProbeOperation struct {
	OperationID string `json:"operation_id"`
	SourceID    string `json:"source_id"`
	Provider    string `json:"provider"`
	AdapterID   string `json:"adapter_id"`
	Protocol    string `json:"protocol"`
}

type operationPlanProbeExecution struct {
	RequestStarted bool  `json:"request_started"`
	RequestBudget  int   `json:"request_budget"`
	TimeoutMS      int64 `json:"timeout_ms"`
	DurationMS     int64 `json:"duration_ms"`
}

type operationPlanProbeObservation struct {
	ResponseObserved bool   `json:"response_observed"`
	ObservedAt       string `json:"observed_at,omitempty"`
	HTTPStatus       int    `json:"http_status,omitempty"`
	Outcome          string `json:"outcome"`
	ReasonCode       string `json:"reason_code"`
	AssertionKind    string `json:"assertion_kind"`
	AssertionStatus  string `json:"assertion_status"`
}

type operationPlanProbeRedaction struct {
	CredentialValuesRemoved     bool `json:"credential_values_removed"`
	CredentialReferencesRemoved bool `json:"credential_references_removed"`
	CredentialEnvNamesRemoved   bool `json:"credential_env_names_removed"`
	QueryValuesRemoved          bool `json:"query_values_removed"`
	RequestBodyRemoved          bool `json:"request_body_removed"`
	ResponseBodyRemoved         bool `json:"response_body_removed"`
	ResponseRowsRemoved         bool `json:"response_rows_removed"`
	EndpointDetailsRemoved      bool `json:"endpoint_details_removed"`
	QuotaDetailsRemoved         bool `json:"quota_details_removed"`
}

// OperationPlanProbeExpectation is the immutable receipt identity assembled
// from the verified Registry release, one operation record, and its shard.
// Its fields are internal trust inputs; none are public status values.
type OperationPlanProbeExpectation struct {
	AttemptID                   string
	CLIVersion                  string
	CLIBinarySHA256             string
	DatasetID                   string
	Distribution                string
	DistributionDatasetRevision string
	RegistrySHA256              string
	RegistryRevision            string
	ReleaseManifestSHA256       string
	OperationManifestSHA256     string
	ProviderIndexSHA256         string
	PlanSchemaSHA256            string
	IndexSHA256                 string
	ShardSHA256                 string
	SourceIdentitySetSHA256     string
	SourceID                    string
	OperationID                 string
	Provider                    string
	AdapterID                   string
	Protocol                    string
	ResponseAssertionKind       string
	RequestTimeout              time.Duration
	StartedAt                   time.Time
}

// OperationPlanProbeResult contains only schema-validated redacted receipt
// bytes and the safe fields needed by the durable attempt/outbox layers.
type OperationPlanProbeResult struct {
	Receipt        operationPlanProbeReceipt
	ReceiptBytes   []byte
	ReceiptSHA256  string
	ReceivedAt     time.Time
	ObservedAt     time.Time
	Outcome        string
	ReasonCode     string
	RequestStarted bool
	HTTPStatus     int
	Latency        time.Duration
}

// OperationPlanProbeConfig binds a direct child process to the CLI binary and
// the private runtime binding file in the image. It contains no credential
// value. Environment entries must be explicitly named by the caller.
type OperationPlanProbeConfig struct {
	ExecutablePath     string
	ExecutableSHA256   string
	CLIVersion         string
	RegistryIndexPath  string
	CredentialBindings string
	ReceiptDirectory   string
	EnvironmentNames   []string
}

// OperationPlanProbeRunner invokes the fixed CLI child ABI. No endpoint,
// parameter, credential, query, or response value is accepted by this type.
type OperationPlanProbeRunner struct {
	config OperationPlanProbeConfig
}

func NewOperationPlanProbeRunner(config OperationPlanProbeConfig) (*OperationPlanProbeRunner, error) {
	if !filepath.IsAbs(config.ExecutablePath) || !filepath.IsAbs(config.RegistryIndexPath) || !filepath.IsAbs(config.CredentialBindings) || !filepath.IsAbs(config.ReceiptDirectory) || !sha256Pattern.MatchString(config.ExecutableSHA256) || strings.TrimSpace(config.CLIVersion) == "" || len(config.CLIVersion) > 64 {
		return nil, errOperationPlanProbeUnavailable
	}
	runner := &OperationPlanProbeRunner{config: config}
	if err := runner.VerifyExecutable(); err != nil {
		return nil, errOperationPlanProbeUnavailable
	}
	return runner, nil
}

// OperationPlanProbeConfigFromRuntimeLock selects the architecture-specific
// CLI identity from the already verified image dependency lock.
func OperationPlanProbeConfigFromRuntimeLock(lock runtimebundle.Lock, arch, cliPath, indexPath, credentialBindings, receiptDirectory string, environmentNames []string) (OperationPlanProbeConfig, error) {
	if lock.Validate() != nil {
		return OperationPlanProbeConfig{}, errOperationPlanProbeUnavailable
	}
	binary, ok := lock.CLI.Binaries[arch]
	if !ok {
		return OperationPlanProbeConfig{}, errOperationPlanProbeUnavailable
	}
	return OperationPlanProbeConfig{
		ExecutablePath: cliPath, ExecutableSHA256: binary.BinarySHA256, CLIVersion: lock.CLI.Release,
		RegistryIndexPath: indexPath, CredentialBindings: credentialBindings, ReceiptDirectory: receiptDirectory,
		EnvironmentNames: append([]string(nil), environmentNames...),
	}, nil
}

// VerifyExecutable confirms that the direct child still has the exact binary
// bytes selected by the immutable runtime dependency lock.
func (runner *OperationPlanProbeRunner) VerifyExecutable() error {
	if runner == nil || runner.config.ExecutablePath == "" {
		return errOperationPlanProbeUnavailable
	}
	file, err := runner.openVerifiedExecutable()
	if err != nil {
		return errOperationPlanProbeUnavailable
	}
	return file.Close()
}

// Run executes one selected identity and rejects any receipt that does not
// match the full immutable release/index/shard/source/operation chain.
func (runner *OperationPlanProbeRunner) Run(ctx context.Context, expectation OperationPlanProbeExpectation, deadline time.Time) (OperationPlanProbeResult, int, error) {
	if runner == nil || !validOperationProbeExpectation(expectation, runner.config) || deadline.IsZero() || !deadline.After(time.Now()) || deadline.Sub(time.Now()) > maxOperationPlanProbeDeadline {
		return OperationPlanProbeResult{}, -1, errOperationPlanProbeUnavailable
	}
	executable, err := runner.openVerifiedExecutable()
	if err != nil {
		return OperationPlanProbeResult{}, -1, errOperationPlanProbeUnavailable
	}
	defer executable.Close()
	if err := checkOperationCredentialBindingFile(runner.config.CredentialBindings); err != nil {
		return OperationPlanProbeResult{}, -1, err
	}
	if err := os.MkdirAll(runner.config.ReceiptDirectory, 0o700); err != nil {
		return OperationPlanProbeResult{}, -1, errOperationPlanProbeUnavailable
	}
	if err := checkPrivateOperationDirectory(runner.config.ReceiptDirectory); err != nil {
		return OperationPlanProbeResult{}, -1, err
	}
	outputDirectory, err := os.MkdirTemp(runner.config.ReceiptDirectory, ".attempt-")
	if err != nil {
		return OperationPlanProbeResult{}, -1, errOperationPlanProbeUnavailable
	}
	defer os.RemoveAll(outputDirectory)
	if err := os.Chmod(outputDirectory, 0o700); err != nil {
		return OperationPlanProbeResult{}, -1, errOperationPlanProbeUnavailable
	}
	outputPath := filepath.Join(outputDirectory, "receipt.json")
	args := []string{
		"verify", "--health", "--json",
		"--health-plan-index", runner.config.RegistryIndexPath,
		"--health-operation-id", expectation.OperationID,
		"--health-registry-revision", expectation.RegistryRevision,
		"--health-credential-bindings", runner.config.CredentialBindings,
		"--health-attempt-id", expectation.AttemptID,
		"--health-cli-version", runner.config.CLIVersion,
		"--health-deadline", deadline.UTC().Format(time.RFC3339Nano),
		"--output", outputPath,
	}
	processCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// Execute the exact opened inode that was hashed above. Passing the file as
	// descriptor 3 prevents a pathname replacement between digest verification
	// and exec from selecting different bytes. This Linux-only child route fails
	// closed if procfs is unavailable; it never falls back to reopening by path.
	cmd := exec.CommandContext(processCtx, "/proc/self/fd/3", args...)
	cmd.ExtraFiles = []*os.File{executable}
	cmd.Env = selectEnvironment(runner.config.EnvironmentNames)
	stdout, stderr := &boundedOperationOutput{limit: maxOperationPlanProbeReceiptBytes}, &boundedOperationOutput{limit: maxOperationPlanProbeStderrBytes}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	started := time.Now().UTC()
	runErr := cmd.Run()
	receivedAt := time.Now().UTC()
	exitCode := 0
	if runErr != nil {
		var exit *exec.ExitError
		if !errors.As(runErr, &exit) {
			return OperationPlanProbeResult{}, -1, errOperationPlanProbeUnavailable
		}
		exitCode = exit.ExitCode()
	}
	if stdout.exceeded || stderr.exceeded {
		return OperationPlanProbeResult{}, exitCode, errOperationPlanProbeUnavailable
	}
	receiptBytes, err := readOperationProbeReceiptFile(outputPath)
	if err != nil || !bytes.Equal(stdout.data, receiptBytes) {
		return OperationPlanProbeResult{}, exitCode, errOperationPlanProbeUnavailable
	}
	// Validate provider timestamps from the durable claim time, not a later
	// point sampled after command setup. The child request can begin only after
	// this claim already exists.
	if started.Before(expectation.StartedAt.Add(-time.Second)) {
		return OperationPlanProbeResult{}, exitCode, errOperationPlanProbeUnavailable
	}
	result, err := ValidateOperationPlanProbeReceipt(receiptBytes, expectation, expectation.StartedAt, receivedAt, exitCode)
	if err != nil {
		return OperationPlanProbeResult{}, exitCode, errOperationPlanProbeUnavailable
	}
	return result, exitCode, nil
}

func (runner *OperationPlanProbeRunner) openVerifiedExecutable() (*os.File, error) {
	if runner == nil || runner.config.ExecutablePath == "" {
		return nil, errOperationPlanProbeUnavailable
	}
	fd, err := syscall.Open(runner.config.ExecutablePath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, errOperationPlanProbeUnavailable
	}
	file := os.NewFile(uintptr(fd), "health-plan-cli")
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errOperationPlanProbeUnavailable
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 || info.Size() < 1 || info.Size() > maxOperationPlanProbeBinaryBytes {
		_ = file.Close()
		return nil, errOperationPlanProbeUnavailable
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, maxOperationPlanProbeBinaryBytes+1)); err != nil || hex.EncodeToString(hash.Sum(nil)) != runner.config.ExecutableSHA256 {
		_ = file.Close()
		return nil, errOperationPlanProbeUnavailable
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, errOperationPlanProbeUnavailable
	}
	return file, nil
}

func validOperationProbeExpectation(expected OperationPlanProbeExpectation, config OperationPlanProbeConfig) bool {
	return quotaAttemptIDPattern.MatchString(expected.AttemptID) && expected.CLIVersion == config.CLIVersion && expected.CLIBinarySHA256 == config.ExecutableSHA256 && expected.DatasetID == "StatPan/datapan-registry" && expected.Distribution == "huggingface_dataset" && commitPattern.MatchString(expected.DistributionDatasetRevision) && sha256Pattern.MatchString(expected.RegistrySHA256) && commitPattern.MatchString(expected.RegistryRevision) && sha256Pattern.MatchString(expected.ReleaseManifestSHA256) && sha256Pattern.MatchString(expected.OperationManifestSHA256) && sha256Pattern.MatchString(expected.ProviderIndexSHA256) && sha256Pattern.MatchString(expected.PlanSchemaSHA256) && sha256Pattern.MatchString(expected.IndexSHA256) && sha256Pattern.MatchString(expected.ShardSHA256) && sha256Pattern.MatchString(expected.SourceIdentitySetSHA256) && operationSourceIDPattern.MatchString(expected.SourceID) && expected.OperationID != "" && len(expected.OperationID) <= 256 && expected.Provider != "" && expected.AdapterID != "" && (expected.Protocol == "REST" || expected.Protocol == "SOAP") && validOperationProbeAssertionKind(expected.Protocol, expected.ResponseAssertionKind) && expected.RequestTimeout > 0 && expected.RequestTimeout <= maxOperationPlanProbeDeadline-maxOperationPlanProbeProcessOverhead && !expected.StartedAt.IsZero()
}

func validOperationProbeAssertionKind(protocol, kind string) bool {
	if protocol == "REST" {
		return kind == "http_status" || kind == "json_contract" || kind == "observation_only"
	}
	if protocol == "SOAP" {
		return kind == "http_status" || kind == "soap_fault_free" || kind == "xml_contract" || kind == "observation_only"
	}
	return false
}

// ValidateOperationPlanProbeReceipt validates strict schema, canonical byte
// representation, child exit semantics, and identity/timestamp consistency.
func ValidateOperationPlanProbeReceipt(raw []byte, expected OperationPlanProbeExpectation, startedAt, receivedAt time.Time, exitCode int) (OperationPlanProbeResult, error) {
	if len(raw) == 0 || len(raw) > maxOperationPlanProbeReceiptBytes || schemas.HealthOperationPlanProbeV1SchemaSHA256() != OperationPlanProbeReceiptSchemaSHA256 || schemas.ValidateHealthOperationPlanProbeV1(raw) != nil || !validOperationProbeExpectation(expected, OperationPlanProbeConfig{CLIVersion: expected.CLIVersion, ExecutableSHA256: expected.CLIBinarySHA256}) || startedAt.IsZero() || !startedAt.Equal(expected.StartedAt) || receivedAt.Before(startedAt) {
		return OperationPlanProbeResult{}, errOperationPlanProbeUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var receipt operationPlanProbeReceipt
	if decoder.Decode(&receipt) != nil || ensureEOF(decoder) != nil {
		return OperationPlanProbeResult{}, errOperationPlanProbeUnavailable
	}
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return OperationPlanProbeResult{}, errOperationPlanProbeUnavailable
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, raw) || !validOperationProbeReceiptSemantics(receipt, expected, startedAt, receivedAt, exitCode) {
		return OperationPlanProbeResult{}, errOperationPlanProbeUnavailable
	}
	var observedAt time.Time
	if receipt.Observation.ObservedAt != "" {
		observedAt, err = time.Parse(time.RFC3339Nano, receipt.Observation.ObservedAt)
		if err != nil {
			return OperationPlanProbeResult{}, errOperationPlanProbeUnavailable
		}
		observedAt = observedAt.UTC()
	}
	latency := time.Duration(receipt.Execution.DurationMS) * time.Millisecond
	if latency < 0 || latency > maxOperationPlanProbeDeadline {
		return OperationPlanProbeResult{}, errOperationPlanProbeUnavailable
	}
	return OperationPlanProbeResult{
		Receipt: receipt, ReceiptBytes: append([]byte(nil), raw...), ReceiptSHA256: digest(raw),
		ReceivedAt: receivedAt.UTC(), ObservedAt: observedAt, Outcome: receipt.Observation.Outcome,
		ReasonCode: receipt.Observation.ReasonCode, RequestStarted: receipt.Execution.RequestStarted,
		HTTPStatus: receipt.Observation.HTTPStatus, Latency: latency,
	}, nil
}

func validOperationProbeReceiptSemantics(receipt operationPlanProbeReceipt, expected OperationPlanProbeExpectation, startedAt, receivedAt time.Time, exitCode int) bool {
	if receipt.SchemaVersion != OperationPlanProbeReceiptSchemaVersion || receipt.AttemptID != expected.AttemptID || receipt.CLI.Version != expected.CLIVersion || receipt.CLI.BinarySHA256 != expected.CLIBinarySHA256 ||
		receipt.Registry.DatasetID != expected.DatasetID || receipt.Registry.RegistryRevision != expected.RegistryRevision || receipt.Registry.Distribution != expected.Distribution || receipt.Registry.DistributionDatasetRevision != expected.DistributionDatasetRevision ||
		receipt.Registry.RegistrySHA256 != expected.RegistrySHA256 || receipt.Registry.ManifestSHA256 != expected.ReleaseManifestSHA256 || receipt.Registry.OperationManifestSHA256 != expected.OperationManifestSHA256 || receipt.Registry.ProviderIndexSHA256 != expected.ProviderIndexSHA256 || receipt.Registry.PlanSchemaSHA256 != expected.PlanSchemaSHA256 || receipt.Registry.IndexSHA256 != expected.IndexSHA256 || receipt.Registry.ShardSHA256 != expected.ShardSHA256 || receipt.Registry.SourceIdentitySetSHA256 != expected.SourceIdentitySetSHA256 ||
		receipt.Operation.OperationID != expected.OperationID || receipt.Operation.SourceID != expected.SourceID || receipt.Operation.Provider != expected.Provider || receipt.Operation.AdapterID != expected.AdapterID || receipt.Operation.Protocol != expected.Protocol || receipt.Observation.AssertionKind != expected.ResponseAssertionKind ||
		receipt.Execution.TimeoutMS != expected.RequestTimeout.Milliseconds() || receipt.Execution.DurationMS < 0 || receipt.Execution.DurationMS > (receivedAt.Sub(startedAt)+time.Second).Milliseconds() ||
		!receipt.Redaction.CredentialValuesRemoved || !receipt.Redaction.CredentialReferencesRemoved || !receipt.Redaction.CredentialEnvNamesRemoved || !receipt.Redaction.QueryValuesRemoved || !receipt.Redaction.RequestBodyRemoved || !receipt.Redaction.ResponseBodyRemoved || !receipt.Redaction.ResponseRowsRemoved || !receipt.Redaction.EndpointDetailsRemoved || !receipt.Redaction.QuotaDetailsRemoved {
		return false
	}
	if receipt.Execution.RequestStarted {
		if receipt.Execution.RequestBudget != 1 {
			return false
		}
	} else if receipt.Execution.RequestBudget != 0 || receipt.Observation.ResponseObserved || receipt.Observation.ObservedAt != "" || receipt.Observation.HTTPStatus != 0 {
		return false
	}
	if receipt.Observation.ResponseObserved {
		if receipt.Observation.HTTPStatus < 100 || receipt.Observation.HTTPStatus > 599 || receipt.Observation.ObservedAt == "" {
			return false
		}
		observedAt, err := time.Parse(time.RFC3339Nano, receipt.Observation.ObservedAt)
		if err != nil || observedAt.Before(startedAt.Add(-time.Second)) || observedAt.After(receivedAt.Add(time.Second)) {
			return false
		}
	} else if receipt.Observation.HTTPStatus != 0 || receipt.Observation.ObservedAt != "" {
		return false
	}
	switch receipt.Observation.Outcome {
	case "healthy":
		return expected.ResponseAssertionKind != "observation_only" && exitCode == 0 && receipt.Execution.RequestStarted && receipt.Observation.ResponseObserved && receipt.Observation.AssertionStatus == "passed" && receipt.Observation.ReasonCode == "response_assertion_passed"
	case "unhealthy":
		if exitCode != 4 || !receipt.Execution.RequestStarted || !receipt.Observation.ResponseObserved || receipt.Observation.AssertionStatus != "failed" {
			return false
		}
		if expected.ResponseAssertionKind == "observation_only" {
			return receipt.Observation.ReasonCode == "response_http_failure" && (receipt.Observation.HTTPStatus < 200 || receipt.Observation.HTTPStatus >= 300)
		}
		return receipt.Observation.ReasonCode == "response_assertion_failed" || receipt.Observation.ReasonCode == "response_assertion_invalid"
	case "blocked":
		if exitCode != 3 || receipt.Execution.RequestStarted || receipt.Observation.ResponseObserved || receipt.Observation.AssertionStatus != "not_run" {
			return false
		}
		switch receipt.Observation.ReasonCode {
		case "credential_binding_unavailable", "credential_binding_mismatch", "credential_source_unavailable", "operation_plan_unsupported", "deadline_expired_before_request", "request_limit_exceeded":
			return true
		default:
			return false
		}
	case "indeterminate":
		if exitCode != 4 || !receipt.Execution.RequestStarted || receipt.Observation.AssertionStatus != "not_run" {
			return false
		}
		switch receipt.Observation.ReasonCode {
		case "response_semantics_unestablished":
			return expected.ResponseAssertionKind == "observation_only" && receipt.Observation.ResponseObserved && receipt.Observation.HTTPStatus >= 200 && receipt.Observation.HTTPStatus < 300
		case "request_deadline_exceeded", "request_limit_exceeded", "response_limit_exceeded", "request_transport_failed", "response_read_failed", "response_invalid":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func operationPlanProbeExpected(plan PinnedOperationObservationPlan, record OperationObservationPlanRecord, shardSHA string, attemptID string, lock runtimebundle.Lock, arch string, startedAt time.Time) (OperationPlanProbeExpectation, error) {
	if plan.state == nil || !plan.state.verified || !record.ExecutionEligible || !sha256Pattern.MatchString(shardSHA) || lock.Validate() != nil {
		return OperationPlanProbeExpectation{}, errOperationPlanProbeUnavailable
	}
	scope, ok := plan.state.byScope[record.SourceID]
	if !ok || scope.Provider != record.Provider || scope.AdapterID != record.AdapterID || !sha256Pattern.MatchString(scope.IdentitySetSHA256) || !validOperationPlanProbeGenerationInputPins(plan.state) {
		return OperationPlanProbeExpectation{}, errOperationPlanProbeUnavailable
	}
	if !plan.state.providerIndexRefExists {
		return OperationPlanProbeExpectation{}, errOperationPlanProbeUnavailable
	}
	binary, ok := lock.CLI.Binaries[arch]
	if !ok {
		return OperationPlanProbeExpectation{}, errOperationPlanProbeUnavailable
	}
	return OperationPlanProbeExpectation{
		AttemptID: attemptID, CLIVersion: lock.CLI.Release, CLIBinarySHA256: binary.BinarySHA256,
		DatasetID: "StatPan/datapan-registry", Distribution: "huggingface_dataset", DistributionDatasetRevision: lock.Registry.DatasetRevision,
		RegistrySHA256: lock.Registry.SourceRegistrySHA256, RegistryRevision: plan.RegistryRevision(), ReleaseManifestSHA256: plan.binding.ReleaseManifestSHA256,
		OperationManifestSHA256: plan.state.operationManifestRef.SHA256, ProviderIndexSHA256: plan.state.providerIndexRef.SHA256,
		PlanSchemaSHA256: plan.binding.SchemaSHA256, IndexSHA256: plan.IndexSHA256(), ShardSHA256: shardSHA,
		SourceIdentitySetSHA256: scope.IdentitySetSHA256, SourceID: record.SourceID, OperationID: record.OperationID,
		Provider: record.Provider, AdapterID: record.AdapterID, Protocol: record.Protocol, ResponseAssertionKind: record.ResponseAssertionKind,
		RequestTimeout: record.RequestTimeout, StartedAt: startedAt.UTC(),
	}, nil
}

func validOperationPlanProbeGenerationInputPins(state *operationPlanIndexState) bool {
	if state == nil || !state.verified || !releaseManifestBinds(state.manifest, state.operationManifestRef.Path, state.operationManifestRef.Bytes, state.operationManifestRef.SHA256) {
		return false
	}
	if !state.providerIndexRefExists {
		return state.providerIndexRef == (operationPlanArtifactRef{})
	}
	return releaseManifestBinds(state.manifest, state.providerIndexRef.Path, state.providerIndexRef.Bytes, state.providerIndexRef.SHA256)
}

func checkOperationCredentialBindingFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > 256<<10 || info.Mode().Perm()&0o077 != 0 {
		return errOperationPlanProbeUnavailable
	}
	return nil
}

func checkPrivateOperationDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errOperationPlanProbeUnavailable
	}
	return nil
}

func readOperationProbeReceiptFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 || info.Size() < 1 || info.Size() > maxOperationPlanProbeReceiptBytes {
		return nil, errOperationPlanProbeUnavailable
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errOperationPlanProbeUnavailable
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxOperationPlanProbeReceiptBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxOperationPlanProbeReceiptBytes {
		return nil, errOperationPlanProbeUnavailable
	}
	return raw, nil
}

type boundedOperationOutput struct {
	data     []byte
	limit    int
	exceeded bool
}

func (buffer *boundedOperationOutput) Write(value []byte) (int, error) {
	remaining := buffer.limit - len(buffer.data)
	if remaining > 0 {
		if len(value) > remaining {
			buffer.data = append(buffer.data, value[:remaining]...)
		} else {
			buffer.data = append(buffer.data, value...)
		}
	}
	if len(value) > remaining {
		buffer.exceeded = true
	}
	return len(value), nil
}

func NewOperationPlanProbeAttemptID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", errOperationPlanProbeUnavailable
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}
