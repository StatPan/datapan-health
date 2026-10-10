package health

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	actualCLIExpectedSourceRevision = "89d1164ac8c910e18e50fc1c3a3961977c4d4f2e"
	actualCLIExpectedVersion        = "v0.1.41"
	actualCLIProviderSubnet         = "45.77.0.0/24"
	actualCLIProviderIP             = "45.77.0.2"
	actualCLIGatusIP                = "45.77.0.3"
	actualCLIGatusImage             = pinnedOperationPlanTestGatusImage
	actualCLIGovRESTObservationOK   = "00004a9f03e1bb109137e444e9b58ffe105d5d5c49254abf5e3094b2e3574749"
	actualCLIGovRESTObservation503  = "0004cea4696c10954bc7db92690058078e6dd3a7ffddd92c61e7f4061e83ef0a"
	actualCLIGovSOAPObservationOK   = "03d8a11773389ac22d176554aa878adb643d905f667c5115ed447d28476c78be"
	actualCLIGovSOAPObservation503  = "28256cae93511a322963841fb8e03ac4c0273a45f85fd0371ac0f9f7b7bfb8b2"
	actualCLIGovRESTTypedSuccess    = "001145a8aa9aa99135ef4d039f85b932cc0fc25641ed9ba2b5f0748728de61c4"
	actualCLIGovRESTTypedFailure    = "0014af9e0f58c9dd10c0167164e037ddf5f75658431d5ad3ffe531b6bf45d97a"
	actualCLIGovSOAPTypedSuccess    = "07776a0ef594eae07eeb13ac59eb5f659f9227dd513cc7505ce60dab21695e7e"
	actualCLIGovSOAPTypedFailure    = "30a31059d5847698f696854e772aa1b22569c45c200d4e460c8e5f0c6358578c"
)

type actualCLIReleaseManifest struct {
	SchemaVersion  string                            `json:"schema_version"`
	GeneratedAt    string                            `json:"generated_at"`
	DatapanVersion string                            `json:"datapan_version"`
	Provider       string                            `json:"provider"`
	SourceRegistry string                            `json:"source_registry"`
	OutputDir      string                            `json:"output_dir"`
	ArtifactCount  int                               `json:"artifact_count"`
	Artifacts      []RegistryReleaseManifestArtifact `json:"artifacts"`
}

type actualCLIDocumentRef struct {
	path  string
	sha   string
	bytes int64
}

type actualCLIProjectionMeasurements struct {
	BoundArtifactBytes    int64
	ManifestBytes         int64
	PhysicalBytes         int64
	ManifestArtifactCount int
}

type actualCLIInvocationTelemetry struct {
	mu             sync.Mutex
	calls          int
	contextTimeout int
	exitErrors     int
	otherErrors    int
	totalElapsed   time.Duration
	maxElapsed     time.Duration
	stdoutBytes    int64
	stderrBytes    int64
	stderrClasses  map[string]int
}

type actualCLIInvocationTelemetrySnapshot struct {
	Calls          int
	ContextTimeout int
	ExitErrors     int
	OtherErrors    int
	TotalElapsed   time.Duration
	MaxElapsed     time.Duration
	StdoutBytes    int64
	StderrBytes    int64
	StderrClasses  map[string]int
}

func (telemetry *actualCLIInvocationTelemetry) reset() {
	if telemetry == nil {
		return
	}
	telemetry.mu.Lock()
	defer telemetry.mu.Unlock()
	telemetry.calls = 0
	telemetry.contextTimeout = 0
	telemetry.exitErrors = 0
	telemetry.otherErrors = 0
	telemetry.totalElapsed = 0
	telemetry.maxElapsed = 0
	telemetry.stdoutBytes = 0
	telemetry.stderrBytes = 0
	telemetry.stderrClasses = nil
}

func (telemetry *actualCLIInvocationTelemetry) snapshot() actualCLIInvocationTelemetrySnapshot {
	if telemetry == nil {
		return actualCLIInvocationTelemetrySnapshot{}
	}
	telemetry.mu.Lock()
	defer telemetry.mu.Unlock()
	classes := make(map[string]int, len(telemetry.stderrClasses))
	for class, count := range telemetry.stderrClasses {
		classes[class] = count
	}
	return actualCLIInvocationTelemetrySnapshot{
		Calls: telemetry.calls, ContextTimeout: telemetry.contextTimeout, ExitErrors: telemetry.exitErrors,
		OtherErrors: telemetry.otherErrors, TotalElapsed: telemetry.totalElapsed, MaxElapsed: telemetry.maxElapsed,
		StdoutBytes: telemetry.stdoutBytes, StderrBytes: telemetry.stderrBytes, StderrClasses: classes,
	}
}

func (telemetry *actualCLIInvocationTelemetry) record(elapsed time.Duration, childErr, contextErr error, stdoutBytes, stderrBytes int64, stderrClass string) {
	if telemetry == nil {
		return
	}
	telemetry.mu.Lock()
	defer telemetry.mu.Unlock()
	telemetry.calls++
	telemetry.totalElapsed += elapsed
	if elapsed > telemetry.maxElapsed {
		telemetry.maxElapsed = elapsed
	}
	telemetry.stdoutBytes += stdoutBytes
	telemetry.stderrBytes += stderrBytes
	if stderrClass != "" {
		if telemetry.stderrClasses == nil {
			telemetry.stderrClasses = make(map[string]int)
		}
		telemetry.stderrClasses[stderrClass]++
	}
	if errors.Is(contextErr, context.DeadlineExceeded) {
		telemetry.contextTimeout++
		return
	}
	if childErr == nil {
		return
	}
	var exit *exec.ExitError
	if errors.As(childErr, &exit) {
		telemetry.exitErrors++
	} else {
		telemetry.otherErrors++
	}
}

func instrumentActualCLIChildInvoker(base operationPlanProbeChildInvoker, telemetry *actualCLIInvocationTelemetry) operationPlanProbeChildInvoker {
	return func(ctx context.Context, executable *os.File, args, env []string, stdout, stderr io.Writer) error {
		started := time.Now()
		err := base(ctx, executable, args, env, stdout, stderr)
		stdoutBytes, stderrBytes := int64(0), int64(0)
		stderrData := []byte(nil)
		if buffer, ok := stdout.(*boundedOperationOutput); ok {
			stdoutBytes = int64(len(buffer.data))
		}
		if buffer, ok := stderr.(*boundedOperationOutput); ok {
			stderrBytes = int64(len(buffer.data))
			stderrData = buffer.data
		}
		telemetry.record(time.Since(started), err, ctx.Err(), stdoutBytes, stderrBytes, actualCLIChildStderrClass(stderrData))
		return err
	}
}

func actualCLIChildStderrClass(stderr []byte) string {
	line := strings.TrimSpace(string(stderr))
	const readyPrefix = "health operation plan is not ready: "
	if strings.HasPrefix(line, readyPrefix) {
		switch strings.TrimPrefix(line, readyPrefix) {
		case "health operation plan is not executable under its declared bounds":
			return "plan_not_executable"
		case "selected operation-document evidence is invalid":
			return "document_evidence_invalid"
		case "selected reviewed operation policy is invalid":
			return "policy_invalid"
		case "selected read-only effect policy does not match its source facts":
			return "effect_policy_invalid"
		case "selected response assertion is invalid":
			return "assertion_invalid"
		default:
			return "operation_plan_load_rejected"
		}
	}
	switch line {
	case "health operation plan selection does not match its verified immutable Registry plan":
		return "selection_identity_mismatch"
	case "health operation-plan execution requires JSON output to a new path outside the installed Registry":
		return "receipt_output_rejected"
	default:
		if line == "" {
			return ""
		}
		return "unclassified_child_error"
	}
}

func actualCLIChildStderrClassSummary(classes map[string]int) string {
	if len(classes) == 0 {
		return "none"
	}
	keys := make([]string, 0, len(classes))
	for key := range classes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+strconv.Itoa(classes[key]))
	}
	return strings.Join(parts, ",")
}

// TestOperationPlanActualCLIProviderGatusIntegration is the opt-in source-QA
// proof for the compiled, exact-pinned CLI child, a no-egress synthetic REST/
// SOAP provider, durable operation receipts, and the pinned native Gatus API.
// Use HEALTH_OPERATION_ACTUAL_CLI_MODE=smoke first, then full for all 12,666
// manifest-derived identities. It never reads provider credentials or calls
// provider infrastructure.
func TestOperationPlanActualCLIProviderGatusIntegration(t *testing.T) {
	qaStarted := time.Now()
	mode := os.Getenv("HEALTH_OPERATION_ACTUAL_CLI_MODE")
	if mode != "smoke" && mode != "full" {
		t.Skip("set HEALTH_OPERATION_ACTUAL_CLI_MODE=smoke or full for isolated actual-CLI source QA")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("the pinned child execution and Docker fixture require Linux amd64")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("Docker is required for the isolated actual-CLI source-QA target")
	}

	sourceRoot, sourceRevision, binaryPath, binarySHA, goBuildVersion := actualCLIInput(t)
	t.Logf("actual CLI source-QA build complete: elapsed=%s", time.Since(qaStarted).Round(time.Millisecond))
	metadata, canaries, basePlan, planRoot, identities := loadManifestDerivedPopulationPlan(t)
	plan := bindActualCLIEvidenceFixture(t, sourceRoot, planRoot, basePlan, metadata, identities)
	credentialBindings := filepath.Join(planRoot, ".datapan", "credential-bindings.json")
	if err := os.MkdirAll(filepath.Dir(credentialBindings), 0o700); err != nil {
		t.Fatal("could not stage the empty credential binding file")
	}
	if err := os.WriteFile(credentialBindings, []byte(`{"schema_version":"datapan.health-credential-bindings.v1","bindings":[]}`), 0o600); err != nil {
		t.Fatal("could not stage the empty credential binding file")
	}
	projection := stageActualCLITrustedRegistryProjection(t, planRoot, plan)
	t.Logf("actual CLI source-QA fixture and installed projection complete: elapsed=%s", time.Since(qaStarted).Round(time.Millisecond))
	if plan.ExecutableOperations() != len(identities) || len(identities) != 12666 {
		t.Fatalf("actual-CLI fixture did not retain the full pinned identity set: executable=%d identities=%d", plan.ExecutableOperations(), len(identities))
	}
	protocolCounts := make(map[string]int)
	unknownInventoryCount := 0
	for _, identity := range identities {
		if identity.SourceID == "data_go_kr" {
			protocolCounts[identity.Protocol]++
		}
		if identity.InventoryUnknown {
			unknownInventoryCount++
		}
	}
	if protocolCounts["REST"] != 12627 || protocolCounts["SOAP"] != 35 || unknownInventoryCount != 4 {
		t.Fatalf("actual-CLI fixture source-known protocol or partial-inventory counts differ from pinned metadata: rest=%d soap=%d unknown_inventory=%d", protocolCounts["REST"], protocolCounts["SOAP"], unknownInventoryCount)
	}

	fixtureRoot := t.TempDir()
	delayedOperationID := ""
	if mode == "smoke" {
		delayed, found := actualCLICancellationIdentity(identities)
		if !found {
			t.Fatal("actual CLI cancellation probe could not select a non-smoke Registry identity")
		}
		delayedOperationID = delayed.OperationID
	}
	providerBinary, providerCA, providerCertificate, providerKey, providerRoutes := buildActualCLIProvider(t, fixtureRoot, identities, delayedOperationID)
	providerRoutesSHA256 := actualCLIFileSHA256(t, providerRoutes)
	verifiedRuntime, paths := buildActualCLIRuntime(t, fixtureRoot, planRoot, metadata, canaries, plan, identities)
	token := "synthetic-local-actual-cli-gatus-token"
	receiptRoot := filepath.Join(fixtureRoot, "private-receipts")
	if err := os.MkdirAll(receiptRoot, 0o700); err != nil {
		t.Fatal("could not prepare the private actual-CLI receipt mount")
	}
	previousCAPath, hadCAPath := os.LookupEnv("SSL_CERT_FILE")
	if err := os.Setenv("SSL_CERT_FILE", "/fixture-ca.pem"); err != nil {
		t.Fatal("could not set the explicit local CA path for the actual CLI child")
	}
	t.Cleanup(func() {
		if hadCAPath {
			_ = os.Setenv("SSL_CERT_FILE", previousCAPath)
		} else {
			_ = os.Unsetenv("SSL_CERT_FILE")
		}
	})
	networkName, cliContainer, baseURL, metricsURL, monitor := startActualCLIContainers(t, fixtureRoot, binaryPath, binarySHA, providerBinary, providerCA, providerCertificate, providerKey, providerRoutes, planRoot, credentialBindings, receiptRoot, verifiedRuntime.Artifacts.Config, token)
	delivery, err := NewOperationPlanGatusDelivery(baseURL, token, 5*time.Second)
	if err != nil {
		t.Fatal("pinned Gatus adapter rejected the local loopback listener")
	}
	indexPath := filepath.Join(planRoot, filepath.FromSlash(plan.binding.IndexPath))
	probeConfig, err := OperationPlanProbeConfigFromRuntimeLock(actualCLIRuntimeLock(binarySHA, sourceRevision, plan), "amd64", binaryPath, indexPath, credentialBindings, receiptRoot, []string{"SSL_CERT_FILE"})
	if err != nil {
		t.Fatal("actual CLI child could not bind to the immutable runtime lock")
	}
	runner, err := NewOperationPlanProbeRunner(probeConfig)
	if err != nil {
		t.Fatal("actual compiled CLI failed its executable digest check")
	}
	// Keep the production runner, worker and receipt validation path while
	// placing every actual CLI child inside the Docker internal network. The
	// package-private launcher seam is unavailable to production callers.
	if filepath.Clean(runner.workingDirectory) != filepath.Clean(planRoot) {
		t.Fatal("actual CLI sandbox working directory does not match the pinned operation-index root")
	}
	childTelemetry := &actualCLIInvocationTelemetry{}
	runner.childInvoker = instrumentActualCLIChildInvoker(dockerActualCLIChildInvoker(networkName, cliContainer, runner.workingDirectory), childTelemetry)
	lock := actualCLIRuntimeLock(binarySHA, sourceRevision, plan)
	resolver, err := NewPinnedOperationPlanProbeExpectationResolver(plan, lock, "amd64")
	if err != nil {
		t.Fatal("actual CLI receipt resolver rejected the pinned plan")
	}
	historyValidator, err := NewOperationPlanProbeHistoryValidator(actualCLIExpectedSourceRevision, resolver)
	if err != nil {
		t.Fatal("actual CLI receipt validator rejected the exact source pin")
	}
	attempts, err := OpenOperationAttemptStore(filepath.Join(fixtureRoot, "attempts"))
	if err != nil {
		t.Fatal("could not open the durable actual-CLI attempt store")
	}
	quotas, err := OpenOperationQuotaAuthority(filepath.Join(fixtureRoot, "quotas"))
	if err != nil {
		t.Fatal("could not open the durable actual-CLI quota store")
	}
	history, err := OpenOperationHistoryStore(filepath.Join(fixtureRoot, "history"), maxOperationHistoryStoreBytes, historyValidator)
	if err != nil {
		t.Fatal("could not open the durable actual-CLI receipt history")
	}
	worker, err := NewOperationPlanWorker(OperationPlanWorkerConfig{
		Runtime: verifiedRuntime, Runner: runner, Attempts: attempts, Quotas: quotas, History: history,
		HistoryValidator: historyValidator, Gatus: delivery, RuntimeLock: lock, Architecture: "amd64",
		AttemptLease: time.Minute, QuotaLease: time.Minute,
	})
	if err != nil {
		t.Fatal("production worker rejected the compiled actual-CLI runner")
	}
	t.Logf("actual CLI source-QA production runtime ready: elapsed=%s", time.Since(qaStarted).Round(time.Millisecond))

	if mode == "smoke" {
		actualCLIRejectsMissingInstallEvidence(t, worker, identities, planRoot, metricsURL, providerCA)
		childTelemetry.reset()
		smokeStarted := time.Now()
		actualCLISmoke(t, worker, attempts, history, identities, metricsURL, providerCA, childTelemetry)
		smokeChildren := childTelemetry.snapshot()
		cancellationElapsed := actualCLICancellationProbe(t, runner, worker, identities, delayedOperationID, metricsURL, providerCA, cliContainer)
		peakBytes, samples := monitor.Snapshot()
		metrics := actualCLIProviderMetrics(t, metricsURL, providerCA)
		if metrics["requests"] != 9 || metrics["unique"] != 9 || metrics["duplicates"] != 0 || metrics["invalid"] != 0 {
			t.Fatalf("actual CLI cancellation probe did not preserve exact isolated provider accounting: requests=%d unique=%d duplicates=%d invalid=%d", metrics["requests"], metrics["unique"], metrics["duplicates"], metrics["invalid"])
		}
		t.Logf("actual CLI source-QA smoke passed: cli_source=%s cli_source_tree_verified=true cli_version=%s cli_sha256=%s go_build=%q registry_revision=%s registry_manifest_sha256=%s registry_index_sha256=%s provider_route_sha256=%s full_identities=%d registry_rest=%d registry_soap=%d inventory_unknown=%d synthetic_rest=4 synthetic_soap=4 synthetic_smoke_requests=8 cancellation_probe_requests=1 provider_requests=%d gatus_readbacks=6 external_provider_destinations=0 bound_artifact_bytes=%d manifest_bytes=%d physical_projection_bytes=%d manifest_artifact_count=%d cli_peak_bytes=%d memory_samples=%d cli_children=%d cli_child_total=%s cli_child_max=%s cli_child_timeouts=%d cli_child_exit_errors=%d cli_child_other_errors=%d cli_child_stdout_bytes=%d cli_child_stderr_bytes=%d cancellation_probe_elapsed=%s smoke_elapsed=%s", sourceRevision, actualCLIExpectedVersion, binarySHA, goBuildVersion, plan.binding.RegistryRevision, plan.binding.ReleaseManifestSHA256, plan.IndexSHA256(), providerRoutesSHA256, len(identities), protocolCounts["REST"], protocolCounts["SOAP"], unknownInventoryCount, metrics["requests"], projection.BoundArtifactBytes, projection.ManifestBytes, projection.PhysicalBytes, projection.ManifestArtifactCount, peakBytes, samples, smokeChildren.Calls, smokeChildren.TotalElapsed.Round(time.Millisecond), smokeChildren.MaxElapsed.Round(time.Millisecond), smokeChildren.ContextTimeout, smokeChildren.ExitErrors, smokeChildren.OtherErrors, smokeChildren.StdoutBytes, smokeChildren.StderrBytes, cancellationElapsed.Round(time.Millisecond), time.Since(smokeStarted).Round(time.Second))
		return
	}

	actualCLIFullPopulation(t, worker, attempts, history, plan, metadata, identities, metricsURL, providerCA, providerRoutesSHA256, paths, sourceRevision, binarySHA, goBuildVersion, projection, monitor)
}

func stageActualCLITrustedRegistryProjection(t *testing.T, planRoot string, plan PinnedOperationObservationPlan) actualCLIProjectionMeasurements {
	t.Helper()
	if plan.state == nil || !plan.state.verified || filepath.Clean(plan.state.root) != filepath.Clean(planRoot) {
		t.Fatal("actual CLI trusted projection requires the verified pinned plan root")
	}
	manifestPath := filepath.Join(planRoot, filepath.FromSlash(plan.binding.ReleaseManifestPath))
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil || int64(len(manifestRaw)) != plan.binding.ReleaseManifestBytes || digest(manifestRaw) != plan.binding.ReleaseManifestSHA256 {
		t.Fatal("actual CLI release manifest is not the exact manifest bound by the loaded plan")
	}
	var manifest actualCLIReleaseManifest
	if json.Unmarshal(manifestRaw, &manifest) != nil || manifest.SchemaVersion != "datapan.release-manifest.v1" || manifest.ArtifactCount != len(manifest.Artifacts) || manifest.SourceRegistry != "data/data-go-kr.registry.json" {
		t.Fatal("actual CLI release manifest does not bind the expected Registry source artifact")
	}
	registrySHA := ""
	var boundArtifactBytes int64
	for _, artifact := range manifest.Artifacts {
		if artifact.Bytes <= 0 || !sha256Pattern.MatchString(artifact.SHA256) {
			t.Fatal("actual CLI release manifest has an invalid artifact entry")
		}
		if artifact.Path == manifest.SourceRegistry {
			registrySHA = artifact.SHA256
			continue
		}
		boundArtifactBytes += artifact.Bytes
	}
	if !strings.EqualFold(registrySHA, plan.state.manifest[manifest.SourceRegistry].SHA256) || boundArtifactBytes <= 0 {
		t.Fatal("actual CLI release manifest source Registry digest differs from the pinned plan")
	}
	verified := true
	manifestSHA := digest(manifestRaw)
	datasetManifestSHA := digest([]byte("synthetic local actual-CLI source-QA distribution manifest:" + plan.RegistryRevision()))
	provenanceRaw, err := json.Marshal(struct {
		SchemaVersion            string `json:"schema_version"`
		InstalledAt              string `json:"installed_at"`
		Provider                 string `json:"provider"`
		RegistryPath             string `json:"registry_path"`
		RegistrySHA256           string `json:"registry_sha256"`
		ReleaseTag               string `json:"release_tag"`
		AssetURL                 string `json:"asset_url"`
		PinMode                  string `json:"pin_mode"`
		SourceMode               string `json:"source_mode"`
		ReleaseDir               string `json:"release_dir"`
		ReleaseManifestPath      string `json:"release_manifest"`
		ReleaseManifestSHA256    string `json:"release_manifest_sha256"`
		ManifestRegistryVerified *bool  `json:"manifest_registry_verified"`
		Distribution             string `json:"distribution"`
		DatasetID                string `json:"dataset_id"`
		DatasetRevision          string `json:"dataset_revision"`
		DatasetManifestURL       string `json:"dataset_manifest_url"`
		DatasetManifestSHA256    string `json:"dataset_manifest_sha256"`
	}{
		SchemaVersion: "datapan.registry-install.v1", InstalledAt: "2026-10-10T00:00:00Z", Provider: "datapan-registry",
		RegistryPath: ".datapan/data-go-kr.registry.json", RegistrySHA256: registrySHA, ReleaseTag: plan.RegistryRevision(),
		AssetURL: "synthetic-local-source-qa-only", PinMode: "pinned", SourceMode: "default_installed",
		ReleaseDir: ".datapan/release", ReleaseManifestPath: ".datapan/release/manifest.json", ReleaseManifestSHA256: manifestSHA,
		ManifestRegistryVerified: &verified, Distribution: "huggingface_dataset", DatasetID: "StatPan/datapan-registry",
		DatasetRevision: plan.RegistryRevision(), DatasetManifestURL: "synthetic-local-source-qa-only",
		DatasetManifestSHA256: datasetManifestSHA,
	})
	if err != nil || len(provenanceRaw) == 0 || len(provenanceRaw) > 64<<10 {
		t.Fatal("actual CLI synthetic install provenance could not be encoded within its source bound")
	}
	defaultManifestPath := filepath.Join(planRoot, ".datapan", "release", "manifest.json")
	provenancePath := filepath.Join(planRoot, ".datapan", "registry-install.json")
	if err := os.MkdirAll(filepath.Dir(defaultManifestPath), 0o700); err != nil {
		t.Fatal("actual CLI synthetic release directory could not be staged")
	}
	if err := os.WriteFile(defaultManifestPath, manifestRaw, 0o400); err != nil {
		t.Fatal("actual CLI synthetic default release manifest could not be staged")
	}
	if err := os.WriteFile(provenancePath, provenanceRaw, 0o400); err != nil {
		t.Fatal("actual CLI synthetic install provenance could not be staged")
	}
	if err := os.Chmod(defaultManifestPath, 0o400); err != nil {
		t.Fatal("actual CLI synthetic release manifest did not retain its read-only mode")
	}
	var physicalBytes int64
	err = filepath.WalkDir(planRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("actual CLI projection contains a symbolic link")
		}
		if !entry.IsDir() {
			info, err := entry.Info()
			if err != nil || !info.Mode().IsRegular() {
				return errors.New("actual CLI projection contains a non-regular file")
			}
			physicalBytes += info.Size()
		}
		return nil
	})
	if err != nil || physicalBytes < int64(len(manifestRaw)+len(provenanceRaw)) {
		t.Fatal("actual CLI projection physical-byte inventory failed")
	}
	return actualCLIProjectionMeasurements{BoundArtifactBytes: boundArtifactBytes, ManifestBytes: int64(len(manifestRaw)), PhysicalBytes: physicalBytes, ManifestArtifactCount: len(manifest.Artifacts)}
}

func actualCLIRejectsMissingInstallEvidence(t *testing.T, worker *OperationPlanWorker, identities []operationPlanPopulationIdentity, planRoot, metricsURL, caPath string) {
	t.Helper()
	runner, ok := worker.runner.(*OperationPlanProbeRunner)
	if !ok || filepath.Clean(runner.workingDirectory) != filepath.Clean(planRoot) {
		t.Fatal("actual CLI install-evidence check has no production runner bound to the mounted plan root")
	}
	used := map[string]struct{}{
		actualCLIGovRESTObservationOK: {}, actualCLIGovRESTObservation503: {}, actualCLIGovSOAPObservationOK: {}, actualCLIGovSOAPObservation503: {},
		actualCLIGovRESTTypedSuccess: {}, actualCLIGovRESTTypedFailure: {}, actualCLIGovSOAPTypedSuccess: {}, actualCLIGovSOAPTypedFailure: {},
	}
	selected := make([]operationPlanPopulationIdentity, 0, 2)
	for _, identity := range identities {
		if _, smokeID := used[identity.OperationID]; smokeID {
			continue
		}
		selected = append(selected, identity)
		if len(selected) == 2 {
			break
		}
	}
	if len(selected) != 2 {
		t.Fatal("actual CLI install-evidence checks could not select two non-smoke identities")
	}
	before := actualCLIProviderMetrics(t, metricsURL, caPath)
	if before["requests"] != 0 {
		t.Fatal("actual CLI install-evidence checks require a fresh provider with zero prior requests")
	}
	provenancePath := filepath.Join(planRoot, ".datapan", "registry-install.json")
	manifestPath := filepath.Join(planRoot, ".datapan", "release", "manifest.json")
	for index, item := range []struct {
		name string
		path string
		bad  []byte
	}{
		{name: "missing provenance", path: provenancePath},
		{name: "wrong manifest digest", path: manifestPath, bad: []byte("{}\n")},
	} {
		backup := item.path + ".health-source-qa-backup"
		if _, err := os.Lstat(backup); err == nil || !os.IsNotExist(err) {
			t.Fatal("actual CLI install-evidence backup path already exists")
		}
		if err := os.Rename(item.path, backup); err != nil {
			t.Fatalf("could not prepare the %s negative check", item.name)
		}
		if len(item.bad) != 0 {
			if err := os.WriteFile(item.path, item.bad, 0o400); err != nil {
				_ = os.Rename(backup, item.path)
				t.Fatalf("could not stage the %s negative input", item.name)
			}
		}
		target := worker.targets[operationReadModelIdentityKey(selected[index].SourceID, selected[index].OperationID)]
		attemptID, err := NewOperationPlanProbeAttemptID()
		started := time.Now().UTC()
		var expected OperationPlanProbeExpectation
		if err == nil {
			expected, err = operationPlanProbeExpected(worker.runtime.Plan, target.Record, target.ShardSHA256, attemptID, worker.lock, worker.arch, started)
		}
		if err == nil {
			_, exitCode, runErr := runner.Run(context.Background(), expected, started.Add(10*time.Second))
			if runErr == nil || exitCode == 0 {
				err = errors.New("CLI accepted missing or mismatched installed Registry evidence")
			}
		}
		restoreErr := os.Remove(item.path)
		if len(item.bad) == 0 {
			restoreErr = nil
		}
		if renameErr := os.Rename(backup, item.path); restoreErr == nil {
			restoreErr = renameErr
		}
		if restoreErr != nil {
			t.Fatalf("could not restore the immutable installed input after %s: %v", item.name, restoreErr)
		}
		if err != nil {
			t.Fatalf("actual CLI did not fail closed for %s: %v", item.name, err)
		}
	}
	after := actualCLIProviderMetrics(t, metricsURL, caPath)
	if after["requests"] != 0 || after["invalid"] != 0 {
		t.Fatal("actual CLI reached the synthetic provider without valid installed provenance and manifest binding")
	}
	t.Logf("actual CLI install evidence gates passed: missing_provenance_rejected=1 wrong_manifest_digest_rejected=1 provider_requests=0")
}

func actualCLIInput(t *testing.T) (sourceRoot, revision, binaryPath, binarySHA, buildGoVersion string) {
	t.Helper()
	sourceRoot = strings.TrimSpace(os.Getenv("HEALTH_OPERATION_ACTUAL_CLI_SOURCE"))
	if !filepath.IsAbs(sourceRoot) {
		t.Fatal("HEALTH_OPERATION_ACTUAL_CLI_SOURCE must name the exact clean CLI source checkout")
	}
	output, err := exec.Command("git", "-C", sourceRoot, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal("could not verify the CLI source revision")
	}
	revision = strings.TrimSpace(string(output))
	if revision != actualCLIExpectedSourceRevision {
		t.Fatalf("CLI source revision is not the merged source pin: got=%s expected=%s", revision, actualCLIExpectedSourceRevision)
	}
	status, err := exec.Command("git", "-C", sourceRoot, "status", "--porcelain", "--untracked-files=all").Output()
	if err != nil || len(status) != 0 {
		t.Fatal("CLI source checkout must be clean so the source revision identifies the compiled code")
	}
	goVersionOutput, err := exec.Command("go", "version").Output()
	if err != nil {
		t.Fatal("could not identify the Go toolchain used for source QA")
	}
	buildGoVersion = strings.TrimSpace(string(goVersionOutput))
	binaryPath = filepath.Join(t.TempDir(), "datapan-amd64")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags", "-X github.com/StatPan/datapan-cli/internal/cli.version="+actualCLIExpectedVersion, "-o", binaryPath, "./cmd/datapan")
	build.Dir = sourceRoot
	build.Env = offlineGoBuildEnv()
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("could not build the exact CLI source for local source QA (exit=%v, output_bytes=%d)", err, len(output))
	}
	info, err := os.Stat(binaryPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatal("actual CLI source-QA binary is missing or not executable")
	}
	binaryBytes, err := os.ReadFile(binaryPath)
	if err != nil || len(binaryBytes) == 0 {
		t.Fatal("could not read the actual CLI binary identity")
	}
	sum := sha256.Sum256(binaryBytes)
	binarySHA = hex.EncodeToString(sum[:])
	if supplied := strings.TrimSpace(os.Getenv("HEALTH_OPERATION_ACTUAL_CLI_BINARY")); supplied != "" {
		if !filepath.IsAbs(supplied) {
			t.Fatal("HEALTH_OPERATION_ACTUAL_CLI_BINARY must be an absolute path")
		}
		suppliedBytes, readErr := os.ReadFile(supplied)
		suppliedSHA := sha256.Sum256(suppliedBytes)
		if readErr != nil || len(suppliedBytes) == 0 || hex.EncodeToString(suppliedSHA[:]) != binarySHA {
			t.Fatal("supplied CLI source-QA binary does not match a fresh build from the exact pinned source")
		}
	}
	if expected := strings.TrimSpace(os.Getenv("HEALTH_OPERATION_ACTUAL_CLI_BINARY_SHA256")); expected != "" && !strings.EqualFold(expected, binarySHA) {
		t.Fatalf("fresh exact-source CLI binary digest differs from its explicit source-QA pin: got=%s expected=%s", binarySHA, expected)
	}
	versionOutput, err := exec.Command(binaryPath, "version", "--json").Output()
	if err != nil {
		t.Fatal("actual CLI binary did not report its local source-QA version")
	}
	var versionInfo struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(versionOutput, &versionInfo) != nil || versionInfo.Version != actualCLIExpectedVersion {
		t.Fatal("actual CLI binary version does not match the test-only locked version")
	}
	return sourceRoot, revision, binaryPath, binarySHA, buildGoVersion
}

func buildActualCLIProvider(t *testing.T, root string, identities []operationPlanPopulationIdentity, delayedOperationID string) (binaryPath, caPath, certificatePath, keyPath, routesPath string) {
	t.Helper()
	binaryPath = filepath.Join(root, "actual-cli-provider")
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-o", binaryPath, "./internal/health/testdata/actual-cli-provider")
	command.Dir = "../.."
	command.Env = offlineGoBuildEnv()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("could not build the synthetic no-egress provider (exit=%v, output_bytes=%d)", err, len(output))
	}
	if err := os.Chmod(binaryPath, 0o755); err != nil {
		t.Fatal("could not mark the synthetic provider executable")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("could not generate an ephemeral local provider certificate key")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal("could not generate an ephemeral local certificate serial")
	}
	certificate := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "Synthetic Health fixture"},
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
		IPAddresses: []net.IP{net.ParseIP(actualCLIProviderIP), net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal("could not create an ephemeral local provider certificate")
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("could not encode the ephemeral local provider key")
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	caPath = filepath.Join(root, "provider-ca.pem")
	certificatePath = filepath.Join(root, "provider-server.pem")
	keyPath = filepath.Join(root, "provider-server.key")
	for path, data := range map[string][]byte{caPath: certificatePEM, certificatePath: certificatePEM, keyPath: privateKeyPEM} {
		mode := os.FileMode(0o444)
		if path == keyPath {
			mode = 0o400
		}
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal("could not stage ephemeral local provider certificate material")
		}
	}
	if len(identities) != 12666 {
		t.Fatal("synthetic provider route allowlist requires the full manifest-derived identity set")
	}
	routes := make([]actualCLIProviderRoute, 0, len(identities))
	for _, identity := range identities {
		protocol := "REST"
		if identity.SourceID == "data_go_kr" && identity.Protocol == "SOAP" {
			protocol = "SOAP"
		}
		route := actualCLIProviderRoute{SourceID: identity.SourceID, OperationID: identity.OperationID, Protocol: protocol}
		if identity.SourceID == "data_go_kr" && identity.OperationID == delayedOperationID {
			route.ResponseDelaySeconds = 30
		}
		routes = append(routes, route)
	}
	sort.Slice(routes, func(left, right int) bool {
		if routes[left].SourceID != routes[right].SourceID {
			return routes[left].SourceID < routes[right].SourceID
		}
		return routes[left].OperationID < routes[right].OperationID
	})
	routesRaw, err := json.Marshal(routes)
	if err != nil {
		t.Fatal("could not bind the local provider to exact source identity routes")
	}
	routesPath = filepath.Join(root, "provider-routes.json")
	if err := os.WriteFile(routesPath, routesRaw, 0o444); err != nil {
		t.Fatal("could not stage the exact local provider route allowlist")
	}
	return binaryPath, caPath, certificatePath, keyPath, routesPath
}

type actualCLIProviderRoute struct {
	SourceID             string `json:"source_id"`
	OperationID          string `json:"operation_id"`
	Protocol             string `json:"protocol"`
	ResponseDelaySeconds int    `json:"response_delay_seconds,omitempty"`
}

func actualCLICancellationIdentity(identities []operationPlanPopulationIdentity) (operationPlanPopulationIdentity, bool) {
	used := map[string]struct{}{
		actualCLIGovRESTObservationOK: {}, actualCLIGovRESTObservation503: {}, actualCLIGovSOAPObservationOK: {}, actualCLIGovSOAPObservation503: {},
		actualCLIGovRESTTypedSuccess: {}, actualCLIGovRESTTypedFailure: {}, actualCLIGovSOAPTypedSuccess: {}, actualCLIGovSOAPTypedFailure: {},
	}
	for _, identity := range identities {
		if identity.SourceID != "data_go_kr" || identity.Protocol != "REST" {
			continue
		}
		if _, alreadyUsed := used[identity.OperationID]; alreadyUsed {
			continue
		}
		return identity, true
	}
	return operationPlanPopulationIdentity{}, false
}

func actualCLICancellationProbe(t *testing.T, runner *OperationPlanProbeRunner, worker *OperationPlanWorker, identities []operationPlanPopulationIdentity, operationID, metricsURL, caPath, cliContainer string) time.Duration {
	t.Helper()
	if runner == nil || worker == nil || operationID == "" || cliContainer == "" {
		t.Fatal("actual CLI cancellation probe is not bound to the production runner and worker")
	}
	identity, found := actualCLICancellationIdentity(identities)
	if !found || identity.OperationID != operationID || identity.SourceID != "data_go_kr" || identity.Protocol != "REST" {
		t.Fatal("actual CLI cancellation route is not a distinct pinned Registry REST identity")
	}
	before := actualCLIProviderMetrics(t, metricsURL, caPath)
	if before["requests"] != 8 || before["unique"] != 8 || before["duplicates"] != 0 || before["invalid"] != 0 {
		t.Fatal("actual CLI cancellation probe requires the exact eight-case smoke state")
	}
	target, found := worker.targets[operationReadModelIdentityKey(identity.SourceID, identity.OperationID)]
	if !found {
		t.Fatal("actual CLI cancellation identity is absent from the production worker")
	}
	attemptID, err := NewOperationPlanProbeAttemptID()
	if err != nil {
		t.Fatal("actual CLI cancellation attempt identity could not be generated")
	}
	started := time.Now().UTC()
	expected, err := operationPlanProbeExpected(worker.runtime.Plan, target.Record, target.ShardSHA256, attemptID, worker.lock, worker.arch, started)
	if err != nil {
		t.Fatal("actual CLI cancellation attempt did not bind to the selected Registry record")
	}
	ctx, cancel := context.WithCancel(context.Background())
	type runResult struct {
		err      error
		elapsed  time.Duration
		exitCode int
	}
	done := make(chan runResult, 1)
	childStarted := time.Now()
	go func() {
		_, exitCode, runErr := runner.Run(ctx, expected, childStarted.Add(20*time.Second))
		done <- runResult{err: runErr, elapsed: time.Since(childStarted), exitCode: exitCode}
	}()
	requestObserved := false
	requestDeadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(requestDeadline) {
		metrics := actualCLIProviderMetrics(t, metricsURL, caPath)
		if metrics["requests"] == 9 && metrics["unique"] == 9 && metrics["duplicates"] == 0 && metrics["invalid"] == 0 {
			requestObserved = true
			break
		}
		if metrics["requests"] > 9 || metrics["invalid"] != 0 || metrics["duplicates"] != 0 {
			cancel()
			t.Fatal("actual CLI cancellation probe observed an unexpected synthetic provider request")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !requestObserved {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("actual CLI cancellation probe did not stop its child after the provider request deadline")
		}
		t.Fatal("actual CLI cancellation probe did not reach its delayed synthetic provider route")
	}
	cancel()
	var completed runResult
	select {
	case completed = <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("actual CLI runner did not return promptly after cancellation")
	}
	if completed.err == nil {
		t.Fatalf("actual CLI runner accepted a response after cancellation: exit_code=%d", completed.exitCode)
	}
	if entries, readErr := os.ReadDir(runner.config.ReceiptDirectory); readErr != nil || len(entries) != 0 {
		t.Fatal("actual CLI cancellation left an output file that could be mistaken for a receipt")
	}
	containerGone := false
	containerDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(containerDeadline) {
		ctx, stop := context.WithTimeout(context.Background(), time.Second)
		output, inspectErr := exec.CommandContext(ctx, "docker", "inspect", "--format", "{{.State.Running}}", cliContainer).Output()
		stop()
		if inspectErr != nil {
			containerGone = true
			break
		}
		if strings.TrimSpace(string(output)) != "false" {
			t.Fatal("actual CLI sandbox remained running after the canceled provider request")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !containerGone {
		t.Fatal("actual CLI cancellation did not remove its --rm sandbox container")
	}
	after := actualCLIProviderMetrics(t, metricsURL, caPath)
	if after["requests"] != 9 || after["unique"] != 9 || after["duplicates"] != 0 || after["invalid"] != 0 {
		t.Fatal("actual CLI cancellation did not reconcile to one exact delayed local provider request")
	}
	return completed.elapsed
}

func buildActualCLIRuntime(t *testing.T, root, planRoot string, metadata VerifiedRegistryAPIMetadata, canaries CanaryConfig, plan PinnedOperationObservationPlan, identities []operationPlanPopulationIdentity) (*VerifiedOperationPlanRuntime, OperationPlanRuntimePaths) {
	t.Helper()
	entries := make([]OperationGatusActivationEntry, len(identities))
	for index, identity := range identities {
		entries[index] = OperationGatusActivationEntry{SourceID: identity.SourceID, OperationID: identity.OperationID}
	}
	activationRaw, err := json.Marshal(OperationGatusActivation{
		SchemaVersion: OperationGatusActivationSchemaVersion, RegistryRevision: plan.RegistryRevision(), IndexSHA256: plan.IndexSHA256(), Operations: entries,
	})
	if err != nil {
		t.Fatal("could not encode the exact full-population activation")
	}
	activation, activationSHA, err := DecodeOperationGatusActivation(activationRaw, plan)
	if err != nil {
		t.Fatal("full-population activation did not bind to the exact actual-CLI plan")
	}
	canaryRaw, err := os.ReadFile("../../config/canaries.json")
	if err != nil {
		t.Fatal("could not read pinned canary metadata")
	}
	baseConfig := []byte("web:\n  port: 8080\nendpoints:\n  - name: local-health\n    url: http://127.0.0.1:8080/health\n    interval: 5s\n    conditions:\n      - '[STATUS] == 200'\nexternal-endpoints:\n  - name: placeholder\n")
	artifacts, err := GenerateOperationGatusArtifacts(baseConfig, digestOperationGatusBytes(canaryRaw), canaries, metadata, &plan, &activation, activationSHA)
	if err != nil {
		t.Fatalf("native Gatus generation could not consume the actual-CLI plan: %v", err)
	}
	var mapping OperationGatusIdentityMapping
	if json.Unmarshal(artifacts.Mapping, &mapping) != nil || len(mapping.Operations) != len(identities) || mapping.KnownPlanOperations != len(identities) || mapping.ActivatedPlanOperations != len(identities) || mapping.ConfiguredExternalEndpoints != len(identities) {
		t.Fatalf("native Gatus mapping did not retain every exact identity: identities=%d mapped=%d endpoints=%d", len(identities), len(mapping.Operations), mapping.ConfiguredExternalEndpoints)
	}
	if strings.Contains(string(artifacts.Config), actualCLIProviderIP) {
		t.Fatal("Gatus configuration unexpectedly contains the synthetic provider destination")
	}

	paths := operationPlanTestRuntimePaths(root)
	paths.PlanRoot = planRoot
	paths.ActivationPath = filepath.Join(root, "activation.json")
	paths.ActivationSHA256 = activationSHA
	planPin, err := json.Marshal(operationObservationPlanRuntimePin{SchemaVersion: OperationObservationPlanRuntimePinSchema, Plan: plan.binding})
	if err != nil {
		t.Fatal("could not encode the actual-CLI plan pin")
	}
	metadataRaw, err := os.ReadFile("../../config/registry/api-metadata.v1.json")
	if err != nil {
		t.Fatal("could not read pinned Registry metadata")
	}
	metadataPin, err := os.ReadFile("../../config/registry/api-metadata-source-pin.v1.json")
	if err != nil {
		t.Fatal("could not read pinned Registry metadata source pin")
	}
	files := map[string][]byte{
		paths.PlanPinPath: planPin, paths.CanaryConfigPath: canaryRaw, paths.RegistryMetadataPath: metadataRaw,
		paths.RegistryMetadataPin: metadataPin, paths.BaseGatusConfigPath: baseConfig, paths.GeneratedConfigPath: artifacts.Config,
		paths.IdentityMappingPath: artifacts.Mapping, paths.RuntimePinPath: artifacts.RuntimePin,
		paths.ActivationPath: activationRaw,
	}
	for path, data := range files {
		if err := os.WriteFile(path, data, 0o400); err != nil {
			t.Fatal("could not stage the exact Gatus runtime dependency set")
		}
	}
	verified, err := verifyOperationGatusRuntimeArtifacts(paths, canaryRaw, canaries, metadata, plan)
	if err != nil || len(verified.ActiveTargets) != len(identities) {
		t.Fatalf("pinned native Gatus runtime rejected the full actual-CLI target set: active=%d expected=%d", len(verified.ActiveTargets), len(identities))
	}
	return verified, paths
}

func actualCLIProviderMetrics(t *testing.T, endpoint, caPath string) map[string]int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/__metrics", nil)
	if err != nil {
		t.Fatal("could not inspect aggregate synthetic provider counters")
	}
	caRaw, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal("could not inspect the public local fixture CA")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caRaw) {
		t.Fatal("local fixture CA did not parse")
	}
	response, err := (&http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots}}}).Do(request)
	if err != nil {
		t.Fatal("aggregate synthetic provider counters are unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("aggregate synthetic provider counters returned an invalid status")
	}
	var result map[string]int
	if json.NewDecoder(response.Body).Decode(&result) != nil {
		t.Fatal("aggregate synthetic provider counters were not valid JSON")
	}
	return result
}

func actualCLISmoke(t *testing.T, worker *OperationPlanWorker, attempts *OperationAttemptStore, history *OperationHistoryStore, identities []operationPlanPopulationIdentity, metricsURL, caPath string, telemetry *actualCLIInvocationTelemetry) {
	t.Helper()
	type smokeCase struct {
		name        string
		operationID string
		protocol    string
		outcome     string
	}
	cases := []smokeCase{
		{name: "REST observation-only 2xx", operationID: actualCLIGovRESTObservationOK, protocol: "REST", outcome: "indeterminate"},
		{name: "REST observation-only 503", operationID: actualCLIGovRESTObservation503, protocol: "REST", outcome: "unhealthy_http"},
		{name: "SOAP observation-only 2xx", operationID: actualCLIGovSOAPObservationOK, protocol: "SOAP", outcome: "indeterminate"},
		{name: "SOAP observation-only 503", operationID: actualCLIGovSOAPObservation503, protocol: "SOAP", outcome: "unhealthy_http"},
		{name: "REST typed success", operationID: actualCLIGovRESTTypedSuccess, protocol: "REST", outcome: "healthy"},
		{name: "REST typed provider error", operationID: actualCLIGovRESTTypedFailure, protocol: "REST", outcome: "unhealthy_typed"},
		{name: "SOAP typed success", operationID: actualCLIGovSOAPTypedSuccess, protocol: "SOAP", outcome: "healthy"},
		{name: "SOAP typed Fault", operationID: actualCLIGovSOAPTypedFailure, protocol: "SOAP", outcome: "unhealthy_typed"},
	}
	selected := make([]struct {
		caseSpec smokeCase
		identity operationPlanPopulationIdentity
	}, len(cases))
	used := make(map[string]struct{}, len(cases))
	for index, testCase := range cases {
		identity, found := actualCLISmokeIdentity(identities, testCase.operationID, testCase.protocol, used)
		if !found {
			t.Fatalf("pinned source metadata has no identity for the local %s case", testCase.name)
		}
		key := operationReadModelIdentityKey(identity.SourceID, identity.OperationID)
		used[key] = struct{}{}
		selected[index].caseSpec, selected[index].identity = testCase, identity
	}
	type execution struct {
		result OperationPlanWorkerResult
		err    error
	}
	results := make([]execution, len(selected))
	var wait sync.WaitGroup
	for index := range selected {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			identity := selected[index].identity
			results[index].result, results[index].err = worker.ExecuteOne(context.Background(), identity.SourceID, identity.OperationID, time.Now().UTC())
		}(index)
	}
	wait.Wait()
	for index, selectedCase := range selected {
		testCase, identity := selectedCase.caseSpec, selectedCase.identity
		result, err := results[index].result, results[index].err
		if err != nil || result.AttemptState != "observed" || !result.RequestStarted {
			storedState, blockReason, requestStarted := "missing", "none", "unset"
			stored, found, readErr := attempts.Latest(identity.SourceID, identity.OperationID)
			if readErr == nil && found {
				storedState, blockReason = stored.State, stored.BlockReason
				if stored.RequestStarted != nil {
					requestStarted = strconv.FormatBool(*stored.RequestStarted)
				}
			}
			children := telemetry.snapshot()
			t.Fatalf("actual CLI did not commit a durable %s observation: attempt_state=%s execution_block=%s request=%t stored_state=%s stored_block=%s stored_request=%s worker_error=%t child_calls=%d child_total=%s child_max=%s child_timeouts=%d child_exit_errors=%d child_other_errors=%d child_stdout_bytes=%d child_stderr_bytes=%d child_stderr_classes=%s", testCase.name, result.AttemptState, result.ExecutionBlockReason, result.RequestStarted, storedState, blockReason, requestStarted, err != nil, children.Calls, children.TotalElapsed.Round(time.Millisecond), children.MaxElapsed.Round(time.Millisecond), children.ContextTimeout, children.ExitErrors, children.OtherErrors, children.StdoutBytes, children.StderrBytes, actualCLIChildStderrClassSummary(children.StderrClasses))
		}
		latest, found, err := attempts.Latest(identity.SourceID, identity.OperationID)
		if err != nil || !found || latest.Result == nil || !latest.ReceiptValidated || latest.State != "observed" {
			t.Fatalf("actual CLI %s receipt was not durably validated", testCase.protocol)
		}
		shouldDeliver := true
		switch testCase.outcome {
		case "unhealthy_http":
			if latest.Result.State != "unhealthy" || latest.Result.Category != "response_http_failure" || latest.DeliveryState == "not_applicable" {
				t.Fatalf("local 503 did not retain provider-unhealthy classification for %s", testCase.protocol)
			}
		case "indeterminate":
			shouldDeliver = false
			if latest.Result.State != "indeterminate" || latest.Result.Category != "response_semantics_unestablished" || latest.DeliveryState != "not_applicable" {
				t.Fatalf("local 2xx did not remain observation-only indeterminate for %s", testCase.protocol)
			}
		case "healthy":
			if latest.Result.State != "healthy" || latest.Result.Category != "healthy" || latest.DeliveryState == "not_applicable" {
				t.Fatalf("valid typed %s response was not classified healthy", testCase.protocol)
			}
		case "unhealthy_typed":
			if latest.Result.State != "unhealthy" || latest.Result.Category != "provider_failure" || latest.DeliveryState == "not_applicable" {
				t.Fatalf("typed %s provider error was not classified unhealthy", testCase.protocol)
			}
		default:
			t.Fatalf("unsupported smoke outcome %q", testCase.outcome)
		}
		if shouldDeliver {
			if err := worker.DeliverOne(context.Background(), identity.SourceID, identity.OperationID, latest.AttemptID, latest.Generation, time.Now().UTC(), time.Minute); err != nil {
				t.Fatalf("native Gatus did not accept the %s receipt by exact-key readback", testCase.protocol)
			}
			latest, found, err = attempts.Latest(identity.SourceID, identity.OperationID)
			if err != nil || !found || latest.DeliveryState != "readback_verified" || latest.GatusReceivedAt.IsZero() {
				t.Fatalf("native Gatus readback was not durably stored for %s", testCase.protocol)
			}
		}
	}
	usage, err := history.Usage(context.Background())
	if err != nil || usage.RecordCount != int64(len(cases)) || usage.ReservationCount != 0 {
		t.Fatalf("actual CLI smoke did not reconcile durable validated receipt history: records=%d reservations=%d", usage.RecordCount, usage.ReservationCount)
	}
	metrics := actualCLIProviderMetrics(t, metricsURL, caPath)
	if metrics["requests"] != 8 || metrics["unique"] != 8 || metrics["duplicates"] != 0 || metrics["allowed_routes"] != len(identities) || metrics["rest_get"] != 4 || metrics["soap_post"] != 4 || metrics["status_2xx"] != 6 || metrics["status_503"] != 2 || metrics["invalid"] != 0 {
		t.Fatalf("isolated provider did not receive the eight exact manifest-bound REST/SOAP cases: requests=%d unique=%d duplicates=%d allowed=%d rest=%d soap=%d 2xx=%d 503=%d invalid=%d", metrics["requests"], metrics["unique"], metrics["duplicates"], metrics["allowed_routes"], metrics["rest_get"], metrics["soap_post"], metrics["status_2xx"], metrics["status_503"], metrics["invalid"])
	}
}

func actualCLISmokeIdentity(identities []operationPlanPopulationIdentity, operationID, protocol string, used map[string]struct{}) (operationPlanPopulationIdentity, bool) {
	for _, identity := range identities {
		if identity.SourceID != "data_go_kr" || identity.OperationID != operationID || identity.Protocol != protocol {
			continue
		}
		key := operationReadModelIdentityKey(identity.SourceID, identity.OperationID)
		if _, exists := used[key]; exists {
			continue
		}
		return identity, true
	}
	return operationPlanPopulationIdentity{}, false
}

func actualCLIFullPopulation(t *testing.T, worker *OperationPlanWorker, attempts *OperationAttemptStore, history *OperationHistoryStore, plan PinnedOperationObservationPlan, metadata VerifiedRegistryAPIMetadata, identities []operationPlanPopulationIdentity, metricsURL, caPath, providerRoutesSHA256 string, paths OperationPlanRuntimePaths, sourceRevision, binarySHA, goBuildVersion string, projection actualCLIProjectionMeasurements, monitor *actualCLIContainerMonitor) {
	t.Helper()
	const concurrency = 8
	scheduler, err := NewOperationPlanScheduler(OperationPlanSchedulerConfig{
		Worker: worker, MaxConcurrent: concurrency, MaxStartsPerPass: concurrency, MaxDeliveriesPerPass: concurrency,
		CandidateScanPerPass: operationPlanSchedulerMaximumScanBudget, DeliveryLease: time.Minute,
	})
	if err != nil {
		t.Fatal("bounded production scheduler rejected the actual-CLI full population")
	}
	preflight := scheduler.Status(time.Now().UTC())
	if !preflight.CapacityFeasible || preflight.AdmittedOperations != len(identities) || preflight.RequiredConcurrency > concurrency {
		t.Fatalf("actual CLI full source-QA capacity preflight failed before provider requests: feasible=%t required_concurrency=%d max_concurrent=%d required_starts_per_second=%.9f admitted=%d expected=%d", preflight.CapacityFeasible, preflight.RequiredConcurrency, concurrency, preflight.RequiredStartsPerSecond, preflight.AdmittedOperations, len(identities))
	}
	t.Logf("actual CLI full source-QA capacity preflight: identities=%d required_starts_per_second=%.9f required_concurrency=%d max_concurrent=%d feasible=true", preflight.AdmittedOperations, preflight.RequiredStartsPerSecond, preflight.RequiredConcurrency, concurrency)
	controllerCtx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()
	startedAt := time.Now().UTC()
	lastProgressAt := time.Now()
	status := preflight
	completed := false
	for controllerCtx.Err() == nil {
		before := status.PassesSinceStart
		if err := scheduler.ProcessDue(controllerCtx, time.Now().UTC()); err != nil {
			scheduler.Wait()
			t.Fatalf("bounded production pass failed after %s with no provider call outside the isolated fixture: %v", time.Since(startedAt).Round(time.Second), err)
		}
		status = scheduler.Status(time.Now().UTC())
		if time.Since(lastProgressAt) >= 30*time.Second {
			usage, _ := history.Usage(context.Background())
			t.Logf("actual CLI full source-QA progress: starts=%d observations=%d readbacks=%d not_applicable=%d active=%d execution_failures=%d delivery_failures=%d receipt_records=%d elapsed=%s", status.RequestStartsSinceStart, status.ObservationsSinceStart, status.ReadbacksSinceStart, status.NotApplicableSinceStart, status.ActiveWork, status.ExecutionFailuresSinceStart, status.DeliveryFailuresSinceStart, usage.RecordCount, time.Since(startedAt).Round(time.Second))
			lastProgressAt = time.Now()
		}
		if status.RequestStartsSinceStart == uint64(len(identities)) && status.ObservationsSinceStart == uint64(len(identities)) && status.ReadbacksSinceStart+status.NotApplicableSinceStart == uint64(len(identities)) && status.ActiveWork == 0 && status.EvidenceCurrentOperations == len(identities) && status.Ready {
			completed = true
			break
		}
		wait := operationPlanSchedulerPassInterval
		if status.PassesSinceStart > before {
			wait = operationPlanSchedulerPassInterval
		}
		timer := time.NewTimer(wait)
		select {
		case <-controllerCtx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	if !completed {
		cancel()
		scheduler.Wait()
		usage, _ := history.Usage(context.Background())
		elapsed := time.Since(startedAt)
		t.Fatalf("actual CLI did not reconcile all pinned identities within the 45-minute source-QA bound: starts=%d observations=%d readbacks=%d not_applicable=%d execution_failures=%d delivery_failures=%d active=%d expected=%d elapsed=%s receipts=%d history_bytes=%d", status.RequestStartsSinceStart, status.ObservationsSinceStart, status.ReadbacksSinceStart, status.NotApplicableSinceStart, status.ExecutionFailuresSinceStart, status.DeliveryFailuresSinceStart, status.ActiveWork, len(identities), elapsed.Round(time.Second), usage.RecordCount, usage.UsedBytes)
	}
	scheduler.Wait()
	status = scheduler.Status(time.Now().UTC())
	if status.ExecutionFailuresSinceStart != 0 || status.DeliveryFailuresSinceStart != 0 || status.IdentityScanFailuresSinceStart != 0 || status.PendingDeliveryScanFailures != 0 || status.EvidenceCurrentOperations != len(identities) || !status.Ready {
		t.Fatalf("actual CLI readiness sweep did not prove a current exact receipt for every identity: ready=%t evidence=%d/%d execution_failures=%d delivery_failures=%d identity_scan_failures=%d delivery_scan_failures=%d", status.Ready, status.EvidenceCurrentOperations, len(identities), status.ExecutionFailuresSinceStart, status.DeliveryFailuresSinceStart, status.IdentityScanFailuresSinceStart, status.PendingDeliveryScanFailures)
	}
	usage, err := history.Usage(context.Background())
	if err != nil || usage.RecordCount != int64(len(identities)) || usage.ReservationCount != 0 {
		t.Fatalf("actual child receipt history did not reconcile to the full identity set: records=%d reservations=%d expected=%d", usage.RecordCount, usage.ReservationCount, len(identities))
	}
	rows, err := attempts.SnapshotReadModelAttempts()
	if err != nil || len(rows) != len(identities) {
		t.Fatalf("durable attempts did not cover every actual CLI identity: rows=%d expected=%d", len(rows), len(identities))
	}
	unknownIDs := populationIdentityMap(identities)
	seenRows := make(map[string]OperationReadModelAttempt, len(rows))
	govUnavailableCount := 0
	typedErrorCount := 0
	typedSuccessCount := 0
	for _, row := range rows {
		key := operationReadModelIdentityKey(row.SourceID, row.OperationID)
		if _, expected := unknownIDs[key]; !expected || row.AttemptState != "observed" || row.ObservationAttemptState != "observed" || !row.ReceiptValidated {
			t.Fatal("durable actual CLI attempt set contains an unknown identity or invalid receipt")
		}
		if _, duplicate := seenRows[key]; duplicate {
			t.Fatal("durable actual CLI attempt set repeated a Registry identity")
		}
		seenRows[key] = row
		govUnavailable := row.SourceID == "data_go_kr" && (row.OperationID == actualCLIGovRESTObservation503 || row.OperationID == actualCLIGovSOAPObservation503)
		typedError := row.SourceID == "data_go_kr" && (row.OperationID == actualCLIGovRESTTypedFailure || row.OperationID == actualCLIGovSOAPTypedFailure)
		typedSuccess := row.SourceID == "data_go_kr" && (row.OperationID == actualCLIGovRESTTypedSuccess || row.OperationID == actualCLIGovSOAPTypedSuccess)
		switch {
		case govUnavailable:
			govUnavailableCount++
			if row.ResultState != "unhealthy" || row.ResultCategory != "response_http_failure" || row.GatusDeliveryState != "readback_verified" || row.GatusReadbackAt.IsZero() {
				t.Fatal("local provider 503 did not retain unhealthy state and exact native Gatus readback")
			}
		case typedError:
			typedErrorCount++
			if row.ResultState != "unhealthy" || row.ResultCategory != "provider_failure" || row.GatusDeliveryState != "readback_verified" || row.GatusReadbackAt.IsZero() {
				t.Fatal("invalid typed 2xx response did not retain unhealthy state and exact native Gatus readback")
			}
		case typedSuccess:
			typedSuccessCount++
			if row.ResultState != "healthy" || row.ResultCategory != "healthy" || row.GatusDeliveryState != "readback_verified" || row.GatusReadbackAt.IsZero() {
				t.Fatal("valid typed 2xx response did not retain healthy state and exact native Gatus readback")
			}
		default:
			if row.ResultState != "indeterminate" || row.ResultCategory != "response_semantics_unestablished" || row.GatusDeliveryState != "not_applicable" || !row.GatusReadbackAt.IsZero() {
				t.Fatal("local provider 2xx did not remain observation-only indeterminate without Gatus delivery")
			}
		}
	}
	expectedReadbacks := govUnavailableCount + typedErrorCount + typedSuccessCount
	expectedNotApplicable := len(identities) - expectedReadbacks
	if typedErrorCount != 2 || typedSuccessCount != 2 || status.ReadbacksSinceStart != uint64(expectedReadbacks) || status.NotApplicableSinceStart != uint64(expectedNotApplicable) {
		t.Fatalf("durable Gatus and observation-only outcomes do not reconcile: readbacks=%d expected=%d not_applicable=%d expected=%d typed_errors=%d typed_successes=%d", status.ReadbacksSinceStart, expectedReadbacks, status.NotApplicableSinceStart, expectedNotApplicable, typedErrorCount, typedSuccessCount)
	}
	metrics := actualCLIProviderMetrics(t, metricsURL, caPath)
	if metrics["requests"] != len(identities) || metrics["unique"] != len(identities) || metrics["duplicates"] != 0 || metrics["allowed_routes"] != len(identities) || metrics["rest_get"] != 12631 || metrics["soap_post"] != 35 || metrics["status_2xx"]+metrics["status_503"] != len(identities) || metrics["invalid"] != 0 {
		t.Fatalf("isolated provider aggregates do not match the exact pinned route set: requests=%d unique=%d duplicates=%d allowed=%d rest=%d soap=%d 2xx=%d 503=%d invalid=%d", metrics["requests"], metrics["unique"], metrics["duplicates"], metrics["allowed_routes"], metrics["rest_get"], metrics["soap_post"], metrics["status_2xx"], metrics["status_503"], metrics["invalid"])
	}
	if metrics["status_503"] != govUnavailableCount || metrics["status_2xx"] != len(identities)-govUnavailableCount {
		t.Fatal("provider aggregate responses do not reconcile to durable receipt classifications")
	}

	readModel, err := NewOperationReadModel(plan, metadata, nil, time.Now().UTC())
	if err != nil {
		t.Fatal("public Registry read model rejected the actual CLI receipt set")
	}
	refreshAt := time.Now().UTC().Add(time.Second)
	for offset := 0; ; {
		next, complete, refreshErr := readModel.RefreshFromStoreBatch(attempts, offset, operationAttemptIdentityBatchMaximum, refreshAt)
		if refreshErr != nil {
			t.Fatalf("bounded public read-model refresh failed at offset %d", offset)
		}
		if complete {
			break
		}
		offset = next
	}
	expected := populationIdentityMap(identities)
	seen := make(map[string]struct{}, len(identities))
	cursor := ""
	for {
		page, pageErr := readModel.PageOperations(OperationPageQuery{Limit: operationReadModelMaximumPage, Cursor: cursor}, refreshAt)
		if pageErr != nil {
			t.Fatal("bounded public operation paging failed")
		}
		if page.IdentityCounts.Known != len(identities) || page.IdentityCounts.Admitted != len(identities) || page.IdentityCounts.Attempted != len(identities) || page.IdentityCounts.Persisted != len(identities) || page.IdentityCounts.ReadbackVerified != expectedReadbacks || page.IdentityCounts.DeliveryPending != 0 || page.IdentityCounts.InventoryUnknownScopes != plan.Counts().InventoryUnknownScopes || page.IdentityCounts.InventoryUnknownOperations != unknownOperationCount(identities) || page.IdentityCounts.Missing != 0 || page.IdentityCounts.Late != 0 {
			t.Fatalf("public page identity counts did not reconcile actual receipt and Gatus states: known=%d admitted=%d attempted=%d persisted=%d readback=%d pending=%d unknown_scopes=%d unknown_ops=%d missing=%d late=%d expected=%d", page.IdentityCounts.Known, page.IdentityCounts.Admitted, page.IdentityCounts.Attempted, page.IdentityCounts.Persisted, page.IdentityCounts.ReadbackVerified, page.IdentityCounts.DeliveryPending, page.IdentityCounts.InventoryUnknownScopes, page.IdentityCounts.InventoryUnknownOperations, page.IdentityCounts.Missing, page.IdentityCounts.Late, len(identities))
		}
		for _, operation := range page.Operations {
			key := operationReadModelIdentityKey(operation.SourceID, operation.RegistryOperationID)
			identity, found := expected[key]
			_, duplicate := seen[key]
			if !found || duplicate || operation.Provider != identity.Provider || operation.AdapterID != identity.AdapterID || operation.InventoryUnknown != identity.InventoryUnknown || operation.AttemptState != "observed" {
				t.Fatal("public operation page repeated or changed a source-bound actual CLI identity")
			}
			if identity.SourceID == "data_go_kr" && (identity.OperationID == actualCLIGovRESTObservation503 || identity.OperationID == actualCLIGovSOAPObservation503 || identity.OperationID == actualCLIGovRESTTypedFailure || identity.OperationID == actualCLIGovSOAPTypedFailure) {
				if operation.ObservationState != "current_fail" || operation.GatusDeliveryState != "readback_verified" {
					t.Fatal("public operation page did not expose the provider-unhealthy receipt and verified Gatus state")
				}
			} else if identity.SourceID == "data_go_kr" && (identity.OperationID == actualCLIGovRESTTypedSuccess || identity.OperationID == actualCLIGovSOAPTypedSuccess) {
				if operation.ObservationState != "current_pass" || operation.GatusDeliveryState != "readback_verified" {
					t.Fatal("public operation page did not preserve valid typed synthetic success and verified delivery")
				}
			} else if operation.ObservationState != "current_indeterminate" || operation.GatusDeliveryState != "not_applicable" {
				t.Fatal("public operation page did not preserve observation-only indeterminate semantics")
			}
			seen[key] = struct{}{}
		}
		cursor = page.NextCursor
		if cursor == "" {
			break
		}
	}
	if len(seen) != len(identities) {
		t.Fatalf("public paged reconciliation covered %d of %d exact Registry identities", len(seen), len(identities))
	}
	elapsed := time.Since(startedAt)
	storeBytes := operationPlanPopulationStorageBytes(t, filepath.Dir(paths.PlanPinPath))
	identityMappingSHA256 := actualCLIFileSHA256(t, paths.IdentityMappingPath)
	runtimePinSHA256 := actualCLIFileSHA256(t, paths.RuntimePinPath)
	gatusConfigSHA256 := actualCLIFileSHA256(t, paths.GeneratedConfigPath)
	peakBytes, memorySamples := monitor.Snapshot()
	t.Logf("actual CLI full source-QA passed: cli_source=%s cli_source_tree_verified=true cli_version=%s cli_sha256=%s go_build=%q registry_revision=%s registry_manifest_sha256=%s registry_index_sha256=%s provider_route_sha256=%s identity_mapping_sha256=%s runtime_pin_sha256=%s gatus_config_sha256=%s identities=%d registry_rest=%d registry_soap=%d inventory_unknown_scopes=%d inventory_unknown_operations=%d synthetic_rest=%d synthetic_soap=%d requests=%d provider_503=%d typed_successes=%d typed_errors=%d indeterminate_2xx=%d gatus_readbacks=%d not_applicable=%d scheduler_passes=%d elapsed=%s requests_per_second=%.2f history_records=%d history_bytes=%d runtime_store_bytes=%d public_pages=%d bound_artifact_bytes=%d manifest_bytes=%d physical_projection_bytes=%d manifest_artifact_count=%d external_provider_destinations=0 cli_peak_bytes=%d memory_samples=%d", sourceRevision, actualCLIExpectedVersion, binarySHA, goBuildVersion, plan.RegistryRevision(), plan.binding.ReleaseManifestSHA256, plan.IndexSHA256(), providerRoutesSHA256, identityMappingSHA256, runtimePinSHA256, gatusConfigSHA256, len(identities), 12627, 35, plan.Counts().InventoryUnknownScopes, unknownOperationCount(identities), metrics["rest_get"], metrics["soap_post"], metrics["requests"], metrics["status_503"], typedSuccessCount, typedErrorCount, metrics["status_2xx"]-typedSuccessCount-typedErrorCount, status.ReadbacksSinceStart, status.NotApplicableSinceStart, status.PassesSinceStart, elapsed.Round(time.Second), float64(len(identities))/max(elapsed.Seconds(), 1), usage.RecordCount, usage.UsedBytes, storeBytes, (len(seen)+operationReadModelMaximumPage-1)/operationReadModelMaximumPage, projection.BoundArtifactBytes, projection.ManifestBytes, projection.PhysicalBytes, projection.ManifestArtifactCount, peakBytes, memorySamples)
}

func actualCLIFileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		t.Fatal("could not read a generated source-QA artifact digest")
	}
	return digestOperationGatusBytes(data)
}
