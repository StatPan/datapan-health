package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
	"github.com/StatPan/datapan-health/internal/runtimebundle"
)

var operationPlanAllowedCLISourceSHAs = map[string]struct{}{
	"89d1164ac8c910e18e50fc1c3a3961977c4d4f2e": {}, // merged CLI source with reviewed observation-only identity binding
	"752e995c1fc030e139cac90e3796e69884365383": {}, // reviewed source tree with the same tree hash
}

func operationPlanCLISourceAllowed(sourceSHA string) bool {
	if len(sourceSHA) != 40 {
		return false
	}
	_, ok := operationPlanAllowedCLISourceSHAs[strings.ToLower(sourceSHA)]
	return ok
}

var errOperationPlanPathUnavailable = errors.New("operation-plan runtime path is unavailable")

type operationPlanControl struct {
	legacyConfig health.CanaryConfig
	scheduler    *health.OperationPlanScheduler
	required     bool
	legacySafe   bool
	failure      string
	status       health.OperationPlanSchedulerStatus
}

func loadOperationPlanControl(configPath string, config health.CanaryConfig, legacyRunner health.CLIProcess) operationPlanControl {
	control := operationPlanControl{
		legacyConfig: config,
		legacySafe:   true,
		status: health.OperationPlanSchedulerStatus{
			SchemaVersion: "datapan.health-operation-plan-scheduler-status.v1",
			State:         "disabled", Ready: false, Reason: "activation_not_configured",
		},
	}
	activationPath := strings.TrimSpace(os.Getenv("HEALTH_OPERATION_GATUS_ACTIVATION"))
	activationSHA := strings.TrimSpace(os.Getenv("HEALTH_OPERATION_GATUS_ACTIVATION_SHA256"))
	if activationPath == "" && activationSHA == "" {
		return control
	}
	control.required = true
	control.legacySafe = false
	if activationPath == "" || activationSHA == "" {
		return control.fail("activation_pin_unavailable")
	}

	paths, err := operationPlanRuntimePaths(configPath, activationPath, activationSHA)
	if err != nil {
		return control.fail("runtime_inputs_unavailable")
	}
	verifiedRuntime, err := health.LoadVerifiedOperationPlanRuntime(paths)
	if err != nil {
		return control.fail("runtime_binding_unavailable")
	}
	control.status = operationPlanRuntimeStatus(verifiedRuntime, "cli_artifact_unavailable")
	filtered, err := filterSuppressedLegacyCanaries(config, verifiedRuntime.SuppressedLegacy)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "legacy_overlap_binding_invalid")
	}
	control.legacyConfig = filtered
	control.legacySafe = true

	lockPath := strings.TrimSpace(os.Getenv("RUNTIME_DEPENDENCY_LOCK"))
	lock, err := runtimebundle.ReadLock(lockPath)
	if err != nil || !operationPlanCLISourceAllowed(lock.CLI.SourceSHA) || legacyRunner.Path == "" || !filepath.IsAbs(legacyRunner.Path) {
		return control.failRuntime(verifiedRuntime, "cli_artifact_unavailable")
	}
	if runtimebundle.VerifyLocal(lock, runtime.GOARCH, filepath.Dir(legacyRunner.Path)) != nil {
		return control.failRuntime(verifiedRuntime, "cli_artifact_unavailable")
	}
	if len(verifiedRuntime.ActiveTargets) == 0 {
		control.status = operationPlanRuntimeStatus(verifiedRuntime, "zero_admitted_operations")
		return control
	}

	maxHistoryBytes, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("HEALTH_OPERATION_HISTORY_MAX_BYTES")), 10, 64)
	if err != nil || maxHistoryBytes <= 0 {
		return control.failRuntime(verifiedRuntime, "history_capacity_unconfigured")
	}
	planBinding, err := health.LoadOperationObservationPlanRuntimePin(paths.PlanPinPath)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "plan_index_unavailable")
	}
	indexPath := filepath.Join(paths.PlanRoot, filepath.FromSlash(planBinding.IndexPath))
	credentialBindings := strings.TrimSpace(os.Getenv("HEALTH_OPERATION_CREDENTIAL_BINDINGS"))
	receiptDirectory := absolutePathOrEmpty(os.Getenv("HEALTH_OPERATION_RECEIPT_DIRECTORY"), "data/operation-receipts")
	if credentialBindings == "" {
		return control.failRuntime(verifiedRuntime, "credential_binding_unavailable")
	}
	credentialBindings, err = filepath.Abs(credentialBindings)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "credential_binding_unavailable")
	}
	receiptDirectory, err = filepath.Abs(receiptDirectory)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "receipt_storage_unavailable")
	}
	probeConfig, err := health.OperationPlanProbeConfigFromRuntimeLock(lock, runtime.GOARCH, legacyRunner.Path, indexPath, credentialBindings, receiptDirectory, append(envList("CLI_RUNTIME_ENV"), envList("CLI_CREDENTIAL_ENV")...))
	if err != nil {
		return control.failRuntime(verifiedRuntime, "cli_artifact_unavailable")
	}
	probeRunner, err := health.NewOperationPlanProbeRunner(probeConfig)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "cli_artifact_unavailable")
	}

	validatorRevision := strings.ToLower(strings.TrimSpace(healthBuildRevision))
	validator, err := health.NewPinnedOperationPlanProbeExpectationResolver(verifiedRuntime.Plan, lock, runtime.GOARCH)
	if err != nil || len(validatorRevision) != 40 {
		return control.failRuntime(verifiedRuntime, "receipt_validator_unavailable")
	}
	historyValidator, err := health.NewOperationPlanProbeHistoryValidator(validatorRevision, validator)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "receipt_validator_unavailable")
	}

	attemptRoot := absolutePathOrEmpty(os.Getenv("HEALTH_OPERATION_ATTEMPT_STATE"), "data/operation-attempts")
	quotaRoot := absolutePathOrEmpty(os.Getenv("HEALTH_OPERATION_QUOTA_STATE"), "data/operation-quotas")
	historyRoot := absolutePathOrEmpty(os.Getenv("HEALTH_OPERATION_HISTORY_STATE"), "data/operation-history")
	for _, root := range []*string{&attemptRoot, &quotaRoot, &historyRoot} {
		*root, err = filepath.Abs(*root)
		if err != nil {
			return control.failRuntime(verifiedRuntime, "state_storage_unavailable")
		}
	}
	attempts, err := health.OpenOperationAttemptStore(attemptRoot)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "state_storage_unavailable")
	}
	quotas, err := health.OpenOperationQuotaAuthority(quotaRoot)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "quota_storage_unavailable")
	}
	history, err := health.OpenOperationHistoryStore(historyRoot, maxHistoryBytes, historyValidator)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "history_storage_unavailable")
	}
	gatus, err := health.NewOperationPlanGatusDelivery(os.Getenv("GATUS_URL"), os.Getenv("GATUS_TOKEN"), 3*time.Second)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "delivery_configuration_unavailable")
	}
	worker, err := health.NewOperationPlanWorker(health.OperationPlanWorkerConfig{
		Runtime: verifiedRuntime, Runner: probeRunner, Attempts: attempts, Quotas: quotas,
		History: history, HistoryValidator: historyValidator, Gatus: gatus,
		RuntimeLock: lock, Architecture: runtime.GOARCH,
		AttemptLease: time.Minute, QuotaLease: time.Minute,
	})
	if err != nil {
		return control.failRuntime(verifiedRuntime, "worker_unavailable")
	}
	maxConcurrent, err := operationPlanBoundedIntEnv("HEALTH_OPERATION_MAX_CONCURRENT", 1, 1, 32)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "worker_capacity_unconfigured")
	}
	maxStarts, err := operationPlanBoundedIntEnv("HEALTH_OPERATION_MAX_STARTS_PER_SECOND", 1, 1, maxConcurrent)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "worker_capacity_unconfigured")
	}
	maxDeliveries, err := operationPlanBoundedIntEnv("HEALTH_OPERATION_MAX_DELIVERIES_PER_SECOND", 1, 1, maxConcurrent)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "worker_capacity_unconfigured")
	}
	scanBudget, err := operationPlanBoundedIntEnv("HEALTH_OPERATION_CANDIDATE_SCAN_PER_SECOND", 256, 1, 256)
	if err != nil {
		return control.failRuntime(verifiedRuntime, "worker_capacity_unconfigured")
	}
	scheduler, err := health.NewOperationPlanScheduler(health.OperationPlanSchedulerConfig{
		Worker: worker, MaxConcurrent: maxConcurrent, MaxStartsPerPass: maxStarts,
		MaxDeliveriesPerPass: maxDeliveries, CandidateScanPerPass: scanBudget, DeliveryLease: time.Minute,
	})
	if err != nil {
		return control.failRuntime(verifiedRuntime, "worker_unavailable")
	}
	control.scheduler = scheduler
	control.status = scheduler.Status(time.Time{})
	return control
}

func (control operationPlanControl) fail(reason string) operationPlanControl {
	control.failure = reason
	control.status.State = "degraded"
	control.status.Ready = false
	control.status.Reason = reason
	return control
}

func (control operationPlanControl) failRuntime(runtime *health.VerifiedOperationPlanRuntime, reason string) operationPlanControl {
	control = control.fail(reason)
	if runtime != nil {
		control.status = operationPlanRuntimeStatus(runtime, reason)
		control.failure = reason
	}
	return control
}

func (control operationPlanControl) currentStatus(at time.Time) health.OperationPlanSchedulerStatus {
	if control.scheduler != nil {
		return control.scheduler.Status(at)
	}
	return control.status
}

func operationPlanRuntimeStatus(runtime *health.VerifiedOperationPlanRuntime, reason string) health.OperationPlanSchedulerStatus {
	status := health.OperationPlanSchedulerStatus{
		SchemaVersion: "datapan.health-operation-plan-scheduler-status.v1",
		State:         "degraded", Ready: false, Reason: reason,
	}
	if runtime != nil {
		status.RegistryRevision = runtime.Plan.RegistryRevision()
		status.ReleaseManifestSHA256 = runtime.IdentityMapping.ReleaseManifestSHA256
		status.IndexSHA256 = runtime.Plan.IndexSHA256()
		status.ActivationSHA256 = runtime.IdentityMapping.ActivationSHA256
		status.CanaryConfigSHA256 = runtime.IdentityMapping.CanaryConfigSHA256
		status.IdentityMappingSHA256 = runtime.Artifacts.MappingSHA256
		status.RuntimePinSHA256 = runtime.Artifacts.RuntimePinSHA256
		status.SuppressedLegacyCanaries = append([]string(nil), runtime.SuppressedLegacy...)
		sort.Strings(status.SuppressedLegacyCanaries)
		status.KnownOperations = runtime.Plan.Counts().KnownOperations
		status.AdmittedOperations = len(runtime.ActiveTargets)
	}
	return status
}

func operationPlanRuntimePaths(configPath, activationPath, activationSHA string) (health.OperationPlanRuntimePaths, error) {
	absolute := func(value string) (string, error) {
		if strings.TrimSpace(value) == "" {
			return "", errOperationPlanPathUnavailable
		}
		return filepath.Abs(value)
	}
	planRoot, err := absolute(os.Getenv("REGISTRY_OPERATION_PLAN_ROOT"))
	if err != nil {
		return health.OperationPlanRuntimePaths{}, err
	}
	planPin, err := absolute(os.Getenv("REGISTRY_OPERATION_PLAN_PIN"))
	if err != nil {
		return health.OperationPlanRuntimePaths{}, err
	}
	canaryPath, err := absolute(configPath)
	if err != nil {
		return health.OperationPlanRuntimePaths{}, err
	}
	metadataPath, err := absolute(env("REGISTRY_API_METADATA", "config/registry/api-metadata.v1.json"))
	if err != nil {
		return health.OperationPlanRuntimePaths{}, err
	}
	metadataPin, err := absolute(env("REGISTRY_API_METADATA_PIN", "config/registry/api-metadata-source-pin.v1.json"))
	if err != nil {
		return health.OperationPlanRuntimePaths{}, err
	}
	baseConfig, err := absolute(env("HEALTH_GATUS_BASE_CONFIG", "config/gatus.yaml"))
	if err != nil {
		return health.OperationPlanRuntimePaths{}, err
	}
	generatedConfig, err := absolute(os.Getenv("HEALTH_GATUS_GENERATED_CONFIG"))
	if err != nil {
		return health.OperationPlanRuntimePaths{}, err
	}
	identityMapping, err := absolute(os.Getenv("HEALTH_GATUS_IDENTITY_MAPPING"))
	if err != nil {
		return health.OperationPlanRuntimePaths{}, err
	}
	runtimePin, err := absolute(os.Getenv("HEALTH_GATUS_RUNTIME_PIN"))
	if err != nil {
		return health.OperationPlanRuntimePaths{}, err
	}
	activationPath, err = absolute(activationPath)
	if err != nil {
		return health.OperationPlanRuntimePaths{}, err
	}
	return health.OperationPlanRuntimePaths{
		PlanRoot: planRoot, PlanPinPath: planPin, CanaryConfigPath: canaryPath,
		RegistryMetadataPath: metadataPath, RegistryMetadataPin: metadataPin,
		BaseGatusConfigPath: baseConfig, GeneratedConfigPath: generatedConfig,
		IdentityMappingPath: identityMapping, RuntimePinPath: runtimePin,
		ActivationPath: activationPath, ActivationSHA256: activationSHA,
	}, nil
}

func filterSuppressedLegacyCanaries(config health.CanaryConfig, suppressed []string) (health.CanaryConfig, error) {
	if len(suppressed) == 0 {
		return config, nil
	}
	selected := make(map[string]struct{}, len(suppressed))
	for _, operationID := range suppressed {
		if operationID == "" {
			return health.CanaryConfig{}, errOperationPlanPathUnavailable
		}
		if _, exists := selected[operationID]; exists {
			return health.CanaryConfig{}, errOperationPlanPathUnavailable
		}
		selected[operationID] = struct{}{}
	}
	filtered := config
	filtered.Canaries = make([]health.Canary, 0, len(config.Canaries))
	for _, canary := range config.Canaries {
		if _, suppress := selected[canary.OperationID]; suppress {
			delete(selected, canary.OperationID)
			continue
		}
		filtered.Canaries = append(filtered.Canaries, canary)
	}
	if len(selected) != 0 {
		return health.CanaryConfig{}, errOperationPlanPathUnavailable
	}
	return filtered, nil
}

func operationPlanBoundedIntEnv(name string, fallback, minimum, maximum int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, errOperationPlanPathUnavailable
	}
	return parsed, nil
}

func absolutePathOrEmpty(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		value = fallback
	}
	return value
}
