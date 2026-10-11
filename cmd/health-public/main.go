package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
)

func main() {
	listen := flag.String("listen", env("PUBLIC_STATUS_LISTEN", ":8082"), "private listener for the public status adapter")
	gatusStatusURL := flag.String("gatus-status-url", env("GATUS_STATUS_URL", "http://gatus:8080/api/v1/endpoints/statuses"), "private Gatus summary URL")
	selfReadinessURL := flag.String("self-readiness-url", env("HEALTH_SELF_READINESS_URL", "http://scheduler:8081/status"), "private Health scheduler aggregate readiness URL")
	canaryPath := flag.String("canaries", env("CANARY_CONFIG", "config/canaries.json"), "reviewed public canary identity map")
	registryMetadataPath := flag.String("registry-api-metadata", env("REGISTRY_API_METADATA", "/opt/datapan-health/config/registry/api-metadata.v1.json"), "pinned Registry API purpose and inventory metadata")
	registryMetadataPinPath := flag.String("registry-api-metadata-pin", env("REGISTRY_API_METADATA_PIN", "/opt/datapan-health/config/registry/api-metadata-source-pin.v1.json"), "pinned Registry API metadata source and artifact identity")
	operationDisplayPath := flag.String("operation-display-metadata", env("PUBLIC_OPERATION_DISPLAY_METADATA", "/opt/datapan-health/config/registry/operator-operation-display.v1.json"), "hash-pinned Korean display labels and Registry source-document facts for partial scopes")
	operationDisplayEvidenceRoot := flag.String("operation-display-evidence-root", env("PUBLIC_OPERATION_DISPLAY_EVIDENCE_ROOT", "/opt/datapan-health/config/registry/operation-display-registry-760"), "manifest-bound Registry document-evidence subset used for partial-scope metadata")
	diagnosisPath := flag.String("diagnosis-snapshot", env("PUBLIC_DIAGNOSIS_SNAPSHOT", "data/public-diagnosis-snapshot.json"), "atomic reviewed diagnosis snapshot")
	assertionPinPath := flag.String("assertion-pin", env("ASSERTION_POLICY_PIN", "config/registry/assertion-policy-contract-pin.json"), "exact assertion policy contract")
	operationPlanRoot := flag.String("operation-plan-root", os.Getenv("REGISTRY_OPERATION_PLAN_ROOT"), "installed pinned Registry operation-plan release root")
	operationPlanPinPath := flag.String("operation-plan-pin", os.Getenv("REGISTRY_OPERATION_PLAN_PIN"), "image-owned Registry operation-plan binding")
	operationAttemptStorePath := flag.String("operation-attempt-store", os.Getenv("HEALTH_OPERATION_ATTEMPT_STATE"), "read-only shared durable operation-attempt store")
	operationReadMaxAge := flag.Duration("operation-read-max-age", envDuration("HEALTH_OPERATION_READ_MAX_AGE", 5*time.Minute), "maximum age for a complete operation read-model snapshot")
	operationBatchInterval := flag.Duration("operation-refresh-batch-interval", envDuration("HEALTH_OPERATION_REFRESH_BATCH_INTERVAL", time.Second), "delay between bounded read-model identity batches")
	operationFullRefreshInterval := flag.Duration("operation-full-refresh-interval", envDuration("HEALTH_OPERATION_FULL_REFRESH_INTERVAL", time.Minute), "delay after each complete full-inventory read-model refresh")
	scheduleCoverageState := flag.String("schedule-coverage-state", os.Getenv("SCHEDULE_COVERAGE_STATE"), "private durable full-population schedule coverage authority state")
	scheduleCoverageMaxAge := flag.Duration("schedule-coverage-max-age", 20*time.Minute, "maximum accepted age for schedule coverage receipt in doctor mode")
	scheduleCoverageReferenceAt := flag.String("schedule-coverage-reference-at", "", "optional RFC3339 doctor reference time")
	originList := flag.String("allowed-origins", os.Getenv("PUBLIC_STATUS_ALLOWED_ORIGINS"), "comma-separated exact HTTPS browser origins")
	readRate := flag.Int("read-rate", envInt("PUBLIC_STATUS_READ_RATE", 20), "global read requests per second")
	readBurst := flag.Int("read-burst", envInt("PUBLIC_STATUS_READ_BURST", 40), "global read burst")
	readConcurrent := flag.Int("read-concurrent", envInt("PUBLIC_STATUS_READ_CONCURRENT", 16), "maximum concurrent reads")
	doctor := flag.Bool("doctor", false, "print value-free service/dependency readiness report and exit")
	flag.Parse()

	canaries, err := health.LoadCanaryConfig(*canaryPath)
	if err != nil {
		fatalAt(startupStageCanaryConfig)
	}
	if *doctor {
		reference := time.Now().UTC()
		if *scheduleCoverageReferenceAt != "" {
			parsed, parseErr := time.Parse(time.RFC3339, *scheduleCoverageReferenceAt)
			if parseErr != nil {
				fatalAt(startupStageDoctorReference)
			}
			reference = parsed.UTC()
		}
		schedule := health.ReadScheduleCoverageDoctorReport(*scheduleCoverageState, reference, *scheduleCoverageMaxAge)
		report, err := health.BuildPublicStatusDoctorReportWithSchedule(context.Background(), health.DefaultOwnedServiceStatusSource(), len(canaries.Canaries), schedule)
		if err != nil || json.NewEncoder(os.Stdout).Encode(report) != nil {
			fatalAt(startupStageDoctorReport)
		}
		return
	}
	registryMetadata, err := health.LoadRegistryAPIMetadata(*registryMetadataPath, *registryMetadataPinPath, canaries)
	if err != nil {
		fatalAt(startupStageRegistryMetadata)
	}
	operationDisplay, err := health.LoadPublicOperationDisplayMetadata(*operationDisplayPath, *operationDisplayEvidenceRoot)
	if err != nil {
		fatalAt(startupStageDisplayMetadata)
	}
	source, err := health.NewGatusPublicStatusSource(*gatusStatusURL, canaries, 5*time.Second)
	if err != nil {
		fatalAt(startupStageGatusAdapter)
	}
	assertionContract, err := health.LoadAssertionPolicyContract(*assertionPinPath, canaries)
	if err != nil {
		fatalAt(startupStageAssertionContract)
	}
	publicSource, err := health.NewDiagnosisOverlaySource(source, *diagnosisPath, assertionContract)
	if err != nil {
		fatalAt(startupStageDiagnosisOverlay)
	}
	origins := splitOrigins(*originList)
	cachedSource, err := health.NewCachedPublicStatusSource(publicSource, 5*time.Second, 5*time.Second)
	if err != nil {
		fatalAt(startupStagePublicStatusCache)
	}
	operationPlanBinding, err := operationPlanSelfReadinessBinding(*canaryPath, *registryMetadataPath, *registryMetadataPinPath, *operationPlanRoot, *operationPlanPinPath)
	if err != nil {
		fatalAt(startupStageSelfReadiness)
	}
	readinessSource, err := health.NewSchedulerHealthSelfReadinessSourceWithOperationPlanBinding(*selfReadinessURL, canaries, time.Second, operationPlanBinding)
	if err != nil {
		fatalAt(startupStageSelfReadiness)
	}
	cachedReadiness, err := health.NewCachedHealthSelfReadinessSource(readinessSource, time.Second, time.Second)
	if err != nil {
		fatalAt(startupStageSelfReadiness)
	}
	var operationSource health.PublicRegistryOperationsSource
	operationConfigured, operationConfigValid := operationReadModelConfiguration(*operationPlanRoot, *operationPlanPinPath, *operationAttemptStorePath)
	if !operationConfigured {
		log.Print("Registry operation read model unavailable: pinned plan and shared state are not configured")
	} else if !operationConfigValid {
		log.Print("Registry operation read model unavailable: configuration is incomplete")
	} else {
		verifiedMetadata, metadataErr := health.NewVerifiedRegistryAPIMetadata(registryMetadata)
		policy := health.OperationReadModelRefreshPolicy{
			BatchSize: 256, BatchInterval: *operationBatchInterval,
			FullRefreshInterval: *operationFullRefreshInterval, MaxPassDuration: 2 * time.Minute,
		}
		if health.ValidateOperationReadModelRefreshPolicy(policy) != nil {
			fatalAt(startupStageReadModel)
		}
		if *operationReadMaxAge < time.Minute || *operationReadMaxAge > 24*time.Hour {
			fatalAt(startupStageReadModel)
		}
		if metadataErr != nil {
			log.Print("Registry operation read model unavailable: verified metadata is unavailable")
		} else {
			operationRuntime, runtimeErr := health.LoadOperationReadModelRuntime(*operationPlanRoot, *operationPlanPinPath, *operationAttemptStorePath, verifiedMetadata, *operationReadMaxAge, time.Now().UTC())
			if runtimeErr != nil {
				log.Print("Registry operation read model unavailable: pinned plan or shared state is unavailable")
			} else {
				operationSource = operationRuntime
				runtimeContext, cancelRuntime := context.WithCancel(context.Background())
				defer cancelRuntime()
				go func() { _ = operationRuntime.Run(runtimeContext, policy) }()
			}
		}
	}
	handler, err := health.NewPublicStatusHandlerWithOperationDisplay(cachedSource, origins, registryMetadata, cachedReadiness, operationSource, operationDisplay)
	if err != nil {
		fatalAt(startupStagePublicHandler)
	}

	guard, err := health.NewPublicReadGuard(handler, health.PublicReadLimits{RequestsPerSecond: *readRate, Burst: *readBurst, MaxConcurrent: *readConcurrent})
	if err != nil {
		fatalAt(startupStageReadGuard)
	}
	server := &http.Server{Addr: *listen, Handler: guard, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatalAt(startupStageListener)
	}
}

type publicStartupFailureStage string

const (
	startupStageCanaryConfig      publicStartupFailureStage = "canary_config"
	startupStageDoctorReference   publicStartupFailureStage = "doctor_reference"
	startupStageDoctorReport      publicStartupFailureStage = "doctor_report"
	startupStageRegistryMetadata  publicStartupFailureStage = "registry_metadata"
	startupStageDisplayMetadata   publicStartupFailureStage = "display_metadata"
	startupStageGatusAdapter      publicStartupFailureStage = "gatus_adapter"
	startupStageAssertionContract publicStartupFailureStage = "assertion_contract"
	startupStageDiagnosisOverlay  publicStartupFailureStage = "diagnosis_overlay"
	startupStagePublicStatusCache publicStartupFailureStage = "public_status_cache"
	startupStageSelfReadiness     publicStartupFailureStage = "self_readiness"
	startupStageReadModel         publicStartupFailureStage = "read_model"
	startupStagePublicHandler     publicStartupFailureStage = "public_handler"
	startupStageReadGuard         publicStartupFailureStage = "read_guard"
	startupStageListener          publicStartupFailureStage = "listener"
	startupStageConfiguration     publicStartupFailureStage = "configuration"
)

func splitOrigins(value string) []string {
	parts := strings.Split(value, ",")
	origins := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			origins = append(origins, trimmed)
		}
	}
	return origins
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func fatalAt(stage publicStartupFailureStage) {
	switch stage {
	case startupStageCanaryConfig, startupStageDoctorReference, startupStageDoctorReport,
		startupStageRegistryMetadata, startupStageDisplayMetadata, startupStageGatusAdapter,
		startupStageAssertionContract, startupStageDiagnosisOverlay, startupStagePublicStatusCache,
		startupStageSelfReadiness, startupStageReadModel, startupStagePublicHandler,
		startupStageReadGuard, startupStageListener, startupStageConfiguration:
	default:
		stage = startupStageConfiguration
	}
	fmt.Fprintf(os.Stderr, "public status service failed at stage=%s\n", stage)
	os.Exit(1)
}

func envInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		fatalAt(startupStageConfiguration)
	}
	return value
}

func envDuration(key string, fallback time.Duration) time.Duration {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		fatalAt(startupStageConfiguration)
	}
	return value
}

func operationReadModelConfiguration(planRoot, planPinPath, attemptStorePath string) (configured, valid bool) {
	values := []string{planRoot, planPinPath, attemptStorePath}
	configuredCount := 0
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			configuredCount++
		}
	}
	if configuredCount == 0 {
		return false, true
	}
	return true, configuredCount == len(values)
}

func operationPlanSelfReadinessBinding(canaryPath, metadataPath, metadataPinPath, planRoot, planPinPath string) (*health.OperationPlanReadinessBinding, error) {
	activationPath := strings.TrimSpace(os.Getenv("HEALTH_OPERATION_GATUS_ACTIVATION"))
	activationSHA := strings.TrimSpace(os.Getenv("HEALTH_OPERATION_GATUS_ACTIVATION_SHA256"))
	if activationPath == "" && activationSHA == "" {
		return nil, nil
	}
	if activationPath == "" || activationSHA == "" {
		return nil, fmt.Errorf("operation-plan activation pin is incomplete")
	}
	absolute := func(value string) (string, error) {
		if strings.TrimSpace(value) == "" {
			return "", fmt.Errorf("operation-plan runtime path is empty")
		}
		return filepath.Abs(value)
	}
	planRoot, err := absolute(planRoot)
	if err != nil {
		return nil, err
	}
	planPinPath, err = absolute(planPinPath)
	if err != nil {
		return nil, err
	}
	canaryPath, err = absolute(canaryPath)
	if err != nil {
		return nil, err
	}
	metadataPath, err = absolute(metadataPath)
	if err != nil {
		return nil, err
	}
	metadataPinPath, err = absolute(metadataPinPath)
	if err != nil {
		return nil, err
	}
	baseGatusPath, err := absolute(env("HEALTH_GATUS_BASE_CONFIG", "config/gatus.yaml"))
	if err != nil {
		return nil, err
	}
	generatedConfigPath, err := absolute(os.Getenv("HEALTH_GATUS_GENERATED_CONFIG"))
	if err != nil {
		return nil, err
	}
	identityMappingPath, err := absolute(os.Getenv("HEALTH_GATUS_IDENTITY_MAPPING"))
	if err != nil {
		return nil, err
	}
	runtimePinPath, err := absolute(os.Getenv("HEALTH_GATUS_RUNTIME_PIN"))
	if err != nil {
		return nil, err
	}
	activationPath, err = absolute(activationPath)
	if err != nil {
		return nil, err
	}
	paths := health.OperationPlanRuntimePaths{
		PlanRoot: planRoot, PlanPinPath: planPinPath, CanaryConfigPath: canaryPath,
		RegistryMetadataPath: metadataPath, RegistryMetadataPin: metadataPinPath,
		BaseGatusConfigPath: baseGatusPath, GeneratedConfigPath: generatedConfigPath,
		IdentityMappingPath: identityMappingPath, RuntimePinPath: runtimePinPath,
		ActivationPath: activationPath, ActivationSHA256: activationSHA,
	}
	verified, err := health.LoadVerifiedOperationPlanRuntime(paths)
	if err != nil {
		return nil, fmt.Errorf("verified operation-plan runtime is unavailable")
	}
	binding, err := health.NewOperationPlanReadinessBinding(verified)
	if err != nil {
		return nil, fmt.Errorf("verified operation-plan readiness binding is unavailable")
	}
	return binding, nil
}
