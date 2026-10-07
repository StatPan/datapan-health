package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
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
	diagnosisPath := flag.String("diagnosis-snapshot", env("PUBLIC_DIAGNOSIS_SNAPSHOT", "data/public-diagnosis-snapshot.json"), "atomic reviewed diagnosis snapshot")
	assertionPinPath := flag.String("assertion-pin", env("ASSERTION_POLICY_PIN", "config/registry/assertion-policy-contract-pin.json"), "exact assertion policy contract")
	operationPlanRoot := flag.String("operation-plan-root", env("REGISTRY_OPERATION_PLAN_ROOT", "/opt/datapan-cli/.datapan/release"), "installed pinned Registry operation-plan release root")
	operationPlanPinPath := flag.String("operation-plan-pin", env("REGISTRY_OPERATION_PLAN_PIN", "/opt/datapan-cli/.datapan/release/operation-observation-plan-runtime-pin.v1.json"), "image-owned Registry operation-plan binding")
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
		fatal()
	}
	if *doctor {
		reference := time.Now().UTC()
		if *scheduleCoverageReferenceAt != "" {
			parsed, parseErr := time.Parse(time.RFC3339, *scheduleCoverageReferenceAt)
			if parseErr != nil {
				fatal()
			}
			reference = parsed.UTC()
		}
		schedule := health.ReadScheduleCoverageDoctorReport(*scheduleCoverageState, reference, *scheduleCoverageMaxAge)
		report, err := health.BuildPublicStatusDoctorReportWithSchedule(context.Background(), health.DefaultOwnedServiceStatusSource(), len(canaries.Canaries), schedule)
		if err != nil || json.NewEncoder(os.Stdout).Encode(report) != nil {
			fatal()
		}
		return
	}
	registryMetadata, err := health.LoadRegistryAPIMetadata(*registryMetadataPath, *registryMetadataPinPath, canaries)
	if err != nil {
		fatal()
	}
	source, err := health.NewGatusPublicStatusSource(*gatusStatusURL, canaries, 5*time.Second)
	if err != nil {
		fatal()
	}
	assertionContract, err := health.LoadAssertionPolicyContract(*assertionPinPath, canaries)
	if err != nil {
		fatal()
	}
	publicSource, err := health.NewDiagnosisOverlaySource(source, *diagnosisPath, assertionContract)
	if err != nil {
		fatal()
	}
	origins := splitOrigins(*originList)
	cachedSource, err := health.NewCachedPublicStatusSource(publicSource, 5*time.Second, 5*time.Second)
	if err != nil {
		fatal()
	}
	readinessSource, err := health.NewSchedulerHealthSelfReadinessSource(*selfReadinessURL, canaries, time.Second)
	if err != nil {
		fatal()
	}
	cachedReadiness, err := health.NewCachedHealthSelfReadinessSource(readinessSource, time.Second, time.Second)
	if err != nil {
		fatal()
	}
	var operationSource health.PublicRegistryOperationsSource
	verifiedMetadata, metadataErr := health.NewVerifiedRegistryAPIMetadata(registryMetadata)
	if strings.TrimSpace(*operationAttemptStorePath) != "" {
		policy := health.OperationReadModelRefreshPolicy{
			BatchSize: 256, BatchInterval: *operationBatchInterval,
			FullRefreshInterval: *operationFullRefreshInterval, MaxPassDuration: 2 * time.Minute,
		}
		if health.ValidateOperationReadModelRefreshPolicy(policy) != nil {
			fatal()
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
	handler, err := health.NewPublicStatusHandlerWithRegistryOperations(cachedSource, origins, registryMetadata, cachedReadiness, operationSource)
	if err != nil {
		fatal()
	}

	guard, err := health.NewPublicReadGuard(handler, health.PublicReadLimits{RequestsPerSecond: *readRate, Burst: *readBurst, MaxConcurrent: *readConcurrent})
	if err != nil {
		fatal()
	}
	server := &http.Server{Addr: *listen, Handler: guard, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatal()
	}
}

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

func fatal() {
	fmt.Fprintln(os.Stderr, "public status service failed")
	os.Exit(1)
}

func envInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		fatal()
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
		fatal()
	}
	return value
}
