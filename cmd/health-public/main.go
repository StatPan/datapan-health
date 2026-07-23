package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
)

func main() {
	listen := flag.String("listen", env("PUBLIC_STATUS_LISTEN", ":8082"), "private listener for the public status adapter")
	gatusStatusURL := flag.String("gatus-status-url", env("GATUS_STATUS_URL", "http://gatus:8080/api/v1/endpoints/statuses"), "private Gatus summary URL")
	canaryPath := flag.String("canaries", env("CANARY_CONFIG", "config/canaries.json"), "reviewed public canary identity map")
	diagnosisPath := flag.String("diagnosis-snapshot", env("PUBLIC_DIAGNOSIS_SNAPSHOT", "data/public-diagnosis-snapshot.json"), "atomic reviewed diagnosis snapshot")
	assertionPinPath := flag.String("assertion-pin", env("ASSERTION_POLICY_PIN", "config/registry/assertion-policy-contract-pin.json"), "exact assertion policy contract")
	scheduleCoverageState := flag.String("schedule-coverage-state", os.Getenv("SCHEDULE_COVERAGE_STATE"), "private durable full-population schedule coverage authority state")
	scheduleCoverageMaxAge := flag.Duration("schedule-coverage-max-age", 20*time.Minute, "maximum accepted age for schedule coverage receipt in doctor mode")
	scheduleCoverageReferenceAt := flag.String("schedule-coverage-reference-at", "", "optional RFC3339 doctor reference time")
	originList := flag.String("allowed-origins", os.Getenv("PUBLIC_STATUS_ALLOWED_ORIGINS"), "comma-separated exact HTTPS browser origins")
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
	handler, err := health.NewPublicStatusHandler(publicSource, origins)
	if err != nil {
		fatal()
	}

	server := &http.Server{Addr: *listen, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
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
