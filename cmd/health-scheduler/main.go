package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
)

func main() {
	configPath := env("CANARY_CONFIG", "config/canaries.json")
	config, err := health.LoadCanaryConfig(configPath)
	if err != nil {
		log.Fatal("scheduler configuration is not ready")
	}
	runner := health.CLIProcess{
		Path:              env("DATAPAN_BIN", "datapan"),
		Environment:       append(envList("CLI_RUNTIME_ENV"), envList("CLI_CREDENTIAL_ENV")...),
		HealthCatalogPath: env("HEALTH_PROBE_CATALOG", "/config/registry/health-probe-catalog.json"),
		RegistryRevision:  config.ConsumptionProvenance.RegistryDatasetRevision,
	}
	adapter := health.AdapterProcess{Path: env("HEALTH_RUNNER_BIN", "health-runner"), Env: []string{"GATUS_URL", "GATUS_TOKEN", "RECEIPT_ARCHIVE", "CANARY_CONFIG"}}
	coverage, err := scheduleCoverageLifecycle()
	if err != nil {
		log.Fatal("scheduler coverage configuration is not ready")
	}
	scheduler, err := health.NewSchedulerWithCoverage(config, env("SCHEDULER_STATE", "data/scheduler-state.json"), runner, adapter, coverage)
	if err != nil {
		log.Fatal("scheduler state is not ready")
	}

	server := &http.Server{Addr: env("SCHEDULER_ADDR", ":8081"), Handler: healthSchedulerHandler(scheduler)}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Print("scheduler HTTP server stopped")
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			if err := scheduler.ProcessDue(context.Background(), now); err != nil {
				log.Print("scheduler state update failed")
			}
		case <-stop:
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_ = server.Shutdown(ctx)
			done := make(chan struct{})
			go func() { scheduler.Wait(); close(done) }()
			select {
			case <-done:
			case <-ctx.Done():
			}
			return
		}
	}
}

func healthSchedulerHandler(s *health.Scheduler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/live", "/ready":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
		case "/metrics":
			m := s.Metrics()
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = fmt.Fprintf(w, "datapan_health_scheduler_runs_started_total %d\ndatapan_health_scheduler_runs_completed_total %d\ndatapan_health_scheduler_runs_failed_total %d\ndatapan_health_scheduler_slots_skipped_total %d\ndatapan_health_scheduler_delivery_failed_total %d\n", m.RunsStarted, m.RunsCompleted, m.RunsFailed, m.RunsSkippedCapacity, m.DeliveryFailed)
		default:
			http.NotFound(w, r)
		}
	})
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
func envList(key string) []string { return strings.Split(strings.TrimSpace(os.Getenv(key)), ",") }

// scheduleCoverageLifecycle is opt-in and dry-run-only. It joins the real
// health-scheduler acceptance loop without adding a provider runner, canary
// execution mode, credential, or delivery target for full-population work.
func scheduleCoverageLifecycle() (*health.ScheduleCoverageLifecycle, error) {
	// An explicit mode declaration is a global scheduler safety gate. Validate
	// it before looking at coverage state so false/invalid cannot silently fall
	// back to legacy canary execution when SCHEDULE_COVERAGE_STATE is unset.
	dryRun := true
	if raw, declared := os.LookupEnv("SCHEDULE_COVERAGE_DRY_RUN"); declared {
		parsed, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil || !parsed {
			return nil, fmt.Errorf("schedule coverage requires dry run")
		}
		dryRun = parsed
	}
	statePath := strings.TrimSpace(os.Getenv("SCHEDULE_COVERAGE_STATE"))
	if statePath == "" {
		return nil, nil
	}
	shards, err := strconv.Atoi(env("SCHEDULE_COVERAGE_SHARDS", "64"))
	if err != nil {
		return nil, err
	}
	return health.NewScheduleCoverageLifecycle(health.ScheduleCoverageLifecycleConfig{
		StatePath:           statePath,
		ManifestPath:        strings.TrimSpace(os.Getenv("SCHEDULE_COVERAGE_MANIFEST")),
		ReleaseManifestPath: strings.TrimSpace(os.Getenv("SCHEDULE_COVERAGE_RELEASE_MANIFEST")),
		ReceiptPath:         env("SCHEDULE_COVERAGE_RECEIPT", "config/registry/operation-manifest-receipt.json"),
		ShardCount:          shards,
		DryRun:              dryRun,
	})
}
