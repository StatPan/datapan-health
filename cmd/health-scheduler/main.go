package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
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
		HealthCatalogPath: env("HEALTH_PROBE_CATALOG", config.CatalogPath),
		RegistryRevision:  config.ConsumptionProvenance.RegistryDatasetRevision,
	}
	adapter := health.AdapterProcess{Path: env("HEALTH_RUNNER_BIN", "health-runner"), Env: []string{"GATUS_URL", "GATUS_TOKEN", "RECEIPT_ARCHIVE", "RECEIPT_DELIVERY_JOURNAL", "CANARY_CONFIG"}}
	coverage, err := scheduleCoverageLifecycle()
	if err != nil {
		log.Fatal("scheduler coverage configuration is not ready")
	}
	scheduler, err := health.NewSchedulerWithCoverage(config, env("SCHEDULER_STATE", "data/scheduler-state.json"), runner, adapter, coverage)
	if err != nil {
		log.Fatal("scheduler state is not ready")
	}

	preflight := func() string {
		if !health.CheckExecutable(runner.Path) {
			return "cli_unavailable"
		}
		if !health.CheckExecutable(adapter.Path) {
			return "adapter_unavailable"
		}
		if os.Getenv("GATUS_TOKEN") == "" {
			return "delivery_configuration_unavailable"
		}
		if _, err := health.LoadCatalog(runner.HealthCatalogPath, config.CatalogSHA256); err != nil {
			return "catalog_unavailable"
		}
		archive := env("RECEIPT_ARCHIVE", "data/receipts.jsonl")
		statePath := env("SCHEDULER_STATE", "data/scheduler-state.json")
		for _, path := range []string{statePath, filepath.Join(filepath.Dir(statePath), "receipt-staging", ".staging-write-check"), archive, env("RECEIPT_DELIVERY_JOURNAL", archive+".deliveries.jsonl")} {
			if !health.CheckWriteBoundary(path) {
				return "storage_unavailable"
			}
		}
		return ""
	}
	server := &http.Server{Addr: env("SCHEDULER_ADDR", ":8081"), Handler: healthSchedulerHandler(scheduler, preflight), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatal("scheduler HTTP listener unavailable")
	}
	serverFailed := make(chan struct{}, 1)
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Print("scheduler HTTP server stopped")
			serverFailed <- struct{}{}
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	runCtx, cancelRun := context.WithCancel(context.Background())
	defer cancelRun()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case now := <-ticker.C:
			if preflight() != "" {
				continue
			}
			if err := scheduler.ProcessDue(runCtx, now); err != nil {
				log.Print("scheduler state update failed")
			}
		case <-serverFailed:
			log.Fatal("scheduler HTTP server unavailable")
		case <-stop:
			cancelRun()
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

func healthSchedulerHandler(s *health.Scheduler, preflight func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch r.URL.Path {
		case "/live":
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte("ok\n"))
			}
		case "/ready", "/status":
			report := s.Readiness(time.Now().UTC())
			if reason := preflight(); reason != "" {
				report.Ready = false
				report.State = "degraded"
				report.Reason = reason
			}
			code := http.StatusOK
			if !report.Ready {
				code = http.StatusServiceUnavailable
			}
			if r.URL.Path == "/status" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(code)
				if r.Method != http.MethodHead {
					_ = json.NewEncoder(w).Encode(report)
				}
				return
			}
			w.WriteHeader(code)
			if r.Method != http.MethodHead {
				if report.Ready {
					_, _ = w.Write([]byte("ready\n"))
				} else {
					_, _ = w.Write([]byte("not ready\n"))
				}
			}
		case "/metrics":
			m := s.Metrics()
			report := s.Readiness(time.Now().UTC())
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			if r.Method == http.MethodHead {
				return
			}
			_, _ = fmt.Fprintf(w, "datapan_health_scheduler_runs_started_total %d\ndatapan_health_scheduler_runs_completed_total %d\ndatapan_health_scheduler_runs_failed_total %d\ndatapan_health_scheduler_slots_skipped_total %d\ndatapan_health_scheduler_delivery_failed_total %d\ndatapan_health_scheduler_admission_rejected_total %d\ndatapan_health_scheduler_state_failures_total %d\n", m.RunsStarted, m.RunsCompleted, m.RunsFailed, m.RunsSkippedCapacity, m.DeliveryFailed, m.AdmissionRejected, report.StateFailures)
			loop, delivered := int64(0), int64(0)
			if report.LastLoop != nil {
				loop = report.LastLoop.Unix()
			}
			if !m.LastCompleted.IsZero() {
				delivered = m.LastCompleted.Unix()
			}
			ready := 0
			if report.Ready && preflight() == "" {
				ready = 1
			}
			_, _ = fmt.Fprintf(w, "datapan_health_scheduler_ready %d\ndatapan_health_scheduler_last_loop_timestamp_seconds %d\ndatapan_health_scheduler_last_delivery_timestamp_seconds %d\n", ready, loop, delivered)
			for _, p := range report.Canaries {
				at := int64(0)
				if p.LastDelivered != nil {
					at = p.LastDelivered.Unix()
				}
				_, _ = fmt.Fprintf(w, "datapan_health_scheduler_canary_last_delivery_timestamp_seconds{operation_id=%q} %d\n", p.OperationID, at)
			}
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
