package main

import (
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StatPan/datapan-health/internal/health"
)

func TestAdapterChild(t *testing.T) {
	if os.Getenv("HEALTH_ADAPTER_TEST_CHILD") != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet("adapter", flag.ExitOnError)
	os.Args = append([]string{"adapter"}, strings.Split(os.Getenv("HEALTH_ADAPTER_TEST_ARGS"), "\n")...)
	main()
	os.Exit(0)
}

func TestAdapterRejectsBeforeArchiveAndGatus(t *testing.T) {
	config, err := health.LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := config.Entry(config.Canaries[0])
	base, err := health.ReadReceipt("../../testdata/receipts/v1/healthy.json")
	if err != nil {
		t.Fatal(err)
	}
	base.Registry = health.Registry{DatasetID: entry.Aliases.DatasetID, DatasetRevision: config.ConsumptionProvenance.RegistryDatasetRevision, RegistrySHA256: config.ConsumptionProvenance.SourceRegistrySHA256, ManifestSHA256: config.ConsumptionProvenance.ReleaseManifestSHA256}
	base.Policy = &health.Policy{Key: entry.Policy.Key, Version: entry.Policy.Version, Authority: entry.Policy.Authority, MaxLevel: entry.Policy.MaxLevel}
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { posts.Add(1); w.WriteHeader(202) }))
	defer server.Close()
	for _, name := range []string{"registry", "policy", "stale", "future", "budget", "valid", "provider_timeout"} {
		t.Run(name, func(t *testing.T) {
			r := base
			r.ObservedAt = time.Now().UTC()
			switch name {
			case "registry":
				r.Registry.DatasetRevision = strings.Repeat("a", 40)
			case "policy":
				r.Policy = nil
			case "stale":
				r.ObservedAt = r.ObservedAt.Add(-72 * time.Hour)
			case "future":
				r.ObservedAt = r.ObservedAt.Add(72 * time.Hour)
			case "budget":
				r.Execution.RequestBudget = 2
			case "provider_timeout":
				r.Assessment.Outcome = "unhealthy"
				r.Assessment.Category = "timeout"
				r.Observation.MaxLevel = "L0"
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "receipt.json")
			archive := filepath.Join(dir, "archive.jsonl")
			raw, _ := json.Marshal(r)
			_ = os.WriteFile(path, raw, 0600)
			cfg, _ := filepath.Abs("../../config/canaries.json")
			cmd := exec.Command(os.Args[0], "-test.run=^TestAdapterChild$")
			cmd.Env = append(os.Environ(), "HEALTH_ADAPTER_TEST_CHILD=1", "HEALTH_ADAPTER_TEST_ARGS="+strings.Join([]string{"-receipt", path, "-archive", archive, "-canaries", cfg, "-gatus-url", server.URL, "-token", "synthetic-test-token"}, "\n"))
			before := posts.Load()
			output, err := cmd.CombinedOutput()
			valid := name == "valid" || name == "provider_timeout"
			if valid {
				if err != nil || posts.Load() != before+1 {
					t.Fatalf("valid receipt failed: %s", output)
				}
			} else {
				if err == nil || posts.Load() != before {
					t.Fatal("rejection reached Gatus")
				}
				if _, err := os.Stat(archive); !os.IsNotExist(err) {
					t.Fatal("rejection reached archive")
				}
				if strings.Contains(string(output), "synthetic-test-token") || strings.Contains(string(output), entry.Endpoint.Host) {
					t.Fatal("unsafe rejection output")
				}
			}
		})
	}
}
