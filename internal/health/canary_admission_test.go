package health

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiveCanaryAdmissionRejectsMismatchedEvidence(t *testing.T) {
	config := schedulerConfig(t, 1)
	entry, _ := config.Entry(config.Canaries[0])
	now := time.Now().UTC()
	base := fixtureForEntry(mustRead(t, "../../testdata/receipts/v1/healthy.json"), entry)
	cases := map[string]func(*Receipt){
		"registry_revision": func(r *Receipt) { r.Registry.DatasetRevision = strings.Repeat("a", 40) },
		"registry_source":   func(r *Receipt) { r.Registry.RegistrySHA256 = strings.Repeat("b", 64) },
		"registry_manifest": func(r *Receipt) { r.Registry.ManifestSHA256 = strings.Repeat("c", 64) },
		"registry_dataset":  func(r *Receipt) { r.Registry.DatasetID = "other" },
		"policy_absent":     func(r *Receipt) { r.Policy = nil },
		"policy_key":        func(r *Receipt) { r.Policy.Key = "dpr-op-00000002" },
		"policy_version":    func(r *Receipt) { r.Policy.Version++ },
		"policy_authority":  func(r *Receipt) { r.Policy.Authority = "other" },
		"policy_level":      func(r *Receipt) { r.Policy.MaxLevel = "L5" },
		"provider":          func(r *Receipt) { r.Operation.Provider = "other" },
		"host":              func(r *Receipt) { r.Operation.EndpointHost = "other.example" },
		"path":              func(r *Receipt) { r.Operation.EndpointPath = "/other" },
		"budget":            func(r *Receipt) { r.Execution.RequestBudget = 2 },
		"timeout":           func(r *Receipt) { r.Execution.TimeoutMS = int64(entry.Execution.TimeoutCeilingMS + 1) },
		"parameters":        func(r *Receipt) { r.Execution.SafeParameterNames = []string{"other"} },
		"stale":             func(r *Receipt) { r.ObservedAt = now.Add(-72 * time.Hour) },
		"future":            func(r *Receipt) { r.ObservedAt = now.Add(72 * time.Hour) },
		"prior_invocation":  func(r *Receipt) { r.ObservedAt = now.Add(-15 * time.Second) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			var r Receipt
			if json.Unmarshal(base, &r) != nil {
				t.Fatal("fixture decode")
			}
			r.ObservedAt = now
			mutate(&r)
			if _, err := config.AdmitReceipt(r, now, now); err == nil {
				t.Fatal("mismatch admitted")
			}
		})
	}
	for _, outcome := range []string{"healthy", "unhealthy"} {
		var r Receipt
		_ = json.Unmarshal(base, &r)
		r.ObservedAt = now.Add(-receiptClockSkew)
		r.Assessment.Outcome = outcome
		if _, err := config.AdmitReceipt(r, now, now); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCanaryConfigRejectsMountedReleaseClaimChanges(t *testing.T) {
	original := mustRead(t, "../../config/canaries.json")
	for _, field := range []string{"registry_dataset_revision", "source_registry_sha256", "release_manifest_sha256", "release_tag"} {
		t.Run(field, func(t *testing.T) {
			var config CanaryConfig
			_ = json.Unmarshal(original, &config)
			config.CatalogPath, _ = filepath.Abs("../../config/registry/health-probe-catalog.json")
			switch field {
			case "registry_dataset_revision":
				config.ConsumptionProvenance.RegistryDatasetRevision = strings.Repeat("a", 40)
			case "source_registry_sha256":
				config.ConsumptionProvenance.SourceRegistrySHA256 = strings.Repeat("a", 64)
			case "release_manifest_sha256":
				config.ConsumptionProvenance.ReleaseManifestSHA256 = strings.Repeat("a", 64)
			case "release_tag":
				config.ConsumptionProvenance.ReleaseTag = "v2026.10.04"
			}
			data, _ := json.Marshal(config)
			path := filepath.Join(t.TempDir(), "canaries.json")
			_ = os.WriteFile(path, data, 0600)
			if _, err := LoadCanaryConfig(path); err == nil {
				t.Fatal("unreviewed release promotion admitted")
			}
		})
	}
}

type staleProbeRunner struct{}

func (staleProbeRunner) Run(_ context.Context, _ Canary, entry CatalogEntry, path string) error {
	raw, err := os.ReadFile("../../testdata/receipts/v1/healthy.json")
	if err != nil {
		return err
	}
	var r Receipt
	_ = json.Unmarshal(fixtureForEntry(raw, entry), &r)
	r.ObservedAt = time.Now().Add(-72 * time.Hour)
	return writeReceipt(path, r)
}
func TestSchedulerRejectsBeforeDelivery(t *testing.T) {
	config := schedulerConfig(t, 1)
	d := &fakeDeliverer{}
	s, err := NewScheduler(config, filepath.Join(t.TempDir(), "state.json"), staleProbeRunner{}, d)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := config.Entry(config.Canaries[0])
	s.run(context.Background(), config.Canaries[0], entry)
	m := s.Metrics()
	if d.count() != 0 || m.AdmissionRejected != 1 || m.LastAdmissionReason != "stale_observation" {
		t.Fatal("rejection did not stop delivery")
	}
}
