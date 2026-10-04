// This offline smoke executable is built explicitly and never shipped in the
// runtime image. It creates synthetic evidence and has no network implementation.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/StatPan/datapan-health/internal/health"
	"os"
	"time"
)

func main() {
	values := map[string]string{}
	for i := 1; i+1 < len(os.Args); i++ {
		if os.Args[i] == "--output" || os.Args[i] == "--operation" || os.Args[i] == "--ref" {
			values[os.Args[i]] = os.Args[i+1]
		}
	}
	cfg, err := health.LoadCanaryConfig(os.Getenv("CANARY_CONFIG"))
	if err != nil {
		os.Exit(2)
	}
	modeBytes, _ := os.ReadFile(os.Getenv("SMOKE_CONTROL_FILE"))
	mode := string(modeBytes)
	if mode == "no_receipt" {
		os.Exit(1)
	}
	for _, canary := range cfg.Canaries {
		e, _ := cfg.Entry(canary)
		if e.Aliases.DatasetID != values["--ref"] || e.Aliases.OperationName != values["--operation"] {
			continue
		}
		var id [16]byte
		_, _ = rand.Read(id[:])
		id[6] = id[6]&15 | 64
		id[8] = id[8]&63 | 128
		p := cfg.ConsumptionProvenance
		r := health.Receipt{SchemaVersion: health.SchemaVersion, ProbeID: fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", id[:4], id[4:6], id[6:8], id[8:10], id[10:]), ObservedAt: time.Now().UTC(), Operation: health.Operation{OperationKey: e.Aliases.CLIOperationKey, DatasetID: e.Aliases.DatasetID, OperationName: e.Aliases.OperationName, Provider: e.Provider, EndpointHost: e.Endpoint.Host, EndpointPath: e.Endpoint.Path, DependencyClass: e.Endpoint.DependencyClass}, Registry: health.Registry{DatasetID: e.Aliases.DatasetID, DatasetRevision: p.RegistryDatasetRevision, RegistrySHA256: p.SourceRegistrySHA256, ManifestSHA256: p.ReleaseManifestSHA256}, Policy: &health.Policy{Key: e.Policy.Key, Version: e.Policy.Version, Authority: e.Policy.Authority, MaxLevel: e.Policy.MaxLevel}, Execution: health.Execution{CLIVersion: "offline-smoke-fixture", Attempted: true, TimeoutMS: int64(e.Execution.TimeoutCeilingMS), RequestBudget: e.Execution.RequestBudget}, Observation: health.Observation{MaxLevel: e.Policy.MaxLevel, LatencyMS: 1, ProviderMessageClass: "normal", DataPresence: "present", SchemaStatus: "not_observed", FreshnessStatus: "not_observed"}, Assessment: health.Assessment{Outcome: "healthy", Category: "healthy", ReasonCode: "verification_succeeded"}, Redaction: health.Redaction{CredentialsRemoved: true, QueryValuesRemoved: true, ResponseRowsRemoved: true}}
		for _, param := range e.Execution.SafeParameters {
			r.Execution.SafeParameterNames = append(r.Execution.SafeParameterNames, param.Name)
		}
		if mode == "provider_timeout" {
			r.Observation.MaxLevel = "L0"
			r.Observation.DataPresence = "not_observed"
			r.Assessment = health.Assessment{Outcome: "unhealthy", Category: "timeout", ReasonCode: "timeout", Retryable: true}
		}
		if mode == "bad_registry" {
			r.Registry.DatasetRevision = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}
		raw, _ := json.Marshal(r)
		if os.WriteFile(values["--output"], raw, 0600) != nil {
			os.Exit(2)
		}
		return
	}
	os.Exit(2)
}
