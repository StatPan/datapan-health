package health

import (
	"errors"
	"time"
)

// These pins are compiled into the reviewed consumer image. A mutable mounted
// configuration cannot promote a Registry release by changing its claims.
// Promotion requires review of Registry release evidence and a new image.
const acceptedCanaryCatalogSHA256 = "e84f0da2f532a32833def1118a4610bf2322f370783d120b84cf85306d244840"

func acceptedCanaryProvenance() ConsumptionProvenance {
	return ConsumptionProvenance{
		RegistryDatasetRevision: "10f375182f992bc700468dd9d6e2930acd3bf8e8",
		SourceRegistrySHA256:    "eeda72ee8590f458de8d75703662578e80edf3e61282f0e5e67547c4f6e5f644",
		ReleaseTag:              "v2026.07.14",
		ReleaseManifestSHA256:   "0b78c286b8cfa889ddccf51f83a9d8adc4eac8617ea6d9fd2d66d1fcf668281f",
	}
}

const (
	receiptMaxAge    = time.Minute
	receiptClockSkew = 5 * time.Second
)

// AdmissionError exposes only a bounded reason; receipt values never enter logs.
type AdmissionError string

func (e AdmissionError) Error() string { return "canary admission rejected: " + string(e) }

// AdmitScheduledReceipt also binds a child's result to the exact canary that
// launched it. Admission to the catalog alone cannot prove invocation identity.
func (c CanaryConfig) AdmitScheduledReceipt(r Receipt, expected Canary, now, started time.Time) (string, error) {
	actual, err := c.CanaryFor(r)
	if err != nil || actual.OperationID != expected.OperationID || actual.GatusEndpointKey != expected.GatusEndpointKey {
		return "", AdmissionError("scheduled_identity")
	}
	return c.AdmitReceipt(r, now, started)
}

// AdmitReceipt is the only live canary admission boundary, shared by scheduler
// and adapter. Historical schema decoding and archive identity mapping remain
// separate; neither grants permission to publish a current observation.
// started is optional for one-shot delivery. Scheduled children must also bind
// their observation to the invocation that produced it.
func (c CanaryConfig) AdmitReceipt(r Receipt, now, started time.Time) (string, error) {
	if c.CatalogSHA256 != acceptedCanaryCatalogSHA256 || c.ConsumptionProvenance != acceptedCanaryProvenance() {
		return "", AdmissionError("release_binding")
	}
	canary, err := c.CanaryFor(r)
	if err != nil {
		return "", AdmissionError("operation_identity")
	}
	entry, ok := c.Entry(canary)
	if !ok || validateCatalogReceipt(r, entry) != nil || r.Operation.Provider != entry.Provider || r.Operation.EndpointHost != entry.Endpoint.Host || r.Operation.EndpointPath != entry.Endpoint.Path {
		return "", AdmissionError("catalog_identity")
	}
	p := c.ConsumptionProvenance
	if r.Registry.DatasetID != entry.Aliases.DatasetID || r.Registry.DatasetRevision != p.RegistryDatasetRevision || r.Registry.RegistrySHA256 != p.SourceRegistrySHA256 || r.Registry.ManifestSHA256 != p.ReleaseManifestSHA256 {
		return "", AdmissionError("registry_identity")
	}
	if r.Policy == nil || r.Policy.Key != entry.Policy.Key || r.Policy.Version != entry.Policy.Version || r.Policy.Authority != entry.Policy.Authority || r.Policy.MaxLevel != entry.Policy.MaxLevel {
		return "", AdmissionError("policy_identity")
	}
	level, ceiling := probeLevel(r.Observation.MaxLevel), probeLevel(entry.Policy.MaxLevel)
	if level < 0 || ceiling < 0 || level > ceiling {
		return "", AdmissionError("policy_ceiling")
	}
	if now.IsZero() || r.ObservedAt.IsZero() || r.ObservedAt.After(now.Add(receiptClockSkew)) {
		return "", AdmissionError("future_observation")
	}
	if r.ObservedAt.Before(now.Add(-receiptMaxAge)) || (!started.IsZero() && r.ObservedAt.Before(started.Add(-receiptClockSkew))) {
		return "", AdmissionError("stale_observation")
	}
	if err := r.Validate(); err != nil {
		return "", AdmissionError("receipt_contract")
	}
	return canary.GatusEndpointKey, nil
}

func probeLevel(level string) int {
	switch level {
	case "L0":
		return 0
	case "L1":
		return 1
	case "L2":
		return 2
	case "L3":
		return 3
	case "L4":
		return 4
	case "L5":
		return 5
	}
	return -1
}

func admissionReason(err error) string {
	var reason AdmissionError
	if errors.As(err, &reason) {
		return string(reason)
	}
	return "receipt_contract"
}
