package health

import (
	"bytes"
	"errors"
	"sort"
)

const DiagnosticCompatibilityReceiptVersion = "datapan.health-diagnostic-compatibility-receipt.v1"

type DiagnosticCompatibilityReceipt struct {
	SchemaVersion    string                            `json:"schema_version"`
	Status           string                            `json:"status"`
	HealthHead       string                            `json:"health_head"`
	TestedRevision   string                            `json:"tested_revision"`
	RegistryRevision string                            `json:"registry_revision"`
	Contracts        DiagnosticCompatibilityPins       `json:"contracts"`
	Fixtures         []DiagnosticFixtureProof          `json:"fixtures"`
	Bindings         []DiagnosticServiceBindingProof   `json:"bindings"`
	TestProof        DiagnosticTestProof               `json:"test_proof"`
	Boundaries       DiagnosticCompatibilityBoundaries `json:"boundaries"`
}

type DiagnosticCompatibilityPins struct {
	Schema   ArtifactPin `json:"schema"`
	Mapping  ArtifactPin `json:"mapping"`
	Consumer ArtifactPin `json:"consumer"`
}

type DiagnosticFixtureProof struct {
	Name          string `json:"name"`
	SHA256        string `json:"sha256"`
	Cause         string `json:"cause"`
	Determination string `json:"determination"`
}

type DiagnosticServiceBindingProof struct {
	OperationID      string `json:"operation_id"`
	DatasetID        string `json:"dataset_id"`
	ServiceID        string `json:"service_id"`
	RegistryRevision string `json:"registry_revision"`
}

type DiagnosticCompatibilityBoundaries struct {
	ExistingHealthProbeV1 string `json:"existing_health_probe_v1"`
	GatusProjection       string `json:"gatus_projection"`
	SensitiveEvidence     string `json:"sensitive_evidence"`
	PublicAPI             string `json:"public_api"`
	Deployment            string `json:"deployment"`
}

var expectedDiagnosticServiceBindings = map[string]string{
	"dpr-op-00000001": "public-data_holiday-emergency-clinics",
	"dpr-op-00000002": "public-data_election-codes",
	"dpr-op-00000003": "public-data_medical-institution-codes",
	"dpr-op-00000004": "public-data_private-resource-services",
	"dpr-op-00000005": "public-data_culture-facility-restaurants",
	"dpr-op-00000006": "public-data_qnet-practical-pass-rate",
	"dpr-op-00000007": "public-data_weather-nearby-realtime",
	"dpr-op-00000008": "public-data_transit-card-chargers",
	"dpr-op-00000009": "public-data_bus-depot-status",
	"dpr-op-00000010": "public-data_university-majors",
}

func BuildDiagnosticCompatibilityReceipt(healthHead, testedRevision, repoRoot string, contract DiagnosticContract, canaries CanaryConfig) (DiagnosticCompatibilityReceipt, error) {
	if !commitPattern.MatchString(healthHead) || !commitPattern.MatchString(testedRevision) {
		return DiagnosticCompatibilityReceipt{}, errors.New("health head and tested revision must be exact commits")
	}
	testProof, err := contract.ValidateTestManifest(repoRoot)
	if err != nil {
		return DiagnosticCompatibilityReceipt{}, err
	}
	fixtures := make([]DiagnosticFixtureProof, 0, len(contract.fixtureNames))
	for _, name := range contract.fixtureNames {
		raw, err := contract.ReadFixture(name)
		if err != nil {
			return DiagnosticCompatibilityReceipt{}, err
		}
		envelope, err := contract.Decode(bytes.NewReader(raw))
		if err != nil {
			return DiagnosticCompatibilityReceipt{}, err
		}
		fixtures = append(fixtures, DiagnosticFixtureProof{Name: name, SHA256: envelope.OriginalSHA256, Cause: envelope.Cause.Code, Determination: envelope.Cause.Determination})
	}
	bindings := make([]DiagnosticServiceBindingProof, 0, len(canaries.Canaries))
	for _, canary := range canaries.Canaries {
		entry, ok := canaries.Entry(canary)
		if !ok {
			return DiagnosticCompatibilityReceipt{}, errors.New("configured canary is absent from the pinned catalog")
		}
		envelope := DiagnosticEnvelope{
			Subject: DiagnosticSubject{
				SourceID: contract.SourceID, ProviderID: contract.ProviderID,
				DatasetID: entry.Aliases.DatasetID, OperationID: canary.OperationID,
			},
			OriginalSHA256: digest([]byte(canary.OperationID + "\x00" + entry.Aliases.DatasetID)),
		}
		binding, err := contract.Resolve(envelope, canaries)
		if err != nil {
			return DiagnosticCompatibilityReceipt{}, err
		}
		bindings = append(bindings, DiagnosticServiceBindingProof{
			OperationID: binding.OperationID, DatasetID: entry.Aliases.DatasetID,
			ServiceID: binding.ServiceID, RegistryRevision: binding.RegistryRevision,
		})
	}
	if err := validateExactDiagnosticServiceBindings(canaries); err != nil {
		return DiagnosticCompatibilityReceipt{}, err
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].OperationID < bindings[j].OperationID })

	return DiagnosticCompatibilityReceipt{
		SchemaVersion:    DiagnosticCompatibilityReceiptVersion,
		Status:           "consumer_compatible",
		HealthHead:       healthHead,
		TestedRevision:   testedRevision,
		RegistryRevision: contract.RegistryRevision,
		Contracts:        DiagnosticCompatibilityPins{Schema: contract.Schema, Mapping: contract.Mapping, Consumer: contract.Consumer},
		Fixtures:         fixtures,
		Bindings:         bindings,
		TestProof:        testProof,
		Boundaries: DiagnosticCompatibilityBoundaries{
			ExistingHealthProbeV1: "preserved",
			GatusProjection:       "unchanged_enum_only",
			SensitiveEvidence:     "rejected_before_normalization",
			PublicAPI:             "not_implemented",
			Deployment:            "not_performed",
		},
	}, nil
}

func validateExactDiagnosticServiceBindings(canaries CanaryConfig) error {
	if len(canaries.Canaries) != len(expectedDiagnosticServiceBindings) {
		return errors.New("diagnostic compatibility requires the exact canary set")
	}
	seenOperations := make(map[string]bool, len(canaries.Canaries))
	seenServices := make(map[string]bool, len(canaries.Canaries))
	for _, canary := range canaries.Canaries {
		expectedService, ok := expectedDiagnosticServiceBindings[canary.OperationID]
		if !ok || canary.GatusEndpointKey != expectedService || seenOperations[canary.OperationID] || seenServices[canary.GatusEndpointKey] {
			return errors.New("diagnostic compatibility requires an exact operation and service bijection")
		}
		seenOperations[canary.OperationID] = true
		seenServices[canary.GatusEndpointKey] = true
	}
	if len(seenOperations) != len(expectedDiagnosticServiceBindings) || len(seenServices) != len(expectedDiagnosticServiceBindings) {
		return errors.New("diagnostic compatibility operation and service binding is incomplete")
	}
	return nil
}
