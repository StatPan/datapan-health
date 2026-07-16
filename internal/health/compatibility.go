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
	RequiredTests    []string                          `json:"required_tests"`
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

func BuildDiagnosticCompatibilityReceipt(healthHead, testedRevision string, contract DiagnosticContract, canaries CanaryConfig) (DiagnosticCompatibilityReceipt, error) {
	if !commitPattern.MatchString(healthHead) || !commitPattern.MatchString(testedRevision) {
		return DiagnosticCompatibilityReceipt{}, errors.New("health head and tested revision must be exact commits")
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
		RequiredTests: []string{
			"TestPinnedSchemaAndCLIStyleFixturesAreCompatible",
			"TestAcceptedDiagnosticFixturesMatchExactRegistryContract",
			"TestDiagnosticDecoderFailsClosedForUnknownVersionEnumAndExtraField",
			"TestDiagnosticSubjectBindsExactlyOnceToConfiguredService",
			"TestDiagnosticSubjectRejectsUnknownCrossOperationDuplicateAndStaleRevision",
			"TestDiagnosticProducerBoundaryRejectsEveryRedactionLeakClass",
			"TestDiagnosticCauseCannotChangeGatusProjection",
			"TestDiagnosticPinRejectsRevisionAndArtifactDrift",
		},
		Boundaries: DiagnosticCompatibilityBoundaries{
			ExistingHealthProbeV1: "preserved",
			GatusProjection:       "unchanged_enum_only",
			SensitiveEvidence:     "rejected_before_normalization",
			PublicAPI:             "not_implemented",
			Deployment:            "not_performed",
		},
	}, nil
}
