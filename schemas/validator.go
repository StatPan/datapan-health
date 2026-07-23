// Package schemas validates repository-pinned external contracts.
package schemas

import (
	_ "embed"
	"encoding/json"
	"errors"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

//go:embed datapan.health-probe.v1.schema.json
var healthProbeSchema []byte

//go:embed datapan.health-archive.v1.schema.json
var healthArchiveSchema []byte

//go:embed datapan.health-public-status.v1.schema.json
var healthPublicStatusSchema []byte

//go:embed datapan.service-status.v1.schema.json
var serviceStatusSchema []byte

//go:embed datapan.dependency-observation.v1.schema.json
var dependencyObservationSchema []byte

//go:embed datapan.dependency-status-legacy.v1.schema.json
var legacyDependencySchema []byte

//go:embed datapan.health-public-diagnosis-snapshot.v1.schema.json
var healthPublicDiagnosisSnapshotSchema []byte

//go:embed datapan.health-bounded-observation-run.v1.schema.json
var healthBoundedObservationRunSchema []byte

//go:embed datapan.health-schedule-coverage.v1.schema.json
var healthScheduleCoverageSchema []byte

var (
	healthProbeOnce                   sync.Once
	healthProbe                       *jsonschema.Schema
	healthProbeErr                    error
	healthArchiveOnce                 sync.Once
	healthArchive                     *jsonschema.Schema
	healthArchiveErr                  error
	healthPublicStatusOnce            sync.Once
	healthPublicStatus                *jsonschema.Schema
	healthPublicStatusErr             error
	serviceStatusOnce                 sync.Once
	serviceStatus                     *jsonschema.Schema
	serviceStatusErr                  error
	dependencyObservationOnce         sync.Once
	dependencyObservation             *jsonschema.Schema
	dependencyObservationErr          error
	legacyDependencyOnce              sync.Once
	legacyDependency                  *jsonschema.Schema
	legacyDependencyErr               error
	healthPublicDiagnosisSnapshotOnce sync.Once
	healthPublicDiagnosisSnapshot     *jsonschema.Schema
	healthPublicDiagnosisSnapshotErr  error
	healthBoundedObservationRunOnce   sync.Once
	healthBoundedObservationRun       *jsonschema.Schema
	healthBoundedObservationRunErr    error
	healthScheduleCoverageOnce        sync.Once
	healthScheduleCoverage            *jsonschema.Schema
	healthScheduleCoverageErr         error
)

func ValidateHealthProbeV1(data []byte) error {
	healthProbeOnce.Do(func() {
		healthProbe, healthProbeErr = compile(healthProbeSchema, "https://schemas.datapan.dev/datapan.health-probe.v1.schema.json")
	})
	return validate(data, healthProbe, healthProbeErr, "receipt")
}

// ValidateHealthArchiveV1 only accepts the intentionally minimized public
// observation projection. Detailed receipts never cross this boundary.
func ValidateHealthArchiveV1(data []byte) error {
	healthArchiveOnce.Do(func() {
		healthArchive, healthArchiveErr = compile(healthArchiveSchema, "https://schemas.datapan.dev/datapan.health-archive.v1.schema.json")
	})
	return validate(data, healthArchive, healthArchiveErr, "archive observation")
}

func ValidateHealthPublicStatusV1(data []byte) error {
	healthPublicStatusOnce.Do(func() {
		healthPublicStatus, healthPublicStatusErr = compile(healthPublicStatusSchema, "https://schemas.datapan.dev/datapan.health-public-status.v1.schema.json")
	})
	return validate(data, healthPublicStatus, healthPublicStatusErr, "public status")
}

func ValidateServiceStatusV1(data []byte) error {
	serviceStatusOnce.Do(func() {
		serviceStatus, serviceStatusErr = compile(serviceStatusSchema, "https://schemas.datapan.dev/datapan.service-status.v1.schema.json")
	})
	return validate(data, serviceStatus, serviceStatusErr, "service status")
}

func ValidateDependencyObservationV1(data []byte) error {
	dependencyObservationOnce.Do(func() {
		dependencyObservation, dependencyObservationErr = compile(dependencyObservationSchema, "https://schemas.datapan.dev/datapan.dependency-observation.v1.schema.json")
	})
	return validate(data, dependencyObservation, dependencyObservationErr, "dependency observation")
}

func ValidateLegacyDependencyStatusV1(data []byte) error {
	legacyDependencyOnce.Do(func() {
		legacyDependency, legacyDependencyErr = compile(legacyDependencySchema, "https://schemas.datapan.dev/datapan.dependency-status-legacy.v1.schema.json")
	})
	return validate(data, legacyDependency, legacyDependencyErr, "legacy dependency status")
}

func ValidateHealthPublicDiagnosisSnapshotV1(data []byte) error {
	healthPublicDiagnosisSnapshotOnce.Do(func() {
		healthPublicDiagnosisSnapshot, healthPublicDiagnosisSnapshotErr = compile(healthPublicDiagnosisSnapshotSchema, "https://schemas.datapan.dev/datapan.health-public-diagnosis-snapshot.v1.schema.json")
	})
	return validate(data, healthPublicDiagnosisSnapshot, healthPublicDiagnosisSnapshotErr, "public diagnosis snapshot")
}

// ValidateHealthBoundedObservationRunV1 validates the private Health producer
// receipt used to replace Registry-side bounded provider execution. It is not
// a public status or archive schema.
func ValidateHealthBoundedObservationRunV1(data []byte) error {
	healthBoundedObservationRunOnce.Do(func() {
		healthBoundedObservationRun, healthBoundedObservationRunErr = compile(healthBoundedObservationRunSchema, "https://schemas.datapan.dev/datapan.health-bounded-observation-run.v1.schema.json")
	})
	return validate(data, healthBoundedObservationRun, healthBoundedObservationRunErr, "bounded observation run")
}

// ValidateHealthScheduleCoverageV1 validates private queue/coverage evidence.
// It is intentionally not a provider-observation, public-status, or archive
// contract.
func ValidateHealthScheduleCoverageV1(data []byte) error {
	healthScheduleCoverageOnce.Do(func() {
		healthScheduleCoverage, healthScheduleCoverageErr = compile(healthScheduleCoverageSchema, "https://schemas.datapan.dev/datapan.health-schedule-coverage.v1.schema.json")
	})
	return validate(data, healthScheduleCoverage, healthScheduleCoverageErr, "schedule coverage")
}

func compile(source []byte, uri string) (*jsonschema.Schema, error) {
	var document any
	if err := json.Unmarshal(source, &document); err != nil {
		return nil, err
	}
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(uri, document); err != nil {
		return nil, err
	}
	return compiler.Compile(uri)
}

func validate(data []byte, schema *jsonschema.Schema, schemaErr error, kind string) error {
	if schemaErr != nil {
		return schemaErr
	}
	var instance any
	if err := json.Unmarshal(data, &instance); err != nil {
		return errors.New(kind + " is not valid JSON")
	}
	if err := schema.Validate(instance); err != nil {
		return errors.New(kind + " does not match its pinned schema")
	}
	return nil
}
