package health

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

const (
	ServiceStatusSchemaVersion         = "datapan.service-status.v1"
	DependencyObservationSchemaVersion = "datapan.dependency-observation.v1"
	LegacyDependencySchemaVersion      = "datapan.dependency-status-legacy.v1"
	PublicStatusDoctorSchemaVersion    = "datapan.public-status-doctor.v1"
)

// PublicServiceStatus is intentionally limited to a Datapan-owned deployment
// surface. Provider observations are represented by DependencyObservationDocument
// and cannot be projected into this type.
type PublicServiceStatus struct {
	ServiceID          string    `json:"service_id"`
	Owner              string    `json:"owner"`
	SurfaceKind        string    `json:"surface_kind"`
	PublicSurface      string    `json:"public_surface,omitempty"`
	State              string    `json:"state"`
	ObservedAt         time.Time `json:"observed_at"`
	CheckID            string    `json:"check_id"`
	DeploymentIdentity string    `json:"deployment_identity,omitempty"`
	UnknownReason      string    `json:"unknown_reason,omitempty"`
}

type ServiceStatusDocument struct {
	SchemaVersion string                `json:"schema_version"`
	GeneratedAt   time.Time             `json:"generated_at"`
	Scope         string                `json:"scope"`
	Services      []PublicServiceStatus `json:"services"`
}

type DependencyObservationScope struct {
	Kind        string `json:"kind"`
	CanaryCount int    `json:"canary_count"`
	Coverage    string `json:"coverage"`
}

type DependencyObservationDocument struct {
	SchemaVersion string                     `json:"schema_version"`
	GeneratedAt   time.Time                  `json:"generated_at"`
	Scope         DependencyObservationScope `json:"scope"`
	Operations    []PublicOperationStatus    `json:"operations"`
}

type LegacyDependencyDocument struct {
	SchemaVersion string                     `json:"schema_version"`
	GeneratedAt   time.Time                  `json:"generated_at"`
	Scope         DependencyObservationScope `json:"scope"`
	Operations    []PublicOperationStatus    `json:"operations"`
}

// PublicStatusDoctorReport is a value-free readiness report. It names the two
// contracts separately and retains each owned service's explicit unknown
// reason, without querying a provider or claiming a deployed service state.
type PublicStatusDoctorReport struct {
	SchemaVersion              string                `json:"schema_version"`
	ServiceContract            string                `json:"service_contract"`
	DependencyContract         string                `json:"dependency_contract"`
	DependencyCanaryCount      int                   `json:"dependency_canary_count"`
	OwnedServiceStatus         []PublicServiceStatus `json:"owned_service_status"`
	ExternalObservationMeaning string                `json:"external_observation_meaning"`
}

type PublicServiceStatusSource interface {
	Snapshot(context.Context) (ServiceStatusDocument, error)
}

type OwnedServiceCheck interface {
	Check(context.Context, time.Time) PublicServiceStatus
}

type OwnedServiceCheckFunc func(context.Context, time.Time) PublicServiceStatus

func (f OwnedServiceCheckFunc) Check(ctx context.Context, now time.Time) PublicServiceStatus {
	return f(ctx, now)
}

type OwnedServiceStatusSource struct {
	checks []OwnedServiceCheck
	now    func() time.Time
}

func NewOwnedServiceStatusSource(checks []OwnedServiceCheck) (*OwnedServiceStatusSource, error) {
	if len(checks) != 4 {
		return nil, errors.New("four owned service checks are required")
	}
	return &OwnedServiceStatusSource{checks: append([]OwnedServiceCheck(nil), checks...), now: time.Now}, nil
}

// DefaultOwnedServiceStatusSource deliberately has no deployment bindings. It
// makes the absence visible as unknown instead of confusing this local adapter
// or an external canary with a deployed Datapan service.
func DefaultOwnedServiceStatusSource() *OwnedServiceStatusSource {
	checks := []OwnedServiceCheck{
		missingIdentityCheck("dataset-api", "datapan-data", "dataset_api", "dataset-api-immutable-deployment"),
		missingIdentityCheck("registry-distribution", "datapan-registry", "registry_distribution", "registry-distribution-artifact"),
		missingIdentityCheck("datapan-web-atlas", "datapan", "web_delivery", "datapan-web-immutable-release"),
		missingIdentityCheck("datapan-health", "datapan-health", "health_self", "health-self-immutable-deployment"),
	}
	source, err := NewOwnedServiceStatusSource(checks)
	if err != nil {
		panic(err)
	}
	return source
}

func missingIdentityCheck(serviceID, owner, surfaceKind, checkID string) OwnedServiceCheck {
	return OwnedServiceCheckFunc(func(_ context.Context, now time.Time) PublicServiceStatus {
		return PublicServiceStatus{ServiceID: serviceID, Owner: owner, SurfaceKind: surfaceKind, State: "unknown", ObservedAt: now.UTC(), CheckID: checkID, UnknownReason: "deployment_identity_unavailable"}
	})
}

func (s *OwnedServiceStatusSource) Snapshot(ctx context.Context) (ServiceStatusDocument, error) {
	now := s.now().UTC().Truncate(30 * time.Second)
	document := ServiceStatusDocument{SchemaVersion: ServiceStatusSchemaVersion, GeneratedAt: now, Scope: "datapan_owned_services", Services: make([]PublicServiceStatus, 0, len(s.checks))}
	seen := map[string]bool{}
	for _, check := range s.checks {
		service := check.Check(ctx, now)
		if !validPublicServiceStatus(service) || seen[service.ServiceID] {
			return ServiceStatusDocument{}, errors.New("owned service check is invalid")
		}
		seen[service.ServiceID] = true
		document.Services = append(document.Services, service)
	}
	sort.Slice(document.Services, func(i, j int) bool { return document.Services[i].ServiceID < document.Services[j].ServiceID })
	encoded, err := json.Marshal(document)
	if err != nil || schemas.ValidateServiceStatusV1(encoded) != nil {
		return ServiceStatusDocument{}, errors.New("owned service status is invalid")
	}
	return document, nil
}

func validPublicServiceStatus(service PublicServiceStatus) bool {
	if service.ObservedAt.IsZero() || service.CheckID == "" {
		return false
	}
	expected := map[string]struct{ owner, surface string }{
		"dataset-api":           {"datapan-data", "dataset_api"},
		"registry-distribution": {"datapan-registry", "registry_distribution"},
		"datapan-web-atlas":     {"datapan", "web_delivery"},
		"datapan-health":        {"datapan-health", "health_self"},
	}
	want, ok := expected[service.ServiceID]
	if !ok || service.Owner != want.owner || service.SurfaceKind != want.surface {
		return false
	}
	if service.State == "unknown" {
		return service.DeploymentIdentity == "" && service.UnknownReason != ""
	}
	return (service.State == "operational" || service.State == "degraded") && service.PublicSurface != "" && service.DeploymentIdentity != "" && service.UnknownReason == ""
}

func dependencyDocument(document PublicStatusDocument) DependencyObservationDocument {
	return DependencyObservationDocument{SchemaVersion: DependencyObservationSchemaVersion, GeneratedAt: document.GeneratedAt, Scope: DependencyObservationScope{Kind: "external_dependency_observations", CanaryCount: len(document.Operations), Coverage: "not_datapan_service_sla_or_catalog_coverage"}, Operations: document.Operations}
}

func legacyDependencyDocument(document PublicStatusDocument) LegacyDependencyDocument {
	return LegacyDependencyDocument{SchemaVersion: LegacyDependencySchemaVersion, GeneratedAt: document.GeneratedAt, Scope: DependencyObservationScope{Kind: "external_dependency_legacy_alias", CanaryCount: len(document.Operations), Coverage: "not_datapan_service_sla_or_catalog_coverage"}, Operations: document.Operations}
}

func BuildPublicStatusDoctorReport(ctx context.Context, services PublicServiceStatusSource, dependencyCanaryCount int) (PublicStatusDoctorReport, error) {
	if services == nil || dependencyCanaryCount != 10 {
		return PublicStatusDoctorReport{}, errors.New("public status doctor configuration is invalid")
	}
	document, err := services.Snapshot(ctx)
	if err != nil || len(document.Services) != 4 {
		return PublicStatusDoctorReport{}, errors.New("public status doctor services are invalid")
	}
	return PublicStatusDoctorReport{
		SchemaVersion:              PublicStatusDoctorSchemaVersion,
		ServiceContract:            ServiceStatusSchemaVersion,
		DependencyContract:         DependencyObservationSchemaVersion,
		DependencyCanaryCount:      dependencyCanaryCount,
		OwnedServiceStatus:         document.Services,
		ExternalObservationMeaning: "external_dependency_observations_not_datapan_service_incidents",
	}, nil
}
