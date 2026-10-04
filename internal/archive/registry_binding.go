package archive

import (
	"errors"
	"path/filepath"
	"sort"

	"github.com/StatPan/datapan-health/internal/health"
)

// RegistryBinding identifies a consumed release, separately from historical
// schema/catalog contract authority and without provider request data.
type RegistryBinding struct {
	health.ConsumptionProvenance
	CatalogSHA256 string `json:"catalog_sha256"`
}

type HistoricalCatalog struct {
	RegistryBinding
	Path string `json:"path"`
}

func acceptedHistoricalCatalogs() []HistoricalCatalog {
	return []HistoricalCatalog{
		{RegistryBinding{health.ConsumptionProvenance{
			RegistryDatasetRevision: "10f375182f992bc700468dd9d6e2930acd3bf8e8",
			SourceRegistrySHA256:    "eeda72ee8590f458de8d75703662578e80edf3e61282f0e5e67547c4f6e5f644",
			ReleaseTag:              "v2026.07.14",
			ReleaseManifestSHA256:   "0b78c286b8cfa889ddccf51f83a9d8adc4eac8617ea6d9fd2d66d1fcf668281f",
		}, "e84f0da2f532a32833def1118a4610bf2322f370783d120b84cf85306d244840"}, "registry/archive-history/health-probe-catalog-10f37518.json"},
		{RegistryBinding{health.ConsumptionProvenance{
			RegistryDatasetRevision: "247975f0ba5872cb84d22f007fc4b8a934539b7b",
			SourceRegistrySHA256:    "0520d0db0d9ee07b7cbccce0c08439d0b02be901bf10e8491187d96e59d7a0d0",
			ReleaseTag:              "247975f0ba5872cb84d22f007fc4b8a934539b7b",
			ReleaseManifestSHA256:   "c40e661c4e3fa6dd2c9e43f6aca17e9544a09831d83300b624df14d68123d5d2",
		}, "827433dec514fa10ebef780ff611f6314b6e1d7270acde81ce6d60ec7a46e27e"}, "registry/archive-history/health-probe-catalog-247975f0.json"},
	}
}

type archiveCatalog struct {
	binding RegistryBinding
	entries map[string]health.CatalogEntry
}

type archiveMapper struct {
	catalogs map[string]archiveCatalog
	canaries map[string]health.Canary
	used     map[string]RegistryBinding
}

func loadArchiveMapper(config Config, configPath string, canaries health.CanaryConfig) (*archiveMapper, error) {
	if config.ActiveRegistry != (RegistryBinding{canaries.ConsumptionProvenance, canaries.CatalogSHA256}) {
		return nil, errors.New("archive active Registry binding does not match reviewed canaries")
	}
	historical := acceptedHistoricalCatalogs()
	if len(config.HistoricalRegistryCatalogs) != len(historical) {
		return nil, errors.New("archive historical catalog authority is invalid")
	}
	mapper := &archiveMapper{catalogs: map[string]archiveCatalog{}, canaries: map[string]health.Canary{}, used: map[string]RegistryBinding{}}
	active := archiveCatalog{binding: config.ActiveRegistry, entries: map[string]health.CatalogEntry{}}
	for _, canary := range canaries.Canaries {
		entry, ok := canaries.Entry(canary)
		if !ok {
			return nil, errors.New("archive service mapping is invalid")
		}
		mapper.canaries[canary.OperationID] = canary
		active.entries[entry.Aliases.CLIOperationKey] = entry
	}
	mapper.catalogs[config.ActiveRegistry.RegistryDatasetRevision] = active
	for index, record := range config.HistoricalRegistryCatalogs {
		if record != historical[index] {
			return nil, errors.New("archive historical catalog authority is invalid")
		}
		catalog, err := health.LoadCatalog(filepath.Join(filepath.Dir(configPath), record.Path), record.CatalogSHA256)
		if err != nil || catalog.SourceRegistry.SHA256 != record.SourceRegistrySHA256 {
			return nil, errors.New("archive historical catalog bytes do not match authority")
		}
		old := archiveCatalog{binding: record.RegistryBinding, entries: map[string]health.CatalogEntry{}}
		for _, entry := range catalog.Entries {
			if _, ok := mapper.canaries[entry.OperationID]; !ok {
				return nil, errors.New("archive historical service mapping is invalid")
			}
			if _, exists := old.entries[entry.Aliases.CLIOperationKey]; exists {
				return nil, errors.New("archive historical operation mapping is ambiguous")
			}
			old.entries[entry.Aliases.CLIOperationKey] = entry
		}
		mapper.catalogs[record.RegistryDatasetRevision] = old
	}
	return mapper, nil
}

// This mapping accepts historical evidence for asynchronous export only. It
// never calls live admission or rewrites a receipt to the active release.
func (m *archiveMapper) canaryFor(receipt health.Receipt) (health.Canary, error) {
	catalog, known := m.catalogs[receipt.Registry.DatasetRevision]
	if !known || receipt.Registry.DatasetID != "StatPan/datapan-registry" || receipt.Registry.RegistrySHA256 != catalog.binding.SourceRegistrySHA256 || receipt.Registry.ManifestSHA256 != catalog.binding.ReleaseManifestSHA256 {
		return health.Canary{}, errors.New("archive receipt Registry identity is not reviewed")
	}
	entry, known := catalog.entries[receipt.Operation.OperationKey]
	if !known || receipt.Operation.DatasetID != entry.Aliases.DatasetID || receipt.Operation.OperationName != entry.Aliases.OperationName || receipt.Operation.Provider != entry.Provider || receipt.Operation.EndpointHost != entry.Endpoint.Host || receipt.Operation.EndpointPath != entry.Endpoint.Path || receipt.Operation.DependencyClass != entry.Endpoint.DependencyClass {
		return health.Canary{}, errors.New("archive receipt operation identity is not reviewed")
	}
	if receipt.Policy == nil {
		// The original v1 contract predates policy fields. Only its exact reviewed
		// historical release can retain that absence; no current policy is inferred.
		if receipt.Registry.DatasetRevision != "10f375182f992bc700468dd9d6e2930acd3bf8e8" {
			return health.Canary{}, errors.New("archive receipt policy identity is missing")
		}
	} else if receipt.Policy.Key != entry.Policy.Key || receipt.Policy.Version != entry.Policy.Version || receipt.Policy.Authority != entry.Policy.Authority || receipt.Policy.MaxLevel != entry.Policy.MaxLevel {
		return health.Canary{}, errors.New("archive receipt policy identity is not reviewed")
	}
	canary, known := m.canaries[entry.OperationID]
	if !known {
		return health.Canary{}, errors.New("archive receipt service identity is not reviewed")
	}
	m.used[receipt.Registry.DatasetRevision] = catalog.binding
	return canary, nil
}

func (m *archiveMapper) inputCatalogs() []RegistryBinding {
	result := make([]RegistryBinding, 0, len(m.used))
	for _, binding := range m.used {
		result = append(result, binding)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].RegistryDatasetRevision < result[j].RegistryDatasetRevision })
	return result
}

// An already published safe projection has no provider operation details. Keep
// its original revision and require that revision/service to remain reviewed.
func (m *archiveMapper) retainProjection(row Observation) error {
	catalog, known := m.catalogs[row.RegistryRevision]
	if !known {
		return errors.New("archive retained projection Registry identity is not reviewed")
	}
	for _, canary := range m.canaries {
		if row.ServiceID == canary.GatusEndpointKey {
			m.used[row.RegistryRevision] = catalog.binding
			return nil
		}
	}
	return errors.New("archive retained projection service identity is not reviewed")
}
