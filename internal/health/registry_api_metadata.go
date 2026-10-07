package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/StatPan/datapan-health/schemas"
)

const (
	RegistryAPIMetadataSchemaVersion  = "datapan.health-registry-api-metadata.v1"
	maxRegistryAPIMetadataBytes       = 64 * 1024 * 1024
	maxRegistryMetadataPinBytes       = 1024 * 1024
	acceptedRegistryAPIMetadataSHA256 = "6f7b2ba4a0dbb8adc31c954485f5ca7677553a7609353a9c59f2769bba6f8650"
	acceptedRegistryMetadataPinSHA256 = "e49a4f65f20eaa12dd6c9290f51e47a2d31e372f4f092c41c95f5e57cd0a2e98"
)

var (
	registryAPIIDPattern        = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	registryOperationIDPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	registryOperationKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)
	registryHealthIDPattern     = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	registryMetadataStateValues = map[string]bool{"present": true, "sanitized": true, "missing": true, "blank": true, "redacted_unsafe": true, "invalid_source": true}
)

// RegistryAPIMetadata is the bounded, source-derived display projection. It
// contains no endpoint, request, credential, or response fields.
type RegistryAPIMetadata struct {
	SchemaVersion            string                     `json:"schema_version"`
	RegistryRevision         string                     `json:"registry_revision"`
	Scope                    registryMetadataScope      `json:"scope"`
	Source                   registryMetadataSource     `json:"source"`
	Catalog                  registryMetadataCatalog    `json:"catalog"`
	Counts                   RegistryAPIMetadataCounts  `json:"counts"`
	APIs                     []RegistryAPIMetadataAPI   `json:"apis"`
	HealthCanaryLinks        []RegistryHealthCanaryLink `json:"health_canary_links"`
	healthCatalogRevision    string
	verifiedArtifactSHA256   string
	verifiedSourceSHA256     string
	verifiedProjectionSHA256 string
	byID                     map[string]int
	operationByID            map[string]RegistryAPIMetadataOperation
	canaryByOpID             map[string]RegistryHealthCanaryLink
	canaryByHealthID         map[string]RegistryHealthCanaryLink
	canaryDisplays           []RegistryCanaryDisplay
	orderedAPIIndices        []int
	searchText               []string
}

type registryMetadataScope struct {
	Provider                     string `json:"provider"`
	SourceSnapshotComplete       bool   `json:"source_snapshot_complete"`
	RegistryWideMetadataComplete bool   `json:"registry_wide_metadata_complete"`
	CoverageNote                 string `json:"coverage_note"`
}

type registryMetadataSource struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type registryMetadataCatalog struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	EntryCount int    `json:"entry_count"`
}

type RegistryAPIMetadataCounts struct {
	APIEntities                 int `json:"api_entities"`
	APIOperations               int `json:"api_operations"`
	LinkOperations              int `json:"link_operations"`
	OperationlessCatalogEntries int `json:"operationless_catalog_entries"`
	FiledataCatalogEntries      int `json:"filedata_catalog_entries"`
	Institutions                int `json:"institutions"`
	MatchedHealthCanaries       int `json:"matched_health_canaries"`
}

type RegistryAPIMetadataAPI struct {
	RegistryAPIID      string                         `json:"registry_api_id"`
	Provider           string                         `json:"provider"`
	Title              string                         `json:"title"`
	TitleState         string                         `json:"title_state"`
	Organization       string                         `json:"organization"`
	OrganizationState  string                         `json:"organization_state"`
	Description        string                         `json:"description"`
	DescriptionState   string                         `json:"description_state"`
	LinkOperationCount int                            `json:"link_operation_count"`
	Operations         []RegistryAPIMetadataOperation `json:"operations"`
}

type RegistryAPIMetadataOperation struct {
	RegistryOperationID  string `json:"registry_operation_id"`
	DatasetID            string `json:"dataset_id"`
	SourceSystem         string `json:"source_system"`
	UpstreamOperationKey string `json:"upstream_operation_key"`
	UpstreamOperationSeq string `json:"upstream_operation_seq"`
	Name                 string `json:"name"`
	NameState            string `json:"name_state"`
	Protocol             string `json:"protocol"`
}

type RegistryHealthCanaryLink struct {
	HealthOperationID    string `json:"health_operation_id"`
	RegistryAPIID        string `json:"registry_api_id"`
	RegistryOperationID  string `json:"registry_operation_id"`
	DatasetID            string `json:"dataset_id"`
	UpstreamOperationSeq string `json:"upstream_operation_seq"`
	OperationName        string `json:"operation_name"`
	CLIOperationKey      string `json:"cli_operation_key"`
}

type RegistryCanaryDisplay struct {
	HealthOperationID string
	OperationName     string
}

type registryAPIMetadataSourcePin struct {
	SchemaVersion    string                    `json:"schema_version"`
	RegistryRevision string                    `json:"registry_revision"`
	Source           registryMetadataSource    `json:"source"`
	Catalog          registryMetadataCatalog   `json:"catalog"`
	ExpectedCounts   RegistryAPIMetadataCounts `json:"expected_counts"`
	Artifact         struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"artifact"`
}

// LoadRegistryAPIMetadata verifies the generated display artifact against the
// checked-in source pin and the exact Registry inputs already accepted by the
// Health canary catalog.
func LoadRegistryAPIMetadata(path, pinPath string, canaries CanaryConfig) (RegistryAPIMetadata, error) {
	metadataData, err := readLimitedMetadataFile(path, maxRegistryAPIMetadataBytes)
	if err != nil || len(metadataData) == 0 {
		return RegistryAPIMetadata{}, errors.New("invalid Registry API metadata")
	}
	pinData, err := readLimitedMetadataFile(pinPath, maxRegistryMetadataPinBytes)
	if err != nil || len(pinData) == 0 {
		return RegistryAPIMetadata{}, errors.New("invalid Registry API metadata")
	}
	pinSum := sha256.Sum256(pinData)
	if hex.EncodeToString(pinSum[:]) != acceptedRegistryMetadataPinSHA256 || schemas.ValidateHealthRegistryAPIMetadataSourcePinV1(pinData) != nil {
		return RegistryAPIMetadata{}, errors.New("invalid Registry API metadata")
	}
	var pin registryAPIMetadataSourcePin
	if decodeMetadataJSON(pinData, &pin) != nil || pin.SchemaVersion != "datapan.health-registry-api-metadata-source-pin.v1" {
		return RegistryAPIMetadata{}, errors.New("invalid Registry API metadata")
	}
	sum := sha256.Sum256(metadataData)
	artifactSHA := hex.EncodeToString(sum[:])
	if !sha256Pattern.MatchString(pin.Artifact.SHA256) || artifactSHA != pin.Artifact.SHA256 || artifactSHA != acceptedRegistryAPIMetadataSHA256 || pin.Artifact.Path != "config/registry/api-metadata.v1.json" {
		return RegistryAPIMetadata{}, errors.New("invalid Registry API metadata")
	}
	var metadata RegistryAPIMetadata
	if decodeMetadataJSON(metadataData, &metadata) != nil || metadata.SchemaVersion != RegistryAPIMetadataSchemaVersion {
		return RegistryAPIMetadata{}, errors.New("invalid Registry API metadata")
	}
	if schemas.ValidateHealthRegistryAPIMetadataV1(metadataData) != nil {
		return RegistryAPIMetadata{}, errors.New("invalid Registry API metadata")
	}
	if !sameMetadataProvenance(metadata, pin, canaries) || metadata.Counts != pin.ExpectedCounts {
		return RegistryAPIMetadata{}, errors.New("invalid Registry API metadata")
	}
	if err := metadata.indexAndValidate(canaries); err != nil {
		return RegistryAPIMetadata{}, errors.New("invalid Registry API metadata")
	}
	metadata.healthCatalogRevision = canaries.ConsumptionProvenance.RegistryDatasetRevision
	metadata.verifiedArtifactSHA256 = artifactSHA
	metadata.verifiedSourceSHA256 = metadata.Source.SHA256
	projection, err := json.Marshal(metadata)
	if err != nil {
		return RegistryAPIMetadata{}, errors.New("invalid Registry API metadata")
	}
	projectionSum := sha256.Sum256(projection)
	metadata.verifiedProjectionSHA256 = hex.EncodeToString(projectionSum[:])
	return metadata, nil
}

func readLimitedMetadataFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, errors.New("metadata file is too large")
	}
	return data, nil
}

func decodeMetadataJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := ensureEOF(decoder); err != nil {
		return err
	}
	return nil
}

func sameMetadataProvenance(metadata RegistryAPIMetadata, pin registryAPIMetadataSourcePin, canaries CanaryConfig) bool {
	provenance := canaries.ConsumptionProvenance
	return metadata.RegistryRevision == pin.RegistryRevision &&
		metadata.Source == pin.Source && metadata.Catalog == pin.Catalog &&
		metadata.Source.SHA256 == provenance.SourceRegistrySHA256 &&
		metadata.Catalog.SHA256 == canaries.CatalogSHA256 &&
		metadata.Catalog.EntryCount == len(canaries.catalog.Entries) &&
		metadata.Source.SizeBytes > 0 && metadata.Catalog.EntryCount > 0
}

func (m *RegistryAPIMetadata) indexAndValidate(canaries CanaryConfig) error {
	if m.RegistryRevision == "" || m.Scope.Provider != "data.go.kr" || !m.Scope.SourceSnapshotComplete || m.Scope.RegistryWideMetadataComplete || m.Scope.CoverageNote != "Complete for the pinned data.go.kr source only; not a complete inventory of all Registry adapters." || !sha256Pattern.MatchString(m.Source.SHA256) || !sha256Pattern.MatchString(m.Catalog.SHA256) || m.Source.Path != "data/data-go-kr.registry.json" || m.Catalog.Path != "config/registry/health-probe-catalog.json" || m.Source.SizeBytes <= 0 || m.Catalog.EntryCount <= 0 || len(m.APIs) != m.Counts.APIEntities || len(m.HealthCanaryLinks) != m.Counts.MatchedHealthCanaries {
		return errors.New("invalid Registry metadata identity")
	}
	m.byID = make(map[string]int, len(m.APIs))
	m.operationByID = make(map[string]RegistryAPIMetadataOperation, m.Counts.APIOperations)
	m.canaryByOpID = make(map[string]RegistryHealthCanaryLink, len(m.HealthCanaryLinks))
	m.canaryByHealthID = make(map[string]RegistryHealthCanaryLink, len(m.HealthCanaryLinks))
	m.canaryDisplays = make([]RegistryCanaryDisplay, 0, len(canaries.Canaries))
	m.orderedAPIIndices = make([]int, len(m.APIs))
	m.searchText = make([]string, len(m.APIs))
	operationCount, linkOperationCount := 0, 0
	institutions := map[string]bool{}
	for apiIndex, api := range m.APIs {
		if !registryAPIIDPattern.MatchString(api.RegistryAPIID) || api.Provider != "data.go.kr" || api.LinkOperationCount < 0 {
			return errors.New("invalid Registry API entity")
		}
		if _, exists := m.byID[api.RegistryAPIID]; exists {
			return errors.New("duplicate Registry API identity")
		}
		m.byID[api.RegistryAPIID] = apiIndex
		if !validMetadataField(api.Title, api.TitleState, 1024) || !validMetadataField(api.Organization, api.OrganizationState, 1024) || !validMetadataField(api.Description, api.DescriptionState, 8192) {
			return errors.New("invalid Registry API display field")
		}
		if api.OrganizationState == "present" || api.OrganizationState == "sanitized" {
			institutions[strings.TrimSpace(api.Organization)] = true
		}
		linkOperationCount += api.LinkOperationCount
		for _, operation := range api.Operations {
			if operation.DatasetID != api.RegistryAPIID || !registryAPIIDPattern.MatchString(operation.DatasetID) || len(operation.SourceSystem) == 0 || len(operation.SourceSystem) > 128 || !registryOperationKeyPattern.MatchString(operation.UpstreamOperationKey) || (operation.UpstreamOperationSeq != "" && !registryOperationKeyPattern.MatchString(operation.UpstreamOperationSeq)) || !registryOperationIDPattern.MatchString(operation.RegistryOperationID) || (operation.Protocol != "REST" && operation.Protocol != "SOAP") || !validMetadataField(operation.Name, operation.NameState, 1024) {
				return errors.New("invalid Registry API operation")
			}
			if _, exists := m.operationByID[operation.RegistryOperationID]; exists {
				return errors.New("duplicate Registry operation identity")
			}
			m.operationByID[operation.RegistryOperationID] = operation
			operationCount++
		}
		m.orderedAPIIndices[apiIndex] = apiIndex
		sort.SliceStable(m.APIs[apiIndex].Operations, func(i, j int) bool {
			left, right := strings.ToLower(m.APIs[apiIndex].Operations[i].Name), strings.ToLower(m.APIs[apiIndex].Operations[j].Name)
			if left == right {
				return m.APIs[apiIndex].Operations[i].RegistryOperationID < m.APIs[apiIndex].Operations[j].RegistryOperationID
			}
			return left < right
		})
		parts := []string{api.Title, api.Organization, api.Description}
		for _, operation := range api.Operations {
			parts = append(parts, operation.Name)
		}
		m.searchText[apiIndex] = strings.ToLower(strings.Join(parts, "\n"))
	}
	if operationCount != m.Counts.APIOperations || linkOperationCount != m.Counts.LinkOperations || len(institutions) != m.Counts.Institutions {
		return errors.New("Registry metadata counts disagree")
	}
	for _, link := range m.HealthCanaryLinks {
		if !registryHealthIDPattern.MatchString(link.HealthOperationID) || !registryAPIIDPattern.MatchString(link.RegistryAPIID) || !registryAPIIDPattern.MatchString(link.DatasetID) || !registryOperationKeyPattern.MatchString(link.UpstreamOperationSeq) || !registryOperationIDPattern.MatchString(link.RegistryOperationID) || !registryOperationIDPattern.MatchString(link.CLIOperationKey) || !validMetadataField(link.OperationName, "present", 1024) {
			return errors.New("invalid Registry canary link")
		}
		if _, duplicate := m.canaryByHealthID[link.HealthOperationID]; duplicate {
			return errors.New("duplicate Health canary link")
		}
		if _, duplicate := m.canaryByOpID[link.RegistryOperationID]; duplicate {
			return errors.New("duplicate Registry canary link")
		}
		apiIndex, ok := m.byID[link.RegistryAPIID]
		if !ok || link.DatasetID != link.RegistryAPIID {
			return errors.New("Registry canary link has no API")
		}
		operation, ok := m.operationByID[link.RegistryOperationID]
		if !ok || operation.DatasetID != link.DatasetID || operation.UpstreamOperationSeq != link.UpstreamOperationSeq || operation.Name != link.OperationName {
			return errors.New("Registry canary link has no exact operation")
		}
		if api := m.APIs[apiIndex]; api.RegistryAPIID != link.RegistryAPIID {
			return errors.New("Registry canary link API mismatch")
		}
		var configCanary *Canary
		for index := range canaries.Canaries {
			if canaries.Canaries[index].OperationID == link.HealthOperationID {
				configCanary = &canaries.Canaries[index]
				break
			}
		}
		if configCanary == nil {
			return errors.New("Registry canary link is not configured")
		}
		entry, ok := canaries.Entry(*configCanary)
		if !ok || entry.Aliases.DatasetID != link.DatasetID || entry.Aliases.UpstreamOperationSeq != link.UpstreamOperationSeq || entry.Aliases.OperationName != link.OperationName || entry.Aliases.CLIOperationKey != link.CLIOperationKey {
			return errors.New("Registry canary link does not match the pinned catalog")
		}
		m.canaryByHealthID[link.HealthOperationID] = link
		m.canaryByOpID[link.RegistryOperationID] = link
	}
	for _, canary := range canaries.Canaries {
		entry, ok := canaries.Entry(canary)
		if !ok || strings.TrimSpace(entry.Aliases.OperationName) == "" {
			return errors.New("invalid configured canary display name")
		}
		m.canaryDisplays = append(m.canaryDisplays, RegistryCanaryDisplay{HealthOperationID: canary.OperationID, OperationName: entry.Aliases.OperationName})
	}
	sort.SliceStable(m.orderedAPIIndices, func(i, j int) bool {
		leftAPI, rightAPI := m.APIs[m.orderedAPIIndices[i]], m.APIs[m.orderedAPIIndices[j]]
		left, right := strings.ToLower(leftAPI.Title), strings.ToLower(rightAPI.Title)
		if left == right {
			return leftAPI.RegistryAPIID < rightAPI.RegistryAPIID
		}
		return left < right
	})
	return nil
}

func validMetadataField(value, state string, maxBytes int) bool {
	if !registryMetadataStateValues[state] {
		return false
	}
	if !utf8.ValidString(value) {
		return false
	}
	if state == "present" || state == "sanitized" {
		return strings.TrimSpace(value) != "" && len(value) <= maxBytes
	}
	return value == ""
}

func (m RegistryAPIMetadata) APIByID(id string) (RegistryAPIMetadataAPI, bool) {
	index, ok := m.byID[id]
	if !ok || index < 0 || index >= len(m.APIs) {
		return RegistryAPIMetadataAPI{}, false
	}
	return m.APIs[index], true
}

func (m RegistryAPIMetadata) CanaryLinkByOperationID(id string) (RegistryHealthCanaryLink, bool) {
	link, ok := m.canaryByOpID[id]
	return link, ok
}

func (m RegistryAPIMetadata) CanaryLinkByHealthID(id string) (RegistryHealthCanaryLink, bool) {
	link, ok := m.canaryByHealthID[id]
	return link, ok
}

func (m RegistryAPIMetadata) CanaryDisplays() []RegistryCanaryDisplay {
	return append([]RegistryCanaryDisplay(nil), m.canaryDisplays...)
}

// APIPage returns a stable Korean-display-title-sorted slice without mutating
// the verified artifact or retaining any request-specific result state.
func (m RegistryAPIMetadata) APIPage(query string, page, pageSize int) ([]RegistryAPIMetadataAPI, int) {
	return m.APIPagePrioritized(query, page, pageSize, nil)
}

// APIPagePrioritized keeps the full directory deterministic while allowing a
// small, bounded set of configured/observed APIs to be surfaced first.
func (m RegistryAPIMetadata) APIPagePrioritized(query string, page, pageSize int, priorityByAPI map[string]int) ([]RegistryAPIMetadataAPI, int) {
	if page < 1 || pageSize < 1 {
		return nil, 0
	}
	needle := strings.ToLower(strings.TrimSpace(query))
	start := (page - 1) * pageSize
	items := make([]RegistryAPIMetadataAPI, 0, pageSize)
	total := 0
	order := m.orderedAPIIndices
	if len(order) == 0 && len(m.APIs) > 0 {
		order = make([]int, len(m.APIs))
		for index := range order {
			order[index] = index
		}
	}
	if len(priorityByAPI) > 0 {
		order = append([]int(nil), order...)
		sort.SliceStable(order, func(i, j int) bool {
			leftPriority, rightPriority := 2, 2
			if left, ok := priorityByAPI[m.APIs[order[i]].RegistryAPIID]; ok {
				leftPriority = left
			}
			if right, ok := priorityByAPI[m.APIs[order[j]].RegistryAPIID]; ok {
				rightPriority = right
			}
			return leftPriority < rightPriority
		})
	}
	for _, index := range order {
		if index < 0 || index >= len(m.APIs) {
			continue
		}
		if needle != "" && (index >= len(m.searchText) || !strings.Contains(m.searchText[index], needle)) {
			continue
		}
		if total >= start && len(items) < pageSize {
			items = append(items, m.APIs[index])
		}
		total++
	}
	return items, total
}
