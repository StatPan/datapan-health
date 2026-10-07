package registrymetadata

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"html"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MetadataSchemaVersion = "datapan.health-registry-api-metadata.v1"
	PinSchemaVersion      = "datapan.health-registry-api-metadata-source-pin.v1"
	MaxSourceBytes        = 160 * 1024 * 1024
	MaxRecordBytes        = 16 * 1024 * 1024
	MaxSourceAPIs         = 20000
	MaxSourceOperations   = 50000
	MaxArtifactBytes      = 32 * 1024 * 1024
	MaxTextBytes          = 8192
	MaxTitleBytes         = 1024
	MaxOrganizationBytes  = 1024
	MaxOperationNameBytes = 1024
)

var (
	sha256Pattern       = regexp.MustCompile("^[a-f0-9]{64}$")
	commitPattern       = regexp.MustCompile("^[a-f0-9]{40}$")
	identifierPattern   = regexp.MustCompile("^[A-Za-z0-9._-]{1,128}$")
	healthOperationIDRE = regexp.MustCompile("^[a-z0-9-]{1,64}$")
	urlPattern          = regexp.MustCompile("(?i)\\b(?:https?://|www\\.)[^\\s<>\"')]+")
	domainPathPattern   = regexp.MustCompile("(?i)\\b(?:[a-z0-9-]+\\.)+(?:go\\.kr|or\\.kr|co\\.kr|ac\\.kr|com|net|org|io)(?:/[a-z0-9._~!$&'()*+,;=:@%/-]*)?(?:\\?[^\\s<>\"')]+)?")
	barePathPattern     = regexp.MustCompile("(?i)(?:^|\\s)/[a-z0-9._~%+-]+(?:/[a-z0-9._~%+-]+)+")
	queryPattern        = regexp.MustCompile("[?&][a-z0-9_.-]{1,64}=[^\\s&<>\"']*")
	tagPattern          = regexp.MustCompile("(?s)<[^>]*>")
	scriptStylePattern  = regexp.MustCompile("(?is)<(?:script|style|iframe|object|noscript)\\b[^>]*>.*?</(?:script|style|iframe|object|noscript)\\s*>")
	pairedXMLPattern    = regexp.MustCompile("(?is)<(?:request|response|row|item|result|data)\\b[^>]*>.*?</(?:request|response|row|item|result|data)\\s*>")
	fencedCodePattern   = regexp.MustCompile("(?s)(?:```|~~~).*?(?:```|~~~)")
	inlineCodePattern   = regexp.MustCompile("`[^`]*`")
	markdownLinkPattern = regexp.MustCompile("\\[([^]]{1,256})\\]\\([^)]{1,1000}\\)")
	exampleMarker       = regexp.MustCompile("(?i)(요청\\s*(?:예시|샘플)|응답\\s*(?:예시|샘플)|request\\s+(?:example|sample)|response\\s+(?:example|sample)|(?:example|sample)\\s+(?:request|response))")
)

type SourcePin struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type CatalogPin struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	EntryCount int    `json:"entry_count"`
}

type ExpectedCounts struct {
	APIEntities                 int `json:"api_entities"`
	APIOperations               int `json:"api_operations"`
	LinkOperations              int `json:"link_operations"`
	OperationlessCatalogEntries int `json:"operationless_catalog_entries"`
	FiledataCatalogEntries      int `json:"filedata_catalog_entries"`
	Institutions                int `json:"institutions"`
	MatchedHealthCanaries       int `json:"matched_health_canaries"`
}

type ArtifactPin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Pin struct {
	SchemaVersion    string         `json:"schema_version"`
	RegistryRevision string         `json:"registry_revision"`
	Source           SourcePin      `json:"source"`
	Catalog          CatalogPin     `json:"catalog"`
	ExpectedCounts   ExpectedCounts `json:"expected_counts"`
	Artifact         ArtifactPin    `json:"artifact"`
}

type Counts struct {
	APIEntities                 int `json:"api_entities"`
	APIOperations               int `json:"api_operations"`
	LinkOperations              int `json:"link_operations"`
	OperationlessCatalogEntries int `json:"operationless_catalog_entries"`
	FiledataCatalogEntries      int `json:"filedata_catalog_entries"`
	Institutions                int `json:"institutions"`
	MatchedHealthCanaries       int `json:"matched_health_canaries"`
}

type SourceIdentity struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type CatalogIdentity struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	EntryCount int    `json:"entry_count"`
}

type MetadataScope struct {
	Provider                     string `json:"provider"`
	SourceSnapshotComplete       bool   `json:"source_snapshot_complete"`
	RegistryWideMetadataComplete bool   `json:"registry_wide_metadata_complete"`
	CoverageNote                 string `json:"coverage_note"`
}

type MetadataArtifact struct {
	SchemaVersion     string             `json:"schema_version"`
	RegistryRevision  string             `json:"registry_revision"`
	Scope             MetadataScope      `json:"scope"`
	Source            SourceIdentity     `json:"source"`
	Catalog           CatalogIdentity    `json:"catalog"`
	Counts            Counts             `json:"counts"`
	APIs              []API              `json:"apis"`
	HealthCanaryLinks []HealthCanaryLink `json:"health_canary_links"`
}

type API struct {
	RegistryAPIID      string      `json:"registry_api_id"`
	Provider           string      `json:"provider"`
	Title              string      `json:"title"`
	TitleState         string      `json:"title_state"`
	Organization       string      `json:"organization"`
	OrganizationState  string      `json:"organization_state"`
	Description        string      `json:"description"`
	DescriptionState   string      `json:"description_state"`
	LinkOperationCount int         `json:"link_operation_count"`
	Operations         []Operation `json:"operations"`
}

type Operation struct {
	RegistryOperationID  string `json:"registry_operation_id"`
	DatasetID            string `json:"dataset_id"`
	SourceSystem         string `json:"source_system"`
	UpstreamOperationKey string `json:"upstream_operation_key"`
	UpstreamOperationSeq string `json:"upstream_operation_seq"`
	Name                 string `json:"name"`
	NameState            string `json:"name_state"`
	Protocol             string `json:"protocol"`
}

type HealthCanaryLink struct {
	HealthOperationID    string `json:"health_operation_id"`
	RegistryAPIID        string `json:"registry_api_id"`
	RegistryOperationID  string `json:"registry_operation_id"`
	DatasetID            string `json:"dataset_id"`
	UpstreamOperationSeq string `json:"upstream_operation_seq"`
	OperationName        string `json:"operation_name"`
	CLIOperationKey      string `json:"cli_operation_key"`
}

type catalogDocument struct {
	SchemaVersion  string `json:"schema_version"`
	SourceRegistry struct {
		SHA256 string `json:"sha256"`
	} `json:"source_registry"`
	Entries []catalogEntry `json:"entries"`
}

type catalogEntry struct {
	OperationID string `json:"operation_id"`
	Provider    string `json:"provider"`
	Aliases     struct {
		DatasetID        string `json:"dataset_id"`
		OperationName    string `json:"operation_name"`
		UpstreamSequence string `json:"upstream_operation_seq"`
		CLIOperationKey  string `json:"cli_operation_key"`
	} `json:"aliases"`
}

type sourceSpec struct {
	ID           string          `json:"id"`
	Provider     string          `json:"provider"`
	Title        json.RawMessage `json:"title"`
	Organization json.RawMessage `json:"organization"`
	Description  json.RawMessage `json:"description"`
	Source       struct {
		System string `json:"system"`
		Raw    struct {
			APIType  json.RawMessage `json:"api_type"`
			ListType json.RawMessage `json:"list_type"`
		} `json:"raw"`
	} `json:"source"`
	Operations []sourceOperation `json:"operations"`
}

type sourceOperation struct {
	Name     json.RawMessage `json:"name"`
	Endpoint string          `json:"endpoint"`
	Source   struct {
		System string `json:"system"`
		Raw    struct {
			ListID            string          `json:"list_id"`
			OperationSeq      string          `json:"operation_seq"`
			SourceAPIType     json.RawMessage `json:"source_api_type"`
			SourceInterfaceID string          `json:"source_interface_id"`
			DataSN            string          `json:"data_sn"`
			OperationURL      string          `json:"operation_url"`
		} `json:"raw"`
	} `json:"source"`
}

type aliasKey struct {
	datasetID string
	sequence  string
	name      string
}

func ValidatePin(pin Pin) error {
	if pin.SchemaVersion != PinSchemaVersion || !commitPattern.MatchString(pin.RegistryRevision) {
		return errors.New("invalid registry metadata pin")
	}
	if pin.Source.Path != "data/data-go-kr.registry.json" || !sha256Pattern.MatchString(pin.Source.SHA256) || pin.Source.SizeBytes < 1 || pin.Source.SizeBytes > MaxSourceBytes {
		return errors.New("invalid registry metadata source pin")
	}
	if pin.Catalog.Path != "config/registry/health-probe-catalog.json" || !sha256Pattern.MatchString(pin.Catalog.SHA256) || pin.Catalog.EntryCount < 1 || pin.Catalog.EntryCount > 100 {
		return errors.New("invalid registry metadata catalog pin")
	}
	if pin.Artifact.Path != "config/registry/api-metadata.v1.json" || (pin.Artifact.SHA256 != "" && !sha256Pattern.MatchString(pin.Artifact.SHA256)) {
		return errors.New("invalid registry metadata artifact pin")
	}
	c := pin.ExpectedCounts
	if c.APIEntities < 1 || c.APIEntities > MaxSourceAPIs || c.APIOperations < 1 || c.APIOperations > MaxSourceOperations || c.LinkOperations < 0 || c.LinkOperations > MaxSourceOperations || c.OperationlessCatalogEntries < 0 || c.FiledataCatalogEntries < 0 || c.Institutions < 1 || c.Institutions > c.APIEntities || c.MatchedHealthCanaries != pin.Catalog.EntryCount {
		return errors.New("invalid registry metadata expected counts")
	}
	return nil
}

// Project turns a pinned Registry source snapshot into a safe metadata-only
// inventory. Source records are decoded one at a time; endpoints, parameters,
// examples, and response content are never represented in the output types.
func Project(source io.Reader, catalogBytes []byte, pin Pin) (MetadataArtifact, []byte, error) {
	if err := ValidatePin(pin); err != nil {
		return MetadataArtifact{}, nil, err
	}
	if len(catalogBytes) == 0 || len(catalogBytes) > 1024*1024 {
		return MetadataArtifact{}, nil, errors.New("health catalog exceeds size budget")
	}
	catalogHash := sha256.Sum256(catalogBytes)
	if hex.EncodeToString(catalogHash[:]) != pin.Catalog.SHA256 {
		return MetadataArtifact{}, nil, errors.New("health catalog digest mismatch")
	}
	catalog, err := decodeCatalog(catalogBytes, pin)
	if err != nil {
		return MetadataArtifact{}, nil, err
	}
	byAlias := make(map[aliasKey]catalogEntry, len(catalog.Entries))
	for _, entry := range catalog.Entries {
		key := aliasKey{datasetID: entry.Aliases.DatasetID, sequence: entry.Aliases.UpstreamSequence, name: entry.Aliases.OperationName}
		if _, exists := byAlias[key]; exists {
			return MetadataArtifact{}, nil, errors.New("health catalog aliases are ambiguous")
		}
		byAlias[key] = entry
	}

	inputHash := sha256.New()
	counter := &countingHashWriter{hash: inputHash}
	limited := &io.LimitedReader{R: source, N: MaxSourceBytes + 1}
	stream := io.TeeReader(limited, counter)
	array, err := newJSONArrayReader(stream)
	if err != nil {
		return MetadataArtifact{}, nil, errors.New("registry source must be a top-level JSON array")
	}

	artifact := MetadataArtifact{
		SchemaVersion:    MetadataSchemaVersion,
		RegistryRevision: pin.RegistryRevision,
		Scope: MetadataScope{
			Provider:                     "data.go.kr",
			SourceSnapshotComplete:       true,
			RegistryWideMetadataComplete: false,
			CoverageNote:                 "Complete for the pinned data.go.kr source only; not a complete inventory of all Registry adapters.",
		},
		Source:            SourceIdentity{Path: pin.Source.Path, SHA256: pin.Source.SHA256, SizeBytes: pin.Source.SizeBytes},
		Catalog:           CatalogIdentity{Path: pin.Catalog.Path, SHA256: pin.Catalog.SHA256, EntryCount: pin.Catalog.EntryCount},
		APIs:              make([]API, 0, pin.ExpectedCounts.APIEntities),
		HealthCanaryLinks: make([]HealthCanaryLink, 0, pin.Catalog.EntryCount),
	}
	counts := Counts{}
	seenAPIIDs := make(map[string]struct{}, pin.ExpectedCounts.APIEntities)
	seenOperationIDs := make(map[string]struct{}, pin.ExpectedCounts.APIOperations)
	institutions := make(map[string]struct{}, pin.ExpectedCounts.Institutions)
	matchedCanaries := make(map[string]int, len(catalog.Entries))

	for {
		record, more, err := array.NextRecord()
		if err != nil {
			return MetadataArtifact{}, nil, err
		}
		if !more {
			break
		}
		var spec sourceSpec
		if err := json.Unmarshal(record, &spec); err != nil {
			return MetadataArtifact{}, nil, errors.New("registry source record is invalid")
		}
		if len(artifact.APIs) >= MaxSourceAPIs {
			return MetadataArtifact{}, nil, errors.New("registry source API count exceeds budget")
		}
		if !identifierPattern.MatchString(spec.ID) || spec.Provider != "data.go.kr" {
			return MetadataArtifact{}, nil, errors.New("registry API identity is missing or unsafe")
		}
		if _, exists := seenAPIIDs[spec.ID]; exists {
			return MetadataArtifact{}, nil, errors.New("registry API identity is duplicated")
		}
		seenAPIIDs[spec.ID] = struct{}{}
		counts.APIEntities++

		title, titleState := projectText(spec.Title, MaxTitleBytes)
		organization, organizationState := projectText(spec.Organization, MaxOrganizationBytes)
		description, descriptionState := projectText(spec.Description, MaxTextBytes)
		if organizationState == "present" || organizationState == "sanitized" {
			institutions[organization] = struct{}{}
		}

		api := API{
			RegistryAPIID:     spec.ID,
			Provider:          spec.Provider,
			Title:             title,
			TitleState:        titleState,
			Organization:      organization,
			OrganizationState: organizationState,
			Description:       description,
			DescriptionState:  descriptionState,
			Operations:        make([]Operation, 0, len(spec.Operations)),
		}
		if len(spec.Operations) == 0 {
			counts.OperationlessCatalogEntries++
			listType, _ := decodeJSONText(spec.Source.Raw.ListType)
			if listType == "PR0010" {
				counts.FiledataCatalogEntries++
			}
		}

		for _, sourceOp := range spec.Operations {
			operationProtocol := protocolFor(spec, sourceOp)
			if operationProtocol == "" {
				api.LinkOperationCount++
				counts.LinkOperations++
				continue
			}
			sourceSystem := sourceOp.Source.System
			if !identifierPattern.MatchString(sourceSystem) {
				return MetadataArtifact{}, nil, errors.New("registry API source system is missing or unsafe")
			}
			if counts.APIOperations >= MaxSourceOperations {
				return MetadataArtifact{}, nil, errors.New("registry API operation count exceeds budget")
			}
			nameRaw, nameOK := decodeJSONText(sourceOp.Name)
			if !nameOK || strings.TrimSpace(nameRaw) == "" {
				return MetadataArtifact{}, nil, errors.New("registry API operation name is missing")
			}
			sequence := sourceOp.Source.Raw.OperationSeq
			if sourceOp.Source.Raw.ListID != "" && sourceOp.Source.Raw.ListID != spec.ID {
				return MetadataArtifact{}, nil, errors.New("registry API operation parent identity mismatch")
			}
			upstreamKey := sequence
			if sourceOp.Source.System == "safetydata.go.kr" {
				upstreamKey = sourceOp.Source.Raw.SourceInterfaceID
				if upstreamKey == "" {
					upstreamKey = sourceOp.Source.Raw.DataSN
				}
			}
			if !identifierPattern.MatchString(upstreamKey) {
				return MetadataArtifact{}, nil, errors.New("registry API operation key is missing or unsafe")
			}
			if sequence != "" && !identifierPattern.MatchString(sequence) {
				return MetadataArtifact{}, nil, errors.New("registry API operation sequence is unsafe")
			}
			methodOrAction := "GET"
			if operationProtocol == "SOAP" {
				methodOrAction = sourceOp.Source.Raw.OperationURL
				if methodOrAction == "" {
					methodOrAction = nameRaw
				}
			}
			operationID := lengthPrefixedSHA256([]string{
				"data.go.kr", spec.ID, operationProtocol, sourceSystem,
				upstreamKey, sourceOp.Endpoint, methodOrAction, nameRaw,
			})
			if _, exists := seenOperationIDs[operationID]; exists {
				return MetadataArtifact{}, nil, errors.New("registry API operation identity is duplicated")
			}
			seenOperationIDs[operationID] = struct{}{}
			counts.APIOperations++
			name, nameState := projectText(sourceOp.Name, MaxOperationNameBytes)
			api.Operations = append(api.Operations, Operation{
				RegistryOperationID:  operationID,
				DatasetID:            spec.ID,
				SourceSystem:         sourceSystem,
				UpstreamOperationKey: upstreamKey,
				UpstreamOperationSeq: sequence,
				Name:                 name,
				NameState:            nameState,
				Protocol:             operationProtocol,
			})

			key := aliasKey{datasetID: spec.ID, sequence: sequence, name: nameRaw}
			if canary, ok := byAlias[key]; ok {
				if matchedCanaries[canary.OperationID] != 0 {
					return MetadataArtifact{}, nil, errors.New("health catalog alias matches multiple source operations")
				}
				// The CLI operation key is a Health-local selector. Its canonical
				// endpoint can include a Health catalog correction that is not
				// represented by the raw Registry endpoint, so the source join is
				// established by the exact Registry aliases above, not that key.
				matchedCanaries[canary.OperationID]++
				operationName, state := projectText(sourceOp.Name, MaxOperationNameBytes)
				if state != "present" && state != "sanitized" {
					return MetadataArtifact{}, nil, errors.New("health catalog operation name is unsafe")
				}
				artifact.HealthCanaryLinks = append(artifact.HealthCanaryLinks, HealthCanaryLink{
					HealthOperationID:    canary.OperationID,
					RegistryAPIID:        spec.ID,
					RegistryOperationID:  operationID,
					DatasetID:            spec.ID,
					UpstreamOperationSeq: sequence,
					OperationName:        operationName,
					CLIOperationKey:      canary.Aliases.CLIOperationKey,
				})
			}
		}
		sort.Slice(api.Operations, func(i, j int) bool {
			return api.Operations[i].RegistryOperationID < api.Operations[j].RegistryOperationID
		})
		artifact.APIs = append(artifact.APIs, api)
	}
	if err := array.DrainAndValidateTrailing(); err != nil {
		return MetadataArtifact{}, nil, errors.New("registry source could not be fully read")
	}
	if counter.n > MaxSourceBytes || counter.n != pin.Source.SizeBytes {
		return MetadataArtifact{}, nil, errors.New("registry source size mismatch")
	}
	actualSourceHash := hex.EncodeToString(inputHash.Sum(nil))
	if actualSourceHash != pin.Source.SHA256 {
		return MetadataArtifact{}, nil, errors.New("registry source digest mismatch")
	}
	for _, entry := range catalog.Entries {
		if matchedCanaries[entry.OperationID] != 1 {
			return MetadataArtifact{}, nil, errors.New("health catalog operation does not join uniquely to registry source")
		}
	}
	counts.Institutions = len(institutions)
	counts.MatchedHealthCanaries = len(artifact.HealthCanaryLinks)
	if counts != countsFromExpected(pin.ExpectedCounts) {
		return MetadataArtifact{}, nil, fmt.Errorf("registry metadata counts mismatch: got %+v", counts)
	}
	if len(artifact.APIs) != counts.APIEntities || counts.APIOperations != len(seenOperationIDs) || len(artifact.HealthCanaryLinks) != pin.Catalog.EntryCount {
		return MetadataArtifact{}, nil, errors.New("registry metadata identity reconciliation failed")
	}
	artifact.Counts = counts
	sort.Slice(artifact.APIs, func(i, j int) bool { return artifact.APIs[i].RegistryAPIID < artifact.APIs[j].RegistryAPIID })
	sort.Slice(artifact.HealthCanaryLinks, func(i, j int) bool {
		return artifact.HealthCanaryLinks[i].HealthOperationID < artifact.HealthCanaryLinks[j].HealthOperationID
	})

	encoded, err := json.MarshalIndent(artifact, "", "  ")
	if err != nil || len(encoded) > MaxArtifactBytes {
		return MetadataArtifact{}, nil, errors.New("registry metadata artifact exceeds output budget")
	}
	encoded = append(encoded, '\n')
	return artifact, encoded, nil
}

func decodeCatalog(data []byte, pin Pin) (catalogDocument, error) {
	var catalog catalogDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&catalog); err != nil || ensureEOF(decoder) != nil {
		return catalogDocument{}, errors.New("health catalog is invalid")
	}
	if catalog.SchemaVersion != "datapan.health-probe-catalog.v1" || catalog.SourceRegistry.SHA256 != pin.Source.SHA256 || len(catalog.Entries) != pin.Catalog.EntryCount {
		return catalogDocument{}, errors.New("health catalog source binding mismatch")
	}
	seenIDs := map[string]bool{}
	for _, entry := range catalog.Entries {
		if !healthOperationIDRE.MatchString(entry.OperationID) || seenIDs[entry.OperationID] || entry.Provider != "data.go.kr" || !identifierPattern.MatchString(entry.Aliases.DatasetID) || !identifierPattern.MatchString(entry.Aliases.UpstreamSequence) || entry.Aliases.OperationName == "" || !sha256Pattern.MatchString(entry.Aliases.CLIOperationKey) {
			return catalogDocument{}, errors.New("health catalog entry identity is invalid")
		}
		seenIDs[entry.OperationID] = true
	}
	return catalog, nil
}

func projectText(raw json.RawMessage, maxBytes int) (string, string) {
	if len(raw) == 0 {
		return "", "missing"
	}
	value, ok := decodeJSONText(raw)
	if !ok {
		return "", "invalid_source"
	}
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", "blank"
	}
	if len(trimmed) > maxBytes || len(trimmed) > MaxTextBytes || !utf8.ValidString(trimmed) {
		return "", "redacted_unsafe"
	}
	cleaned := sanitizeText(trimmed)
	if cleaned == "" {
		return "", "redacted_unsafe"
	}
	if len(cleaned) > maxBytes || len(cleaned) > MaxTextBytes {
		return "", "redacted_unsafe"
	}
	if cleaned != trimmed {
		return cleaned, "sanitized"
	}
	return cleaned, "present"
}

func sanitizeText(input string) string {
	value := html.UnescapeString(input)
	value = scriptStylePattern.ReplaceAllString(value, " ")
	value = pairedXMLPattern.ReplaceAllString(value, " ")
	value = fencedCodePattern.ReplaceAllString(value, " ")
	value = inlineCodePattern.ReplaceAllString(value, " ")
	value = markdownLinkPattern.ReplaceAllString(value, "$1")
	value = redactStructuredJSON(value)
	if loc := exampleMarker.FindStringIndex(value); loc != nil {
		value = value[:loc[0]]
	}
	value = tagPattern.ReplaceAllString(value, " ")
	value = urlPattern.ReplaceAllString(value, " ")
	value = domainPathPattern.ReplaceAllString(value, " ")
	value = barePathPattern.ReplaceAllString(value, " ")
	value = queryPattern.ReplaceAllString(value, " ")
	var cleaned strings.Builder
	for _, r := range value {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			continue
		}
		cleaned.WriteRune(r)
	}
	return strings.Join(strings.Fields(cleaned.String()), " ")
}

func redactStructuredJSON(input string) string {
	var cleaned strings.Builder
	for offset := 0; offset < len(input); {
		if input[offset] == '{' || input[offset] == '[' {
			if end, ok := jsonValueEnd(input, offset); ok && json.Valid([]byte(input[offset:end])) {
				cleaned.WriteByte(' ')
				offset = end
				continue
			}
		}
		cleaned.WriteByte(input[offset])
		offset++
	}
	return cleaned.String()
}

func jsonValueEnd(input string, start int) (int, bool) {
	openers := make([]byte, 0, 8)
	inString := false
	escaped := false
	for offset := start; offset < len(input); offset++ {
		current := input[offset]
		if inString {
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		switch current {
		case '"':
			inString = true
		case '{', '[':
			openers = append(openers, current)
		case '}', ']':
			if len(openers) == 0 || (current == '}' && openers[len(openers)-1] != '{') || (current == ']' && openers[len(openers)-1] != '[') {
				return 0, false
			}
			openers = openers[:len(openers)-1]
			if len(openers) == 0 {
				return offset + 1, true
			}
		}
	}
	return 0, false
}

func protocolFor(spec sourceSpec, operation sourceOperation) string {
	if operation.Source.System == "safetydata.go.kr" {
		if protocol, ok := decodeJSONText(operation.Source.Raw.SourceAPIType); ok && protocol == "REST" {
			return "REST"
		}
	}
	protocol, _ := decodeJSONText(spec.Source.Raw.APIType)
	if protocol == "REST" || protocol == "SOAP" {
		return protocol
	}
	return ""
}

func lengthPrefixedSHA256(fields []string) string {
	digest := sha256.New()
	for _, field := range fields {
		encoded := []byte(field)
		_, _ = fmt.Fprintf(digest, "%d:", len(encoded))
		_, _ = digest.Write(encoded)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func decodeJSONText(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || !utf8.ValidString(value) {
		return "", false
	}
	return value, true
}

func countsFromExpected(expected ExpectedCounts) Counts {
	return Counts{
		APIEntities:                 expected.APIEntities,
		APIOperations:               expected.APIOperations,
		LinkOperations:              expected.LinkOperations,
		OperationlessCatalogEntries: expected.OperationlessCatalogEntries,
		FiledataCatalogEntries:      expected.FiledataCatalogEntries,
		Institutions:                expected.Institutions,
		MatchedHealthCanaries:       expected.MatchedHealthCanaries,
	}
}

func ensureEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

type countingHashWriter struct {
	hash hash.Hash
	n    int64
}

func (w *countingHashWriter) Write(p []byte) (int, error) {
	n, err := w.hash.Write(p)
	w.n += int64(n)
	return n, err
}

// jsonArrayReader finds complete top-level object records before decoding
// them, so a single oversized record cannot be allocated into sourceSpec.
// A JSON decoder later validates each bounded slice in full.
type jsonArrayReader struct {
	reader     *bufio.Reader
	needComma  bool
	afterComma bool
	closed     bool
}

func newJSONArrayReader(reader io.Reader) (*jsonArrayReader, error) {
	buffered := bufio.NewReader(reader)
	first, err := nextNonSpace(buffered)
	if err != nil || first != '[' {
		return nil, errors.New("top-level JSON value is not an array")
	}
	return &jsonArrayReader{reader: buffered}, nil
}

func (r *jsonArrayReader) NextRecord() ([]byte, bool, error) {
	if r.closed {
		return nil, false, nil
	}
	if r.needComma {
		delimiter, err := nextNonSpace(r.reader)
		if err != nil {
			return nil, false, errors.New("registry source array is incomplete")
		}
		if delimiter == ']' {
			r.closed = true
			return nil, false, nil
		}
		if delimiter != ',' {
			return nil, false, errors.New("registry source array separator is invalid")
		}
		r.needComma = false
		r.afterComma = true
	}

	first, err := nextNonSpace(r.reader)
	if err != nil {
		return nil, false, errors.New("registry source array is incomplete")
	}
	if first == ']' {
		if r.afterComma {
			return nil, false, errors.New("registry source array has a trailing comma")
		}
		r.closed = true
		return nil, false, nil
	}
	if first != '{' {
		return nil, false, errors.New("registry source records must be objects")
	}
	r.afterComma = false

	var record bytes.Buffer
	if err := appendBoundedByte(&record, first); err != nil {
		return nil, false, err
	}
	depth := 1
	inString := false
	escaped := false
	for depth > 0 {
		current, err := r.reader.ReadByte()
		if err != nil {
			return nil, false, errors.New("registry source record is incomplete")
		}
		if err := appendBoundedByte(&record, current); err != nil {
			return nil, false, err
		}
		if inString {
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		switch current {
		case '"':
			inString = true
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth < 0 {
				return nil, false, errors.New("registry source record has invalid nesting")
			}
		}
	}
	r.needComma = true
	return record.Bytes(), true, nil
}

func (r *jsonArrayReader) DrainAndValidateTrailing() error {
	if !r.closed {
		return errors.New("registry source array is incomplete")
	}
	for {
		current, err := r.reader.ReadByte()
		if err == io.EOF {
			return nil
		}
		if err != nil || (current != ' ' && current != '\t' && current != '\r' && current != '\n') {
			return errors.New("registry source has trailing data")
		}
	}
}

func nextNonSpace(reader *bufio.Reader) (byte, error) {
	for {
		current, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		if current != ' ' && current != '\t' && current != '\r' && current != '\n' {
			return current, nil
		}
	}
}

func appendBoundedByte(buffer *bytes.Buffer, value byte) error {
	if buffer.Len() >= MaxRecordBytes {
		return errors.New("registry source record exceeds size budget")
	}
	return buffer.WriteByte(value)
}
