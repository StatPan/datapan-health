package health

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	publicOperationDisplaySchemaVersion  = "datapan.health-operator-operation-display.v1"
	acceptedPublicOperationDisplaySHA256 = "15e02c34feb50c65bb59a354e683e7c63c42eee8367a932c4aa4cf7840d87a2e"
	publicOperationDisplayMaxBytes       = 16 * 1024
)

var errPublicOperationDisplayUnavailable = errors.New("verified operator operation display metadata unavailable")

// PublicOperationDisplayMetadata is a byte-pinned, operator-authored Korean
// display layer for the four known Registry scopes that lack API-purpose
// metadata. It cannot change admission, inventory, or observation state.
type PublicOperationDisplayMetadata struct {
	verified bool
	byID     map[string]operatorOperationDisplayEntry
}

type operatorOperationDisplayDocument struct {
	SchemaVersion       string                          `json:"schema_version"`
	Authority           string                          `json:"authority"`
	RegistryRevision    string                          `json:"registry_revision"`
	RegistryManifestSHA string                          `json:"registry_manifest_sha256"`
	RegistrySchemaSHA   string                          `json:"registry_schema_sha256"`
	Entries             []operatorOperationDisplayEntry `json:"entries"`
}

type operatorOperationDisplayEntry struct {
	SourceID               string                         `json:"source_id"`
	RegistryOperationID    string                         `json:"registry_operation_id"`
	IdentitySource         operatorDisplaySource          `json:"identity_source"`
	OperatorLabelKO        string                         `json:"operator_label_ko"`
	OperatorLabelAuthority string                         `json:"operator_label_authority"`
	OfficialAPITitle       operatorDisplayField           `json:"official_api_title"`
	OfficialPurpose        operatorDisplayField           `json:"official_purpose"`
	GuideTitle             operatorDisplayField           `json:"guide_title"`
	ServiceStatus          operatorDisplayField           `json:"service_status"`
	DocumentSource         *operatorDisplayDocumentSource `json:"document_source"`
}

type operatorDisplayField struct {
	Value string `json:"value"`
	State string `json:"state"`
}

type operatorDisplaySource struct {
	Path      string `json:"path"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type operatorDisplayDocumentSource struct {
	Path      string                   `json:"path"`
	SHA256    string                   `json:"sha256"`
	SizeBytes int64                    `json:"size_bytes"`
	Facts     []operatorDisplayFactRef `json:"facts"`
}

type operatorDisplayFactRef struct {
	Field        string `json:"field"`
	Status       string `json:"status"`
	SourceID     string `json:"source_id"`
	EvidenceKind string `json:"evidence_kind"`
	ByteStart    int64  `json:"byte_start"`
	ByteEnd      int64  `json:"byte_end"`
}

// LoadPublicOperationDisplayMetadata accepts only the exact reviewed artifact
// whose Registry manifest, sidecar hashes, and operation identities are
// embedded in its content and locked by this source revision.
func LoadPublicOperationDisplayMetadata(path, registryEvidenceRoot string) (PublicOperationDisplayMetadata, error) {
	data, err := readLimitedMetadataFile(path, publicOperationDisplayMaxBytes)
	if err != nil || len(data) == 0 {
		return PublicOperationDisplayMetadata{}, errPublicOperationDisplayUnavailable
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != acceptedPublicOperationDisplaySHA256 {
		return PublicOperationDisplayMetadata{}, errPublicOperationDisplayUnavailable
	}
	var document operatorOperationDisplayDocument
	if decodeStrictJSON(data, &document) != nil || !validOperatorOperationDisplayDocument(document) {
		return PublicOperationDisplayMetadata{}, errPublicOperationDisplayUnavailable
	}
	sidecars, err := verifyRegistry760DisplayEvidence(registryEvidenceRoot)
	if err != nil {
		return PublicOperationDisplayMetadata{}, errPublicOperationDisplayUnavailable
	}
	entries := make(map[string]operatorOperationDisplayEntry, len(document.Entries))
	for _, entry := range document.Entries {
		if entry.DocumentSource != nil {
			sidecar, ok := sidecars[registryOperationLookupKey(entry.SourceID, entry.RegistryOperationID)]
			if !ok || !operatorDisplayMatchesSidecar(entry, sidecar) {
				return PublicOperationDisplayMetadata{}, errPublicOperationDisplayUnavailable
			}
		}
		entries[registryOperationLookupKey(entry.SourceID, entry.RegistryOperationID)] = entry
	}
	return PublicOperationDisplayMetadata{verified: true, byID: entries}, nil
}

func validOperatorOperationDisplayDocument(document operatorOperationDisplayDocument) bool {
	if document.SchemaVersion != publicOperationDisplaySchemaVersion || document.Authority != "operator_interpretation" ||
		document.RegistryRevision != registry760Revision ||
		document.RegistryManifestSHA != registry760ManifestSHA256 ||
		document.RegistrySchemaSHA != registry760EvidenceSchemaSHA256 || len(document.Entries) != 4 {
		return false
	}
	expected := []struct {
		sourceID, operationID, identityPath, identitySHA, label string
		identityBytes                                           int64
	}{
		{"ecos", "ecos-statistic-search-102y004", "reports/ecos/operation-denominator.json", "d8619c61c2a718547ad5867b0125b74c21cf46d8cc3b74f369062e087387c62b", "ECOS 통계 검색", 961},
		{"kosis", "kosis-statistics-data-dt-1b41", "reports/kosis/operation-denominator.json", "03c57ba3715b713d3ecac7be0cd5147d5d4f19187a79fb810dfce8a031255e9b", "KOSIS 통계 자료", 1712},
		{"open_assembly", "open-assembly-opensrvapi-list", "reports/open-assembly/operation-denominator.json", "d14aab4e423b66f5bb7539c87d1ec34634ac85a06d10c2dcbc9369dba4df7e52", "국회 Open API 목록", 930},
		{"seoul_open_data", "seoul-open-data-subway-station-list", "reports/seoul-open-data/operation-denominator.json", "7c44a8357903f223df195e6e48165b5fe058e4372bdcfe7c3022af80b5266b54", "서울 지하철역 목록", 970},
	}
	seen := make(map[string]struct{}, len(expected))
	for index, want := range expected {
		entry := document.Entries[index]
		identity := registryOperationLookupKey(entry.SourceID, entry.RegistryOperationID)
		if _, duplicate := seen[identity]; duplicate {
			return false
		}
		seen[identity] = struct{}{}
		if entry.SourceID != want.sourceID || entry.RegistryOperationID != want.operationID ||
			entry.IdentitySource.Path != want.identityPath || entry.IdentitySource.SHA256 != want.identitySHA || entry.IdentitySource.SizeBytes != want.identityBytes ||
			entry.OperatorLabelKO != want.label || entry.OperatorLabelAuthority != "operator_interpretation" ||
			safePublicOperationReadText(entry.OperatorLabelKO, 128, 64) == "" {
			return false
		}
	}
	if !validOperatorDisplayEntry(document.Entries[0], false, false, false, false, false) || !validOperatorDisplayEntry(document.Entries[2], false, false, false, false, false) {
		return false
	}
	kosis := document.Entries[1]
	if !validOperatorDisplayEntry(kosis, false, false, true, false, true) || kosis.GuideTitle.Value != "통계표선택 방법" ||
		kosis.DocumentSource == nil || kosis.DocumentSource.Path != "reports/operation-document-evidence/source-scopes/kosis-statistics-data-dt-1b41.json" ||
		kosis.DocumentSource.SHA256 != "74c32e047d9421894ca952d4820b9310336d1a827551c90c49a0427bb9ac5b4f" || kosis.DocumentSource.SizeBytes != 111121 || len(kosis.DocumentSource.Facts) != 2 {
		return false
	}
	if !validOperatorDisplayFact(kosis.DocumentSource.Facts[0], "guide_title", "documented", "kosis_official_devguide", "official_operation_title", 26473, 26495) ||
		!validOperatorDisplayFact(kosis.DocumentSource.Facts[1], "official_purpose", "not_found_in_parsed_operation_sources", "", "", 0, 0) {
		return false
	}
	seoul := document.Entries[3]
	if !validOperatorDisplayEntry(seoul, true, true, false, true, true) || seoul.OfficialAPITitle.Value != "서울교통공사_노선별 지하철역 정보" ||
		seoul.OfficialPurpose.Value != "서울교통공사에서 제공하는 1~8호선, 9호선 2~3단계(언주~중앙보훈병원) 노선별 지하철역을 제공하는 서비스 입니다." ||
		seoul.ServiceStatus.Value != "terminated" || seoul.DocumentSource == nil ||
		seoul.DocumentSource.Path != "reports/operation-document-evidence/source-scopes/seoul-open-data-subway-station-list.json" ||
		seoul.DocumentSource.SHA256 != "498dc88551ce046316f1e3a233bc1cceead3ae3d7d856b01e01b50ebd0ee00c4" || seoul.DocumentSource.SizeBytes != 117708 || len(seoul.DocumentSource.Facts) != 3 {
		return false
	}
	return validOperatorDisplayFact(seoul.DocumentSource.Facts[0], "official_api_title", "documented", "seoul_official_dataset_view", "official_operation_title", 51505, 51657) &&
		validOperatorDisplayFact(seoul.DocumentSource.Facts[1], "official_purpose", "documented", "seoul_official_dataset_view", "official_operation_purpose", 51716, 51869) &&
		validOperatorDisplayFact(seoul.DocumentSource.Facts[2], "service_status", "documented", "seoul_official_dataset_view", "official_service_termination_notice", 85007, 85057)
}

func validOperatorDisplayEntry(entry operatorOperationDisplayEntry, title, purpose, guide, terminated, hasDocument bool) bool {
	wantTitle, wantPurpose, wantGuide, wantStatus := "missing", "missing", "missing", "unknown"
	if title {
		wantTitle = "documented"
	}
	if purpose {
		wantPurpose = "documented"
	}
	if guide {
		wantGuide = "documented"
	}
	if terminated {
		wantStatus = "documented"
	}
	return validOperatorDisplayField(entry.OfficialAPITitle, wantTitle) && validOperatorDisplayField(entry.OfficialPurpose, wantPurpose) &&
		validOperatorDisplayField(entry.GuideTitle, wantGuide) && validOperatorDisplayField(entry.ServiceStatus, wantStatus) &&
		hasDocument == (entry.DocumentSource != nil)
}

func validOperatorDisplayField(field operatorDisplayField, state string) bool {
	if field.State != state {
		return false
	}
	if state == "missing" || state == "unknown" {
		return field.Value == ""
	}
	return safePublicOperationReadText(field.Value, 8192, 8192) != ""
}

func validOperatorDisplayFact(fact operatorDisplayFactRef, field, status, sourceID, evidenceKind string, start, end int64) bool {
	return fact.Field == field && fact.Status == status && fact.SourceID == sourceID && fact.EvidenceKind == evidenceKind && fact.ByteStart == start && fact.ByteEnd == end
}

func operatorDisplayMatchesSidecar(entry operatorOperationDisplayEntry, sidecar registry760EvidenceSidecar) bool {
	if entry.SourceID != sidecar.Identity.SourceID || entry.RegistryOperationID != sidecar.Identity.OperationID || entry.DocumentSource == nil {
		return false
	}
	switch entry.SourceID {
	case "kosis":
		return entry.GuideTitle.State == sidecar.OperationDocument.Title.Status && sidecar.OperationDocument.Title.Value != nil && entry.GuideTitle.Value == *sidecar.OperationDocument.Title.Value &&
			entry.OfficialAPITitle.State == "missing" && entry.OfficialPurpose.State == "missing" && sidecar.OperationDocument.Purpose.Status == "not_found_in_parsed_operation_sources" && sidecar.OperationDocument.Purpose.Value == nil &&
			entry.ServiceStatus.State == "unknown"
	case "seoul_open_data":
		if sidecar.OperationDocument.ServiceStatus == nil || sidecar.OperationDocument.Title.Value == nil || sidecar.OperationDocument.Purpose.Value == nil {
			return false
		}
		return entry.OfficialAPITitle.State == sidecar.OperationDocument.Title.Status && entry.OfficialAPITitle.Value == *sidecar.OperationDocument.Title.Value &&
			entry.OfficialPurpose.State == sidecar.OperationDocument.Purpose.Status && entry.OfficialPurpose.Value == *sidecar.OperationDocument.Purpose.Value &&
			entry.ServiceStatus.State == sidecar.OperationDocument.ServiceStatus.Status && entry.ServiceStatus.Value == sidecar.OperationDocument.ServiceStatus.Classification
	default:
		return false
	}
}

func registryOperationLookupKey(sourceID, operationID string) string {
	return strings.ToLower(sourceID) + "\x00" + strings.ToLower(operationID)
}

func (metadata PublicOperationDisplayMetadata) entry(sourceID, operationID string) (operatorOperationDisplayEntry, bool) {
	if !metadata.verified {
		return operatorOperationDisplayEntry{}, false
	}
	entry, ok := metadata.byID[registryOperationLookupKey(sourceID, operationID)]
	return entry, ok
}

func clonePublicOperationDisplayMetadata(metadata PublicOperationDisplayMetadata) (PublicOperationDisplayMetadata, error) {
	if !metadata.verified || len(metadata.byID) != 4 {
		return PublicOperationDisplayMetadata{}, errPublicOperationDisplayUnavailable
	}
	copyEntries := make(map[string]operatorOperationDisplayEntry, len(metadata.byID))
	for key, entry := range metadata.byID {
		copyEntry := entry
		if entry.DocumentSource != nil {
			document := *entry.DocumentSource
			document.Facts = append([]operatorDisplayFactRef(nil), entry.DocumentSource.Facts...)
			copyEntry.DocumentSource = &document
		}
		copyEntries[key] = copyEntry
	}
	if len(copyEntries) != 4 {
		return PublicOperationDisplayMetadata{}, fmt.Errorf("%w: invalid entry set", errPublicOperationDisplayUnavailable)
	}
	return PublicOperationDisplayMetadata{verified: true, byID: copyEntries}, nil
}
