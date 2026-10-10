package health

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/StatPan/datapan-health/schemas"
)

const (
	registry760Revision             = "6e52aa59d79afa0371423ead8c287a05c4ab6210"
	registry760ManifestSHA256       = "9b95b298a8186d0f71624869bb9d7bd4317ee736ae236797c56c2af69de216cc"
	registry760EvidenceSchemaSHA256 = "d6edb7dad63b9d7cdac6753fc02cba962cb8d96d7c01119c031935abfc973108"
	maxRegistry760ManifestBytes     = 256 * 1024
	maxRegistry760SchemaBytes       = 64 * 1024
	maxRegistry760EvidenceBytes     = 128 * 1024
)

type registry760Manifest struct {
	SchemaVersion  string                    `json:"schema_version"`
	GeneratedAt    string                    `json:"generated_at"`
	DatapanVersion string                    `json:"datapan_version"`
	Provider       string                    `json:"provider"`
	SourceRegistry string                    `json:"source_registry"`
	OutputDir      string                    `json:"output_dir"`
	ArtifactCount  int                       `json:"artifact_count"`
	Artifacts      []registry760ManifestItem `json:"artifacts"`
}

type registry760ManifestItem struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Schema string `json:"schema,omitempty"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type registry760EvidenceSidecar struct {
	SchemaVersion     string                       `json:"schema_version"`
	Identity          registry760EvidenceIdentity  `json:"identity"`
	OperationDocument registry760OperationDocument `json:"operation_document"`
}

type registry760EvidenceIdentity struct {
	SourceID      string `json:"source_id"`
	OperationID   string `json:"operation_id"`
	Provider      string `json:"provider"`
	Protocol      string `json:"protocol"`
	OperationName string `json:"operation_name"`
}

type registry760OperationDocument struct {
	Title         registry760EvidenceField  `json:"title"`
	Purpose       registry760EvidenceField  `json:"purpose"`
	ServiceStatus *registry760ServiceStatus `json:"service_status"`
}

type registry760EvidenceField struct {
	Value      *string                     `json:"value"`
	Status     string                      `json:"status"`
	SourceRefs []registry760EvidenceSource `json:"source_refs"`
}

type registry760ServiceStatus struct {
	Classification string                      `json:"classification"`
	Status         string                      `json:"status"`
	SourceRefs     []registry760EvidenceSource `json:"source_refs"`
}

type registry760EvidenceSource struct {
	EvidenceKind string                   `json:"evidence_kind"`
	Locator      registry760EvidenceEntry `json:"locator"`
}

type registry760EvidenceEntry struct {
	SourceID  string `json:"source_id"`
	Kind      string `json:"kind"`
	ByteStart int64  `json:"byte_start"`
	ByteEnd   int64  `json:"byte_end"`
}

// verifyRegistry760DisplayEvidence proves the two selected document facts are
// present in the exact release manifest before returning a typed projection.
// It reads only the manifest, schema, and the two required sidecars.
func verifyRegistry760DisplayEvidence(root string) (map[string]registry760EvidenceSidecar, error) {
	manifestBytes, err := readLimitedMetadataFile(filepath.Join(root, "manifest.json"), maxRegistry760ManifestBytes)
	if err != nil || digestSHA256(manifestBytes) != registry760ManifestSHA256 {
		return nil, errPublicOperationDisplayUnavailable
	}
	var manifest registry760Manifest
	if decodeStrictJSON(manifestBytes, &manifest) != nil || manifest.SchemaVersion != "datapan.release-manifest.v1" ||
		manifest.ArtifactCount != len(manifest.Artifacts) || manifest.ArtifactCount != 385 {
		return nil, errPublicOperationDisplayUnavailable
	}
	items := make(map[string]registry760ManifestItem, len(manifest.Artifacts))
	for _, item := range manifest.Artifacts {
		if item.Path == "" || filepath.ToSlash(filepath.Clean(item.Path)) != item.Path {
			return nil, errPublicOperationDisplayUnavailable
		}
		if _, duplicate := items[item.Path]; duplicate {
			return nil, errPublicOperationDisplayUnavailable
		}
		items[item.Path] = item
	}
	expected := []registry760ManifestItem{
		{Path: "schemas/datapan.operation-document-evidence.v2.schema.json", Kind: "schema", Bytes: 57563, SHA256: registry760EvidenceSchemaSHA256},
		{Path: "reports/operation-document-evidence/source-scopes/kosis-statistics-data-dt-1b41.json", Kind: "operation_document_evidence", Schema: "https://schemas.datapan.dev/datapan.operation-document-evidence.v2.schema.json", Bytes: 111121, SHA256: "74c32e047d9421894ca952d4820b9310336d1a827551c90c49a0427bb9ac5b4f"},
		{Path: "reports/operation-document-evidence/source-scopes/seoul-open-data-subway-station-list.json", Kind: "operation_document_evidence", Schema: "https://schemas.datapan.dev/datapan.operation-document-evidence.v2.schema.json", Bytes: 117708, SHA256: "498dc88551ce046316f1e3a233bc1cceead3ae3d7d856b01e01b50ebd0ee00c4"},
	}
	for _, want := range expected {
		if got, ok := items[want.Path]; !ok || got != want {
			return nil, errPublicOperationDisplayUnavailable
		}
	}

	schemaBytes, err := readLimitedMetadataFile(filepath.Join(root, filepath.FromSlash(expected[0].Path)), maxRegistry760SchemaBytes)
	if err != nil || int64(len(schemaBytes)) != expected[0].Bytes || digestSHA256(schemaBytes) != registry760EvidenceSchemaSHA256 {
		return nil, errPublicOperationDisplayUnavailable
	}
	result := make(map[string]registry760EvidenceSidecar, 2)
	for _, want := range expected[1:] {
		data, err := readLimitedMetadataFile(filepath.Join(root, filepath.FromSlash(want.Path)), maxRegistry760EvidenceBytes)
		if err != nil || int64(len(data)) != want.Bytes || digestSHA256(data) != want.SHA256 || schemas.ValidateRegistryOperationDocumentEvidenceV2(data, schemaBytes) != nil {
			return nil, errPublicOperationDisplayUnavailable
		}
		var sidecar registry760EvidenceSidecar
		if json.Unmarshal(data, &sidecar) != nil || sidecar.SchemaVersion != "datapan.operation-document-evidence.v2" {
			return nil, errPublicOperationDisplayUnavailable
		}
		if !validRegistry760DisplaySidecar(want.Path, sidecar) {
			return nil, errPublicOperationDisplayUnavailable
		}
		result[registryOperationLookupKey(sidecar.Identity.SourceID, sidecar.Identity.OperationID)] = sidecar
	}
	if len(result) != 2 {
		return nil, fmt.Errorf("%w: selected Registry evidence set incomplete", errPublicOperationDisplayUnavailable)
	}
	return result, nil
}

func validRegistry760DisplaySidecar(path string, sidecar registry760EvidenceSidecar) bool {
	switch path {
	case "reports/operation-document-evidence/source-scopes/kosis-statistics-data-dt-1b41.json":
		return sidecar.Identity.SourceID == "kosis" && sidecar.Identity.OperationID == "kosis-statistics-data-dt-1b41" &&
			sidecar.Identity.Provider == "KOSIS" && sidecar.Identity.Protocol == "REST" &&
			registry760FieldMatches(sidecar.OperationDocument.Title, "통계표선택 방법", "documented", "kosis_official_devguide", "official_operation_title", 26473, 26495) &&
			registry760FieldMatches(sidecar.OperationDocument.Purpose, "", "not_found_in_parsed_operation_sources", "", "", 0, 0) && sidecar.OperationDocument.ServiceStatus == nil
	case "reports/operation-document-evidence/source-scopes/seoul-open-data-subway-station-list.json":
		if sidecar.Identity.SourceID != "seoul_open_data" || sidecar.Identity.OperationID != "seoul-open-data-subway-station-list" || sidecar.Identity.Provider != "data.seoul.go.kr" || sidecar.Identity.Protocol != "REST" || sidecar.OperationDocument.ServiceStatus == nil {
			return false
		}
		return registry760FieldMatches(sidecar.OperationDocument.Title, "서울교통공사_노선별 지하철역 정보", "documented", "seoul_official_dataset_view", "official_operation_title", 51505, 51657) &&
			registry760FieldMatches(sidecar.OperationDocument.Purpose, "서울교통공사에서 제공하는 1~8호선, 9호선 2~3단계(언주~중앙보훈병원) 노선별 지하철역을 제공하는 서비스 입니다.", "documented", "seoul_official_dataset_view", "official_operation_purpose", 51716, 51869) &&
			registry760ServiceStatusMatches(*sidecar.OperationDocument.ServiceStatus, "terminated", "seoul_official_dataset_view", "official_service_termination_notice", 85007, 85057)
	default:
		return false
	}
}

func registry760ServiceStatusMatches(status registry760ServiceStatus, classification, sourceID, evidenceKind string, start, end int64) bool {
	if status.Classification != classification || status.Status != "documented" || len(status.SourceRefs) != 1 {
		return false
	}
	ref := status.SourceRefs[0]
	return ref.EvidenceKind == evidenceKind && ref.Locator.SourceID == sourceID && ref.Locator.Kind == "html_byte_range" && ref.Locator.ByteStart == start && ref.Locator.ByteEnd == end
}

func registry760FieldMatches(field registry760EvidenceField, wantValue, wantStatus, sourceID, evidenceKind string, start, end int64) bool {
	if field.Status != wantStatus {
		return false
	}
	if wantValue == "" {
		return field.Value == nil && len(field.SourceRefs) == 0
	}
	if field.Value == nil || *field.Value != wantValue || len(field.SourceRefs) != 1 {
		return false
	}
	ref := field.SourceRefs[0]
	return ref.EvidenceKind == evidenceKind && ref.Locator.SourceID == sourceID && ref.Locator.Kind == "html_byte_range" && ref.Locator.ByteStart == start && ref.Locator.ByteEnd == end
}

func digestSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
