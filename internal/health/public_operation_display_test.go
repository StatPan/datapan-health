package health

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestPublicOperationDisplayMetadataIsPinnedAndScoped(t *testing.T) {
	path, evidenceRoot := publicOperationDisplayArtifactPaths(t)
	metadata, err := LoadPublicOperationDisplayMetadata(path, evidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !metadata.verified || len(metadata.byID) != 4 {
		t.Fatalf("operator display artifact did not load its four exact scopes: %#v", metadata)
	}
	if got, ok := metadata.entry("kosis", "kosis-statistics-data-dt-1b41"); !ok || got.OperatorLabelKO != "KOSIS 통계 자료" || got.GuideTitle.Value != "통계표선택 방법" || got.OfficialAPITitle.State != "missing" || got.OfficialPurpose.State != "missing" {
		t.Fatalf("KOSIS guide title was misrepresented as API title/purpose: %#v, %t", got, ok)
	}
	if got, ok := metadata.entry("seoul_open_data", "seoul-open-data-subway-station-list"); !ok || got.OfficialAPITitle.Value != "서울교통공사_노선별 지하철역 정보" || got.OfficialPurpose.State != "documented" || got.ServiceStatus.Value != "terminated" {
		t.Fatalf("Seoul source-documented API facts were not retained: %#v, %t", got, ok)
	}
	if _, ok := metadata.entry("seoul_open_data", "different-operation"); ok {
		t.Fatal("display metadata matched an operation by provider or fuzzy name")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"https://", "http://", "endpoint_template", "apiKey", "service_key"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("operator display artifact contains private/request detail %q", forbidden)
		}
	}
	tampered := filepath.Join(t.TempDir(), "display.json")
	changed := strings.Replace(string(data), "ECOS 통계 검색", "ECOS 통계 조회", 1)
	if err := os.WriteFile(tampered, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicOperationDisplayMetadata(tampered, evidenceRoot); err == nil {
		t.Fatal("modified operator text passed the compiled artifact digest pin")
	}
	corruptEvidenceRoot := filepath.Join(t.TempDir(), "registry-evidence")
	for _, relative := range []string{
		"manifest.json",
		"schemas/datapan.operation-document-evidence.v2.schema.json",
		"reports/operation-document-evidence/source-scopes/kosis-statistics-data-dt-1b41.json",
		"reports/operation-document-evidence/source-scopes/seoul-open-data-subway-station-list.json",
	} {
		source := filepath.Join(evidenceRoot, filepath.FromSlash(relative))
		destination := filepath.Join(corruptEvidenceRoot, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			t.Fatal(err)
		}
		bytes, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
	seoulSidecar := filepath.Join(corruptEvidenceRoot, "reports/operation-document-evidence/source-scopes/seoul-open-data-subway-station-list.json")
	seoulBytes, err := os.ReadFile(seoulSidecar)
	if err != nil {
		t.Fatal(err)
	}
	seoulBytes = append(seoulBytes, '\n')
	if err := os.WriteFile(seoulSidecar, seoulBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPublicOperationDisplayMetadata(path, corruptEvidenceRoot); err == nil {
		t.Fatal("modified source sidecar passed the Registry manifest digest boundary")
	}
}

func TestPartialScopeProjectionKeepsOperatorLabelsSeparateFromOfficialPurpose(t *testing.T) {
	path, evidenceRoot := publicOperationDisplayArtifactPaths(t)
	metadata, err := LoadPublicOperationDisplayMetadata(path, evidenceRoot)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 7, 8, 0, 0, 0, time.UTC)
	rows := make([]OperationReadModelRow, 0, len(publicPartialRegistryOperations))
	for _, expected := range publicPartialRegistryOperations {
		rows = append(rows, OperationReadModelRow{
			SourceID: expected.sourceID, RegistryOperationID: expected.operationID, Provider: expected.provider, Protocol: "REST",
			OperationNameState: "missing", TitleState: "missing", OrganizationState: "missing", PurposeState: "missing",
			RequestPlanState: "incomplete", RuntimeBindingState: "unbound", AdmissionState: "not_admitted", InventoryUnknown: true,
			MissingReason: "inventory_unknown", AttemptState: "none", ObservationAttemptState: "none", ObservationState: "unobserved", GatusDeliveryState: "not_ready",
		})
	}
	page := publicHTMLPage{OperationPlan: publicHTMLOperationPlan{InventoryUnknownScopes: 4, InventoryUnknownOperations: 4}}
	attachPublicPartialScopes(&page, staticPublicRegistryOperations{lookup: rows}, &metadata, now)
	if page.PartialScopesUnavailable || len(page.PartialScopes) != 4 {
		t.Fatalf("verified partial scopes were not rendered: %#v", page)
	}
	byProvider := make(map[string]publicHTMLPartialScope, len(page.PartialScopes))
	for _, row := range page.PartialScopes {
		byProvider[row.ProviderLabel] = row
	}
	ec, ok := byProvider["ECOS"]
	if !ok || ec.OperationName != "ECOS 통계 검색" || ec.NameAttribution != "운영자 표기 · 등록 ID 해석" || ec.Purpose != "기능 설명을 확인할 수 없습니다" || !strings.Contains(ec.MetadataAction, "공식 제공처 설명") {
		t.Fatalf("ECOS ID interpretation was presented as official purpose: %#v", ec)
	}
	kosis, ok := byProvider["KOSIS"]
	if !ok || kosis.OperationName != "KOSIS 통계 자료" || kosis.Title != "API 이름 확인 필요" || kosis.GuideTitle != "통계표선택 방법" || kosis.Purpose != "기능 설명을 확인할 수 없습니다" {
		t.Fatalf("KOSIS guide was not separated from missing API purpose: %#v", kosis)
	}
	seoul, ok := byProvider["서울 열린데이터광장"]
	if !ok || seoul.Title != "서울교통공사_노선별 지하철역 정보" || !strings.Contains(seoul.Purpose, "노선별 지하철역") || seoul.ServiceStatusLabel != "제공처 문서 상태: 서비스 종료 · 검사 결과와 별도 정보" || seoul.StatusClass == "badge-good" {
		t.Fatalf("Seoul source metadata/status was not separated from current observation: %#v", seoul)
	}
	assembly, ok := byProvider["국회 Open API"]
	if !ok || assembly.OperationName != "국회 Open API 목록" || assembly.Purpose != "기능 설명을 확인할 수 없습니다" {
		t.Fatalf("Open Assembly translation was mistaken for an API purpose: %#v", assembly)
	}
}

func publicOperationDisplayArtifactPaths(t *testing.T) (string, string) {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source path unavailable")
	}
	base := filepath.Join(filepath.Dir(file), "..", "..", "config", "registry")
	return filepath.Join(base, "operator-operation-display.v1.json"), filepath.Join(base, "operation-display-registry-760")
}
