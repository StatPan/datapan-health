package registrymetadata_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/StatPan/datapan-health/internal/registrymetadata"
	"github.com/StatPan/datapan-health/schemas"
)

func TestProjectStreamsAndRedactsPinnedMetadata(t *testing.T) {
	source := `[
  {
    "id":"12345678","provider":"data.go.kr",
    "title":"<script>alert(1)</script>안전 API https://evil.example/path?token=discard",
    "organization":"기관 A","description":"기능 설명 https://example.com/path?serviceKey=discard /v1/rows {\"rows\":[{\"secret\":\"discard\"}]}",
    "source":{"system":"data.go.kr","raw":{"api_type":"REST","list_type":"PR0027"}},
    "operations":[
      {"name":"확인 조회","endpoint":"https://provider.example/open?serviceKey=discard","source":{"system":"data.go.kr","raw":{"list_id":"12345678","operation_seq":"44"}}}
    ]
  },
  {
    "id":"12345679","provider":"data.go.kr","title":"","organization":"기관 B",
    "source":{"system":"data.go.kr","raw":{"list_type":"PR0010"}},
    "operations":[{"name":"연결 링크","source":{"system":"data.go.kr","raw":{}}}]
  },
  {
    "id":"12345680","provider":"data.go.kr","title":"기록","organization":"기관 B",
    "source":{"system":"data.go.kr","raw":{"list_type":"PR0010"}},"operations":[]
  }
]`
	sourceDigest := sha256.Sum256([]byte(source))
	sourceSHA := hex.EncodeToString(sourceDigest[:])
	cliKey := testOperationKey([]string{"data.go.kr", "12345678", "확인 조회", "external_endpoint", "provider.example", "/open"})
	catalog := `{"schema_version":"datapan.health-probe-catalog.v1","source_registry":{"sha256":"` + sourceSHA + `"},"entries":[{"operation_id":"dpr-op-00000001","provider":"data.go.kr","aliases":{"dataset_id":"12345678","operation_name":"확인 조회","upstream_operation_seq":"44","cli_operation_key":"` + cliKey + `"}}]}`
	catalogDigest := sha256.Sum256([]byte(catalog))
	catalogSHA := hex.EncodeToString(catalogDigest[:])
	pin := registrymetadata.Pin{
		SchemaVersion:    registrymetadata.PinSchemaVersion,
		RegistryRevision: strings.Repeat("a", 40),
		Source:           registrymetadata.SourcePin{Path: "data/data-go-kr.registry.json", SHA256: sourceSHA, SizeBytes: int64(len(source))},
		Catalog:          registrymetadata.CatalogPin{Path: "config/registry/health-probe-catalog.json", SHA256: catalogSHA, EntryCount: 1},
		ExpectedCounts: registrymetadata.ExpectedCounts{
			APIEntities: 3, APIOperations: 1, LinkOperations: 1,
			OperationlessCatalogEntries: 1, FiledataCatalogEntries: 1,
			Institutions: 2, MatchedHealthCanaries: 1,
		},
		Artifact: registrymetadata.ArtifactPin{Path: "config/registry/api-metadata.v1.json"},
	}
	artifact, encoded, err := registrymetadata.Project(strings.NewReader(source), []byte(catalog), pin)
	if err != nil {
		t.Fatalf("Project returned error: %v", err)
	}
	if err := schemas.ValidateHealthRegistryAPIMetadataV1(encoded); err != nil {
		t.Fatalf("artifact schema validation failed: %v", err)
	}
	if got, want := len(artifact.APIs), 3; got != want {
		t.Fatalf("API entity count = %d, want %d", got, want)
	}
	if got, want := artifact.Counts, (registrymetadata.Counts{APIEntities: 3, APIOperations: 1, LinkOperations: 1, OperationlessCatalogEntries: 1, FiledataCatalogEntries: 1, Institutions: 2, MatchedHealthCanaries: 1}); got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
	if artifact.APIs[0].TitleState != "sanitized" || artifact.APIs[0].Title != "안전 API" {
		t.Fatalf("unsafe title projection = %q (%s)", artifact.APIs[0].Title, artifact.APIs[0].TitleState)
	}
	if artifact.APIs[0].DescriptionState != "sanitized" || artifact.APIs[0].Description != "기능 설명" {
		t.Fatalf("unsafe description projection = %q (%s)", artifact.APIs[0].Description, artifact.APIs[0].DescriptionState)
	}
	if artifact.APIs[1].Operations == nil || artifact.APIs[1].LinkOperationCount != 1 || len(artifact.APIs[1].Operations) != 0 {
		t.Fatalf("LINK operations were not kept separate: %+v", artifact.APIs[1])
	}
	if artifact.APIs[1].TitleState != "blank" || artifact.APIs[1].DescriptionState != "missing" {
		t.Fatalf("missing/blank fields were hidden: %+v", artifact.APIs[1])
	}
	if len(artifact.HealthCanaryLinks) != 1 || artifact.HealthCanaryLinks[0].RegistryAPIID != "12345678" || artifact.HealthCanaryLinks[0].UpstreamOperationSeq != "44" {
		t.Fatalf("canary alias did not join exactly: %+v", artifact.HealthCanaryLinks)
	}
	for _, prohibited := range []string{"https://", "evil.example", "provider.example", "serviceKey=", "token=discard", "/v1/rows", "secret", "<script>", "rows"} {
		if strings.Contains(string(encoded), prohibited) {
			t.Fatalf("artifact contains prohibited source content %q", prohibited)
		}
	}
	var roundTrip registrymetadata.MetadataArtifact
	if err := json.Unmarshal(encoded, &roundTrip); err != nil || roundTrip.Counts != artifact.Counts {
		t.Fatalf("artifact JSON roundtrip failed: %v", err)
	}
}

func TestProjectFailsClosedOnSourceOrAliasMismatch(t *testing.T) {
	source := `[{"id":"12345678","provider":"data.go.kr","title":"이름","organization":"기관","description":"기능","source":{"raw":{"api_type":"REST"}},"operations":[{"name":"조회","endpoint":"","source":{"system":"data.go.kr","raw":{"list_id":"12345678","operation_seq":"44"}}}]}]`
	sourceDigest := sha256.Sum256([]byte(source))
	sourceSHA := hex.EncodeToString(sourceDigest[:])
	catalog := `{"schema_version":"datapan.health-probe-catalog.v1","source_registry":{"sha256":"` + sourceSHA + `"},"entries":[{"operation_id":"dpr-op-00000001","provider":"data.go.kr","aliases":{"dataset_id":"12345678","operation_name":"wrong name","upstream_operation_seq":"44","cli_operation_key":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}]}`
	catalogDigest := sha256.Sum256([]byte(catalog))
	pin := registrymetadata.Pin{
		SchemaVersion: registrymetadata.PinSchemaVersion, RegistryRevision: strings.Repeat("a", 40),
		Source:         registrymetadata.SourcePin{Path: "data/data-go-kr.registry.json", SHA256: sourceSHA, SizeBytes: int64(len(source))},
		Catalog:        registrymetadata.CatalogPin{Path: "config/registry/health-probe-catalog.json", SHA256: hex.EncodeToString(catalogDigest[:]), EntryCount: 1},
		ExpectedCounts: registrymetadata.ExpectedCounts{APIEntities: 1, APIOperations: 1, Institutions: 1, MatchedHealthCanaries: 1},
		Artifact:       registrymetadata.ArtifactPin{Path: "config/registry/api-metadata.v1.json"},
	}
	if _, _, err := registrymetadata.Project(strings.NewReader(source), []byte(catalog), pin); err == nil {
		t.Fatal("Project accepted an alias that does not exactly match source metadata")
	}
	pin.Source.SHA256 = strings.Repeat("b", 64)
	if _, _, err := registrymetadata.Project(strings.NewReader(source), []byte(catalog), pin); err == nil {
		t.Fatal("Project accepted a source digest mismatch")
	}
}

func TestProjectRejectsOversizedRecordBeforeDecoding(t *testing.T) {
	source := `[{"id":"12345678","provider":"data.go.kr","title":"` + strings.Repeat("x", registrymetadata.MaxRecordBytes) + `"}]`
	sourceDigest := sha256.Sum256([]byte(source))
	sourceSHA := hex.EncodeToString(sourceDigest[:])
	cliKey := strings.Repeat("a", 64)
	catalog := `{"schema_version":"datapan.health-probe-catalog.v1","source_registry":{"sha256":"` + sourceSHA + `"},"entries":[{"operation_id":"dpr-op-00000001","provider":"data.go.kr","aliases":{"dataset_id":"12345678","operation_name":"조회","upstream_operation_seq":"44","cli_operation_key":"` + cliKey + `"}}]}`
	catalogDigest := sha256.Sum256([]byte(catalog))
	pin := registrymetadata.Pin{
		SchemaVersion:    registrymetadata.PinSchemaVersion,
		RegistryRevision: strings.Repeat("a", 40),
		Source:           registrymetadata.SourcePin{Path: "data/data-go-kr.registry.json", SHA256: sourceSHA, SizeBytes: int64(len(source))},
		Catalog:          registrymetadata.CatalogPin{Path: "config/registry/health-probe-catalog.json", SHA256: hex.EncodeToString(catalogDigest[:]), EntryCount: 1},
		ExpectedCounts:   registrymetadata.ExpectedCounts{APIEntities: 1, APIOperations: 1, Institutions: 1, MatchedHealthCanaries: 1},
		Artifact:         registrymetadata.ArtifactPin{Path: "config/registry/api-metadata.v1.json"},
	}
	_, _, err := registrymetadata.Project(strings.NewReader(source), []byte(catalog), pin)
	if err == nil || !strings.Contains(err.Error(), "record exceeds size budget") {
		t.Fatalf("oversized record was not rejected before decoding: %v", err)
	}
}

func testOperationKey(fields []string) string {
	var payload []byte
	for _, field := range fields {
		encoded := []byte(field)
		payload = append(payload, []byte(fmt.Sprintf("%d:", len(encoded)))...)
		payload = append(payload, encoded...)
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
