package health

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestVerifiedRegistryMetadataBindsExactSourceDigestWithoutConflatingRevisions(t *testing.T) {
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRegistryAPIMetadata("../../config/registry/api-metadata.v1.json", "../../config/registry/api-metadata-source-pin.v1.json", canaries)
	if err != nil {
		t.Fatalf("load verified API metadata: %v", err)
	}
	metadata, err := NewVerifiedRegistryAPIMetadata(loaded)
	if err != nil {
		t.Fatalf("adapt verified API metadata: %v", err)
	}
	if metadata.pin.RegistryRevision == "" || metadata.pin.RegistryRevision == strings.Repeat("c", 40) || metadata.pin.SourceSHA256 != "0520d0db0d9ee07b7cbccce0c08439d0b02be901bf10e8491187d96e59d7a0d0" || len(metadata.operations) != 12662 {
		t.Fatalf("unexpected pinned metadata identity: revision=%q source=%q operations=%d", metadata.pin.RegistryRevision, metadata.pin.SourceSHA256, len(metadata.operations))
	}
	if metadataProjectionDigest(loaded) != loaded.verifiedProjectionSHA256 {
		t.Fatal("loader projection digest does not cover the exact exported metadata")
	}

	const sourcePath = "data/data-go-kr.registry.json"
	ref := operationPlanArtifactRef{Path: sourcePath, Bytes: loaded.Source.SizeBytes, SHA256: metadata.pin.SourceSHA256}
	scope := OperationObservationPlanSourceScope{
		SourceID: "data_go_kr", Provider: "data.go.kr", IdentitySetSHA256: metadata.identitySetSHA256,
		SourceArtifacts: []operationPlanArtifactRef{ref},
	}
	planRevision := strings.Repeat("c", 40)
	plan := PinnedOperationObservationPlan{state: &operationPlanIndexState{
		verified: true,
		index:    operationObservationPlanIndex{RegistryRevision: planRevision},
		byScope:  map[string]OperationObservationPlanSourceScope{"data_go_kr": scope},
		manifest: map[string]RegistryReleaseManifestArtifact{sourcePath: {Path: sourcePath, Kind: "registry_source", Schema: "application/json", Bytes: ref.Bytes, SHA256: ref.SHA256}},
	}}
	if metadata.pin.RegistryRevision == plan.RegistryRevision() || !plan.bindsSourceInventory("data_go_kr", "data.go.kr", sourcePath, metadata.pin.SourceSHA256, metadata.identitySetSHA256) {
		t.Fatal("exact source digest and complete operation identity set were not accepted across distinct Registry revisions")
	}

	// Keep the entire operation-ID set and all metadata counts unchanged while
	// presenting a different raw Registry source digest. Identity equality must
	// not substitute for the source-byte binding.
	wrongDigest := strings.Repeat("f", 64)
	wrongRef := ref
	wrongRef.SHA256 = wrongDigest
	wrongScope := scope
	wrongScope.SourceArtifacts = []operationPlanArtifactRef{wrongRef}
	plan.state.byScope["data_go_kr"] = wrongScope
	plan.state.manifest[sourcePath] = RegistryReleaseManifestArtifact{Path: sourcePath, Kind: "registry_source", Schema: "application/json", Bytes: wrongRef.Bytes, SHA256: wrongRef.SHA256}
	if plan.bindsSourceInventory("data_go_kr", "data.go.kr", sourcePath, metadata.pin.SourceSHA256, metadata.identitySetSHA256) {
		t.Fatal("same operation identity set with a different raw-source digest was accepted")
	}

	plan.state.byScope["data_go_kr"] = scope
	plan.state.manifest[sourcePath] = RegistryReleaseManifestArtifact{Path: sourcePath, Kind: "registry_source", Schema: "application/json", Bytes: ref.Bytes, SHA256: ref.SHA256}
	wrongIdentitySet := strings.Repeat("a", 64)
	if plan.bindsSourceInventory("data_go_kr", "data.go.kr", sourcePath, metadata.pin.SourceSHA256, wrongIdentitySet) {
		t.Fatal("matching source digest with a different operation identity set was accepted")
	}
}

func TestVerifiedRegistryMetadataRejectsUnmarkedAndMutatedProjection(t *testing.T) {
	if _, err := NewVerifiedRegistryAPIMetadata(RegistryAPIMetadata{Source: registryMetadataSource{SHA256: strings.Repeat("a", 64)}}); err == nil {
		t.Fatal("caller-constructed Registry metadata was treated as byte-verified")
	}
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRegistryAPIMetadata("../../config/registry/api-metadata.v1.json", "../../config/registry/api-metadata-source-pin.v1.json", canaries)
	if err != nil {
		t.Fatal(err)
	}
	loaded.APIs[0].Description = "tampered post-load text"
	if _, err := NewVerifiedRegistryAPIMetadata(loaded); err == nil {
		t.Fatal("mutated public-purpose text retained the loader's verification marker")
	}
}

func TestVerifiedRegistryMetadataPreservesLongKoreanPurposeText(t *testing.T) {
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadRegistryAPIMetadata("../../config/registry/api-metadata.v1.json", "../../config/registry/api-metadata-source-pin.v1.json", canaries)
	if err != nil {
		t.Fatal(err)
	}
	preservedLong := 0
	sourceNonempty := 0
	retained := 0
	droppedReasons := map[string]int{}
	longByBytes := 0
	longByRunes := 0
	maxBytes := 0
	maxRunes := 0
	for _, api := range loaded.APIs {
		if api.DescriptionState != "present" && api.DescriptionState != "sanitized" {
			continue
		}
		sourceNonempty++
		byteCount := len(api.Description)
		runeCount := utf8.RuneCountInString(api.Description)
		if byteCount > maxBytes {
			maxBytes = byteCount
		}
		if runeCount > maxRunes {
			maxRunes = runeCount
		}
		if byteCount > 512 {
			longByBytes++
		}
		if runeCount > 512 {
			longByRunes++
		}
		value, state := sanitizeClassifiedMetadata(api.Description, api.DescriptionState, 8192, 8192)
		if (state == "present" || state == "sanitized") && value == api.Description {
			retained++
		} else {
			droppedReasons[metadataTextDropReason(api.Description)]++
		}
		if (state == "present" || state == "sanitized") && value == api.Description && runeCount > 512 {
			preservedLong++
		}
	}
	// These floors are grounded in the exact byte-verified metadata pin. They
	// catch byte-count truncation of valid Korean prose without pinning display
	// coverage to every content-level redaction decision.
	if longByBytes < 8000 || longByRunes < 700 || preservedLong < 700 || retained < sourceNonempty-1000 || maxBytes > 8192 || maxRunes > 8192 {
		t.Fatalf("verified Korean purpose corpus was unexpectedly dropped or over-bounded: source_nonempty=%d retained=%d dropped_reasons=%v long_bytes=%d long_runes=%d preserved_long=%d max_bytes=%d max_runes=%d", sourceNonempty, retained, droppedReasons, longByBytes, longByRunes, preservedLong, maxBytes, maxRunes)
	}
	longKorean := strings.Repeat("안전한 설명", 252) // 1,512 Unicode code points.
	value, state := sanitizeClassifiedMetadata(longKorean, "present", 8192, 8192)
	if state != "present" || value != longKorean {
		t.Fatalf("long Korean purpose text was not preserved: state=%q bytes=%d runes=%d", state, len(value), utf8.RuneCountInString(value))
	}
	comparison := "기준값 `1`보다 작은 값만 대상으로 처리"
	value, state = sanitizeClassifiedMetadata(comparison, "sanitized", 8192, 8192)
	if state != "sanitized" || value != comparison {
		t.Fatal("verified prose with harmless inline-code punctuation was dropped")
	}
	t.Logf("verified purpose corpus counts: source_nonempty=%d retained=%d dropped_reasons=%v long_bytes=%d long_runes=%d preserved_long=%d max_bytes=%d max_runes=%d", sourceNonempty, retained, droppedReasons, longByBytes, longByRunes, preservedLong, maxBytes, maxRunes)
}

func metadataTextDropReason(value string) string {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	switch {
	case value == "" || !utf8.ValidString(value):
		return "empty_or_invalid_utf8"
	case strings.TrimSpace(value) != value:
		return "surrounding_whitespace"
	case len(value) > 8192 || utf8.RuneCountInString(value) > 8192:
		return "field_limit"
	case strings.ContainsAny(value, "\r\n\x00"):
		return "control_character"
	case strings.Contains(value, "`"):
		return "backtick"
	case strings.Contains(value, "\\"):
		return "backslash"
	case operationReadModelMarkupPattern.MatchString(value):
		return "html_like_markup"
	case operationReadModelURLPattern.MatchString(value):
		return "url"
	case operationReadModelRequestTargetPattern.MatchString(value):
		return "request_target"
	case operationReadModelSecretPattern.MatchString(value):
		return "credential_or_query_assignment"
	case operationReadModelIPPattern.MatchString(value):
		return "private_or_literal_ip"
	case operationReadModelDomainPattern.MatchString(value):
		return "domain"
	case strings.Contains(lower, "authorization:") || strings.Contains(lower, "bearer "):
		return "authorization_text"
	case strings.Contains(lower, "localhost") || strings.Contains(lower, ".internal") || strings.Contains(lower, ".local"):
		return "internal_target"
	default:
		return "other"
	}
}
