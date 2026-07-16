package health

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

const correlationRulePath = "../../config/correlation/provider-outage.v1.json"

func TestCorrelationReplayInfersOnlyWithBoundedAffectedAndControlCounts(t *testing.T) {
	rule, canaries := mustCorrelationInputs(t)
	replay := mustCorrelationReplay(t, "inferred.json")
	receipt, err := CorrelateProviderOutage(rule, canaries, replay)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Result.Cause != "provider_outage" || receipt.Result.Determination != "inferred" || receipt.Result.AffectedCount != 2 || receipt.Result.ControlCount != 1 || receipt.NoticeEvidence.LinkedNoticeRef != "" {
		t.Fatalf("unexpected inferred receipt: %#v", receipt)
	}
	if len(receipt.AffectedEvidence) != 2 || len(receipt.ControlEvidence) != 1 || len(receipt.HealthObservationEvidence) != 2 || receipt.AffectedEvidence[0].OperationID != "dpr-op-00000001" || receipt.Rule.SHA256 != rule.SHA256 || receipt.Boundaries.AlertPolicy != "unchanged" || receipt.Boundaries.PublicProjection != "unchanged" {
		t.Fatalf("correlation evidence or boundary is incomplete: %#v", receipt)
	}
	for _, evidence := range receipt.HealthObservationEvidence {
		if evidence.Kind != "health_observation" || evidence.Authority != "datapan_health" || evidence.Scope.Level != "operation" || evidence.Scope.DependencyClass != replay.Scope.DependencyClass || evidence.HealthCorrelation.ProbePolicyVersion != 1 || evidence.HealthCorrelation.AffectedCount != 2 || evidence.HealthCorrelation.ControlCount != 1 || !strings.HasPrefix(evidence.RefID, "health-correlation:sha256:") {
			t.Fatalf("health_observation evidence is not exact and replayable: %#v", evidence)
		}
	}
}

func TestCorrelationReplayRequiresAuthoritativeExactOverlapForObservedOutage(t *testing.T) {
	rule, canaries := mustCorrelationInputs(t)
	replay := mustCorrelationReplay(t, "observed-notice.json")
	receipt, err := CorrelateProviderOutage(rule, canaries, replay)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Result.Determination != "observed" || !strings.HasPrefix(receipt.NoticeEvidence.LinkedNoticeRef, "provider-notice:data-go-kr-maintenance-20260717:v1:sha256:") {
		t.Fatalf("authoritative exact-overlap notice was not linked: %#v", receipt)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"data.go.kr/bbs", "source_ref", "response_body", "credential_hash", "provider_text"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("receipt leaked non-public evidence field %q", forbidden)
		}
	}
}

func TestCorrelationFalsePositiveReplaysRemainUnknown(t *testing.T) {
	rule, canaries := mustCorrelationInputs(t)
	base := mustCorrelationReplay(t, "inferred.json")
	tests := map[string]func(CorrelationReplay) CorrelationReplay{
		"single timeout": func(_ CorrelationReplay) CorrelationReplay { return mustCorrelationReplay(t, "single-timeout.json") },
		"single 503": func(replay CorrelationReplay) CorrelationReplay {
			replay.Observations = replay.Observations[1:]
			return replay
		},
		"missing control": func(replay CorrelationReplay) CorrelationReplay {
			replay.Observations = replay.Observations[:2]
			return replay
		},
		"stale affected": func(replay CorrelationReplay) CorrelationReplay {
			for index := 0; index < 2; index++ {
				replay.Observations[index].ObservedAt = replay.AssessedAt.Add(-901 * time.Second)
			}
			return replay
		},
		"mixed credential scopes": func(replay CorrelationReplay) CorrelationReplay {
			replay.Observations[1].CredentialScopeID = "different-canary-credential-scope"
			return replay
		},
		"mixed dependency scopes": func(replay CorrelationReplay) CorrelationReplay {
			replay.Observations[1].OperationID = "dpr-op-00000006"
			replay.Observations[1].ProbePolicyKey = "dpr-op-00000006"
			replay.Observations[1].DependencyClass = "external_endpoint"
			return replay
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			receipt, err := CorrelateProviderOutage(rule, canaries, mutate(cloneReplay(t, base)))
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Result.Cause != "unknown" || receipt.Result.Determination != "unknown" || receipt.NoticeEvidence.LinkedNoticeRef != "" {
				t.Fatalf("false-positive replay was promoted: %#v", receipt)
			}
			if len(receipt.HealthObservationEvidence) != 0 {
				t.Fatal("insufficient evidence produced promotable health_observation evidence")
			}
		})
	}
}

func TestCorrelationWindowBoundaryAndPolicyIdentityAreExact(t *testing.T) {
	rule, canaries := mustCorrelationInputs(t)
	boundary := mustCorrelationReplay(t, "inferred.json")
	boundary.Observations[0].ObservedAt = boundary.AssessedAt.Add(-time.Duration(rule.WindowSeconds) * time.Second)
	receipt, err := CorrelateProviderOutage(rule, canaries, boundary)
	if err != nil || receipt.Result.Determination != "inferred" {
		t.Fatalf("inclusive boundary did not replay deterministically: receipt=%#v err=%v", receipt, err)
	}
	for name, mutate := range map[string]func(*HealthObservation){
		"policy key":               func(observation *HealthObservation) { observation.ProbePolicyKey = "dpr-op-00000002" },
		"policy version":           func(observation *HealthObservation) { observation.ProbePolicyVersion = 2 },
		"operation dependency":     func(observation *HealthObservation) { observation.DependencyClass = "external_endpoint" },
		"redaction":                func(observation *HealthObservation) { observation.Redaction.RawProviderTextRemoved = false },
		"401 disguised as timeout": func(observation *HealthObservation) { observation.HTTPStatus = 401 },
		"403 disguised as timeout": func(observation *HealthObservation) { observation.HTTPStatus = 403 },
	} {
		t.Run(name, func(t *testing.T) {
			replay := mustCorrelationReplay(t, "inferred.json")
			mutate(&replay.Observations[0])
			if _, err := CorrelateProviderOutage(rule, canaries, replay); err == nil {
				t.Fatal("drifted or unsafe observation was accepted")
			}
		})
	}
}

func TestProviderNoticeAgeBoundaryIsCurrentButStaleNoticeCannotUpgrade(t *testing.T) {
	rule, canaries := mustCorrelationInputs(t)
	boundary := mustCorrelationReplay(t, "observed-notice.json")
	boundary.ProviderNotices[0].ObservedAt = boundary.AssessedAt.Add(-time.Duration(rule.NoticeMaxAgeSeconds) * time.Second)
	receipt, err := CorrelateProviderOutage(rule, canaries, boundary)
	if err != nil || receipt.Result.Determination != "observed" {
		t.Fatalf("notice age boundary was not inclusive: %#v err=%v", receipt, err)
	}
	boundary.ProviderNotices[0].ObservedAt = boundary.ProviderNotices[0].ObservedAt.Add(-time.Second)
	receipt, err = CorrelateProviderOutage(rule, canaries, boundary)
	if err != nil || receipt.Result.Determination != "inferred" || len(receipt.NoticeEvidence.ConsideredNoticeRefs) != 1 || receipt.NoticeEvidence.LinkedNoticeRef != "" {
		t.Fatalf("stale notice was not preserved without upgrade: %#v err=%v", receipt, err)
	}
}

func TestProviderNoticeSupersessionWithdrawalAndScopeMismatchPreserveHistory(t *testing.T) {
	rule, canaries := mustCorrelationInputs(t)
	base := mustCorrelationReplay(t, "observed-notice.json")
	prior := base.ProviderNotices[0]
	tests := map[string]struct {
		latest     ProviderNotice
		want       string
		wantLinked bool
	}{
		"withdrawal":       {latest: revisedNotice(prior, "withdrawn", "", []string{"dpr-op-00000001", "dpr-op-00000002"}), want: "inferred"},
		"scope correction": {latest: revisedNotice(prior, "corrected", "degraded", []string{"dpr-op-00000001"}), want: "inferred"},
		"exact correction": {latest: revisedNotice(prior, "corrected", "service_suspended", []string{"dpr-op-00000001", "dpr-op-00000002"}), want: "observed", wantLinked: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			replay := cloneReplay(t, base)
			replay.ProviderNotices = append(replay.ProviderNotices, test.latest)
			receipt, err := CorrelateProviderOutage(rule, canaries, replay)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Result.Determination != test.want || (receipt.NoticeEvidence.LinkedNoticeRef != "") != test.wantLinked || len(receipt.NoticeEvidence.ConsideredNoticeRefs) != 2 || len(receipt.NoticeEvidence.SupersededNoticeRefs) != 1 {
				t.Fatalf("supersession was not preserved safely: %#v", receipt)
			}
		})
	}
	scopeMismatch := cloneReplay(t, base)
	scopeMismatch.ProviderNotices[0].OperationIDs = []string{"dpr-op-00000001"}
	receipt, err := CorrelateProviderOutage(rule, canaries, scopeMismatch)
	if err != nil || receipt.Result.Determination != "inferred" || receipt.NoticeEvidence.LinkedNoticeRef != "" {
		t.Fatalf("scope-mismatched notice was linked: %#v err=%v", receipt, err)
	}
}

func TestCorrelationReplayIsInputOrderInvariant(t *testing.T) {
	rule, canaries := mustCorrelationInputs(t)
	replay := mustCorrelationReplay(t, "observed-notice.json")
	replay.ProviderNotices = append(replay.ProviderNotices, revisedNotice(replay.ProviderNotices[0], "corrected", "degraded", []string{"dpr-op-00000001", "dpr-op-00000002"}))
	want, err := CorrelateProviderOutage(rule, canaries, replay)
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(replay.Observations)
	slices.Reverse(replay.ProviderNotices)
	got, err := CorrelateProviderOutage(rule, canaries, replay)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("input order changed deterministic receipt:\nwant=%#v\ngot=%#v", want, got)
	}
}

func TestCorrelationReplayDecoderAndRuleFailClosed(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/correlation/inferred.json")
	if err != nil {
		t.Fatal(err)
	}
	for name, mutation := range map[string][]byte{
		"unknown field": bytes.Replace(raw, []byte(`"schema_version":`), []byte(`"response_body":"secret","schema_version":`), 1),
		"oversized":     append(raw, bytes.Repeat([]byte(" "), maxCorrelationReplayBytes)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeCorrelationReplay(bytes.NewReader(mutation)); err == nil {
				t.Fatal("unsafe replay was accepted")
			}
		})
	}
	ruleRaw, err := os.ReadFile(correlationRulePath)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutation := range map[string][]byte{
		"single affected":  bytes.Replace(ruleRaw, []byte(`"minimum_affected_operations": 2`), []byte(`"minimum_affected_operations": 1`), 1),
		"missing control":  bytes.Replace(ruleRaw, []byte(`"minimum_control_operations": 1`), []byte(`"minimum_control_operations": 0`), 1),
		"unbounded window": bytes.Replace(ruleRaw, []byte(`"window_seconds": 900`), []byte(`"window_seconds": 3600`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			path := t.TempDir() + "/rule.json"
			if err := os.WriteFile(path, mutation, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadCorrelationRule(path); err == nil {
				t.Fatal("unsafe rule drift was accepted")
			}
		})
	}
}

func TestCorrelationRejectsDuplicateObservationReferenceAndUnsafeNoticeLink(t *testing.T) {
	rule, canaries := mustCorrelationInputs(t)
	replay := mustCorrelationReplay(t, "inferred.json")
	replay.Observations[1].ObservationRef = replay.Observations[0].ObservationRef
	if _, err := CorrelateProviderOutage(rule, canaries, replay); err == nil {
		t.Fatal("duplicate immutable observation reference was accepted")
	}
	replay = mustCorrelationReplay(t, "observed-notice.json")
	replay.ProviderNotices[0].SourceRef += "?credential=prohibited"
	if _, err := CorrelateProviderOutage(rule, canaries, replay); err == nil {
		t.Fatal("query-bearing provider notice source was accepted")
	}
}

func mustCorrelationInputs(t *testing.T) (CorrelationRule, CanaryConfig) {
	t.Helper()
	rule, err := LoadCorrelationRule(correlationRulePath)
	if err != nil {
		t.Fatal(err)
	}
	canaries, err := LoadCanaryConfig("../../config/canaries.json")
	if err != nil {
		t.Fatal(err)
	}
	return rule, canaries
}

func mustCorrelationReplay(t *testing.T, name string) CorrelationReplay {
	t.Helper()
	file, err := os.Open("../../testdata/correlation/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	replay, err := DecodeCorrelationReplay(file)
	if err != nil {
		t.Fatal(err)
	}
	return replay
}

func cloneReplay(t *testing.T, replay CorrelationReplay) CorrelationReplay {
	t.Helper()
	raw, err := json.Marshal(replay)
	if err != nil {
		t.Fatal(err)
	}
	var clone CorrelationReplay
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func revisedNotice(prior ProviderNotice, state, effect string, operations []string) ProviderNotice {
	return ProviderNotice{
		SchemaVersion: ProviderNoticeSchemaVersion, NoticeID: prior.NoticeID, Version: 2,
		Authority: prior.Authority, ObservedAt: prior.ObservedAt.Add(time.Minute), EffectiveFrom: prior.EffectiveFrom,
		EffectiveUntil: prior.EffectiveUntil, State: state, Effect: effect, DependencyClass: prior.DependencyClass,
		OperationIDs: operations, SourceRef: "https://www.data.go.kr/bbs/notice/20260717-correction",
		ContentSHA256: strings.Repeat("e", 64), SupersedesVersion: 1,
	}
}
