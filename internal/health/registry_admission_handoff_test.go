package health

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRegistryAdmissionHandoffPinIsImmutableMetadataOnly(t *testing.T) {
	var pin struct {
		SchemaVersion string `json:"schema_version"`
		Registry      struct {
			Revision           string `json:"revision"`
			SchemaSHA256       string `json:"schema_sha256"`
			PolicySHA256       string `json:"policy_sha256"`
			ValidatorSHA256    string `json:"validator_sha256"`
			AcceptedFixtureSHA string `json:"accepted_fixture_sha256"`
			SchemaURL          string `json:"schema_url"`
		} `json:"registry"`
	}
	if err := json.Unmarshal(mustRead(t, "../../config/registry/release-admission-handoff-contract-pin.json"), &pin); err != nil {
		t.Fatal(err)
	}
	if pin.SchemaVersion != "datapan.health-registry-admission-handoff-pin.v1" || pin.Registry.Revision != "4458003e1490e70d2efc538df93aeaa3addc90ef" || !strings.Contains(pin.Registry.SchemaURL, pin.Registry.Revision) {
		t.Fatal("Registry handoff pin is not immutable")
	}
	for _, digest := range []string{pin.Registry.SchemaSHA256, pin.Registry.PolicySHA256, pin.Registry.ValidatorSHA256, pin.Registry.AcceptedFixtureSHA} {
		if !sha256Pattern.MatchString(digest) {
			t.Fatal("Registry handoff pin has an invalid byte digest")
		}
	}
}

func TestRegistryAdmissionHandoffBindsAggregateAndAllEightActualShardBytes(t *testing.T) {
	aggregate := mustRead(t, "../../testdata/observation-runs/v1/complete-verified.json")
	handoff, err := BuildRegistryAdmissionHandoff(aggregate, "../../testdata/observation-runs/v1", handoffGuard(t, aggregate))
	if err != nil {
		t.Fatal(err)
	}
	if handoff.Aggregate.Path != "runs/health-run-fixture-0001.json" || handoff.Aggregate.SHA256 != digestHandoffBytes(aggregate) || len(handoff.Shards) != 8 {
		t.Fatalf("unexpected handoff: %#v", handoff)
	}
	for index, shard := range handoff.Shards {
		if shard.Path != "shards/"+string(rune('0'+index))+"/receipt.json" || shard.SHA256 != digestHandoffBytes(shard.Bytes) {
			t.Fatalf("shard %d is not byte-bound: %#v", index, shard)
		}
	}
}

func TestRegistryAdmissionHandoffRejectsPartialAndByteDriftWithoutAdmissionClaim(t *testing.T) {
	partial := mustRead(t, "../../testdata/observation-runs/v1/partial-unknown.json")
	if _, err := BuildRegistryAdmissionHandoff(partial, "../../testdata/observation-runs/v1", handoffGuard(t, partial)); err == nil {
		t.Fatal("partial handoff was exported")
	}
	base := mustRead(t, "../../testdata/observation-runs/v1/complete-verified.json")
	var document map[string]any
	if err := json.Unmarshal(base, &document); err != nil {
		t.Fatal(err)
	}
	document["shards"].([]any)[0].(map[string]any)["receipt_sha256"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	mutated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildRegistryAdmissionHandoff(bytes.TrimSpace(mutated), "../../testdata/observation-runs/v1", handoffGuard(t, base)); err == nil {
		t.Fatal("byte-drifted handoff was exported")
	}
}

func TestRegistryAdmissionHandoffRejectsMatchingDigestNonCanonicalShardBytes(t *testing.T) {
	base := mustRead(t, "../../testdata/observation-runs/v1/complete-verified.json")
	var document map[string]any
	if err := json.Unmarshal(base, &document); err != nil {
		t.Fatal(err)
	}
	malicious := []byte(`{"raw_response":"secret-value"}`)
	document["shards"].([]any)[0].(map[string]any)["receipt_sha256"] = digestHandoffBytes(malicious)
	aggregate, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for index := 0; index < 8; index++ {
		dir := filepath.Join(root, "shards", string(rune('0'+index)))
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		data := mustRead(t, "../../testdata/observation-runs/v1/shards/"+string(rune('0'+index))+"/receipt.json")
		if index == 0 {
			data = malicious
		}
		if err := os.WriteFile(filepath.Join(dir, "receipt.json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := BuildRegistryAdmissionHandoff(aggregate, root, handoffGuard(t, base)); err == nil {
		t.Fatal("noncanonical secret-bearing shard bytes were exported")
	}
}

func TestRegistryAdmissionHandoffRejectsStaleFutureAndMismatchedGuardBeforeSourceRead(t *testing.T) {
	aggregate := mustRead(t, "../../testdata/observation-runs/v1/complete-verified.json")
	for _, test := range []struct {
		name   string
		mutate func(*HandoffGuard)
	}{
		{"stale", func(g *HandoffGuard) {
			g.ReferenceAt = g.ReferenceAt.Add(11 * time.Minute)
			g.MaxAge = 10 * time.Minute
		}},
		{"future", func(g *HandoffGuard) { g.ReferenceAt = g.ReferenceAt.Add(-2 * time.Minute) }},
		{"health", func(g *HandoffGuard) { g.ExpectedHealthRevision = strings.Repeat("f", 40) }},
		{"manifest", func(g *HandoffGuard) { g.ExpectedRegistry.ManifestSHA256 = strings.Repeat("f", 64) }},
		{"policy", func(g *HandoffGuard) { g.ExpectedRegistry.PolicySHA256 = strings.Repeat("f", 64) }},
		{"source", func(g *HandoffGuard) { g.ExpectedRegistry.SourceSHA256 = strings.Repeat("f", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			guard := handoffGuard(t, aggregate)
			test.mutate(&guard)
			if _, err := BuildRegistryAdmissionHandoff(aggregate, filepath.Join(t.TempDir(), "missing"), guard); err == nil {
				t.Fatal("unsafe guard reached source read")
			}
		})
	}
}

func handoffGuard(t *testing.T, aggregate []byte) HandoffGuard {
	t.Helper()
	run, err := DecodeBoundedObservationRun(bytes.NewReader(aggregate))
	if err != nil {
		t.Fatal(err)
	}
	return HandoffGuard{ExpectedHealthRevision: run.Producer.Revision, ExpectedRegistry: run.Registry, ReferenceAt: run.Run.CompletedAt.Add(time.Minute), MaxAge: 10 * time.Minute}
}

func TestRegistryAdmissionHandoffReaderRejectsEverySymlinkComponent(t *testing.T) {
	outside := t.TempDir()
	for _, test := range []struct {
		name  string
		setup func(root string)
	}{
		{"root", func(root string) { _ = os.Remove(root); _ = os.Symlink(outside, root) }},
		{"shards", func(root string) { _ = os.Symlink(outside, filepath.Join(root, "shards")) }},
		{"index", func(root string) {
			_ = os.MkdirAll(filepath.Join(root, "shards"), 0o700)
			_ = os.Symlink(outside, filepath.Join(root, "shards", "0"))
		}},
		{"receipt", func(root string) {
			_ = os.MkdirAll(filepath.Join(root, "shards", "0"), 0o700)
			_ = os.Symlink(filepath.Join(outside, "x"), filepath.Join(root, "shards", "0", "receipt.json"))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			test.setup(root)
			if _, err := readBoundedObservationHandoffArtifact(root, "shards/0/receipt.json"); err == nil {
				t.Fatal("symlink component accepted")
			}
		})
	}
}
