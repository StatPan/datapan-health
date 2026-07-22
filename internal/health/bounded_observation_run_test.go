package health

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const observationRunFixtureRoot = "../../testdata/observation-runs/v1"

func TestBoundedObservationRunFixturesPreserveEightShardMatrix(t *testing.T) {
	for _, fixture := range []struct {
		name, state, completeness string
	}{
		{"complete-verified.json", "verified", "complete"},
		{"partial-unknown.json", "unknown", "partial"},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			receipt, err := DecodeBoundedObservationRun(bytes.NewReader(mustRead(t, "../../testdata/observation-runs/v1/"+fixture.name)))
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Aggregate.TerminalState != fixture.state || receipt.Aggregate.Completeness != fixture.completeness || receipt.Run.ShardCount != 8 || receipt.Run.BatchSize != 100 || receipt.Run.MaxParallel != 2 || receipt.Run.TimeoutMS != 20000 {
				t.Fatalf("unexpected bounded run: %#v", receipt)
			}
			if fixture.completeness == "partial" && !receipt.Aggregate.TimedOut {
				t.Fatal("partial timeout fixture did not retain explicit timeout evidence")
			}
			seen := map[int]bool{}
			for _, shard := range receipt.Shards {
				if seen[shard.Index] {
					t.Fatalf("duplicate fixture shard %d", shard.Index)
				}
				seen[shard.Index] = true
			}
			for index := 0; index < 8; index++ {
				if !seen[index] {
					t.Fatalf("legacy shard %d is missing from fixture matrix", index)
				}
			}
		})
	}
}

func TestBoundedObservationRunFixtureBindsEveryAdmittableShardArtifact(t *testing.T) {
	receipt, err := DecodeBoundedObservationRun(bytes.NewReader(mustRead(t, "../../testdata/observation-runs/v1/complete-verified.json")))
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range receipt.Shards {
		if !shard.ReceiptAvailable {
			t.Fatalf("complete fixture has non-admittable shard %d", shard.Index)
		}
		raw := mustRead(t, "../../testdata/observation-runs/v1/"+shard.ReceiptPath)
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != shard.ReceiptSHA256 {
			t.Fatalf("shard %d receipt digest mismatch: got %s", shard.Index, got)
		}
	}
	partial, err := DecodeBoundedObservationRun(bytes.NewReader(mustRead(t, "../../testdata/observation-runs/v1/partial-unknown.json")))
	if err != nil {
		t.Fatal(err)
	}
	for _, shard := range partial.Shards {
		if shard.ReceiptAvailable {
			t.Fatalf("partial fixture incorrectly made shard %d admittable", shard.Index)
		}
	}
}

func TestBoundedObservationRunRegistryAdmissionMapBindsAggregateAndShardBytes(t *testing.T) {
	type mappedShard struct {
		Index         int    `json:"shard_index"`
		Digest        string `json:"shard_digest"`
		ReceiptPath   string `json:"receipt_path"`
		ReceiptSHA256 string `json:"receipt_sha256"`
	}
	var mapping struct {
		AggregatePath   string        `json:"aggregate_path"`
		AggregateSHA256 string        `json:"aggregate_sha256"`
		Shards          []mappedShard `json:"shards"`
	}
	if err := json.Unmarshal(mustRead(t, "../../testdata/observation-runs/v1/registry-admission-map.json"), &mapping); err != nil {
		t.Fatal(err)
	}
	aggregate := mustReadBoundedObservationArtifact(t, observationRunFixtureRoot, mapping.AggregatePath)
	sum := sha256.Sum256(aggregate)
	if got := hex.EncodeToString(sum[:]); got != mapping.AggregateSHA256 {
		t.Fatalf("aggregate receipt digest mismatch: got %s", got)
	}
	receipt, err := DecodeBoundedObservationRun(bytes.NewReader(aggregate))
	if err != nil {
		t.Fatal(err)
	}
	if len(mapping.Shards) != 8 {
		t.Fatalf("registry map must bind eight shards, got %d", len(mapping.Shards))
	}
	seen := make(map[int]bool, len(mapping.Shards))
	for _, shard := range mapping.Shards {
		if shard.Index < 0 || shard.Index >= len(receipt.Shards) || seen[shard.Index] {
			t.Fatalf("registry map has invalid shard index %d", shard.Index)
		}
		seen[shard.Index] = true
		source := receipt.Shards[shard.Index]
		if source.ShardDigest != shard.Digest || source.ReceiptPath != shard.ReceiptPath || source.ReceiptSHA256 != shard.ReceiptSHA256 {
			t.Fatalf("registry map does not match Health source shard %d", shard.Index)
		}
		raw := mustReadBoundedObservationArtifact(t, observationRunFixtureRoot, shard.ReceiptPath)
		sum := sha256.Sum256(raw)
		if got := hex.EncodeToString(sum[:]); got != shard.ReceiptSHA256 {
			t.Fatalf("registry map shard %d receipt digest mismatch: got %s", shard.Index, got)
		}
	}
}

func TestBoundedObservationArtifactReadFailsClosedForPathTraversalAndSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "shards", "0"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "shards", "0", "receipt.json")); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		"../outside.json",
		"shards/0/../../../outside.json",
		"shards/0/receipt.json",
	} {
		if _, err := readBoundedObservationArtifact(root, path); err == nil {
			t.Fatalf("unsafe fixture artifact path %q was accepted", path)
		}
	}
}

func mustReadBoundedObservationArtifact(t *testing.T, root, path string) []byte {
	t.Helper()
	raw, err := readBoundedObservationArtifact(root, path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func readBoundedObservationArtifact(root, path string) ([]byte, error) {
	if filepath.IsAbs(path) {
		return nil, os.ErrPermission
	}
	clean := filepath.Clean(path)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	resolvedPath, err := filepath.EvalSymlinks(filepath.Join(resolvedRoot, clean))
	if err != nil {
		return nil, err
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, os.ErrPermission
	}
	info, err := os.Stat(resolvedPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, os.ErrPermission
	}
	return os.ReadFile(resolvedPath)
}

func TestBoundedObservationRunFailsClosedForCoverageAndAggregateDrift(t *testing.T) {
	base := mustRead(t, "../../testdata/observation-runs/v1/complete-verified.json")
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "duplicate shard index",
			mutate: func(document map[string]any) {
				shards := document["shards"].([]any)
				shards[7].(map[string]any)["index"] = float64(0)
			},
		},
		{
			name: "missing shard",
			mutate: func(document map[string]any) {
				document["shards"] = document["shards"].([]any)[:7]
			},
		},
		{
			name: "mismatched manifest binding",
			mutate: func(document map[string]any) {
				document["shards"].([]any)[4].(map[string]any)["manifest_sha256"] = strings.Repeat("f", 64)
			},
		},
		{
			name: "incomplete shard promoted to verified",
			mutate: func(document map[string]any) {
				shard := document["shards"].([]any)[7].(map[string]any)
				shard["completed"] = false
				shard["terminal_state"] = "unknown"
				shard["timed_out"] = true
				delete(shard, "observed_at")
				delete(shard, "receipt_sha256")
				document["aggregate"].(map[string]any)["terminal_state"] = "verified"
				document["aggregate"].(map[string]any)["completeness"] = "complete"
			},
		},
		{
			name: "unknown complete shard promoted to verified",
			mutate: func(document map[string]any) {
				document["shards"].([]any)[3].(map[string]any)["terminal_state"] = "unknown"
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := mutateBoundedObservationRun(t, base, test.mutate)
			if _, err := DecodeBoundedObservationRun(bytes.NewReader(mutated)); err == nil {
				t.Fatal("unsafe aggregate or coverage drift was accepted")
			}
		})
	}
}

func TestBoundedObservationRunRejectsStaleFutureAndOverlongEvidence(t *testing.T) {
	raw := mustRead(t, "../../testdata/observation-runs/v1/complete-verified.json")
	receipt, err := DecodeBoundedObservationRun(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := receipt.ValidateAt(receipt.Run.CompletedAt.Add(30*time.Second), time.Minute); err != nil {
		t.Fatalf("current bounded evidence was rejected: %v", err)
	}
	if err := receipt.ValidateAt(receipt.Run.CompletedAt.Add(2*time.Minute), time.Minute); err == nil {
		t.Fatal("stale bounded evidence was accepted")
	}
	if err := receipt.ValidateAt(receipt.Run.CompletedAt.Add(-time.Second), time.Minute); err == nil {
		t.Fatal("future bounded evidence was accepted")
	}
	overlong := mutateBoundedObservationRun(t, raw, func(document map[string]any) {
		document["run"].(map[string]any)["completed_at"] = "2026-07-22T02:13:21Z"
	})
	if _, err := DecodeBoundedObservationRun(bytes.NewReader(overlong)); err == nil {
		t.Fatal("run beyond deterministic bounded duration was accepted")
	}
	overTimeout := mutateBoundedObservationRun(t, raw, func(document map[string]any) {
		document["run"].(map[string]any)["timeout_ms"] = float64(20001)
	})
	if _, err := DecodeBoundedObservationRun(bytes.NewReader(overTimeout)); err == nil {
		t.Fatal("per-operation timeout above the 20-second runtime boundary was accepted")
	}
	malformedTime := mutateBoundedObservationRun(t, raw, func(document map[string]any) {
		document["run"].(map[string]any)["completed_at"] = "not-a-timestamp"
	})
	if _, err := DecodeBoundedObservationRun(bytes.NewReader(malformedTime)); err == nil {
		t.Fatal("malformed observation timestamp was accepted")
	}
}

func TestBoundedObservationRunRejectsLeakFieldsWithoutEchoingThem(t *testing.T) {
	base := mustRead(t, "../../testdata/observation-runs/v1/complete-verified.json")
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{
			name: "authorization header",
			mutate: func(document map[string]any) {
				document["authorization_header"] = "Bearer actual-secret-value"
			},
		},
		{
			name: "credential hash",
			mutate: func(document map[string]any) {
				document["credential_sha256"] = strings.Repeat("e", 64)
			},
		},
		{
			name: "credential bearing URL",
			mutate: func(document map[string]any) {
				document["provider_url"] = "https://provider.example/?serviceKey=actual-secret-value"
			},
		},
		{
			name: "raw response body",
			mutate: func(document map[string]any) {
				document["shards"].([]any)[0].(map[string]any)["response_body"] = "actual-secret-value"
			},
		},
		{
			name: "response rows",
			mutate: func(document map[string]any) {
				document["shards"].([]any)[0].(map[string]any)["response_rows"] = []any{"actual-secret-value"}
			},
		},
		{
			name: "user identity",
			mutate: func(document map[string]any) {
				document["user_identity"] = "actual-secret-value"
			},
		},
		{
			name: "redaction assertion false",
			mutate: func(document map[string]any) {
				document["redaction"].(map[string]any)["authorization_headers_removed"] = false
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mutated := mutateBoundedObservationRun(t, base, test.mutate)
			_, err := DecodeBoundedObservationRun(bytes.NewReader(mutated))
			if err == nil {
				t.Fatal("unsafe observation receipt was accepted")
			}
			if strings.Contains(err.Error(), "actual-secret-value") {
				t.Fatalf("decoder echoed unsafe input: %v", err)
			}
		})
	}
}

func mutateBoundedObservationRun(t *testing.T, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	mutate(document)
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
