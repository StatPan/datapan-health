package runtimebundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ProveCLI executes the bundled binary against a synthetic loopback HTTP
// provider. Run this in the isolated image with --network none. It neither
// reads an operational credential nor executes the published canary catalog.
func ProveCLI(ctx context.Context, lock Lock, directory string) error {
	// Use a registered gateway identity while enforcing loopback resolution.
	// An unregistered IP would be correctly skipped by the CLI adapter gate.
	addresses, err := net.DefaultResolver.LookupHost(ctx, "apis.data.go.kr")
	if err != nil || len(addresses) != 1 || addresses[0] != "127.0.0.1" {
		return fmt.Errorf("synthetic CLI proof requires isolated loopback host mapping")
	}
	binary := filepath.Join(directory, "datapan")
	version := exec.CommandContext(ctx, binary, "version", "--json")
	version.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin"}
	raw, err := version.Output()
	var identity struct {
		Version string `json:"version"`
	}
	if err != nil || json.Unmarshal(raw, &identity) != nil || identity.Version != lock.CLI.Release {
		return fmt.Errorf("bundled CLI release identity mismatch")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:80")
	if err != nil {
		return fmt.Errorf("synthetic CLI proof listener unavailable")
	}
	var calls atomic.Int32
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.Host != "apis.data.go.kr" || r.URL.Path != "/proof" || r.URL.Query().Get("serviceKey") != "synthetic-health-proof" || r.URL.Query().Get("pageNo") != "1" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"response":{"header":{"resultCode":"00","resultMsg":"NORMAL SERVICE"},"body":{"items":{"item":[{"proof_row":"must-be-redacted"}]}}}}`)
	})}
	defer server.Close()
	go func() { _ = server.Serve(listener) }()
	root, err := os.MkdirTemp("", "datapan-cli-http-proof-")
	if err != nil {
		return fmt.Errorf("synthetic CLI proof storage unavailable")
	}
	defer os.RemoveAll(root)
	sourceSHA := strings.Repeat("a", 64)
	var entries []any
	for i := 1; i <= 10; i++ {
		dataset := fmt.Sprintf("fixture-%03d", i)
		var fields strings.Builder
		for _, field := range []string{"data.go.kr", dataset, "probe", "data_go_kr_gateway", "apis.data.go.kr", "/proof"} {
			fields.WriteString(strconv.Itoa(len([]byte(field))) + ":" + field)
		}
		sum := sha256.Sum256([]byte(fields.String()))
		entries = append(entries, map[string]any{
			"operation_id": fmt.Sprintf("dpr-op-%08d", i), "provider": "data.go.kr",
			"policy":      map[string]any{"key": fmt.Sprintf("dpr-op-%08d", i), "version": 1, "authority": "datapan-registry", "max_level": "L4"},
			"aliases":     map[string]any{"dataset_id": dataset, "operation_name": "probe", "cli_operation_key": hex.EncodeToString(sum[:])},
			"endpoint":    map[string]any{"scheme": "http", "host": "apis.data.go.kr", "path": "/proof", "dependency_class": "data_go_kr_gateway"},
			"eligibility": map[string]any{"status": "credential_required"},
			"execution":   map[string]any{"timeout_ceiling_ms": 2000, "request_budget": 1, "safe_parameters": []any{map[string]any{"name": "pageNo", "strategy": "bounded_integer", "minimum": 1, "maximum": 1}}},
		})
	}
	catalog, _ := json.Marshal(map[string]any{"schema_version": "datapan.health-probe-catalog.v1", "authority": "datapan-registry", "source_registry": map[string]any{"sha256": sourceSHA}, "entries": entries})
	manifest, _ := json.Marshal(map[string]any{"schema_version": "datapan.release-manifest.v1", "artifacts": []any{map[string]any{"path": "reports/health-probe-catalog.json", "bytes": len(catalog), "sha256": digest(catalog)}, map[string]any{"path": "data/data-go-kr.registry.json", "bytes": 1, "sha256": sourceSHA}}})
	revision := strings.Repeat("b", 40)
	provenance, _ := json.Marshal(map[string]any{"schema_version": "datapan.registry-install.v1", "registry_path": ".datapan/data-go-kr.registry.json", "registry_sha256": sourceSHA, "release_manifest_sha256": digest(manifest), "manifest_registry_verified": true, "pin_mode": "pinned", "release_tag": revision, "dataset_revision": revision})
	for name, data := range map[string][]byte{"catalog.json": catalog, ".datapan/release/manifest.json": manifest, ".datapan/registry-install.json": provenance} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return fmt.Errorf("synthetic proof directory failed")
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			return fmt.Errorf("synthetic proof input failed")
		}
	}
	command := exec.CommandContext(ctx, binary, "verify", "--ref", "fixture-001", "--operation", "probe", "--health", "--timeout", "2s", "--health-catalog", filepath.Join(root, "catalog.json"), "--health-registry-revision", revision, "--output", filepath.Join(root, "receipt.json"), "--json")
	command.Dir = root
	command.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "DATAPAN_DATA_GO_KR_KEY=synthetic-health-proof"}
	command.Stdout, command.Stderr = io.Discard, io.Discard
	if err := command.Run(); err != nil || calls.Load() != 1 {
		return fmt.Errorf("bundled CLI did not honor one declared HTTP request")
	}
	receipt, err := os.ReadFile(filepath.Join(root, "receipt.json"))
	var assessment struct {
		Assessment struct {
			Category string `json:"category"`
		} `json:"assessment"`
		Registry struct {
			DatasetRevision string `json:"dataset_revision"`
			ManifestSHA256  string `json:"manifest_sha256"`
		} `json:"registry"`
		Execution struct {
			RequestBudget int `json:"request_budget"`
		} `json:"execution"`
	}
	if err != nil || len(receipt) > 64<<10 || json.Unmarshal(receipt, &assessment) != nil || assessment.Assessment.Category != "healthy" || assessment.Registry.DatasetRevision != revision || assessment.Registry.ManifestSHA256 != digest(manifest) || assessment.Execution.RequestBudget != 1 || strings.Contains(string(receipt), "synthetic-health-proof") || strings.Contains(string(receipt), "must-be-redacted") {
		return fmt.Errorf("bundled CLI proof receipt invalid or unredacted")
	}
	return nil
}
