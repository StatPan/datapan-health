package runtimebundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func sample(t *testing.T) (Lock, map[string][]byte) {
	t.Helper()
	registry := []byte(`[{"id":"test-only"}]`)
	catalog, _ := json.Marshal(map[string]any{"schema_version": "datapan.health-probe-catalog.v1", "authority": "datapan-registry", "source_registry": map[string]any{"sha256": digest(registry)}})
	manifest, _ := json.Marshal(map[string]any{"schema_version": "datapan.release-manifest.v1", "artifacts": []any{map[string]any{"path": "data/data-go-kr.registry.json", "bytes": len(registry), "sha256": digest(registry)}, map[string]any{"path": "reports/health-probe-catalog.json", "bytes": len(catalog), "sha256": digest(catalog)}}})
	pointer, _ := json.Marshal(map[string]any{"schema_version": "datapan.huggingface-distribution.v1", "dataset": map[string]any{"id": "StatPan/datapan-registry", "revision": strings.Repeat("d", 40)}, "release_manifest": map[string]any{"path": "manifest.json", "sha256": digest(manifest)}})
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	executable := make([]byte, 64)
	copy(executable, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(executable[16:], 2)
	binary.LittleEndian.PutUint16(executable[18:], 62)
	binary.LittleEndian.PutUint32(executable[20:], 1)
	binary.LittleEndian.PutUint16(executable[52:], 64)
	for name, body := range map[string]string{"datapan": string(executable), "LICENSE": "test-license", "NOTICE": "test-notice", "credentials.json": "never-copy-credential-marker", "../../escape": "never-extract-marker"} {
		if err := tw.WriteHeader(&tar.Header{Name: "datapan-cli_v0.1.40_linux_amd64/" + name, Mode: 0755, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	lock := Lock{SchemaVersion: Schema}
	lock.CLI.SourceSHA = strings.Repeat("a", 40)
	lock.CLI.Release = "v0.1.40"
	lock.CLI.Binaries = map[string]Binary{"amd64": {digest(archive.Bytes()), digest(executable)}, "arm64": {strings.Repeat("b", 64), strings.Repeat("c", 64)}}
	lock.Registry.DatasetRevision = strings.Repeat("d", 40)
	lock.Registry.DistributionRevision = strings.Repeat("d", 40)
	lock.Registry.DistributionSHA256 = digest(pointer)
	lock.Registry.SourceSHA = strings.Repeat("e", 40)
	lock.Registry.SourceRegistrySHA256 = digest(registry)
	lock.Registry.ManifestSHA256 = digest(manifest)
	lock.Registry.CatalogSHA256 = digest(catalog)
	lock.Registry.ReleaseTag = lock.Registry.DatasetRevision
	lock.Registry.AcquiredAt = "2026-10-04T15:00:00Z"
	return lock, map[string][]byte{"release/distribution-manifest.json": pointer, "manifest.json": manifest, "reports/health-probe-catalog.json": catalog, "data/data-go-kr.registry.json": registry, "datapan-cli_v0.1.40_linux_amd64.tar.gz": archive.Bytes()}
}

func clientFor(t *testing.T, files map[string][]byte) *http.Client {
	t.Helper()
	return &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "" {
			t.Fatal("unexpected credential-bearing or mutable request")
		}
		path := strings.TrimPrefix(r.URL.Path, "/datasets/StatPan/datapan-registry/resolve/"+strings.Repeat("d", 40)+"/")
		if r.URL.Host == "github.com" {
			path = filepath.Base(r.URL.Path)
		}
		body, ok := files[path]
		if !ok {
			t.Fatalf("unexpected source path %s", path)
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}
}

func TestImmutableMinimalInstallAndLocalTamper(t *testing.T) {
	lock, files := sample(t)
	directory := filepath.Join(t.TempDir(), "cli")
	if err := Install(context.Background(), clientFor(t, files), lock, "amd64", directory); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLocal(lock, "amd64", directory); err != nil {
		t.Fatal(err)
	}
	var paths []string
	if err := filepath.WalkDir(directory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, path)
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if bytes.Contains(raw, []byte("never-")) {
				t.Fatalf("non-whitelisted content copied")
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 6 {
		t.Fatalf("unexpected installed files %v", paths)
	}
	if _, err := os.Stat(filepath.Join(directory, ".datapan/data-go-kr.registry.json")); !os.IsNotExist(err) {
		t.Fatal("canonical snapshot must be verification-only")
	}
	if err := os.Chmod(filepath.Join(directory, "datapan"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "datapan"), []byte("tampered"), 0555); err != nil {
		t.Fatal(err)
	}
	if err := VerifyLocal(lock, "amd64", directory); err == nil {
		t.Fatal("tampered binary accepted")
	}
}

func TestTamperedRemoteInputsNeverInstall(t *testing.T) {
	for _, path := range []string{"release/distribution-manifest.json", "manifest.json", "reports/health-probe-catalog.json", "data/data-go-kr.registry.json", "datapan-cli_v0.1.40_linux_amd64.tar.gz"} {
		t.Run(path, func(t *testing.T) {
			lock, files := sample(t)
			files[path] = append(files[path], 'x')
			directory := filepath.Join(t.TempDir(), "cli")
			if err := Install(context.Background(), clientFor(t, files), lock, "amd64", directory); err == nil {
				t.Fatal("tampered artifact accepted")
			}
			if _, err := os.Stat(directory); !os.IsNotExist(err) {
				t.Fatal("failed verification left an install")
			}
		})
	}
}

func TestLocalProvenanceSymlinkAndUnexpectedFilesAreRejected(t *testing.T) {
	for _, mutation := range []string{"provenance", "parent_symlink", "extra_file"} {
		t.Run(mutation, func(t *testing.T) {
			lock, files := sample(t)
			directory := filepath.Join(t.TempDir(), "cli")
			if err := Install(context.Background(), clientFor(t, files), lock, "amd64", directory); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "provenance":
				path := filepath.Join(directory, ".datapan/registry-install.json")
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(`{"dataset_revision":"tampered"}`), 0444); err != nil {
					t.Fatal(err)
				}
			case "parent_symlink":
				path := filepath.Join(directory, ".datapan")
				target := filepath.Join(t.TempDir(), "source")
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "extra_file":
				if err := os.WriteFile(filepath.Join(directory, "credentials.json"), []byte("must-not-be-bundled"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := VerifyLocal(lock, "amd64", directory); err == nil {
				t.Fatal("altered runtime bundle admitted")
			}
		})
	}
}

func TestDistributionCannotRedirectToAnotherPayload(t *testing.T) {
	lock, files := sample(t)
	var pointer map[string]any
	if err := json.Unmarshal(files["release/distribution-manifest.json"], &pointer); err != nil {
		t.Fatal(err)
	}
	pointer["dataset"].(map[string]any)["revision"] = strings.Repeat("f", 40)
	files["release/distribution-manifest.json"], _ = json.Marshal(pointer)
	lock.Registry.DistributionSHA256 = digest(files["release/distribution-manifest.json"])
	directory := filepath.Join(t.TempDir(), "cli")
	if err := Install(context.Background(), clientFor(t, files), lock, "amd64", directory); err == nil {
		t.Fatal("unrelated payload revision accepted")
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("invalid payload installed")
	}
}

func TestWrongBindingAndArchitectureStopBeforeNetwork(t *testing.T) {
	lock, files := sample(t)
	lock.CLI.SourceSHA = "main"
	if err := Install(context.Background(), clientFor(t, files), lock, "amd64", filepath.Join(t.TempDir(), "cli")); err == nil {
		t.Fatal("mutable source accepted")
	}
	lock, _ = sample(t)
	client := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported architecture made a request")
		return nil, nil
	})}
	if err := Install(context.Background(), client, lock, "386", filepath.Join(t.TempDir(), "cli")); err == nil {
		t.Fatal("unsupported architecture accepted")
	}
}

func TestAmbiguousManifestBindingFailsBeforeCanonicalDownload(t *testing.T) {
	lock, files := sample(t)
	var manifest map[string]any
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	artifacts := manifest["artifacts"].([]any)
	manifest["artifacts"] = append(artifacts, artifacts[0])
	files["manifest.json"], _ = json.Marshal(manifest)
	lock.Registry.ManifestSHA256 = digest(files["manifest.json"])
	if err := Install(context.Background(), clientFor(t, files), lock, "amd64", filepath.Join(t.TempDir(), "cli")); err == nil {
		t.Fatal("ambiguous manifest accepted")
	}
}

func TestPinnedWrongArchitectureIsRejected(t *testing.T) {
	_, files := sample(t)
	wrong := append([]byte(nil), files["datapan-cli_v0.1.40_linux_amd64.tar.gz"]...)
	payload, err := extractCLI(wrong, "datapan-cli_v0.1.40_linux_amd64/")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyArchitecture(payload["datapan"], "arm64"); err == nil {
		t.Fatal("x86 executable accepted for ARM64")
	}
}
