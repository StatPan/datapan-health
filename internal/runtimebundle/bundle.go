// Package runtimebundle installs only immutable, credential-free Health inputs.
package runtimebundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const Schema = "datapan.health-runtime-dependencies.v1"

// Release manifests carry the full bounded Registry projection consumed by
// the Health worker and CLI. Keep this aligned with their 16 MiB manifest
// ceiling so a valid plan-bearing release can be installed.
const releaseManifestMaxBytes int64 = 16 << 20

var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var releasePattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

type Binary struct {
	ArchiveSHA256 string `json:"archive_sha256"`
	BinarySHA256  string `json:"binary_sha256"`
}

type Lock struct {
	SchemaVersion string `json:"schema_version"`
	CLI           struct {
		SourceSHA string            `json:"source_sha"`
		Release   string            `json:"release"`
		Binaries  map[string]Binary `json:"linux_binaries"`
	} `json:"cli"`
	Registry struct {
		DatasetRevision      string `json:"dataset_revision"`
		DistributionRevision string `json:"distribution_revision"`
		DistributionSHA256   string `json:"distribution_manifest_sha256"`
		SourceSHA            string `json:"source_sha"`
		SourceRegistrySHA256 string `json:"source_registry_sha256"`
		ManifestSHA256       string `json:"manifest_sha256"`
		CatalogSHA256        string `json:"catalog_sha256"`
		ReleaseTag           string `json:"release_tag"`
		AcquiredAt           string `json:"acquired_at"`
	} `json:"registry"`
}

func ReadLock(path string) (Lock, error) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 16<<10 {
		return Lock{}, errors.New("dependency lock unavailable")
	}
	var lock Lock
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&lock); err != nil {
		return Lock{}, errors.New("dependency lock invalid")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return Lock{}, errors.New("dependency lock has trailing content")
	}
	return lock, lock.Validate()
}

func (l Lock) Validate() error {
	if l.SchemaVersion != Schema || !commitPattern.MatchString(l.CLI.SourceSHA) || !releasePattern.MatchString(l.CLI.Release) || len(l.CLI.Binaries) != 2 || !commitPattern.MatchString(l.Registry.DatasetRevision) || !commitPattern.MatchString(l.Registry.DistributionRevision) || !shaPattern.MatchString(l.Registry.DistributionSHA256) || !commitPattern.MatchString(l.Registry.SourceSHA) || !shaPattern.MatchString(l.Registry.SourceRegistrySHA256) || !shaPattern.MatchString(l.Registry.ManifestSHA256) || !shaPattern.MatchString(l.Registry.CatalogSHA256) || l.Registry.ReleaseTag != l.Registry.DatasetRevision {
		return errors.New("dependency identities invalid")
	}
	if _, err := time.Parse(time.RFC3339, l.Registry.AcquiredAt); err != nil {
		return errors.New("dependency acquisition time invalid")
	}
	for _, arch := range []string{"amd64", "arm64"} {
		b, ok := l.CLI.Binaries[arch]
		if !ok || !shaPattern.MatchString(b.ArchiveSHA256) || !shaPattern.MatchString(b.BinarySHA256) {
			return errors.New("dependency binary identity invalid")
		}
	}
	return nil
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// Install verifies the archive, catalog, manifest and full canonical snapshot
// before writing a minimal Health-only install. The source snapshot is streamed
// through its digest check and is never copied into the image.
func Install(ctx context.Context, client *http.Client, lock Lock, arch, directory string) error {
	if err := lock.Validate(); err != nil {
		return err
	}
	binary, ok := lock.CLI.Binaries[arch]
	if !ok {
		return errors.New("unsupported dependency architecture")
	}
	base := "https://huggingface.co/datasets/StatPan/datapan-registry/resolve/" + lock.Registry.DatasetRevision + "/"
	pointerURL := "https://huggingface.co/datasets/StatPan/datapan-registry/resolve/" + lock.Registry.DistributionRevision + "/release/distribution-manifest.json"
	pointer, err := fetch(ctx, client, pointerURL, 4<<20)
	if err != nil || digest(pointer) != lock.Registry.DistributionSHA256 {
		return errors.New("dependency distribution verification failed")
	}
	var distribution struct {
		SchemaVersion   string                        `json:"schema_version"`
		Dataset         struct{ ID, Revision string } `json:"dataset"`
		ReleaseManifest struct {
			Path   string
			SHA256 string
		} `json:"release_manifest"`
	}
	if json.Unmarshal(pointer, &distribution) != nil || distribution.SchemaVersion != "datapan.huggingface-distribution.v1" || distribution.Dataset.ID != "StatPan/datapan-registry" || distribution.Dataset.Revision != lock.Registry.DatasetRevision || distribution.ReleaseManifest.Path != "manifest.json" || distribution.ReleaseManifest.SHA256 != lock.Registry.ManifestSHA256 {
		return errors.New("dependency distribution binding invalid")
	}
	manifest, err := fetch(ctx, client, base+"manifest.json", releaseManifestMaxBytes)
	if err != nil || digest(manifest) != lock.Registry.ManifestSHA256 {
		return errors.New("dependency manifest verification failed")
	}
	catalog, err := fetch(ctx, client, base+"reports/health-probe-catalog.json", 64<<10)
	if err != nil || digest(catalog) != lock.Registry.CatalogSHA256 {
		return errors.New("dependency catalog verification failed")
	}
	var release struct {
		SchemaVersion string `json:"schema_version"`
		Artifacts     []struct {
			Path   string `json:"path"`
			Bytes  int64  `json:"bytes"`
			SHA256 string `json:"sha256"`
		} `json:"artifacts"`
	}
	var projection struct {
		SchemaVersion  string `json:"schema_version"`
		Authority      string `json:"authority"`
		SourceRegistry struct {
			SHA256 string `json:"sha256"`
		} `json:"source_registry"`
	}
	if json.Unmarshal(manifest, &release) != nil || release.SchemaVersion != "datapan.release-manifest.v1" || json.Unmarshal(catalog, &projection) != nil || projection.SchemaVersion != "datapan.health-probe-catalog.v1" || projection.Authority != "datapan-registry" || projection.SourceRegistry.SHA256 != lock.Registry.SourceRegistrySHA256 {
		return errors.New("dependency Registry contract invalid")
	}
	var registryBytes int64
	counts := map[string]int{}
	for _, a := range release.Artifacts {
		switch a.Path {
		case "reports/health-probe-catalog.json":
			counts[a.Path]++
			if a.Bytes != int64(len(catalog)) || a.SHA256 != lock.Registry.CatalogSHA256 {
				return errors.New("dependency catalog manifest binding invalid")
			}
		case "data/data-go-kr.registry.json":
			counts[a.Path]++
			if a.Bytes < 1 || a.Bytes > 160<<20 || a.SHA256 != lock.Registry.SourceRegistrySHA256 {
				return errors.New("dependency source manifest binding invalid")
			}
			registryBytes = a.Bytes
		}
	}
	if counts["reports/health-probe-catalog.json"] != 1 || counts["data/data-go-kr.registry.json"] != 1 {
		return errors.New("dependency manifest binding absent or ambiguous")
	}
	if err := verifyRemote(ctx, client, base+"data/data-go-kr.registry.json", registryBytes, lock.Registry.SourceRegistrySHA256); err != nil {
		return err
	}
	archiveURL := fmt.Sprintf("https://github.com/StatPan/datapan-cli/releases/download/%s/datapan-cli_%s_linux_%s.tar.gz", lock.CLI.Release, lock.CLI.Release, arch)
	archive, err := fetch(ctx, client, archiveURL, 64<<20)
	if err != nil || digest(archive) != binary.ArchiveSHA256 {
		return errors.New("dependency CLI archive verification failed")
	}
	payload, err := extractCLI(archive, fmt.Sprintf("datapan-cli_%s_linux_%s/", lock.CLI.Release, arch))
	executable := payload["datapan"]
	if err != nil || digest(executable) != binary.BinarySHA256 {
		return errors.New("dependency CLI binary verification failed")
	}
	if err := verifyArchitecture(executable, arch); err != nil {
		return err
	}
	provenanceBytes, err := provenanceFor(lock)
	if err != nil {
		return err
	}
	files := map[string][]byte{"datapan": executable, ".datapan/release/manifest.json": manifest, ".datapan/release/reports/health-probe-catalog.json": catalog, ".datapan/registry-install.json": provenanceBytes, "licenses/datapan-cli/LICENSE": payload["LICENSE"], "licenses/datapan-cli/NOTICE": payload["NOTICE"]}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		return errors.New("dependency destination must be absent")
	}
	if err := os.MkdirAll(filepath.Dir(directory), 0755); err != nil {
		return errors.New("dependency parent unavailable")
	}
	staging, err := os.MkdirTemp(filepath.Dir(directory), ".runtime-dependencies-")
	if err != nil {
		return errors.New("dependency staging unavailable")
	}
	defer os.RemoveAll(staging)
	for path, raw := range files {
		target := filepath.Join(staging, path)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return errors.New("dependency directory write failed")
		}
		mode := os.FileMode(0444)
		if path == "datapan" {
			mode = 0555
		}
		if err := os.WriteFile(target, raw, mode); err != nil {
			return errors.New("dependency file write failed")
		}
	}
	if err := os.Chmod(staging, 0755); err != nil {
		return errors.New("dependency directory mode failed")
	}
	if err := os.Rename(staging, directory); err != nil {
		return errors.New("dependency install failed")
	}
	return nil
}

func provenanceFor(lock Lock) ([]byte, error) {
	base := "https://huggingface.co/datasets/StatPan/datapan-registry/resolve/" + lock.Registry.DatasetRevision + "/"
	provenance := map[string]any{
		"schema_version": "datapan.registry-install.v1", "installed_at": lock.Registry.AcquiredAt,
		"provider": "datapan-registry", "registry_path": ".datapan/data-go-kr.registry.json", "registry_sha256": lock.Registry.SourceRegistrySHA256,
		"release_tag": lock.Registry.ReleaseTag, "asset_url": base + "data/data-go-kr.registry.json", "pin_mode": "pinned", "source_mode": "health_catalog_only",
		"release_dir": ".datapan/release", "release_manifest": ".datapan/release/manifest.json", "release_manifest_sha256": lock.Registry.ManifestSHA256,
		"manifest_registry_verified": true, "distribution": "huggingface_dataset", "dataset_id": "StatPan/datapan-registry", "dataset_revision": lock.Registry.DatasetRevision,
		"dataset_manifest_url": "https://huggingface.co/datasets/StatPan/datapan-registry/resolve/" + lock.Registry.DistributionRevision + "/release/distribution-manifest.json", "dataset_manifest_sha256": lock.Registry.DistributionSHA256,
	}
	raw, err := json.MarshalIndent(provenance, "", "  ")
	if err != nil {
		return nil, errors.New("dependency provenance encoding failed")
	}
	return append(raw, '\n'), nil
}

func fetch(ctx context.Context, client *http.Client, address string, maximum int64) ([]byte, error) {
	response, err := request(ctx, client, address)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("dependency download exceeds bounds or failed")
	}
	return raw, nil
}

func request(ctx context.Context, client *http.Client, address string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, errors.New("dependency request invalid")
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, errors.New("dependency download unavailable")
	}
	if response.StatusCode != http.StatusOK {
		response.Body.Close()
		return nil, errors.New("dependency download status invalid")
	}
	return response, nil
}

func verifyRemote(ctx context.Context, client *http.Client, address string, size int64, want string) error {
	response, err := request(ctx, client, address)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(response.Body, size+1))
	if err != nil || count != size || hex.EncodeToString(hash.Sum(nil)) != want {
		return errors.New("dependency canonical snapshot verification failed")
	}
	return nil
}

func extractCLI(archive []byte, prefix string) (map[string][]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, errors.New("dependency archive invalid")
	}
	defer gz.Close()
	t := tar.NewReader(io.LimitReader(gz, 128<<20))
	payload := map[string][]byte{}
	for {
		header, err := t.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.New("dependency tar invalid")
		}
		name := ""
		for _, candidate := range []string{"datapan", "LICENSE", "NOTICE"} {
			if header.Name == prefix+candidate {
				name = candidate
			}
		}
		if name == "" {
			continue
		}
		maximum := int64(1 << 20)
		if name == "datapan" {
			maximum = 64 << 20
		}
		if payload[name] != nil || header.Typeflag != tar.TypeReg || header.Size < 1 || header.Size > maximum {
			return nil, errors.New("dependency executable entry invalid")
		}
		payload[name], err = io.ReadAll(t)
		if err != nil || int64(len(payload[name])) != header.Size {
			return nil, errors.New("dependency executable entry truncated")
		}
	}
	if len(payload) != 3 {
		return nil, errors.New("dependency executable absent")
	}
	return payload, nil
}

func VerifyLocal(lock Lock, arch, directory string) error {
	if err := lock.Validate(); err != nil {
		return err
	}
	binary, ok := lock.CLI.Binaries[arch]
	if !ok {
		return errors.New("unsupported dependency architecture")
	}
	provenance, err := provenanceFor(lock)
	if err != nil {
		return err
	}
	wanted := map[string]string{"datapan": binary.BinarySHA256, ".datapan/release/manifest.json": lock.Registry.ManifestSHA256, ".datapan/release/reports/health-probe-catalog.json": lock.Registry.CatalogSHA256, ".datapan/registry-install.json": digest(provenance), "licenses/datapan-cli/LICENSE": "", "licenses/datapan-cli/NOTICE": ""}
	seen := 0
	if err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("local dependency tree unavailable")
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(directory, path)
		if _, ok := wanted[relative]; err != nil || !ok {
			return errors.New("local dependency tree contains unexpected files")
		}
		seen++
		return nil
	}); err != nil || seen != len(wanted) {
		return errors.New("local dependency tree invalid")
	}
	for path, want := range wanted {
		info, err := os.Lstat(filepath.Join(directory, path))
		if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
			return errors.New("local dependency unavailable")
		}
		raw, err := os.ReadFile(filepath.Join(directory, path))
		if err != nil || len(raw) == 0 || (want != "" && digest(raw) != want) {
			return errors.New("local dependency digest mismatch")
		}
		if path == "datapan" {
			if err := verifyArchitecture(raw, arch); err != nil {
				return err
			}
		}
	}
	return nil
}

func verifyArchitecture(binary []byte, arch string) error {
	f, err := elf.NewFile(bytes.NewReader(binary))
	if err != nil {
		return errors.New("dependency CLI is not a Linux executable")
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || (f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN) || (arch == "arm64" && f.Machine != elf.EM_AARCH64) || (arch == "amd64" && f.Machine != elf.EM_X86_64) {
		return errors.New("dependency CLI architecture mismatch")
	}
	return nil
}
