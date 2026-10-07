package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/StatPan/datapan-health/internal/registrymetadata"
	"github.com/StatPan/datapan-health/schemas"
)

const (
	maxPinBytes     = 64 * 1024
	maxCatalogBytes = 1024 * 1024
)

type receipt struct {
	SchemaVersion    string                  `json:"schema_version"`
	GeneratedAt      string                  `json:"generated_at"`
	RegistryRevision string                  `json:"registry_revision"`
	SourceSHA256     string                  `json:"source_sha256"`
	CatalogSHA256    string                  `json:"catalog_sha256"`
	ArtifactPath     string                  `json:"artifact_path"`
	ArtifactSHA256   string                  `json:"artifact_sha256"`
	Counts           registrymetadata.Counts `json:"counts"`
}

func main() {
	root := flag.String("repo-root", ".", "Health repository root")
	sourcePath := flag.String("source", "", "local copy of the pinned Registry source JSON")
	pinPath := flag.String("pin", "config/registry/api-metadata-source-pin.v1.json", "source and artifact pins")
	receiptPath := flag.String("receipt", "config/registry/api-metadata-receipt.v1.json", "generation receipt output")
	flag.Parse()
	if *sourcePath == "" {
		fail()
	}
	if err := generate(*root, *sourcePath, *pinPath, *receiptPath); err != nil {
		fmt.Fprintln(os.Stderr, "health registry metadata generation failed:", err.Error())
		os.Exit(1)
	}
}

func generate(root, sourcePath, pinPath, receiptPath string) error {
	pinFullPath := rooted(root, pinPath)
	pinBytes, err := readBounded(pinFullPath, maxPinBytes)
	if err != nil || schemas.ValidateHealthRegistryAPIMetadataSourcePinV1(pinBytes) != nil {
		return errors.New("invalid source pin")
	}
	var pin registrymetadata.Pin
	decoder := json.NewDecoder(bytesReader(pinBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&pin); err != nil || ensureEOF(decoder) != nil {
		return errors.New("invalid source pin")
	}
	if err := registrymetadata.ValidatePin(pin); err != nil {
		return errors.New("invalid source pin")
	}
	catalogBytes, err := readBounded(rooted(root, pin.Catalog.Path), maxCatalogBytes)
	if err != nil {
		return errors.New("health catalog unavailable")
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return errors.New("Registry source unavailable")
	}
	defer source.Close()
	stat, err := source.Stat()
	if err != nil || stat.Size() != pin.Source.SizeBytes || stat.Size() > registrymetadata.MaxSourceBytes {
		return errors.New("Registry source size mismatch")
	}
	_, artifactBytes, err := registrymetadata.Project(source, catalogBytes, pin)
	if err != nil {
		return err
	}
	if err := schemas.ValidateHealthRegistryAPIMetadataV1(artifactBytes); err != nil {
		return errors.New("Registry metadata schema validation failed")
	}
	artifactHash := sha256.Sum256(artifactBytes)
	artifactSHA256 := hex.EncodeToString(artifactHash[:])
	if pin.Artifact.SHA256 != "" && artifactSHA256 != pin.Artifact.SHA256 {
		return errors.New("Registry metadata artifact digest mismatch")
	}
	var metadata registrymetadata.MetadataArtifact
	if err := json.Unmarshal(artifactBytes, &metadata); err != nil {
		return errors.New("Registry metadata projection failed")
	}
	receiptDocument := receipt{
		SchemaVersion:    "datapan.health-registry-api-metadata-receipt.v1",
		GeneratedAt:      time.Now().UTC().Truncate(time.Second).Format(time.RFC3339),
		RegistryRevision: pin.RegistryRevision,
		SourceSHA256:     pin.Source.SHA256,
		CatalogSHA256:    pin.Catalog.SHA256,
		ArtifactPath:     pin.Artifact.Path,
		ArtifactSHA256:   artifactSHA256,
		Counts:           metadata.Counts,
	}
	receiptBytes, err := json.MarshalIndent(receiptDocument, "", "  ")
	if err != nil {
		return errors.New("receipt encoding failed")
	}
	receiptBytes = append(receiptBytes, '\n')
	if err := writeAtomic(rooted(root, pin.Artifact.Path), artifactBytes); err != nil {
		return errors.New("artifact write failed")
	}
	if err := writeAtomic(rooted(root, receiptPath), receiptBytes); err != nil {
		return errors.New("receipt write failed")
	}
	fmt.Printf("metadata generated: api_entities=%d api_operations=%d link_operations=%d institutions=%d matched_health_canaries=%d artifact_sha256=%s\n",
		metadata.Counts.APIEntities, metadata.Counts.APIOperations, metadata.Counts.LinkOperations,
		metadata.Counts.Institutions, metadata.Counts.MatchedHealthCanaries, artifactSHA256)
	return nil
}

func readBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, errors.New("input exceeds size budget")
	}
	return data, nil
}

func rooted(root, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(root, path)
}

func ensureEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func bytesReader(data []byte) *bytes.Reader {
	return bytes.NewReader(data)
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".health-registry-metadata-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func fail() {
	fmt.Fprintln(os.Stderr, "health registry metadata generation failed")
	os.Exit(1)
}
