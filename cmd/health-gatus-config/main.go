package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/StatPan/datapan-health/internal/health"
)

const (
	maxInputBytes = 4 << 20
	maxPinBytes   = 16 << 10
)

func main() {
	baseConfigPath := flag.String("base-config", env("HEALTH_GATUS_BASE_CONFIG", "config/gatus.yaml"), "image-owned Gatus base configuration")
	canaryPath := flag.String("canaries", env("CANARY_CONFIG", "config/canaries.json"), "verified legacy canary identity map")
	metadataPath := flag.String("registry-api-metadata", env("REGISTRY_API_METADATA", "config/registry/api-metadata.v1.json"), "pinned Registry API metadata")
	metadataPinPath := flag.String("registry-api-metadata-pin", env("REGISTRY_API_METADATA_PIN", "config/registry/api-metadata-source-pin.v1.json"), "Registry API metadata source pin")
	planRoot := flag.String("operation-plan-root", os.Getenv("REGISTRY_OPERATION_PLAN_ROOT"), "optional installed Registry operation-plan release root")
	planPinPath := flag.String("operation-plan-pin", os.Getenv("REGISTRY_OPERATION_PLAN_PIN"), "optional image-owned Registry operation-plan binding")
	activationPath := flag.String("activation", os.Getenv("HEALTH_OPERATION_GATUS_ACTIVATION"), "optional exact-ID reviewed activation file")
	activationPin := flag.String("activation-sha256", os.Getenv("HEALTH_OPERATION_GATUS_ACTIVATION_SHA256"), "image-owned digest for the reviewed activation file")
	outputDir := flag.String("output-dir", env("HEALTH_GATUS_OUTPUT_DIR", "data/generated-gatus"), "directory for generated config and private identity pins")
	flag.Parse()
	if err := generate(*baseConfigPath, *canaryPath, *metadataPath, *metadataPinPath, *planRoot, *planPinPath, *activationPath, *activationPin, *outputDir); err != nil {
		fmt.Fprintln(os.Stderr, "Health Gatus configuration generation failed")
		os.Exit(1)
	}
}

func generate(baseConfigPath, canaryPath, metadataPath, metadataPinPath, planRoot, planPinPath, activationPath, activationPin, outputDir string) error {
	baseConfig, err := readBoundedRegular(baseConfigPath, maxInputBytes)
	if err != nil {
		return errors.New("Gatus base configuration unavailable")
	}
	canaryBytes, err := readBoundedRegular(canaryPath, maxInputBytes)
	if err != nil {
		return errors.New("canary configuration unavailable")
	}
	canaries, err := health.LoadCanaryConfig(canaryPath)
	if err != nil {
		return errors.New("canary configuration is not valid")
	}
	metadata, err := health.LoadRegistryAPIMetadata(metadataPath, metadataPinPath, canaries)
	if err != nil {
		return errors.New("Registry metadata is not valid")
	}
	verifiedMetadata, err := health.NewVerifiedRegistryAPIMetadata(metadata)
	if err != nil {
		return errors.New("Registry metadata provenance is not valid")
	}

	var plan *health.PinnedOperationObservationPlan
	if (planRoot == "") != (planPinPath == "") {
		return errors.New("Registry operation-plan root and pin must be supplied together")
	}
	if planRoot != "" {
		binding, err := health.LoadOperationObservationPlanRuntimePin(planPinPath)
		if err != nil {
			return errors.New("Registry operation-plan pin unavailable")
		}
		loaded, err := health.LoadPinnedOperationObservationPlan(planRoot, binding)
		if err != nil {
			return errors.New("Registry operation-plan release unavailable")
		}
		plan = &loaded
	}

	var activation *health.OperationGatusActivation
	var activationSHA string
	if (activationPath == "") != (activationPin == "") {
		return errors.New("activation file and digest must be supplied together")
	}
	if activationPath != "" {
		if !validSHA256(activationPin) {
			return errors.New("operation activation digest is invalid")
		}
		if plan == nil {
			return errors.New("activation requires a pinned Registry operation plan")
		}
		raw, err := readBoundedRegular(activationPath, 4<<20)
		if err != nil {
			return errors.New("operation activation unavailable")
		}
		loaded, sha, err := health.DecodeOperationGatusActivation(raw, *plan)
		if err != nil || sha != activationPin {
			return errors.New("operation activation is not valid")
		}
		activation, activationSHA = &loaded, sha
	}

	canarySum := sha256.Sum256(canaryBytes)
	artifacts, err := health.GenerateOperationGatusArtifacts(baseConfig, hex.EncodeToString(canarySum[:]), canaries, verifiedMetadata, plan, activation, activationSHA)
	if err != nil {
		return errors.New("operation Gatus projection is not valid")
	}
	for name, data := range map[string][]byte{
		"config.yaml":                 artifacts.Config,
		"operation-identity-map.json": artifacts.Mapping,
		"runtime-dependencies.json":   artifacts.RuntimePin,
	} {
		if err := writeAtomic(outputDir, name, data); err != nil {
			return errors.New("generated Gatus artifacts could not be published")
		}
	}
	return nil
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("input file outside bounds")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("input file unavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) > maximum {
		return nil, errors.New("input file outside bounds")
	}
	return raw, nil
}

func writeAtomic(directory, name string, data []byte) error {
	if filepath.Base(name) != name || len(data) == 0 || len(data) > 32<<20 {
		return errors.New("generated file outside bounds")
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output directory invalid")
	}
	temporary, err := os.CreateTemp(directory, ".health-gatus-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o444); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(data)); err != nil {
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
	if err := os.Rename(temporaryPath, filepath.Join(directory, name)); err != nil {
		return err
	}
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryHandle.Close()
	return directoryHandle.Sync()
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}
