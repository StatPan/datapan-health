package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

var sourcePaths = []string{
	"internal/health/diagnostic_test.go",
	"internal/health/health_test.go",
}

func main() {
	root := flag.String("root", ".", "repository root")
	check := flag.Bool("check", false, "fail when generated provenance is stale")
	flag.Parse()

	updates, err := generate(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	stale := false
	for path, wanted := range updates {
		current, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if string(current) == wanted {
			continue
		}
		stale = true
		if *check {
			fmt.Fprintln(os.Stderr, "stale diagnostic provenance:", path)
			continue
		}
		if err := os.WriteFile(path, []byte(wanted), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("updated", path)
	}
	if stale && *check {
		os.Exit(1)
	}
}

func generate(root string) (map[string]string, error) {
	manifestPath := filepath.Join(root, "config/registry/diagnostic-test-manifest.json")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	updatedManifest := string(manifest)
	for _, sourcePath := range sourcePaths {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(sourcePath)))
		if err != nil {
			return nil, err
		}
		pattern := regexp.MustCompile(`("path": "` + regexp.QuoteMeta(sourcePath) + `",\s*"sha256": ")[0-9a-f]{64}(")`)
		if len(pattern.FindAllStringIndex(updatedManifest, -1)) != 1 {
			return nil, errors.New("diagnostic test manifest source pin is missing or duplicated: " + sourcePath)
		}
		updatedManifest = pattern.ReplaceAllString(updatedManifest, `${1}`+digest(raw)+`${2}`)
	}

	contractPath := filepath.Join(root, "config/registry/diagnostic-contract-pin.json")
	contract, err := os.ReadFile(contractPath)
	if err != nil {
		return nil, err
	}
	contractPattern := regexp.MustCompile(`("path": "diagnostic-test-manifest.json",\s*"sha256": ")[0-9a-f]{64}(")`)
	if len(contractPattern.FindAllStringIndex(string(contract), -1)) != 1 {
		return nil, errors.New("diagnostic contract test-manifest pin is missing or duplicated")
	}
	manifestDigest := digest([]byte(updatedManifest))
	updatedContract := contractPattern.ReplaceAllString(string(contract), `${1}`+manifestDigest+`${2}`)

	diagnosticPath := filepath.Join(root, "internal/health/diagnostic.go")
	diagnostic, err := os.ReadFile(diagnosticPath)
	if err != nil {
		return nil, err
	}
	diagnosticPattern := regexp.MustCompile(`(AcceptedDiagnosticTestManifestSHA256 = ")[0-9a-f]{64}(")`)
	if len(diagnosticPattern.FindAllStringIndex(string(diagnostic), -1)) != 1 {
		return nil, errors.New("accepted diagnostic test manifest digest is missing or duplicated")
	}
	updatedDiagnostic := diagnosticPattern.ReplaceAllString(string(diagnostic), `${1}`+manifestDigest+`${2}`)

	return map[string]string{
		manifestPath:   updatedManifest,
		contractPath:   updatedContract,
		diagnosticPath: updatedDiagnostic,
	}, nil
}

func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return fmt.Sprintf("%x", sum[:])
}
