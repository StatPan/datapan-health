package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const DiagnosticTestManifestVersion = "datapan.health-diagnostic-test-manifest.v1"

type DiagnosticTestManifest struct {
	SchemaVersion string                    `json:"schema_version"`
	Sources       []DiagnosticTestSourcePin `json:"sources"`
	Tests         []DiagnosticTestIdentity  `json:"tests"`
}

type DiagnosticTestSourcePin struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type DiagnosticTestIdentity struct {
	Name       string `json:"name"`
	SourcePath string `json:"source_path"`
}

type DiagnosticTestProof struct {
	Manifest ArtifactPin               `json:"manifest"`
	Sources  []DiagnosticTestSourcePin `json:"sources"`
	Tests    []DiagnosticTestIdentity  `json:"tests"`
	Count    int                       `json:"count"`
}

func decodeDiagnosticTestManifest(raw []byte) (DiagnosticTestManifest, error) {
	var manifest DiagnosticTestManifest
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil || ensureEOF(decoder) != nil || manifest.SchemaVersion != DiagnosticTestManifestVersion || len(manifest.Sources) == 0 || len(manifest.Tests) == 0 {
		return DiagnosticTestManifest{}, errors.New("invalid diagnostic test manifest")
	}
	sourcePaths := make(map[string]bool, len(manifest.Sources))
	for index, source := range manifest.Sources {
		if !safeRepositoryPath(source.Path) || !sha256Pattern.MatchString(source.SHA256) || sourcePaths[source.Path] || (index > 0 && manifest.Sources[index-1].Path >= source.Path) {
			return DiagnosticTestManifest{}, errors.New("invalid diagnostic test source pin")
		}
		sourcePaths[source.Path] = true
	}
	for index, test := range manifest.Tests {
		if !strings.HasPrefix(test.Name, "Test") || !sourcePaths[test.SourcePath] || (index > 0 && manifest.Tests[index-1].Name >= test.Name) {
			return DiagnosticTestManifest{}, errors.New("invalid diagnostic test identity")
		}
	}
	return manifest, nil
}

func (c DiagnosticContract) ValidateTestManifest(repoRoot string) (DiagnosticTestProof, error) {
	if c.TestManifest.SHA256 != AcceptedDiagnosticTestManifestSHA256 || c.testManifest.SchemaVersion != DiagnosticTestManifestVersion {
		return DiagnosticTestProof{}, errors.New("unsupported diagnostic test manifest")
	}
	declared := make(map[string]string, len(c.testManifest.Tests))
	for _, test := range c.testManifest.Tests {
		declared[test.Name] = test.SourcePath
	}
	found := make(map[string]string, len(declared))
	for _, source := range c.testManifest.Sources {
		path := filepath.Join(repoRoot, filepath.FromSlash(source.Path))
		raw, err := os.ReadFile(path)
		if err != nil || digest(raw) != source.SHA256 {
			return DiagnosticTestProof{}, errors.New("diagnostic test source digest does not match manifest")
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, raw, 0)
		if err != nil {
			return DiagnosticTestProof{}, errors.New("diagnostic test source cannot be parsed")
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || function.Type.Results != nil || function.Type.Params == nil || len(function.Type.Params.List) != 1 {
				continue
			}
			wantedSource, wanted := declared[function.Name.Name]
			if strings.HasPrefix(function.Name.Name, "TestDiagnostic") && (!wanted || wantedSource != source.Path) {
				return DiagnosticTestProof{}, errors.New("diagnostic test source contains an undeclared compatibility test")
			}
			if wanted && wantedSource == source.Path {
				found[function.Name.Name] = source.Path
			}
		}
	}
	if len(found) != len(declared) {
		return DiagnosticTestProof{}, errors.New("diagnostic test manifest names do not match source")
	}

	return DiagnosticTestProof{
		Manifest: c.TestManifest,
		Sources:  append([]DiagnosticTestSourcePin(nil), c.testManifest.Sources...),
		Tests:    append([]DiagnosticTestIdentity(nil), c.testManifest.Tests...),
		Count:    len(c.testManifest.Tests),
	}, nil
}

func safeRepositoryPath(path string) bool {
	clean := filepath.Clean(filepath.FromSlash(path))
	return path != "" && filepath.ToSlash(clean) == path && !filepath.IsAbs(clean) && clean != "." && !strings.HasPrefix(clean, ".."+string(filepath.Separator)) && filepath.Ext(clean) == ".go"
}

func sortedDiagnosticTestNames(proof DiagnosticTestProof) []string {
	names := make([]string, 0, len(proof.Tests))
	for _, test := range proof.Tests {
		names = append(names, test.Name)
	}
	sort.Strings(names)
	return names
}
