package health

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type DiagnosisSourceProof struct {
	Sources []ArtifactPin `json:"sources"`
	Tests   []string      `json:"tests"`
}

func BindDiagnosisProjectionEvidence(receipt *DiagnosisProjectionReceipt, healthHead, testedRevision, repoRoot string) error {
	if receipt == nil || !commitPattern.MatchString(healthHead) || !commitPattern.MatchString(testedRevision) || receipt.SchemaVersion != DiagnosisProjectionReceiptVersion {
		return errors.New("diagnosis projection evidence requires exact revisions")
	}
	paths := []string{"schemas/datapan.health-public-diagnosis-snapshot.v1.schema.json", "internal/health/diagnosis_snapshot.go", "internal/health/diagnosis_snapshot_test.go"}
	sources := make([]ArtifactPin, 0, len(paths))
	for _, path := range paths {
		raw, err := os.ReadFile(filepath.Join(repoRoot, path))
		if err != nil {
			return err
		}
		sha := digest(raw)
		if path == paths[0] && sha != DiagnosisSnapshotSchemaSHA256 {
			return errors.New("diagnosis snapshot schema digest drifted")
		}
		sources = append(sources, ArtifactPin{Path: path, SHA256: sha})
	}
	testPath := filepath.Join(repoRoot, "internal/health/diagnosis_snapshot_test.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), testPath, nil, 0)
	if err != nil {
		return errors.New("diagnosis snapshot tests cannot be parsed")
	}
	var tests []string
	for _, declaration := range parsed.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv == nil && strings.HasPrefix(function.Name.Name, "TestDiagnosisSnapshot") {
			tests = append(tests, function.Name.Name)
		}
	}
	sort.Strings(tests)
	if len(tests) < 8 {
		return errors.New("diagnosis snapshot cross-contract test proof is incomplete")
	}
	receipt.HealthHead = healthHead
	receipt.TestedRevision = testedRevision
	receipt.SnapshotSchemaSHA256 = DiagnosisSnapshotSchemaSHA256
	receipt.SourceProof = &DiagnosisSourceProof{Sources: sources, Tests: tests}
	return nil
}
