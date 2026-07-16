package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadAssertionsRejectsExternallyAssessedEvaluationWrapper(t *testing.T) {
	path := filepath.Join(t.TempDir(), "assertions.json")
	forged := `[{
  "assessed_at":"2026-07-17T00:15:00Z",
  "evaluation":{
    "schema_version":"datapan.health-assertion-evaluation.v1",
    "assessed_at":"2026-07-17T00:15:00Z",
    "operation_id":"dpr-op-00000001",
    "dimension":"contract",
    "outcome":"fail",
    "reason_code":"undeclared_response_field",
    "observed_field_count":-1
  }
}]`
	if err := os.WriteFile(path, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAssertions(path); err == nil {
		t.Fatal("externally assessed assertion evaluation was accepted")
	}
}
