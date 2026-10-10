package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOperationPlanInstallRootRequiresCanonicalPinnedIndexPath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "installed")
	index := filepath.Join(root, "reports", "operation-observation-plan", "index.json")
	got, err := operationPlanInstallRootFromIndex(index)
	if err != nil || filepath.Clean(got) != filepath.Clean(root) {
		t.Fatalf("canonical pinned index did not bind its install root: root=%q err=%v", got, err)
	}
	for _, invalid := range []string{
		filepath.Join(root, "index.json"),
		filepath.Join(root, "reports", "elsewhere", "index.json"),
		"reports/operation-observation-plan/index.json",
	} {
		if _, err := operationPlanInstallRootFromIndex(invalid); err == nil {
			t.Fatalf("noncanonical or relative operation index path accepted: %q", invalid)
		}
	}
}

func TestOperationPlanProbeRunnerRejectsChildOutputThatDoesNotEqualCanonicalReceipt(t *testing.T) {
	for _, test := range []struct {
		name       string
		fileBytes  []byte
		stdoutMode string
	}{
		{
			name:       "valid receipt with truncated stdout",
			fileBytes:  []byte("valid"), // populated with the valid canonical receipt below
			stdoutMode: "truncated",
		},
		{
			name:       "matching malformed bytes still fail receipt validation",
			fileBytes:  []byte("{\"schema_version\":\"unknown\"}\n"),
			stdoutMode: "same",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			executable := filepath.Join(root, "actual-cli-placeholder")
			binary := []byte("#!/bin/sh\nexit 0\n")
			if err := os.WriteFile(executable, binary, 0o700); err != nil {
				t.Fatal(err)
			}
			binaryHash := sha256.Sum256(binary)
			credentialPath := filepath.Join(root, "bindings.json")
			if err := os.WriteFile(credentialPath, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			receiptDirectory := filepath.Join(root, "receipts")
			runner, err := NewOperationPlanProbeRunner(OperationPlanProbeConfig{
				ExecutablePath: executable, ExecutableSHA256: hex.EncodeToString(binaryHash[:]), CLIVersion: "v0.1.41",
				RegistryIndexPath: filepath.Join(root, "reports", "operation-observation-plan", "index.json"), CredentialBindings: credentialPath,
				ReceiptDirectory: receiptDirectory,
			})
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now().UTC().Add(-time.Second)
			expected := testOperationPlanProbeExpectation(started)
			expected.CLIBinarySHA256 = hex.EncodeToString(binaryHash[:])
			fileBytes := test.fileBytes
			if test.stdoutMode == "truncated" {
				observed := time.Now().UTC().Add(-100 * time.Millisecond)
				receipt := testOperationPlanProbeReceipt(expected, observed, "healthy", "response_assertion_passed", "passed", true, true, 1, 200)
				fileBytes = marshalOperationPlanProbeReceipt(t, receipt)
			}
			runner.childInvoker = func(_ context.Context, _ *os.File, args, _ []string, stdout, _ io.Writer) error {
				outputPath := ""
				for index := 0; index+1 < len(args); index++ {
					if args[index] == "--output" {
						outputPath = args[index+1]
						break
					}
				}
				if outputPath == "" {
					return os.ErrInvalid
				}
				if err := os.WriteFile(outputPath, fileBytes, 0o600); err != nil {
					return err
				}
				bytes := fileBytes
				if test.stdoutMode == "truncated" {
					bytes = []byte("truncated\n")
				}
				_, err := stdout.Write(bytes)
				return err
			}
			_, _, err = runner.Run(context.Background(), expected, time.Now().UTC().Add(5*time.Second))
			if err == nil {
				t.Fatal("runner accepted child bytes that were truncated or not a canonical receipt")
			}
		})
	}
}
