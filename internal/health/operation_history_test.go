package health

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestOperationHistoryRecordValidationBindsExactRedactedReceipt(t *testing.T) {
	receipt := []byte("{\"schema_version\":\"fixture.v1\",\"state\":\"healthy\"}\n")
	sum := sha256.Sum256(receipt)
	record := OperationHistoryRecord{
		SchemaVersion: OperationHistoryRecordSchemaVersion,
		Identity: OperationHistoryIdentity{
			SourceID:              "data_go_kr",
			OperationID:           strings.Repeat("a", 64),
			AttemptID:             "00000000-0000-4000-8000-000000000001",
			Generation:            7,
			RegistryRevision:      strings.Repeat("b", 40),
			ReleaseManifestSHA256: strings.Repeat("c", 64),
			IndexSHA256:           strings.Repeat("d", 64),
			ShardSHA256:           strings.Repeat("e", 64),
		},
		ReceiptSchemaURI:     "https://schemas.datapan.dev/datapan.health-operation-receipt.v1.schema.json",
		ReceiptSchemaVersion: "datapan.health-operation-receipt.v1",
		ReceiptSchemaSHA256:  strings.Repeat("f", 64),
		ReceiptSHA256:        hex.EncodeToString(sum[:]),
		ReceiptBytes:         receipt,
		ValidatorIdentity:    "datapan-cli-health-receipt",
		ValidatorRevision:    strings.Repeat("1", 40),
		AttemptStartedAt:     time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC).Add(-time.Minute),
		ValidatedAt:          time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC),
	}
	if err := validateOperationHistoryRecord(record); err == nil {
		t.Fatal("unvalidated receipt construction was accepted")
	}
	record, err := newValidatedOperationHistoryRecord(record)
	if err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
	receipt[0] = 'x'
	if err := record.Validate(); err != nil {
		t.Fatalf("constructor did not defensively copy receipt bytes: %v", err)
	}

	mutated := record
	mutated.ReceiptBytes = []byte("{\"schema_version\":\"fixture.v1\",\"state\":\"unhealthy\"}\n")
	mutatedDigest := sha256.Sum256(mutated.ReceiptBytes)
	mutated.ReceiptSHA256 = hex.EncodeToString(mutatedDigest[:])
	if err := mutated.Validate(); err == nil {
		t.Fatal("record accepted mutated receipt evidence after its digest was recomputed")
	}
	mutated = record
	mutated.Identity.IndexSHA256 = strings.Repeat("9", 64)
	if err := mutated.Validate(); err == nil {
		t.Fatal("record accepted a changed immutable Registry pin after validation")
	}

	mutated = record
	mutated.ReceiptSchemaURI += "?token=redacted"
	if err := mutated.Validate(); err == nil {
		t.Fatal("record accepted a query-bearing receipt schema URI")
	}

	mutated = record
	mutated.AttemptStartedAt = mutated.ValidatedAt.Add(time.Second)
	if err := mutated.Validate(); err == nil {
		t.Fatal("record accepted an attempt that started after validation")
	}
	mutated = record
	mutated.AttemptStartedAt = mutated.AttemptStartedAt.In(time.FixedZone("UTC", 0))
	if err := mutated.Validate(); err == nil {
		t.Fatal("record accepted an attempt timestamp that was not normalized to UTC")
	}

	mutated = record
	mutated.ReceiptBytes = []byte(`{"data":"` + strings.Repeat("x", MaxOperationHistoryReceiptBytes) + `"}`)
	sum = sha256.Sum256(mutated.ReceiptBytes)
	mutated.ReceiptSHA256 = hex.EncodeToString(sum[:])
	if err := mutated.Validate(); err == nil {
		t.Fatal("record accepted a receipt over the fixed reservation bound")
	}
}
