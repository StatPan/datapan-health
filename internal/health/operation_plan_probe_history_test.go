package health

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestOperationPlanProbeHistoryValidatorRevalidatesAndSealsReceipt(t *testing.T) {
	startedAt := time.Now().UTC().Add(-2 * time.Second)
	receivedAt := time.Now().UTC()
	expected := testOperationPlanProbeExpectation(startedAt)
	receipt := testOperationPlanProbeReceipt(expected, receivedAt.Add(-time.Second), "healthy", "response_assertion_passed", "passed", true, true, 1, 200)
	raw := marshalOperationPlanProbeReceipt(t, receipt)
	result, err := ValidateOperationPlanProbeReceipt(raw, expected, startedAt, receivedAt, 0)
	if err != nil {
		t.Fatalf("valid receipt fixture rejected: %v", err)
	}

	identity := OperationHistoryIdentity{
		SourceID:              expected.SourceID,
		OperationID:           expected.OperationID,
		AttemptID:             expected.AttemptID,
		Generation:            9,
		RegistryRevision:      expected.RegistryRevision,
		ReleaseManifestSHA256: expected.ReleaseManifestSHA256,
		IndexSHA256:           expected.IndexSHA256,
		ShardSHA256:           expected.ShardSHA256,
	}
	validator, err := NewOperationPlanProbeHistoryValidator(strings.Repeat("9", 40))
	if err != nil {
		t.Fatal("valid Health revision rejected")
	}
	sealed, err := validator.newRecord(identity, result, startedAt)
	if err != nil {
		t.Fatalf("validated receipt could not be sealed: %v", err)
	}
	if err := sealed.Validate(); err != nil {
		t.Fatalf("sealed record failed self-validation: %v", err)
	}
	reopened, err := validator.ValidateStoredOperationHistoryRecord(context.Background(), sealed)
	if err != nil || reopened.Validate() != nil {
		t.Fatalf("stored receipt did not revalidate: err=%v", err)
	}

	tests := []struct {
		name   string
		mutate func(*OperationHistoryRecord)
	}{
		{name: "wrong attempt identity", mutate: func(record *OperationHistoryRecord) {
			record.Identity.AttemptID = "00000000-0000-4000-8000-000000000001"
		}},
		{name: "wrong operation identity", mutate: func(record *OperationHistoryRecord) { record.Identity.OperationID = strings.Repeat("7", 64) }},
		{name: "wrong manifest pin", mutate: func(record *OperationHistoryRecord) { record.Identity.ReleaseManifestSHA256 = strings.Repeat("8", 64) }},
		{name: "wrong index pin", mutate: func(record *OperationHistoryRecord) { record.Identity.IndexSHA256 = strings.Repeat("8", 64) }},
		{name: "wrong shard pin", mutate: func(record *OperationHistoryRecord) { record.Identity.ShardSHA256 = strings.Repeat("8", 64) }},
		{name: "wrong receipt schema pin", mutate: func(record *OperationHistoryRecord) { record.ReceiptSchemaSHA256 = strings.Repeat("8", 64) }},
		{name: "wrong receipt digest", mutate: func(record *OperationHistoryRecord) { record.ReceiptSHA256 = strings.Repeat("8", 64) }},
		{name: "future validation timestamp", mutate: func(record *OperationHistoryRecord) { record.ValidatedAt = time.Now().UTC().Add(time.Hour) }},
		{name: "attempt after validation", mutate: func(record *OperationHistoryRecord) { record.AttemptStartedAt = record.ValidatedAt.Add(time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := sealed
			candidate.ReceiptBytes = append([]byte(nil), sealed.ReceiptBytes...)
			test.mutate(&candidate)
			if _, err := validator.ValidateStoredOperationHistoryRecord(context.Background(), candidate); err == nil {
				t.Fatal("invalid stored receipt was re-sealed")
			}
		})
	}

	duplicate := sealed
	duplicate.ReceiptBytes = []byte(strings.Replace(string(sealed.ReceiptBytes), `"outcome":"healthy"`, `"outcome":"healthy","outcome":"healthy"`, 1))
	if _, err := validator.ValidateStoredOperationHistoryRecord(context.Background(), duplicate); err == nil {
		t.Fatal("duplicate receipt member was re-sealed")
	}
	if _, err := validator.ValidateStoredOperationHistoryRecord(nil, sealed); err == nil {
		t.Fatal("nil context was accepted")
	}
}
