package health

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type fixedOperationPlanProbeExpectationResolver struct {
	expected OperationPlanProbeExpectation
}

func (resolver fixedOperationPlanProbeExpectationResolver) ResolveOperationPlanProbeExpectation(_ context.Context, _ OperationHistoryIdentity, startedAt time.Time) (OperationPlanProbeExpectation, error) {
	expected := resolver.expected
	expected.StartedAt = startedAt.UTC()
	return expected, nil
}

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
	validator, err := NewOperationPlanProbeHistoryValidator(strings.Repeat("9", 40), fixedOperationPlanProbeExpectationResolver{expected: expected})
	if err != nil {
		t.Fatal("valid Health revision rejected")
	}
	sealed, err := validator.newRecord(identity, result, expected, startedAt)
	if err != nil {
		t.Fatalf("validated receipt could not be sealed: %v", err)
	}
	wrongExpected := expected
	wrongExpected.CLIBinarySHA256 = strings.Repeat("f", 64)
	if _, err := validator.newRecord(identity, result, wrongExpected, startedAt); err == nil {
		t.Fatal("receipt was sealed against a caller-selected CLI binary expectation")
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

	for _, test := range []struct {
		name   string
		mutate func(*operationPlanProbeReceipt)
	}{
		{name: "forged CLI digest", mutate: func(receipt *operationPlanProbeReceipt) { receipt.CLI.BinarySHA256 = strings.Repeat("f", 64) }},
		{name: "forged provider", mutate: func(receipt *operationPlanProbeReceipt) { receipt.Operation.Provider = "attacker.example" }},
		{name: "forged adapter", mutate: func(receipt *operationPlanProbeReceipt) { receipt.Operation.AdapterID = "other-adapter" }},
		{name: "forged source identity set", mutate: func(receipt *operationPlanProbeReceipt) {
			receipt.Registry.SourceIdentitySetSHA256 = strings.Repeat("e", 64)
		}},
		{name: "forged response assertion mode", mutate: func(receipt *operationPlanProbeReceipt) { receipt.Observation.AssertionKind = "http_status" }},
	} {
		t.Run("receipt cannot authorize itself: "+test.name, func(t *testing.T) {
			candidate := sealed
			candidate.ReceiptBytes = append([]byte(nil), sealed.ReceiptBytes...)
			var receipt operationPlanProbeReceipt
			if err := json.Unmarshal(candidate.ReceiptBytes, &receipt); err != nil {
				t.Fatal(err)
			}
			test.mutate(&receipt)
			raw, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			candidate.ReceiptBytes = append(raw, '\n')
			candidate.ReceiptSHA256 = digest(candidate.ReceiptBytes)
			if _, err := validator.ValidateStoredOperationHistoryRecord(context.Background(), candidate); err == nil {
				t.Fatal("receipt fields were accepted as their own expected authority")
			}
		})
	}
}
