package health

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

const operationPlanProbeHistoryValidatorIdentity = "datapan-health-operation-plan-probe"

var errOperationPlanProbeHistoryUnavailable = errors.New("operation-plan receipt history is unavailable")

// OperationPlanProbeHistoryValidator revalidates exact CLI receipt bytes when
// archive records are reopened after a restart. ValidatorRevision identifies
// the Health source revision that accepted a newly appended record.
type OperationPlanProbeHistoryValidator struct {
	ValidatorRevision string
}

func NewOperationPlanProbeHistoryValidator(validatorRevision string) (OperationPlanProbeHistoryValidator, error) {
	if !commitPattern.MatchString(validatorRevision) {
		return OperationPlanProbeHistoryValidator{}, errOperationPlanProbeHistoryUnavailable
	}
	return OperationPlanProbeHistoryValidator{ValidatorRevision: validatorRevision}, nil
}

// NewRecord seals an already validated child receipt for durable append. The
// receipt is validated again against the immutable archive identity so callers
// cannot accidentally pair a result with another operation or plan shard.
func (validator OperationPlanProbeHistoryValidator) newRecord(identity OperationHistoryIdentity, result OperationPlanProbeResult, attemptStartedAt time.Time) (OperationHistoryRecord, error) {
	if !commitPattern.MatchString(validator.ValidatorRevision) || identity.Validate() != nil {
		return OperationHistoryRecord{}, errOperationPlanProbeHistoryUnavailable
	}
	record := OperationHistoryRecord{
		SchemaVersion:        OperationHistoryRecordSchemaVersion,
		Identity:             identity,
		ReceiptSchemaURI:     OperationPlanProbeReceiptSchemaURI,
		ReceiptSchemaVersion: OperationPlanProbeReceiptSchemaVersion,
		ReceiptSchemaSHA256:  OperationPlanProbeReceiptSchemaSHA256,
		ReceiptSHA256:        result.ReceiptSHA256,
		ReceiptBytes:         append([]byte(nil), result.ReceiptBytes...),
		ValidatorIdentity:    operationPlanProbeHistoryValidatorIdentity,
		ValidatorRevision:    validator.ValidatorRevision,
		AttemptStartedAt:     attemptStartedAt.UTC(),
		ValidatedAt:          result.ReceivedAt.UTC(),
	}
	validated, err := validator.ValidateStoredOperationHistoryRecord(context.Background(), record)
	if err != nil {
		return OperationHistoryRecord{}, err
	}
	return validated, nil
}

// ValidateStoredOperationHistoryRecord checks the pinned receipt schema, exact
// canonical bytes and digest, semantic outcome/timestamp rules, and all
// attempt/release/shard identities before recreating the package-private seal.
func (validator OperationPlanProbeHistoryValidator) ValidateStoredOperationHistoryRecord(ctx context.Context, candidate OperationHistoryRecord) (OperationHistoryRecord, error) {
	if ctx == nil || ctx.Err() != nil {
		return OperationHistoryRecord{}, errOperationPlanProbeHistoryUnavailable
	}
	if !commitPattern.MatchString(validator.ValidatorRevision) ||
		candidate.ValidatorIdentity != operationPlanProbeHistoryValidatorIdentity ||
		!commitPattern.MatchString(candidate.ValidatorRevision) ||
		candidate.ReceiptSchemaURI != OperationPlanProbeReceiptSchemaURI ||
		candidate.ReceiptSchemaVersion != OperationPlanProbeReceiptSchemaVersion ||
		candidate.ReceiptSchemaSHA256 != OperationPlanProbeReceiptSchemaSHA256 ||
		schemas.HealthOperationPlanProbeV1SchemaSHA256() != OperationPlanProbeReceiptSchemaSHA256 ||
		validateOperationHistoryRecordFields(candidate) != nil ||
		len(candidate.ReceiptBytes) > maxOperationPlanProbeReceiptBytes ||
		futureOperationHistoryTime(candidate.ValidatedAt, time.Now().UTC()) {
		return OperationHistoryRecord{}, errOperationPlanProbeHistoryUnavailable
	}

	decoder := json.NewDecoder(bytes.NewReader(candidate.ReceiptBytes))
	decoder.DisallowUnknownFields()
	var receipt operationPlanProbeReceipt
	if decoder.Decode(&receipt) != nil || ensureEOF(decoder) != nil {
		return OperationHistoryRecord{}, errOperationPlanProbeHistoryUnavailable
	}
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return OperationHistoryRecord{}, errOperationPlanProbeHistoryUnavailable
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, candidate.ReceiptBytes) {
		return OperationHistoryRecord{}, errOperationPlanProbeHistoryUnavailable
	}

	identity := candidate.Identity
	if receipt.AttemptID != identity.AttemptID ||
		receipt.Operation.SourceID != identity.SourceID ||
		receipt.Operation.OperationID != identity.OperationID ||
		receipt.Registry.RegistryRevision != identity.RegistryRevision ||
		receipt.Registry.ManifestSHA256 != identity.ReleaseManifestSHA256 ||
		receipt.Registry.IndexSHA256 != identity.IndexSHA256 ||
		receipt.Registry.ShardSHA256 != identity.ShardSHA256 {
		return OperationHistoryRecord{}, errOperationPlanProbeHistoryUnavailable
	}

	expected := operationPlanProbeExpectationFromReceipt(receipt, candidate.AttemptStartedAt)
	result, err := ValidateOperationPlanProbeReceipt(candidate.ReceiptBytes, expected, candidate.AttemptStartedAt, candidate.ValidatedAt, operationPlanProbeExitCode(receipt.Observation.Outcome))
	if err != nil || result.ReceiptSHA256 != candidate.ReceiptSHA256 {
		return OperationHistoryRecord{}, errOperationPlanProbeHistoryUnavailable
	}
	return newValidatedOperationHistoryRecord(candidate)
}

func operationPlanProbeExpectationFromReceipt(receipt operationPlanProbeReceipt, startedAt time.Time) OperationPlanProbeExpectation {
	return OperationPlanProbeExpectation{
		AttemptID:                   receipt.AttemptID,
		CLIVersion:                  receipt.CLI.Version,
		CLIBinarySHA256:             receipt.CLI.BinarySHA256,
		DatasetID:                   receipt.Registry.DatasetID,
		Distribution:                receipt.Registry.Distribution,
		DistributionDatasetRevision: receipt.Registry.DistributionDatasetRevision,
		RegistrySHA256:              receipt.Registry.RegistrySHA256,
		RegistryRevision:            receipt.Registry.RegistryRevision,
		ReleaseManifestSHA256:       receipt.Registry.ManifestSHA256,
		OperationManifestSHA256:     receipt.Registry.OperationManifestSHA256,
		ProviderIndexSHA256:         receipt.Registry.ProviderIndexSHA256,
		PlanSchemaSHA256:            receipt.Registry.PlanSchemaSHA256,
		IndexSHA256:                 receipt.Registry.IndexSHA256,
		ShardSHA256:                 receipt.Registry.ShardSHA256,
		SourceIdentitySetSHA256:     receipt.Registry.SourceIdentitySetSHA256,
		SourceID:                    receipt.Operation.SourceID,
		OperationID:                 receipt.Operation.OperationID,
		Provider:                    receipt.Operation.Provider,
		AdapterID:                   receipt.Operation.AdapterID,
		Protocol:                    receipt.Operation.Protocol,
		RequestTimeout:              time.Duration(receipt.Execution.TimeoutMS) * time.Millisecond,
		StartedAt:                   startedAt.UTC(),
	}
}

func operationPlanProbeExitCode(outcome string) int {
	switch outcome {
	case "healthy":
		return 0
	case "blocked":
		return 3
	case "unhealthy", "indeterminate":
		return 4
	default:
		return -1
	}
}

func futureOperationHistoryTime(candidate, now time.Time) bool {
	return candidate.After(now.Add(time.Second))
}
