package health

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/StatPan/datapan-health/internal/runtimebundle"
	"github.com/StatPan/datapan-health/schemas"
)

const operationPlanProbeHistoryValidatorIdentity = "datapan-health-operation-plan-probe"

var errOperationPlanProbeHistoryUnavailable = errors.New("operation-plan receipt history is unavailable")

// OperationPlanProbeHistoryValidator revalidates exact CLI receipt bytes when
// archive records are reopened after a restart. ValidatorRevision identifies
// the Health source revision that accepted a newly appended record.
type OperationPlanProbeHistoryValidator struct {
	ValidatorRevision string
	Expectations      OperationPlanProbeExpectationResolver
}

// OperationPlanProbeExpectationResolver supplies authority independently from
// the receipt bytes being validated. Implementations must resolve only from a
// verified, immutable Registry/runtime binding.
type OperationPlanProbeExpectationResolver interface {
	ResolveOperationPlanProbeExpectation(context.Context, OperationHistoryIdentity, time.Time) (OperationPlanProbeExpectation, error)
}

type OperationPlanProbeHistoryRecordValidator interface {
	OperationHistoryRecordValidator
	ValidateStoredOperationPlanProbeRecord(context.Context, OperationHistoryRecord) (OperationHistoryRecord, OperationPlanProbeResult, error)
}

func NewOperationPlanProbeHistoryValidator(validatorRevision string, expectations OperationPlanProbeExpectationResolver) (OperationPlanProbeHistoryValidator, error) {
	if !commitPattern.MatchString(validatorRevision) || expectations == nil {
		return OperationPlanProbeHistoryValidator{}, errOperationPlanProbeHistoryUnavailable
	}
	return OperationPlanProbeHistoryValidator{ValidatorRevision: validatorRevision, Expectations: expectations}, nil
}

// NewRecord seals an already validated child receipt for durable append. The
// receipt is validated again against the immutable archive identity so callers
// cannot accidentally pair a result with another operation or plan shard.
func (validator OperationPlanProbeHistoryValidator) newRecord(identity OperationHistoryIdentity, result OperationPlanProbeResult, expected OperationPlanProbeExpectation, attemptStartedAt time.Time) (OperationHistoryRecord, error) {
	if !commitPattern.MatchString(validator.ValidatorRevision) || validator.Expectations == nil || identity.Validate() != nil || !utcNormalized(attemptStartedAt) {
		return OperationHistoryRecord{}, errOperationPlanProbeHistoryUnavailable
	}
	resolved, err := validator.resolveExpectation(context.Background(), identity, attemptStartedAt)
	if err != nil || !operationPlanProbeExpectationsEqual(resolved, expected) {
		return OperationHistoryRecord{}, errOperationPlanProbeHistoryUnavailable
	}
	checked, err := ValidateOperationPlanProbeReceipt(result.ReceiptBytes, expected, attemptStartedAt, result.ReceivedAt, operationPlanProbeExitCode(result.Receipt.Observation.Outcome))
	if err != nil || checked.ReceiptSHA256 != result.ReceiptSHA256 || checked.Outcome != result.Outcome || checked.ObservedAt != result.ObservedAt || checked.RequestStarted != result.RequestStarted || checked.HTTPStatus != result.HTTPStatus || checked.Latency != result.Latency {
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
	validated, _, err := validator.ValidateStoredOperationPlanProbeRecord(context.Background(), record)
	if err != nil {
		return OperationHistoryRecord{}, err
	}
	return validated, nil
}

// ValidateStoredOperationHistoryRecord checks the pinned receipt schema, exact
// canonical bytes and digest, semantic outcome/timestamp rules, and all
// attempt/release/shard identities before recreating the package-private seal.
func (validator OperationPlanProbeHistoryValidator) ValidateStoredOperationHistoryRecord(ctx context.Context, candidate OperationHistoryRecord) (OperationHistoryRecord, error) {
	validated, _, err := validator.ValidateStoredOperationPlanProbeRecord(ctx, candidate)
	return validated, err
}

// ValidateStoredOperationPlanProbeRecord returns both a resealed archive value
// and its typed result, using independently resolved plan/runtime expectations.
func (validator OperationPlanProbeHistoryValidator) ValidateStoredOperationPlanProbeRecord(ctx context.Context, candidate OperationHistoryRecord) (OperationHistoryRecord, OperationPlanProbeResult, error) {
	if ctx == nil || ctx.Err() != nil {
		return OperationHistoryRecord{}, OperationPlanProbeResult{}, errOperationPlanProbeHistoryUnavailable
	}
	if !commitPattern.MatchString(validator.ValidatorRevision) || validator.Expectations == nil ||
		candidate.ValidatorIdentity != operationPlanProbeHistoryValidatorIdentity ||
		!commitPattern.MatchString(candidate.ValidatorRevision) ||
		candidate.ReceiptSchemaURI != OperationPlanProbeReceiptSchemaURI ||
		candidate.ReceiptSchemaVersion != OperationPlanProbeReceiptSchemaVersion ||
		candidate.ReceiptSchemaSHA256 != OperationPlanProbeReceiptSchemaSHA256 ||
		schemas.HealthOperationPlanProbeV1SchemaSHA256() != OperationPlanProbeReceiptSchemaSHA256 ||
		validateOperationHistoryRecordFields(candidate) != nil ||
		len(candidate.ReceiptBytes) > maxOperationPlanProbeReceiptBytes ||
		futureOperationHistoryTime(candidate.ValidatedAt, time.Now().UTC()) {
		return OperationHistoryRecord{}, OperationPlanProbeResult{}, errOperationPlanProbeHistoryUnavailable
	}

	decoder := json.NewDecoder(bytes.NewReader(candidate.ReceiptBytes))
	decoder.DisallowUnknownFields()
	var receipt operationPlanProbeReceipt
	if decoder.Decode(&receipt) != nil || ensureEOF(decoder) != nil {
		return OperationHistoryRecord{}, OperationPlanProbeResult{}, errOperationPlanProbeHistoryUnavailable
	}
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return OperationHistoryRecord{}, OperationPlanProbeResult{}, errOperationPlanProbeHistoryUnavailable
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(canonical, candidate.ReceiptBytes) {
		return OperationHistoryRecord{}, OperationPlanProbeResult{}, errOperationPlanProbeHistoryUnavailable
	}

	identity := candidate.Identity
	expected, err := validator.resolveExpectation(ctx, identity, candidate.AttemptStartedAt)
	if err != nil {
		return OperationHistoryRecord{}, OperationPlanProbeResult{}, errOperationPlanProbeHistoryUnavailable
	}
	result, err := ValidateOperationPlanProbeReceipt(candidate.ReceiptBytes, expected, candidate.AttemptStartedAt, candidate.ValidatedAt, operationPlanProbeExitCode(receipt.Observation.Outcome))
	if err != nil || result.ReceiptSHA256 != candidate.ReceiptSHA256 {
		return OperationHistoryRecord{}, OperationPlanProbeResult{}, errOperationPlanProbeHistoryUnavailable
	}
	sealed, err := newValidatedOperationHistoryRecord(candidate)
	if err != nil {
		return OperationHistoryRecord{}, OperationPlanProbeResult{}, errOperationPlanProbeHistoryUnavailable
	}
	return sealed, result, nil
}

func (validator OperationPlanProbeHistoryValidator) resolveExpectation(ctx context.Context, identity OperationHistoryIdentity, startedAt time.Time) (OperationPlanProbeExpectation, error) {
	if ctx == nil || ctx.Err() != nil || validator.Expectations == nil || identity.Validate() != nil || !utcNormalized(startedAt) {
		return OperationPlanProbeExpectation{}, errOperationPlanProbeHistoryUnavailable
	}
	expected, err := validator.Expectations.ResolveOperationPlanProbeExpectation(ctx, identity, startedAt)
	if err != nil || !operationPlanProbeExpectationMatchesIdentity(expected, identity, startedAt) {
		return OperationPlanProbeExpectation{}, errOperationPlanProbeHistoryUnavailable
	}
	return expected, nil
}

func operationPlanProbeExpectationMatchesIdentity(expected OperationPlanProbeExpectation, identity OperationHistoryIdentity, startedAt time.Time) bool {
	return expected.AttemptID == identity.AttemptID && expected.SourceID == identity.SourceID && expected.OperationID == identity.OperationID && expected.RegistryRevision == identity.RegistryRevision && expected.ReleaseManifestSHA256 == identity.ReleaseManifestSHA256 && expected.IndexSHA256 == identity.IndexSHA256 && expected.ShardSHA256 == identity.ShardSHA256 && expected.StartedAt.Equal(startedAt.UTC()) && validOperationProbeExpectation(expected, OperationPlanProbeConfig{CLIVersion: expected.CLIVersion, ExecutableSHA256: expected.CLIBinarySHA256})
}

func operationPlanProbeExpectationsEqual(left, right OperationPlanProbeExpectation) bool {
	return left.AttemptID == right.AttemptID && left.CLIVersion == right.CLIVersion && left.CLIBinarySHA256 == right.CLIBinarySHA256 && left.DatasetID == right.DatasetID && left.Distribution == right.Distribution && left.DistributionDatasetRevision == right.DistributionDatasetRevision && left.RegistrySHA256 == right.RegistrySHA256 && left.RegistryRevision == right.RegistryRevision && left.ReleaseManifestSHA256 == right.ReleaseManifestSHA256 && left.OperationManifestSHA256 == right.OperationManifestSHA256 && left.ProviderIndexSHA256 == right.ProviderIndexSHA256 && left.PlanSchemaSHA256 == right.PlanSchemaSHA256 && left.IndexSHA256 == right.IndexSHA256 && left.ShardSHA256 == right.ShardSHA256 && left.SourceIdentitySetSHA256 == right.SourceIdentitySetSHA256 && left.SourceID == right.SourceID && left.OperationID == right.OperationID && left.Provider == right.Provider && left.AdapterID == right.AdapterID && left.Protocol == right.Protocol && left.ResponseAssertionKind == right.ResponseAssertionKind && left.RequestTimeout == right.RequestTimeout && left.StartedAt.Equal(right.StartedAt)
}

// PinnedOperationPlanProbeExpectationResolver derives historic receipt
// expectations from one already verified Registry plan and the immutable CLI
// runtime lock. It deliberately resolves only the currently image-pinned
// release; records from another release remain unavailable until that exact
// historical binding is installed again.
type PinnedOperationPlanProbeExpectationResolver struct {
	plan      PinnedOperationObservationPlan
	lock      runtimebundle.Lock
	arch      string
	templates map[string]OperationPlanProbeExpectation
}

func NewPinnedOperationPlanProbeExpectationResolver(plan PinnedOperationObservationPlan, lock runtimebundle.Lock, arch string) (*PinnedOperationPlanProbeExpectationResolver, error) {
	if plan.state == nil || !plan.state.verified || lock.Validate() != nil || arch == "" || plan.Counts().KnownOperations < 0 || plan.Counts().KnownOperations > maxOperationGatusTargets {
		return nil, errOperationPlanProbeHistoryUnavailable
	}
	if !operationPlanProbeGenerationInputPinsMatchSource(plan.state) {
		return nil, errOperationPlanProbeHistoryUnavailable
	}
	resolver := &PinnedOperationPlanProbeExpectationResolver{plan: plan, lock: lock, arch: arch, templates: make(map[string]OperationPlanProbeExpectation)}
	const templateAttemptID = "00000000-0000-4000-8000-000000000000"
	templateStart := time.Unix(1, 0).UTC()
	for shardIndex, ref := range plan.state.index.Shards {
		records, err := plan.ReadShard(shardIndex)
		if err != nil {
			return nil, errOperationPlanProbeHistoryUnavailable
		}
		for _, record := range records {
			if !record.ExecutionEligible {
				continue
			}
			expected, err := operationPlanProbeExpected(plan, record, ref.SHA256, templateAttemptID, lock, arch, templateStart)
			if err != nil {
				return nil, errOperationPlanProbeHistoryUnavailable
			}
			key := operationReadModelIdentityKey(record.SourceID, record.OperationID)
			if _, exists := resolver.templates[key]; exists {
				return nil, errOperationPlanProbeHistoryUnavailable
			}
			resolver.templates[key] = expected
		}
	}
	return resolver, nil
}

func operationPlanProbeGenerationInputPinsMatchSource(state *operationPlanIndexState) bool {
	if state == nil || !state.verified || len(state.index.GenerationInputs) == 0 {
		return false
	}
	var inputs operationObservationPlanGenerationInputs
	if json.Unmarshal(state.index.GenerationInputs, &inputs) != nil || !validOperationPlanGenerationInputs(inputs, state.manifest) || inputs.OperationManifest != state.operationManifestRef {
		return false
	}
	if inputs.ProviderIndex == nil {
		return !state.providerIndexRefExists && state.providerIndexRef == (operationPlanArtifactRef{})
	}
	return state.providerIndexRefExists && *inputs.ProviderIndex == state.providerIndexRef
}

func (resolver *PinnedOperationPlanProbeExpectationResolver) ResolveOperationPlanProbeExpectation(ctx context.Context, identity OperationHistoryIdentity, startedAt time.Time) (OperationPlanProbeExpectation, error) {
	if resolver == nil || ctx == nil || ctx.Err() != nil || identity.Validate() != nil || !utcNormalized(startedAt) || identity.RegistryRevision != resolver.plan.RegistryRevision() || identity.ReleaseManifestSHA256 != resolver.plan.binding.ReleaseManifestSHA256 || identity.IndexSHA256 != resolver.plan.IndexSHA256() {
		return OperationPlanProbeExpectation{}, errOperationPlanProbeHistoryUnavailable
	}
	expected, found := resolver.templates[operationReadModelIdentityKey(identity.SourceID, identity.OperationID)]
	if !found || expected.ShardSHA256 != identity.ShardSHA256 {
		return OperationPlanProbeExpectation{}, errOperationPlanProbeHistoryUnavailable
	}
	expected.AttemptID = identity.AttemptID
	expected.StartedAt = startedAt.UTC()
	return expected, nil
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
