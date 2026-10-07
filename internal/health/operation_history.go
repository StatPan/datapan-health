package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	OperationHistoryRecordSchemaVersion    = "datapan.health-operation-archive.v2"
	MaxOperationHistoryReceiptBytes        = 64 * 1024
	MaxOperationHistorySerializedReceipt   = ((MaxOperationHistoryReceiptBytes + 2) / 3) * 4
	OperationHistoryEnvelopeReserveBytes   = 8 * 1024
	OperationHistoryAtomicTempReserveBytes = MaxOperationHistorySerializedReceipt + OperationHistoryEnvelopeReserveBytes
	OperationHistoryJournalReserveBytes    = 4 * 1024
	MaxOperationHistoryReservedBytes       = MaxOperationHistoryReceiptBytes + MaxOperationHistorySerializedReceipt + OperationHistoryEnvelopeReserveBytes + OperationHistoryAtomicTempReserveBytes + OperationHistoryJournalReserveBytes
	MaxOperationHistoryBatchRecords        = 256
	MaxOperationHistoryBatchBytes          = 8 * 1024 * 1024
)

var (
	ErrOperationHistoryUnavailable       = errors.New("operation history archive is unavailable")
	ErrOperationHistoryCapacity          = errors.New("operation history archive capacity is full")
	ErrOperationHistoryReserved          = errors.New("operation history reservation is unavailable")
	ErrOperationHistoryStale             = errors.New("operation history attempt generation is stale")
	ErrOperationHistoryConflict          = errors.New("operation history identity conflicts with existing evidence")
	ErrOperationHistoryCorrupt           = errors.New("operation history archive is corrupt")
	operationHistorySourcePattern        = regexp.MustCompile(`^[a-z0-9]+(?:_[a-z0-9]+)*$`)
	operationHistoryAttemptPattern       = regexp.MustCompile(`^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|[0-9a-f]{64})$`)
	operationHistorySchemaVersionPattern = regexp.MustCompile(`^[a-z0-9]+(?:[.-][a-z0-9]+)*$`)
	operationHistoryValidatorPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
)

// OperationHistoryIdentity binds one receipt to the exact operation attempt
// and Registry policy inputs that admitted it. The manifest/index/shard pins
// are part of the identity because one Registry revision may contain multiple
// policy-bound operation plans.
type OperationHistoryIdentity struct {
	SourceID              string `json:"source_id"`
	OperationID           string `json:"operation_id"`
	AttemptID             string `json:"attempt_id"`
	Generation            uint64 `json:"generation"`
	RegistryRevision      string `json:"registry_revision"`
	ReleaseManifestSHA256 string `json:"release_manifest_sha256"`
	IndexSHA256           string `json:"index_sha256"`
	ShardSHA256           string `json:"shard_sha256"`
}

func (identity OperationHistoryIdentity) Validate() error {
	if !validateOperationHistoryIdentity(identity) {
		return ErrOperationHistoryUnavailable
	}
	return nil
}

// OperationHistoryRecord is the immutable, redacted evidence accepted by the
// long-term generic-operation archive. ReceiptBytes are the exact canonical
// bytes already validated by the worker and atomically captured in its 0600
// receipt file. Provider URLs, credentials, and response rows are not added by
// this archive layer.
type OperationHistoryRecord struct {
	SchemaVersion        string                   `json:"schema_version"`
	Identity             OperationHistoryIdentity `json:"identity"`
	ReceiptSchemaURI     string                   `json:"receipt_schema_uri"`
	ReceiptSchemaVersion string                   `json:"receipt_schema_version"`
	ReceiptSchemaSHA256  string                   `json:"receipt_schema_sha256"`
	ReceiptSHA256        string                   `json:"receipt_sha256"`
	ReceiptBytes         []byte                   `json:"receipt_bytes"`
	ValidatorIdentity    string                   `json:"validator_identity"`
	ValidatorRevision    string                   `json:"validator_revision"`
	AttemptStartedAt     time.Time                `json:"attempt_started_at"`
	ValidatedAt          time.Time                `json:"validated_at"`
	validatedByWorker    bool
	sealedRecordSHA256   string
}

// OperationHistoryReservation is an opaque capability returned by Reserve.
// It reserves worst-case record capacity before provider dispatch; callers
// must not derive or persist their own token values.
type OperationHistoryReservation struct {
	identityID string
	token      string
}

func (reservation OperationHistoryReservation) Matches(identity OperationHistoryIdentity) bool {
	identityID, err := operationHistoryIdentityKey(identity)
	return err == nil && reservation.identityID != "" && reservation.identityID == identityID && reservation.token != ""
}

func operationHistoryIdentityKey(identity OperationHistoryIdentity) (string, error) {
	if err := identity.Validate(); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

type OperationHistoryRecordRef struct {
	RecordID    string    `json:"record_id"`
	SHA256      string    `json:"sha256"`
	AppendedAt  time.Time `json:"appended_at"`
	appendProof *operationHistoryAppendProof
}

// operationHistoryAppendProof is an in-process capability. It is minted only
// after the store has durably appended the matching record or revalidated an
// identical durable record during idempotent recovery. The exported ref fields
// remain useful for persistence and diagnostics, but cannot by themselves
// authorize an observation.
type operationHistoryAppendProof struct {
	refSHA256 string
}

// MatchesValidatedRecord proves this exact ref was minted by the archive store
// for this validated record. JSON-decoded or caller-constructed refs have no
// proof, and changing any exported field invalidates the private seal.
func (ref OperationHistoryRecordRef) MatchesValidatedRecord(record OperationHistoryRecord) bool {
	if ref.appendProof == nil || record.Validate() != nil || !utcNormalized(ref.AppendedAt) || ref.AppendedAt.Before(record.ValidatedAt) {
		return false
	}
	recordID, err := operationHistoryIdentityID(record.Identity)
	if err != nil {
		return false
	}
	contentSHA, err := record.ContentSHA256()
	if err != nil || ref.RecordID != recordID || ref.SHA256 != contentSHA {
		return false
	}
	return ref.appendProof.refSHA256 == operationHistoryRecordRefSeal(ref)
}

type operationHistoryRecordRefWire struct {
	RecordID   string    `json:"record_id"`
	SHA256     string    `json:"sha256"`
	AppendedAt time.Time `json:"appended_at"`
}

func operationHistoryRecordRefSeal(ref OperationHistoryRecordRef) string {
	encoded, err := json.Marshal(operationHistoryRecordRefWire{RecordID: ref.RecordID, SHA256: ref.SHA256, AppendedAt: ref.AppendedAt})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func newDurableOperationHistoryRecordRef(record OperationHistoryRecord, appendedAt time.Time) (OperationHistoryRecordRef, error) {
	if record.Validate() != nil || !utcNormalized(appendedAt) || appendedAt.Before(record.ValidatedAt) {
		return OperationHistoryRecordRef{}, ErrOperationHistoryUnavailable
	}
	recordID, err := operationHistoryIdentityID(record.Identity)
	if err != nil {
		return OperationHistoryRecordRef{}, ErrOperationHistoryUnavailable
	}
	contentSHA, err := record.ContentSHA256()
	if err != nil {
		return OperationHistoryRecordRef{}, ErrOperationHistoryUnavailable
	}
	ref := OperationHistoryRecordRef{RecordID: recordID, SHA256: contentSHA, AppendedAt: appendedAt}
	ref.appendProof = &operationHistoryAppendProof{refSHA256: operationHistoryRecordRefSeal(ref)}
	return ref, nil
}

type OperationHistoryBatchRecord struct {
	RecordID   string                 `json:"record_id"`
	RecordSHA  string                 `json:"record_sha256"`
	Sequence   uint64                 `json:"sequence"`
	AppendedAt time.Time              `json:"appended_at"`
	Record     OperationHistoryRecord `json:"record"`
}

type OperationHistoryBatch struct {
	SchemaVersion  string                        `json:"schema_version"`
	BatchID        string                        `json:"batch_id"`
	RecordSetSHA   string                        `json:"record_set_sha256"`
	ManifestSHA256 string                        `json:"manifest_sha256,omitempty"`
	RecordsSHA256  string                        `json:"records_sha256,omitempty"`
	Records        []OperationHistoryBatchRecord `json:"records"`
}

// OperationHistoryPublicationConfirmation is returned only after the batch
// publisher has read back the exact immutable files from the pinned remote
// revision and matched their local SHA-256 digests.
type OperationHistoryPublicationConfirmation struct {
	BatchID             string    `json:"batch_id"`
	DatasetRepo         string    `json:"dataset_repo"`
	Revision            string    `json:"revision"`
	ManifestSHA256      string    `json:"manifest_sha256"`
	RecordsSHA256       string    `json:"records_sha256"`
	RecordSetSHA256     string    `json:"record_set_sha256"`
	VerifiedAt          time.Time `json:"verified_at"`
	verifiedByPublisher bool
	sealSHA256          string
}

// OperationHistoryPublicationReadback is the public metadata returned by the
// configured asynchronous publisher after it has verified exact remote bytes.
type OperationHistoryPublicationReadback struct {
	DatasetRepo     string
	Revision        string
	ManifestSHA256  string
	RecordsSHA256   string
	RecordSetSHA256 string
	VerifiedAt      time.Time
}

// OperationHistoryBatchPublisher owns external upload and readback. It is
// called only by the asynchronous publisher path, after local append succeeds.
type OperationHistoryBatchPublisher interface {
	PublishAndReadback(context.Context, OperationHistoryBatch) (OperationHistoryPublicationReadback, error)
}

// OperationHistoryAppender separates the synchronous local durability gate
// from later asynchronous archive publication. Reserve must run after the
// attempt generation is known and before provider dispatch. If Reserve returns
// an error with a nonzero token, the caller must not dispatch and may cancel
// that pre-dispatch reservation. AppendValidated is called only after strict
// CLI receipt validation succeeds. Cancel is safe only when no provider
// request was started.
type OperationHistoryAppender interface {
	Reserve(context.Context, OperationHistoryIdentity) (OperationHistoryReservation, error)
	AppendValidated(context.Context, OperationHistoryReservation, OperationHistoryRecord) (OperationHistoryRecordRef, error)
	CancelReservation(context.Context, OperationHistoryIdentity, OperationHistoryReservation) error
}

// OperationHistoryRecordValidator is the trusted schema-aware boundary used
// when reopening persisted records. It must validate the exact historical
// schema pin, canonical receipt bytes, semantic receipt identity, and original
// digest before returning a sealed value. Unsupported schema versions fail
// closed rather than being interpreted with the current schema.
type OperationHistoryRecordValidator interface {
	ValidateStoredOperationHistoryRecord(context.Context, OperationHistoryRecord) (OperationHistoryRecord, error)
}

func validateOperationHistoryIdentity(identity OperationHistoryIdentity) bool {
	return len(identity.SourceID) <= 64 && operationHistorySourcePattern.MatchString(identity.SourceID) && identity.OperationID != "" && len(identity.OperationID) <= 256 && operationHistoryAttemptPattern.MatchString(identity.AttemptID) && identity.Generation > 0 && commitPattern.MatchString(identity.RegistryRevision) && sha256Pattern.MatchString(identity.ReleaseManifestSHA256) && sha256Pattern.MatchString(identity.IndexSHA256) && sha256Pattern.MatchString(identity.ShardSHA256)
}

func validateOperationHistoryRecord(record OperationHistoryRecord) error {
	if !record.validatedByWorker || !sha256Pattern.MatchString(record.sealedRecordSHA256) || validateOperationHistoryRecordFields(record) != nil || operationHistoryRecordSeal(record) != record.sealedRecordSHA256 {
		return ErrOperationHistoryUnavailable
	}
	return nil
}

func validateOperationHistoryRecordFields(record OperationHistoryRecord) error {
	if record.SchemaVersion != OperationHistoryRecordSchemaVersion || !validateOperationHistoryIdentity(record.Identity) || len(record.ReceiptBytes) == 0 || len(record.ReceiptBytes) > MaxOperationHistoryReceiptBytes || !json.Valid(record.ReceiptBytes) || !sha256Pattern.MatchString(record.ReceiptSchemaSHA256) || !sha256Pattern.MatchString(record.ReceiptSHA256) || !safeOperationHistorySchemaURI(record.ReceiptSchemaURI) || !operationHistorySchemaVersionPattern.MatchString(record.ReceiptSchemaVersion) || !operationHistoryValidatorPattern.MatchString(record.ValidatorIdentity) || !commitPattern.MatchString(record.ValidatorRevision) || !utcNormalized(record.AttemptStartedAt) || !utcNormalized(record.ValidatedAt) || record.AttemptStartedAt.After(record.ValidatedAt) {
		return ErrOperationHistoryUnavailable
	}
	digest := sha256.Sum256(record.ReceiptBytes)
	if hex.EncodeToString(digest[:]) != record.ReceiptSHA256 {
		return ErrOperationHistoryUnavailable
	}
	return nil
}

func utcNormalized(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value == value.Round(0)
}

// newValidatedOperationHistoryRecord is intentionally package-private. The
// operation worker calls it only after its strict CLI schema, semantic,
// attempt-identity, and canonical-byte checks pass. Keeping the validation
// marker private prevents other packages from submitting arbitrary receipt
// JSON directly to the archive appender.
func newValidatedOperationHistoryRecord(record OperationHistoryRecord) (OperationHistoryRecord, error) {
	record.ReceiptBytes = append([]byte(nil), record.ReceiptBytes...)
	record.validatedByWorker = true
	if err := validateOperationHistoryRecordFields(record); err != nil {
		return OperationHistoryRecord{}, err
	}
	record.sealedRecordSHA256 = operationHistoryRecordSeal(record)
	if err := validateOperationHistoryRecord(record); err != nil {
		return OperationHistoryRecord{}, err
	}
	return record, nil
}

// Validate proves this value was produced by the Health package's validated
// receipt boundary and that its immutable digest and bounded fields still
// match before an archive appender accepts it.
func (record OperationHistoryRecord) Validate() error {
	return validateOperationHistoryRecord(record)
}

// ContentSHA256 returns the immutable digest sealed by the worker constructor.
func (record OperationHistoryRecord) ContentSHA256() (string, error) {
	if err := record.Validate(); err != nil {
		return "", err
	}
	return record.sealedRecordSHA256, nil
}

type operationHistoryRecordWire OperationHistoryRecord

func operationHistoryRecordSeal(record OperationHistoryRecord) string {
	encoded, err := json.Marshal(operationHistoryRecordWire(record))
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func safeOperationHistorySchemaURI(value string) bool {
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n\t ") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("-._~:/", char)) {
			return false
		}
	}
	return true
}
