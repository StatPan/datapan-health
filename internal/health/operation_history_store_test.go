package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixtureOperationHistoryValidator struct{}

type fixtureOperationHistoryPublisher struct {
	readback OperationHistoryPublicationReadback
	err      error
	calls    int
}

func (publisher *fixtureOperationHistoryPublisher) PublishAndReadback(_ context.Context, _ OperationHistoryBatch) (OperationHistoryPublicationReadback, error) {
	publisher.calls++
	return publisher.readback, publisher.err
}

func (fixtureOperationHistoryValidator) ValidateStoredOperationHistoryRecord(_ context.Context, candidate OperationHistoryRecord) (OperationHistoryRecord, error) {
	if candidate.ReceiptSchemaURI != "https://schemas.datapan.dev/datapan.health-operation-receipt.v1.schema.json" || candidate.ReceiptSchemaVersion != "datapan.health-operation-receipt.v1" || validateOperationHistoryRecordFields(candidate) != nil {
		return OperationHistoryRecord{}, ErrOperationHistoryCorrupt
	}
	var receipt struct {
		SchemaVersion string `json:"schema_version"`
		State         string `json:"state"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(candidate.ReceiptBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil || receipt.SchemaVersion != "fixture.v1" || (receipt.State != "healthy" && receipt.State != "unhealthy") {
		return OperationHistoryRecord{}, ErrOperationHistoryCorrupt
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return OperationHistoryRecord{}, ErrOperationHistoryCorrupt
	}
	return newValidatedOperationHistoryRecord(candidate)
}

func fixtureOperationHistoryRecord(t *testing.T, identity OperationHistoryIdentity, state string) OperationHistoryRecord {
	t.Helper()
	receipt := []byte(`{"schema_version":"fixture.v1","state":"` + state + `"}` + "\n")
	digest := sha256.Sum256(receipt)
	record, err := newValidatedOperationHistoryRecord(OperationHistoryRecord{
		SchemaVersion:        OperationHistoryRecordSchemaVersion,
		Identity:             identity,
		ReceiptSchemaURI:     "https://schemas.datapan.dev/datapan.health-operation-receipt.v1.schema.json",
		ReceiptSchemaVersion: "datapan.health-operation-receipt.v1",
		ReceiptSchemaSHA256:  strings.Repeat("f", 64),
		ReceiptSHA256:        hex.EncodeToString(digest[:]),
		ReceiptBytes:         receipt,
		ValidatorIdentity:    "datapan-cli-health-receipt",
		ValidatorRevision:    strings.Repeat("1", 40),
		AttemptStartedAt:     time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC),
		ValidatedAt:          time.Date(2026, 10, 7, 0, 1, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("construct fixture operation history record: %v", err)
	}
	return record
}

func fixtureOperationHistoryIdentity(attempt string) OperationHistoryIdentity {
	return OperationHistoryIdentity{
		SourceID:              "data_go_kr",
		OperationID:           strings.Repeat("a", 64),
		AttemptID:             attempt,
		Generation:            7,
		RegistryRevision:      strings.Repeat("b", 40),
		ReleaseManifestSHA256: strings.Repeat("c", 64),
		IndexSHA256:           strings.Repeat("d", 64),
		ShardSHA256:           strings.Repeat("e", 64),
	}
}

func TestOperationHistoryStoreReserveAppendRestartAndIdempotency(t *testing.T) {
	root := t.TempDir()
	identity := fixtureOperationHistoryIdentity("00000000-0000-4000-8000-000000000002")
	record := fixtureOperationHistoryRecord(t, identity, "healthy")
	store, err := OpenOperationHistoryStore(root, MaxOperationHistoryReservedBytes*3+operationHistoryPublicationHeadroom, fixtureOperationHistoryValidator{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	token, err := store.Reserve(context.Background(), identity)
	if err != nil || !token.Matches(identity) {
		t.Fatalf("reserve: token_matches=%v err=%v", token.Matches(identity), err)
	}
	usage, err := store.Usage(context.Background())
	if err != nil || usage.ReservationCount != 1 || usage.ReservedBytes != MaxOperationHistoryReservedBytes || usage.RecordCount != 0 {
		t.Fatalf("reserved usage: %#v err=%v", usage, err)
	}
	ref, err := store.AppendValidated(context.Background(), token, record)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if !ref.MatchesValidatedRecord(record) {
		t.Fatal("durable append ref did not prove the matching validated record")
	}
	forged := OperationHistoryRecordRef{RecordID: ref.RecordID, SHA256: ref.SHA256, AppendedAt: ref.AppendedAt}
	if forged.MatchesValidatedRecord(record) {
		t.Fatal("caller-constructed ref must not prove a durable append")
	}
	mutatedRefs := []OperationHistoryRecordRef{ref, ref, ref}
	mutatedRefs[0].RecordID += "x"
	mutatedRefs[1].SHA256 = strings.Repeat("f", 64)
	mutatedRefs[2].AppendedAt = mutatedRefs[2].AppendedAt.Add(time.Second)
	for index, mutated := range mutatedRefs {
		if mutated.MatchesValidatedRecord(record) {
			t.Fatalf("mutated ref %d must not prove a durable append", index)
		}
	}
	changedRecord := fixtureOperationHistoryRecord(t, identity, "unhealthy")
	if ref.MatchesValidatedRecord(changedRecord) {
		t.Fatal("append ref must bind the exact validated record digest")
	}
	refBytes, err := json.Marshal(ref)
	if err != nil {
		t.Fatalf("marshal append ref: %v", err)
	}
	var decodedRef OperationHistoryRecordRef
	if err := json.Unmarshal(refBytes, &decodedRef); err != nil {
		t.Fatalf("unmarshal append ref: %v", err)
	}
	if decodedRef.MatchesValidatedRecord(record) {
		t.Fatal("serialized ref must not retain its in-process append capability")
	}
	info, err := os.Stat(store.recordPath(ref.RecordID))
	if err != nil {
		t.Fatalf("stat stored record: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("stored record must be mode 0600, mode=%v", info.Mode().Perm())
	}
	usage, err = store.Usage(context.Background())
	if err != nil || usage.RecordCount != 1 || usage.ReservationCount != 0 || usage.UsedBytes <= 0 || usage.ReservedBytes != 0 {
		t.Fatalf("appended usage: %#v err=%v", usage, err)
	}

	store, err = OpenOperationHistoryStore(root, MaxOperationHistoryReservedBytes*3+operationHistoryPublicationHeadroom, fixtureOperationHistoryValidator{})
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	duplicate, err := store.AppendValidated(context.Background(), token, record)
	if err != nil || duplicate.RecordID != ref.RecordID || duplicate.SHA256 != ref.SHA256 || !duplicate.AppendedAt.Equal(ref.AppendedAt) {
		t.Fatalf("same record append must be idempotent: got=%#v want=%#v err=%v", duplicate, ref, err)
	}
	if !duplicate.MatchesValidatedRecord(record) {
		t.Fatal("revalidated durable duplicate did not mint an append capability")
	}
	conflict := fixtureOperationHistoryRecord(t, identity, "unhealthy")
	if _, err := store.AppendValidated(context.Background(), token, conflict); !errors.Is(err, ErrOperationHistoryConflict) {
		t.Fatalf("conflicting payload error=%v, want %v", err, ErrOperationHistoryConflict)
	}
	if err := store.CancelReservation(context.Background(), identity, token); !errors.Is(err, ErrOperationHistoryReserved) {
		t.Fatalf("cancel after durable append error=%v, want %v", err, ErrOperationHistoryReserved)
	}
}

func TestOperationHistoryStoreBackpressureAndPreDispatchCancellation(t *testing.T) {
	root := t.TempDir()
	store, err := OpenOperationHistoryStore(root, MaxOperationHistoryReservedBytes*2+operationHistoryPublicationHeadroom-1, fixtureOperationHistoryValidator{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	firstIdentity := fixtureOperationHistoryIdentity("00000000-0000-4000-8000-000000000003")
	first, err := store.Reserve(context.Background(), firstIdentity)
	if err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	secondIdentity := fixtureOperationHistoryIdentity("00000000-0000-4000-8000-000000000004")
	if _, err := store.Reserve(context.Background(), secondIdentity); !errors.Is(err, ErrOperationHistoryCapacity) {
		t.Fatalf("second reserve error=%v, want explicit capacity backpressure", err)
	}
	if !first.Matches(firstIdentity) || first.Matches(secondIdentity) {
		t.Fatal("reservation did not remain bound to its immutable attempt identity")
	}
	if err := store.CancelReservation(context.Background(), firstIdentity, first); err != nil {
		t.Fatalf("cancel before dispatch: %v", err)
	}
	usage, err := store.Usage(context.Background())
	if err != nil || usage.ReservationCount != 0 || usage.ReservedBytes != 0 || usage.CapacityBlockedCount == 0 {
		t.Fatalf("cancelled usage: %#v err=%v", usage, err)
	}
	retryToken, err := store.Reserve(context.Background(), firstIdentity)
	if err != nil || retryToken.token == first.token {
		t.Fatalf("a fresh reservation must get a distinct capability: old=%v new=%v err=%v", first.token != "", retryToken.token != "", err)
	}
	blockedRecord := fixtureOperationHistoryRecord(t, firstIdentity, "healthy")
	if _, err := store.AppendValidated(context.Background(), first, blockedRecord); !errors.Is(err, ErrOperationHistoryReserved) {
		t.Fatalf("cancelled token appended under a later reservation: %v", err)
	}
	if err := store.CancelReservation(context.Background(), firstIdentity, retryToken); err != nil {
		t.Fatalf("cancel retry reservation: %v", err)
	}
}

func TestOperationHistoryStoreRetainsUncertainReservationAcrossRestart(t *testing.T) {
	root := t.TempDir()
	identity := fixtureOperationHistoryIdentity("00000000-0000-4000-8000-000000000006")
	store, err := OpenOperationHistoryStore(root, MaxOperationHistoryReservedBytes*2+operationHistoryPublicationHeadroom-1, fixtureOperationHistoryValidator{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	first, err := store.Reserve(context.Background(), identity)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	store, err = OpenOperationHistoryStore(root, MaxOperationHistoryReservedBytes*2+operationHistoryPublicationHeadroom-1, fixtureOperationHistoryValidator{})
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	second, err := store.Reserve(context.Background(), identity)
	if err != nil || !second.Matches(identity) || !first.Matches(identity) {
		t.Fatalf("reservation did not survive restart: first=%v second=%v err=%v", first.Matches(identity), second.Matches(identity), err)
	}
	usage, err := store.Usage(context.Background())
	if err != nil || usage.ReservationCount != 1 || usage.ReservedBytes != MaxOperationHistoryReservedBytes {
		t.Fatalf("recovered reservation usage: %#v err=%v", usage, err)
	}
}

func TestOperationHistoryStoreRecoveryRejectsTamperingAndCleansCrashTemps(t *testing.T) {
	root := t.TempDir()
	identity := fixtureOperationHistoryIdentity("00000000-0000-4000-8000-000000000005")
	record := fixtureOperationHistoryRecord(t, identity, "healthy")
	store, err := OpenOperationHistoryStore(root, MaxOperationHistoryReservedBytes*3+operationHistoryPublicationHeadroom, fixtureOperationHistoryValidator{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	token, err := store.Reserve(context.Background(), identity)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := store.AppendValidated(context.Background(), token, record); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Model a crash after the record file reached stable storage but before its
	// reservation and usage metadata were finalized.
	reservation := operationHistoryReservationFile{SchemaVersion: OperationHistoryStoreSchemaVersion, ReservationID: operationHistoryIdentityIDMust(identity), Token: strings.Repeat("8", 64), Identity: identity, ReservedBytes: MaxOperationHistoryReservedBytes, CreatedAt: time.Now().UTC()}
	if err := writePrivateJSONAtomic(store.reservationPath(reservation.ReservationID), reservation); err != nil {
		t.Fatalf("write crash reservation: %v", err)
	}
	if err := os.WriteFile(store.transactionPath(), []byte(`{"schema_version":"datapan.health-operation-history-store.v1","operation":"append"}`), 0o600); err != nil {
		t.Fatalf("write crash marker: %v", err)
	}
	partial := filepath.Join(root, "records", ".operation-history-partial-crash")
	if err := os.WriteFile(partial, []byte("partial"), 0o600); err != nil {
		t.Fatalf("write crash temp: %v", err)
	}
	if err := os.Remove(filepath.Join(root, "usage.json")); err != nil {
		t.Fatalf("remove usage for rebuild: %v", err)
	}
	store, err = OpenOperationHistoryStore(root, MaxOperationHistoryReservedBytes*3+operationHistoryPublicationHeadroom, fixtureOperationHistoryValidator{})
	if err != nil {
		t.Fatalf("recover store: %v", err)
	}
	if _, err := os.Lstat(partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("crash temp remains after recovery: %v", err)
	}
	usage, err := store.Usage(context.Background())
	if err != nil || usage.RecordCount != 1 || usage.ReservationCount != 0 || usage.ReservedBytes != 0 {
		t.Fatalf("recovered usage: %#v err=%v", usage, err)
	}
	if _, err := os.Lstat(store.reservationPath(reservation.ReservationID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery left a reservation beside a durable record: %v", err)
	}

	recordPath := store.recordPath(operationHistoryIdentityIDMust(identity))
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("read stored file: %v", err)
	}
	var stored operationHistoryStoredRecord
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("decode stored file: %v", err)
	}
	stored.RecordSHA256 = strings.Repeat("9", 64)
	data, err = json.Marshal(stored)
	if err != nil {
		t.Fatalf("encode tampered file: %v", err)
	}
	if err := os.WriteFile(recordPath, data, 0o600); err != nil {
		t.Fatalf("tamper stored file: %v", err)
	}
	if _, err := OpenOperationHistoryStore(root, MaxOperationHistoryReservedBytes*3+operationHistoryPublicationHeadroom, fixtureOperationHistoryValidator{}); !errors.Is(err, ErrOperationHistoryCorrupt) {
		t.Fatalf("tampered recovery error=%v, want %v", err, ErrOperationHistoryCorrupt)
	}
}

func TestOperationHistoryPublicationCheckpointRecoversPartialCleanupAndFencesStaleAttempts(t *testing.T) {
	root := t.TempDir()
	maxBytes := MaxOperationHistoryReservedBytes*4 + operationHistoryPublicationHeadroom
	store, err := OpenOperationHistoryStore(root, maxBytes, fixtureOperationHistoryValidator{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	firstIdentity := fixtureOperationHistoryIdentity("00000000-0000-4000-8000-000000000020")
	firstIdentity.Generation = 7
	first := fixtureOperationHistoryRecord(t, firstIdentity, "healthy")
	firstToken, err := store.Reserve(context.Background(), firstIdentity)
	if err != nil {
		t.Fatalf("reserve first: %v", err)
	}
	firstRef, err := store.AppendValidated(context.Background(), firstToken, first)
	if err != nil {
		t.Fatalf("append first: %v", err)
	}
	secondIdentity := firstIdentity
	secondIdentity.AttemptID = "00000000-0000-4000-8000-000000000021"
	secondIdentity.Generation = 8
	second := fixtureOperationHistoryRecord(t, secondIdentity, "unhealthy")
	secondToken, err := store.Reserve(context.Background(), secondIdentity)
	if err != nil {
		t.Fatalf("reserve second: %v", err)
	}
	secondRef, err := store.AppendValidated(context.Background(), secondToken, second)
	if err != nil {
		t.Fatalf("append second: %v", err)
	}

	batch, err := store.PendingOperationHistoryBatch(context.Background())
	if err != nil || len(batch.Records) != 2 || batch.Records[0].Sequence != 1 || batch.Records[1].Sequence != 2 {
		t.Fatalf("pending batch: records=%d batch=%#v err=%v", len(batch.Records), batch, err)
	}
	batch.ManifestSHA256 = strings.Repeat("a", 64)
	batch.RecordsSHA256 = strings.Repeat("b", 64)
	confirmation, err := newVerifiedOperationHistoryPublicationConfirmation(batch, OperationHistoryPublicationReadback{
		DatasetRepo:     "StatPan/datapan-health-operation-history",
		Revision:        strings.Repeat("f", 40),
		ManifestSHA256:  batch.ManifestSHA256,
		RecordsSHA256:   batch.RecordsSHA256,
		RecordSetSHA256: batch.RecordSetSHA,
		VerifiedAt:      time.Date(2026, 10, 7, 1, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("seal verified publication: %v", err)
	}
	transaction := operationHistoryPublicationTransaction{
		SchemaVersion: OperationHistoryStoreSchemaVersion,
		BatchID:       batch.BatchID,
		RecordSetSHA:  batch.RecordSetSHA,
		Confirmation:  confirmation,
		Records:       operationHistoryBatchRefs(batch.Records),
	}
	transaction.IndexChanges, err = store.operationHistoryIndexChangesLocked(context.Background(), transaction.Records)
	if err != nil {
		t.Fatalf("snapshot index changes: %v", err)
	}
	transaction.TransactionSHA = operationHistoryPublicationTransactionDigest(transaction)
	if err := validateOperationHistoryPublicationTransaction(transaction); err != nil {
		t.Fatalf("publication transaction validation: %v", err)
	}
	if err := writePrivateJSONAtomic(store.publicationTransactionPath(), transaction); err != nil {
		t.Fatalf("persist publication transaction: %v", err)
	}
	// Model a crash after the durable publication transaction and partial local
	// cleanup, before the operation indexes/checkpoint finish.
	if err := removePrivateFile(store.recordPath(firstRef.RecordID)); err != nil {
		t.Fatalf("remove first acknowledged record: %v", err)
	}
	store, err = OpenOperationHistoryStore(root, maxBytes, fixtureOperationHistoryValidator{})
	if err != nil {
		t.Fatalf("recover publication transaction: %v", err)
	}
	usage, err := store.Usage(context.Background())
	if err != nil || usage.AcceptedRecordCount != 2 || usage.RecordCount != 0 || usage.VerifiedPublicationCount != 2 || usage.OperationKeyCount != 1 {
		t.Fatalf("recovered publication usage: %#v err=%v", usage, err)
	}
	if _, err := os.Stat(store.recordPath(secondRef.RecordID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery left second published receipt pending: %v", err)
	}
	if err := store.AcknowledgeOperationHistoryBatch(context.Background(), batch, confirmation); err != nil {
		t.Fatalf("same publication acknowledgement must be idempotent: %v", err)
	}
	if _, err := store.Reserve(context.Background(), firstIdentity); !errors.Is(err, ErrOperationHistoryStale) {
		t.Fatalf("old generation reserve error=%v, want stale fence", err)
	}
	if _, err := store.Reserve(context.Background(), secondIdentity); !errors.Is(err, ErrOperationHistoryStale) {
		t.Fatalf("latest generation reserve error=%v, want stale fence", err)
	}
	if duplicate, err := store.AppendValidated(context.Background(), secondToken, second); err != nil || duplicate.RecordID != secondRef.RecordID || duplicate.SHA256 != secondRef.SHA256 || !duplicate.AppendedAt.Equal(secondRef.AppendedAt) {
		t.Fatalf("latest exact duplicate should retain its proof: got=%#v err=%v", duplicate, err)
	} else if !duplicate.MatchesValidatedRecord(second) {
		t.Fatal("verified published high-water duplicate did not mint an append capability")
	}
	conflict := fixtureOperationHistoryRecord(t, secondIdentity, "healthy")
	if _, err := store.AppendValidated(context.Background(), secondToken, conflict); !errors.Is(err, ErrOperationHistoryConflict) {
		t.Fatalf("latest changed receipt error=%v, want conflict", err)
	}
	thirdIdentity := secondIdentity
	thirdIdentity.AttemptID = "00000000-0000-4000-8000-000000000022"
	thirdIdentity.Generation = 9
	thirdToken, err := store.Reserve(context.Background(), thirdIdentity)
	if err != nil || !thirdToken.Matches(thirdIdentity) {
		t.Fatalf("strictly newer generation should reserve: token=%v err=%v", thirdToken.Matches(thirdIdentity), err)
	}
	if err := store.CancelReservation(context.Background(), thirdIdentity, thirdToken); err != nil {
		t.Fatalf("cancel unstarted newer generation: %v", err)
	}
}

func TestOperationHistoryPublicationAcknowledgeCompactsVerifiedPrefix(t *testing.T) {
	root := t.TempDir()
	maxBytes := MaxOperationHistoryReservedBytes*4 + operationHistoryPublicationHeadroom
	store, err := OpenOperationHistoryStore(root, maxBytes, fixtureOperationHistoryValidator{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	identity := fixtureOperationHistoryIdentity("00000000-0000-4000-8000-000000000030")
	identity.Generation = 11
	record := fixtureOperationHistoryRecord(t, identity, "healthy")
	token, err := store.Reserve(context.Background(), identity)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := store.AppendValidated(context.Background(), token, record); err != nil {
		t.Fatalf("append: %v", err)
	}
	batch, err := store.PendingOperationHistoryBatch(context.Background())
	if err != nil || len(batch.Records) != 1 {
		t.Fatalf("pending batch: %#v err=%v", batch, err)
	}
	batch.ManifestSHA256 = strings.Repeat("a", 64)
	batch.RecordsSHA256 = strings.Repeat("b", 64)
	confirmation, err := newVerifiedOperationHistoryPublicationConfirmation(batch, OperationHistoryPublicationReadback{
		DatasetRepo:     "StatPan/datapan-health-operation-history",
		Revision:        strings.Repeat("f", 40),
		ManifestSHA256:  batch.ManifestSHA256,
		RecordsSHA256:   batch.RecordsSHA256,
		RecordSetSHA256: batch.RecordSetSHA,
		VerifiedAt:      time.Date(2026, 10, 7, 1, 2, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("seal verified publication: %v", err)
	}
	if err := store.AcknowledgeOperationHistoryBatch(context.Background(), batch, confirmation); err != nil {
		t.Fatalf("acknowledge verified publication: %v", err)
	}
	usage, err := store.Usage(context.Background())
	if err != nil || usage.AcceptedRecordCount != 1 || usage.RecordCount != 0 || usage.VerifiedPublicationCount != 1 || usage.OperationKeyCount != 1 {
		t.Fatalf("compacted publication usage: %#v err=%v", usage, err)
	}
	if pending, err := store.PendingOperationHistoryBatch(context.Background()); err != nil || len(pending.Records) != 0 {
		t.Fatalf("published prefix remains pending: %#v err=%v", pending, err)
	}
	store, err = OpenOperationHistoryStore(root, maxBytes, fixtureOperationHistoryValidator{})
	if err != nil {
		t.Fatalf("reopen compacted store: %v", err)
	}
	usage, err = store.Usage(context.Background())
	if err != nil || usage.AcceptedRecordCount != 1 || usage.VerifiedPublicationCount != 1 || usage.OperationKeyCount != 1 {
		t.Fatalf("reopened publication usage: %#v err=%v", usage, err)
	}
	if err := removePrivateFile(store.operationIndexPath(operationHistoryOperationIndexID(identity))); err != nil {
		t.Fatalf("remove operation fence fixture: %v", err)
	}
	if _, err := OpenOperationHistoryStore(root, maxBytes, fixtureOperationHistoryValidator{}); !errors.Is(err, ErrOperationHistoryCorrupt) {
		t.Fatalf("missing compact operation fence error=%v, want %v", err, ErrOperationHistoryCorrupt)
	}
}

func TestOperationHistoryPublishPathRequiresExactReadbackAndRetainsFailedBatch(t *testing.T) {
	root := t.TempDir()
	store, err := OpenOperationHistoryStore(root, MaxOperationHistoryReservedBytes*4+operationHistoryPublicationHeadroom, fixtureOperationHistoryValidator{})
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	identity := fixtureOperationHistoryIdentity("00000000-0000-4000-8000-000000000031")
	identity.Generation = 12
	record := fixtureOperationHistoryRecord(t, identity, "healthy")
	token, err := store.Reserve(context.Background(), identity)
	if err != nil {
		t.Fatalf("reserve: %v", err)
	}
	if _, err := store.AppendValidated(context.Background(), token, record); err != nil {
		t.Fatalf("append: %v", err)
	}
	batch, err := store.PendingOperationHistoryBatch(context.Background())
	if err != nil || len(batch.Records) != 1 {
		t.Fatalf("pending batch: %#v err=%v", batch, err)
	}
	readback := OperationHistoryPublicationReadback{
		DatasetRepo:     "StatPan/datapan-health-operation-history",
		Revision:        strings.Repeat("e", 40),
		ManifestSHA256:  strings.Repeat("a", 64),
		RecordsSHA256:   strings.Repeat("b", 64),
		RecordSetSHA256: strings.Repeat("c", 64),
		VerifiedAt:      time.Date(2026, 10, 7, 1, 3, 0, 0, time.UTC),
	}
	publisher := &fixtureOperationHistoryPublisher{readback: readback}
	if published, err := store.PublishPendingOperationHistoryBatch(context.Background(), publisher); err == nil || published {
		t.Fatalf("publisher readback with a mismatched record-set hash was accepted: published=%v err=%v", published, err)
	}
	usage, err := store.Usage(context.Background())
	if err != nil || usage.RecordCount != 1 || usage.VerifiedPublicationCount != 0 || publisher.calls != 1 {
		t.Fatalf("failed publication must retain local record: usage=%#v calls=%d err=%v", usage, publisher.calls, err)
	}
	readback.RecordSetSHA256 = batch.RecordSetSHA
	publisher = &fixtureOperationHistoryPublisher{readback: readback}
	if published, err := store.PublishPendingOperationHistoryBatch(context.Background(), publisher); err != nil || !published {
		t.Fatalf("exact readback should advance checkpoint: published=%v err=%v", published, err)
	}
	usage, err = store.Usage(context.Background())
	if err != nil || usage.RecordCount != 0 || usage.VerifiedPublicationCount != 1 || publisher.calls != 1 {
		t.Fatalf("verified publication usage: %#v calls=%d err=%v", usage, publisher.calls, err)
	}
}
