package health

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	OperationHistoryStoreSchemaVersion            = "datapan.health-operation-history-store.v1"
	maxOperationHistoryStoreBytes                 = int64(512 * 1024 * 1024)
	maxOperationHistoryPendingRecords             = 131_072
	maxOperationHistoryOperationKeys              = 131_072
	maxOperationHistoryReservations               = 1_024
	operationHistoryFileCharge                    = int64(4 * 1024)
	operationHistoryPendingMetadataReserve        = int64(16 * 1024)
	maxOperationHistoryStoredFile                 = int64(MaxOperationHistoryReservedBytes)
	maxOperationHistoryCheckpointFile             = int64(8 * 1024)
	maxOperationHistoryPublicationTransactionFile = int64(1024 * 1024)
	operationHistoryOperationIndexMaximumBytes    = int64(8 * 1024)
	operationHistoryPublicationHeadroom           = int64(3 * 1024 * 1024)
)

type OperationHistoryStore struct {
	root      string
	maxBytes  int64
	validator OperationHistoryRecordValidator
}

type OperationHistoryStoreUsage struct {
	SchemaVersion            string `json:"schema_version"`
	MaximumBytes             int64  `json:"maximum_bytes"`
	UsedBytes                int64  `json:"used_bytes"`
	ReservedBytes            int64  `json:"reserved_bytes"`
	RecordCount              int64  `json:"record_count"`
	ReservationCount         int64  `json:"reservation_count"`
	AcceptedRecordCount      int64  `json:"accepted_record_count"`
	VerifiedPublicationCount int64  `json:"verified_publication_count"`
	CapacityBlockedCount     int64  `json:"capacity_blocked_count"`
	OperationKeyCount        int64  `json:"operation_key_count"`
	NextSequence             uint64 `json:"next_sequence"`
	UsageSHA256              string `json:"usage_sha256"`
}

type operationHistoryUsagePayload struct {
	SchemaVersion            string `json:"schema_version"`
	MaximumBytes             int64  `json:"maximum_bytes"`
	UsedBytes                int64  `json:"used_bytes"`
	ReservedBytes            int64  `json:"reserved_bytes"`
	RecordCount              int64  `json:"record_count"`
	ReservationCount         int64  `json:"reservation_count"`
	AcceptedRecordCount      int64  `json:"accepted_record_count"`
	VerifiedPublicationCount int64  `json:"verified_publication_count"`
	CapacityBlockedCount     int64  `json:"capacity_blocked_count"`
	OperationKeyCount        int64  `json:"operation_key_count"`
	NextSequence             uint64 `json:"next_sequence"`
}

type operationHistoryReservationFile struct {
	SchemaVersion string                   `json:"schema_version"`
	ReservationID string                   `json:"reservation_id"`
	Token         string                   `json:"token"`
	Identity      OperationHistoryIdentity `json:"identity"`
	ReservedBytes int64                    `json:"reserved_bytes"`
	CreatedAt     time.Time                `json:"created_at"`
}

type operationHistoryStoredRecord struct {
	SchemaVersion string                 `json:"schema_version"`
	Record        OperationHistoryRecord `json:"record"`
	RecordSHA256  string                 `json:"record_sha256"`
	Sequence      uint64                 `json:"sequence"`
	AppendedAt    time.Time              `json:"appended_at"`
}

type operationHistoryAckRecord struct {
	RecordID   string                   `json:"record_id"`
	RecordSHA  string                   `json:"record_sha256"`
	Sequence   uint64                   `json:"sequence"`
	AppendedAt time.Time                `json:"appended_at"`
	Identity   OperationHistoryIdentity `json:"identity"`
}

type operationHistoryOperationIndex struct {
	SchemaVersion string                                  `json:"schema_version"`
	Identity      OperationHistoryIdentity                `json:"identity"`
	RecordSHA     string                                  `json:"record_sha256"`
	Sequence      uint64                                  `json:"sequence"`
	AppendedAt    time.Time                               `json:"appended_at"`
	Confirmation  OperationHistoryPublicationConfirmation `json:"confirmation"`
	IndexSHA256   string                                  `json:"index_sha256"`
}

type operationHistoryOperationIndexPayload struct {
	SchemaVersion string                                  `json:"schema_version"`
	Identity      OperationHistoryIdentity                `json:"identity"`
	RecordSHA     string                                  `json:"record_sha256"`
	Sequence      uint64                                  `json:"sequence"`
	AppendedAt    time.Time                               `json:"appended_at"`
	Confirmation  OperationHistoryPublicationConfirmation `json:"confirmation"`
}

type operationHistoryCheckpoint struct {
	SchemaVersion        string                                  `json:"schema_version"`
	Sequence             uint64                                  `json:"sequence"`
	OperationKeyCount    int64                                   `json:"operation_key_count"`
	OperationIndexSetSHA string                                  `json:"operation_index_set_sha256"`
	Confirmation         OperationHistoryPublicationConfirmation `json:"confirmation"`
	CheckpointSHA        string                                  `json:"checkpoint_sha256"`
}

type operationHistoryCheckpointPayload struct {
	SchemaVersion        string                                  `json:"schema_version"`
	Sequence             uint64                                  `json:"sequence"`
	OperationKeyCount    int64                                   `json:"operation_key_count"`
	OperationIndexSetSHA string                                  `json:"operation_index_set_sha256"`
	Confirmation         OperationHistoryPublicationConfirmation `json:"confirmation"`
}

type operationHistoryPublicationTransaction struct {
	SchemaVersion  string                                  `json:"schema_version"`
	BatchID        string                                  `json:"batch_id"`
	RecordSetSHA   string                                  `json:"record_set_sha256"`
	Confirmation   OperationHistoryPublicationConfirmation `json:"confirmation"`
	Records        []operationHistoryAckRecord             `json:"records"`
	IndexChanges   []operationHistoryIndexChange           `json:"index_changes"`
	TransactionSHA string                                  `json:"transaction_sha256"`
}

type operationHistoryIndexChange struct {
	Key      string                          `json:"key"`
	Previous *operationHistoryOperationIndex `json:"previous,omitempty"`
}

type operationHistoryPublicationTransactionPayload struct {
	SchemaVersion string                                  `json:"schema_version"`
	BatchID       string                                  `json:"batch_id"`
	RecordSetSHA  string                                  `json:"record_set_sha256"`
	Confirmation  OperationHistoryPublicationConfirmation `json:"confirmation"`
	Records       []operationHistoryAckRecord             `json:"records"`
	IndexChanges  []operationHistoryIndexChange           `json:"index_changes"`
}

// OpenOperationHistoryStore opens a private, byte-bounded append store. The
// trusted Health validator is required to revalidate every persisted receipt
// on recovery; this layer never upgrades unknown historical schemas by
// interpreting them as the current contract.
func OpenOperationHistoryStore(root string, maxBytes int64, validator OperationHistoryRecordValidator) (*OperationHistoryStore, error) {
	if strings.TrimSpace(root) == "" || validator == nil || maxBytes < MaxOperationHistoryReservedBytes+operationHistoryPublicationHeadroom || maxBytes > maxOperationHistoryStoreBytes {
		return nil, ErrOperationHistoryUnavailable
	}
	abs, err := filepath.Abs(root)
	if err != nil || filepath.Clean(abs) == string(filepath.Separator) {
		return nil, ErrOperationHistoryUnavailable
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, ErrOperationHistoryUnavailable
	}
	if err := ensurePrivateDirectory(abs); err != nil {
		return nil, ErrOperationHistoryUnavailable
	}
	store := &OperationHistoryStore{root: abs, maxBytes: maxBytes, validator: validator}
	for _, name := range []string{"records", "reservations", "operation-index"} {
		directory := filepath.Join(abs, name)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, ErrOperationHistoryUnavailable
		}
		if err := ensurePrivateDirectory(directory); err != nil {
			return nil, ErrOperationHistoryUnavailable
		}
	}
	if err := store.withLock(context.Background(), func() error { return store.rebuildUsageLocked(context.Background()) }); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *OperationHistoryStore) Reserve(ctx context.Context, identity OperationHistoryIdentity) (OperationHistoryReservation, error) {
	if store == nil || !validHistoryIdentity(identity) || ctx == nil {
		return OperationHistoryReservation{}, ErrOperationHistoryUnavailable
	}
	reservationID, err := operationHistoryIdentityID(identity)
	if err != nil {
		return OperationHistoryReservation{}, ErrOperationHistoryUnavailable
	}
	var reservationToken OperationHistoryReservation
	mutationStarted := false
	err = store.withLock(ctx, func() error {
		usage, err := store.ensureUsageLocked(ctx)
		if err != nil {
			return err
		}
		if published, found, err := store.readOperationIndex(identity); err != nil {
			return err
		} else if found && identity.Generation <= published.Identity.Generation {
			return ErrOperationHistoryStale
		}
		if _, err := os.Lstat(store.recordPath(reservationID)); err == nil {
			stored, loadErr := store.readStoredRecord(ctx, reservationID)
			if loadErr != nil {
				return loadErr
			}
			if stored.Record.Identity != identity {
				return ErrOperationHistoryCorrupt
			}
			return ErrOperationHistoryReserved
		} else if !errors.Is(err, os.ErrNotExist) {
			return ErrOperationHistoryUnavailable
		}
		reservationPath := store.reservationPath(reservationID)
		if _, err := os.Lstat(reservationPath); err == nil {
			reservation, readErr := store.readReservation(reservationID)
			if readErr != nil || reservation.Identity != identity {
				return ErrOperationHistoryCorrupt
			}
			reservationToken = OperationHistoryReservation{identityID: reservationID, token: reservation.Token}
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return ErrOperationHistoryUnavailable
		}
		operationKeyLimit := usage.OperationKeyCount+usage.RecordCount+usage.ReservationCount >= maxOperationHistoryOperationKeys && !store.operationIndexExists(identity)
		if usage.RecordCount+usage.ReservationCount >= maxOperationHistoryPendingRecords || usage.ReservationCount >= maxOperationHistoryReservations || operationKeyLimit || usage.UsedBytes+usage.ReservedBytes+MaxOperationHistoryReservedBytes+operationHistoryPublicationHeadroom > store.maxBytes {
			store.recordCapacityBlockLocked(usage, reservationID)
			return ErrOperationHistoryCapacity
		}
		token, err := newOperationHistoryReservationToken()
		if err != nil {
			return ErrOperationHistoryUnavailable
		}
		if err := store.beginMutationLocked("reserve", reservationID); err != nil {
			return err
		}
		mutationStarted = true
		reservationToken = OperationHistoryReservation{identityID: reservationID, token: token}
		reservation := operationHistoryReservationFile{SchemaVersion: OperationHistoryStoreSchemaVersion, ReservationID: reservationID, Token: token, Identity: identity, ReservedBytes: MaxOperationHistoryReservedBytes, CreatedAt: time.Now().UTC()}
		if err := writePrivateJSONAtomic(reservationPath, reservation); err != nil {
			return ErrOperationHistoryUnavailable
		}
		usage.ReservedBytes += reservation.ReservedBytes
		usage.ReservationCount++
		return store.finishMutationLocked(usage)
	})
	if err != nil {
		if mutationStarted {
			return reservationToken, err
		}
		return OperationHistoryReservation{}, err
	}
	return reservationToken, nil
}

func (store *OperationHistoryStore) AppendValidated(ctx context.Context, token OperationHistoryReservation, record OperationHistoryRecord) (OperationHistoryRecordRef, error) {
	if store == nil || ctx == nil || record.Validate() != nil || !token.Matches(record.Identity) {
		return OperationHistoryRecordRef{}, ErrOperationHistoryUnavailable
	}
	recordID, err := operationHistoryIdentityID(record.Identity)
	if err != nil || !token.Matches(record.Identity) {
		return OperationHistoryRecordRef{}, ErrOperationHistoryReserved
	}
	contentSHA, err := record.ContentSHA256()
	if err != nil {
		return OperationHistoryRecordRef{}, ErrOperationHistoryUnavailable
	}
	var result OperationHistoryRecordRef
	err = store.withLock(ctx, func() error {
		usage, err := store.ensureUsageLocked(ctx)
		if err != nil {
			return err
		}
		if _, err := os.Lstat(store.recordPath(recordID)); err == nil {
			stored, loadErr := store.readStoredRecord(ctx, recordID)
			if loadErr != nil {
				return loadErr
			}
			storedSHA, digestErr := stored.Record.ContentSHA256()
			if digestErr != nil || stored.Record.Identity != record.Identity || storedSHA != contentSHA {
				return ErrOperationHistoryConflict
			}
			if _, err := os.Lstat(store.reservationPath(recordID)); err == nil {
				if err := store.beginMutationLocked("reconcile_append", recordID); err != nil {
					return err
				}
				reservation, readErr := store.readReservation(recordID)
				if readErr != nil || reservation.Identity != record.Identity || reservation.Token != token.token {
					return ErrOperationHistoryCorrupt
				}
				if err := removePrivateFile(store.reservationPath(recordID)); err != nil {
					return ErrOperationHistoryUnavailable
				}
				usage.ReservedBytes -= reservation.ReservedBytes
				usage.ReservationCount--
				if err := store.finishMutationLocked(usage); err != nil {
					return err
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				return ErrOperationHistoryUnavailable
			}
			result = OperationHistoryRecordRef{RecordID: recordID, SHA256: contentSHA, AppendedAt: stored.AppendedAt}
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return ErrOperationHistoryUnavailable
		}
		if published, found, err := store.readOperationIndex(record.Identity); err != nil {
			return err
		} else if found {
			switch {
			case published.Identity == record.Identity && published.RecordSHA == contentSHA:
				result = OperationHistoryRecordRef{RecordID: recordID, SHA256: contentSHA, AppendedAt: published.AppendedAt}
				return nil
			case published.Identity == record.Identity:
				return ErrOperationHistoryConflict
			case published.Identity.Generation >= record.Identity.Generation:
				return ErrOperationHistoryStale
			}
		}
		reservation, err := store.readReservation(recordID)
		if err != nil || reservation.Identity != record.Identity || reservation.Token != token.token {
			return ErrOperationHistoryReserved
		}
		appendedAt := time.Now().UTC()
		if usage.NextSequence == 0 || usage.NextSequence == ^uint64(0) {
			store.recordCapacityBlockLocked(usage, recordID)
			return ErrOperationHistoryCapacity
		}
		sequence := usage.NextSequence
		encoded, err := json.Marshal(operationHistoryStoredRecord{SchemaVersion: OperationHistoryStoreSchemaVersion, Record: record, RecordSHA256: contentSHA, Sequence: sequence, AppendedAt: appendedAt})
		if err != nil {
			return ErrOperationHistoryUnavailable
		}
		fileCharge := operationHistoryPendingRecordCharge(int64(len(encoded)))
		if fileCharge > reservation.ReservedBytes || fileCharge > MaxOperationHistoryReservedBytes {
			return ErrOperationHistoryCapacity
		}
		if usage.RecordCount >= maxOperationHistoryPendingRecords {
			store.recordCapacityBlockLocked(usage, recordID)
			return ErrOperationHistoryCapacity
		}
		if err := store.beginMutationLocked("append", recordID); err != nil {
			return err
		}
		if err := writePrivateBytesAtomic(store.recordPath(recordID), encoded); err != nil {
			return ErrOperationHistoryUnavailable
		}
		if err := removePrivateFile(store.reservationPath(recordID)); err != nil {
			return ErrOperationHistoryUnavailable
		}
		usage.UsedBytes += fileCharge
		usage.ReservedBytes -= reservation.ReservedBytes
		usage.RecordCount++
		usage.ReservationCount--
		usage.AcceptedRecordCount++
		usage.NextSequence++
		if err := store.finishMutationLocked(usage); err != nil {
			return err
		}
		result = OperationHistoryRecordRef{RecordID: recordID, SHA256: contentSHA, AppendedAt: appendedAt}
		return nil
	})
	if err != nil {
		return OperationHistoryRecordRef{}, err
	}
	return result, nil
}

// CancelReservation releases capacity only when the caller has proved that no
// provider request started. There is deliberately no reservation expiry.
func (store *OperationHistoryStore) CancelReservation(ctx context.Context, identity OperationHistoryIdentity, token OperationHistoryReservation) error {
	if store == nil || ctx == nil || !token.Matches(identity) {
		return ErrOperationHistoryReserved
	}
	identityID, err := operationHistoryIdentityID(identity)
	if err != nil {
		return ErrOperationHistoryReserved
	}
	return store.withLock(ctx, func() error {
		usage, err := store.ensureUsageLocked(ctx)
		if err != nil {
			return err
		}
		path := store.reservationPath(identityID)
		reservation, err := store.readReservation(identityID)
		if errors.Is(err, os.ErrNotExist) {
			if _, recordErr := os.Lstat(store.recordPath(identityID)); recordErr == nil {
				return ErrOperationHistoryReserved
			} else if !errors.Is(recordErr, os.ErrNotExist) {
				return ErrOperationHistoryUnavailable
			}
			return nil
		}
		if err != nil {
			return err
		}
		if reservation.Identity != identity || reservation.Token != token.token {
			return ErrOperationHistoryReserved
		}
		if err := store.beginMutationLocked("cancel", identityID); err != nil {
			return err
		}
		if err := removePrivateFile(path); err != nil {
			return ErrOperationHistoryUnavailable
		}
		usage.ReservedBytes -= reservation.ReservedBytes
		usage.ReservationCount--
		return store.finishMutationLocked(usage)
	})
}

func (store *OperationHistoryStore) Usage(ctx context.Context) (OperationHistoryStoreUsage, error) {
	if store == nil || ctx == nil {
		return OperationHistoryStoreUsage{}, ErrOperationHistoryUnavailable
	}
	var result OperationHistoryStoreUsage
	err := store.withLock(ctx, func() error {
		usage, err := store.ensureUsageLocked(ctx)
		if err == nil {
			result = publicOperationHistoryUsage(usage)
		}
		return err
	})
	return result, err
}

func (store *OperationHistoryStore) withLock(ctx context.Context, apply func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	lockPath := filepath.Join(store.root, "store.lock")
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return ErrOperationHistoryUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return ErrOperationHistoryUnavailable
	}
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN && err != syscall.EINTR {
			return ErrOperationHistoryUnavailable
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	if err := ctx.Err(); err != nil {
		return err
	}
	return apply()
}

func (store *OperationHistoryStore) ensureUsageLocked(ctx context.Context) (operationHistoryUsagePayload, error) {
	if _, err := os.Lstat(store.publicationTransactionPath()); err == nil {
		if err := store.rebuildUsageLocked(ctx); err != nil {
			return operationHistoryUsagePayload{}, err
		}
		return store.readUsage()
	} else if !errors.Is(err, os.ErrNotExist) {
		return operationHistoryUsagePayload{}, ErrOperationHistoryCorrupt
	}
	if _, err := os.Lstat(store.transactionPath()); err == nil {
		if err := store.rebuildUsageLocked(ctx); err != nil {
			return operationHistoryUsagePayload{}, err
		}
		return store.readUsage()
	} else if !errors.Is(err, os.ErrNotExist) {
		return operationHistoryUsagePayload{}, ErrOperationHistoryCorrupt
	}
	usage, err := store.readUsage()
	if err == nil && usage.MaximumBytes == store.maxBytes {
		return usage, nil
	}
	if err := store.rebuildUsageLocked(ctx); err != nil {
		return operationHistoryUsagePayload{}, err
	}
	return store.readUsage()
}

func (store *OperationHistoryStore) rebuildUsageLocked(ctx context.Context) error {
	previous, previousErr := store.readUsage()
	if previousErr != nil {
		previous = operationHistoryUsagePayload{}
	}
	if err := cleanupOperationHistoryPartials(store.root); err != nil {
		return err
	}
	if _, err := os.Lstat(store.publicationTransactionPath()); err == nil {
		transaction, readErr := store.readPublicationTransaction()
		if readErr != nil {
			return readErr
		}
		if err := store.applyPublicationTransactionLocked(ctx, transaction); err != nil {
			return err
		}
		if err := removePrivateFile(store.publicationTransactionPath()); err != nil {
			return ErrOperationHistoryUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrOperationHistoryCorrupt
	}
	if err := store.beginMutationLocked("rebuild", ""); err != nil {
		return err
	}
	checkpoint, err := store.readCheckpoint()
	if err != nil {
		return err
	}
	usage := operationHistoryUsagePayload{SchemaVersion: OperationHistoryStoreSchemaVersion, MaximumBytes: store.maxBytes, NextSequence: checkpoint.Sequence + 1, VerifiedPublicationCount: int64(checkpoint.Sequence), CapacityBlockedCount: previous.CapacityBlockedCount}
	checkpointInfo, checkpointErr := os.Lstat(store.checkpointPath())
	if checkpointErr == nil {
		if !checkpointInfo.Mode().IsRegular() || checkpointInfo.Mode()&os.ModeSymlink != 0 || checkpointInfo.Mode().Perm() != 0o600 {
			return ErrOperationHistoryCorrupt
		}
		usage.UsedBytes += fileCharge(checkpointInfo.Size())
	} else if !errors.Is(checkpointErr, os.ErrNotExist) {
		return ErrOperationHistoryCorrupt
	}
	indexEntries, err := os.ReadDir(filepath.Join(store.root, "operation-index"))
	if err != nil || len(indexEntries) > maxOperationHistoryOperationKeys {
		return ErrOperationHistoryCorrupt
	}
	var operationIndexSet [sha256.Size]byte
	for _, entry := range indexEntries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		id := strings.TrimSuffix(name, ".json")
		if entry.IsDir() || name != id+".json" || !validHistoryRecordID(id) {
			return ErrOperationHistoryCorrupt
		}
		var index operationHistoryOperationIndex
		data, readErr := readPrivateFile(filepath.Join(store.root, "operation-index", name), operationHistoryOperationIndexMaximumBytes)
		if readErr != nil || decodeOperationHistoryJSON(data, &index) != nil || !validOperationHistoryOperationIndex(index, id) || index.Sequence > checkpoint.Sequence {
			return ErrOperationHistoryCorrupt
		}
		info, statErr := os.Lstat(filepath.Join(store.root, "operation-index", name))
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
			return ErrOperationHistoryCorrupt
		}
		usage.OperationKeyCount++
		usage.UsedBytes += fileCharge(info.Size())
		xorOperationHistoryDigest(&operationIndexSet, operationHistoryOperationIndexFingerprint(index))
	}
	if checkpoint.Sequence == 0 {
		if len(indexEntries) != 0 {
			return ErrOperationHistoryCorrupt
		}
	} else if usage.OperationKeyCount != checkpoint.OperationKeyCount || hex.EncodeToString(operationIndexSet[:]) != checkpoint.OperationIndexSetSHA {
		return ErrOperationHistoryCorrupt
	}
	entries, err := os.ReadDir(filepath.Join(store.root, "records"))
	if err != nil || len(entries) > maxOperationHistoryPendingRecords {
		return ErrOperationHistoryCorrupt
	}
	pendingSequences := make([]uint64, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || !validHistoryRecordID(id) || entry.Name() != id+".json" {
			return ErrOperationHistoryCorrupt
		}
		stored, err := store.readStoredRecord(ctx, id)
		if err != nil {
			return err
		}
		fileInfo, err := os.Lstat(store.recordPath(id))
		if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode()&os.ModeSymlink != 0 {
			return ErrOperationHistoryCorrupt
		}
		if stored.Sequence <= checkpoint.Sequence {
			return ErrOperationHistoryCorrupt
		}
		if index, found, err := store.readOperationIndex(stored.Record.Identity); err != nil {
			return err
		} else if found && index.Identity.Generation >= stored.Record.Identity.Generation {
			return ErrOperationHistoryCorrupt
		}
		usage.UsedBytes += operationHistoryPendingRecordCharge(fileInfo.Size())
		usage.RecordCount++
		pendingSequences = append(pendingSequences, stored.Sequence)
	}
	sort.Slice(pendingSequences, func(i, j int) bool { return pendingSequences[i] < pendingSequences[j] })
	for index, sequence := range pendingSequences {
		if sequence != checkpoint.Sequence+uint64(index)+1 {
			return ErrOperationHistoryCorrupt
		}
	}
	usage.AcceptedRecordCount = int64(checkpoint.Sequence) + usage.RecordCount
	usage.NextSequence = uint64(usage.AcceptedRecordCount) + 1
	reservations, err := os.ReadDir(filepath.Join(store.root, "reservations"))
	if err != nil || len(reservations) > maxOperationHistoryReservations+maxOperationHistoryPendingRecords {
		return ErrOperationHistoryCorrupt
	}
	for _, entry := range reservations {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || !validHistoryRecordID(id) || entry.Name() != id+".json" {
			return ErrOperationHistoryCorrupt
		}
		reservation, err := store.readReservation(id)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if _, recordErr := os.Lstat(store.recordPath(id)); recordErr == nil {
			if err := removePrivateFile(store.reservationPath(id)); err != nil {
				return ErrOperationHistoryUnavailable
			}
			continue
		} else if !errors.Is(recordErr, os.ErrNotExist) {
			return ErrOperationHistoryCorrupt
		}
		usage.ReservedBytes += reservation.ReservedBytes
		usage.ReservationCount++
	}
	if usage.OperationKeyCount > maxOperationHistoryOperationKeys || usage.RecordCount+usage.ReservationCount > maxOperationHistoryPendingRecords || usage.ReservationCount > maxOperationHistoryReservations || usage.UsedBytes+usage.ReservedBytes+operationHistoryPublicationHeadroom > store.maxBytes {
		return ErrOperationHistoryCapacity
	}
	if err := store.writeUsage(usage); err != nil {
		return ErrOperationHistoryUnavailable
	}
	if err := removePrivateFile(store.transactionPath()); err != nil {
		return ErrOperationHistoryUnavailable
	}
	return nil
}

func (store *OperationHistoryStore) readStoredRecord(ctx context.Context, id string) (operationHistoryStoredRecord, error) {
	var stored operationHistoryStoredRecord
	data, err := readPrivateFile(store.recordPath(id), maxOperationHistoryStoredFile)
	if err != nil {
		return stored, ErrOperationHistoryCorrupt
	}
	if err := decodeOperationHistoryJSON(data, &stored); err != nil || stored.SchemaVersion != OperationHistoryStoreSchemaVersion || stored.Sequence == 0 || !utcNormalized(stored.AppendedAt) || !validHistoryRecordID(id) {
		return operationHistoryStoredRecord{}, ErrOperationHistoryCorrupt
	}
	sealed, err := store.validator.ValidateStoredOperationHistoryRecord(ctx, stored.Record)
	if err != nil || sealed.Validate() != nil || operationHistoryIdentityIDMust(sealed.Identity) != id {
		return operationHistoryStoredRecord{}, ErrOperationHistoryCorrupt
	}
	digest, err := sealed.ContentSHA256()
	if err != nil || digest != stored.RecordSHA256 {
		return operationHistoryStoredRecord{}, ErrOperationHistoryCorrupt
	}
	stored.Record = sealed
	return stored, nil
}

func (store *OperationHistoryStore) readReservation(id string) (operationHistoryReservationFile, error) {
	var reservation operationHistoryReservationFile
	data, err := readPrivateFile(store.reservationPath(id), 16*1024)
	if err != nil {
		return reservation, err
	}
	if err := decodeOperationHistoryJSON(data, &reservation); err != nil || reservation.SchemaVersion != OperationHistoryStoreSchemaVersion || reservation.ReservationID != id || !validHistoryToken(reservation.Token) || !validHistoryIdentity(reservation.Identity) || operationHistoryIdentityIDMust(reservation.Identity) != id || reservation.ReservedBytes != MaxOperationHistoryReservedBytes || !utcNormalized(reservation.CreatedAt) {
		return operationHistoryReservationFile{}, ErrOperationHistoryCorrupt
	}
	return reservation, nil
}

func (store *OperationHistoryStore) beginMutationLocked(operation, recordID string) error {
	marker := struct {
		SchemaVersion string    `json:"schema_version"`
		Operation     string    `json:"operation"`
		RecordID      string    `json:"record_id,omitempty"`
		StartedAt     time.Time `json:"started_at"`
	}{SchemaVersion: OperationHistoryStoreSchemaVersion, Operation: operation, RecordID: recordID, StartedAt: time.Now().UTC()}
	if err := writePrivateJSONAtomic(store.transactionPath(), marker); err != nil {
		return ErrOperationHistoryUnavailable
	}
	return nil
}

func (store *OperationHistoryStore) finishMutationLocked(usage operationHistoryUsagePayload) error {
	if err := store.writeUsage(usage); err != nil {
		return ErrOperationHistoryUnavailable
	}
	if err := removePrivateFile(store.transactionPath()); err != nil {
		return ErrOperationHistoryUnavailable
	}
	return nil
}

func (store *OperationHistoryStore) readUsage() (operationHistoryUsagePayload, error) {
	var result operationHistoryUsagePayload
	data, err := readPrivateFile(filepath.Join(store.root, "usage.json"), 16*1024)
	if err != nil {
		return result, err
	}
	var stored OperationHistoryStoreUsage
	if err := decodeOperationHistoryJSON(data, &stored); err != nil || stored.SchemaVersion != OperationHistoryStoreSchemaVersion || stored.MaximumBytes != store.maxBytes || stored.UsedBytes < 0 || stored.ReservedBytes < 0 || stored.RecordCount < 0 || stored.RecordCount > maxOperationHistoryPendingRecords || stored.ReservationCount < 0 || stored.ReservationCount > maxOperationHistoryReservations || stored.AcceptedRecordCount < stored.RecordCount || stored.VerifiedPublicationCount < 0 || stored.VerifiedPublicationCount != stored.AcceptedRecordCount-stored.RecordCount || stored.AcceptedRecordCount < 0 || stored.CapacityBlockedCount < 0 || stored.OperationKeyCount < 0 || stored.OperationKeyCount > maxOperationHistoryOperationKeys || stored.NextSequence != uint64(stored.AcceptedRecordCount)+1 || stored.UsedBytes+stored.ReservedBytes > store.maxBytes {
		return result, ErrOperationHistoryCorrupt
	}
	payload := operationHistoryUsagePayload{SchemaVersion: stored.SchemaVersion, MaximumBytes: stored.MaximumBytes, UsedBytes: stored.UsedBytes, ReservedBytes: stored.ReservedBytes, RecordCount: stored.RecordCount, ReservationCount: stored.ReservationCount, AcceptedRecordCount: stored.AcceptedRecordCount, VerifiedPublicationCount: stored.VerifiedPublicationCount, CapacityBlockedCount: stored.CapacityBlockedCount, OperationKeyCount: stored.OperationKeyCount, NextSequence: stored.NextSequence}
	encoded, _ := json.Marshal(payload)
	digest := sha256.Sum256(encoded)
	if hex.EncodeToString(digest[:]) != stored.UsageSHA256 {
		return result, ErrOperationHistoryCorrupt
	}
	return payload, nil
}

func publicOperationHistoryUsage(payload operationHistoryUsagePayload) OperationHistoryStoreUsage {
	encoded, _ := json.Marshal(payload)
	digest := sha256.Sum256(encoded)
	return OperationHistoryStoreUsage{SchemaVersion: payload.SchemaVersion, MaximumBytes: payload.MaximumBytes, UsedBytes: payload.UsedBytes, ReservedBytes: payload.ReservedBytes, RecordCount: payload.RecordCount, ReservationCount: payload.ReservationCount, AcceptedRecordCount: payload.AcceptedRecordCount, VerifiedPublicationCount: payload.VerifiedPublicationCount, CapacityBlockedCount: payload.CapacityBlockedCount, OperationKeyCount: payload.OperationKeyCount, NextSequence: payload.NextSequence, UsageSHA256: hex.EncodeToString(digest[:])}
}

func (store *OperationHistoryStore) writeUsage(payload operationHistoryUsagePayload) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	usage := OperationHistoryStoreUsage{SchemaVersion: payload.SchemaVersion, MaximumBytes: payload.MaximumBytes, UsedBytes: payload.UsedBytes, ReservedBytes: payload.ReservedBytes, RecordCount: payload.RecordCount, ReservationCount: payload.ReservationCount, AcceptedRecordCount: payload.AcceptedRecordCount, VerifiedPublicationCount: payload.VerifiedPublicationCount, CapacityBlockedCount: payload.CapacityBlockedCount, OperationKeyCount: payload.OperationKeyCount, NextSequence: payload.NextSequence, UsageSHA256: hex.EncodeToString(digest[:])}
	return writePrivateJSONAtomic(filepath.Join(store.root, "usage.json"), usage)
}

func (store *OperationHistoryStore) transactionPath() string {
	return filepath.Join(store.root, "transaction.json")
}
func (store *OperationHistoryStore) recordPath(id string) string {
	return filepath.Join(store.root, "records", id+".json")
}
func (store *OperationHistoryStore) reservationPath(id string) string {
	return filepath.Join(store.root, "reservations", id+".json")
}
func (store *OperationHistoryStore) operationIndexPath(key string) string {
	return filepath.Join(store.root, "operation-index", key+".json")
}
func (store *OperationHistoryStore) checkpointPath() string {
	return filepath.Join(store.root, "checkpoint.json")
}
func (store *OperationHistoryStore) publicationTransactionPath() string {
	return filepath.Join(store.root, "publication-transaction.json")
}

func operationHistoryIdentityID(identity OperationHistoryIdentity) (string, error) {
	return operationHistoryIdentityKey(identity)
}

func newOperationHistoryReservationToken() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func (store *OperationHistoryStore) recordCapacityBlockLocked(usage operationHistoryUsagePayload, recordID string) {
	if usage.CapacityBlockedCount == int64(^uint64(0)>>1) {
		return
	}
	usage.CapacityBlockedCount++
	if store.beginMutationLocked("capacity_block", recordID) != nil {
		return
	}
	_ = store.finishMutationLocked(usage)
}

func operationHistoryIdentityIDMust(identity OperationHistoryIdentity) string {
	id, _ := operationHistoryIdentityID(identity)
	return id
}

func validHistoryIdentity(identity OperationHistoryIdentity) bool {
	return identity.Validate() == nil
}

func validHistoryRecordID(id string) bool {
	if len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil && strings.ToLower(id) == id
}

func validHistoryToken(token string) bool {
	if len(token) != 64 {
		return false
	}
	_, err := hex.DecodeString(token)
	return err == nil && strings.ToLower(token) == token
}

func fileCharge(size int64) int64 {
	return size + operationHistoryFileCharge
}

func operationHistoryPendingRecordCharge(size int64) int64 {
	return fileCharge(size) + operationHistoryPendingMetadataReserve
}

func ensurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrOperationHistoryUnavailable
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	info, err = os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return ErrOperationHistoryUnavailable
	}
	return nil
}

func writePrivateJSONAtomic(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writePrivateBytesAtomic(path, data)
}

func writePrivateBytesAtomic(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".operation-history-partial-")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := io.Copy(temporary, bytes.NewReader(data)); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func removePrivateFile(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
		return ErrOperationHistoryCorrupt
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func readPrivateFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() < 0 || info.Size() > maximum || info.Mode().Perm()&0o077 != 0 {
		return nil, ErrOperationHistoryCorrupt
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Size() != info.Size() || opened.Mode().Perm() != 0o600 {
		return nil, ErrOperationHistoryCorrupt
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) > maximum {
		return nil, ErrOperationHistoryCorrupt
	}
	return data, nil
}

func decodeOperationHistoryJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing data in operation history file")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func cleanupOperationHistoryPartials(root string) error {
	for _, directory := range []string{root, filepath.Join(root, "records"), filepath.Join(root, "reservations"), filepath.Join(root, "operation-index")} {
		entries, err := os.ReadDir(directory)
		if err != nil {
			return ErrOperationHistoryUnavailable
		}
		removed := false
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".operation-history-partial-") {
				continue
			}
			path := filepath.Join(directory, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 {
				return ErrOperationHistoryCorrupt
			}
			if err := os.Remove(path); err != nil {
				return ErrOperationHistoryUnavailable
			}
			removed = true
		}
		if removed {
			if err := syncDirectory(directory); err != nil {
				return ErrOperationHistoryUnavailable
			}
		}
	}
	return nil
}
