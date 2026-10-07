package health

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"regexp"
)

var operationHistoryDatasetRepoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)

// PublishPendingOperationHistoryBatch publishes one stable local batch and
// acknowledges it only after the configured publisher returns exact readback
// hashes for a pinned remote revision.
func (store *OperationHistoryStore) PublishPendingOperationHistoryBatch(ctx context.Context, publisher OperationHistoryBatchPublisher) (bool, error) {
	if store == nil || ctx == nil || publisher == nil {
		return false, ErrOperationHistoryUnavailable
	}
	batch, err := store.PendingOperationHistoryBatch(ctx)
	if err != nil {
		return false, err
	}
	if len(batch.Records) == 0 {
		return false, nil
	}
	readback, err := publisher.PublishAndReadback(ctx, batch)
	if err != nil {
		return false, err
	}
	batch.ManifestSHA256 = readback.ManifestSHA256
	batch.RecordsSHA256 = readback.RecordsSHA256
	confirmation, err := newVerifiedOperationHistoryPublicationConfirmation(batch, readback)
	if err != nil {
		return false, err
	}
	if err := store.AcknowledgeOperationHistoryBatch(ctx, batch, confirmation); err != nil {
		return false, err
	}
	return true, nil
}

// PendingOperationHistoryBatch returns the oldest contiguous unpublished
// prefix. The first selection is durably frozen before returning, so new
// appends cannot change a batch across publisher retries.
func (store *OperationHistoryStore) PendingOperationHistoryBatch(ctx context.Context) (OperationHistoryBatch, error) {
	if store == nil || ctx == nil {
		return OperationHistoryBatch{}, ErrOperationHistoryUnavailable
	}
	var batch OperationHistoryBatch
	err := store.withLock(ctx, func() error {
		if _, err := store.ensureUsageLocked(ctx); err != nil {
			return err
		}
		var err error
		batch, err = store.pendingOperationHistoryBatchLocked(ctx)
		return err
	})
	return batch, err
}

func (store *OperationHistoryStore) pendingOperationHistoryBatchLocked(ctx context.Context) (OperationHistoryBatch, error) {
	checkpoint, err := store.readCheckpoint()
	if err != nil {
		return OperationHistoryBatch{}, err
	}
	usage, err := store.readUsage()
	if err != nil {
		return OperationHistoryBatch{}, err
	}
	if descriptor, found, err := store.readPendingBatchDescriptor(); err != nil {
		return OperationHistoryBatch{}, err
	} else if found {
		if int64(len(descriptor.Records)) > usage.RecordCount {
			return OperationHistoryBatch{}, ErrOperationHistoryCorrupt
		}
		return store.loadPendingOperationHistoryBatchLocked(ctx, checkpoint, descriptor)
	}

	batch := OperationHistoryBatch{SchemaVersion: OperationHistoryRecordSchemaVersion, Records: make([]OperationHistoryBatchRecord, 0, MaxOperationHistoryBatchRecords)}
	if usage.RecordCount == 0 {
		return batch, nil
	}
	var totalBytes int64
	maxRecords := uint64(usage.RecordCount)
	if maxRecords > MaxOperationHistoryBatchRecords {
		maxRecords = MaxOperationHistoryBatchRecords
	}
	for offset := uint64(0); offset < maxRecords; offset++ {
		if err := ctx.Err(); err != nil {
			return OperationHistoryBatch{}, err
		}
		sequence := checkpoint.Sequence + offset + 1
		index, found, err := store.readPendingSequenceIndex(sequence)
		if err != nil {
			return OperationHistoryBatch{}, err
		}
		if !found {
			return OperationHistoryBatch{}, ErrOperationHistoryCorrupt
		}
		if totalBytes+index.SerializedBytes+1 > MaxOperationHistoryBatchBytes {
			if len(batch.Records) == 0 {
				return OperationHistoryBatch{}, ErrOperationHistoryCapacity
			}
			break
		}
		stored, err := store.readStoredRecord(ctx, index.RecordID)
		if err != nil || stored.Sequence != sequence || stored.RecordSHA256 != index.RecordSHA || !stored.AppendedAt.Equal(index.AppendedAt) {
			return OperationHistoryBatch{}, ErrOperationHistoryCorrupt
		}
		encoded, err := json.Marshal(stored.Record)
		if err != nil || int64(len(encoded)) != index.SerializedBytes {
			return OperationHistoryBatch{}, ErrOperationHistoryCorrupt
		}
		batch.Records = append(batch.Records, OperationHistoryBatchRecord{RecordID: index.RecordID, RecordSHA: index.RecordSHA, Sequence: sequence, AppendedAt: index.AppendedAt, Record: stored.Record})
		totalBytes += index.SerializedBytes + 1
	}
	if len(batch.Records) == 0 {
		return batch, nil
	}
	refs := operationHistoryBatchRefs(batch.Records)
	batch.RecordSetSHA, batch.BatchID = operationHistoryBatchDigests(refs)
	descriptor := newOperationHistoryPendingBatchDescriptor(batch)
	if err := store.writePendingBatchDescriptorLocked(descriptor); err != nil {
		return OperationHistoryBatch{}, err
	}
	return batch, nil
}

func (store *OperationHistoryStore) loadPendingOperationHistoryBatchLocked(ctx context.Context, checkpoint operationHistoryCheckpoint, descriptor operationHistoryPendingBatchDescriptor) (OperationHistoryBatch, error) {
	if validateOperationHistoryPendingBatchDescriptor(descriptor) != nil || descriptor.Records[0].Sequence != checkpoint.Sequence+1 {
		return OperationHistoryBatch{}, ErrOperationHistoryCorrupt
	}
	batch := OperationHistoryBatch{SchemaVersion: OperationHistoryRecordSchemaVersion, BatchID: descriptor.BatchID, RecordSetSHA: descriptor.RecordSetSHA, Records: make([]OperationHistoryBatchRecord, 0, len(descriptor.Records))}
	var totalBytes int64
	for _, ref := range descriptor.Records {
		if err := ctx.Err(); err != nil {
			return OperationHistoryBatch{}, err
		}
		index, found, err := store.readPendingSequenceIndex(ref.Sequence)
		if err != nil || !found || index.RecordID != ref.RecordID || index.RecordSHA != ref.RecordSHA || !index.AppendedAt.Equal(ref.AppendedAt) {
			return OperationHistoryBatch{}, ErrOperationHistoryCorrupt
		}
		totalBytes += index.SerializedBytes + 1
		if totalBytes > MaxOperationHistoryBatchBytes {
			return OperationHistoryBatch{}, ErrOperationHistoryCorrupt
		}
		stored, err := store.readStoredRecord(ctx, ref.RecordID)
		if err != nil || stored.Sequence != ref.Sequence || stored.RecordSHA256 != ref.RecordSHA || !stored.AppendedAt.Equal(ref.AppendedAt) || stored.Record.Identity != ref.Identity {
			return OperationHistoryBatch{}, ErrOperationHistoryCorrupt
		}
		batch.Records = append(batch.Records, OperationHistoryBatchRecord{RecordID: ref.RecordID, RecordSHA: ref.RecordSHA, Sequence: ref.Sequence, AppendedAt: ref.AppendedAt, Record: stored.Record})
	}
	if validateOperationHistoryBatch(batch) != nil {
		return OperationHistoryBatch{}, ErrOperationHistoryCorrupt
	}
	return batch, nil
}

func newOperationHistoryPendingBatchDescriptor(batch OperationHistoryBatch) operationHistoryPendingBatchDescriptor {
	descriptor := operationHistoryPendingBatchDescriptor{
		SchemaVersion: OperationHistoryStoreSchemaVersion,
		BatchID:       batch.BatchID,
		RecordSetSHA:  batch.RecordSetSHA,
		Records:       operationHistoryBatchRefs(batch.Records),
	}
	descriptor.DescriptorSHA = operationHistoryPendingBatchDescriptorDigest(descriptor)
	return descriptor
}

func validateOperationHistoryPendingBatchDescriptor(descriptor operationHistoryPendingBatchDescriptor) error {
	if descriptor.SchemaVersion != OperationHistoryStoreSchemaVersion || len(descriptor.Records) == 0 || len(descriptor.Records) > MaxOperationHistoryBatchRecords || !sha256Pattern.MatchString(descriptor.BatchID) || !sha256Pattern.MatchString(descriptor.RecordSetSHA) || !sha256Pattern.MatchString(descriptor.DescriptorSHA) || operationHistoryPendingBatchDescriptorDigest(descriptor) != descriptor.DescriptorSHA {
		return ErrOperationHistoryCorrupt
	}
	recordSetSHA, batchID := operationHistoryBatchDigests(descriptor.Records)
	if recordSetSHA != descriptor.RecordSetSHA || batchID != descriptor.BatchID {
		return ErrOperationHistoryCorrupt
	}
	var previousSequence uint64
	for _, record := range descriptor.Records {
		if !validHistoryRecordID(record.RecordID) || !sha256Pattern.MatchString(record.RecordSHA) || record.Sequence == 0 || (previousSequence != 0 && record.Sequence != previousSequence+1) || !utcNormalized(record.AppendedAt) || !validHistoryIdentity(record.Identity) || operationHistoryIdentityIDMust(record.Identity) != record.RecordID {
			return ErrOperationHistoryCorrupt
		}
		previousSequence = record.Sequence
	}
	return nil
}

func operationHistoryPendingBatchDescriptorDigest(descriptor operationHistoryPendingBatchDescriptor) string {
	encoded, _ := json.Marshal(operationHistoryPendingBatchDescriptorPayload{SchemaVersion: descriptor.SchemaVersion, BatchID: descriptor.BatchID, RecordSetSHA: descriptor.RecordSetSHA, Records: descriptor.Records})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (store *OperationHistoryStore) readPendingBatchDescriptor() (operationHistoryPendingBatchDescriptor, bool, error) {
	var descriptor operationHistoryPendingBatchDescriptor
	data, err := readPrivateFile(store.pendingBatchDescriptorPath(), maxOperationHistoryPendingBatchDescriptorFile)
	if errors.Is(err, os.ErrNotExist) {
		return descriptor, false, nil
	}
	if err != nil || decodeOperationHistoryJSON(data, &descriptor) != nil || validateOperationHistoryPendingBatchDescriptor(descriptor) != nil {
		return operationHistoryPendingBatchDescriptor{}, false, ErrOperationHistoryCorrupt
	}
	return descriptor, true, nil
}

func (store *OperationHistoryStore) writePendingBatchDescriptorLocked(descriptor operationHistoryPendingBatchDescriptor) error {
	if validateOperationHistoryPendingBatchDescriptor(descriptor) != nil {
		return ErrOperationHistoryUnavailable
	}
	if _, found, err := store.readPendingBatchDescriptor(); err != nil {
		return err
	} else if found {
		return ErrOperationHistoryConflict
	}
	encoded, err := json.Marshal(descriptor)
	if err != nil || int64(len(encoded))+operationHistoryFileCharge > maxOperationHistoryPendingBatchDescriptorFile {
		return ErrOperationHistoryCapacity
	}
	charge := fileCharge(int64(len(encoded)))
	if charge+operationHistoryPublicationTailroom > operationHistoryPublicationHeadroom {
		return ErrOperationHistoryCapacity
	}
	usage, err := store.readUsage()
	if err != nil {
		return err
	}
	if usage.UsedBytes+usage.ReservedBytes+charge+operationHistoryPublicationTailroom > store.maxBytes {
		store.recordCapacityBlockLocked(usage, descriptor.BatchID)
		return ErrOperationHistoryCapacity
	}
	if err := store.beginMutationLocked("freeze_batch", descriptor.BatchID); err != nil {
		return err
	}
	if err := writePrivateBytesAtomic(store.pendingBatchDescriptorPath(), encoded); err != nil {
		return ErrOperationHistoryUnavailable
	}
	usage.UsedBytes += charge
	return store.finishMutationLocked(usage)
}

// AcknowledgeOperationHistoryBatch is called only after exact remote readback
// verifies the immutable manifest and record artifact at one pinned revision.
// The local publication transaction is durable before any receipt is removed.
func (store *OperationHistoryStore) AcknowledgeOperationHistoryBatch(ctx context.Context, batch OperationHistoryBatch, confirmation OperationHistoryPublicationConfirmation) error {
	if store == nil || ctx == nil || validateOperationHistoryBatch(batch) != nil || !validSealedOperationHistoryConfirmation(batch, confirmation) {
		return ErrOperationHistoryUnavailable
	}
	return store.withLock(ctx, func() error {
		usage, err := store.ensureUsageLocked(ctx)
		if err != nil {
			return err
		}
		current, err := store.pendingOperationHistoryBatchLocked(ctx)
		if err != nil {
			return err
		}
		usage, err = store.readUsage()
		if err != nil {
			return err
		}
		if !sameOperationHistoryBatch(current, batch) {
			checkpoint, checkpointErr := store.readCheckpoint()
			if checkpointErr != nil {
				return checkpointErr
			}
			if checkpoint.Sequence >= batch.Records[len(batch.Records)-1].Sequence && sameOperationHistoryPublicationArtifact(checkpoint.Confirmation, confirmation) {
				return nil
			}
			return ErrOperationHistoryConflict
		}
		if len(batch.Records) == 0 || batch.Records[0].Sequence != uint64(usage.VerifiedPublicationCount)+1 {
			return ErrOperationHistoryConflict
		}
		records := operationHistoryBatchRefs(batch.Records)
		indexChanges, err := store.operationHistoryIndexChangesLocked(ctx, records)
		if err != nil {
			return err
		}
		transaction := operationHistoryPublicationTransaction{
			SchemaVersion: OperationHistoryStoreSchemaVersion,
			BatchID:       batch.BatchID,
			RecordSetSHA:  batch.RecordSetSHA,
			Confirmation:  confirmation,
			Records:       records,
			IndexChanges:  indexChanges,
		}
		transaction.TransactionSHA = operationHistoryPublicationTransactionDigest(transaction)
		if err := validateOperationHistoryPublicationTransaction(transaction); err != nil {
			return ErrOperationHistoryUnavailable
		}
		encoded, err := json.Marshal(transaction)
		if err != nil || int64(len(encoded))+operationHistoryFileCharge > maxOperationHistoryPublicationTransactionFile {
			return ErrOperationHistoryCapacity
		}
		if usage.UsedBytes+usage.ReservedBytes+2*fileCharge(int64(len(encoded))) > store.maxBytes {
			store.recordCapacityBlockLocked(usage, batch.BatchID)
			return ErrOperationHistoryCapacity
		}
		if err := writePrivateBytesAtomic(store.publicationTransactionPath(), encoded); err != nil {
			return ErrOperationHistoryUnavailable
		}
		if err := store.applyPublicationTransactionLocked(ctx, transaction); err != nil {
			return err
		}
		if err := removePrivateFile(store.publicationTransactionPath()); err != nil {
			return ErrOperationHistoryUnavailable
		}
		return store.rebuildUsageLocked(ctx)
	})
}

func (store *OperationHistoryStore) applyPublicationTransactionLocked(ctx context.Context, transaction operationHistoryPublicationTransaction) error {
	if err := validateOperationHistoryPublicationTransaction(transaction); err != nil {
		return ErrOperationHistoryCorrupt
	}
	checkpoint, err := store.readCheckpoint()
	if err != nil {
		return err
	}
	first := transaction.Records[0].Sequence
	last := transaction.Records[len(transaction.Records)-1].Sequence
	replay := checkpoint.Sequence == last && checkpoint.Confirmation.BatchID == transaction.BatchID
	if replay && !sameOperationHistoryPublicationArtifact(checkpoint.Confirmation, transaction.Confirmation) {
		return ErrOperationHistoryCorrupt
	}
	if !replay && checkpoint.Sequence+1 != first {
		return ErrOperationHistoryCorrupt
	}
	descriptor, descriptorFound, descriptorErr := store.readPendingBatchDescriptor()
	if descriptorErr != nil {
		return descriptorErr
	}
	if descriptorFound && (descriptor.BatchID != transaction.BatchID || descriptor.RecordSetSHA != transaction.RecordSetSHA || !sameOperationHistoryAckRecords(descriptor.Records, transaction.Records)) {
		return ErrOperationHistoryCorrupt
	}
	if !replay && !descriptorFound {
		return ErrOperationHistoryCorrupt
	}
	changes := make(map[string]operationHistoryIndexChange, len(transaction.IndexChanges))
	for _, change := range transaction.IndexChanges {
		changes[change.Key] = change
	}
	indices := make(map[string]operationHistoryOperationIndex, len(transaction.IndexChanges))
	for _, ref := range transaction.Records {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := store.recordPath(ref.RecordID)
		if _, statErr := os.Lstat(path); statErr == nil {
			stored, readErr := store.readStoredRecord(ctx, ref.RecordID)
			if readErr != nil || stored.RecordSHA256 != ref.RecordSHA || stored.Sequence != ref.Sequence || !stored.AppendedAt.Equal(ref.AppendedAt) || stored.Record.Identity != ref.Identity {
				return ErrOperationHistoryCorrupt
			}
			sequenceIndex, found, indexErr := store.readPendingSequenceIndex(ref.Sequence)
			if indexErr != nil || !found || sequenceIndex.RecordID != ref.RecordID || sequenceIndex.RecordSHA != ref.RecordSHA || !sequenceIndex.AppendedAt.Equal(ref.AppendedAt) {
				return ErrOperationHistoryCorrupt
			}
		} else if errors.Is(statErr, os.ErrNotExist) {
			// The durable transaction is the recovery source after record cleanup
			// has started. Its exact identity, sequence, receipt digest, and remote
			// confirmation were fsynced before any record file was removed.
		} else {
			return ErrOperationHistoryUnavailable
		}
		key := operationHistoryOperationIndexID(ref.Identity)
		_, foundChange := changes[key]
		if !foundChange {
			return ErrOperationHistoryCorrupt
		}
		candidate := operationHistoryOperationIndex{
			SchemaVersion: OperationHistoryStoreSchemaVersion,
			Identity:      ref.Identity,
			RecordSHA:     ref.RecordSHA,
			Sequence:      ref.Sequence,
			AppendedAt:    ref.AppendedAt,
			Confirmation:  transaction.Confirmation,
		}
		if prior, exists := indices[key]; exists {
			if prior.Identity.SourceID != candidate.Identity.SourceID || prior.Identity.OperationID != candidate.Identity.OperationID || prior.Identity.Generation >= candidate.Identity.Generation || prior.Sequence >= candidate.Sequence {
				return ErrOperationHistoryCorrupt
			}
		}
		indices[key] = candidate
	}
	for key, change := range changes {
		final, exists := indices[key]
		if !exists {
			return ErrOperationHistoryCorrupt
		}
		final.IndexSHA256 = operationHistoryOperationIndexDigest(final)
		indices[key] = final
		current, found, err := store.readOperationIndex(final.Identity)
		if err != nil {
			return err
		}
		if found && !sameOperationHistoryOperationIndex(current, final) && (change.Previous == nil || !sameOperationHistoryOperationIndex(current, *change.Previous)) {
			return ErrOperationHistoryCorrupt
		}
		if !found && change.Previous != nil {
			return ErrOperationHistoryCorrupt
		}
	}
	for _, ref := range transaction.Records {
		if err := removePrivateFile(store.recordPath(ref.RecordID)); err != nil {
			return ErrOperationHistoryUnavailable
		}
		if err := removePrivateFile(store.pendingSequencePath(ref.Sequence)); err != nil {
			return ErrOperationHistoryUnavailable
		}
	}
	for key, index := range indices {
		if err := writePrivateJSONAtomic(store.operationIndexPath(key), index); err != nil {
			return ErrOperationHistoryUnavailable
		}
	}
	if !replay {
		operationKeyCount := checkpoint.OperationKeyCount
		operationIndexSet := decodeOperationHistoryDigest(checkpoint.OperationIndexSetSHA)
		for key, change := range changes {
			index := indices[key]
			if change.Previous != nil {
				xorOperationHistoryDigest(&operationIndexSet, operationHistoryOperationIndexFingerprint(*change.Previous))
			} else {
				operationKeyCount++
			}
			xorOperationHistoryDigest(&operationIndexSet, operationHistoryOperationIndexFingerprint(index))
		}
		checkpoint = operationHistoryCheckpoint{SchemaVersion: OperationHistoryStoreSchemaVersion, Sequence: last, OperationKeyCount: operationKeyCount, OperationIndexSetSHA: hex.EncodeToString(operationIndexSet[:]), Confirmation: transaction.Confirmation}
		checkpoint.CheckpointSHA = operationHistoryCheckpointDigest(checkpoint)
		if err := writePrivateJSONAtomic(store.checkpointPath(), checkpoint); err != nil {
			return ErrOperationHistoryUnavailable
		}
	}
	if descriptorFound {
		if err := removePrivateFile(store.pendingBatchDescriptorPath()); err != nil {
			return ErrOperationHistoryUnavailable
		}
	}
	return nil
}

func validateOperationHistoryBatch(batch OperationHistoryBatch) error {
	if batch.SchemaVersion != OperationHistoryRecordSchemaVersion || len(batch.Records) == 0 || len(batch.Records) > MaxOperationHistoryBatchRecords || !sha256Pattern.MatchString(batch.BatchID) || !sha256Pattern.MatchString(batch.RecordSetSHA) {
		return ErrOperationHistoryUnavailable
	}
	refs := operationHistoryBatchRefs(batch.Records)
	setSHA, batchID := operationHistoryBatchDigests(refs)
	if batch.RecordSetSHA != setSHA || batch.BatchID != batchID {
		return ErrOperationHistoryUnavailable
	}
	var total int
	var previousSequence uint64
	for _, item := range batch.Records {
		if !validHistoryRecordID(item.RecordID) || !sha256Pattern.MatchString(item.RecordSHA) || item.Sequence == 0 || (previousSequence != 0 && item.Sequence != previousSequence+1) || !utcNormalized(item.AppendedAt) || item.Record.Validate() != nil || operationHistoryIdentityIDMust(item.Record.Identity) != item.RecordID {
			return ErrOperationHistoryUnavailable
		}
		recordSHA, err := item.Record.ContentSHA256()
		if err != nil || recordSHA != item.RecordSHA {
			return ErrOperationHistoryUnavailable
		}
		encoded, err := json.Marshal(item.Record)
		if err != nil {
			return ErrOperationHistoryUnavailable
		}
		total += len(encoded) + 1
		if total > MaxOperationHistoryBatchBytes {
			return ErrOperationHistoryCapacity
		}
		previousSequence = item.Sequence
	}
	return nil
}

func validOperationHistoryConfirmation(batch OperationHistoryBatch, confirmation OperationHistoryPublicationConfirmation) bool {
	return confirmation.BatchID == batch.BatchID && operationHistoryDatasetRepoPattern.MatchString(confirmation.DatasetRepo) && commitPattern.MatchString(confirmation.Revision) && sha256Pattern.MatchString(confirmation.ManifestSHA256) && sha256Pattern.MatchString(confirmation.RecordsSHA256) && confirmation.ManifestSHA256 == batch.ManifestSHA256 && confirmation.RecordsSHA256 == batch.RecordsSHA256 && confirmation.RecordSetSHA256 == batch.RecordSetSHA && utcNormalized(confirmation.VerifiedAt)
}

func newVerifiedOperationHistoryPublicationConfirmation(batch OperationHistoryBatch, readback OperationHistoryPublicationReadback) (OperationHistoryPublicationConfirmation, error) {
	confirmation := OperationHistoryPublicationConfirmation{BatchID: batch.BatchID, DatasetRepo: readback.DatasetRepo, Revision: readback.Revision, ManifestSHA256: readback.ManifestSHA256, RecordsSHA256: readback.RecordsSHA256, RecordSetSHA256: readback.RecordSetSHA256, VerifiedAt: readback.VerifiedAt, verifiedByPublisher: true}
	if !validOperationHistoryConfirmation(batch, confirmation) {
		return OperationHistoryPublicationConfirmation{}, ErrOperationHistoryUnavailable
	}
	confirmation.sealSHA256 = operationHistoryPublicationConfirmationSeal(confirmation)
	return confirmation, nil
}

func validSealedOperationHistoryConfirmation(batch OperationHistoryBatch, confirmation OperationHistoryPublicationConfirmation) bool {
	return confirmation.verifiedByPublisher && confirmation.sealSHA256 != "" && operationHistoryPublicationConfirmationSeal(confirmation) == confirmation.sealSHA256 && validOperationHistoryConfirmation(batch, confirmation)
}

func operationHistoryPublicationConfirmationSeal(confirmation OperationHistoryPublicationConfirmation) string {
	encoded, _ := json.Marshal(confirmation)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func operationHistoryBatchRefs(records []OperationHistoryBatchRecord) []operationHistoryAckRecord {
	refs := make([]operationHistoryAckRecord, 0, len(records))
	for _, record := range records {
		refs = append(refs, operationHistoryAckRecord{RecordID: record.RecordID, RecordSHA: record.RecordSHA, Sequence: record.Sequence, AppendedAt: record.AppendedAt, Identity: record.Record.Identity})
	}
	return refs
}

func (store *OperationHistoryStore) operationHistoryIndexChangesLocked(ctx context.Context, records []operationHistoryAckRecord) ([]operationHistoryIndexChange, error) {
	changes := make([]operationHistoryIndexChange, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key := operationHistoryOperationIndexID(record.Identity)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		previous, found, err := store.readOperationIndex(record.Identity)
		if err != nil {
			return nil, err
		}
		change := operationHistoryIndexChange{Key: key}
		if found {
			copy := previous
			change.Previous = &copy
		}
		changes = append(changes, change)
	}
	return changes, nil
}

func sameOperationHistoryOperationIndex(left, right operationHistoryOperationIndex) bool {
	return left.SchemaVersion == right.SchemaVersion && left.Identity == right.Identity && left.RecordSHA == right.RecordSHA && left.Sequence == right.Sequence && left.AppendedAt.Equal(right.AppendedAt) && left.Confirmation == right.Confirmation && left.IndexSHA256 == right.IndexSHA256
}

func operationHistoryBatchDigests(refs []operationHistoryAckRecord) (recordSetSHA, batchID string) {
	encoded, _ := json.Marshal(refs)
	digest := sha256.Sum256(encoded)
	recordSetSHA = hex.EncodeToString(digest[:])
	batchDigest := sha256.Sum256([]byte(OperationHistoryRecordSchemaVersion + "\n" + recordSetSHA))
	return recordSetSHA, hex.EncodeToString(batchDigest[:])
}

func sameOperationHistoryBatch(left, right OperationHistoryBatch) bool {
	if left.BatchID != right.BatchID || left.RecordSetSHA != right.RecordSetSHA || len(left.Records) != len(right.Records) {
		return false
	}
	for index := range left.Records {
		a, b := left.Records[index], right.Records[index]
		if a.RecordID != b.RecordID || a.RecordSHA != b.RecordSHA || a.Sequence != b.Sequence || !a.AppendedAt.Equal(b.AppendedAt) || a.Record.Identity != b.Record.Identity {
			return false
		}
	}
	return true
}

func sameOperationHistoryAckRecords(left, right []operationHistoryAckRecord) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		a, b := left[index], right[index]
		if a.RecordID != b.RecordID || a.RecordSHA != b.RecordSHA || a.Sequence != b.Sequence || !a.AppendedAt.Equal(b.AppendedAt) || a.Identity != b.Identity {
			return false
		}
	}
	return true
}

func sameOperationHistoryPublicationArtifact(left, right OperationHistoryPublicationConfirmation) bool {
	return left.BatchID == right.BatchID && left.DatasetRepo == right.DatasetRepo && left.Revision == right.Revision && left.ManifestSHA256 == right.ManifestSHA256 && left.RecordsSHA256 == right.RecordsSHA256 && left.RecordSetSHA256 == right.RecordSetSHA256
}

func operationHistoryOperationIndexID(identity OperationHistoryIdentity) string {
	digest := sha256.Sum256([]byte(identity.SourceID + "\n" + identity.OperationID))
	return hex.EncodeToString(digest[:])
}

func operationHistoryOperationIndexDigest(index operationHistoryOperationIndex) string {
	payload := operationHistoryOperationIndexPayload{SchemaVersion: index.SchemaVersion, Identity: index.Identity, RecordSHA: index.RecordSHA, Sequence: index.Sequence, AppendedAt: index.AppendedAt, Confirmation: index.Confirmation}
	encoded, _ := json.Marshal(payload)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func operationHistoryCheckpointDigest(checkpoint operationHistoryCheckpoint) string {
	payload := operationHistoryCheckpointPayload{SchemaVersion: checkpoint.SchemaVersion, Sequence: checkpoint.Sequence, OperationKeyCount: checkpoint.OperationKeyCount, OperationIndexSetSHA: checkpoint.OperationIndexSetSHA, Confirmation: checkpoint.Confirmation}
	encoded, _ := json.Marshal(payload)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func operationHistoryOperationIndexFingerprint(index operationHistoryOperationIndex) [sha256.Size]byte {
	digest := sha256.Sum256([]byte(operationHistoryOperationIndexID(index.Identity) + "\n" + index.IndexSHA256))
	return digest
}

func xorOperationHistoryDigest(target *[sha256.Size]byte, value [sha256.Size]byte) {
	for i := range target {
		target[i] ^= value[i]
	}
}

func decodeOperationHistoryDigest(value string) [sha256.Size]byte {
	var digest [sha256.Size]byte
	if value == "" {
		return digest
	}
	decoded, err := hex.DecodeString(value)
	if err == nil && len(decoded) == len(digest) {
		copy(digest[:], decoded)
	}
	return digest
}

func operationHistoryPublicationTransactionDigest(transaction operationHistoryPublicationTransaction) string {
	payload := operationHistoryPublicationTransactionPayload{SchemaVersion: transaction.SchemaVersion, BatchID: transaction.BatchID, RecordSetSHA: transaction.RecordSetSHA, Confirmation: transaction.Confirmation, Records: transaction.Records, IndexChanges: transaction.IndexChanges}
	encoded, _ := json.Marshal(payload)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validateOperationHistoryPublicationTransaction(transaction operationHistoryPublicationTransaction) error {
	if transaction.SchemaVersion != OperationHistoryStoreSchemaVersion || len(transaction.Records) == 0 || len(transaction.Records) > MaxOperationHistoryBatchRecords || !sha256Pattern.MatchString(transaction.BatchID) || !sha256Pattern.MatchString(transaction.RecordSetSHA) || operationHistoryPublicationTransactionDigest(transaction) != transaction.TransactionSHA {
		return ErrOperationHistoryCorrupt
	}
	setSHA, batchID := operationHistoryBatchDigests(transaction.Records)
	confirmation := transaction.Confirmation
	batch := OperationHistoryBatch{BatchID: transaction.BatchID, RecordSetSHA: transaction.RecordSetSHA, ManifestSHA256: confirmation.ManifestSHA256, RecordsSHA256: confirmation.RecordsSHA256}
	if batchID != transaction.BatchID || setSHA != transaction.RecordSetSHA || !validOperationHistoryConfirmation(batch, confirmation) {
		return ErrOperationHistoryCorrupt
	}
	var previous uint64
	expectedKeys := make(map[string]OperationHistoryIdentity, len(transaction.Records))
	for _, ref := range transaction.Records {
		if !validHistoryRecordID(ref.RecordID) || operationHistoryIdentityIDMust(ref.Identity) != ref.RecordID || !sha256Pattern.MatchString(ref.RecordSHA) || ref.Sequence == 0 || (previous != 0 && ref.Sequence != previous+1) || !utcNormalized(ref.AppendedAt) {
			return ErrOperationHistoryCorrupt
		}
		previous = ref.Sequence
		key := operationHistoryOperationIndexID(ref.Identity)
		if prior, found := expectedKeys[key]; found && (prior.SourceID != ref.Identity.SourceID || prior.OperationID != ref.Identity.OperationID) {
			return ErrOperationHistoryCorrupt
		}
		expectedKeys[key] = ref.Identity
	}
	if len(transaction.IndexChanges) != len(expectedKeys) {
		return ErrOperationHistoryCorrupt
	}
	seenChanges := make(map[string]struct{}, len(transaction.IndexChanges))
	firstSequence := transaction.Records[0].Sequence
	for _, change := range transaction.IndexChanges {
		operation, expected := expectedKeys[change.Key]
		if !expected || operationHistoryOperationIndexID(operation) != change.Key {
			return ErrOperationHistoryCorrupt
		}
		if _, duplicate := seenChanges[change.Key]; duplicate {
			return ErrOperationHistoryCorrupt
		}
		seenChanges[change.Key] = struct{}{}
		if change.Previous != nil {
			if !validOperationHistoryOperationIndex(*change.Previous, change.Key) || change.Previous.Identity.SourceID != operation.SourceID || change.Previous.Identity.OperationID != operation.OperationID || change.Previous.Sequence >= firstSequence {
				return ErrOperationHistoryCorrupt
			}
			for _, ref := range transaction.Records {
				if operationHistoryOperationIndexID(ref.Identity) == change.Key && ref.Identity.Generation <= change.Previous.Identity.Generation {
					return ErrOperationHistoryCorrupt
				}
			}
		}
	}
	return nil
}

func (store *OperationHistoryStore) readOperationIndex(identity OperationHistoryIdentity) (operationHistoryOperationIndex, bool, error) {
	var index operationHistoryOperationIndex
	if !validHistoryIdentity(identity) {
		return index, false, ErrOperationHistoryCorrupt
	}
	key := operationHistoryOperationIndexID(identity)
	data, err := readPrivateFile(store.operationIndexPath(key), operationHistoryOperationIndexMaximumBytes)
	if errors.Is(err, os.ErrNotExist) {
		return index, false, nil
	}
	if err != nil {
		return index, false, ErrOperationHistoryCorrupt
	}
	if err := decodeOperationHistoryJSON(data, &index); err != nil || !validOperationHistoryOperationIndex(index, key) || index.Identity.SourceID != identity.SourceID || index.Identity.OperationID != identity.OperationID {
		return operationHistoryOperationIndex{}, false, ErrOperationHistoryCorrupt
	}
	return index, true, nil
}

func validOperationHistoryOperationIndex(index operationHistoryOperationIndex, key string) bool {
	confirmation := index.Confirmation
	return index.SchemaVersion == OperationHistoryStoreSchemaVersion && validHistoryIdentity(index.Identity) && operationHistoryOperationIndexID(index.Identity) == key && sha256Pattern.MatchString(index.RecordSHA) && index.Sequence > 0 && utcNormalized(index.AppendedAt) && index.Identity.Generation > 0 && operationHistoryDatasetRepoPattern.MatchString(confirmation.DatasetRepo) && commitPattern.MatchString(confirmation.Revision) && sha256Pattern.MatchString(confirmation.ManifestSHA256) && sha256Pattern.MatchString(confirmation.RecordsSHA256) && sha256Pattern.MatchString(confirmation.RecordSetSHA256) && sha256Pattern.MatchString(confirmation.BatchID) && utcNormalized(confirmation.VerifiedAt) && operationHistoryOperationIndexDigest(index) == index.IndexSHA256
}

func (store *OperationHistoryStore) readCheckpoint() (operationHistoryCheckpoint, error) {
	var checkpoint operationHistoryCheckpoint
	data, err := readPrivateFile(store.checkpointPath(), maxOperationHistoryCheckpointFile)
	if errors.Is(err, os.ErrNotExist) {
		return checkpoint, nil
	}
	if err != nil {
		return checkpoint, ErrOperationHistoryCorrupt
	}
	if err := decodeOperationHistoryJSON(data, &checkpoint); err != nil || checkpoint.SchemaVersion != OperationHistoryStoreSchemaVersion || checkpoint.Sequence == 0 || checkpoint.Sequence > uint64(^uint64(0)>>1) || checkpoint.OperationKeyCount < 0 || checkpoint.OperationKeyCount > maxOperationHistoryOperationKeys || !sha256Pattern.MatchString(checkpoint.OperationIndexSetSHA) || !validOperationHistoryCheckpointConfirmation(checkpoint.Confirmation) || operationHistoryCheckpointDigest(checkpoint) != checkpoint.CheckpointSHA {
		return operationHistoryCheckpoint{}, ErrOperationHistoryCorrupt
	}
	return checkpoint, nil
}

func validOperationHistoryCheckpointConfirmation(confirmation OperationHistoryPublicationConfirmation) bool {
	return sha256Pattern.MatchString(confirmation.BatchID) && operationHistoryDatasetRepoPattern.MatchString(confirmation.DatasetRepo) && commitPattern.MatchString(confirmation.Revision) && sha256Pattern.MatchString(confirmation.ManifestSHA256) && sha256Pattern.MatchString(confirmation.RecordsSHA256) && sha256Pattern.MatchString(confirmation.RecordSetSHA256) && utcNormalized(confirmation.VerifiedAt)
}

func (store *OperationHistoryStore) readPublicationTransaction() (operationHistoryPublicationTransaction, error) {
	var transaction operationHistoryPublicationTransaction
	data, err := readPrivateFile(store.publicationTransactionPath(), maxOperationHistoryPublicationTransactionFile)
	if err != nil {
		return transaction, err
	}
	if err := decodeOperationHistoryJSON(data, &transaction); err != nil || validateOperationHistoryPublicationTransaction(transaction) != nil {
		return operationHistoryPublicationTransaction{}, ErrOperationHistoryCorrupt
	}
	return transaction, nil
}

func (store *OperationHistoryStore) operationIndexExists(identity OperationHistoryIdentity) bool {
	_, found, err := store.readOperationIndex(identity)
	return err == nil && found
}
