package health

import "time"

// LookupPublicOperationRows returns rows for exact, bounded identities from the
// immutable in-memory projection. It never scans files or reads Gatus.
func (model *OperationReadModel) LookupPublicOperationRows(identities []RegistryOperationLookupIdentity, at time.Time) ([]OperationReadModelRow, error) {
	if model == nil || at.IsZero() || len(identities) == 0 || len(identities) > operationReadModelMaximumAPIIDs {
		return nil, ErrOperationReadModelUnavailable
	}
	seen := make(map[string]struct{}, len(identities))
	for _, identity := range identities {
		if !operationSourceIDPattern.MatchString(identity.SourceID) || identity.OperationID == "" || len(identity.OperationID) > 256 {
			return nil, ErrOperationReadModelUnavailable
		}
		key := operationReadModelIdentityKey(identity.SourceID, identity.OperationID)
		if _, duplicate := seen[key]; duplicate {
			return nil, ErrOperationReadModelUnavailable
		}
		seen[key] = struct{}{}
	}

	model.mu.RLock()
	defer model.mu.RUnlock()
	rows := make([]OperationReadModelRow, 0, len(identities))
	for _, identity := range identities {
		key := operationReadModelIdentityKey(identity.SourceID, identity.OperationID)
		index, ok := model.byIdentity[key]
		if !ok || index < 0 || index >= len(model.rows) {
			return nil, ErrOperationReadModelUnavailable
		}
		row := model.rows[index]
		refreshOperationReadModelFreshness(&row, at)
		if row.ValidatePublicProjection(at) != nil {
			return nil, ErrOperationReadModelUnavailable
		}
		rows = append(rows, row)
	}
	return rows, nil
}
