package health

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

var errRegistryAPIMetadataUnavailable = errors.New("verified Registry API metadata unavailable")

// VerifiedRegistryAPIMetadata is the only metadata input accepted by the
// operation read model. Its marker is populated after LoadRegistryAPIMetadata
// verifies the artifact bytes and source pin; callers cannot set that marker
// outside this package.
type VerifiedRegistryAPIMetadata struct {
	verified          bool
	pin               RegistryAPIMetadataPin
	identitySetSHA256 string
	operations        []RegistryOperationMetadata
}

// NewVerifiedRegistryAPIMetadata adapts the shared, byte-verified API metadata
// loader into the exact operation join needed by the read model. The loader's
// unexported source/artifact markers prevent an arbitrary struct literal from
// being treated as verified. The underlying public metadata rows are also
// rechecked against the loader-built identity maps to reject post-load edits.
func NewVerifiedRegistryAPIMetadata(metadata RegistryAPIMetadata) (VerifiedRegistryAPIMetadata, error) {
	if metadata.verifiedArtifactSHA256 != acceptedRegistryAPIMetadataSHA256 ||
		metadata.verifiedSourceSHA256 == "" || metadata.verifiedSourceSHA256 != metadata.Source.SHA256 ||
		metadata.verifiedProjectionSHA256 == "" || metadataProjectionDigest(metadata) != metadata.verifiedProjectionSHA256 ||
		metadata.Source.Path != "data/data-go-kr.registry.json" || metadata.Scope.Provider != "data.go.kr" ||
		!metadata.Scope.SourceSnapshotComplete || metadata.Scope.RegistryWideMetadataComplete ||
		metadata.Counts.APIEntities != len(metadata.APIs) || metadata.Counts.APIOperations != len(metadata.operationByID) ||
		metadata.Counts.APIOperations == 0 || len(metadata.byID) != metadata.Counts.APIEntities || metadata.byID == nil || metadata.operationByID == nil {
		return VerifiedRegistryAPIMetadata{}, errRegistryAPIMetadataUnavailable
	}

	operations := make([]RegistryOperationMetadata, 0, metadata.Counts.APIOperations)
	seen := make(map[string]struct{}, metadata.Counts.APIOperations)
	for apiIndex, api := range metadata.APIs {
		if metadata.byID[api.RegistryAPIID] != apiIndex || api.Provider != "data.go.kr" {
			return VerifiedRegistryAPIMetadata{}, errRegistryAPIMetadataUnavailable
		}
		for _, operation := range api.Operations {
			verifiedOperation, ok := metadata.operationByID[operation.RegistryOperationID]
			if !ok || verifiedOperation != operation || operation.DatasetID != api.RegistryAPIID {
				return VerifiedRegistryAPIMetadata{}, errRegistryAPIMetadataUnavailable
			}
			if _, duplicate := seen[operation.RegistryOperationID]; duplicate {
				return VerifiedRegistryAPIMetadata{}, errRegistryAPIMetadataUnavailable
			}
			seen[operation.RegistryOperationID] = struct{}{}
			operations = append(operations, RegistryOperationMetadata{
				RegistryOperationID: operation.RegistryOperationID,
				APIID:               api.RegistryAPIID,
				OperationName:       operation.Name,
				OperationNameState:  operation.NameState,
				Title:               api.Title,
				TitleState:          api.TitleState,
				Organization:        api.Organization,
				OrganizationState:   api.OrganizationState,
				Purpose:             api.Description,
				PurposeState:        api.DescriptionState,
			})
		}
	}
	if len(operations) != metadata.Counts.APIOperations {
		return VerifiedRegistryAPIMetadata{}, errors.New("verified Registry API operation count changed")
	}
	identitySet := newOperationIdentitySetHash()
	identitySetIDs := make([]string, 0, len(operations))
	for _, operation := range operations {
		identitySetIDs = append(identitySetIDs, operation.RegistryOperationID)
	}
	sort.Strings(identitySetIDs)
	for _, operationID := range identitySetIDs {
		identitySet.add(operationID)
	}
	return VerifiedRegistryAPIMetadata{
		verified:          true,
		identitySetSHA256: identitySet.digest(),
		pin: RegistryAPIMetadataPin{
			RegistryRevision: metadata.RegistryRevision,
			SourceSHA256:     metadata.Source.SHA256,
			CatalogSHA256:    metadata.Catalog.SHA256,
			ArtifactSHA256:   metadata.verifiedArtifactSHA256,
			APIEntityCount:   metadata.Counts.APIEntities,
			OperationCount:   metadata.Counts.APIOperations,
		},
		operations: operations,
	}, nil
}

// cloneVerifiedRegistryAPIMetadata freezes the public metadata projection for
// handlers. It copies every exported slice and every derived index, then
// revalidates the loader's artifact/source/projection markers on that copy.
func cloneVerifiedRegistryAPIMetadata(metadata RegistryAPIMetadata) (RegistryAPIMetadata, error) {
	clone := metadata
	clone.APIs = make([]RegistryAPIMetadataAPI, len(metadata.APIs))
	if metadata.HealthCanaryLinks != nil {
		clone.HealthCanaryLinks = make([]RegistryHealthCanaryLink, len(metadata.HealthCanaryLinks))
		copy(clone.HealthCanaryLinks, metadata.HealthCanaryLinks)
	}
	clone.byID = make(map[string]int, len(metadata.APIs))
	clone.operationByID = make(map[string]RegistryAPIMetadataOperation, metadata.Counts.APIOperations)
	clone.canaryByOpID = make(map[string]RegistryHealthCanaryLink, len(metadata.HealthCanaryLinks))
	clone.canaryByHealthID = make(map[string]RegistryHealthCanaryLink, len(metadata.HealthCanaryLinks))
	if metadata.canaryDisplays != nil {
		clone.canaryDisplays = make([]RegistryCanaryDisplay, len(metadata.canaryDisplays))
		copy(clone.canaryDisplays, metadata.canaryDisplays)
	}
	clone.orderedAPIIndices = make([]int, len(metadata.APIs))
	clone.searchText = make([]string, len(metadata.APIs))

	for index, api := range metadata.APIs {
		if api.Operations != nil {
			operations := make([]RegistryAPIMetadataOperation, len(api.Operations))
			copy(operations, api.Operations)
			api.Operations = operations
		}
		clone.APIs[index] = api
		clone.byID[api.RegistryAPIID] = index
		parts := []string{api.Title, api.Organization, api.Description}
		for _, operation := range api.Operations {
			if operation.RegistryOperationID != "" {
				clone.operationByID[operation.RegistryOperationID] = operation
			}
			parts = append(parts, operation.Name)
		}
		clone.orderedAPIIndices[index] = index
		clone.searchText[index] = strings.ToLower(strings.Join(parts, "\n"))
	}
	for _, link := range clone.HealthCanaryLinks {
		clone.canaryByOpID[link.RegistryOperationID] = link
		clone.canaryByHealthID[link.HealthOperationID] = link
	}
	sort.SliceStable(clone.orderedAPIIndices, func(i, j int) bool {
		left := clone.APIs[clone.orderedAPIIndices[i]]
		right := clone.APIs[clone.orderedAPIIndices[j]]
		leftTitle, rightTitle := strings.ToLower(left.Title), strings.ToLower(right.Title)
		if leftTitle == rightTitle {
			return left.RegistryAPIID < right.RegistryAPIID
		}
		return leftTitle < rightTitle
	})
	if metadataProjectionDigest(clone) != clone.verifiedProjectionSHA256 {
		return RegistryAPIMetadata{}, errors.New("verified Registry API metadata projection changed while freezing")
	}
	if _, err := NewVerifiedRegistryAPIMetadata(clone); err != nil {
		return RegistryAPIMetadata{}, fmt.Errorf("verified Registry API metadata copy failed validation: %w", err)
	}
	return clone, nil
}

func metadataProjectionDigest(metadata RegistryAPIMetadata) string {
	raw, err := json.Marshal(metadata)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (plan PinnedOperationObservationPlan) bindsSourceArtifact(sourceID, provider, path, sourceSHA256 string) bool {
	if plan.state == nil || !plan.state.verified || sourceSHA256 == "" {
		return false
	}
	scope, ok := plan.state.byScope[sourceID]
	if !ok || scope.Provider != provider {
		return false
	}
	var found bool
	for _, source := range scope.SourceArtifacts {
		if source.Path != path {
			continue
		}
		if found || source.SHA256 != sourceSHA256 {
			return false
		}
		manifestArtifact, exists := plan.state.manifest[path]
		if !exists || manifestArtifact.Bytes != source.Bytes || manifestArtifact.SHA256 != source.SHA256 {
			return false
		}
		found = true
	}
	return found
}

func (plan PinnedOperationObservationPlan) bindsSourceInventory(sourceID, provider, path, sourceSHA256, identitySetSHA256 string) bool {
	if !sha256Pattern.MatchString(identitySetSHA256) || !plan.bindsSourceArtifact(sourceID, provider, path, sourceSHA256) {
		return false
	}
	scope, ok := plan.state.byScope[sourceID]
	return ok && scope.IdentitySetSHA256 == identitySetSHA256
}

func (metadata VerifiedRegistryAPIMetadata) sourceDigest() string {
	if !metadata.verified {
		return ""
	}
	return metadata.pin.SourceSHA256
}
