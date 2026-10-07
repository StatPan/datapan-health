package health

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

var errRegistryAPIMetadataUnavailable = errors.New("verified Registry API metadata unavailable")

// VerifiedRegistryAPIMetadata is the only metadata input accepted by the
// operation read model. Its marker is populated after LoadRegistryAPIMetadata
// verifies the artifact bytes and source pin; callers cannot set that marker
// outside this package.
type VerifiedRegistryAPIMetadata struct {
	verified              bool
	pin                   RegistryAPIMetadataPin
	identitySetSHA256     string
	operations            []RegistryOperationMetadata
	canaryLinksByHealthID map[string]RegistryHealthCanaryLink
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
		verified:              true,
		identitySetSHA256:     identitySet.digest(),
		canaryLinksByHealthID: cloneRegistryCanaryLinksByHealthID(metadata),
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

func cloneRegistryCanaryLinksByHealthID(metadata RegistryAPIMetadata) map[string]RegistryHealthCanaryLink {
	links := make(map[string]RegistryHealthCanaryLink, len(metadata.HealthCanaryLinks))
	for _, link := range metadata.HealthCanaryLinks {
		links[link.HealthOperationID] = link
	}
	return links
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
