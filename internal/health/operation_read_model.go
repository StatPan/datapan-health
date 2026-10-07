package health

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

const (
	RegistryOperationsPageSchemaVersion = "datapan.health-registry-operations-page.v2"
	operationReadModelMaximumPage       = 50
	operationReadModelMaximumAPIIDs     = 50
	operationReadModelMaximumQueryBytes = 128
	operationReadModelMaximumCursor     = 1024
)

var (
	ErrOperationReadModelUnavailable             = errors.New("operation read model unavailable")
	ErrOperationReadModelQuery                   = errors.New("operation read model query is invalid")
	operationReadModelAPIIDPattern               = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	operationReadModelRegistryOperationIDPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	operationReadModelCursorVersion              = "datapan.health-registry-operations-cursor.v2"
	operationReadModelDomainPattern              = regexp.MustCompile(`(?i)(^|[^[:alnum:]_-])([a-z0-9-]+\.)+[a-z]{2,}([^[:alnum:]_-]|$)`)
	operationReadModelIPPattern                  = regexp.MustCompile(`\b(10|127|192\.168|172\.(1[6-9]|2[0-9]|3[01]))(\.\d{1,3}){2}\b`)
	operationReadModelSecretPattern              = regexp.MustCompile(`(?i)(\b(api[_ -]?key|service[_ -]?key|authorization|bearer|password|token|secret|client[_ -]?secret)\b\s*[:=]|[?&][a-z0-9_.-]+=)`)
	operationReadModelPathPattern                = regexp.MustCompile(`(^|[\s:])/([a-z0-9._~%-]+/)*[a-z0-9._~%-]*`)
)

// RegistryOperationMetadata contains only fields already projected and
// classified by the pinned Registry metadata artifact. A present value is
// independently rechecked before it enters a public page.
type RegistryOperationMetadata struct {
	RegistryOperationID string `json:"registry_operation_id"`
	APIID               string `json:"registry_api_id"`
	OperationName       string `json:"name"`
	OperationNameState  string `json:"name_state"`
	Title               string `json:"title"`
	TitleState          string `json:"title_state"`
	Organization        string `json:"organization"`
	OrganizationState   string `json:"organization_state"`
	Purpose             string `json:"description"`
	PurposeState        string `json:"description_state"`
}

type RegistryAPIMetadataPin struct {
	RegistryRevision string `json:"registry_revision"`
	SourceSHA256     string `json:"source_sha256"`
	CatalogSHA256    string `json:"catalog_sha256"`
	ArtifactSHA256   string `json:"artifact_sha256"`
	APIEntityCount   int    `json:"api_entity_count"`
	OperationCount   int    `json:"operation_count"`
}

// OperationReadModelAttempt is the only observation input accepted by the
// read model. It intentionally excludes receipts, errors, endpoints, quota
// scopes, credentials, and response data.
type OperationReadModelAttempt struct {
	SourceID            string
	OperationID         string
	AttemptState        string // claimed, request_started, observed, failed, unknown
	RequestStarted      *bool
	EverRequestStarted  bool
	ResultState         string // healthy, unhealthy, indeterminate
	ResultCategory      string
	ProviderObservedAt  time.Time
	HealthReceivedAt    time.Time
	GatusDeliveryState  string // not_ready, pending, acknowledged, readback_verified
	GatusAcknowledgedAt time.Time
	GatusReadbackAt     time.Time
	GatusObservedState  string
}

type OperationReadModelIdentityCounts struct {
	Known                      int `json:"known"`
	Admitted                   int `json:"admitted"`
	Claimed                    int `json:"claimed"`
	Attempted                  int `json:"attempted"`
	Persisted                  int `json:"persisted"`
	InventoryUnknownScopes     int `json:"inventory_unknown_scopes"`
	InventoryUnknownOperations int `json:"inventory_unknown_operations"`
	Acknowledged               int `json:"acknowledged"`
	ReadbackVerified           int `json:"readback_verified"`
	DeliveryPending            int `json:"delivery_pending"`
	Missing                    int `json:"missing"`
	Late                       int `json:"late"`
}

type OperationAPIProgress struct {
	APIID              string         `json:"api_id"`
	TotalFunctions     int            `json:"total_functions"`
	ConfiguredAdmitted int            `json:"configured_admitted"`
	Claimed            int            `json:"claimed"`
	Attempted          int            `json:"attempted"`
	CurrentPass        int            `json:"current_pass"`
	CurrentFail        int            `json:"current_fail"`
	Pending            int            `json:"pending"`
	Stale              int            `json:"stale"`
	Unobserved         int            `json:"unobserved"`
	DeliveryPending    int            `json:"delivery_pending"`
	ReadbackVerified   int            `json:"readback_verified"`
	MissingReasons     map[string]int `json:"missing_reasons"`
	CoverageState      string         `json:"coverage_state"`
}

type OperationPageQuery struct {
	APIID  string
	Query  string
	Cursor string
	Limit  int
}

type OperationReadModelPage struct {
	SchemaVersion            string                           `json:"schema_version"`
	GeneratedAt              time.Time                        `json:"generated_at"`
	ReadModelGeneratedAt     time.Time                        `json:"read_model_generated_at"`
	RegistryRevision         string                           `json:"registry_revision"`
	ReleaseManifestSHA256    string                           `json:"release_manifest_sha256"`
	IndexSHA256              string                           `json:"index_sha256"`
	PlanSchemaSHA256         string                           `json:"plan_schema_sha256"`
	PageSchemaSHA256         string                           `json:"page_schema_sha256"`
	MetadataRegistryRevision string                           `json:"metadata_registry_revision"`
	MetadataSourceSHA256     string                           `json:"metadata_source_sha256"`
	MetadataCatalogSHA256    string                           `json:"metadata_catalog_sha256"`
	MetadataArtifactSHA256   string                           `json:"metadata_artifact_sha256"`
	MetadataAPIEntityCount   int                              `json:"metadata_api_entity_count"`
	MetadataOperationCount   int                              `json:"metadata_operation_count"`
	IdentityCounts           OperationReadModelIdentityCounts `json:"identity_counts"`
	APIID                    string                           `json:"api_id,omitempty"`
	Query                    string                           `json:"query,omitempty"`
	Limit                    int                              `json:"limit"`
	TotalAfterSearch         int                              `json:"total_after_search"`
	NextCursor               string                           `json:"next_cursor,omitempty"`
	Operations               []OperationReadModelRow          `json:"operations"`
}

type OperationReadModelRow struct {
	SourceID                 string     `json:"source_id"`
	RegistryOperationID      string     `json:"registry_operation_id"`
	APIID                    *string    `json:"api_id"`
	Provider                 string     `json:"provider"`
	AdapterID                string     `json:"adapter_id"`
	Protocol                 string     `json:"protocol"`
	OperationName            string     `json:"operation_name,omitempty"`
	OperationNameState       string     `json:"operation_name_state"`
	Title                    string     `json:"title,omitempty"`
	TitleState               string     `json:"title_state"`
	Organization             string     `json:"organization,omitempty"`
	OrganizationState        string     `json:"organization_state"`
	Purpose                  string     `json:"purpose,omitempty"`
	PurposeState             string     `json:"purpose_state"`
	RequestPlanState         string     `json:"request_plan_state"`
	RuntimeBindingState      string     `json:"runtime_binding_state"`
	AdmissionState           string     `json:"admission_state"`
	MissingReason            string     `json:"missing_reason,omitempty"`
	ObservationPeriodSeconds *int64     `json:"observation_period_seconds"`
	NextDueAt                *time.Time `json:"next_due_at"`
	AttemptState             string     `json:"attempt_state"`
	RequestStarted           *bool      `json:"request_started"`
	Attempted                bool       `json:"attempted"`
	ObservationState         string     `json:"observation_state"`
	ResultCategory           string     `json:"result_category,omitempty"`
	ProviderObservedAt       *time.Time `json:"provider_observed_at"`
	HealthReceivedAt         *time.Time `json:"health_received_at"`
	GatusDeliveryState       string     `json:"gatus_delivery_state"`
	GatusAcknowledgedAt      *time.Time `json:"gatus_acknowledged_at"`
	GatusReadbackAt          *time.Time `json:"gatus_readback_at"`
	GatusObservedState       string     `json:"gatus_observed_state,omitempty"`
}

type operationReadModelCursor struct {
	Version     string `json:"v"`
	IndexSHA256 string `json:"i"`
	APIID       string `json:"a"`
	Query       string `json:"q"`
	SourceID    string `json:"s"`
	OperationID string `json:"o"`
}

// OperationReadModel is an immutable plan projection plus an atomically
// replaceable, bounded latest-attempt cache. Public reads never touch the
// durable state directory or Gatus.
type OperationReadModel struct {
	mu                     sync.RWMutex
	registryRevision       string
	manifestSHA            string
	indexSHA               string
	planSchemaSHA          string
	pageSchemaSHA          string
	metadataPin            RegistryAPIMetadataPin
	inventoryUnknownScopes int
	generatedAt            time.Time
	rows                   []OperationReadModelRow
	byIdentity             map[string]int
	byAPI                  map[string][]int
}

// NewOperationReadModel verifies the full pinned plan once, joins metadata by
// exact source, Registry operation ID, and API ID, and builds an in-memory index. A caller
// refreshes attempts from the durable store at startup and applies subsequent
// validated updates with ApplyAttempt.
func NewOperationReadModel(plan PinnedOperationObservationPlan, metadataPin RegistryAPIMetadataPin, metadata []RegistryOperationMetadata, attempts []OperationReadModelAttempt, generatedAt time.Time) (*OperationReadModel, error) {
	if !plan.state.verified || generatedAt.IsZero() || !validRegistryAPIMetadataPin(metadataPin) || len(metadata) != metadataPin.OperationCount {
		return nil, ErrOperationReadModelUnavailable
	}
	metadataByOperationID := make(map[string]RegistryOperationMetadata, len(metadata))
	for _, item := range metadata {
		if !operationReadModelAPIIDPattern.MatchString(item.APIID) || !operationReadModelRegistryOperationIDPattern.MatchString(item.RegistryOperationID) {
			return nil, ErrOperationReadModelUnavailable
		}
		if _, exists := metadataByOperationID[item.RegistryOperationID]; exists {
			return nil, ErrOperationReadModelUnavailable
		}
		metadataByOperationID[item.RegistryOperationID] = sanitizeRegistryOperationMetadata(item)
	}
	model := &OperationReadModel{
		registryRevision:       plan.RegistryRevision(),
		manifestSHA:            plan.binding.ReleaseManifestSHA256,
		indexSHA:               plan.IndexSHA256(),
		planSchemaSHA:          plan.binding.SchemaSHA256,
		pageSchemaSHA:          schemas.HealthRegistryOperationsPageV2SchemaSHA256(),
		metadataPin:            metadataPin,
		inventoryUnknownScopes: plan.Counts().InventoryUnknownScopes,
		generatedAt:            generatedAt.UTC(),
		byIdentity:             make(map[string]int),
		byAPI:                  make(map[string][]int),
	}
	joinedMetadata := make(map[string]struct{}, len(metadataByOperationID))
	for shardIndex := 0; shardIndex < plan.ShardCount(); shardIndex++ {
		records, err := plan.ReadShard(shardIndex)
		if err != nil {
			return nil, ErrOperationReadModelUnavailable
		}
		for _, record := range records {
			var metadataForRecord *RegistryOperationMetadata
			if record.SourceID == "data_go_kr" {
				item, ok := metadataByOperationID[record.OperationID]
				if !ok || item.APIID != record.DatasetID {
					return nil, ErrOperationReadModelUnavailable
				}
				metadataForRecord = &item
				joinedMetadata[record.OperationID] = struct{}{}
			}
			row := operationReadModelRow(record, metadataForRecord)
			key := operationReadModelIdentityKey(row.SourceID, row.RegistryOperationID)
			if _, exists := model.byIdentity[key]; exists {
				return nil, ErrOperationReadModelUnavailable
			}
			model.byIdentity[key] = len(model.rows)
			model.rows = append(model.rows, row)
		}
	}
	if len(joinedMetadata) != len(metadataByOperationID) {
		return nil, ErrOperationReadModelUnavailable
	}
	sort.Slice(model.rows, func(i, j int) bool {
		if model.rows[i].SourceID != model.rows[j].SourceID {
			return model.rows[i].SourceID < model.rows[j].SourceID
		}
		return model.rows[i].RegistryOperationID < model.rows[j].RegistryOperationID
	})
	model.reindex()
	for _, attempt := range attempts {
		if err := model.ApplyAttempt(attempt); err != nil {
			return nil, ErrOperationReadModelUnavailable
		}
	}
	return model, nil
}

// ApplyAttempt replaces the cached latest safe state for one exact Registry
// identity. It is called after the durable attempt/outbox transaction commits.
func (model *OperationReadModel) ApplyAttempt(attempt OperationReadModelAttempt) error {
	if model == nil || !validOperationReadModelAttempt(attempt) {
		return ErrOperationReadModelUnavailable
	}
	model.mu.Lock()
	defer model.mu.Unlock()
	index, ok := model.byIdentity[operationReadModelIdentityKey(attempt.SourceID, attempt.OperationID)]
	if !ok {
		return ErrOperationReadModelUnavailable
	}
	row := model.rows[index]
	applyOperationReadModelAttempt(&row, attempt)
	model.rows[index] = row
	return nil
}

// LookupAPIProgress returns exact per-API identity-set rollups. It accepts at
// most 50 unique IDs and reads only the already-built in-memory index.
func (model *OperationReadModel) LookupAPIProgress(apiIDs []string, at time.Time) ([]OperationAPIProgress, error) {
	if model == nil || len(apiIDs) > operationReadModelMaximumAPIIDs || at.IsZero() {
		return nil, ErrOperationReadModelQuery
	}
	model.mu.RLock()
	defer model.mu.RUnlock()
	seen := make(map[string]struct{}, len(apiIDs))
	results := make([]OperationAPIProgress, 0, len(apiIDs))
	for _, apiID := range apiIDs {
		if !operationReadModelAPIIDPattern.MatchString(apiID) {
			return nil, ErrOperationReadModelQuery
		}
		if _, ok := seen[apiID]; ok {
			return nil, ErrOperationReadModelQuery
		}
		seen[apiID] = struct{}{}
		progress := OperationAPIProgress{APIID: apiID, MissingReasons: map[string]int{}}
		for _, index := range model.byAPI[apiID] {
			row := model.rows[index]
			refreshOperationReadModelFreshness(&row, at)
			progress.TotalFunctions++
			if row.AdmissionState == "admitted" && row.RuntimeBindingState == "bound" && row.RequestPlanState == "complete" {
				progress.ConfiguredAdmitted++
			}
			switch row.AttemptState {
			case "claimed":
				progress.Claimed++
				progress.Pending++
			}
			if row.Attempted {
				progress.Attempted++
			}
			switch row.ObservationState {
			case "current_pass":
				progress.CurrentPass++
			case "current_fail":
				progress.CurrentFail++
			case "stale":
				progress.Stale++
			case "unobserved":
				progress.Unobserved++
				if row.MissingReason != "" {
					progress.MissingReasons[row.MissingReason]++
				}
			}
			if row.GatusDeliveryState == "pending" {
				progress.DeliveryPending++
			}
			if row.GatusDeliveryState == "readback_verified" {
				progress.ReadbackVerified++
			}
		}
		results = append(results, progress)
		if progress.TotalFunctions == 0 {
			results[len(results)-1].CoverageState = "no_registered_operations"
		} else if progress.CurrentPass+progress.CurrentFail == progress.TotalFunctions {
			results[len(results)-1].CoverageState = "current"
		} else if progress.CurrentPass+progress.CurrentFail > 0 {
			results[len(results)-1].CoverageState = "partial"
		} else if progress.Stale > 0 {
			results[len(results)-1].CoverageState = "stale"
		} else {
			results[len(results)-1].CoverageState = "unobserved"
		}
	}
	return results, nil
}

// PageOperations returns one deterministic page, at most 50 records. Cursors
// are bound to the immutable index digest, exact API filter, and normalized
// query; no endpoint/request values are searchable or returned.
func (model *OperationReadModel) PageOperations(query OperationPageQuery, at time.Time) (OperationReadModelPage, error) {
	if model == nil || at.IsZero() || query.Limit < 1 || query.Limit > operationReadModelMaximumPage || query.APIID != "" && !operationReadModelAPIIDPattern.MatchString(query.APIID) || len(query.Query) > operationReadModelMaximumQueryBytes || len(query.Cursor) > operationReadModelMaximumCursor {
		return OperationReadModelPage{}, ErrOperationReadModelQuery
	}
	model.mu.RLock()
	defer model.mu.RUnlock()
	needle := normalizeOperationReadModelQuery(query.Query)
	if strings.ContainsAny(needle, "\r\n\x00") || needle != "" && safeOperationReadText(needle) == "" {
		return OperationReadModelPage{}, ErrOperationReadModelQuery
	}
	var after operationReadModelCursor
	if query.Cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(query.Cursor)
		if err != nil || len(decoded) > 768 || json.Unmarshal(decoded, &after) != nil || after.Version != operationReadModelCursorVersion || after.IndexSHA256 != model.indexSHA || after.APIID != query.APIID || after.Query != needle || after.SourceID == "" || after.OperationID == "" {
			return OperationReadModelPage{}, ErrOperationReadModelQuery
		}
	}
	matching := make([]int, 0, len(model.rows))
	for index, row := range model.rows {
		if query.APIID != "" && (row.APIID == nil || *row.APIID != query.APIID) {
			continue
		}
		if needle != "" && !operationReadModelMatches(row, needle) {
			continue
		}
		matching = append(matching, index)
	}
	start := 0
	if query.Cursor != "" {
		start = sort.Search(len(matching), func(position int) bool {
			row := model.rows[matching[position]]
			return row.SourceID > after.SourceID || row.SourceID == after.SourceID && row.RegistryOperationID > after.OperationID
		})
	}
	end := start + query.Limit
	if end > len(matching) {
		end = len(matching)
	}
	page := OperationReadModelPage{
		SchemaVersion:            RegistryOperationsPageSchemaVersion,
		GeneratedAt:              at.UTC(),
		ReadModelGeneratedAt:     model.generatedAt,
		RegistryRevision:         model.registryRevision,
		ReleaseManifestSHA256:    model.manifestSHA,
		IndexSHA256:              model.indexSHA,
		PlanSchemaSHA256:         model.planSchemaSHA,
		PageSchemaSHA256:         model.pageSchemaSHA,
		MetadataRegistryRevision: model.metadataPin.RegistryRevision,
		MetadataSourceSHA256:     model.metadataPin.SourceSHA256,
		MetadataCatalogSHA256:    model.metadataPin.CatalogSHA256,
		MetadataArtifactSHA256:   model.metadataPin.ArtifactSHA256,
		MetadataAPIEntityCount:   model.metadataPin.APIEntityCount,
		MetadataOperationCount:   model.metadataPin.OperationCount,
		IdentityCounts:           model.identityCounts(at),
		APIID:                    query.APIID,
		Query:                    needle,
		Limit:                    query.Limit,
		TotalAfterSearch:         len(matching),
		Operations:               make([]OperationReadModelRow, 0, end-start),
	}
	for _, index := range matching[start:end] {
		row := model.rows[index]
		refreshOperationReadModelFreshness(&row, at)
		page.Operations = append(page.Operations, row)
	}
	if end < len(matching) && end > start {
		last := model.rows[matching[end-1]]
		raw, err := json.Marshal(operationReadModelCursor{Version: operationReadModelCursorVersion, IndexSHA256: model.indexSHA, APIID: query.APIID, Query: needle, SourceID: last.SourceID, OperationID: last.RegistryOperationID})
		if err != nil {
			return OperationReadModelPage{}, ErrOperationReadModelUnavailable
		}
		page.NextCursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	return page, nil
}

func (model *OperationReadModel) identityCounts(at time.Time) OperationReadModelIdentityCounts {
	var counts OperationReadModelIdentityCounts
	counts.InventoryUnknownScopes = model.inventoryUnknownScopes
	unknownScopes := make(map[string]struct{})
	for _, original := range model.rows {
		row := original
		refreshOperationReadModelFreshness(&row, at)
		counts.Known++
		if row.MissingReason == "inventory_unknown" {
			counts.InventoryUnknownOperations++
			unknownScopes[row.SourceID] = struct{}{}
		}
		if row.AdmissionState == "admitted" && row.RuntimeBindingState == "bound" && row.RequestPlanState == "complete" {
			counts.Admitted++
		}
		switch row.AttemptState {
		case "claimed":
			counts.Claimed++
		}
		if row.Attempted {
			counts.Attempted++
		}
		if row.HealthReceivedAt != nil {
			counts.Persisted++
		}
		if row.GatusDeliveryState == "acknowledged" || row.GatusDeliveryState == "readback_verified" {
			counts.Acknowledged++
		}
		if row.GatusDeliveryState == "readback_verified" {
			counts.ReadbackVerified++
		}
		if row.GatusDeliveryState == "pending" {
			counts.DeliveryPending++
		}
		if row.ObservationState == "stale" || row.ObservationState == "unobserved" {
			counts.Missing++
		}
		if row.NextDueAt != nil && !at.Before(*row.NextDueAt) && row.ObservationState != "current_pass" && row.ObservationState != "current_fail" {
			counts.Late++
		}
	}
	if len(unknownScopes) > counts.InventoryUnknownScopes {
		counts.InventoryUnknownScopes = len(unknownScopes)
	}
	return counts
}

func operationReadModelRow(record OperationObservationPlanRecord, metadata *RegistryOperationMetadata) OperationReadModelRow {
	row := OperationReadModelRow{
		SourceID: record.SourceID, RegistryOperationID: record.OperationID, Provider: safePlanLabel(record.Provider), AdapterID: safePlanLabel(record.AdapterID), Protocol: safePlanLabel(record.Protocol),
		OperationName: safeOperationReadText(record.OperationName), OperationNameState: "missing", TitleState: "missing", OrganizationState: "missing", PurposeState: "missing",
		RequestPlanState: record.RequestPlanStatus, RuntimeBindingState: record.RuntimeBindingStatus, AdmissionState: record.AdmissionStatus,
		AttemptState: "none", ObservationState: "unobserved", GatusDeliveryState: "not_ready",
	}
	if row.OperationName != "" {
		row.OperationNameState = "present"
	} else {
		row.OperationNameState = "missing"
	}
	if metadata != nil && record.SourceID == "data_go_kr" && record.OperationID == metadata.RegistryOperationID && record.DatasetID == metadata.APIID && operationReadModelAPIIDPattern.MatchString(metadata.APIID) {
		apiID := metadata.APIID
		row.APIID = &apiID
		row.OperationName, row.OperationNameState = sanitizeClassifiedMetadata(metadata.OperationName, metadata.OperationNameState)
		row.Title, row.TitleState = sanitizeClassifiedMetadata(metadata.Title, metadata.TitleState)
		row.Organization, row.OrganizationState = sanitizeClassifiedMetadata(metadata.Organization, metadata.OrganizationState)
		row.Purpose, row.PurposeState = sanitizeClassifiedMetadata(metadata.Purpose, metadata.PurposeState)
	}
	row.MissingReason = operationMissingReason(record)
	if record.ObservationPeriod > 0 && record.RuntimeBindingStatus == "bound" {
		seconds := int64(record.ObservationPeriod / time.Second)
		row.ObservationPeriodSeconds = &seconds
	}
	return row
}

func sanitizeRegistryOperationMetadata(item RegistryOperationMetadata) RegistryOperationMetadata {
	item.Title, item.TitleState = sanitizeClassifiedMetadata(item.Title, item.TitleState)
	item.Organization, item.OrganizationState = sanitizeClassifiedMetadata(item.Organization, item.OrganizationState)
	item.Purpose, item.PurposeState = sanitizeClassifiedMetadata(item.Purpose, item.PurposeState)
	return item
}

func sanitizeClassifiedMetadata(value, state string) (string, string) {
	switch state {
	case "present", "sanitized":
		// Re-check the source projection despite its own pinned sanitizer.
	case "blank", "missing":
		return "", state
	case "unsafe", "redacted_unsafe":
		return "", "unsafe"
	case "invalid", "invalid_source":
		return "", "invalid"
	default:
		return "", "invalid"
	}
	safe := safeOperationReadText(value)
	if safe == "" {
		return "", "unsafe"
	}
	return safe, "present"
}

func safeOperationReadText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 512 || strings.ContainsAny(value, "\r\n\x00<>`?=#\\") {
		return ""
	}
	lower := strings.ToLower(value)
	if operationReadModelDomainPattern.MatchString(value) || operationReadModelIPPattern.MatchString(value) || operationReadModelSecretPattern.MatchString(value) || operationReadModelPathPattern.MatchString(value) {
		return ""
	}
	for _, unsafe := range []string{"http://", "https://", "www.", "authorization:", "bearer ", "servicekey", "service_key", "api_key", "apikey", "password", "token", "secret", "localhost", ".internal", ".local"} {
		if strings.Contains(lower, unsafe) {
			return ""
		}
	}
	return value
}

func safePlanLabel(value string) string {
	if value == "" || len(value) > 128 || !operationReadModelAPIIDPattern.MatchString(value) {
		return "unknown"
	}
	return value
}

func operationMissingReason(record OperationObservationPlanRecord) string {
	switch {
	case record.InventoryUnknown:
		return "inventory_unknown"
	case record.TestOnly:
		return "test_only"
	case record.RequestPlanStatus != "complete":
		return "request_plan_incomplete"
	case record.RuntimeBindingStatus != "bound":
		return "runtime_unbound"
	case record.AdmissionStatus != "admitted":
		return "not_admitted"
	case !record.ExecutionEligible:
		return "unsupported_contract"
	default:
		return "no_validated_observation"
	}
}

func validOperationReadModelAttempt(attempt OperationReadModelAttempt) bool {
	if !operationSourceIDPattern.MatchString(attempt.SourceID) || attempt.OperationID == "" || len(attempt.OperationID) > 256 || !validOperationReadModelAttemptState(attempt.AttemptState) || !validOperationReadModelDeliveryState(attempt.GatusDeliveryState) {
		return false
	}
	if attempt.RequestStarted != nil && attempt.AttemptState != "request_started" && attempt.AttemptState != "observed" && attempt.AttemptState != "failed" && attempt.AttemptState != "unknown" {
		return false
	}
	if attempt.AttemptState == "observed" {
		return attempt.RequestStarted != nil && *attempt.RequestStarted && validOperationReadModelResultState(attempt.ResultState) && attempt.ProviderObservedAt.IsZero() == false && attempt.HealthReceivedAt.IsZero() == false && !attempt.ProviderObservedAt.After(attempt.HealthReceivedAt) && validGatusReadback(attempt)
	}
	if !attempt.ProviderObservedAt.IsZero() || !attempt.HealthReceivedAt.IsZero() {
		return false
	}
	if attempt.GatusDeliveryState == "acknowledged" || attempt.GatusDeliveryState == "readback_verified" {
		return false
	}
	return true
}

func validGatusReadback(attempt OperationReadModelAttempt) bool {
	switch attempt.GatusDeliveryState {
	case "not_ready", "pending":
		return attempt.GatusAcknowledgedAt.IsZero() && attempt.GatusReadbackAt.IsZero()
	case "acknowledged":
		return !attempt.GatusAcknowledgedAt.IsZero() && attempt.GatusReadbackAt.IsZero() && validGatusResultState(attempt.GatusObservedState)
	case "readback_verified":
		return !attempt.GatusAcknowledgedAt.IsZero() && !attempt.GatusReadbackAt.IsZero() && !attempt.GatusReadbackAt.Before(attempt.GatusAcknowledgedAt) && validGatusResultState(attempt.GatusObservedState)
	default:
		return false
	}
}

func applyOperationReadModelAttempt(row *OperationReadModelRow, attempt OperationReadModelAttempt) {
	row.AttemptState = attempt.AttemptState
	row.RequestStarted = cloneBool(attempt.RequestStarted)
	row.Attempted = row.Attempted || attempt.EverRequestStarted || attempt.RequestStarted != nil && *attempt.RequestStarted
	if attempt.AttemptState == "observed" {
		row.ResultCategory = attempt.ResultCategory
		row.ProviderObservedAt = cloneTime(attempt.ProviderObservedAt)
		row.HealthReceivedAt = cloneTime(attempt.HealthReceivedAt)
		row.GatusDeliveryState = attempt.GatusDeliveryState
		row.GatusAcknowledgedAt = cloneTime(attempt.GatusAcknowledgedAt)
		row.GatusReadbackAt = cloneTime(attempt.GatusReadbackAt)
		row.GatusObservedState = safePlanLabel(attempt.GatusObservedState)
	}
}

func refreshOperationReadModelFreshness(row *OperationReadModelRow, at time.Time) {
	row.NextDueAt = nil
	row.ObservationState = "unobserved"
	if row.ProviderObservedAt != nil && row.ObservationPeriodSeconds != nil {
		due := row.ProviderObservedAt.Add(time.Duration(*row.ObservationPeriodSeconds) * time.Second)
		row.NextDueAt = &due
		if at.Before(due) {
			if row.ResultCategory == "healthy" {
				row.ObservationState = "current_pass"
			} else {
				row.ObservationState = "current_fail"
			}
		} else {
			row.ObservationState = "stale"
		}
	}
}

func operationReadModelMatches(row OperationReadModelRow, needle string) bool {
	values := []string{row.SourceID, row.RegistryOperationID, row.OperationName, row.Title, row.Organization, row.Purpose}
	if row.APIID != nil {
		values = append(values, *row.APIID)
	}
	for _, value := range values {
		if strings.Contains(normalizeOperationReadModelQuery(value), needle) {
			return true
		}
	}
	return false
}

func normalizeOperationReadModelQuery(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func (model *OperationReadModel) reindex() {
	model.byIdentity = make(map[string]int, len(model.rows))
	model.byAPI = make(map[string][]int)
	for index, row := range model.rows {
		model.byIdentity[operationReadModelIdentityKey(row.SourceID, row.RegistryOperationID)] = index
		if row.APIID != nil {
			model.byAPI[*row.APIID] = append(model.byAPI[*row.APIID], index)
		}
	}
}

func operationReadModelIdentityKey(sourceID, operationID string) string {
	return sourceID + "\x00" + operationID
}
func validOperationReadModelAttemptState(value string) bool {
	return value == "claimed" || value == "request_started" || value == "observed" || value == "failed" || value == "unknown"
}

func validRegistryAPIMetadataPin(pin RegistryAPIMetadataPin) bool {
	return commitPattern.MatchString(pin.RegistryRevision) && sha256Pattern.MatchString(pin.SourceSHA256) && sha256Pattern.MatchString(pin.CatalogSHA256) && sha256Pattern.MatchString(pin.ArtifactSHA256) && pin.APIEntityCount >= 0 && pin.APIEntityCount <= 20_000 && pin.OperationCount >= 0 && pin.OperationCount <= 50_000
}
func validOperationReadModelDeliveryState(value string) bool {
	return value == "not_ready" || value == "pending" || value == "acknowledged" || value == "readback_verified"
}
func validOperationReadModelResultState(value string) bool {
	return value == "healthy" || value == "unhealthy" || value == "indeterminate"
}
func cloneBool(value *bool) *bool {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
func cloneTime(value time.Time) *time.Time {
	if value.IsZero() {
		return nil
	}
	copy := value.UTC()
	return &copy
}

// CursorDigest is exported for contract tests and clients which need to
// confirm that a cursor is tied to this immutable index without decoding it.
func (model *OperationReadModel) CursorDigest() string {
	if model == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(model.indexSHA))
	return hex.EncodeToString(sum[:])
}

func (row OperationReadModelRow) ValidatePublicProjection() error {
	if row.SourceID == "" || row.RegistryOperationID == "" || row.TitleState == "present" && safeOperationReadText(row.Title) == "" || row.OrganizationState == "present" && safeOperationReadText(row.Organization) == "" || row.PurposeState == "present" && safeOperationReadText(row.Purpose) == "" || row.APIID != nil && !operationReadModelAPIIDPattern.MatchString(*row.APIID) {
		return fmt.Errorf("%w: unsafe projected operation metadata", ErrOperationReadModelUnavailable)
	}
	return nil
}
