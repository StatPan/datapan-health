package health

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/StatPan/datapan-health/schemas"
)

// BoundedObservationRunSchemaVersion is a private Health producer contract.
// It records only digest-bound, redacted batch evidence; it is intentionally
// separate from the ten-canary public-status scheduler contract.
const BoundedObservationRunSchemaVersion = "datapan.health-bounded-observation-run.v1"

type BoundedObservationRun struct {
	SchemaVersion string                            `json:"schema_version"`
	Producer      ObservationRunProducer            `json:"producer"`
	Registry      ObservationRunRegistry            `json:"registry"`
	Run           ObservationRunScope               `json:"run"`
	Shards        []ObservationRunShard             `json:"shards"`
	Aggregate     ObservationRunAggregate           `json:"aggregate"`
	Redaction     ObservationRunRedaction           `json:"redaction"`
	Cleanup       *BoundedObservationCleanupReceipt `json:"cleanup,omitempty"`
}

type ObservationRunProducer struct {
	Repository string `json:"repository"`
	Revision   string `json:"revision"`
}

type ObservationRunRegistry struct {
	SourceRevision string `json:"source_revision"`
	SourceSHA256   string `json:"source_sha256"`
	ManifestSHA256 string `json:"manifest_sha256"`
	PolicySHA256   string `json:"policy_sha256"`
}

// ObservationRunScope records the former Registry runtime-freshness bounds:
// eight shards, up to 100 operations per shard, at most two in parallel, and
// a 1-30 second per-operation timeout.
type ObservationRunScope struct {
	RunID       string    `json:"run_id"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	ShardCount  int       `json:"shard_count"`
	BatchSize   int       `json:"batch_size"`
	MaxParallel int       `json:"max_parallel"`
	TimeoutMS   int64     `json:"timeout_ms"`
}

type ObservationRunShard struct {
	Index            int                      `json:"index"`
	ShardDigest      string                   `json:"shard_digest"`
	Scope            ObservationRunShardScope `json:"scope"`
	ManifestSHA256   string                   `json:"manifest_sha256"`
	PolicySHA256     string                   `json:"policy_sha256"`
	TerminalState    string                   `json:"terminal_state"`
	Completed        bool                     `json:"completed"`
	TimedOut         bool                     `json:"timed_out,omitempty"`
	ReceiptAvailable bool                     `json:"receipt_available"`
	ReceiptPath      string                   `json:"receipt_path,omitempty"`
	ObservedAt       time.Time                `json:"observed_at,omitempty"`
	ReceiptSHA256    string                   `json:"receipt_sha256,omitempty"`
	Redaction        ObservationRunRedaction  `json:"redaction"`
}

type ObservationRunShardScope struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

type ObservationRunAggregate struct {
	TerminalState string `json:"terminal_state"`
	Completeness  string `json:"completeness"`
	TimedOut      bool   `json:"timed_out"`
}

type ObservationRunRedaction struct {
	SecretValuesRemoved          bool `json:"secret_values_removed"`
	SecretHashesRemoved          bool `json:"secret_hashes_removed"`
	AuthorizationHeadersRemoved  bool `json:"authorization_headers_removed"`
	CredentialBearingURLsRemoved bool `json:"credential_bearing_urls_removed"`
	RawProviderTextRemoved       bool `json:"raw_provider_text_removed"`
	RawProviderURLsRemoved       bool `json:"raw_provider_urls_removed"`
	ResponseBodiesRemoved        bool `json:"response_bodies_removed"`
	ResponseRowsRemoved          bool `json:"response_rows_removed"`
	UserIdentityRemoved          bool `json:"user_identity_removed"`
}

// DecodeBoundedObservationRun rejects unsafe input before it can be logged or
// admitted. Errors are generic and never include input values.
func DecodeBoundedObservationRun(r io.Reader) (BoundedObservationRun, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64*1024+1))
	if err != nil {
		return BoundedObservationRun{}, err
	}
	if len(data) > 64*1024 {
		return BoundedObservationRun{}, errors.New("bounded observation run exceeds 64 KiB")
	}
	if err := schemas.ValidateHealthBoundedObservationRunV1(data); err != nil {
		return BoundedObservationRun{}, err
	}
	var receipt BoundedObservationRun
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return BoundedObservationRun{}, errors.New("invalid bounded observation run")
	}
	if err := ensureEOF(decoder); err != nil {
		return BoundedObservationRun{}, err
	}
	if err := receipt.Validate(); err != nil {
		return BoundedObservationRun{}, err
	}
	return receipt, nil
}

func (r BoundedObservationRun) Validate() error {
	if r.SchemaVersion != BoundedObservationRunSchemaVersion || r.Producer.Repository != "StatPan/datapan-health" || !commitPattern.MatchString(r.Producer.Revision) {
		return errors.New("bounded observation producer is invalid")
	}
	if !validObservationRunRegistry(r.Registry) {
		return errors.New("bounded observation registry binding is invalid")
	}
	if r.Run.ShardCount != 8 || r.Run.BatchSize < 1 || r.Run.BatchSize > 100 || r.Run.MaxParallel < 1 || r.Run.MaxParallel > 2 || r.Run.TimeoutMS < 1000 || r.Run.TimeoutMS > 20000 || r.Run.StartedAt.IsZero() || r.Run.CompletedAt.IsZero() || r.Run.CompletedAt.Before(r.Run.StartedAt) || r.Run.CompletedAt.Sub(r.Run.StartedAt) > r.Run.maximumDuration() {
		return errors.New("bounded observation scope is invalid")
	}
	if !validObservationRunRedaction(r.Redaction) {
		return errors.New("bounded observation redaction assertions are required")
	}
	if r.Cleanup != nil && !validBoundedObservationCleanupReceipt(*r.Cleanup) {
		return errors.New("bounded observation cleanup receipt is invalid")
	}
	if len(r.Shards) != r.Run.ShardCount {
		return errors.New("bounded observation shard coverage is incomplete")
	}
	seen := make(map[int]bool, r.Run.ShardCount)
	states := make([]string, 0, len(r.Shards))
	partial := false
	timedOut := false
	for _, shard := range r.Shards {
		if shard.Index < 0 || shard.Index >= r.Run.ShardCount || seen[shard.Index] || !sha256Pattern.MatchString(shard.ShardDigest) || shard.Scope.Provider != "data_go_kr" || shard.Scope.Subject != "runtime_freshness_rotating_shard" || shard.ManifestSHA256 != r.Registry.ManifestSHA256 || shard.PolicySHA256 != r.Registry.PolicySHA256 || !validObservationRunState(shard.TerminalState) || !validObservationRunRedaction(shard.Redaction) || shard.Redaction != r.Redaction {
			return errors.New("bounded observation shard is invalid")
		}
		seen[shard.Index] = true
		if shard.ReceiptAvailable {
			if !shard.Completed || shard.ObservedAt.IsZero() || shard.ObservedAt.Before(r.Run.StartedAt) || shard.ObservedAt.After(r.Run.CompletedAt) || shard.ReceiptPath != fmt.Sprintf("shards/%d/receipt.json", shard.Index) || !sha256Pattern.MatchString(shard.ReceiptSHA256) {
				return errors.New("bounded observation completed shard is invalid")
			}
		} else {
			if shard.Completed || (shard.TerminalState != "unknown" && shard.TerminalState != "failed") || !shard.ObservedAt.IsZero() || shard.ReceiptPath != "" || shard.ReceiptSHA256 != "" {
				return errors.New("bounded observation incomplete shard is invalid")
			}
			partial = true
		}
		if shard.TimedOut {
			if shard.TerminalState != "unknown" || shard.Completed {
				return errors.New("bounded observation timeout state is invalid")
			}
			timedOut = true
		}
		states = append(states, shard.TerminalState)
	}
	for index := 0; index < r.Run.ShardCount; index++ {
		if !seen[index] {
			return errors.New("bounded observation shard coverage is incomplete")
		}
	}
	completeness := "complete"
	if partial {
		completeness = "partial"
	}
	if r.Aggregate.Completeness != completeness || r.Aggregate.TerminalState != aggregateObservationRunState(states, partial) || r.Aggregate.TimedOut != timedOut {
		return errors.New("bounded observation aggregate is invalid")
	}
	return nil
}

func validObservationRunRegistry(registry ObservationRunRegistry) bool {
	return commitPattern.MatchString(registry.SourceRevision) && sha256Pattern.MatchString(registry.SourceSHA256) && sha256Pattern.MatchString(registry.ManifestSHA256) && sha256Pattern.MatchString(registry.PolicySHA256)
}

// ValidateAt adds the admission-safe temporal boundary that intentionally
// cannot be inferred from a receipt alone. Callers choose the reference clock
// and maximum accepted age; old or future evidence must not be admitted.
func (r BoundedObservationRun) ValidateAt(reference time.Time, maxAge time.Duration) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if reference.IsZero() || maxAge <= 0 {
		return errors.New("bounded observation freshness policy is invalid")
	}
	reference = reference.UTC()
	if r.Run.StartedAt.After(reference) || r.Run.CompletedAt.After(reference) {
		return errors.New("bounded observation evidence is from the future")
	}
	if reference.Sub(r.Run.CompletedAt) > maxAge {
		return errors.New("bounded observation evidence is stale")
	}
	return nil
}

func (r ObservationRunScope) maximumDuration() time.Duration {
	operations := int64(r.ShardCount) * int64(r.BatchSize)
	waves := (operations + int64(r.MaxParallel) - 1) / int64(r.MaxParallel)
	return time.Duration(waves*r.TimeoutMS) * time.Millisecond
}

func validObservationRunState(state string) bool {
	return state == "verified" || state == "failed" || state == "skipped" || state == "unknown"
}

func aggregateObservationRunState(states []string, partial bool) string {
	if partial {
		return "unknown"
	}
	for _, state := range states {
		if state == "unknown" {
			return "unknown"
		}
	}
	for _, state := range states {
		if state == "failed" {
			return "failed"
		}
	}
	for _, state := range states {
		if state == "skipped" {
			return "skipped"
		}
	}
	return "verified"
}

func validObservationRunRedaction(r ObservationRunRedaction) bool {
	return r.SecretValuesRemoved && r.SecretHashesRemoved && r.AuthorizationHeadersRemoved && r.CredentialBearingURLsRemoved && r.RawProviderTextRemoved && r.RawProviderURLsRemoved && r.ResponseBodiesRemoved && r.ResponseRowsRemoved && r.UserIdentityRemoved
}

func (r BoundedObservationRun) String() string {
	return fmt.Sprintf("bounded-observation-run(shards=%d,state=%s)", len(r.Shards), r.Aggregate.TerminalState)
}
