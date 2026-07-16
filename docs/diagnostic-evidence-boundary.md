# M003 diagnostic evidence boundary

Status: Health consumer requirements and gap audit for issue #17. This is not a
cross-repository schema decision.

The product-level source is Datapan team mission M003 and its proposed
`datapan.diagnosis.v1` meaning. This document tests whether Health can supply
that meaning from public observations; it does not replace the team mission or
the Registry-owned serialization and compatibility review.

## Decision

Datapan Health can report that a reviewed public operation was healthy,
unhealthy, skipped, or indeterminate and retain a useful redacted observation.
It cannot currently explain every failure as a user problem, approval delay,
bad input, exhausted quota, provider outage, or data-contract failure.

The distinction matters because an HTTP status is an observation, not a root
cause. In particular, one `401` or `403` does not prove whether a credential is
invalid, the operation lacks service-specific approval, a newly granted
approval has not propagated, or the provider has applied another access
policy. Health must preserve the evidence and report an unknown cause until an
authoritative signal or a sufficiently strong correlation rule exists.

The future common diagnostic contract therefore needs to keep three things
separate:

1. objective observations from one execution;
2. authority-bound policy or approval facts;
3. a versioned diagnosis with an explicit confidence and evidence list.

Health is a consumer and correlator of that contract. Datapan CLI owns the
probe execution and local credential/input preflight. Datapan Registry owns
stable operation identity and reviewed provider policy. Neither a Health
incident nor a Registry policy can manufacture a portal approval fact.

## Current evidence surfaces

| Surface | Evidence available now | Boundary |
| --- | --- | --- |
| Pinned receipt | Operation/Registry identity, execution attempted and budget, latency, HTTP/provider/semantic/body observations, data/schema/freshness states, outcome/category/retryability/reason, redaction assertions | `datapan.health-probe.v1` categories are coarse and contain no evidence-source, scope, confidence, approval state, or correlation identity |
| Runner adapter | Strict schema and nested-field validation; exact configured-canary resolution | Gatus receives only `outcome`, `category`, and latency; detailed evidence stays private |
| Local receipt sink | Complete already-redacted v1 receipt, append-only JSONL with mode `0600` | No application retention limit, compaction, deletion, or schema-migration mechanism is implemented here |
| Gatus/PostgreSQL | Per-canary result, enum-only error, heartbeat, two-failure alert threshold, seven-day bounded result history | Two failures create an incident signal, not a root-cause verdict; PostgreSQL retention/backup is infra-owned |
| Public Parquet archive | Public service/time/Registry revision, outcome/category, latency, data/schema/freshness state, schedule tier; non-healthy observation rows and daily rollups | It intentionally excludes reason/provider/operation/user detail and cannot reconstruct a more precise diagnosis |
| Provider notice | No notice feed, notice identity, effective window, affected scope, or incident link exists | Health cannot currently correlate a provider/portal notice with a probe incident |

The implementation evidence is in:

- `schemas/datapan.health-probe.v1.schema.json` and `schemas/PROVENANCE.md`;
- `internal/health/receipt.go`, `canary.go`, `gatus.go`, and `sink.go`;
- `internal/health/health_test.go` redaction and public-projection tests;
- `internal/archive/archive.go` and `archive_test.go`;
- `config/canaries.json` and `config/gatus.yaml`.

The receipt is pinned to Datapan CLI PR #150 at commit
`2fc8343993b7704b50f7d50fcba2642fca439c7f`. Updating it requires a reviewed
CLI schema change plus matching provenance and compatibility tests.

## Cause-family evidence matrix

`Observed` means one receipt can state the fact directly. `Inferred` means
Health may derive a bounded hypothesis only from multiple observations and a
versioned rule. `Unavailable` means the current contract lacks enough evidence.

| Cause family | What is defensible today | What is not defensible today | Current gap |
| --- | --- | --- | --- |
| User or credential | A credential was absent when the CLI reports `credential_missing`; a provider returned an access rejection when the receipt reports `credential_rejected` | That a configured key is globally invalid, belongs to a particular user, has the wrong encoding, or is the sole cause of a `401/403` | Presence is not validity; no credential check kind/scope or independent control observation |
| Approval propagation | Registry can mark an operation credential-required; a skipped `approval_required` result may survive only as a coarse blocked category/reason in the private receipt | Submitted, pending, approved, rejected, propagation start/end, or whether a `403` is approval-related | No authoritative approval-state observation, observation time, authority, or distinction from input blocking |
| Input | `attempted=false`, safe parameter names, `parameter_blocked`, and the reason can show local preflight blocking | Whether an attempted `400/403` came from a bad value, provider policy, stale docs, or server defect | No preflight result per constraint, no provider-neutral input-failure class, and no policy version tied to the assertion |
| Quota or throttling | Explicit HTTP `429` maps to `rate_limited`; latency and retryability are retained | Account quota exhaustion versus per-operation, per-IP, burst, or provider-wide throttling; reset time unless explicitly observed | No quota scope/kind, reset observation, provider code class, or independent comparison cohort |
| Provider outage | Transport failure, timeout, `5xx`, provider failure, heartbeat silence, and repeated observations are available | Root-cause attribution to the provider from one canary or one credential; local network and adapter defects can look identical | No vantage point, dependency target, control canary, cohort/window evidence, or diagnosis confidence |
| Contract or semantic data quality | Provider semantic failure, unclassified response/schema drift, body shape, data presence, schema status, and freshness status exist | Structural conformance or freshness when the producer reports `not_observed`; empty data as a failure without policy | Current canaries stop mainly at L0-L4; no assertion policy/result identity for expected shape, presence, or freshness |

The present categories are still valuable for status and aggregation. They must
be treated as observations or coarse failure classes, not renamed into precise
root causes in the UI or archive.

## Minimum common diagnostic evidence

The following is a Health consumer requirement. Field names are illustrative;
the Datapan product-level contract must choose the final schema and ownership.
Every new field must be additive in a new receipt version or in an optional,
versioned diagnostic block. Health must reject unknown enum values until its
pinned consumer is updated.

| Evidence group | Minimum semantics | Authority | Exposure |
| --- | --- | --- | --- |
| Identity and time | Stable operation key, Registry revision, observation time, probe ID, diagnostic-contract version | Registry for operation identity; producer for execution identity | Public service alias/time; detailed identity private |
| Execution phase | `preflight`, `request`, `response`, or `semantic`; attempted flag; bounded timeout/request budget | CLI | Phase may be public; detailed execution private |
| Dependency scope | Provider-neutral dependency class and a stable public dependency ID; vantage class if more than one exists | Registry for dependency class; Health config for public alias | Allowlisted alias only; no raw host/path |
| Credential evidence | Presence check result and check kind such as `not_checked`, `missing`, `configured`, `provider_accepted`, `provider_rejected`; never the value, fingerprint, owner, or profile name | CLI observation; provider response only proves acceptance/rejection for that request | Aggregate state only if explicitly approved; otherwise private |
| Approval evidence | `not_required`, `required_unknown`, `submitted`, `pending`, `approved`, `rejected`, or `not_observed`, plus authority and observed-at time | Portal/approved adapter for live state; Registry only for requirement policy | Private by default; public diagnosis may expose only a coarse allowlisted state |
| Input evidence | Versioned input-policy key, local constraint result, and provider-neutral failed-constraint class without values | Registry policy and CLI evaluator | Constraint class may be public; names and all values private |
| Response evidence | Transport result, HTTP status class, provider-code class, retry-after/reset observation when safe, parse/semantic/body-shape state | CLI/provider adapter | Public only through bounded enums; raw codes/messages private |
| Data-quality evidence | Assertion-policy key/version and separate results for shape, presence, semantic validity, and freshness | Registry-reviewed policy evaluated by CLI/adapter | Allowlisted result enums public; rows/timestamps from payload never public |
| Diagnosis | Cause family, `observed`/`inferred`/`unknown` confidence, rule key/version, evidence references, retryability | Producer for direct diagnosis; Health for correlation diagnosis | Cause/confidence can be public only after privacy review |
| Correlation | Window start/end, expected and observed sample counts, affected/control service counts, and cohort rule version | Health | Counts and rule version may be public; no user/credential identity |
| Notice evidence | Stable notice ID, source authority, published/effective/resolved times, affected public dependency/operation scope, and redaction-safe reference | Portal/provider notice source; Health only records and correlates | Allowlisted public notice metadata; never infer an unpublished notice |
| Ownership | One of `user`, `portal`, `provider`, or `datapan`, with the evidence that supports assignment | Common diagnosis policy | Public only with diagnosis/confidence; `unknown` when evidence is insufficient |
| Next action | Versioned action-template key, wait/retry condition, safe time bound when authoritative, and prohibited action such as unnecessary key reissue | Registry vocabulary; product renderer supplies presentation | Bounded template and parameters only; no user state or credential data |
| Reproduction | Safe CLI handoff identity and command template, or an explicit `not_available` reason | CLI contract | No credential, query value, raw URL, or shell-ready untrusted provider text |

Two absences are deliberate:

- There is no credential fingerprint or pseudonymous user identifier. Even a
  hash can become a stable tracking key and is unnecessary for public-health
  diagnosis.
- There is no raw provider message, request URL, query value, authorization
  header, response body, or row. Provider adapters must convert them to reviewed
  bounded classes before the receipt crosses into Health.

## Correlation and incident rules

Health may classify an incident more precisely only when a versioned rule can
name all evidence it used. The first safe rule set should obey these limits:

- One observation can report a direct fact such as `credential_missing`, an
  explicit `429`, a timeout, or evaluated schema drift. It cannot report a
  provider outage or approval propagation as proven root cause.
- Two consecutive failures are an alert threshold only. They do not raise
  diagnostic confidence by themselves.
- Provider/dependency outage is at most inferred when multiple independent
  operations for the same dependency fail in a bounded window while suitable
  control operations do not. Without a control or independent vantage, keep
  the cause `unknown` and expose the observed failure class.
- A provider or portal notice is corroborating evidence only when its declared
  affected scope and effective window overlap the canary incident. Temporal
  overlap raises an inference through a versioned rule; it does not rewrite the
  original observations or prove causation by itself. Notice corrections and
  withdrawals supersede the derived link rather than deleting it.
- Credential-wide failure is at most inferred when an independently defined
  credential control fails alongside previously healthy operations. Health
  must not correlate or publish a user or credential identifier.
- Approval propagation requires an authoritative approval observation and its
  timestamp. A later first successful probe can close the interval; a `403`
  alone cannot open it.
- Empty data is not unhealthy unless a Registry-owned, versioned presence
  policy says so. Missing freshness evidence remains `not_observed`, not stale.
- Reclassification creates a new derived incident/diagnosis record. Historical
  receipt bytes and their original assessment are never updated in place.

## Compatibility and retention

### Receipt ingestion

- Continue accepting pinned v1 receipts while a future contract is introduced.
- Select the decoder by exact `schema_version`; do not silently coerce a new
  category into an existing v1 category.
- Store original redacted bytes or a canonical digest beside normalized fields
  so a later rule can be audited without rewriting evidence.
- A producer upgrade must ship fixtures for every new diagnosis family and an
  explicit downgrade/public-projection decision before Health updates its pin.

### Live status

- Gatus remains the familiar one-column status product. Diagnostic enrichment
  must not add secrets or high-cardinality evidence to its URL/error string.
- Keep live availability and diagnosis separate: a service may be unhealthy
  while the cause remains unknown.
- Heartbeat and two-failure thresholds remain scheduling/alert policy. A new
  diagnosis engine must not alter them implicitly.

### Detailed receipts and public archive

- The local `0600` JSONL sink currently has no application-enforced retention;
  deployment must bound rotation/deletion before richer private evidence is
  stored indefinitely.
- Platform PostgreSQL remains a seven-day live-status store; backup and restore
  stay infra-owned.
- Existing `datapan.health-archive.v1` Parquet is immutable history. Diagnostic
  fields require an additive v2 dataset or a separate versioned diagnosis
  table keyed by safe observation ID, never an in-place rewrite of v1 files.
- Public derived incidents need a stable incident ID, rule version, evidence
  window, and supersession relation. The current `incidents/` file is a list of
  non-healthy observations, not an incident lifecycle ledger.
- Notice correlation additionally needs stable notice provenance, effective
  intervals, affected-scope matching, and a supersession link. Scraped notice
  text must not enter the public diagnostic envelope without a reviewed,
  redaction-safe projection.

## Ordered work and ownership

1. **Product-level contract decision (Datapan team, CLI, Registry, Health).**
   Agree on cause families, direct versus inferred confidence, field authority,
   privacy, and versioning. Health supplies this document as consumer input;
   this repository does not finalize the schema.
2. **Producer evidence (Datapan CLI).** Add only evidence the executor or a
   reviewed provider adapter can observe: phase, credential check kind, input
   constraint result, approval observation when authoritative, response class,
   and assertion-policy results. Preserve redaction and exact provenance.
3. **Policy evidence (Datapan Registry).** Version stable dependency identity,
   diagnosis vocabulary/action templates, approval requirement, input policy,
   and live-probe semantic/schema/freshness assertion policy. Registry must not
   claim a user's live approval state.
4. **Health dual-version ingestion.** After a merged producer contract exists,
   pin its schema/provenance, add strict fixtures, preserve v1 compatibility,
   and keep the Gatus projection minimized.
5. **Health correlation ledger.** Add versioned, replayable rules and derived
   incident records with evidence windows, confidence, and supersession. Start
   with offline tests; do not alter public alerting during this step.
6. **Archive/public diagnosis.** After privacy review, publish an additive safe
   projection and migration/query guidance. Retain v1 observations unchanged.

Datapan-data remains the authority for completeness, freshness, and semantic
quality of reviewed published artifacts. Health can contribute only what its
representative live probes actually evaluate; it must not promote a live probe
to an artifact-quality verdict or duplicate datapan-data evidence.

Steps 4-6 are executable Health-owned tickets once their stated prerequisites
exist. Steps 1-3 are cross-repository decisions or producer/policy work and must
be routed by the Datapan team lead rather than implemented from this repository.

## Completion test for this audit

The audit is complete when the evidence matrix, minimum consumer fields,
compatibility/retention risks, and ordered ownership above are reviewed, and the
existing repository tests still pass. Completion does not mean that Health can
already make the six root-cause distinctions in production.
