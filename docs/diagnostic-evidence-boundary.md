# M003 diagnostic evidence boundary

Status: Health consumer requirements and gap audit for issue #17. This is not a
runtime implementation or publication decision.

The product-level source is Datapan team mission M003. Registry issue #566 and
PR #569 merged the draft `datapan.diagnostic-envelope.v1` schema and consumer
contract at commit `2ada3ddea5a497bf315999ea5e30e3474fc86a9b`. This
document evaluates Health against those actual bytes. The draft is test input,
not runtime authority: Registry #567 must accept the data.go.kr evidence
mapping, and Registry #568 requires exact CLI, Health, and Web compatibility
receipts before publication.

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

The merged draft diagnostic contract keeps three things
separate:

1. objective observations from one execution;
2. authority-bound policy or approval facts;
3. a versioned cause with one `observed`/`inferred`/`unknown` determination and
   typed evidence references.

Health is a consumer and correlator of that contract. Datapan CLI owns the
probe execution and local credential/input preflight. Datapan Registry owns
stable operation identity and reviewed provider policy. Neither a Health
incident nor a Registry policy can manufacture a portal approval fact.

## Current evidence surfaces

| Surface | Evidence available now | Boundary |
| --- | --- | --- |
| Pinned receipt | Operation/Registry identity, execution attempted and budget, latency, HTTP/provider/semantic/body observations, data/schema/freshness states, outcome/category/retryability/reason, redaction assertions | `datapan.health-probe.v1` categories are coarse and contain no typed evidence authority/scope/timing, cause determination, approval record, or versioned correlation identity |
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
- `config/canaries.json` and `config/gatus.yaml`;
- Registry commit `2ada3ddea5a497bf315999ea5e30e3474fc86a9b` paths
  `drafts/diagnostic-envelope/datapan.diagnostic-envelope.v1.schema.json` and
  `drafts/diagnostic-envelope/consumer-contract.v1.json`.

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
| Provider outage | Transport failure, timeout, `5xx`, provider failure, heartbeat silence, and repeated observations are available | Root-cause attribution to the provider from one canary or one credential; local network and adapter defects can look identical | No vantage point, dependency target, control canary, cohort/window evidence, or versioned determination rule |
| Contract or semantic data quality | Provider semantic failure, unclassified response/schema drift, body shape, data presence, schema status, and freshness status exist | Structural conformance or freshness when the producer reports `not_observed`; empty data as a failure without policy | Current canaries stop mainly at L0-L4; no assertion policy/result identity for expected shape, presence, or freshness |

The present categories are still valuable for status and aggregation. They must
be treated as observations or coarse failure classes, not renamed into precise
root causes in the UI or archive.

## Merged draft consumer surface

A future Health implementation must consume the exact accepted Registry
artifacts rather than a parallel local model. The following names and
constraints come from the currently merged draft schema and
`consumer-contract.v1.json`. Any accepted or published revision requires a new
exact pin; Health must reject unknown versions and enum values until its
consumer is updated.

| Contract group | Exact semantics Health relies on | Authority and Health boundary |
| --- | --- | --- |
| Version and time | `schema_version=datapan.diagnostic-envelope.v1` and RFC 3339 `assessed_at` | The producer supplies assessment time; Health selects the decoder by exact version. |
| Subject | `source_id`, `provider_id`, `dataset_id`, and `operation_id` | Registry supplies stable identity. Health needs a manifest-bound one-to-one operation-to-canary bridge; fuzzy or positional matching is forbidden. |
| Cause | `code`, `determination`, `layer`, and `explanation_id` | Determination is exactly `observed`, `inferred`, or `unknown`; numeric/probability confidence is forbidden. Health may author only evidence-backed correlation causes. |
| Ownership | `accountable_party` and optional `support_reference_id` | Bounded parties are `user`, `datapan`, `data_go_kr`, `provider`, `shared`, or `unknown`. Health must keep `unknown` when evidence cannot assign responsibility. |
| Actions | Exact `recommended` and `avoid` objects with `action_id`, `actor`, and `rationale_id` | Cause-specific schema rules reject contradictory actions. Health renders IDs only; it does not synthesize free text or new vocabulary. |
| Evidence identity | `kind`, bounded `ref_id`, `authority`, optional `version`, `supports`, and a subject-bound `scope` | Each kind has an authority and scope allowlist. `subject_ref` is always `envelope_subject`; duplicated subject identity is not accepted. |
| Evidence time | `basis=relative_to_assessed_at`, non-negative `observed_age_seconds`, `validity`, `validity_policy_version`, and positive remaining validity for current evidence | Evidence supporting cause, determination, or action must be current. Provider response is bounded to 300 seconds, Health correlation to 900 seconds, and provider notice to 86,400 seconds. |
| Approval, request, and response | Typed `approval_record`, `request_validation`, and `provider_response` payloads | Approval state comes only from `data_go_kr_portal` or `provider_portal`; CLI owns request validation; provider/CLI response classes do not turn a generic `401/403` into an approval or credential verdict. |
| Health correlation | `kind=health_observation`, `authority=datapan_health`, operation scope, and `health_correlation.{state,probe_policy_version}` | State is `unavailable`, `degraded`, `operational`, or `unknown`. A versioned bounded rule and exact evidence cohort are required before Health emits it. |
| Provider notice | `kind=provider_notice` with provider/provider-portal authority and `notice.{state,notice_version}` | Health can correlate only reviewed, current, exact-scope notices; it cannot invent notice authority from timing alone. |
| Contract and quality | Versioned response-contract and quality assertions; freshness additionally carries reference time, actual time, maximum age, and state | Semantic, presence, contract, and freshness results are valid only under an exact operation-bound policy. Missing policy/evidence remains unknown or not observed. |
| Validation | Operation-scoped `validation_result` with required/achieved L1-L4, policy version, and result | A `ready` cause requires passed validation at or above the required level. Health cannot equate transport success with reusable data. |
| Redaction | Eight required false assertions for secret values/hashes, authorization headers, credential-bearing URLs, raw provider text/URLs, response bodies, and user identity | Assertions are necessary but not sufficient: every producer boundary also needs negative leak fixtures before Health accepts the envelope. |

### Public and private exposure

- The complete diagnostic envelope and current `datapan.health-probe.v1`
  receipt are private Health inputs. Passing the schema redaction assertions
  does not authorize publication.
- Existing Gatus output remains limited to the enum-only availability error and
  latency projection described above.
- Health #20 must define a default-deny public allowlist. Candidate public
  fields are an approved service/operation alias, assessment time, availability,
  and reviewed cause/determination/action IDs. Detailed subject identity,
  evidence references and payloads, support references, ownership evidence,
  correlation cohorts, and policy internals remain private unless separately
  justified and reviewed.
- Secret values or hashes, authorization headers, credential-bearing URLs, raw
  provider text or URLs, response bodies or rows, query values, and user or
  credential identity are never public.

Two absences are deliberate:

- There is no credential fingerprint or pseudonymous user identifier. Even a
  hash can become a stable tracking key and is unnecessary for public-health
  diagnosis.
- There is no raw provider message, request URL, query value, authorization
  header, response body, or row. Provider adapters must convert them to reviewed
  bounded classes before the envelope crosses into Health.

## Correlation and incident rules

Health may classify an incident more precisely only when a versioned rule can
name all evidence it used. The first safe rule set should obey these limits:

- One observation can report a direct fact such as `credential_missing`, an
  explicit `429`, a timeout, or evaluated schema drift. It cannot report a
  provider outage or approval propagation as proven root cause.
- Two consecutive failures are an alert threshold only. They do not change a
  cause determination by themselves.
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

- Continue accepting pinned v1 receipts when the accepted diagnostic envelope
  is introduced.
- Select the decoder by exact `schema_version`; do not silently coerce a new
  category into an existing v1 category.
- Store original redacted bytes or a canonical digest beside normalized fields
  so a later rule can be audited without rewriting evidence.
- A producer upgrade must ship fixtures for every new cause family and an
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

1. **Registry evidence mapping — Registry #567.** Accept static data.go.kr
   mapping and corroboration requirements without turning a generic `401/403`
   into approval, credential, or outage certainty. This is the remaining
   upstream semantic dependency for Health implementation.
2. **Health compatibility proof and operation identity — Health #19.** Pin the
   exact accepted contract and mapping, preserve `datapan.health-probe.v1`, add
   strict fixtures and producer-boundary leak tests, bind every Registry
   operation to exactly one canary, and emit the digest-bound Health receipt
   required by Registry #568. The merged #566 draft is test input until #567
   and the accepted revision are known.
3. **Safe browser status interface — Health #20.** After #19, expose an
   allowlisted public operation identity and JSON projection with explicit
   non-credentialed CORS behavior. This is separate from the Gatus HTML surface
   and does not authorize rollout.
4. **Correlation and provider notices — Health #21.** After Registry #567 and
   Health #19, add versioned, bounded, replayable `health_observation` rules and
   exact-scope provider-notice links with immutable/superseding history. Start
   offline and do not alter public alerting.
5. **Contract, semantic, and freshness policy — Health #22.** After Registry
   #567, a versioned Registry assertion policy, and Health #19, evaluate these
   states only for the exact operation/policy pair. Absence remains unknown or
   not observed.
6. **Registry publication — Registry #568.** Publish only after CLI, Health,
   and Web provide compatibility receipts for the exact accepted bytes.
   Publication does not deploy Health or Datapan Web.
7. **Archive/public diagnosis — future privacy-reviewed task.** Publish only an
   additive safe projection and migration/query guidance; retain v1
   observations unchanged.

Datapan-data remains the authority for completeness, freshness, and semantic
quality of reviewed published artifacts. Health can contribute only what its
representative live probes actually evaluate; it must not promote a live probe
to an artifact-quality verdict or duplicate datapan-data evidence.

Health #19-#22 are executable repository work packets with explicit
prerequisites. Registry #567 and #568, CLI producer changes, Web rendering, and
public rollout remain outside this repository.

## Completion test for this audit

The audit is complete when the evidence matrix, minimum consumer fields,
compatibility/retention risks, and ordered ownership above are reviewed, and the
existing repository tests still pass. Completion does not mean that Health can
already make the six root-cause distinctions in production.
