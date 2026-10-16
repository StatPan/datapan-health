# Long-term health archive

The live product is Gatus backed by platform PostgreSQL and retains a bounded
seven days of public status. The archive is a separate, asynchronous batch
path. It must never become a live database, a runner dependency, or an input to
Gatus alert and heartbeat decisions.

## Contract

`cmd/health-archive` accepts a local JSONL stream of canonical,
already-redacted `datapan.health-probe.v1` receipts. It resolves each receipt's
immutable operation key through its exact reviewed Registry release catalog and emits
only the strict `datapan.health-archive.v1` observation projection. The pinned
schema is [datapan.health-archive.v1.schema.json](../schemas/datapan.health-archive.v1.schema.json).

The projection permits UTC observation time, public service ID, registry
revision, outcome/category enums, latency, data/schema/freshness states, and
scheduling tier. It explicitly rejects dataset IDs, endpoint hosts or paths,
provider messages and codes, reason codes, next actions, parameters/query data,
credentials, response bodies/rows, and logs.

## Files and retry behavior

The exporter creates deterministic `date=YYYY-MM-DD` UTC partitions with ZSTD
Parquet files:

- `observations/date=.../part-00000.parquet`
- `incidents/date=.../part-00000.parquet`
- `daily_rollups/date=.../part-00000.parquet`
- `services/services.parquet`

It derives an observation ID from the safe projection. The versioned batch digest
binds sorted projected observations in the emitted partitions, complete archive
configuration, active service mapping, and all catalog bindings represented in
those partitions. Re-running a batch, or retrying after a missing checkpoint,
deduplicates by observation ID. The checkpoint records only safe file digests.
Monthly observation compaction uses DuckDB and performs a bidirectional
`EXCEPT ALL` equivalence check before publishing the compacted file.

Each manifest preserves canonical contract authority: datapan-cli PR #150's
receipt-schema commit/digest and datapan-registry #557's original catalog
revision/digest. These historical pins are not the current publication identity.
`active_registry` must exactly match the reviewed canary release tuple and catalog
digest before export writes anything. `services.catalog_revision` identifies this
active Registry dataset revision. `input_catalogs` records the exact release,
source, manifest, and catalog identities represented in emitted partitions,
including retained observations from earlier batches. A changed configuration or
mapping cannot reuse an old completed checkpoint; a valid retry returns the
persisted manifest, including its original creation time.

Two exact historical input releases are additionally accepted: `10f37518…` and
`247975f0…`. Their original catalog bytes are pinned under
`config/registry/archive-history/`. A receipt must match its own release's Registry
distribution ID, source/manifest digests, operation alias, provider/dependency,
endpoint identity, and policy. Missing policy fields are accepted only for the
original `10f37518…` v1 contract. Unknown or drifted identities stop export before
any output or checkpoint is written. Historical SISUL API/operation identifiers
and policy version 1 map to the same stable public service as current version 2;
their observation revision stays historical. This archive-only mapping never
permits old receipts in live Gatus admission and never alters the detailed private
receipt stream or expands the public observation schema.

The original Health scheduler source `8707dd99…` mislabeled
`registry.dataset_id` with the provider API ID only in its receiptless fallback
records. Export accepts that exact legacy shape only for the reviewed `10f37518…`
tuple, the `scheduler-receiptless-fallback` marker, matching operation alias,
present policy, original execution limits/parameters, and the original
indeterminate missing-receipt/timeout observation. It cannot accept healthy data,
CLI records with provider IDs, or another release through this exception. Detailed
original records stay untouched; the safe public projection preserves the failure.

The dataset card is [dataset-card/README.md](../dataset-card/README.md).

## Publishing

`-publish` is intentionally optional. It first completes a local export, copies
the dataset card, then retries only Hugging Face upload. The publish stage
contains only Parquet, `manifest.json`, and `README.md`; checkpoints and partial
files cannot be uploaded. A missing `HF_TOKEN` or `hf` CLI produces a clearly
recorded skipped authenticated smoke rather than weakening unit/integration
tests. The designated public repository is `StatPan/datapan-health-observations`.
