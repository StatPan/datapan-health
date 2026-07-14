# Long-term health archive

The live product is Gatus backed by platform PostgreSQL and retains a bounded
seven days of public status. The archive is a separate, asynchronous batch
path. It must never become a live database, a runner dependency, or an input to
Gatus alert and heartbeat decisions.

## Contract

`cmd/health-archive` accepts a local JSONL stream of canonical,
already-redacted `datapan.health-probe.v1` receipts. It resolves each receipt's
immutable operation key through the configured public canary mapping and emits
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

It derives an observation ID from the safe projection and a batch ID from sorted
observation IDs. Re-running a batch, or retrying after a missing checkpoint,
deduplicates by observation ID. The checkpoint records only safe file digests.
Monthly observation compaction uses DuckDB and performs a bidirectional
`EXCEPT ALL` equivalence check before publishing the compacted file.

Each manifest records canonical contract provenance: datapan-cli PR #150's
receipt-schema commit/digest and datapan-registry #557's catalog
revision/digest. The dataset card is [dataset-card/README.md](../dataset-card/README.md).

## Publishing

`-publish` is intentionally optional. It first completes a local export, copies
the dataset card, then retries only Hugging Face upload. The publish stage
contains only Parquet, `manifest.json`, and `README.md`; checkpoints and partial
files cannot be uploaded. A missing `HF_TOKEN` or `hf` CLI produces a clearly
recorded skipped authenticated smoke rather than weakening unit/integration
tests. The designated public repository is `StatPan/datapan-health-observations`.
