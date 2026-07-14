# Architecture

The probe boundary accepts the merged `datapan.health-probe.v1` contract from `datapan-cli`, pinned locally with source commit and digest in `schemas/PROVENANCE.md`. The runner embeds that schema for runtime validation; strict nested JSON decoding and schema compatibility tests also reject unknown fields. The receipt must assert that credentials, query values, and response rows were removed.

CLI `probe_id` is a UUID for one execution and is never used as a public identity. The adapter resolves immutable `operation.operation_key` through `config/canaries.json` to a configured Gatus external endpoint. It maps only `assessment.outcome`, `assessment.category`, and `observation.latency_ms`: outcome `healthy` becomes success; every other valid outcome becomes a failure whose error is the enum-only `outcome:category`. Dataset identifiers, endpoint paths, provider messages/codes, reason codes, next actions, parameters, query data, credentials, and response rows never enter Gatus errors, URLs, or logs. Authentication material is read at runtime and used only as the Bearer header.

`ReceiptSink` separates detailed redacted receipt retention from delivery. `LocalSink` is the MVP implementation. Gatus owns live status in PostgreSQL, using `storage.type: postgres` and injected `GATUS_DATABASE_URL`. Production PostgreSQL is platform-owned: `statpan-infra#472` provisions the dedicated `datapan_health` database and least-privilege role, owns network policy, backup/restore, and platform retention. The runner remains database-free. Local Compose uses only an ephemeral PostgreSQL service with a non-secret development credential; SQLite is not a runtime path.

`config/canaries.json` is a Registry-pinned allowlist of ten public operation IDs: five data.go gateway routes and five registered external adapters. It defines Tier A/B/C 5/10/15 minute desired cadence, two missed schedules before heartbeat failure, and two consecutive failures before Gatus incident alerting. `health-runner` remains one-shot; the separate `health-scheduler` consumes this boundary with jitter and bounded concurrency. Neither component uses the archive or Hugging Face to decide live delivery.

`cmd/health-archive` is a separate batch-only process. It reads already-redacted receipt JSONL after live delivery and emits a strict `datapan.health-archive.v1` public projection: no dataset identifier, endpoint, provider message/code, reason code, next action, query, credential, request parameter, or response row leaves the local sink. Its UTC `date=YYYY-MM-DD` partitions are ZSTD Parquet for observations, incident observations, daily rollups, and services. A deterministic batch ID and digest checkpoint make retries idempotent. Monthly observation compaction is written through DuckDB and rejected unless a bidirectional `EXCEPT ALL` comparison proves the compacted rows identical to the daily shards. Filtered DuckDB queries calculate availability and p50/p95 latency directly from Parquet.

Hugging Face is an optional publisher of those completed Parquet artifacts, not a sink for live execution. The publisher retries only its own asynchronous upload and stages only Parquet, `manifest.json`, and the dataset card; checkpoints are excluded. Missing credentials, an unavailable CLI, or a remote outage can never delay or alter a runner-to-Gatus result. `config/archive.json` pins the datapan-cli #150 receipt-schema commit/digest and datapan-registry #557 catalog revision/digest in every manifest. The public dataset card contains the same provenance and querying guidance.

Release images preserve this boundary: the scratch `runtime` target contains
only runner and scheduler, while the separate `archive` target contains
`health-archive` and the pinned `hf` CLI. `HF_TOKEN` is never an image build
argument, environment variable, label, file, or log field; infra #475 injects
it only into the isolated archive Compose role. See
[release-images.md](release-images.md) for reproducible digest handoff.

No deployment resources or `statpan-infra` changes belong to this issue.
