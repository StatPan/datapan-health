---
pretty_name: Datapan Health Observations
license: cc-by-4.0
task_categories:
  - tabular-classification
tags:
  - datapan
  - public-data
  - status-history
  - parquet
  - duckdb
---

# Datapan Health Observations

This public dataset is the asynchronous, long-term history for Datapan public-data service health. It is not a live-status API. Gatus backed by platform PostgreSQL remains the live seven-day status path; publication outages cannot alter probe, heartbeat, incident, or Gatus delivery behavior.

## Data and privacy boundary

All Parquet is ZSTD-compressed and UTC-partitioned by `observations/date=YYYY-MM-DD`. The public observation schema is `datapan.health-archive.v1`: observation time, public service ID, Registry revision, outcome/category enums, latency, data/schema/freshness states, and schedule tier only.

The dataset never includes dataset IDs, endpoint hosts/paths or URLs, query values, credentials, request parameters, provider codes/messages, reason details, next actions, response bodies/rows, or internal logs. Detailed redacted receipts remain in the archive sink and are not published.

`services/services.parquet` maps public service IDs to Registry-owned stable operation IDs, immutable catalog revision, and schedule tier. `incidents/` contains public non-healthy observation transitions; `daily_rollups/` contains availability and latency aggregates. The archive manifest pins [datapan-cli PR #150](https://github.com/StatPan/datapan-cli/pull/150) receipt schema commit `2fc8343993b7704b50f7d50fcba2642fca439c7f` / SHA-256 `b755a5af33152bcb36dc7c2382b94857953d0a9359b6b77cd8b2cb093d0a820d`, and [datapan-registry #557](https://github.com/StatPan/datapan-registry/issues/557) catalog revision `b49d66b97d8155c34649f4dd2040b884c4212d64` / pinned catalog SHA-256 `e84f0da2f532a32833def1118a4610bf2322f370783d120b84cf85306d244840`.

The #150/#557 pins are historical contract authority, separate from the active consumed release in manifest provenance.active_registry. services.catalog_revision identifies the active Registry dataset revision; input_catalogs records exact Registry source/manifest/catalog bindings for all observations in the emitted partitions. The exporter also accepts only the exact reviewed historical releases 10f37518… and 247975f0…. Older SISUL identifiers and policy version 1 retain their original observation revision while mapping to the same stable public service as current version 2. This compatibility does not admit historical observations into live status or expose provider identifiers. Configuration and mapping changes produce a new batch/checkpoint identity.

## Cadence and limitations

Publication is batch-only, at most daily. Tier A/B/C desired schedules are 5/10/15 minutes, respectively. A one-shot runner is not a scheduler; future scheduler work must add jitter and bounded concurrency. A single unhealthy observation can be archived immediately, while Gatus incident alerts require two consecutive failures and heartbeat requires two missed schedules.

Gatus/PostgreSQL retains at most seven days of live status. Parquet is long-term history, subject to platform publication and retention policy. It must not be queried by the public status page.

## DuckDB

Local files:

```sql
SELECT service_id,
       count(*) AS observations,
       avg(outcome = 'healthy') AS availability,
       quantile_cont(latency_ms, 0.50) AS p50_latency_ms,
       quantile_cont(latency_ms, 0.95) AS p95_latency_ms
FROM read_parquet('archive/observations/date=2026-07-13/*.parquet')
WHERE service_id = 'public-data_holiday-emergency-clinics'
GROUP BY service_id;
```

Resolved Hugging Face Parquet URL after publication:

```sql
INSTALL httpfs; LOAD httpfs;
SELECT outcome, category, count(*)
FROM read_parquet('https://huggingface.co/datasets/StatPan/datapan-health-observations/resolve/main/observations/date=2026-07-13/part-00000.parquet')
WHERE service_id = 'public-data_holiday-emergency-clinics'
GROUP BY outcome, category;
```
