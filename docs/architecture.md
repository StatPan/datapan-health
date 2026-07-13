# Architecture

The probe boundary accepts the merged `datapan.health-probe.v1` contract from `datapan-cli`, pinned locally with source commit and digest in `schemas/PROVENANCE.md`. The runner embeds that schema for runtime validation; strict nested JSON decoding and schema compatibility tests also reject unknown fields. The receipt must assert that credentials, query values, and response rows were removed.

CLI `probe_id` is a UUID for one execution and is never used as a public identity. The adapter resolves immutable `operation.operation_key` through `config/canaries.json` to a configured Gatus external endpoint. It maps only `assessment.outcome`, `assessment.category`, and `observation.latency_ms`: outcome `healthy` becomes success; every other valid outcome becomes a failure whose error is the enum-only `outcome:category`. Dataset identifiers, endpoint paths, provider messages/codes, reason codes, next actions, parameters, query data, credentials, and response rows never enter Gatus errors, URLs, or logs. Authentication material is read at runtime and used only as the Bearer header.

`ReceiptSink` separates detailed redacted receipt retention from delivery. `LocalSink` is the MVP implementation. Gatus owns live status in its SQLite volume. A future Hugging Face Dataset sink may upload batches of already-redacted receipts for archive/analysis; it is optional, asynchronous, and never a live or transactional database.

No deployment resources or `statpan-infra` changes belong to this issue.
