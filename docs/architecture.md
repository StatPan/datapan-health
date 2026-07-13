# Architecture

The probe boundary is intentionally narrow. Until `datapan-cli#134` ships, only versioned synthetic `datapan.health-probe.v1` fixtures are accepted. Strict JSON decoding and an allowlist prevent credentials, complete query URLs, response bodies, and rows from entering persistence or Gatus.

The adapter maps `healthy|unhealthy` to Gatus success, `duration_ms` to duration, and an allowlisted public error class to the failure message. Authentication material is read at runtime and used only as the Bearer header.

`ReceiptSink` separates receipt retention from delivery. `LocalSink` is the MVP implementation. Gatus owns live status in its SQLite volume. A future Hugging Face Dataset sink may upload batches of already-redacted receipts for archive/analysis; it is optional, asynchronous, and never a live or transactional database.

No deployment resources or `statpan-infra` changes belong to this issue.
