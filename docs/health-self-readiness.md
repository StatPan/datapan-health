# Health's own readiness

The private scheduler listener has distinct endpoints. /live means the HTTP
process responds. /ready returns 200 only when the loop is current, CLI and
adapter executables and pinned catalog are usable, state/archive/journal write
boundaries are usable, and every configured canary has a recent acknowledged
delivery without a more recent pipeline failure. Otherwise it returns 503.
/status returns the same readiness decision with bounded reasons and timestamps;
/metrics exports last loop, total and per-canary last delivery, rejection and
state/delivery failure signals. GET/HEAD only; no execution route exists.

A restarted scheduler begins in startup/awaiting-first-delivery. It does not
restore readiness from old archive rows. First deliveries follow the existing
5/10/15-minute cadence and jitter; readiness can stay 503 for up to the slowest
initial schedule plus its bounded execution. Do not use /ready as a liveness
restart probe or restart the process repeatedly during this honest warm-up.
A loop more than five seconds old is unready. Each canary becomes stale after
its existing Registry-approved heartbeat window of two schedule intervals.
Cumulative counters survive only within a process; the durable delivery journal
is the independent restart/audit evidence.

Provider timeout/failure with a valid receipt and successful delivery is a
working Health pipeline. Missing CLI output, rejected provenance, failed
storage or failed delivery is a Health fault. A receipt-less child may publish
a bounded indeterminate result to avoid leaving old healthy data behind;
that successful projection still does not make the CLI pipeline ready.

health-runner first archives the redacted observation, then pushes to Gatus,
then durably appends an acknowledgement to RECEIPT_DELIVERY_JOURNAL (default:
RECEIPT_ARCHIVE + .deliveries.jsonl). An archive row is not a delivery receipt.
An acknowledgement states public_readback=not_checked: a successful POST does
not prove the externally served route/image or notification delivery. If
journal persistence fails after Gatus acceptance, the adapter exits nonzero;
readiness remains failed and no duplicate provider request is scheduled to
repair that slot. Delivery is bounded, not distributed exactly-once.

Local proof: make build, local Compose Gatus/public-status, then
RUNTIME_IMAGE=datapan-health-runtime:test python3 scripts/pipeline-proof.py.
It builds an offline synthetic CLI (never shipped in the runtime), uses the
real scheduler/adapter, pinned Gatus, database and public JSON routes, and
writes out/pipeline-proof.json. It exercises all ten canaries, invalid Registry
admission, Gatus failure after archive, valid provider timeout, missing CLI
receipt, and recovery. No provider endpoint is contacted.

## Infra integration handoff

This repository does not deploy or modify statpan-infra. Its owner must:

1. Deploy exact reviewed OCI digests with immutable source/build evidence and
   compare installed CLI Registry source/manifest bytes with the consumer pins.
2. Keep scheduler /status and /metrics private. Independently observe every
   configured canary's last accepted delivery and original observation time;
   one fresh item must not conceal nine stalled items. Retain bounded startup
   grace and sustained alert/recovery policy.
3. Read the durable Gatus acknowledgement journal, not only receipt archive
   freshness. Join it to actual Gatus storage and external public JSON readback
   using exact runtime/config identity. /services remaining unknown is honest
   until immutable service deployment identity is supplied.
4. Verify public route/image delivery, notification dispatch and receipt at
   its destination with a bounded synthetic fixture; do not manufacture
   provider failures or broaden the ten-canary request budget.
5. Verify normal operation, one-item scheduling silence, archive-success /
   delivery-failure, loss of CLI/storage, and recovery at the deployed digest.

Local test or CI success, a 200 /live, old archive rows, and source merge each
prove different things. None alone proves production self-monitoring.
