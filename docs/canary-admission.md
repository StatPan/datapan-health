# Live canary admission

Both health-scheduler and health-runner call AdmitReceipt before downstream
storage or delivery. The exact ten-canary release already reviewed in
config/registry/PROVENANCE.md is compiled into the consumer binary: catalog
SHA-256, immutable Dataset revision, source SHA-256, release tag and manifest
SHA-256. Loading a mounted configuration with different claims fails closed.
This is a consumer allowlist of reviewed release evidence, not a new signature
verifier. datapan-cli retains ownership of signed Registry installation/trust;
operators must separately verify the installed manifest and source bytes
against these pins when accepting a deployment.

Admission compares dataset, operation, provider, target, Registry provenance,
policy key/version/authority/maximum level, execution ceilings and safe
parameter names. A policy absent from the optional-policy v1 wire schema is
still schema-compatible, but cannot enter the live catalog-bound pipeline.
Observed levels cannot exceed the policy maximum. Provider failures, timeouts,
and scheduler receipt-less indeterminate outcomes remain valid evidence;
rejecting provenance is a Health fault, not a provider outage.

Receipts must be at most one minute old, no more than five seconds ahead of the
consumer clock, and, for a scheduled child, no earlier than five seconds before
its invocation. Synchronize host clocks. Delayed receipt imports belong to the
historical archive, not current Gatus ingestion. Gatus stamps external results
at ingestion, so freshness must be enforced here, before provenance disappears
from the public summary. This time window does not provide a distributed
exactly-once delivery guarantee.

The historical testdata/receipts/v1 files deliberately preserve old timestamps,
placeholder release identities and absent policy to exercise wire compatibility.
scripts/prepare-smoke-fixtures.py creates *synthetic* current receipts only from
those fixed test fixtures and the accepted test config for local Compose.
It must never be used to refresh real receipts.

Promotion requires reviewed immutable published Registry release evidence,
updating the compiled pins and config together, compatibility/negative tests,
and a new consumer image. Registry main, a published release, this accepted
consumer pin, and the actual installed runtime are separate identities.
Do not replace pins automatically from mutable main.
