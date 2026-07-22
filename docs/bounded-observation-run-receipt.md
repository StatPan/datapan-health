# Bounded Health observation-run receipt

`datapan.health-bounded-observation-run.v1` is the private, redacted producer
receipt for the former Registry runtime-freshness execution boundary. It is
not the ten-canary public-status scheduler receipt, a Registry release record,
or a public archive schema.

The receipt fixes the existing runtime boundary at eight shards, at most 100
operations per shard, two parallel shards, and a 1--20 second per-operation
timeout. It binds the immutable Health producer revision and Registry source,
manifest, and policy digests. Each shard repeats only the manifest and policy
digests plus an opaque scope digest; operation names, query values, URLs,
credentials, provider prose, response bodies/rows, and user identity are not
fields in the schema.

For an admittable shard, the Health source receipt records the exact relative
`receipt_path`, SHA-256 of those receipt bytes, `shard_digest`, fixed scope
`data_go_kr/runtime_freshness_rotating_shard`, terminal state, and the complete
redaction assertion object. Registry #590 remains the only owner of the outer
`runtime_freshness_shard` admission envelope: it supplies the aggregate
receipt path/SHA and copies/checks these source fields against its producer,
registry, execution, scope, and redaction fields. Health never creates that
outer envelope or admits itself.

`receipt_available=false` represents an explicit incomplete source shard. It
has no artifact path or digest, so Registry must not create an outer envelope;
the aggregate cannot satisfy the required eight admitted shards and fails
closed. The partial fixture demonstrates this without inventing a fallback
artifact.

`registry-admission-map.json` is the offline byte-level hand-off fixture. It
binds the aggregate source receipt path/SHA and all eight Health shard artifact
paths, SHA values, and shard digests. Registry #590 uses the same relation when
it builds its outer admission envelopes; the fixture proves the producer bytes
without allowing Registry to run Health.

## Fixture matrix

`testdata/observation-runs/v1/complete-verified.json` contains exactly one
explicit entry for each prior Registry shard index `0` through `7`.
`partial-unknown.json` preserves all eight entries but marks shard `7` as a
timed-out, not-completed observation and the aggregate as `unknown`/`partial`.
Missing or duplicate shard
indexes are invalid; an incomplete or unknown run can never be promoted to
`verified`.

The aggregate is deterministic:

- any incomplete shard is `unknown` and `partial`; an explicit timeout is
  retained as `timed_out=true` rather than being silently folded into success;
- otherwise any unknown shard is `unknown`;
- otherwise any failed shard is `failed`;
- otherwise any skipped shard is `skipped`;
- only eight completed verified shards yield `verified`/`complete`.

This contract is offline fixture evidence for Health #31. Registry admission
is owned by Registry #590, and runner wiring or an authorized one-shot live
observation remains blocked in Health #33 until both repositories accept the
same immutable receipt boundary.

`ValidateAt(referenceTime, maxAge)` is the required temporal admission gate.
It rejects a future run, a run older than the supplied policy, and any run that
exceeds the deterministic maximum implied by the eight-shard, batch, parallel,
and per-operation timeout bounds. The structural decoder deliberately does not
consult the wall clock, so fixtures remain reproducible; Registry #590 supplies
the admission reference time and maximum age.
