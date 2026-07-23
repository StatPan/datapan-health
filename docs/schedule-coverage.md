# Identity-preserving ten-minute schedule coverage

`health-schedule-coverage` turns the immutable, pinned Registry operation
manifest into one private queue for each ten-minute UTC interval. The only
queue key is `operation_id` / `StatusSubject()`. API URL, dataset, host,
endpoint and the separate ten-canary catalog are metadata or independent
inputs; none can merge, remove, or substitute operation work.

The command is a deterministic scheduling simulation and emits a private
`datapan.health-schedule-coverage.v1` receipt. It proves the active Registry
revision, manifest digest, interval, shard count, queue digest and counts for
`expected`, `assigned`, `attempted`, `completed`, `late`, and `missing`.
With no worker attached, an emitted receipt has zero attempts and completions;
it must never be represented as provider-call evidence.

```sh
make schedule-coverage
# or select a reproducible interval and candidate shard count
go run ./cmd/health-schedule-coverage \
  -at 2026-07-23T00:00:00Z -shards 64 \
  -state out/schedule-coverage-state.json -dry-run \
  -output out/schedule-coverage.json
```

The authority state is private, mode `0600`, and guarded by an adjacent
cross-process exclusive lock. Every mutation reloads the latest state under
that lock, verifies the persisted generation, then atomically CAS-commits a
new generation and directory-syncs it before returning. A stale authority can
therefore neither overwrite another process's claim nor mutate an old plan
after rebalance. It stores queue identity internally so restart recovery can
fence stale workers; browser and Doctor output never contain that identity
list. `-dry-run` is required and is the only mode in this ticket. There is no
provider runner, credential input or provider-call path in this command.

## Queue lifecycle

Each identity is assigned with `sha256(operation_id) mod shard_count`, and the
sorted identities in every shard are bound by a queue SHA-256 digest. A lease
claim carries the Registry revision, interval, shard, generation and expiry.
Retry releases the current claim; the next claim increments the generation.
Completion accepts only the current, unexpired generation. Consequently an
abandoned worker, a delayed stale worker, or a worker restored after a crash
cannot make a second authoritative terminal transition.

Work completed after the interval deadline is counted as `late`; work without
a completion at receipt observation time is `missing`. Those counts are
separate from `attempted` so scheduling pressure is visible without guessing a
provider result.

## Operator readiness

The existing `health-public -doctor` path accepts an optional private
`-schedule-coverage-state` file. It reports only the pinned Registry revision,
manifest digest, shard count, latest interval, aggregate counts, and receipt
state (`current`, `stale`, `missing`, `invalid`, or `not_configured`). It does
not widen the browser-facing service/dependency APIs. Run the deterministic
integration proof with:

```sh
make schedule-coverage-doctor
```

The emitted dry-run example is intentionally `missing=12385`: it proves that
the queue was persisted and observed, not that providers were contacted.

## Scheduler acceptance path

The same lifecycle can be attached to `health-scheduler` without widening its
canary/provider boundary. Set `SCHEDULE_COVERAGE_STATE` together with pinned
`SCHEDULE_COVERAGE_MANIFEST` and `SCHEDULE_COVERAGE_RELEASE_MANIFEST` paths;
the scheduler accepts it only when `SCHEDULE_COVERAGE_DRY_RUN=true` (default)
and uses `SCHEDULE_COVERAGE_RECEIPT` and `SCHEDULE_COVERAGE_SHARDS` only to
construct the coverage plan. Its `ProcessDue` loop persists one receipt per
ten-minute interval before considering canaries. This lifecycle has no
`ProbeRunner`, delivery adapter, endpoint, credential, or provider-call mode.
Setting dry-run false fails scheduler startup rather than enabling execution.

## Capacity and safe shard-count changes

This ticket deliberately models queue capacity but does not authorize calls.
At the current denominator, a full interval makes 12,385 work items due every
600 seconds (20.64 scheduled items/second before retries). A proposed worker
configuration must demonstrate that its bounded per-item execution time,
concurrency, retry headroom, provider quotas, credential isolation, storage
retention and cost fit the interval. That decision belongs to #51; no runtime
configuration here starts a provider worker or expands a live rollout.

Change shard count only at an interval boundary:

1. Pause new claims and retain the old revision, queue receipt and shard count.
2. Allow current leases to finish or expire; emit an old-plan receipt that
   exposes any missing work rather than carrying it into a new plan.
3. Generate and verify the candidate plan from the same pinned manifest,
   checking identical identity cardinality and zero duplicate owners.
4. Start the new shard count only in the next interval, with a new receipt.
5. Roll back by pausing the candidate before new claims, restoring the prior
   shard count at the next boundary, and preserving both receipts for repair.

Do not rebalance an active interval or treat a new queue digest as completion
of unfinished old-plan work.
