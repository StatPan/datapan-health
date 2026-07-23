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
  -output out/schedule-coverage.json
```

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
