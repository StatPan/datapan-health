# Diagnostic contract compatibility

Issue #19 adds an offline, fail-closed consumer boundary for the exact
`datapan.diagnostic-envelope.v1` bytes accepted by Registry #566 and #567. It
does not add a public API, CORS policy, incident correlation, semantic/freshness
policy, UI, or deployment.

## What is accepted

`config/registry/diagnostic-contract-pin.json` binds three reviewed Registry
artifacts and Registry merge commit
`8c5d397f13929ec2b85e63e4ca600887f37929b8`:

- the diagnostic envelope JSON Schema;
- the deterministic data.go.kr evidence mapping;
- the Health consumer packet and its eleven fixtures.

The loader verifies every SHA-256 before compiling the schema. It accepts only
`schema_version=datapan.diagnostic-envelope.v1`; unknown versions, enum values,
fields, stale Registry revisions, and artifact drift fail closed. Accepted raw
bytes are represented by a SHA-256 digest and are not copied into Gatus or the
public archive.

## Operation identity bridge

The existing signed Health probe catalog remains the operation authority. A
diagnostic subject resolves only when all of these values agree exactly:

1. Registry source and provider IDs are `data_go_kr`;
2. `subject.operation_id` occurs exactly once in the configured canary list;
3. `subject.dataset_id` matches the catalog entry for that operation;
4. the catalog provider is exactly `data.go.kr`;
5. the diagnostic contract is pinned to the accepted Registry merge commit.

The result binds the Registry operation ID to the existing Gatus endpoint key,
which is the current Health service identity. Unknown, duplicate, fuzzy,
cross-operation, or revision-mismatched identities are rejected. The diagnostic
cause and actions are deliberately absent from `Summarize`, so this bridge
cannot alter Gatus success, error, cadence, or alert thresholds.

## Redaction boundary

The schema requires all eight sensitive-content assertions to be false. Health
also rejects forbidden producer fields, authorization values, URLs, and
hash-shaped secret material before normalization. Decoder errors are bounded
messages and never echo input. Tests cover secret values and hashes,
authorization headers, credential-bearing URLs, raw provider text and URLs,
response bodies, and user identity. Existing Gatus and archive tests continue
to prove that only their minimized v1 projections cross those boundaries.

## Exact-head receipt

CI runs the full test and container gates before generating a machine-readable
receipt for the exact GitHub commit under test:

```sh
make test
make quality
make build
make image-smoke
make archive-smoke
make diagnostic-compatibility HEALTH_HEAD="$(git rev-parse HEAD)"
```

The generated `out/diagnostic-compatibility.json` binds the Health commit,
Registry revision, three contract digests, eleven fixture digests, ten exact
operation/service bindings, required test names, and unchanged exposure
boundaries. CI uploads it as `diagnostic-compatibility-<commit>`. Registry #568
can consume that exact-head artifact as Health's compatibility proof; the
generated receipt is not a runtime or rollout authorization.
