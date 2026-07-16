# Bounded correlation replay

Health correlation is an offline evidence derivation step. It does not alter
Gatus, the two-failure alert policy, the scheduler, public routing, or a
provider. The accepted rule is
`config/correlation/provider-outage.v1.json`; its exact bytes are represented
by the SHA-256 in every replay receipt.

## Evidence boundary

Each `health_observation` binds an immutable receipt reference to one accepted
Registry operation, its exact dependency class, and its Registry-owned probe
policy key and version. Correlation accepts only the exact non-secret canary
scope alias `datapan-health-public-canary-v1`; arbitrary values, hashes,
fingerprints, and credential-derived identifiers are rejected rather than
reflected into a receipt. Response bodies, rows, query values, provider prose,
and full request URLs are not part of this contract.

The v1 provider-outage rule accepts observations no more than 900 seconds old
at assessment time, with at most 30 seconds of clock skew. It requires:

- at least two distinct unhealthy operations in the exact requested dependency
  and reviewed canary scope;
- at least one current healthy control in that same dependency and credential
  scope; and
- failure categories limited to timeout, transport failure, or an exact 5xx
  provider failure.

A single timeout, 5xx, 401, or 403 therefore cannot select provider outage.
Auth failures are not accepted affected categories. Missing controls, stale
observations, mixed policies, unreviewed canary scopes, and cross-dependency evidence
remain `unknown`. Meeting the bounded Health rule produces only an `inferred`
provider outage.

## Provider notices and supersession

An `observed` provider outage additionally requires a reviewed notice
projection from `provider` or `provider_portal`. Its query-free HTTPS source
must be on an allowed provider host, and its immutable content digest, version,
effective interval, dependency, and optional operation allowlist must cover
every affected observation exactly.

Notice history is append-only. Versions must be contiguous and corrections or
withdrawals name the immediately prior version. The receipt retains considered
and superseded immutable notice references. Only the latest current revision is
eligible: a withdrawal removes the link; a corrected scope that no longer
covers the incident produces no link. Original observations and notice
revisions are never rewritten.

## Offline replay

Run a checked-in deterministic fixture without contacting a provider:

```sh
go run ./cmd/health-correlation \
  -replay testdata/correlation/observed-notice.json
```

The result contains counts and immutable references, not raw evidence. Input
ordering cannot change the receipt. The CI `correlation-replay` artifact uses
this command as an executable example; it is neither runtime state nor rollout
authority.

The v1 rule bytes and exact 900/30/86400-second semantics are pinned together.
Changing a bound under version 1 fails closed; a semantic change requires a new
implemented version, new canonical artifact digest, tests, and review.
