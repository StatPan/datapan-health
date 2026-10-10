# Datapan public status boundary

`health-public` is a read-only adapter. It distinguishes Datapan-owned public
services from observations of external data dependencies; it does not deploy,
route, or prove availability of any Datapan product.

## Routes and scope

| Route | Contract | Meaning |
| --- | --- | --- |
| `GET /datapan/` | Korean HTML API directory | Searchable, paginated one-column list of all API metadata in the pinned `data.go.kr` Registry snapshot, with Korean title/institution/purpose and exact joined Health results. APIs with a recent result sort first, configured APIs next; every API remains searchable and paginated. |
| `GET /datapan/apis/{registry_api_id}/` | Korean HTML API detail | Full source description and API functions, paged at 50 rows. Shows status only for an exact configured-function join; never infers API-wide health. |
| `GET /datapan/services/` | Korean HTML | Datapan-owned service status and a separate aggregate scheduler readiness projection. |
| `GET /datapan/dependencies/` | Korean HTML | Results for the ten configured external API functions, with allowlisted explanation/actions and up to 50 Gatus result-receipt history points per function. |
| `GET /datapan/v1/services` | `datapan.service-status.v1` | Dataset API, Registry distribution, Datapan Web/Atlas, and Health itself. A service is `unknown` unless its own check supplies a public surface and immutable deployment identity. |
| `GET /datapan/v1/dependencies` | `datapan.dependency-observation.v1` | The ten Registry-owned `dpr-op-*` canaries. This is not a Datapan service SLA or catalogue-coverage claim. |
| `GET /datapan/v1/status` | `datapan.dependency-status-legacy.v1` | Dependency-only compatibility alias for one release. It emits `Deprecation: true`, `Sunset: Thu, 31 Dec 2026 23:59:59 GMT`, and links to both successors. |

The legacy alias can be removed only with a separately reviewed decision that
records one full release of consumer evidence, successor parity, a visible
warning period, and the exact removal release. It never represents
Datapan-owned service status.

The checked-in metadata artifact describes the complete pinned `data.go.kr`
Registry source snapshot at revision `d7dba637a06e345cba7ae058cba96fe53d3e532b`:
12,282 API entities, 12,662 REST/SOAP API operations, 8,871 separately
classified LINK operations, 473 operationless entries, and 416 source
institutions. This is not a complete inventory of every Registry adapter;
`registry_wide_metadata_complete` remains false. Counts describe source
metadata, not safe-to-call, entitled, or currently observed APIs. The Health
catalog configures ten exact API-function observations. This fixed Registry
snapshot is not a claim about the portal's current full registration state.
The HTML keeps the metadata source revision and Health observation-catalog
revision distinct in a disclosure. Its recent-result times and history points
are the times Gatus received status results, not original provider request
times. Each function's strip retains at most the latest 50 result-receipt
points, with only timestamp and success/failure; the public v1 JSON is unchanged.

HTML pages also show the private scheduler `/status` aggregate as “Datapan
관제”. The public adapter accepts only the pinned readiness schema, exact
configured-canary identity set, allowlisted reason codes and internally
consistent timestamps; it discards all per-canary rows and identities. It
uses a one-second timeout, one-second coalesced cache and the shorter of the
cache interval, scheduler-loop freshness deadline, and canary heartbeat
deadlines. A null, stale, invalid, or unavailable report becomes a generic
monitoring-system problem and never changes an API-function result.

Only inventory HTML accepts bounded navigation parameters: `/datapan/` accepts
`page` and `q`, and API detail accepts `page`. Search is limited to 128 Unicode
characters and 256 UTF-8 bytes; URL, host, credential, internal-target, and
query/path-shaped search values receive a generic Korean 400 response without
echo. JSON routes, services, and dependency HTML continue to reject query
parameters. Search responses use `no-store`; ordinary HTML uses a byte-derived
ETag and short cache. Listing and detail requests only read the pinned metadata
artifact and cached Gatus summary; they never start provider work.

The dependency adapter deliberately excludes Gatus key/name, dataset ID,
provider host/path/message, query data, receipt, credential identity, response
data, and support references. A missing, future, or heartbeat-expired canary
is `unknown`; it cannot promote an owned service. Diagnosis is projected only
from a separately reviewed accepted input, otherwise it is `unknown` with no
action IDs.

The Korean HTML projection displays only source-sanitized title, institution,
description, and operation-name metadata from the pinned artifact. Missing or
unsafe field states remain visible. Registry operation hashes and internal
Health IDs are used for exact joins and internal navigation only; endpoint
addresses, paths, request examples, query values, credentials, and response
rows are not rendered.

## Dependency observation and incident meaning

Each dependency operation keeps raw observation, incident, and diagnosis
separate. `availability` is the latest raw observation: `operational`,
`degraded`, or `unknown`. It is never a root-cause claim.

- `raw_observation_state` is `succeeded`, `failed`, or `unknown`.
- `incident_state` is `pending` after an isolated failure, `confirmed` after
  the configured consecutive-failure threshold, `recovering` after the first
  success following a confirmed incident, `operational` after the matching
  consecutive-success threshold, or `unknown` when observation is stale or
  missing.
- `consecutive_failure_threshold` and `pending_count` expose the bounded
  alert-state calculation without exposing provider requests or responses.

The reviewed ten-canary `scope` remains explicit in every dependency response:
it is neither whole-catalog coverage nor a data.go.kr/provider SLA. `observed_at`
is per operation; stale and missing observations retain no incident claim.

## `health-public` input files

The public process requires the byte-pinned API metadata artifact and source
pin, the reviewed operator-display artifact
(`config/registry/operator-operation-display.v1.json`), and its exact Registry
760 manifest/evidence subset
(`config/registry/operation-display-registry-760/`). The display artifact
contains operator-authored labels for four partial Registry identities; the
evidence subset supplies only the KOSIS and Seoul document facts it binds.
Missing or changed required inputs prevent startup, with a fixed failure-stage
label and no raw path, parser error, or input value in the log.

The complete-operation read model is a separate optional startup input. Its
plan root, image-owned plan pin, and read-only attempt-store directory must be
configured together using `REGISTRY_OPERATION_PLAN_ROOT`,
`REGISTRY_OPERATION_PLAN_PIN`, and `HEALTH_OPERATION_ATTEMPT_STATE`. If none
are configured, `health-public` still starts and serves the pinned API
directory and the existing ten-canary compatibility views; full-plan pages
remain unavailable. A partial or invalid plan configuration also fails closed
to unavailable operation progress. The public process reads the durable store
for current progress and never runs provider checks or fills missing results.
For a full-coverage claim, the plan release, all pinned artifacts, the runtime
binding, a complete read-model refresh, and the rendered-page acceptance must
each be verified separately.

When the scheduler's activated operation lane is enabled, `health-public` also
needs the same read-only `HEALTH_OPERATION_GATUS_ACTIVATION` and SHA-256 pin,
`HEALTH_GATUS_BASE_CONFIG`, generated config, identity map, and runtime pin.
It verifies the activation against the installed plan and the existing canary
config, then validates that `/status` reports every configured canary exactly
once as either a legacy row or a transferred ID. A transferred ID is accepted
only while the operation lane reports a fresh complete persisted-evidence
sweep; no legacy delivery is fabricated for it. If this bundle is missing or
does not match, self-readiness is unavailable.

## CORS and caching

`PUBLIC_STATUS_ALLOWED_ORIGINS` is required and contains comma-separated exact
HTTPS origins. JSON routes never reflect an unapproved origin, emit
credentials, accept an authorization header, or use a wildcard. Approved
GET/HEAD preflight returns only `GET, HEAD`; other origin, method, and header
shapes fail closed.

JSON responses and ordinary HTML pages use a byte-derived strong ETag and
`Cache-Control: public, max-age=30, stale-if-error=60, no-transform`.
`If-None-Match` returns 304. Search responses and errors use `no-store`; errors
are generic and contain no upstream/parser detail. JSON responses vary on
`Origin`; preflight also varies on its requested method and headers.

## Readiness report

`make public-status-doctor` produces the value-free
`datapan.public-status-doctor.v1` report without a Gatus or provider call. It
names both contracts, fixes the external scope at ten canaries, and reports the
four owned services with their explicit `unknown_reason`. It never turns a
dependency observation into a service incident or readiness claim.

When a private full-population schedule authority state is mounted, the same
Doctor path may include its bounded schedule receipt state and aggregate counts.
It contains no operation IDs, queue members, endpoints, provider values,
credentials, parameters, or response data, and does not change any browser
route or dependency coverage meaning.

## Local container smoke

The Compose `public-status` profile uses the private Gatus status URL and the
reviewed canary map. Add the scheduler profile to show its aggregate readiness;
its local configuration deliberately lacks an executable CLI and provider
credentials, so it cannot make provider calls:

```sh
docker compose --profile public-status --profile scheduler up --build gatus scheduler public-status
curl -H 'Origin: https://datapan.statpan.com' http://127.0.0.1:8082/datapan/v1/dependencies
curl -H 'Origin: https://datapan.statpan.com' http://127.0.0.1:8082/datapan/v1/services
```

`make smoke` verifies the dependency schema/identity and CORS boundary. Public
service checks remain `unknown` in this repository until the owning product
supplies its own reviewed immutable deployment identity. Opening a public
route, adding an origin, connecting a live service check, or deploying a new
runtime image is a separate infra-owned approval and rollout.
