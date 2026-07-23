# Datapan public status boundary

`health-public` is a read-only adapter. It distinguishes Datapan-owned public
services from observations of external data dependencies; it does not deploy,
route, or prove availability of any Datapan product.

## Routes and scope

| Route | Contract | Meaning |
| --- | --- | --- |
| `GET /datapan/` | HTML overview | Explains the two scopes. |
| `GET /datapan/services/` | HTML | Datapan-owned services only. |
| `GET /datapan/dependencies/` | HTML | External dependency observations only. |
| `GET /datapan/v1/services` | `datapan.service-status.v1` | Dataset API, Registry distribution, Datapan Web/Atlas, and Health itself. A service is `unknown` unless its own check supplies a public surface and immutable deployment identity. |
| `GET /datapan/v1/dependencies` | `datapan.dependency-observation.v1` | The ten Registry-owned `dpr-op-*` canaries. This is not a Datapan service SLA or catalogue-coverage claim. |
| `GET /datapan/v1/status` | `datapan.dependency-status-legacy.v1` | Dependency-only compatibility alias for one release. It emits `Deprecation: true`, `Sunset: Thu, 31 Dec 2026 23:59:59 GMT`, and links to both successors. |

The legacy alias can be removed only with a separately reviewed decision that
records one full release of consumer evidence, successor parity, a visible
warning period, and the exact removal release. It never represents
Datapan-owned service status.

The dependency adapter deliberately excludes Gatus key/name, dataset ID,
provider host/path/message, query data, receipt, credential identity, response
data, and support references. A missing, future, or heartbeat-expired canary
is `unknown`; it cannot promote an owned service. Diagnosis is projected only
from a separately reviewed accepted input, otherwise it is `unknown` with no
action IDs.

## CORS and caching

`PUBLIC_STATUS_ALLOWED_ORIGINS` is required and contains comma-separated exact
HTTPS origins. JSON routes never reflect an unapproved origin, emit
credentials, accept an authorization header, or use a wildcard. Approved
GET/HEAD preflight returns only `GET, HEAD`; other origin, method, and header
shapes fail closed.

JSON and HTML responses use a byte-derived strong ETag and
`Cache-Control: public, max-age=30, stale-if-error=60, no-transform`.
`If-None-Match` returns 304. Errors are generic, `no-store`, and contain no
upstream/parser detail. JSON responses vary on `Origin`; preflight also varies
on its requested method and headers.

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
reviewed canary map:

```sh
docker compose --profile public-status up --build gatus public-status
curl -H 'Origin: https://datapan.statpan.com' http://127.0.0.1:8082/datapan/v1/dependencies
curl -H 'Origin: https://datapan.statpan.com' http://127.0.0.1:8082/datapan/v1/services
```

`make smoke` verifies the dependency schema/identity and CORS boundary. Public
service checks remain `unknown` in this repository until the owning product
supplies its own reviewed immutable deployment identity. Opening a public
route, adding an origin, connecting a live service check, or deploying a new
runtime image is a separate infra-owned approval and rollout.
