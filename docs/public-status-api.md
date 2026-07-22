# Datapan public status boundary

## Public presentation and redaction boundary

The public adapter is the only supported Datapan status presentation surface.
It reads Gatus only as an internal availability input and discards the Gatus
endpoint key, endpoint name, group, URL, host, port, query string, and probe
target before creating a public document or HTML card.

Each external-dependency card obtains its primary display name from the
SHA-pinned Registry health-probe catalog at
`entries[].aliases.operation_name`. The catalog is loaded through
`config/canaries.json` and its `catalog_sha256`; it is not translated from a
Gatus slug. A missing, non-Korean, URL-like, or otherwise unsafe catalog name
fails the public source closed rather than falling back to an operation ID or
English endpoint label.

The explicit presentation mapping is deliberately small: the pinned
`data.go.kr` provider maps to `공공데이터`; owned records are headed
`Datapan 서비스`; external observations are headed `외부 데이터 의존성`.
The only public external link is the canonical dataset-entry reference derived
from the pinned numeric `dataset_id`:
`https://www.data.go.kr/data/{dataset_id}/openapi.do`. Probe endpoints are not
links and are never text in the public response.

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
