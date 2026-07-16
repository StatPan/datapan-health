# Browser-consumable public status contract

`health-public` is a separate, read-only adapter for Datapan Web and other
approved anonymous browser clients. It does not replace the Gatus HTML status
page and this repository does not route or deploy it.

## Response

`GET /v1/status` returns `datapan.health-public-status.v1`. Every configured
canary appears exactly once under its Registry-owned `dpr-op-*` operation ID.
The response deliberately excludes the internal Gatus key and name, dataset
ID, operation display text, provider host/path/message, query data, receipt,
credential identity, evidence references, response data, and support
references.

Availability and diagnosis remain separate. The adapter derives only
`operational`, `degraded`, or `unknown` availability from a current Gatus
observation. A missing, future, or heartbeat-expired observation is `unknown`.
Until #21 or #22 supplies a separately reviewed current diagnosis, the public
diagnosis is exactly `unknown` with no action IDs. `ProjectPublicDiagnosis`
defines the allowlisted projection for a future accepted diagnostic input; an
unknown code, malformed ownership, or unsafe action ID degrades to the same
empty `unknown` diagnosis instead of changing availability.

The exact response schema is
`schemas/datapan.health-public-status.v1.schema.json`. Unknown schema versions
are not coerced into v1.

## CORS and caching

`PUBLIC_STATUS_ALLOWED_ORIGINS` is required and contains comma-separated exact
HTTPS origins. The service never reflects an unapproved origin, emits
`Access-Control-Allow-Credentials`, accepts an authorization header, or uses a
wildcard. Approved GET/HEAD preflight returns only `GET, HEAD`; a denied origin,
method, or requested header fails closed.

Successful responses have a byte-derived strong ETag and
`Cache-Control: public, max-age=30, stale-if-error=60, no-transform`.
`If-None-Match` returns 304. Errors are generic, `no-store`, and never contain
an upstream URL, response, or parser detail. `Vary: Origin` keeps browser
origin decisions cache-safe.

## Local container smoke

The Compose `public-status` profile uses the private Gatus status URL and the
reviewed canary map:

```sh
docker compose --profile public-status up --build gatus public-status
curl -H 'Origin: https://datapan.statpan.com' http://127.0.0.1:8082/v1/status
```

`make smoke` also verifies approved and denied browser origins, preflight,
schema identity, exact operation identity, and the public leakage boundary.
Opening a public route, adding an origin, or deploying a new runtime image is a
separate infra-owned approval and rollout.
