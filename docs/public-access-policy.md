# Health read access and capacity policy

The Datapan status adapter remains a public read-only service. It accepts only
existing GET/HEAD routes and approved OPTIONS preflights. It does not accept
arbitrary operation IDs, targets, query parameters, credential uploads or
requests to start a provider check. CORS is browser sharing policy, not login
or protection against direct clients.

health-public now defaults to one process-wide budget of 20 requests/second,
a burst of 40, and 16 active requests. Excess frequency returns 429; exhausted
concurrency returns 503. Both use Retry-After: 1, no-store and a generic redacted
error. Approved browser origins can read Retry-After on rejected JSON reads.
The limiter never trusts X-Forwarded-For/Forwarded as identity, allocates no
per-client map, and cannot be bypassed by rotating spoofed addresses. This
bounds process capacity; it is not per-user fairness or authentication.

Flags --read-rate / --read-burst / --read-concurrent or PUBLIC_STATUS_READ_RATE /
PUBLIC_STATUS_READ_BURST / PUBLIC_STATUS_READ_CONCURRENT tune these budgets.
Values are validated (1..1000 requests/second, 1..2000 burst, 1..256 concurrent).
For multiple replicas each has its own budget; edge policy must bound the
aggregate and fair shares. Normal status viewers should use cache headers
and avoid polling more often than every 30 seconds.

The dependency and legacy status routes share one five-second snapshot cache
and one in-flight refresh with a five-second deadline. One viewer's cancellation
does not cancel other readers' refresh. Upstream errors are cached for one
second to bound retries. Failed refresh returns unavailable; expired healthy
data is not relabeled as a current observation. Original observed_at and
snapshot generated_at stay unchanged. Status reads never call providers.

Local Compose binds all published ports to 127.0.0.1. Scheduler /status and
/metrics are operational interfaces and must stay private. Source changes
here do not change deployed ingress.

## Required edge delivery

The current public Gatus UI/API is a separate upstream surface, retaining the
pinned upstream implementation. These adapter controls cover /datapan/*;
they do not limit direct public Gatus routes. The statpan-infra owner must
apply reviewed limits at the proxy to all status-host routes, constrain allowed
methods, preserve caching/CORS, keep scheduler metrics and external push routes
private, and verify allow/deny plus overflow/recovery at the deployed digest.
Do not trust forwarding headers without an explicit owned proxy trust chain.

If the selected product policy is login-only or permitted-network access,
apply that policy at the owned edge with real account/CIDR inputs before
claiming restricted use. This PR provides bounded public reads and an Infra
handoff; it does not fabricate users, credentials, allowlists or edge rollout.

Local reproduction: build the runtime image, then run
RUNTIME_IMAGE=datapan-health-runtime:test python3 scripts/public-access-proof.py.
The synthetic private source and real read-only runtime container verify a
100-reader burst, coalescing, upstream outage/recovery and forbidden requests;
aggregate-only evidence is saved in out/access-proof.json.
