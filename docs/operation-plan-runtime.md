# Operation-plan runtime acceptance

The scheduler's generic Registry worker is intentionally inactive until an
operator supplies a verified operation-plan release and an exact activation
file. The normal image and local Compose profile continue to use the existing
ten canaries. An activation without its SHA-256 pin, or any invalid artifact,
leaves `/operation-plan/ready` unavailable and blocks scheduler dispatch until
the inputs are corrected. Once the complete activation and its Gatus identity
mapping verify, only exact activated overlaps with legacy canaries are removed
from legacy dispatch. The scheduler's canonical `/status` projection carries
the exact transferred IDs and the operation-lane evidence expiry; it does not
invent legacy delivery timestamps for transferred rows.

The scheduler and Gatus must use the same immutable plan binding, activation,
generated Gatus config, identity map, and runtime pin. Mount these inputs
read-only, provide writable bounded attempt/quota/history state directories,
and provide a secret-backed credential-reference binding file. Do not place
credential values in the operation plan, generated artifacts, or status
responses.

| Input | Purpose |
| --- | --- |
| `REGISTRY_OPERATION_PLAN_ROOT`, `REGISTRY_OPERATION_PLAN_PIN` | Installed plan index/shards and their immutable runtime binding |
| `HEALTH_OPERATION_GATUS_ACTIVATION`, `HEALTH_OPERATION_GATUS_ACTIVATION_SHA256` | Exact activated `(source_id, registry_operation_id)` set and its pinned digest |
| `HEALTH_GATUS_BASE_CONFIG`, `HEALTH_GATUS_GENERATED_CONFIG`, `HEALTH_GATUS_IDENTITY_MAPPING`, `HEALTH_GATUS_RUNTIME_PIN` | Base config and the matching generated Gatus receiver/configuration artifacts |
| `REGISTRY_API_METADATA`, `REGISTRY_API_METADATA_PIN` | Pinned Korean Registry metadata used to verify the registered identities |
| `RUNTIME_DEPENDENCY_LOCK`, `DATAPAN_BIN` | Immutable CLI dependency lock and image-owned CLI executable; the CLI source revision must match the reviewed runtime contract |
| `HEALTH_OPERATION_CREDENTIAL_BINDINGS` | Secret-mounted reference-to-credential binding file for the activated plan |
| `HEALTH_OPERATION_HISTORY_MAX_BYTES` | Explicit maximum size for the validated receipt-history store |
| `HEALTH_OPERATION_ATTEMPT_STATE`, `HEALTH_OPERATION_QUOTA_STATE`, `HEALTH_OPERATION_HISTORY_STATE` | Durable writable state roots for attempt fences, quota leases, and validated receipts |
| `HEALTH_OPERATION_RECEIPT_DIRECTORY` | Private receipt staging directory |
| `GATUS_URL`, `GATUS_TOKEN` | Gatus receiver and secret used by the independent keyed outbox |

When the plan lane is active, `health-public` must receive the same read-only
plan, activation, generated Gatus config, identity map, and runtime-pin inputs.
It independently verifies that bundle, then accepts readiness only when the
legacy canary rows and the exact activated-overlap IDs form a complete,
disjoint partition of the pinned canary set. Transferred IDs require the
plan's current full evidence sweep and expiry. Missing activation inputs leave
public self-readiness unavailable instead of treating missing rows as healthy.

Worker limits are explicit and bounded. `HEALTH_OPERATION_MAX_CONCURRENT` is
1–32; `HEALTH_OPERATION_MAX_STARTS_PER_SECOND` and
`HEALTH_OPERATION_MAX_DELIVERIES_PER_SECOND` cannot exceed that concurrency;
`HEALTH_OPERATION_CANDIDATE_SCAN_PER_SECOND` is 1–256. The scheduler compares
those caps and the plan's reviewed quota scopes/cadences/deadlines before
starting provider work. An infeasible plan reports `capacity_infeasible` and
does not dispatch provider requests; already accepted outbox records remain
eligible for independent delivery retries. Do not invent or raise a provider
quota to make this calculation pass.

Generate Gatus receiver artifacts from the same mounted plan and activation
using `/health-gatus-config`, with its `-operation-plan-root`,
`-operation-plan-pin`, `-activation`, `-activation-sha256`, and `-output-dir`
arguments. Give the Gatus process the generated `config.yaml`; give the
scheduler the matching generated config, `operation-identity-map.json`,
`runtime-dependencies.json`, plan binding, activation, and their configured
pins. Keep the identity map and runtime pin private. Rebuild the scheduler
image with `VCS_REF` set to its exact 40-character source commit so receipt
history is sealed to the validating build.

The base Gatus configuration must retain at least one ordinary endpoint or
suite. Generated `external-endpoints` are receipt receivers and do not satisfy
that startup requirement; the generator rejects a receiver-only base. Offline
capacity fixtures use only a loopback Gatus health endpoint and contain no
provider destinations.

After controlled activation, check `/operation-plan/status` for the pinned
Registry revision/index, admitted count, capacity assessment, recent controller
pass, execution/readback counters, and a generic failure reason. An enabled
plan also participates in canonical `/ready`, `/status`, and
`datapan_health_scheduler_ready`. A disabled plan leaves legacy readiness
unchanged. An enabled plan reports `operation_plan_unavailable` until a bounded
full sweep confirms fresh, exact-plan durable attempt evidence for every
admitted identity and the required per-key delivery proof. A valid provider
failure or indeterminate result can still prove that the observer pipeline is
working; readiness does not claim provider health. The public
`/datapan/v2/operations` reader is based on the pinned operation identities and
durable Health attempts; a Gatus heartbeat alone is never provider evidence.
Verify exact per-key Gatus readback and persisted Health timestamps before
claiming delivery. Keep runtime credentials and raw provider output out of
logs and public status.

Local source QA is provider-free and uses the repository's pinned Gatus image:

```sh
make operation-plan-full-population
make operation-plan-gatus-integration
make operation-plan-gatus-capacity
```

The first command derives a synthetic scheduler/storage/read-model fixture:
12,662 identities from the pinned Gov metadata plus four identities from an
explicit partial-provider fixture. It reconciles bounded scheduler dispatch
using a test receipt executor, validated receipt history, durable attempts,
exact generated Gatus-key bookkeeping, and bounded public paging. This fixture
does not claim to enumerate the entire known Registry population, run the
released CLI, or contact Gatus. The second starts the pinned Gatus container
on loopback and verifies one synthetic receipt through the production Gatus
push/readback adapter using the synthetic worker fixture. The third loads the
same generated fixture identity mapping into the exact pinned Gatus image,
records generated config bytes, startup time, and container memory, then
verifies a bounded spread of per-key receipts and readbacks. Its configuration
does not contact provider destinations. The opt-in
`TestOperationPlanActualCLIProviderGatusIntegration` target exercises the
production child runner against an isolated synthetic provider and local
pinned Gatus; its smoke and full modes are distinct from these source-QA
fixtures. Existing probe-runner tests separately verify production child
arguments, executable digest, private receipt path, and receipt validation.
These tests do not establish deployment or live-provider acceptance.
