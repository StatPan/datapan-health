# Generated Gatus receiver configuration

`health-gatus-config` renders Gatus' native `external-endpoints` section from
the verified Health canary links and, when installed, a pinned Registry
operation-observation plan. It only emits receiver entries. Provider HTTP
requests remain Health-worker work and are never configured as Gatus endpoint
URLs.

The generator binds its output to the exact base Gatus bytes, canary config,
verified API metadata artifact/source/catalog, Registry release manifest and
plan index, activation bytes, identity-map bytes, and generated config bytes.
The identity map is sorted by `(source_id, registry_operation_id)`. New
receiver keys are stable hashes of that exact pair. An operation overlapping
one of the ten legacy canaries reuses the existing key; the map lists the
legacy Health operation ID to suppress before generic dispatch when that
exact plan identity is activated.

Plan operations are inactive by default. An activation file is accepted only
with its separately configured SHA-256 pin and exact Registry revision/index digest. Each
selected identity must also have a complete request contract, a bound runtime
credential/quota policy, and explicit Registry admission. If the plan bundle
is not installed, generated artifacts say `plan_state: unavailable` with
`operation_plan_not_configured`, `known_plan_operations: 0`, and keep only the
legacy receiver set. That output is not whole-Registry coverage.

Compose runs the generator as a one-shot init service. Gatus starts only after
that service exits successfully and mounts the generated directory read-only.
The generated identity map and runtime dependency pin are private runtime
artifacts; the public status handler must continue using its separately pinned
read model and must not infer provider observations from Gatus heartbeats.

`health-scheduler` can consume the same verified bundle through its production
operation-plan controller. The controller remains disabled when both
`HEALTH_OPERATION_GATUS_ACTIVATION` and its `_SHA256` pin are absent. Setting
only one, failing any artifact binding, or failing the exact CLI bundle check
keeps operation readiness closed and prevents overlapping legacy canaries from
running. Once the activation and generated Gatus artifacts verify, the
one-second bounded controller owns due checks, durable attempt/history writes,
and an independent Gatus outbox. See [the runtime acceptance procedure](operation-plan-runtime.md)
for the complete opt-in input set and the separate `/operation-plan/ready`
signal.
