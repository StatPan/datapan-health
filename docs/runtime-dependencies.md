# Image-owned live runtime dependencies

The Health runtime image owns the compatible CLI, immutable Registry health
catalog/install provenance, and live configuration. The production scheduler
verifies the lock, binary ELF architecture and digest, manifest/catalog digests,
exact install provenance, and agreement with compiled canary pins before any
provider request. A mismatch keeps `/live` available and `/ready` at 503.
Runtime deployments must preserve the image's dependency/config paths.

`config/runtime-dependencies.json` records both published Linux CLI archives and
binary digests, exact CLI source/release, Registry source and immutable Dataset
payload/pointer identities. The builder downloads only fixed official GitHub/HF
paths, verifies the full canonical snapshot's manifest size and digest, then
omits that large source file from the final Health-only install. The final CLI
install contains exactly the executable, LICENSE, NOTICE, release manifest,
health catalog and deterministic install provenance. It contains no caches,
credentials, response rows or canonical source snapshot.

`scripts/verify-runtime-dependencies.sh IMAGE` compares image configuration bytes
with the reviewed source, then runs the bundled executable in a read-only
container with external networking disabled and a bounded temporary filesystem.
A synthetic loopback provider must receive exactly one explicit HTTP request.
The resulting receipt must be healthy, bound to the synthetic immutable
manifest/revision and redacted. A release name alone cannot satisfy this check.

The ARM64 publisher emits `statpan.datapan-health-runtime-release.v2`, including
seven exact `runtime_dependencies` fields and `gatus_config_sha256`. It retains
the four-member artifact and 900-second lifetime. Infra #1422 consumes these
identities under a separately reviewed rollout contract. Source merge and image
publication do not close Health #83 or authorize runtime/ingress activation.
Infra #1421 owns exact preimage, approval, migration/rollback, access limiting
and post-deployment acceptance. Archive tooling and full-population scheduling
retain their own existing configuration and proof boundaries.
