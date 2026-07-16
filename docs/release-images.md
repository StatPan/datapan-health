# Immutable runtime images

Ticket #7 supplies application-owned OCI artifacts for the runtime request in
`statpan-infra#475` / PR #476. It does not publish an image, materialize a
secret, deploy a Compose project, or enable ingress.

## Role split

| Infra input | Docker target | Contents | Must not contain |
| --- | --- | --- | --- |
| `DATAPAN_HEALTH_IMAGE` | `runtime` | `/health-runner`, `/health-scheduler`, `/health-public` | `/health-archive`, `hf`, Python, Hugging Face dependencies |
| `DATAPAN_HEALTH_ARCHIVE_IMAGE` | `archive` | `/health-archive`, pinned `hf` CLI | Gatus runtime settings or an `HF_TOKEN` value |

`runtime` is a scratch image. `archive` is intentionally separate because
DuckDB's archive compaction library is glibc-targeted and because the publisher
requires the exact `hf` command selected by `internal/archive.HFCLI`. The
archive is batch-only and isolated by infra's separate Compose project; it
cannot join the live Gatus/scheduler network.

Pinned bases and runtime dependency set are recorded in `Dockerfile` and
`docker/hf-requirements.txt`: Go 1.26.4 Alpine for the static live binaries,
Go 1.26.4 Bookworm plus Python 3.13 Bookworm for the archive, and
`huggingface-hub==1.0.0` with its fully version-pinned CLI set. Image labels
record source, revision, and a deterministic release creation time supplied by
the build script.

## Checks

```sh
make test
make quality
make image-smoke
```

`image-smoke` builds both targets, proves all assigned executables start,
starts scheduler readiness without a provider or HF dependency, and asserts the
live filesystem does not contain archive tooling. It then runs an archive
publish using only the mounted `scripts/testdata/fake-hf` command and the
synthetic `hf-smoke-not-a-secret-7` runtime token. The test checks the fake
upload arguments, emitted archive files, image config/history, and all exported
image layers: that token must not appear in any of them. No network upload or
real Hugging Face credential is used.

## Release handoff to infra

Build the target platform as local OCI archives; this command never pushes:

```sh
PLATFORM=linux/arm64 OUTPUT_DIR=dist/images ./scripts/build-release-oci.sh
```

The command emits `runtime.oci.tar`, `archive.oci.tar`, checksums, and
`infra-image-inputs.env`. The latter contains the exact OCI manifest digests
that an approved release tool must preserve when it promotes the archives to:

- `ghcr.io/statpan/datapan-health-runtime@sha256:...`
- `ghcr.io/statpan/datapan-health-archive@sha256:...`

Before providing the values to infra, an app owner must verify the promoted
registry digest equals the generated manifest digest, preserve the SHA-256
checksums and source revision as release evidence, and fill the prior deployed
pair in the generated rollback fields. Copy the two current and two prior
references into the separate mode-0600 infra role bundles; never place a tag,
`HF_TOKEN`, `GATUS_TOKEN`, or database URL in this repository, image label,
image argument, or release manifest.

For rollback, stop scheduler/archive work and set both current inputs back to
the recorded `*_PREVIOUS` immutable references. PostgreSQL restore is a
separate approved recovery action under infra; image rollback does not alter
the live database.
