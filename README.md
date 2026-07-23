# Datapan Status

공공데이터 API가 고장 난 것처럼 보일 때 가장 먼저 확인하는 공개 상태 페이지의 최소 구현입니다. UI는 익숙한 한 열 세로 목록을 유지하며, [upstream Gatus v5.36.0](https://github.com/TwiN/gatus/releases/tag/v5.36.0)을 수정 없이 사용합니다.

## 로컬 실행

Go 1.26.4와 Docker Compose v2가 필요합니다.

```sh
make test
make quality
make smoke
make archive-smoke
```

`docker compose --profile scheduler up scheduler` starts the separate
scheduler health surface on `:8081` (`/live`, `/ready`, `/metrics`). The local
profile deliberately has no Datapan CLI credential or provider executable, so
it cannot call a real provider.

`health-public` provides separate versioned browser contracts defined in
[docs/public-status-api.md](docs/public-status-api.md): owned service status at
`/datapan/v1/services` and external canary observations at
`/datapan/v1/dependencies`. The latter maps exact Registry operation identity
to current Gatus availability and never promotes a Datapan-owned service.
Owned services fail closed to `unknown` until their own product supplies a
reviewed immutable deployment identity. Both use an explicit non-credentialed
CORS allowlist and are not routed or deployed by this repository.

`make smoke`는 Gatus, ephemeral PostgreSQL, runner 이미지를 빌드하고 CLI 계약과 같은 형태의 합성 receipt 두 개를 push합니다. Gatus가 PostgreSQL table을 생성하고 healthy/unhealthy 상태를 기록했는지도 확인한 뒤 컨테이너를 정리합니다. 로컬 DB user/password는 개발 전용 비밀값이 아닌 `datapan_health` / `local-dev-only`입니다. 수동으로 화면을 유지하려면 다음을 실행합니다.

```sh
docker compose up -d gatus
docker compose --profile fixtures run --rm runner-healthy
docker compose --profile fixtures run --rm runner-unhealthy
```

## Runtime images

`runtime` is the minimal runner/scheduler/public-status image. `archive` is a separate
batch-only image containing `/health-archive` and the pinned `hf` CLI; it is
the only image that may receive `HF_TOKEN` at runtime. Neither image contains
a credential. `make image-smoke` builds both images and performs an offline
synthetic publish check with a fake `hf` command. Release, digest promotion,
and rollback inputs for `statpan-infra#475` are in
[docs/release-images.md](docs/release-images.md).

로컬 기본 토큰은 합성 테스트 전용입니다. 실제 환경에서는 `GATUS_TOKEN`을 secret으로 주입해야 하며 Git, receipt, URL 또는 로그에 넣지 않습니다. 이 저장소는 배포하지 않으며 `statpan-infra`를 수정하지 않습니다.

## Receipt 계약

M003의 원인 진단 범위, 현재 구분 가능한 증거, 공통 계약에 필요한 최소 필드와
호환성 경계는 [diagnostic evidence boundary](docs/diagnostic-evidence-boundary.md)에
정리되어 있습니다. 이 문서는 Registry PR #569에서 병합된
`datapan.diagnostic-envelope.v1` draft의 Health 소비자 요구사항이며, Registry #567의
evidence mapping과 #568의 소비자 호환성 증거 전에는 runtime/publication 권위로
사용하지 않습니다.

입력 계약은 merged `datapan-cli`의 `datapan.health-probe.v1`입니다. 이 저장소는 CLI commit `2fc8343993b7704b50f7d50fcba2642fca439c7f`에서 가져온 [pinned schema](schemas/datapan.health-probe.v1.schema.json)와 [provenance](schemas/PROVENANCE.md)를 보관합니다. runner는 이 schema를 embed하여 runtime에 검증하고, CI test는 합성 healthy/unhealthy CLI-style receipt의 호환성과 pinned digest를 확인합니다.

receipt의 `probe_id`는 CLI가 생성하는 UUID이며 공개 서비스 식별자가 아닙니다. `config/canaries.json`은 immutable `operation.operation_key`를 Gatus external endpoint key에 명시적으로 매핑합니다. 알 수 없거나 중복된 operation은 push하지 않습니다.

Gatus에는 `assessment.outcome`, `assessment.category`, `observation.latency_ms`만 projection합니다: `healthy` outcome은 success, 나머지는 failed이며 public error string은 enum-only `outcome:category`입니다. dataset ID, endpoint host/path, provider code/message, reason code, next actions, safe parameter names, query data, credential, body 및 response row는 Gatus URL/error/log에 넣지 않습니다.

## Bounded correlation replay

`health-correlation`은 immutable Health observation reference와 검토된 provider-notice
projection으로부터 redacted offline receipt를 결정적으로 생성합니다. 동일 dependency와
reviewed non-secret canary scope에서 여러 affected operation과 healthy control을 모두 요구하므로 단일
timeout 또는 5xx만으로 provider outage를 확정하지 않습니다. 상세 계약과 notice
supersession 규칙은 [bounded correlation replay](docs/correlation-replay.md)에 있습니다.
이 명령은 alert policy, public status output, provider state 또는 deployment를 변경하지
않습니다.

## 구조와 저장 경계

```text
CLI-style redacted receipt -> strict Go adapter -> Gatus external endpoint -> public vertical UI
                                  |                         |
                         local ReceiptSink       PostgreSQL live state
```

Gatus live state와 UI history는 PostgreSQL에만 둡니다. Production은 `statpan-infra#472`의 platform PostgreSQL에서 dedicated `datapan_health` database와 least-privilege `datapan_health` role을 만들고, runtime secret/render boundary가 `GATUS_DATABASE_URL`을 주입합니다. runner는 PostgreSQL에 연결하지 않습니다. Local Compose/CI smoke만 ephemeral PostgreSQL container를 사용합니다.

`ReceiptSink`는 detailed but redacted receipt 보존을 교체 가능한 경계로 만들며, MVP 구현은 권한 `0600`의 로컬 JSONL append sink입니다. 이 sink만 receipt의 dataset/provenance/operation metadata를 보존합니다.

Hugging Face Dataset은 선택적 장기 archive만 담당합니다. 향후 별도 batch worker가 로컬 redacted receipt를 시간/일 단위로 모아 commit할 수 있지만, 요청 경로에서 commit하지 않고 heartbeat나 live 상태 판단에 사용하지 않습니다. HF 장애가 Gatus push를 막아서는 안 되며 transactional database로 취급하지 않습니다.

## Long-term Parquet archive

`health-archive` is a separate batch command, not part of `health-runner` or the Compose live-status path. It accepts local, redacted receipt JSONL and writes deterministic UTC partitions for ZSTD-compressed `observations`, `incidents`, `daily_rollups`, and `services`. A checkpoint makes re-runs and interrupted local batches idempotent; monthly compaction is verified with DuckDB before it replaces a completed monthly file.

```sh
go run ./cmd/health-archive -input RECEIPTS.jsonl -output archive
go run ./cmd/health-archive -input RECEIPTS.jsonl -output archive -publish
```

The public observation schema is [datapan.health-archive.v1](schemas/datapan.health-archive.v1.schema.json). It is a strict projection: public service identity, UTC time, registry revision, enum outcome/category, latency, data/schema/freshness state, and schedule tier. It excludes all dataset IDs, endpoint URLs/paths, provider details, query data, credentials, response rows, reason code, and next actions. The [dataset card](dataset-card/README.md) provides the public schema, privacy rules, cadence, provenance, and DuckDB examples.

Publishing is optional and retried only after a complete local export; it is never called by the live runner. The publisher stages only Parquet plus the safe manifest and dataset card, excluding checkpoints. `make hf-publish-smoke` performs an authenticated CLI availability check without printing credentials and records a skipped result if the environment has no usable Hugging Face CLI/session.

## Cadence, incidents, and retention

`config/canaries.json` is a versioned scheduling boundary: Tier A/B/C mean 5/10/15 minute intended schedules. It also requires a heartbeat of exactly two schedule intervals and `2` consecutive failed observations before the configured Gatus incident alert fires. Direct API unhealthy observations still push immediately; Gatus’s alert/incident threshold avoids public alert noise from a single observation. Runner silence is separate: heartbeat fires only after two missed schedules.

`health-runner` remains intentionally one-shot. The separately deployed `health-scheduler` consumes this same Registry-pinned cadence boundary with bounded concurrency and jitter; it does not add an archive or Hugging Face dependency to the live delivery path.

## Immutable operation denominator

The ten public service canaries are a deliberately small observation input,
not a coverage denominator. `make manifest-verify` validates the Health-owned,
redacted receipt and the vendored immutable Registry operation-manifest fixture.
It reproduces 12,385 operation-status subjects (12,350 REST and 35 SOAP) and
7,365 API metadata records. A status subject is the Registry operation identity:
REST includes its method and SOAP includes its action. API, dataset, host, and
endpoint are metadata only and cannot collapse subjects.

The fixture is pinned to Registry commit `420edc34b16d1243e2a2389226615fff9e5b708f`.
It is contract-test input: it can prove a deterministic full-population queue,
but it does not attach a provider worker or change the ten-canary scheduler
boundary.

## Full-population schedule coverage

`health-schedule-coverage` deterministically queues every pinned Registry
operation identity once per ten-minute UTC interval. It emits private queue
coverage evidence (expected, assigned, attempted, completed, late and missing)
bound to the Registry revision and manifest digest. It does not invoke a
provider, alter the ten-canary scheduler, or change the archive policy. See
[schedule coverage](docs/schedule-coverage.md) for lease/fencing semantics,
capacity assumptions, shard-count changes and rollback.

## Scheduler

`health-scheduler` is the composition layer for ticket #4. It pins the signed
Registry `v2026.07.14` ten-canary catalog in `config/registry`, selects reviewed
`operation_id` values from `config/canaries.json`, and invokes only the CLI’s
documented one-shot surface: `datapan verify --ref … --operation … --health
--output … --json`. CLI owns Registry trust, safe parameter generation,
timeouts, request budget, and receipt classification; the scheduler validates
the returned receipt against the pinned entry and invokes the existing
`health-runner` adapter exactly once.

The pinned canary configuration separately records the immutable Registry
Dataset revision, catalog source SHA-256, release tag and manifest SHA-256.
They have distinct meanings: public archive rows use the Dataset revision,
while the source SHA validates the signed catalog input and must never replace
that revision.

Slots are aligned to cadence boundaries and receive deterministic, bounded
jitter. A state file is fsynced before an invocation claims a slot. Restarting
therefore skips an in-flight/overdue slot rather than replaying it; there is no
catch-up burst. Global concurrency is capped at two and a canary cannot overlap
itself. The catalog’s request budget is one, so provider/CLI retries are
intentionally forbidden: a timeout or rate-limit receipt is delivered as-is,
not amplified into more provider traffic. Adapter delivery is also single-shot
because it is not externally idempotent.

For every invocation, the CLI receives `--timeout` exactly equal to the pinned
catalog entry’s `execution.timeout_ceiling_ms`. The scheduler also applies a
deadline of that ceiling plus one second solely to allow the CLI to atomically
write its redacted timeout receipt. If the child still leaves no valid receipt,
the scheduler writes a redacted `indeterminate/timeout` (or
`indeterminate/indeterminate`) receipt from the pinned catalog and pushes it
as a failed external status. It never reads or logs child output, so a missing
receipt cannot expose request data or leave a stale successful public status.

Each probe stages its receipt in a unique, mode-0700 directory below the
configured scheduler state path (the mounted receipt volume in production),
then removes that directory after delivery or failure. The scheduler never
uses the container root `TMPDIR` for receipts. If that mounted boundary is not
writable, it records a bounded redacted scheduler failure without starting the
CLI; it does not weaken the read-only root filesystem or expose filesystem
diagnostics.

Registry가 승인한 operation assertion policy의 정확한 revision 아래에서만 contract,
presence, semantic, freshness를 판정한다. 현재 v1은 contract field vocabulary만
asserted이며, 나머지 차원과 빈 관찰은 실패나 stale로 추론하지 않는다. 고정된 계약,
판정 결과, 안전한 evidence 경계는
[assertion policy compatibility](docs/assertion-policy-compatibility.md)에 설명한다.

공개 어댑터는 Gatus availability와 reviewed diagnosis snapshot을 독립적으로 합성한다.
진단 파일이 없거나 일부 operation이 stale·future·중복·변조된 경우 해당 진단만
`unknown`으로 닫히며 availability는 유지된다. snapshot 생성, atomic update, doctor와
runtime 비배포 경계는 [public diagnosis snapshot](docs/public-diagnosis-snapshot.md)에
정리되어 있다.

Provider credentials are passed only to the CLI child through the explicit
comma-separated `CLI_CREDENTIAL_ENV` variable-name allowlist. Its non-secret
runtime state (for example `DATAPAN_HOME`) is separately allowlisted through
`CLI_RUNTIME_ENV`. Do not include `GATUS_TOKEN` in either list. The adapter
child receives only its Gatus/archive settings; the scheduler never logs CLI or
provider output. A real deployment must mount a pinned `datapan` CLI binary plus
its immutable Registry installation and state directory; this repository does
not deploy or alter `statpan-infra`.

Gatus retains at most 2,016 results per endpoint (seven days at the fastest five-minute tier) and 100 state-change events. Observation volume is `288×A + 144×B + 96×C` results/day for A/B/C canaries. With twenty canaries entirely in one tier, that is 5,760 / 2,880 / 1,920 observations/day; seven-day maxima are 40,320 / 20,160 / 13,440 results. Platform backup, restore, and longer retention are infra-owned under `statpan-infra#472`, not a second application persistence path.
