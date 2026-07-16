# Public diagnosis snapshot

`datapan.health-public-diagnosis-snapshot.v1`은 이미 검토된 Health correlation receipt와
assertion evaluation만 browser-safe diagnosis로 옮기는 내부 입력 계약이다. 이 파일은
새 공개 route가 아니며 기존 `/v1/status` schema를 변경하지 않는다.

## Projection authority

Snapshot은 다음 identity가 모두 정확할 때만 진단을 만든다.

- Registry revision `f90d2d62258e50d562ff08b993c75bc0a4dad6fa`
- diagnostic vocabulary SHA
  `aa03c42960a59725b829b934ad07548dacb8f149c7a920a35a9e32c0459b49fc`
- correlation rule ID/version/SHA
- assertion policy path/set/version/artifact SHA
- 각 public operation ID와 `operation_revision_sha256`

Correlation의 `provider_outage/inferred`는 최소 affected 2개와 control 1개, exact rule,
현재 evidence timing을 요구한다. `observed` 승격에는 correlation producer가 연결한
authoritative provider notice reference가 추가로 필요하다. Snapshot에는 원본 observation,
notice URL, dataset ID, Gatus key/error 대신 affected/control count와 notice 연결 여부만
남는다.

Assertion은 exact asserted contract의 `fail`만 `contract_drift/inferred`로 공개한다.
Contract `pass`는 해당 차원의 evidence로 보존하지만 전체 서비스가 ready라고 주장하지
않는다. `presence`, `semantic`, `freshness`, `transport`의 현재 v1 정책은
`not_asserted`이므로 `not_observed`로 남는다. 단일 HTTP 실패나 timeout은 진단 근거가
아니다.

## Failure and privacy boundary

전체 version/policy binding이 잘못되면 snapshot을 거부한다. Operation 하나의 entry가
missing, stale, future, duplicate, unsupported, superseded, digest-mismatched, malformed,
out-of-operation이거나 leak field를 포함하면 그 operation만 `unknown` 또는 `rejected`로
닫힌다. 다른 operation과 Gatus availability는 유지된다.

허용 입력은 reviewed code/determination/owner/action ID, bounded times, exact contract pins,
source record SHA뿐이다. Provider body/value/text/URL, query, credential, Gatus internal name,
private dataset/operation metadata는 snapshot과 공개 응답에 들어갈 수 없다. 각 entry의
`projection_sha256`은 안전한 projection 전체의 변조를 검출한다.

Writer는 같은 directory에 완성 파일을 쓰고 `fsync`한 뒤 rename하며 directory도
`fsync`한다. Reader는 regular file과 512 KiB 한도를 확인한 뒤 한 file descriptor에서
전체 bytes를 읽는다. 이 경계로 reader는 partial update를 보지 않는다.

## Offline evidence

```sh
make diagnosis-snapshot-evidence
```

명령은 실제 reviewed correlation replay를 통해 아래 세 파일을 만든다.

- `out/public-diagnosis-snapshot.json`
- `out/diagnosis-projector-receipt.json`
- `out/diagnosis-doctor.json`

Doctor는 payload 값을 출력하지 않고 `accepted`, `not_observed`, `unknown`, `rejected`
count만 보고한다. CI는 이 산출물을 보존한다. Snapshot 생성과 merge는 image push,
provider call, deployment 또는 runtime rollout을 승인하지 않는다.
