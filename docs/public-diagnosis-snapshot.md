# Public diagnosis snapshot

`datapan.health-public-diagnosis-snapshot.v1`은 이미 검토된 Health correlation receipt와
exact assertion request만 browser-safe diagnosis로 옮기는 내부 입력 계약이다. 이 파일은
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

Assertion projector는 외부에서 산출한 outcome/reason/count를 입력받지 않는다. `assessed_at`,
operation revision, exact policy binding, dimension과 최소화된 response field name으로 구성된
request를 pinned Health evaluator로 직접 재평가한다. Request 전체 SHA가 source reference가
되므로 `assessed_at`만 다시 포장해 같은 평가처럼 제출할 수도 없다. 평가 결과의
`observed_field_count`는 0 이상이어야 하며 snapshot에도 함께 고정된다.

Exact asserted contract의 `fail`만 `contract_drift/inferred`로 공개한다.
Contract `pass`는 해당 차원의 evidence로 보존하지만 전체 서비스가 ready라고 주장하지
않는다. `presence`, `semantic`, `freshness`, `transport`의 현재 v1 정책은
`not_asserted`이므로 `not_observed`로 남는다. 단일 HTTP 실패나 timeout은 진단 근거가
아니다.

## Failure and privacy boundary

전체 version/policy binding이 잘못되면 snapshot을 거부한다. Operation 하나의 entry가
missing, stale, future, duplicate, unsupported, superseded, digest-mismatched, malformed,
out-of-operation이거나 leak field를 포함하면 그 operation만 `unknown` 또는 `rejected`로
닫힌다. 다른 operation과 Gatus availability는 유지된다.

Reader는 source kind별로 검토된 진단 tuple 전체를 고정한다. Correlation은
`provider_outage/{inferred|observed}/provider/check_provider_status/reissue_credential`, assertion
fail은 `contract_drift/inferred/shared/refresh_contract/reissue_credential`만 허용한다. Entry가
자기 `projection_sha256`을 다시 계산했더라도 다른 owner/action/determination 조합은 거부한다.

허용 입력은 이 reviewed tuple, bounded times, exact contract pins, source request/receipt SHA뿐이다.
Provider body/value/text/URL, query, credential, Gatus internal name,
private dataset/operation metadata는 snapshot과 공개 응답에 들어갈 수 없다. 각 entry의
`projection_sha256`은 안전한 projection 전체의 변조를 검출한다.

Writer는 같은 directory에 완성 파일을 쓰고 `fsync`한 뒤 rename하며 directory도
`fsync`한다. Reader는 regular file과 512 KiB 한도를 확인한 뒤 한 file descriptor에서
전체 bytes를 읽는다. 이 경계로 reader는 partial update를 보지 않는다.

Projection receipt의 `snapshot_sha256`은 논리 객체나 compact JSON의 digest가 아니다.
`snapshot_digest_algorithm=sha256`,
`snapshot_canonicalization=json.marshal-indent.two-spaces+lf.v1`에 따라 Go
`json.MarshalIndent(snapshot, "", "  ")` 결과에 LF 한 바이트를 붙인, 실제 atomic writer가
저장하는 artifact bytes 전체의 SHA-256이다. `snapshot_bytes`도 같은 bytes 길이다.

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
