# Assertion policy compatibility

Health는 Registry commit
`f90d2d62258e50d562ff08b993c75bc0a4dad6fa`에서 승인된 operation assertion
policy bytes를 오프라인으로 고정한다. 이 기능은 provider를 호출하거나 배포를
변경하지 않고, 관찰을 상태로 해석할 수 있는지 여부만 결정한다.

## 판정 규칙

- exact policy path, set ID/version, canonical artifact SHA와 diagnostic vocabulary SHA가
  모두 일치해야 한다.
- active policy가 다른 version/artifact를 가리키면 이전 pin은 superseded로 보고
  `unknown`을 반환한다.
- asserted contract에서 관찰된 field name이 모두 Registry vocabulary 안에 있으면
  `pass`, 하나라도 선언되지 않았으면 `fail`이다.
- contract 관찰이 비어 있으면 `not_observed`다. HTTP 성공을 contract 또는 data
  성공으로 사용하지 않는다.
- v1에서 `presence`, `semantic`, `freshness`, `transport`는 `not_asserted`이므로
  입력 상태와 관계없이 `not_observed`다. 특히 timestamp 정책과 완전한 시간 필드가
  없는 상태에서 `stale`을 만들지 않는다.
- missing, mismatched, unsupported 또는 superseded binding은 health failure가 아닌
  `unknown`이다.

입력 decoder는 field name만 허용한다. HTTP status, provider row/value/message/URL,
timestamp, credential과 64자 hash 모양 값은 evidence 경계를 통과할 수 없다. 출력은
operation/policy identity, outcome, reason과 field count만 포함한다.

## 재현 가능한 증거

다음 명령은 exact Health head/tested revision, Registry artifact pins, 10개 operation
revision, 판정 case, 실제 source SHA와 테스트 함수명을 묶은 receipt를 생성한다.

```sh
make assertion-policy-compatibility \
  HEALTH_HEAD="$(git rev-parse HEAD)" \
  TESTED_REVISION="$(git rev-parse HEAD)"
```

결과는 `out/assertion-policy-compatibility.json`이다. CI가 같은 명령을 실행해 artifact로
보존한다. receipt는 기존 availability v1, archive v1, Gatus projection을 변경하지
않으며 provider runtime과 deployment를 수행하지 않았음을 명시한다.
