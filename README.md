# Datapan Status

공공데이터 API가 고장 난 것처럼 보일 때 가장 먼저 확인하는 공개 상태 페이지의 최소 구현입니다. UI는 익숙한 한 열 세로 목록을 유지하며, [upstream Gatus v5.36.0](https://github.com/TwiN/gatus/releases/tag/v5.36.0)을 수정 없이 사용합니다.

## 로컬 실행

Go 1.26.4와 Docker Compose v2가 필요합니다.

```sh
make test
make quality
make smoke
```

`make smoke`는 Gatus와 runner 이미지를 빌드하고, 버전이 고정된 합성 receipt 두 개를 push합니다. `http://localhost:8080`에서 건강/장애 상태를 확인한 뒤 컨테이너과 볼륨을 정리합니다. 수동으로 화면을 유지하려면 다음을 실행합니다.

```sh
docker compose up -d gatus
docker compose --profile fixtures run --rm runner-healthy
docker compose --profile fixtures run --rm runner-unhealthy
```

로컬 기본 토큰은 합성 테스트 전용입니다. 실제 환경에서는 `GATUS_TOKEN`을 secret으로 주입해야 하며 Git, receipt, URL 또는 로그에 넣지 않습니다. 이 저장소는 배포하지 않으며 `statpan-infra`를 수정하지 않습니다.

## Receipt 계약

CLI [#134](https://github.com/StatPan/datapan-cli/issues/134)가 제공되기 전까지 `testdata/receipts/v1`의 합성 fixture가 입력 계약입니다. runner는 정확히 다음 필드만 받습니다.

- `schema_version`: `datapan.health-probe.v1`
- `probe_id`: 설정된 공개 endpoint 식별자
- `observed_at`: RFC 3339 시각
- `status`: `healthy` 또는 `unhealthy`
- `duration_ms`: 0 이상 24시간 이하
- `error_class`: 장애일 때만 허용되는 `availability`, `authentication`, `rate_limit`, `timeout`, `upstream_contract`, `unknown`

알 수 없는 필드는 모두 거부하므로 credential, 전체 query URL, 응답 body/row는 runner 경계를 통과할 수 없습니다. Gatus에는 성공 여부, duration, 공개 error class만 전달합니다.

## 구조와 저장 경계

```text
synthetic receipt -> strict Go adapter -> Gatus external endpoint -> public vertical UI
                           |                         |
                    local ReceiptSink         SQLite live state
```

Gatus SQLite는 현재 상태와 UI history의 유일한 live database입니다. `ReceiptSink`는 redacted receipt 보존을 교체 가능한 경계로 만들며, MVP 구현은 권한 `0600`의 로컬 JSONL append sink입니다.

Hugging Face Dataset은 선택적 장기 archive만 담당합니다. 향후 별도 batch worker가 로컬 redacted receipt를 시간/일 단위로 모아 commit할 수 있지만, 요청 경로에서 commit하지 않고 heartbeat나 live 상태 판단에 사용하지 않습니다. HF 장애가 Gatus push를 막아서는 안 되며 transactional database로 취급하지 않습니다.

Heartbeat는 각 외부 endpoint에 2분으로 설정되어 runner가 receipt 전송을 중단하면 Gatus 자체 실패 결과로 공개됩니다. 초기 canary 목록은 `config/gatus.yaml`이 소유합니다.
