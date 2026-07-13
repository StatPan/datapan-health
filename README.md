# Datapan Status

공공데이터 API가 고장 난 것처럼 보일 때 가장 먼저 확인하는 공개 상태 페이지의 최소 구현입니다. UI는 익숙한 한 열 세로 목록을 유지하며, [upstream Gatus v5.36.0](https://github.com/TwiN/gatus/releases/tag/v5.36.0)을 수정 없이 사용합니다.

## 로컬 실행

Go 1.26.4와 Docker Compose v2가 필요합니다.

```sh
make test
make quality
make smoke
```

`make smoke`는 Gatus와 runner 이미지를 빌드하고, CLI 계약과 같은 형태의 합성 receipt 두 개를 push합니다. `http://localhost:8080`에서 건강/장애 상태를 확인한 뒤 컨테이너과 볼륨을 정리합니다. 수동으로 화면을 유지하려면 다음을 실행합니다.

```sh
docker compose up -d gatus
docker compose --profile fixtures run --rm runner-healthy
docker compose --profile fixtures run --rm runner-unhealthy
```

로컬 기본 토큰은 합성 테스트 전용입니다. 실제 환경에서는 `GATUS_TOKEN`을 secret으로 주입해야 하며 Git, receipt, URL 또는 로그에 넣지 않습니다. 이 저장소는 배포하지 않으며 `statpan-infra`를 수정하지 않습니다.

## Receipt 계약

입력 계약은 merged `datapan-cli`의 `datapan.health-probe.v1`입니다. 이 저장소는 CLI commit `2fc8343993b7704b50f7d50fcba2642fca439c7f`에서 가져온 [pinned schema](schemas/datapan.health-probe.v1.schema.json)와 [provenance](schemas/PROVENANCE.md)를 보관합니다. runner는 이 schema를 embed하여 runtime에 검증하고, CI test는 합성 healthy/unhealthy CLI-style receipt의 호환성과 pinned digest를 확인합니다.

receipt의 `probe_id`는 CLI가 생성하는 UUID이며 공개 서비스 식별자가 아닙니다. `config/canaries.json`은 immutable `operation.operation_key`를 Gatus external endpoint key에 명시적으로 매핑합니다. 알 수 없거나 중복된 operation은 push하지 않습니다.

Gatus에는 `assessment.outcome`, `assessment.category`, `observation.latency_ms`만 projection합니다: `healthy` outcome은 success, 나머지는 failed이며 public error string은 enum-only `outcome:category`입니다. dataset ID, endpoint host/path, provider code/message, reason code, next actions, safe parameter names, query data, credential, body 및 response row는 Gatus URL/error/log에 넣지 않습니다.

## 구조와 저장 경계

```text
CLI-style redacted receipt -> strict Go adapter -> Gatus external endpoint -> public vertical UI
                                  |                         |
                         local ReceiptSink         SQLite live state
```

Gatus SQLite는 현재 상태와 UI history의 유일한 live database입니다. `ReceiptSink`는 detailed but redacted receipt 보존을 교체 가능한 경계로 만들며, MVP 구현은 권한 `0600`의 로컬 JSONL append sink입니다. 이 sink만 receipt의 dataset/provenance/operation metadata를 보존합니다.

Hugging Face Dataset은 선택적 장기 archive만 담당합니다. 향후 별도 batch worker가 로컬 redacted receipt를 시간/일 단위로 모아 commit할 수 있지만, 요청 경로에서 commit하지 않고 heartbeat나 live 상태 판단에 사용하지 않습니다. HF 장애가 Gatus push를 막아서는 안 되며 transactional database로 취급하지 않습니다.

Heartbeat는 각 외부 endpoint에 2분으로 설정되어 runner가 receipt 전송을 중단하면 Gatus 자체 실패 결과로 공개됩니다. 공개 endpoint 목록은 `config/gatus.yaml`, operation-to-public-key identity mapping은 `config/canaries.json`이 소유합니다.
