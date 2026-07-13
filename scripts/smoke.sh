#!/bin/sh
set -eu

cleanup() {
  docker compose --profile fixtures down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose up --build --detach gatus
docker compose --profile fixtures build runner-healthy runner-unhealthy
ready=false
for _ in $(seq 1 30); do
  if curl --fail --silent http://127.0.0.1:8080/health >/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
if [ "$ready" != true ]; then
  docker compose logs gatus
  echo "Gatus did not become ready" >&2
  exit 1
fi
docker compose --profile fixtures run --rm runner-healthy
docker compose --profile fixtures run --rm runner-unhealthy
statuses="$(curl --fail --silent http://127.0.0.1:8080/api/v1/endpoints/statuses)"
printf '%s' "$statuses" | grep -q 'kosis-population'
printf '%s' "$statuses" | grep -q 'data-go-kr-weather'
printf '%s' "$statuses" | grep -q '"success":true'
printf '%s' "$statuses" | grep -q '"success":false'
printf '%s' "$statuses" | grep -q 'timeout'
if printf '%s' "$statuses" | grep -Eiq 'local-synthetic-token|dataset_id|endpoint_path|provider_message|next_actions|query_url|response_body|rows'; then
  echo "sensitive data found in public Gatus payload" >&2
  exit 1
fi
table_count="$(docker compose exec -T postgres psql -U datapan_health -d datapan_health -tAc "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")"
[ "$table_count" -gt 0 ]
curl --fail --silent http://127.0.0.1:8080/ | grep -q '공공데이터 API 상태'
