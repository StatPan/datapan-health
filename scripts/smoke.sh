#!/bin/sh
set -eu

cleanup() {
  docker compose --profile fixtures --profile scheduler --profile public-status down --volumes --remove-orphans >/dev/null 2>&1 || true
  if [ -n "${public_headers:-}" ]; then rm -f "$public_headers"; fi
}
trap cleanup EXIT

public_headers=$(mktemp)

docker compose --profile scheduler --profile public-status up --build --detach gatus scheduler public-status
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
curl --fail --silent http://127.0.0.1:8081/live >/dev/null
curl --fail --silent http://127.0.0.1:8081/ready >/dev/null
curl --fail --silent http://127.0.0.1:8081/metrics | grep -q 'datapan_health_scheduler_runs_started_total'
public_status="$(curl --fail --silent -H 'Origin: https://datapan.statpan.com' -D "$public_headers" http://127.0.0.1:8082/datapan/v1/dependencies)"
grep -qi '^Access-Control-Allow-Origin: https://datapan.statpan.com' "$public_headers"
printf '%s' "$public_status" | grep -q 'datapan.dependency-observation.v1'
printf '%s' "$public_status" | grep -q 'dpr-op-00000001'
if printf '%s' "$public_status" | grep -Eiq 'dataset_id|endpoint|credential|provider_message|query|response'; then
  echo "sensitive data found in browser status payload" >&2
  exit 1
fi
test "$(curl --silent --output /dev/null --write-out '%{http_code}' -X OPTIONS -H 'Origin: https://datapan.statpan.com' -H 'Access-Control-Request-Method: GET' http://127.0.0.1:8082/datapan/v1/dependencies)" = 204
test "$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'Origin: https://evil.example' http://127.0.0.1:8082/datapan/v1/dependencies)" = 403
services="$(curl --fail --silent http://127.0.0.1:8082/datapan/v1/services)"
printf '%s' "$services" | grep -q 'datapan.service-status.v1'
printf '%s' "$services" | grep -q 'deployment_identity_unavailable'
if printf '%s' "$services" | grep -q 'dpr-op-'; then
  echo "dependency observation leaked into service status payload" >&2
  exit 1
fi
statuses="$(curl --fail --silent http://127.0.0.1:8080/api/v1/endpoints/statuses)"
printf '%s' "$statuses" | grep -q 'holiday-emergency-clinics'
printf '%s' "$statuses" | grep -q 'qnet-practical-pass-rate'
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
