#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
runtime_image=${RUNTIME_IMAGE:-datapan-health-runtime:test}
archive_image=${ARCHIVE_IMAGE:-datapan-health-archive:test}
synthetic_token=hf-smoke-not-a-secret-7
work=$(mktemp -d)
scheduler_id=

cleanup() {
  if [ -n "$scheduler_id" ]; then docker rm -f "$scheduler_id" >/dev/null 2>&1 || true; fi
  if [ -d "$work" ]; then
    docker run --rm --entrypoint /bin/sh -v "$work:/work" "$archive_image" -c 'rm -rf /work/archive /work/hf-args' >/dev/null 2>&1 || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

docker run --rm --entrypoint /health-runner "$runtime_image" -h >/dev/null
docker run --rm --entrypoint /health-archive "$archive_image" -h >/dev/null
docker run --rm --entrypoint hf "$archive_image" --help >/dev/null

# Live image inventory is intentionally limited to the two live binaries.
runtime_container=$(docker create "$runtime_image")
docker export "$runtime_container" > "$work/runtime.tar"
docker rm "$runtime_container" >/dev/null
tar -tf "$work/runtime.tar" | grep -qx 'health-runner'
tar -tf "$work/runtime.tar" | grep -qx 'health-scheduler'
if tar -tf "$work/runtime.tar" | grep -Eq '(^|/)health-archive$|(^|/)hf$'; then
  echo "archive publication tooling leaked into the live image" >&2
  exit 1
fi

# A ready scheduler proves its assigned executable starts without a provider,
# archive image, or Hugging Face credential in the live role.
scheduler_id=$(docker run -d --entrypoint /health-scheduler -p 127.0.0.1::8081 \
  -e CANARY_CONFIG=/config/canaries.json \
  -e SCHEDULER_STATE=/data/scheduler-state.json \
  -v "$root/config:/config:ro" \
  "$runtime_image")
port=$(docker port "$scheduler_id" 8081/tcp | sed -n 's/.*:\([0-9][0-9]*\)$/\1/p')
ready=false
for _ in $(seq 1 20); do
  if curl --fail --silent "http://127.0.0.1:$port/ready" >/dev/null; then ready=true; break; fi
  sleep 1
done
[ "$ready" = true ]
docker rm -f "$scheduler_id" >/dev/null
scheduler_id=

jq -c . "$root/testdata/receipts/v1/healthy.json" > "$work/receipts.jsonl"
docker run --rm \
  -e "HF_TOKEN=$synthetic_token" \
  -e "PATH=/tmp/fake:/usr/local/bin:/usr/bin:/bin" \
  -e HF_SMOKE_OUTPUT=/work/hf-args \
  -v "$root/config:/config:ro" \
  -v "$root/dataset-card:/dataset-card:ro" \
  -v "$root/testdata:/fixtures:ro" \
  -v "$root/scripts/testdata/fake-hf:/tmp/fake/hf:ro" \
  -v "$work:/work" \
  "$archive_image" \
  -input /work/receipts.jsonl -output /work/archive \
  -config /config/archive.json -canaries /config/canaries.json \
  -dataset-card /dataset-card/README.md -publish
test -s "$work/hf-args"
if docker run --rm --entrypoint /bin/sh -v "$work:/work" "$archive_image" -c "grep -R -F '$synthetic_token' /work >/dev/null 2>&1"; then
  echo "synthetic token was emitted by archive output" >&2
  exit 1
fi

# Inspect config, history, and every uncompressed image layer. The synthetic
# token only crossed the docker run environment and must not be baked anywhere.
if docker image inspect "$archive_image" | grep -F "$synthetic_token" >/dev/null \
  || docker history --no-trunc "$archive_image" | grep -F "$synthetic_token" >/dev/null; then
  echo "synthetic token was baked into archive metadata" >&2
  exit 1
fi
docker image save "$archive_image" -o "$work/archive-image.tar"
for layer in $(tar -tf "$work/archive-image.tar" | grep '/layer.tar$'); do
  if tar -xOf "$work/archive-image.tar" "$layer" | grep -a -F "$synthetic_token" >/dev/null; then
    echo "synthetic token was baked into an archive layer" >&2
    exit 1
  fi
done
