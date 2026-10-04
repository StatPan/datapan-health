#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image=${1:?immutable runtime image or local test image required}
work=$(mktemp -d)
container=
cleanup() {
  if [ -n "$container" ]; then docker rm "$container" >/dev/null 2>&1 || true; fi
  rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM

# Verify image bytes, rather than trusting only the source checkout or labels.
container=$(docker create "$image")
for path in runtime-dependencies.json gatus.yaml canaries.json registry/health-probe-catalog.json registry/assertion-policy-contract-pin.json; do
  mkdir -p "$work/$(dirname "$path")"
  docker cp "$container:/opt/datapan-health/config/$path" "$work/$path" >/dev/null
  cmp "$root/config/$path" "$work/$path"
done
docker rm "$container" >/dev/null
container=

# The published CLI must execute one declared HTTP request and emit a redacted,
# manifest-bound receipt. Only synthetic loopback is available to this process.
docker run --rm --network none --add-host apis.data.go.kr:127.0.0.1 --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --entrypoint /health-runtime-dependencies "$image" \
  -lock /opt/datapan-health/config/runtime-dependencies.json -verify-local -prove-cli
