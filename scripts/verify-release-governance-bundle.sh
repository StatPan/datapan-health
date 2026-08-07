#!/bin/sh
set -eu

bundle=
revision=
while test "$#" -gt 0; do
  case "$1" in
    --bundle) bundle=${2:?missing bundle path}; shift 2 ;;
    --revision) revision=${2:?missing source revision}; shift 2 ;;
    *) echo "usage: $0 --bundle PATH --revision SHA" >&2; exit 2 ;;
  esac
done

test -f "$bundle"
test -n "$revision"

for path in \
  ./governance/LICENSE \
  ./governance/NOTICE \
  ./governance/THIRD_PARTY_NOTICES.md \
  ./governance/CONTRIBUTING.md \
  ./governance/SECURITY.md \
  ./governance/TRADEMARKS.md \
  ./third-party-inventory.json \
  ./component-inputs/go.mod \
  ./component-inputs/go.sum \
  ./component-inputs/Dockerfile \
  ./component-inputs/compose.yaml \
  ./component-inputs/docker/hf-requirements.txt; do
  tar -tf "$bundle" | grep -Fxq "$path"
done

tar -xOf "$bundle" ./third-party-inventory.json | jq -e \
  --arg revision "$revision" \
  '(.schema_version == "datapan.health.third-party-inventory.v1") and
   (.source_revision == $revision) and
   (.go_modules | type == "array" and length > 0) and
   all(.go_modules[]; has("path") and has("version") and has("sum") and has("go_mod_sum"))' >/dev/null
