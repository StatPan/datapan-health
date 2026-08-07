#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=
revision=
created=

while test "$#" -gt 0; do
  case "$1" in
    --output) output=${2:?missing output path}; shift 2 ;;
    --revision) revision=${2:?missing source revision}; shift 2 ;;
    --created) created=${2:?missing source creation time}; shift 2 ;;
    *) echo "usage: $0 --output PATH --revision SHA --created RFC3339" >&2; exit 2 ;;
  esac
done

test -n "$output"
test -n "$revision"
test -n "$created"

"$root/scripts/check-release-source.sh" "$root" "$revision"
"$root/scripts/check-governance.sh"

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/governance" "$stage/component-inputs/docker"

for path in LICENSE NOTICE THIRD_PARTY_NOTICES.md CONTRIBUTING.md SECURITY.md TRADEMARKS.md; do
  install -m 0644 "$root/$path" "$stage/governance/$path"
done
install -m 0644 "$root/go.mod" "$stage/component-inputs/go.mod"
install -m 0644 "$root/go.sum" "$stage/component-inputs/go.sum"
install -m 0644 "$root/Dockerfile" "$stage/component-inputs/Dockerfile"
install -m 0644 "$root/compose.yaml" "$stage/component-inputs/compose.yaml"
install -m 0644 "$root/docker/hf-requirements.txt" "$stage/component-inputs/docker/hf-requirements.txt"

go_mod_sha=$(sha256sum "$root/go.mod" | awk '{print $1}')
go_sum_sha=$(sha256sum "$root/go.sum" | awk '{print $1}')
dockerfile_sha=$(sha256sum "$root/Dockerfile" | awk '{print $1}')
compose_sha=$(sha256sum "$root/compose.yaml" | awk '{print $1}')
python_requirements_sha=$(sha256sum "$root/docker/hf-requirements.txt" | awk '{print $1}')

# `go list -m -json all` contains local cache paths. Project only the resolved
# module identity and checksums so the promotion artifact is portable and does
# not disclose the build host's filesystem layout.
go list -m -json all | jq -s \
  --arg revision "$revision" \
  --arg created "$created" \
  --arg go_mod_sha "$go_mod_sha" \
  --arg go_sum_sha "$go_sum_sha" \
  --arg dockerfile_sha "$dockerfile_sha" \
  --arg compose_sha "$compose_sha" \
  --arg python_requirements_sha "$python_requirements_sha" \
  '{
    schema_version: "datapan.health.third-party-inventory.v1",
    source_revision: $revision,
    source_created: $created,
    source_inputs: {
      "go.mod": $go_mod_sha,
      "go.sum": $go_sum_sha,
      "Dockerfile": $dockerfile_sha,
      "compose.yaml": $compose_sha,
      "docker/hf-requirements.txt": $python_requirements_sha
    },
    go_modules: [ .[] | {
      path: .Path,
      version: (.Version // null),
      sum: (.Sum // null),
      go_mod_sum: (.GoModSum // null)
    } ]
  }' >"$stage/third-party-inventory.json"

mkdir -p "$(dirname -- "$output")"
# The source revision and commit timestamp define the archive metadata. The
# resulting tar is reproducible for the same checked-out revision and is
# checksum-bound to the OCI promotion inputs by build-release-oci.sh.
tar --sort=name --mtime="$created" --owner=0 --group=0 --numeric-owner \
  -cf "$output" -C "$stage" .
