#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
platform=${PLATFORM:-linux/arm64}
output=${OUTPUT_DIR:-$root/dist/images}
runtime_repo=${RUNTIME_REPOSITORY:-ghcr.io/statpan/datapan-health-runtime}
archive_repo=${ARCHIVE_REPOSITORY:-ghcr.io/statpan/datapan-health-archive}
builder=${BUILDER:-datapan-health-release}
revision=$(git -C "$root" rev-parse HEAD)
created=$(git -C "$root" log -1 --format=%cI)

"$root/scripts/check-release-source.sh" "$root" "$revision"
mkdir -p "$output"
"$root/scripts/write-release-governance-bundle.sh" \
  --output "$output/governance-bundle.tar" \
  --revision "$revision" \
  --created "$created"
"$root/scripts/verify-release-governance-bundle.sh" \
  --bundle "$output/governance-bundle.tar" \
  --revision "$revision"
if ! docker buildx inspect "$builder" >/dev/null 2>&1; then
  docker buildx create --name "$builder" --driver docker-container >/dev/null
fi
docker buildx inspect "$builder" --bootstrap >/dev/null
build() {
  target=$1
  destination=$2
  docker buildx build --builder "$builder" --quiet --platform "$platform" --target "$target" \
    --build-arg "VCS_REF=$revision" --build-arg "CREATED=$created" \
    --output "type=oci,dest=$destination" "$root"
}
digest() { tar -xOf "$1" index.json | jq -r '.manifests[0].digest'; }

build runtime "$output/runtime.oci.tar"
build archive "$output/archive.oci.tar"
runtime_digest=$(digest "$output/runtime.oci.tar")
archive_digest=$(digest "$output/archive.oci.tar")
governance_bundle_sha=$(sha256sum "$output/governance-bundle.tar" | awk '{print $1}')
cat > "$output/infra-image-inputs.env" <<EOF
# Generated locally; inspect and explicitly promote with a trusted release tool.
DATAPAN_HEALTH_IMAGE=${runtime_repo}@${runtime_digest}
DATAPAN_HEALTH_ARCHIVE_IMAGE=${archive_repo}@${archive_digest}
DATAPAN_HEALTH_RELEASE_REVISION=${revision}
DATAPAN_HEALTH_RELEASE_PLATFORM=${platform}
# Immutable legal/attribution bundle for this exact source revision. Preserve
# this file and its checksum with the OCI archives during promotion.
DATAPAN_HEALTH_GOVERNANCE_BUNDLE_SHA256=${governance_bundle_sha}
DATAPAN_HEALTH_GOVERNANCE_BUNDLE_SOURCE_REVISION=${revision}
# Required before deployment rollback approval; never leave this placeholder.
DATAPAN_HEALTH_IMAGE_PREVIOUS=REQUIRED_PRIOR_RUNTIME_DIGEST
DATAPAN_HEALTH_ARCHIVE_IMAGE_PREVIOUS=REQUIRED_PRIOR_ARCHIVE_DIGEST
EOF
sha256sum "$output/runtime.oci.tar" "$output/archive.oci.tar" "$output/governance-bundle.tar" > "$output/sha256sums.txt"
printf '%s\n' "Wrote OCI archives, immutable governance bundle, and infra inputs to $output"
