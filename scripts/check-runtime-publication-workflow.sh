#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
workflow="$root/.github/workflows/publish-runtime-image.yml"

test -f "$workflow"
grep -Fq 'workflow_dispatch:' "$workflow"
grep -Fq 'source_sha:' "$workflow"
grep -Fq 'rollback_image:' "$workflow"
grep -Fq 'packages: write' "$workflow"
grep -Fq 'PLATFORM=linux/arm64 OUTPUT_DIR=dist/images ./scripts/build-release-oci.sh' "$workflow"
grep -Fq 'test "$(git rev-parse origin/main)" = "$SOURCE_SHA"' "$workflow"
grep -Fq 'SOURCE_CREATED=%s' "$workflow"
grep -Fq 'ghcr.io/statpan/datapan-health-runtime' "$workflow"
grep -Fq 'target: runtime' "$workflow"
grep -Fq 'platforms: linux/arm64' "$workflow"
grep -Fq 'provenance: false' "$workflow"
grep -Fq 'test "$digest" = "$local_runtime_digest"' "$workflow"
grep -Fq 'org.opencontainers.image.revision' "$workflow"
grep -Fq 'runtime-release-receipt.json' "$workflow"
grep -Fq 'declared_rollback_image' "$workflow"
grep -Fq 'RECEIPT_MAX_AGE_SECONDS: "900"' "$workflow"
grep -Fq 'issued_at' "$workflow"
grep -Fq 'expires_at' "$workflow"
grep -Fq 'max_age_seconds' "$workflow"
grep -Fq 'workflow_path .github/workflows/publish-runtime-image.yml' "$workflow"
grep -Fq 'conclusion:"success"' "$workflow"
grep -Fq 'artifact_name' "$workflow"
grep -Fq 'package:{image:$image,digest:$digest,platform:$platform' "$workflow"
if grep -Eq '(^|[^[:alnum:]_])latest([^[:alnum:]_]|$)' "$workflow"; then
  echo "runtime publisher must not use a mutable latest tag" >&2
  exit 1
fi
printf '%s\n' 'runtime publication workflow contract is pinned and source-bound'
