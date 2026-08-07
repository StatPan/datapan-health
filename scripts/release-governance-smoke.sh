#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=$(mktemp -d)
trap 'rm -rf "$output"' EXIT HUP INT TERM
revision=$(git -C "$root" rev-parse HEAD)
created=$(git -C "$root" log -1 --format=%cI)

bundle_a="$output/governance-a.tar"
bundle_b="$output/governance-b.tar"
"$root/scripts/write-release-governance-bundle.sh" --output "$bundle_a" --revision "$revision" --created "$created"
"$root/scripts/write-release-governance-bundle.sh" --output "$bundle_b" --revision "$revision" --created "$created"
cmp "$bundle_a" "$bundle_b"
"$root/scripts/verify-release-governance-bundle.sh" --bundle "$bundle_a" --revision "$revision"

printf '%s\n' 'release governance bundle is reproducible and contains legal notices plus resolved inventory'
