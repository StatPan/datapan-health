#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
temp=$(mktemp -d)
worktree="$temp/worktree"
trap 'git -C "$root" worktree remove --force "$worktree" >/dev/null 2>&1 || true; rm -rf "$temp"' EXIT HUP INT TERM

git -C "$root" worktree add --detach "$worktree" HEAD >/dev/null
printf '%s\n' 'must-not-enter-release' >"$worktree/untracked-release-provenance-fixture"

if OUTPUT_DIR="$temp/output" "$worktree/scripts/build-release-oci.sh" >"$temp/release.log" 2>&1; then
  echo "dirty source tree unexpectedly entered the release path" >&2
  exit 1
fi

grep -Fq 'refusing release from a dirty source tree' "$temp/release.log"
test ! -e "$temp/output/governance-bundle.tar"
printf '%s\n' 'dirty source tree is rejected before legal bundle or OCI output is created'
