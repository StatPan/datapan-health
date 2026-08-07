#!/bin/sh
set -eu

root=${1:?repository root is required}
expected_revision=${2:-}
revision=$(git -C "$root" rev-parse HEAD)

if test -n "$expected_revision" && test "$revision" != "$expected_revision"; then
  echo "release source revision does not match HEAD" >&2
  exit 1
fi

# The OCI build context is the repository directory. Refuse both index and
# worktree changes, plus non-ignored untracked files, so the source revision in
# the bundle, image labels, and promotion receipt names the exact bytes built.
if ! git -C "$root" diff --quiet --ignore-submodules -- \
  || ! git -C "$root" diff --cached --quiet --ignore-submodules -- \
  || test -n "$(git -C "$root" ls-files --others --exclude-standard)"; then
  echo "refusing release from a dirty source tree; commit, stash, or remove non-ignored changes first" >&2
  exit 1
fi

printf '%s\n' "release source verified at $revision"
