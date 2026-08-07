#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
required='LICENSE NOTICE THIRD_PARTY_NOTICES.md CONTRIBUTING.md SECURITY.md TRADEMARKS.md'

for path in $required; do
  test -f "$root/$path"
  git -C "$root" ls-files --error-unmatch "$path" >/dev/null
done

grep -Fq 'Apache License' "$root/LICENSE"
grep -Fq 'Version 2.0, January 2004' "$root/LICENSE"
grep -Fq 'THIRD_PARTY_NOTICES.md' "$root/NOTICE"
grep -Fq 'Governance' "$root/README.md"
grep -Fq 'https://github.com/StatPan/datapan-health/security/advisories/new' "$root/SECURITY.md"
grep -Fq 'make security-reporting-check' "$root/SECURITY.md"

# A Git source archive is the release form this repository can validate without
# building or changing any runtime image. Use the current index tree so the
# check also works as a pre-commit release gate; CI's checkout index is HEAD.
# Verify every required file is present so a source release cannot silently omit
# the notices.
archive_index=$(mktemp)
trap 'rm -f "$archive_index"' EXIT HUP INT TERM
tree=$(git -C "$root" write-tree)
git -C "$root" archive --format=tar "$tree" | tar -tf - >"$archive_index"
for path in $required; do
  grep -Fxq "$path" "$archive_index"
done

printf '%s\n' 'governance files and Git source-archive inclusion verified'
