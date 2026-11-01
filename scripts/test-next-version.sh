#!/usr/bin/env bash
# Checks scripts/next-version.sh against the tags of a scratch repository.
# Run: scripts/test-next-version.sh
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/next-version.sh"
repo="$(mktemp -d)"
trap 'rm -rf "$repo"' EXIT
cd "$repo"
git init -q
git -c user.name=test -c user.email=test@example.invalid commit -q --allow-empty -m test

failed=0
expect() { # LABEL WANTED [RELEASE_DATE]
  local got
  got="$(RELEASE_DATE="${3:-2026.11.01}" bash "$script" 2>/dev/null || echo "(failed)")"
  if [ "$got" = "$2" ]; then
    echo "$1: True"
  else
    echo "$1: False (got $got, wanted $2)"
    failed=1
  fi
}

expect "no tags: the day's first build is 01" 2026.11.01.01
git tag v2026.11.01
git tag v2026.11.01.1
git tag v2026.11.01.01-test
expect "tags not of the form v<date>.NN are left out" 2026.11.01.01
git tag v2026.11.01.01
expect "after the day's first release comes 02" 2026.11.01.02
git tag v2026.11.01.09
git tag v2026.11.01.10
git tag v2026.11.01.08
expect "the next after the highest, 09 and 10 counted as numbers" 2026.11.01.11
git tag v2026.10.31.05
expect "another day's tags don't count" 2026.11.02.01 2026.11.02
expect "a date not in the form YYYY.MM.DD is refused" "(failed)" 2026-11-01
git tag v2026.11.03.99
expect "a day's 100th release is refused" "(failed)" 2026.11.03
today="$(bash "$script")"
if [ "$today" = "$(RELEASE_DATE="$(date -u +%Y.%m.%d)" bash "$script")" ]; then
  echo "without RELEASE_DATE it's today's date (UTC): True"
else
  echo "without RELEASE_DATE it's today's date (UTC): False (got $today)"
  failed=1
fi

if [ "$failed" = 1 ]; then
  echo "Some checks failed."
  exit 1
fi
echo "All checks passed."
