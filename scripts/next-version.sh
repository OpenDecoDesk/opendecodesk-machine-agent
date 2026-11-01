#!/usr/bin/env bash
# Prints the version for a release made now: YYYY.MM.DD.NN, today's date (UTC) and that day's build
# number, one more than the highest tag v<today>.NN there already is (01 for the day's first).
# Tags of any other form, like the hand-made v2026.11.01, don't count. Run it in a checkout that has
# every tag (CI fetches them). RELEASE_DATE=YYYY.MM.DD stands in for today, for the tests.
set -euo pipefail

day="${RELEASE_DATE:-$(date -u +%Y.%m.%d)}"
if ! [[ $day =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}$ ]]; then
  echo "The date must be YYYY.MM.DD, not $day" >&2
  exit 1
fi

last=0
for tag in $(git tag -l "v$day.*"); do
  if [[ $tag =~ ^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.([0-9]{2})$ ]]; then
    n=$((10#${BASH_REMATCH[1]}))
    if ((n > last)); then last=$n; fi
  fi
done

if ((last >= 99)); then
  echo "There are already 99 releases dated $day" >&2
  exit 1
fi
printf '%s.%02d\n' "$day" $((last + 1))
