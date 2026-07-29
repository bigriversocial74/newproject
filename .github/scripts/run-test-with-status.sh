#!/usr/bin/env bash
set -uo pipefail

context="${1:?status context required}"
label="${2:?status label required}"
shift 2

set +e
output=$("$@" 2>&1)
code=$?
set -e
printf '%s\n' "$output"

outcome=success
description="$label success"
if [[ $code -ne 0 ]]; then
  detail=$(printf '%s' "$output" | head -n 1 | tr '\r\n' '  ' | sed 's/["\\]/ /g' | cut -c1-90)
  if [[ -z "$detail" ]]; then
    detail="command failed with exit ${code}"
  fi
  description="$label: $detail"

  diagnostic=$(printf '%s' "$detail" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//' \
    | cut -c1-55)
  if [[ -z "$diagnostic" ]]; then
    diagnostic="exit-${code}"
  fi
  bash .github/scripts/publish-commit-status.sh "phase11b/diagnostic/${diagnostic}" failure "$description"
fi

bash .github/scripts/publish-commit-status.sh "$context" "$outcome" "$description"
exit "$code"
