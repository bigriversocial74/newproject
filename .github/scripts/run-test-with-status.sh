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
  outcome=failure
  detail=$(printf '%s' "$output" | head -n 1 | tr '\r\n' '  ' | sed 's/["\\]/ /g' | cut -c1-90)
  if [[ -z "$detail" ]]; then
    detail="command failed with exit ${code}"
  fi
  description="$label: $detail"
fi

bash .github/scripts/publish-commit-status.sh "$context" "$outcome" "$description"
exit "$code"
