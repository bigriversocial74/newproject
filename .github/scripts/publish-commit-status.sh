#!/usr/bin/env bash
set -euo pipefail

context="${1:?status context required}"
outcome="${2:?step outcome required}"
description="${3:?description required}"
state="success"
if [[ "$outcome" != "success" ]]; then
  state="failure"
fi

curl --fail-with-body -sS -X POST \
  -H "Authorization: Bearer ${GH_TOKEN:?GH_TOKEN required}" \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  "https://api.github.com/repos/${GITHUB_REPOSITORY}/statuses/${GITHUB_SHA}" \
  -d "{\"state\":\"${state}\",\"context\":\"${context}\",\"description\":\"${description} ${state}\"}"
