#!/usr/bin/env bash

set -euo pipefail

log_file="$1"
workflow_name="$2"

body_file="$(mktemp)"
redacted_log="$(mktemp)"
if [[ -s "${log_file}" ]]; then
  cp "${log_file}" "${redacted_log}"
  if [[ -n "${PUSH_TOKEN:-}" ]]; then
    perl -0pi -e 'BEGIN { $s = $ENV{PUSH_TOKEN} // "" } if (length $s) { s/\Q$s\E/<redacted PUSH_TOKEN>/g }' "${redacted_log}"
  fi
  if [[ -n "${GH_TOKEN:-}" ]]; then
    perl -0pi -e 'BEGIN { $s = $ENV{GH_TOKEN} // "" } if (length $s) { s/\Q$s\E/<redacted GH_TOKEN>/g }' "${redacted_log}"
  fi
fi

{
  echo "${workflow_name} failed."
  echo
  echo '```text'
  if [[ -s "${redacted_log}" ]]; then
    tail -n 80 "${redacted_log}"
  else
    echo "No script output was captured."
  fi
  echo '```'
  echo
  echo "Run: ${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
} >"${body_file}"

gh issue comment "${ISSUE_NUMBER}" --body-file "${body_file}"
