#!/usr/bin/env bash

set -euo pipefail

release_version="$1"
next_version="$2"
target_branch="$3"
work_branch="$4"
tag_name="$5"

body_file="$(mktemp)"
cat >"${body_file}" <<EOF
Prepares ${tag_name} from ${target_branch}.

Release issue: #${ISSUE_NUMBER}
Release version: ${release_version}
Next version: ${next_version}
Target branch: ${target_branch}

After required checks pass, add the \`release:publish\` label to issue #${ISSUE_NUMBER}.
EOF

pr_number="$(gh pr list \
  --head "${work_branch}" \
  --base "${target_branch}" \
  --state open \
  --json number \
  --jq '.[0].number // empty')"

if [[ -n "${pr_number}" ]]; then
  gh pr edit "${pr_number}" \
    --title "chore(release): ${release_version}" \
    --body-file "${body_file}"
else
  gh pr create \
    --base "${target_branch}" \
    --head "${work_branch}" \
    --title "chore(release): ${release_version}" \
    --body-file "${body_file}"
fi
