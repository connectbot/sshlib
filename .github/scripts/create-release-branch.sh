#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=.github/scripts/release-common.sh
source "${script_dir}/release-common.sh"

require_maintainer

maintenance_branch="$(extract_issue_field_line "Maintenance branch")"
source_branch="$(extract_issue_field_line "Source branch")"
source_ref="$(extract_issue_field_line "Source ref" || true)"

validate_maintenance_branch "${maintenance_branch}"
validate_release_target_branch "${source_branch}"
if [[ -z "${source_ref}" ]]; then
  source_ref="origin/${source_branch}"
elif [[ "${source_ref}" == "${source_branch}" ]]; then
  source_ref="origin/${source_branch}"
fi
if [[ "${source_ref}" == -* ]]; then
  echo "Source ref must not start with '-'."
  exit 1
fi

require_missing_remote_branch "${maintenance_branch}"
require_remote_branch "${source_branch}"

configure_git_credentials
git fetch origin "+refs/heads/${source_branch}:refs/remotes/origin/${source_branch}" --tags
git rev-parse --verify --end-of-options "${source_ref}^{commit}" >/dev/null
if ! git merge-base --is-ancestor -- "${source_ref}^{commit}" "origin/${source_branch}"; then
  echo "Source ref ${source_ref} is not reachable from origin/${source_branch}."
  exit 1
fi
git push origin "${source_ref}^{commit}:refs/heads/${maintenance_branch}"
gh issue comment "${ISSUE_NUMBER}" --body "Created ${maintenance_branch} from ${source_ref}."
