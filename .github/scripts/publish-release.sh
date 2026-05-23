#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=.github/scripts/release-common.sh
source "${script_dir}/release-common.sh"

require_maintainer

release_version="$(extract_issue_field_line "Release version")"
next_version="$(extract_issue_field_line "Next version")"
target_branch="$(extract_issue_field_line "Target branch")"
release_notes="$(extract_issue_field "Release notes" || true)"

validate_release_version "${release_version}"
validate_next_version "${next_version}"
validate_release_target_branch "${target_branch}"

tag_name="v${release_version}"
work_branch="release-work/${release_version}"

require_missing_remote_tag "${tag_name}"

pr_number="$(gh pr list \
  --head "${work_branch}" \
  --base "${target_branch}" \
  --state open \
  --json number \
  --jq '.[0].number // empty')"

if [[ -z "${pr_number}" ]]; then
  echo "No open release PR found for ${work_branch} into ${target_branch}."
  exit 1
fi

pr_data="$(gh pr view "${pr_number}" --json baseRefName,headRefName,headRefOid,mergeable,mergeStateStatus,reviewDecision)"
actual_base="$(jq -r '.baseRefName' <<<"${pr_data}")"
actual_head="$(jq -r '.headRefName' <<<"${pr_data}")"
head_ref_oid="$(jq -r '.headRefOid' <<<"${pr_data}")"
mergeable="$(jq -r '.mergeable' <<<"${pr_data}")"
merge_state="$(jq -r '.mergeStateStatus' <<<"${pr_data}")"
review_decision="$(jq -r '.reviewDecision' <<<"${pr_data}")"

if [[ "${actual_base}" != "${target_branch}" || "${actual_head}" != "${work_branch}" ]]; then
  echo "Release PR does not match the issue target branch and work branch."
  exit 1
fi
if [[ "${mergeable}" != "MERGEABLE" ]]; then
  echo "Release PR must be mergeable before publishing. Current mergeable state: ${mergeable}."
  exit 1
fi
if [[ "${merge_state}" != "CLEAN" ]]; then
  echo "Release PR must have a clean merge state before publishing. Current merge state: ${merge_state}."
  exit 1
fi
if [[ "${review_decision}" != "APPROVED" ]]; then
  echo "Release PR must be approved before publishing. Current review decision: ${review_decision}."
  exit 1
fi

gh pr checks "${pr_number}" --required --fail-fast

configure_git_author
git fetch origin \
  "+refs/heads/${target_branch}:refs/remotes/origin/${target_branch}" \
  "+refs/heads/${work_branch}:refs/remotes/origin/${work_branch}" \
  --tags

if [[ "$(git rev-parse "origin/${work_branch}")" != "${head_ref_oid}" ]]; then
  echo "Release branch changed after PR checks were inspected."
  exit 1
fi

release_commit=""
while read -r commit; do
  if git show "${commit}:gradle.properties" | grep -q "^version=${release_version}$"; then
    release_commit="${commit}"
    break
  fi
done < <(git rev-list --reverse "origin/${target_branch}..origin/${work_branch}")

if [[ -z "${release_commit}" ]]; then
  echo "Could not find release commit with version=${release_version}."
  exit 1
fi

if ! git show "origin/${work_branch}:gradle.properties" | grep -q "^version=${next_version}$"; then
  echo "Release branch tip does not contain version=${next_version}."
  exit 1
fi

tag_message="$(mktemp)"
{
  echo "Release ${tag_name}"
  if [[ -n "${release_notes}" ]]; then
    echo
    echo "${release_notes}"
  fi
} >"${tag_message}"

git tag -a "${tag_name}" "${release_commit}" -F "${tag_message}"
if [[ "$(git cat-file -t "${tag_name}")" != "tag" ]]; then
  echo "${tag_name} is not an annotated tag."
  exit 1
fi

configure_git_credentials
git push --atomic --follow-tags origin "refs/remotes/origin/${work_branch}:refs/heads/${target_branch}"
gh issue comment "${ISSUE_NUMBER}" --body "Published ${tag_name} to ${target_branch}."
