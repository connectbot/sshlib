#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=.github/scripts/release-common.sh
source "${script_dir}/release-common.sh"

require_maintainer

release_version="$(extract_issue_field_line "Release version")"
next_version="$(extract_issue_field_line "Next version")"
target_branch="$(extract_issue_field_line "Target branch")"

validate_release_version "${release_version}"
validate_next_version "${next_version}"
validate_release_target_branch "${target_branch}"

tag_name="v${release_version}"
work_branch="release-work/${release_version}"

require_missing_remote_tag "${tag_name}"
require_remote_branch "${target_branch}"
require_missing_remote_branch "${work_branch}"

configure_git_author
git fetch origin "+refs/heads/${target_branch}:refs/remotes/origin/${target_branch}" --tags
git checkout -B "${work_branch}" "origin/${target_branch}"

./gradlew release \
  -Pcbssh.release.noPush=true \
  -Prelease.useAutomaticVersion=true \
  -Prelease.releaseVersion="${release_version}" \
  -Prelease.newVersion="${next_version}"

configure_git_credentials
git push origin "HEAD:refs/heads/${work_branch}"

{
  echo "release_version=${release_version}"
  echo "next_version=${next_version}"
  echo "target_branch=${target_branch}"
  echo "work_branch=${work_branch}"
  echo "tag_name=${tag_name}"
} >>"${GITHUB_OUTPUT}"
