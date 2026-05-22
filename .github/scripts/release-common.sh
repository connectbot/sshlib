#!/usr/bin/env bash

set -euo pipefail

require_maintainer() {
  local actor="${RELEASE_ACTOR:-}"
  local permission

  if [[ -z "${actor}" ]]; then
    echo "Release automation requires RELEASE_ACTOR to be set."
    exit 1
  fi

  permission="$(gh api "repos/${GITHUB_REPOSITORY}/collaborators/${actor}/permission" --jq '.permission')"

  case "${permission}" in
    admin|maintain) ;;
    *)
      echo "Release automation must be started by a maintainer with maintain or admin access. ${actor} has ${permission} permission."
      exit 1
      ;;
  esac
}

extract_issue_field() {
  local heading="$1"
  awk -v heading="$heading" '
    $0 == "### " heading { found = 1; next }
    found && /^### / { exit }
    found { print }
  ' <<<"${ISSUE_BODY:-}" |
    sed '/<!--.*-->/d' |
    awk '
      { lines[NR] = $0 }
      END {
        start = 1
        end = NR
        while (start <= end && lines[start] ~ /^[[:space:]]*$/) {
          start++
        }
        while (end >= start && lines[end] ~ /^[[:space:]]*$/) {
          end--
        }
        for (i = start; i <= end; i++) {
          print lines[i]
        }
      }
    '
}

extract_issue_field_line() {
  extract_issue_field "$1" | head -n 1 | tr -d '[:space:]'
}

validate_release_version() {
  local version="$1"
  if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Release version must look like 1.2.3."
    exit 1
  fi
}

validate_next_version() {
  local version="$1"
  if [[ ! "${version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+-SNAPSHOT$ ]]; then
    echo "Next version must look like 1.2.4-SNAPSHOT."
    exit 1
  fi
}

validate_release_target_branch() {
  local branch="$1"
  if [[ ! "${branch}" =~ ^(main|release/[0-9]+\.[0-9]+)$ ]]; then
    echo "Target branch must be main or release/<major.minor>."
    exit 1
  fi
}

validate_maintenance_branch() {
  local branch="$1"
  if [[ ! "${branch}" =~ ^release/[0-9]+\.[0-9]+$ ]]; then
    echo "Maintenance branch must look like release/1.1."
    exit 1
  fi
}

require_remote_branch() {
  local branch="$1"
  if ! git ls-remote --exit-code --heads origin "refs/heads/${branch}" >/dev/null 2>&1; then
    echo "Branch ${branch} does not exist."
    exit 1
  fi
}

require_missing_remote_branch() {
  local branch="$1"
  if git ls-remote --exit-code --heads origin "refs/heads/${branch}" >/dev/null 2>&1; then
    echo "Branch ${branch} already exists."
    exit 1
  fi
}

require_missing_remote_tag() {
  local tag="$1"
  if git ls-remote --exit-code --tags origin "refs/tags/${tag}" >/dev/null 2>&1; then
    echo "Tag ${tag} already exists."
    exit 1
  fi
}

configure_git_author() {
  git config user.name "github-actions[bot]"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
}

configure_git_credentials() {
  if [[ -z "${PUSH_TOKEN:-}" ]]; then
    echo "PUSH_TOKEN is required for authenticated git pushes."
    exit 1
  fi

  git config --global credential.helper store
  {
    printf "https://x-access-token:%s@github.com\n" "${PUSH_TOKEN}"
  } >"${HOME}/.git-credentials"
  chmod 0600 "${HOME}/.git-credentials"
}
