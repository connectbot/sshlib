#!/usr/bin/env bats

setup() {
  REPO_ROOT="$(cd "${BATS_TEST_DIRNAME}/../.." && pwd)"
  export REPO_ROOT

  WORKDIR="${BATS_TEST_TMPDIR}/work"
  BIN_DIR="${BATS_TEST_TMPDIR}/bin"
  LOG_FILE="${BATS_TEST_TMPDIR}/commands.log"
  export HOME="${BATS_TEST_TMPDIR}/home"
  mkdir -p "${WORKDIR}" "${BIN_DIR}" "${HOME}"
  touch "${LOG_FILE}"

  export PATH="${BIN_DIR}:${PATH}"
  export LOG_FILE
  export GITHUB_OUTPUT="${BATS_TEST_TMPDIR}/github-output"
  export GITHUB_REPOSITORY="connectbot/cbssh"
  export GITHUB_RUN_ID="456"
  export GITHUB_SERVER_URL="https://github.com"
  export ISSUE_NUMBER="123"
  export RELEASE_ACTOR="maintainer"
  export GH_TOKEN="test-token"
  export PUSH_TOKEN="push-token"

  cp -R "${REPO_ROOT}/.github" "${WORKDIR}/.github"
  make_gradlew_stub
  make_git_stub
  make_gh_stub
  cd "${WORKDIR}"
}

make_gradlew_stub() {
  cat >"${WORKDIR}/gradlew" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
{
  printf 'gradlew'
  printf ' %q' "$@"
  printf '\n'
} >>"${LOG_FILE}"
STUB
  chmod +x "${WORKDIR}/gradlew"
}

make_git_stub() {
  cat >"${BIN_DIR}/git" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
{
  printf 'git'
  printf ' %q' "$@"
  printf '\n'
} >>"${LOG_FILE}"

case "$1" in
  ls-remote)
    if [[ "$*" == *"refs/tags/v9.9.9"* ]]; then
      exit 0
    fi
    if [[ "$*" == *"refs/tags/"* || "$*" == *"refs/heads/missing"* || "$*" == *"refs/heads/release/1.1"* ]]; then
      exit 2
    fi
    if [[ "$*" == *"refs/heads/release-work/9.9.8"* ]]; then
      exit 0
    fi
    if [[ "$*" == *"refs/heads/release-work/"* ]]; then
      exit 2
    fi
    exit 0
    ;;
  show)
    case "$2" in
      release-commit:gradle.properties)
        echo "version=1.2.3"
        ;;
      refs/remotes/origin/release-work/1.2.3:gradle.properties|origin/release-work/1.2.3:gradle.properties)
        echo "version=1.2.4-SNAPSHOT"
        ;;
      *)
        echo "version=0.0.0-SNAPSHOT"
        ;;
    esac
    ;;
  rev-list)
    echo "release-commit"
    echo "next-commit"
    ;;
  cat-file)
    echo "tag"
    ;;
  rev-parse)
    if [[ "${2:-}" == "origin/release-work/1.2.3" ]]; then
      echo "head-sha"
    fi
    exit 0
    ;;
  merge-base)
    exit 0
    ;;
esac
STUB
  chmod +x "${BIN_DIR}/git"
}

make_gh_stub() {
  cat >"${BIN_DIR}/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
{
  printf 'gh'
  printf ' %q' "$@"
  printf '\n'
} >>"${LOG_FILE}"

if [[ "$1" == "api" ]]; then
  echo "maintain"
elif [[ "$1 $2" == "pr list" ]]; then
  echo "77"
elif [[ "$1 $2" == "pr view" ]]; then
  echo '{"baseRefName":"main","headRefName":"release-work/1.2.3","headRefOid":"head-sha","mergeable":"MERGEABLE","mergeStateStatus":"CLEAN","reviewDecision":"APPROVED"}'
elif [[ "$1 $2" == "pr checks" ]]; then
  if [[ -n "${GH_PR_CHECKS_JSON:-}" ]]; then
    echo "${GH_PR_CHECKS_JSON}"
  else
    echo '[{"bucket":"pass","name":"Build and test","state":"SUCCESS","workflow":"Continuous Integration"}]'
  fi
fi
STUB
  chmod +x "${BIN_DIR}/gh"
}

release_issue_body() {
  cat <<'EOF'
### Release version

1.2.3

### Next version

1.2.4-SNAPSHOT

### Target branch

main

### Release notes

Security fixes and release automation.

Second paragraph stays separate.
EOF
}

branch_issue_body() {
  cat <<'EOF'
### Maintenance branch

release/1.1

### Source branch

main

### Source ref

EOF
}

@test "release-common extracts issue form fields" {
  export ISSUE_BODY
  ISSUE_BODY="$(release_issue_body)"

  run bash -c 'source .github/scripts/release-common.sh; extract_issue_field_line "Release version"'

  [ "$status" -eq 0 ]
  [ "$output" = "1.2.3" ]
}

@test "release-common preserves internal blank lines in multi-line fields" {
  export ISSUE_BODY
  ISSUE_BODY="$(release_issue_body)"

  run bash -c 'source .github/scripts/release-common.sh; extract_issue_field "Release notes"'

  [ "$status" -eq 0 ]
  [[ "$output" == $'Security fixes and release automation.\n\nSecond paragraph stays separate.' ]]
}

@test "prepare-release creates a release-work branch with netrelease no-push mode" {
  export ISSUE_BODY
  ISSUE_BODY="$(release_issue_body)"

  run bash .github/scripts/prepare-release.sh

  [ "$status" -eq 0 ]
  grep -F "gh api repos/connectbot/cbssh/collaborators/maintainer/permission --jq .permission" "${LOG_FILE}"
  grep -F "git config --global credential.helper store" "${LOG_FILE}"
  grep -F "git checkout -B release-work/1.2.3 origin/main" "${LOG_FILE}"
  grep -F "gradlew release -Pcbssh.release.noPush=true -Prelease.useAutomaticVersion=true -Prelease.releaseVersion=1.2.3 -Prelease.newVersion=1.2.4-SNAPSHOT" "${LOG_FILE}"
  grep -F "git push origin HEAD:refs/heads/release-work/1.2.3" "${LOG_FILE}"
  grep -F "tag_name=v1.2.3" "${GITHUB_OUTPUT}"
}

@test "prepare-release rejects an existing v-prefixed tag" {
  export ISSUE_BODY
  ISSUE_BODY="$(release_issue_body | sed 's/1.2.3/9.9.9/')"

  run bash .github/scripts/prepare-release.sh

  [ "$status" -ne 0 ]
  [[ "$output" == *"Tag v9.9.9 already exists."* ]]
}

@test "prepare-release rejects an existing release-work branch" {
  export ISSUE_BODY
  ISSUE_BODY="$(release_issue_body | sed 's/1.2.3/9.9.8/')"

  run bash .github/scripts/prepare-release.sh

  [ "$status" -ne 0 ]
  [[ "$output" == *"Branch release-work/9.9.8 already exists."* ]]
}

@test "publish-release creates an annotated v tag and atomic fast-forward push" {
  export ISSUE_BODY
  ISSUE_BODY="$(release_issue_body)"

  run bash .github/scripts/publish-release.sh

  [ "$status" -eq 0 ]
  grep -E "gh pr checks 77 --required --json .*bucket.*name.*state.*workflow" "${LOG_FILE}"
  grep -F "git config --global credential.helper store" "${LOG_FILE}"
  grep -F "git tag -a v1.2.3 release-commit -F" "${LOG_FILE}"
  grep -F "git push --atomic --follow-tags origin refs/remotes/origin/release-work/1.2.3:refs/heads/main" "${LOG_FILE}"
  grep -F "gh issue comment 123 --body Published\ v1.2.3\ to\ main." "${LOG_FILE}"
  grep -F "https://x-access-token:push-token@github.com" "${HOME}/.git-credentials"
}

@test "publish-release rejects missing required checks" {
  export ISSUE_BODY
  export GH_PR_CHECKS_JSON="[]"
  ISSUE_BODY="$(release_issue_body)"

  run bash .github/scripts/publish-release.sh

  [ "$status" -ne 0 ]
  [[ "$output" == *"Release PR has no reported required checks."* ]]
  ! grep -F "git tag -a v1.2.3" "${LOG_FILE}"
  ! grep -F "git push --atomic --follow-tags" "${LOG_FILE}"
}

@test "publish-release rejects non-passing required checks" {
  export ISSUE_BODY
  export GH_PR_CHECKS_JSON='[{"bucket":"fail","name":"Build and test","state":"FAILURE","workflow":"Continuous Integration"}]'
  ISSUE_BODY="$(release_issue_body)"

  run bash .github/scripts/publish-release.sh

  [ "$status" -ne 0 ]
  [[ "$output" == *"Release PR required checks have not all passed."* ]]
  [[ "$output" == *"- Build and test [Continuous Integration]: FAILURE"* ]]
  ! grep -F "git tag -a v1.2.3" "${LOG_FILE}"
  ! grep -F "git push --atomic --follow-tags" "${LOG_FILE}"
}

@test "create-release-branch cuts from the remote source branch tip by default" {
  export ISSUE_BODY
  ISSUE_BODY="$(branch_issue_body)"

  run bash .github/scripts/create-release-branch.sh

  [ "$status" -eq 0 ]
  grep -F "git config --global credential.helper store" "${LOG_FILE}"
  grep -F "git fetch origin +refs/heads/main:refs/remotes/origin/main --tags" "${LOG_FILE}"
  grep -F "git rev-parse --verify --end-of-options origin/main\\^\\{commit\\}" "${LOG_FILE}"
  grep -F "git merge-base --is-ancestor -- origin/main\\^\\{commit\\} origin/main" "${LOG_FILE}"
  grep -F "git push origin origin/main\\^\\{commit\\}:refs/heads/release/1.1" "${LOG_FILE}"
}

@test "create-release-branch rejects option-like source refs" {
  export ISSUE_BODY
  ISSUE_BODY="$(cat <<'EOF'
### Maintenance branch

release/1.1

### Source branch

main

### Source ref

--help
EOF
)"

  run bash .github/scripts/create-release-branch.sh

  [ "$status" -ne 0 ]
  [[ "$output" == *"Source ref must not start with '-'."* ]]
}

@test "create-release-branch rejects invalid maintenance branch names" {
  export ISSUE_BODY
  ISSUE_BODY="$(branch_issue_body | sed 's#release/1.1#main#')"

  run bash .github/scripts/create-release-branch.sh

  [ "$status" -ne 0 ]
  [[ "$output" == *"Maintenance branch must look like release/1.1."* ]]
}

@test "comment-issue-failure posts captured output and run URL" {
  failure_log="${BATS_TEST_TMPDIR}/failure.log"
  cat >"${failure_log}" <<'EOF'
Release version must look like 1.2.3.
push-token
EOF

  run bash .github/scripts/comment-issue-failure.sh "${failure_log}" "Prepare release"

  [ "$status" -eq 0 ]
  grep -F "gh issue comment 123 --body-file" "${LOG_FILE}"
  body_file="$(awk '/^gh issue comment 123 --body-file / { print $6 }' "${LOG_FILE}")"
  grep -F "Prepare release failed." "${body_file}"
  grep -F "Release version must look like 1.2.3." "${body_file}"
  grep -F "<redacted PUSH_TOKEN>" "${body_file}"
  ! grep -F "push-token" "${body_file}"
  grep -F "Run: https://github.com/connectbot/cbssh/actions/runs/456" "${body_file}"
}
