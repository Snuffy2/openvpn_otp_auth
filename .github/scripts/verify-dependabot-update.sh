#!/usr/bin/env bash

# Verify the policy before any write-scoped job changes an auto-merge request.
set -euo pipefail

write_eligibility() {
  printf 'eligibility=%s\n' "$1" >> "${GITHUB_OUTPUT}"
}

reject_update() {
  echo "$1"
  write_eligibility rejected
  exit 1
}

if [[ -z "${PACKAGE_ECOSYSTEM}" ]]; then
  echo "Dependabot metadata did not report a package ecosystem" >&2
  exit 1
fi

if [[ -z "${PULL_REQUEST_ACTION:-}" || -z "${EVENT_SENDER_LOGIN:-}" ]]; then
  echo "Pull request event provenance was not available" >&2
  exit 1
fi

case "${PULL_REQUEST_ACTION}" in
  opened|synchronize)
    [[ "${EVENT_SENDER_LOGIN}" == "dependabot[bot]" ]] || reject_update \
      "Refusing auto-merge; ${PULL_REQUEST_ACTION} was not produced by Dependabot"
    ;;
  reopened)
    # A reopened event does not identify the actor that produced its current head.
    reject_update "Refusing auto-merge; reopened events cannot prove current-head provenance"
    ;;
  *)
    reject_update "Refusing auto-merge; unsupported pull request event: ${PULL_REQUEST_ACTION}"
    ;;
esac

if changed_files="$(gh api --paginate \
  "repos/${REPOSITORY}/pulls/${PR_NUMBER}/files?per_page=100" \
  --jq '.[].filename')"; then
  :
else
  status=$?
  echo "Could not query changed files for pull request ${PR_NUMBER}" >&2
  exit "${status}"
fi

[[ -n "${changed_files}" ]] || reject_update "Refusing auto-merge; no changed files were reported"

case "${PACKAGE_ECOSYSTEM}" in
  uv)
    [[ "${changed_files}" == "uv.lock" ]] || reject_update "Refusing uv auto-merge; changed files were:
${changed_files}"
    ;;
  github-actions)
    invalid_files="$(printf '%s\n' "${changed_files}" | grep -Ev '^\.github/workflows/[^/]+\.ya?ml$' || true)"
    [[ -z "${invalid_files}" ]] || reject_update "Refusing GitHub Actions auto-merge; unexpected files were:
${invalid_files}"
    ;;
  *)
    reject_update "Refusing unsupported ecosystem: ${PACKAGE_ECOSYSTEM}"
    ;;
esac

write_eligibility eligible
