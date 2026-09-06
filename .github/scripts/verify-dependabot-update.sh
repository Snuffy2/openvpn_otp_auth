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
  github_actions)
    invalid_files="$(printf '%s\n' "${changed_files}" | grep -Ev '^\.github/workflows/[^/]+\.ya?ml$' || true)"
    [[ -z "${invalid_files}" ]] || reject_update "Refusing GitHub Actions auto-merge; unexpected files were:
${invalid_files}"
    ;;
  *)
    reject_update "Refusing unsupported ecosystem: ${PACKAGE_ECOSYSTEM}"
    ;;
esac

write_eligibility eligible
