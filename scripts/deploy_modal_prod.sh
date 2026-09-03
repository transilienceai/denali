#!/usr/bin/env bash

set -euo pipefail

if [[ "${1:-}" != "--confirm-production" || "$#" -ne 1 ]]; then
  echo "Refusing production deployment without --confirm-production." >&2
  echo "Normal releases use the protected Deploy Modal production GitHub Actions workflow." >&2
  exit 2
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Refusing production deployment from a dirty worktree." >&2
  exit 2
fi

head_sha="$(git rev-parse HEAD)"
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  if [[ "${GITHUB_REF:-}" != "refs/heads/main" || "${GITHUB_SHA:-}" != "${head_sha}" ]]; then
    echo "Refusing production deployment: workflow source is not the checked-out main SHA." >&2
    exit 2
  fi
else
  if [[ "$(git branch --show-current)" != "main" ]]; then
    echo "Refusing production deployment from a branch other than main." >&2
    exit 2
  fi
  git fetch --quiet origin main
  if [[ "$(git rev-parse origin/main)" != "${head_sha}" ]]; then
    echo "Refusing production deployment: local main does not match origin/main." >&2
    exit 2
  fi
fi

prod_modal_environment="denali-prod"
export DENALI_MODAL_APP_NAME="denali-production"
export DENALI_MODAL_SECRET_NAME="custom-secret"
export DENALI_MODAL_PROVIDER_SECRET_NAME="${DENALI_MODAL_PROVIDER_SECRET_NAME:-denali-github-provider}"
export DENALI_MODAL_REGION="${DENALI_MODAL_REGION:-us-east}"
production_modal_origin="${DENALI_PRODUCTION_MODAL_ORIGIN:-https://transilience-denali-prod--denali-production-api.modal.run}"
production_web_origin="${DENALI_PRODUCTION_WEB_ORIGIN:-https://denali.transilience.cloud}"

modal run --env "${prod_modal_environment}" modal_app.py::configuration_status
modal run --env "${prod_modal_environment}" modal_app.py::migrate_database
modal run --env "${prod_modal_environment}" modal_app.py::database_status
modal deploy --env "${prod_modal_environment}" modal_app.py

curl --fail --silent --show-error "${production_modal_origin}/healthz" >/dev/null
curl --fail --silent --show-error "${production_web_origin}/api/healthz" >/dev/null
context_status="$(
  curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    "${production_modal_origin}/v1/context"
)"
if [[ "${context_status}" != "401" ]]; then
  echo "Production authorization smoke check failed: expected 401, received ${context_status}." >&2
  exit 1
fi

echo "Production smoke checks passed for commit ${head_sha}."
