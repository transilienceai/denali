#!/usr/bin/env bash

set -euo pipefail

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Refusing development deployment from a dirty worktree." >&2
  exit 2
fi

head_sha="$(git rev-parse HEAD)"
if [[ "${GITHUB_ACTIONS:-}" == "true" ]]; then
  if [[ "${GITHUB_REF:-}" != "refs/heads/dev" || "${GITHUB_SHA:-}" != "${head_sha}" ]]; then
    echo "Refusing development deployment: workflow source is not the checked-out dev SHA." >&2
    exit 2
  fi
fi

git fetch --quiet origin dev
if [[ "$(git rev-parse origin/dev)" != "${head_sha}" ]]; then
  echo "Refusing development deployment: checkout does not match origin/dev." >&2
  exit 2
fi

dev_modal_environment="denali-dev"
export DENALI_MODAL_APP_NAME="denali-dev"
export DENALI_MODAL_SECRET_NAME="denali-dev"
export DENALI_MODAL_PROVIDER_SECRET_NAME="denali-github-provider"
export DENALI_MODAL_SHARED_CONNECTIONS_ORIGIN="${DENALI_MODAL_SHARED_CONNECTIONS_ORIGIN:-https://transilience-transilience-platform-dev--transilience-pla-73050c.modal.run}"
export DENALI_MODAL_REGION="${DENALI_MODAL_REGION:-us-east}"
development_modal_origin="${DENALI_DEVELOPMENT_MODAL_ORIGIN:-https://transilience-denali-dev--denali-dev-api.modal.run}"
development_web_origin="${DENALI_DEVELOPMENT_WEB_ORIGIN:-https://denali-dev.transilience.cloud}"

modal run --env "${dev_modal_environment}" modal_app.py::configuration_status
modal run --env "${dev_modal_environment}" modal_app.py::migrate_database
modal run --env "${dev_modal_environment}" modal_app.py::database_status
modal deploy --env "${dev_modal_environment}" modal_app.py

curl --fail --silent --show-error --retry 6 --retry-delay 5 --retry-all-errors \
  "${development_modal_origin}/healthz" >/dev/null
curl --fail --silent --show-error --retry 6 --retry-delay 5 --retry-all-errors \
  "${development_modal_origin}/openapi.json" | python3 -c '
import json
import sys

paths = json.load(sys.stdin)["paths"]
if "/v1/shared/connections" not in paths:
    raise SystemExit("Development shared-connections route is absent from deployed OpenAPI")
'
curl --fail --silent --show-error --retry 6 --retry-delay 5 --retry-all-errors \
  "${development_web_origin}/api/healthz" >/dev/null
context_status="$(
  curl --silent --show-error --output /dev/null --write-out '%{http_code}' \
    "${development_modal_origin}/v1/context"
)"
if [[ "${context_status}" != "401" ]]; then
  echo "Development authorization smoke check failed: expected 401, received ${context_status}." >&2
  exit 1
fi

echo "Development smoke checks passed for commit ${head_sha}."
