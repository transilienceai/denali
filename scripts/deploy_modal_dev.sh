#!/usr/bin/env bash

set -euo pipefail

dev_modal_environment="denali-dev"
export DENALI_MODAL_APP_NAME="denali-dev"
export DENALI_MODAL_SECRET_NAME="denali-dev"
export DENALI_MODAL_PROVIDER_SECRET_NAME="denali-github-provider"
export DENALI_MODAL_REGION="${DENALI_MODAL_REGION:-us-east}"

modal run --env "${dev_modal_environment}" modal_app.py::migrate_database
modal deploy --env "${dev_modal_environment}" modal_app.py
