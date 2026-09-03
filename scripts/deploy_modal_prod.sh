#!/usr/bin/env bash

set -euo pipefail

prod_modal_environment="denali-prod"
export DENALI_MODAL_APP_NAME="denali-production"
export DENALI_MODAL_SECRET_NAME="custom-secret"
export DENALI_MODAL_PROVIDER_SECRET_NAME="${DENALI_MODAL_PROVIDER_SECRET_NAME:-denali-github-provider}"
export DENALI_MODAL_REGION="${DENALI_MODAL_REGION:-us-east}"

modal run --env "${prod_modal_environment}" modal_app.py::configuration_status
modal run --env "${prod_modal_environment}" modal_app.py::migrate_database
modal run --env "${prod_modal_environment}" modal_app.py::database_status
modal deploy --env "${prod_modal_environment}" modal_app.py
