"""Short-lived Google Cloud Shell project-selection setup scripts."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from denali.connections.aws_onboarding import S3OnboardingClient
from denali.connections.gcp import (
    GcpCredential,
    GcpHttpResponse,
    valid_gcp_project_id,
    valid_gcp_service_account_email,
)

GCP_ONBOARDING_SCRIPT_VERSION = "denali-gcp-project-reader-v2"


class GcpConnectionPrincipalProvisioner:
    """Create a unique, keyless Denali-owned service account for one connection."""

    def __init__(
        self,
        *,
        operator_project_id: str,
        credential_factory: Callable[[], GcpCredential] | None = None,
        request: Callable[..., GcpHttpResponse] | None = None,
    ):
        if not valid_gcp_project_id(operator_project_id):
            raise ValueError("Denali Google Cloud operator project ID is invalid")
        self._operator_project_id = operator_project_id
        self._credential_factory = credential_factory or _default_operator_credential
        self._request = request

    @property
    def operator_project_id(self) -> str:
        return self._operator_project_id

    def create_principal(self, *, connection_id: str, display_name: str) -> dict[str, str]:
        account_id = f"denali-{connection_id.replace('-', '')[:20]}"
        credential = self._credential_factory()
        request = self._request or _authorized_request(credential)
        response = request(
            "POST",
            (
                "https://iam.googleapis.com/v1/projects/"
                f"{self._operator_project_id}/serviceAccounts"
            ),
            json={
                "accountId": account_id,
                "serviceAccount": {
                    "displayName": f"Denali: {display_name}"[:100],
                    "description": f"Keyless read principal for Denali connection {connection_id}",
                },
            },
            timeout=15.0,
        )
        response.raise_for_status()
        principal = response.json()
        email = str(principal.get("email", ""))
        unique_id = str(principal.get("uniqueId", ""))
        expected_email = (
            f"{account_id}@{self._operator_project_id}.iam.gserviceaccount.com"
        )
        if (
            not valid_gcp_service_account_email(email)
            or email != expected_email
            or not unique_id.isdigit()
        ):
            raise RuntimeError("Google Cloud returned an invalid Denali service account")
        return {"principal_email": email, "principal_unique_id": unique_id}


class GcpSetupScriptLauncher:
    """Publish a reviewable GCP project-selection script for Cloud Shell."""

    def __init__(
        self,
        *,
        bucket_name: str,
        s3_client: S3OnboardingClient | None = None,
        expires_in_seconds: int = 3600,
        object_prefix: str = "denali/onboarding/gcp",
        now: Callable[[], datetime] | None = None,
        nonce: Callable[[], str] | None = None,
        token: Callable[[], str] | None = None,
    ):
        if not bucket_name.strip():
            raise ValueError("Google Cloud onboarding script bucket must not be blank")
        if not 300 <= expires_in_seconds <= 3600:
            raise ValueError(
                "Google Cloud onboarding URL lifetime must be between 300 and 3600 seconds"
            )
        self._bucket_name = bucket_name
        self._expires_in_seconds = expires_in_seconds
        self._object_prefix = object_prefix.strip("/")
        self._now = now or (lambda: datetime.now(UTC))
        self._nonce = nonce or (lambda: str(uuid4()))
        self._token = token or (lambda: f"{uuid4()}{uuid4()}")
        self._s3_client = s3_client or _default_s3_client()

    def create_launch(
        self,
        *,
        tenant_id: str,
        connection_id: str,
        connection: dict[str, Any],
    ) -> dict[str, Any]:
        principal_email = connection["credential_reference"]["principal_email"]
        if not valid_gcp_service_account_email(principal_email):
            raise ValueError("Denali Google Cloud service account email is invalid")
        completion_token = self._token()
        script = render_gcp_setup_script(
            principal_email=principal_email,
            completion_token=completion_token,
        )
        script_bytes = script.encode("utf-8")
        script_sha256 = hashlib.sha256(script_bytes).hexdigest()
        published_at = self._now()
        expires_at = published_at + timedelta(seconds=self._expires_in_seconds)
        object_key = f"{self._object_prefix}/{tenant_id}/{connection_id}/{self._nonce()}.sh"
        self._s3_client.put_object(
            Bucket=self._bucket_name,
            Key=object_key,
            Body=script_bytes,
            ContentType="text/x-shellscript",
            ContentDisposition=f'attachment; filename="denali-gcp-{connection_id}.sh"',
            CacheControl="no-store",
            ServerSideEncryption="AES256",
            Metadata={
                "denali-script-version": GCP_ONBOARDING_SCRIPT_VERSION,
                "denali-script-sha256": script_sha256,
            },
        )
        script_url = self._s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self._bucket_name, "Key": object_key},
            ExpiresIn=self._expires_in_seconds,
        )
        return {
            "cloud_shell_url": "https://shell.cloud.google.com/?show=terminal",
            "script_url": script_url,
            "setup_command": (
                f"curl -fsSL '{script_url}' -o denali-gcp-onboard.sh && "
                "bash denali-gcp-onboard.sh"
            ),
            "script_version": GCP_ONBOARDING_SCRIPT_VERSION,
            "script_sha256": script_sha256,
            "completion_token_sha256": hashlib.sha256(
                completion_token.encode()
            ).hexdigest(),
            "principal_email": principal_email,
            "published_at": published_at,
            "expires_at": expires_at,
        }


def render_gcp_setup_script(*, principal_email: str, completion_token: str) -> str:
    """Render an interactive, project-scoped, idempotent Google Cloud setup script."""

    return f"""#!/usr/bin/env bash
set -euo pipefail

DENALI_PRINCIPAL_EMAIL='{principal_email}'
DENALI_SETUP_TOKEN='{completion_token}'
DENALI_ROLES=('roles/cloudasset.viewer' 'roles/logging.viewer')
DENALI_REQUIRED_SERVICES=('cloudasset.googleapis.com' 'logging.googleapis.com')

command -v gcloud >/dev/null || {{ echo 'Google Cloud CLI is required.' >&2; exit 1; }}
command -v jq >/dev/null || {{ echo 'jq is required.' >&2; exit 1; }}

DENALI_ACTIVE_ACCOUNT="$(
  gcloud auth list --filter=status:ACTIVE --format='value(account)' | head -n 1
)"
[[ -n "$DENALI_ACTIVE_ACCOUNT" ]] || {{
  echo 'Sign in to Google Cloud Shell before running this setup.' >&2
  exit 1
}}

mapfile -t DENALI_PROJECTS < <(
  gcloud projects list --filter='lifecycleState:ACTIVE' --format=json |
    jq -r '.[] | [.projectId, .name, .projectNumber] | @tsv'
)

if [[ ${{#DENALI_PROJECTS[@]}} -eq 0 ]]; then
  echo 'No active projects were visible to the signed-in Google identity.' >&2
  exit 1
fi

echo "Active projects visible to $DENALI_ACTIVE_ACCOUNT:"
for index in "${{!DENALI_PROJECTS[@]}}"; do
  IFS=$'\t' read -r project_id project_name project_number <<< "${{DENALI_PROJECTS[$index]}}"
  printf '  %d) %s (%s, number %s)\n' \
    "$((index + 1))" "$project_name" "$project_id" "$project_number"
done
echo '  a) All projects'
read -r -p 'Select projects by number (space-separated) or a for all: ' DENALI_SELECTION

DENALI_SELECTED=()
if [[ "$DENALI_SELECTION" == 'a' || "$DENALI_SELECTION" == 'A' ]]; then
  DENALI_SELECTED=("${{DENALI_PROJECTS[@]}}")
else
  for choice in $DENALI_SELECTION; do
    [[ "$choice" =~ ^[0-9]+$ ]] || {{ echo "Invalid selection: $choice" >&2; exit 1; }}
    (( choice >= 1 && choice <= ${{#DENALI_PROJECTS[@]}} )) || {{
      echo "Selection out of range: $choice" >&2
      exit 1
    }}
    DENALI_SELECTED+=("${{DENALI_PROJECTS[$((choice - 1))]}}")
  done
fi

[[ ${{#DENALI_SELECTED[@]}} -gt 0 ]] || {{ echo 'Select at least one project.' >&2; exit 1; }}
DENALI_SELECTED_JSON='[]'
for selected in "${{DENALI_SELECTED[@]}}"; do
  IFS=$'\t' read -r project_id project_name project_number <<< "$selected"
  echo "Enabling required inventory APIs for $project_name ($project_id)..."
  gcloud services enable "${{DENALI_REQUIRED_SERVICES[@]}}" \
    --project "$project_id" \
    --quiet >/dev/null
  echo "Granting Denali bounded read access to $project_name ($project_id)..."
  for role in "${{DENALI_ROLES[@]}}"; do
    gcloud projects add-iam-policy-binding "$project_id" \
      --member "serviceAccount:$DENALI_PRINCIPAL_EMAIL" \
      --role "$role" \
      --condition=None \
      --quiet >/dev/null
  done
  DENALI_SELECTED_JSON="$(
    jq -c --arg id "$project_id" --arg name "$project_name" --arg number "$project_number" \
      '. + [{{id: $id, name: $name, number: $number}}]' <<< "$DENALI_SELECTED_JSON"
  )"
done

DENALI_COMPLETION_JSON="$(
  jq -cn \
    --arg token "$DENALI_SETUP_TOKEN" \
    --arg principal_email "$DENALI_PRINCIPAL_EMAIL" \
    --argjson projects "$DENALI_SELECTED_JSON" \
    '{{token: $token, principal_email: $principal_email, projects: $projects}}'
)"
DENALI_COMPLETION_CODE="$(
  printf '%s' "$DENALI_COMPLETION_JSON" | base64 | tr -d '\n' | tr '+/' '-_' | tr -d '='
)"

echo
echo 'Google Cloud setup completed. Copy this entire completion code back into Denali:'
echo "DENALI_GCP_SETUP_COMPLETE=$DENALI_COMPLETION_CODE"
"""


def _default_s3_client() -> S3OnboardingClient:
    try:
        import boto3
    except ImportError as error:  # pragma: no cover - installation contract
        raise RuntimeError(
            "install Denali with the aws extra to publish onboarding scripts"
        ) from error
    return boto3.client("s3")


def _default_operator_credential() -> GcpCredential:
    try:
        import google.auth
    except ImportError as error:  # pragma: no cover - installation contract
        raise RuntimeError("install Denali with the gcp extra to provision Google Cloud") from error
    credential, _ = google.auth.default(
        scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    return credential


def _authorized_request(credential: GcpCredential) -> Callable[..., GcpHttpResponse]:
    try:
        from google.auth.transport.requests import AuthorizedSession
    except ImportError as error:  # pragma: no cover - installation contract
        raise RuntimeError("google-auth is required for Google Cloud provisioning") from error
    return AuthorizedSession(credential).request
