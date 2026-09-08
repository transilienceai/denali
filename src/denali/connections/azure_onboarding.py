"""Short-lived Azure Cloud Shell setup scripts."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode, urlparse
from uuid import uuid4

from denali.connections.aws_onboarding import S3OnboardingClient
from denali.connections.azure import AZURE_MANAGEMENT_SCOPE, _default_credential, valid_azure_uuid

AZURE_ONBOARDING_SCRIPT_VERSION = "denali-azure-subscription-reader-v2"


class AzureSetupScriptLauncher:
    """Publish a reviewable subscription-selection script for Azure Cloud Shell."""

    def __init__(
        self,
        *,
        bucket_name: str,
        client_id: str,
        redirect_uri: str,
        web_url: str | None = None,
        s3_client: S3OnboardingClient | None = None,
        expires_in_seconds: int = 3600,
        object_prefix: str = "denali/onboarding/azure",
        now: Callable[[], datetime] | None = None,
        nonce: Callable[[], str] | None = None,
        token: Callable[[], str] | None = None,
        consent_verifier: Callable[[str], None] | None = None,
    ):
        if not bucket_name.strip():
            raise ValueError("Azure onboarding script bucket must not be blank")
        if not valid_azure_uuid(client_id):
            raise ValueError("Denali Azure application client ID is invalid")
        for url, label in ((redirect_uri, "consent redirect"), (web_url or redirect_uri, "web")):
            parsed = urlparse(url)
            is_https = parsed.scheme == "https" and bool(parsed.netloc)
            is_local_http = parsed.scheme == "http" and parsed.hostname in {
                "127.0.0.1",
                "localhost",
            }
            if not (is_https or is_local_http):
                raise ValueError(f"Denali Azure {label} URL is invalid")
        if not 300 <= expires_in_seconds <= 3600:
            raise ValueError("Azure onboarding URL lifetime must be between 300 and 3600 seconds")
        self._bucket_name = bucket_name
        self._client_id = client_id
        self._redirect_uri = redirect_uri
        self._web_url = (web_url or redirect_uri).rstrip("/")
        self._expires_in_seconds = expires_in_seconds
        self._object_prefix = object_prefix.strip("/")
        self._now = now or (lambda: datetime.now(UTC))
        self._nonce = nonce or (lambda: str(uuid4()))
        self._token = token or (lambda: f"{uuid4()}{uuid4()}")
        self._consent_verifier = consent_verifier
        self._s3_client = s3_client or _default_s3_client()

    @property
    def client_id(self) -> str:
        return self._client_id

    @property
    def web_url(self) -> str:
        return self._web_url

    def verify_tenant_identity(self, customer_tenant_id: str) -> None:
        """Prove that the Denali enterprise application exists in the customer tenant."""

        if not valid_azure_uuid(customer_tenant_id):
            raise ValueError("Azure customer tenant ID is invalid")
        if self._consent_verifier is not None:
            self._consent_verifier(customer_tenant_id)
            return
        _default_credential(customer_tenant_id).get_token(AZURE_MANAGEMENT_SCOPE)

    def create_launch(
        self,
        *,
        tenant_id: str,
        connection_id: str,
        connection: dict[str, Any],
        include_consent: bool = True,
    ) -> dict[str, Any]:
        customer_tenant_id = connection["configuration"]["tenant_id"]
        if not valid_azure_uuid(customer_tenant_id):
            raise ValueError("Azure customer tenant ID is invalid")
        callback_token = self._token()
        consent_state = (
            f"{tenant_id}.{connection_id}.{self._token()}" if include_consent else None
        )
        script = render_setup_script(
            client_id=self._client_id,
            customer_tenant_id=customer_tenant_id,
            callback_token=callback_token,
        )
        script_bytes = script.encode("utf-8")
        script_sha256 = hashlib.sha256(script_bytes).hexdigest()
        published_at = self._now()
        expires_at = published_at + timedelta(seconds=self._expires_in_seconds)
        object_key = (
            f"{self._object_prefix}/{tenant_id}/{connection_id}/{self._nonce()}.sh"
        )
        self._s3_client.put_object(
            Bucket=self._bucket_name,
            Key=object_key,
            Body=script_bytes,
            ContentType="text/x-shellscript",
            ContentDisposition=f'attachment; filename="denali-azure-{connection_id}.sh"',
            CacheControl="no-store",
            ServerSideEncryption="AES256",
            Metadata={
                "denali-script-version": AZURE_ONBOARDING_SCRIPT_VERSION,
                "denali-script-sha256": script_sha256,
            },
        )
        script_url = self._s3_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self._bucket_name, "Key": object_key},
            ExpiresIn=self._expires_in_seconds,
        )
        consent_query = (
            urlencode(
                {
                    "client_id": self._client_id,
                    "redirect_uri": self._redirect_uri,
                    "state": consent_state,
                }
            )
            if consent_state is not None
            else None
        )
        return {
            "consent_url": (
                f"https://login.microsoftonline.com/{customer_tenant_id}/adminconsent?"
                f"{consent_query}"
                if consent_query is not None
                else None
            ),
            "consent_state_sha256": (
                hashlib.sha256(consent_state.encode()).hexdigest()
                if consent_state is not None
                else None
            ),
            "cloud_shell_url": "https://shell.azure.com/bash",
            "script_url": script_url,
            "setup_command": (
                f"curl -fsSL '{script_url}' -o denali-azure-onboard.sh && "
                "bash denali-azure-onboard.sh"
            ),
            "script_version": AZURE_ONBOARDING_SCRIPT_VERSION,
            "script_sha256": script_sha256,
            "callback_token_sha256": hashlib.sha256(callback_token.encode()).hexdigest(),
            "client_id": self._client_id,
            "published_at": published_at,
            "expires_at": expires_at,
        }


def render_setup_script(
    *, client_id: str, customer_tenant_id: str, callback_token: str
) -> str:
    """Render a transparent, interactive, idempotent Azure subscription setup script."""

    return f"""#!/usr/bin/env bash
set -euo pipefail

DENALI_CLIENT_ID='{client_id}'
DENALI_CUSTOMER_TENANT_ID='{customer_tenant_id}'
DENALI_SETUP_TOKEN='{callback_token}'
DENALI_READER_ROLE_ID='acdd72a7-3385-48ef-bd42-f606fba81ae7'

command -v az >/dev/null || {{ echo 'Azure CLI is required.' >&2; exit 1; }}
command -v jq >/dev/null || {{ echo 'jq is required.' >&2; exit 1; }}

mapfile -t DENALI_SUBSCRIPTIONS < <(
  az account list --all --refresh --output json |
    jq -r --arg tenant "$DENALI_CUSTOMER_TENANT_ID" \
      '.[] | select(.tenantId == $tenant and .state == "Enabled") | [.id, .name] | @tsv'
)

if [[ ${{#DENALI_SUBSCRIPTIONS[@]}} -eq 0 ]]; then
  echo 'No enabled subscriptions were visible in the configured tenant.' >&2
  echo "Run: az login --tenant $DENALI_CUSTOMER_TENANT_ID --use-device-code" >&2
  echo 'Then run this setup command again.' >&2
  exit 1
fi

FIRST_SUBSCRIPTION_ID="${{DENALI_SUBSCRIPTIONS[0]%%$'\\t'*}}"
az account set --subscription "$FIRST_SUBSCRIPTION_ID"
if ! DENALI_SERVICE_PRINCIPAL_ID="$(
  az ad sp show --id "$DENALI_CLIENT_ID" --query id -o tsv 2>/dev/null
)" \
  || [[ -z "$DENALI_SERVICE_PRINCIPAL_ID" ]]; then
  echo 'Denali enterprise application was not found in this tenant.' >&2
  echo 'Return to Denali, complete Add Denali to tenant, then prepare a fresh setup command.' >&2
  exit 1
fi

echo 'Enabled subscriptions visible to your signed-in Azure identity:'
for index in "${{!DENALI_SUBSCRIPTIONS[@]}}"; do
  IFS=$'\\t' read -r subscription_id subscription_name <<< "${{DENALI_SUBSCRIPTIONS[$index]}}"
  printf '  %d) %s (%s)\\n' "$((index + 1))" "$subscription_name" "$subscription_id"
done
echo '  a) All subscriptions'
read -r -p 'Select subscriptions by number (space-separated) or a for all: ' DENALI_SELECTION

DENALI_SELECTED=()
if [[ "$DENALI_SELECTION" == 'a' || "$DENALI_SELECTION" == 'A' ]]; then
  DENALI_SELECTED=("${{DENALI_SUBSCRIPTIONS[@]}}")
else
  for choice in $DENALI_SELECTION; do
    [[ "$choice" =~ ^[0-9]+$ ]] || {{ echo "Invalid selection: $choice" >&2; exit 1; }}
    (( choice >= 1 && choice <= ${{#DENALI_SUBSCRIPTIONS[@]}} )) || {{
      echo "Selection out of range: $choice" >&2
      exit 1
    }}
    DENALI_SELECTED+=("${{DENALI_SUBSCRIPTIONS[$((choice - 1))]}}")
  done
fi

[[ ${{#DENALI_SELECTED[@]}} -gt 0 ]] || {{ echo 'Select at least one subscription.' >&2; exit 1; }}

DENALI_SELECTED_JSON='[]'
for selected in "${{DENALI_SELECTED[@]}}"; do
  IFS=$'\\t' read -r subscription_id subscription_name <<< "$selected"
  echo "Assigning Reader to $subscription_name ($subscription_id)..."
  az role assignment create \
    --assignee-object-id "$DENALI_SERVICE_PRINCIPAL_ID" \
    --assignee-principal-type ServicePrincipal \
    --role "$DENALI_READER_ROLE_ID" \
    --scope "/subscriptions/$subscription_id" \
    --only-show-errors --output none
  DENALI_SELECTED_JSON="$(
    jq -c --arg id "$subscription_id" --arg name "$subscription_name" \
      '. + [{{id: $id, name: $name}}]' <<< "$DENALI_SELECTED_JSON"
  )"
done

DENALI_COMPLETION_JSON="$(
  jq -cn \
    --arg token "$DENALI_SETUP_TOKEN" \
    --arg tenant_id "$DENALI_CUSTOMER_TENANT_ID" \
    --arg service_principal_id "$DENALI_SERVICE_PRINCIPAL_ID" \
    --argjson subscriptions "$DENALI_SELECTED_JSON" \
    '{{token: $token, tenant_id: $tenant_id,
      service_principal_id: $service_principal_id, subscriptions: $subscriptions}}'
)"
DENALI_COMPLETION_CODE="$(
  printf '%s' "$DENALI_COMPLETION_JSON" | base64 | tr -d '\\n' | tr '+/' '-_' | tr -d '='
)"

echo
echo 'Azure setup completed. Copy this entire completion code back into Denali:'
echo "DENALI_SETUP_COMPLETE=$DENALI_COMPLETION_CODE"
"""


def _default_s3_client() -> S3OnboardingClient:
    try:
        import boto3
    except ImportError as error:  # pragma: no cover - installation contract
        raise RuntimeError(
            "install Denali with the aws extra to publish onboarding scripts"
        ) from error
    return boto3.client("s3")
