"""Hosted-runtime identity bootstrap helpers."""

from __future__ import annotations

import json
import os
import re
from collections.abc import MutableMapping
from pathlib import Path

from denali.connections.gcp import valid_gcp_service_account_email

_GCP_PROVIDER_PATTERN = re.compile(
    r"^projects/[0-9]+/locations/global/workloadIdentityPools/"
    r"[a-z0-9-]+/providers/[a-z0-9-]+$"
)
_GCP_SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"


def configure_gcp_external_account(
    environment: MutableMapping[str, str] | None = None,
    *,
    directory: Path = Path("/tmp"),
) -> bool:
    """Expose Modal's OIDC token through Google Application Default Credentials."""

    values = environment if environment is not None else os.environ
    provider = values.get("DENALI_GCP_WORKLOAD_IDENTITY_PROVIDER", "").strip()
    service_account = values.get("DENALI_GCP_RUNTIME_SERVICE_ACCOUNT", "").strip()
    identity_token = values.get("MODAL_IDENTITY_TOKEN", "").strip()

    if not provider and not service_account:
        return False
    if not provider or not service_account:
        raise RuntimeError("Google Cloud workload identity configuration is incomplete")
    if not _GCP_PROVIDER_PATTERN.fullmatch(provider):
        raise RuntimeError("Google Cloud workload identity provider is invalid")
    if not valid_gcp_service_account_email(service_account):
        raise RuntimeError("Google Cloud runtime service account is invalid")
    if not identity_token:
        return False

    directory.mkdir(parents=True, exist_ok=True)
    token_path = directory / "denali-modal-gcp-identity-token"
    credential_path = directory / "denali-google-application-credentials.json"
    _write_private_text(token_path, identity_token)
    credential = {
        "type": "external_account",
        "audience": f"//iam.googleapis.com/{provider}",
        "subject_token_type": _GCP_SUBJECT_TOKEN_TYPE,
        "token_url": "https://sts.googleapis.com/v1/token",
        "service_account_impersonation_url": (
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
            f"{service_account}:generateAccessToken"
        ),
        "credential_source": {"file": str(token_path)},
    }
    _write_private_text(credential_path, json.dumps(credential, sort_keys=True))
    values["GOOGLE_APPLICATION_CREDENTIALS"] = str(credential_path)
    return True


def _write_private_text(path: Path, value: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    path.chmod(0o600)
