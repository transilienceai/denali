"""Explicit, connection-pinned native GCP credentials without changing ambient ADC.

Workspace and legacy GCP references deliberately keep their existing ADC chain.
Only server-created references carrying the versioned profile opt into this chain.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from typing import Any

NATIVE_GCP_CREDENTIAL_PROFILE = "native_gcp_wif_v1"
NATIVE_GCP_PROVIDER_ENV = "DENALI_GCP_NATIVE_WORKLOAD_IDENTITY_PROVIDER"
NATIVE_GCP_RUNTIME_ENV = "DENALI_GCP_NATIVE_RUNTIME_SERVICE_ACCOUNT"
_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_PROVIDER = re.compile(
    r"^projects/[0-9]+/locations/global/workloadIdentityPools/"
    r"[a-z0-9-]+/providers/[a-z0-9-]+$"
)
_PROJECT = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_SERVICE_ACCOUNT = re.compile(
    r"^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]"
    r"\.iam\.gserviceaccount\.com$"
)


def native_gcp_profile_from_environment(
    environment: Mapping[str, str] | None = None,
) -> str | None:
    """Validate the optional pair; a partial/invalid pair must never select ADC."""

    values = os.environ if environment is None else environment
    provider = values.get(NATIVE_GCP_PROVIDER_ENV, "").strip()
    runtime = values.get(NATIVE_GCP_RUNTIME_ENV, "").strip()
    if not provider and not runtime:
        return None
    if not provider or not runtime:
        raise ValueError("Native Google Cloud workload identity configuration is incomplete")
    if not _PROVIDER.fullmatch(provider) or not _SERVICE_ACCOUNT.fullmatch(runtime):
        raise ValueError("Native Google Cloud workload identity configuration is invalid")
    return NATIVE_GCP_CREDENTIAL_PROFILE


class ModalIdentityTokenSupplier:
    """Read the current process identity token on demand, without retaining or writing it."""

    def get_subject_token(self, context: Any, request: Any) -> str:
        token = os.environ.get("MODAL_IDENTITY_TOKEN", "").strip()
        if not token:
            raise ValueError("Native Google Cloud workload identity token is unavailable")
        return token


def native_gcp_source_credentials() -> Any:
    """Construct explicit in-memory WIF credentials for the native GCP operator."""

    if native_gcp_profile_from_environment() != NATIVE_GCP_CREDENTIAL_PROFILE:
        raise ValueError("Native Google Cloud workload identity configuration is unavailable")
    from google.auth import identity_pool

    provider = os.environ[NATIVE_GCP_PROVIDER_ENV].strip()
    runtime = os.environ[NATIVE_GCP_RUNTIME_ENV].strip()
    return identity_pool.Credentials(
        audience=f"//iam.googleapis.com/{provider}",
        subject_token_type="urn:ietf:params:oauth:token-type:jwt",
        token_url="https://sts.googleapis.com/v1/token",
        service_account_impersonation_url=(
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
            f"{runtime}:generateAccessToken"
        ),
        subject_token_supplier=ModalIdentityTokenSupplier(),
        scopes=[_CLOUD_PLATFORM_SCOPE],
    )


def validate_gcp_credential_reference(reference: Mapping[str, Any]) -> str | None:
    """Validate explicit profile identity before any credentials or network request."""

    if "operator_credential_profile" not in reference:
        return None
    if reference["operator_credential_profile"] != NATIVE_GCP_CREDENTIAL_PROFILE:
        raise ValueError("Native Google Cloud credential profile is unsupported")
    if native_gcp_profile_from_environment() != NATIVE_GCP_CREDENTIAL_PROFILE:
        raise ValueError("Native Google Cloud workload identity configuration is unavailable")
    operator_project = reference.get("operator_project_id")
    configured_project = os.environ.get("DENALI_GCP_OPERATOR_PROJECT_ID", "").strip()
    principal = reference.get("principal_email")
    if (
        not isinstance(operator_project, str)
        or not _PROJECT.fullmatch(operator_project)
        or operator_project != configured_project
        or not isinstance(principal, str)
        or not _SERVICE_ACCOUNT.fullmatch(principal)
        or principal.rsplit("@", 1)[1] != f"{operator_project}.iam.gserviceaccount.com"
    ):
        raise ValueError("Native Google Cloud reader does not match its operator project")
    return NATIVE_GCP_CREDENTIAL_PROFILE


def credential_for_gcp_reference(reference: Mapping[str, Any]) -> Any:
    """Resolve only the saved credential profile; never upgrade a legacy reference."""

    profile = validate_gcp_credential_reference(reference)
    principal = reference["principal_email"]
    if profile is None:
        # Keep the existing helper and its injected/local ADC behavior exactly intact.
        from denali.connections.gcp import _default_credential

        return _default_credential(principal)
    from google.auth import impersonated_credentials

    return impersonated_credentials.Credentials(
        source_credentials=native_gcp_source_credentials(),
        target_principal=principal,
        target_scopes=[_CLOUD_PLATFORM_SCOPE],
        lifetime=900,
    )
