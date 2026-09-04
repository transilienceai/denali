from __future__ import annotations

import json

import pytest

from denali.hosted import configure_gcp_external_account


def _environment() -> dict[str, str]:
    return {
        "DENALI_GCP_WORKLOAD_IDENTITY_PROVIDER": (
            "projects/1037196321759/locations/global/workloadIdentityPools/"
            "denali-production/providers/modal-production"
        ),
        "DENALI_GCP_RUNTIME_SERVICE_ACCOUNT": (
            "denali-production-runtime@iisecurity-denali-prod.iam.gserviceaccount.com"
        ),
        "MODAL_IDENTITY_TOKEN": "short-lived-modal-token",
    }


def test_configure_gcp_external_account_writes_private_adc(tmp_path) -> None:
    environment = _environment()

    assert configure_gcp_external_account(environment, directory=tmp_path)

    credential_path = tmp_path / "denali-google-application-credentials.json"
    token_path = tmp_path / "denali-modal-gcp-identity-token"
    credential = json.loads(credential_path.read_text())
    assert environment["GOOGLE_APPLICATION_CREDENTIALS"] == str(credential_path)
    assert token_path.read_text() == "short-lived-modal-token"
    assert credential["audience"].endswith(
        "/workloadIdentityPools/denali-production/providers/modal-production"
    )
    assert credential["credential_source"] == {"file": str(token_path)}
    assert "short-lived-modal-token" not in credential_path.read_text()
    assert token_path.stat().st_mode & 0o777 == 0o600
    assert credential_path.stat().st_mode & 0o777 == 0o600


def test_configure_gcp_external_account_allows_unconfigured_local_runtime(tmp_path) -> None:
    environment: dict[str, str] = {}

    assert not configure_gcp_external_account(environment, directory=tmp_path)
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in environment


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("DENALI_GCP_WORKLOAD_IDENTITY_PROVIDER", "invalid"),
        ("DENALI_GCP_RUNTIME_SERVICE_ACCOUNT", "not-an-account"),
    ],
)
def test_configure_gcp_external_account_rejects_invalid_identity(
    tmp_path, key: str, value: str
) -> None:
    environment = _environment()
    environment[key] = value

    with pytest.raises(RuntimeError):
        configure_gcp_external_account(environment, directory=tmp_path)


def test_configure_gcp_external_account_rejects_partial_configuration(tmp_path) -> None:
    environment = {
        "DENALI_GCP_WORKLOAD_IDENTITY_PROVIDER": (
            "projects/1037196321759/locations/global/workloadIdentityPools/"
            "denali-production/providers/modal-production"
        )
    }

    with pytest.raises(RuntimeError, match="incomplete"):
        configure_gcp_external_account(environment, directory=tmp_path)
