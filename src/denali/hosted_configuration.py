"""Presence-only hosted configuration gates without exposing configuration values."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

CONFIGURATION_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "core": (
        "DENALI_DSN",
        "DENALI_MIGRATION_DSN",
        "DENALI_WEB_URL",
        "DENALI_CORS_ORIGINS",
        "CLERK_SECRET_KEY",
        "CLERK_JWT_KEY",
        "CLERK_AUTHORIZED_PARTIES",
    ),
    "aws": (
        "DENALI_MODAL_AWS_ROLE_ARN",
        "DENALI_AWS_ONBOARDING_BUCKET",
        "DENALI_AWS_PRINCIPAL_ARN",
    ),
    "azure": (
        "DENALI_AZURE_ONBOARDING_BUCKET",
        "DENALI_AZURE_CLIENT_ID",
        "DENALI_AZURE_CLIENT_SECRET",
    ),
    "entra": (
        "DENALI_ENTRA_CLIENT_ID",
        "DENALI_ENTRA_CLIENT_SECRET",
        "DENALI_ENTRA_CALLBACK_URL",
    ),
    "gcp": (
        "DENALI_GCP_ONBOARDING_BUCKET",
        "DENALI_GCP_OPERATOR_PROJECT_ID",
        "DENALI_GCP_WORKLOAD_IDENTITY_PROVIDER",
        "DENALI_GCP_RUNTIME_SERVICE_ACCOUNT",
    ),
    "google_workspace": (
        "DENALI_GOOGLE_WORKSPACE_SERVICE_ACCOUNT",
        "DENALI_GOOGLE_WORKSPACE_CLIENT_ID",
    ),
    "github": (
        "DENALI_GITHUB_APP_ID",
        "DENALI_GITHUB_CLIENT_ID",
        "DENALI_GITHUB_CLIENT_SECRET",
        "DENALI_GITHUB_APP_SLUG",
        "DENALI_GITHUB_PRIVATE_KEY",
        "DENALI_GITHUB_CALLBACK_URL",
    ),
    "azure_repos": (
        "DENALI_AZURE_CLIENT_ID",
        "DENALI_AZURE_CLIENT_SECRET",
        "DENALI_AZURE_REPOS_CALLBACK_URL",
    ),
}

P0_CONFIGURATION_GROUPS = tuple(CONFIGURATION_REQUIREMENTS)


def configuration_report(environment: Mapping[str, str]) -> dict[str, tuple[str, ...]]:
    """Return missing variable names per group without reading or returning values."""

    return {
        group: tuple(
            name for name in requirements if not environment.get(name, "").strip()
        )
        for group, requirements in CONFIGURATION_REQUIREMENTS.items()
    }


def require_configuration(
    report: Mapping[str, Sequence[str]], required_groups: Sequence[str]
) -> None:
    """Fail closed when a requested group is unknown or incomplete."""

    unknown = sorted(set(required_groups) - set(CONFIGURATION_REQUIREMENTS))
    if unknown:
        raise ValueError(f"unknown configuration groups: {','.join(unknown)}")
    incomplete = [group for group in required_groups if report[group]]
    if incomplete:
        raise RuntimeError(f"required configuration groups are incomplete: {','.join(incomplete)}")
