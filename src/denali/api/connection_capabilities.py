"""Deliberate, bounded public projections for connection lifecycle capabilities."""

from __future__ import annotations

from typing import Any

from denali.connections.google_workspace import GOOGLE_WORKSPACE_AUDIT_SCOPE

CONNECTION_READS = frozenset(
    {
        "connection-setup-status",
        "connection-aws-template",
        "shared-connections",
        "shared-aws-status",
        "shared-aws-template",
    }
)

SUMMARY_FIELDS = frozenset(
    {
        "id",
        "provider",
        "display_name",
        "lifecycle_state",
        "health_state",
        "declared_scopes",
        "created_at",
        "updated_at",
        "last_validated_at",
    }
)
SHARED_FIELDS = frozenset(
    {
        "id",
        "connection_kind",
        "provider",
        "partition",
        "external_account_id",
        "deployment_region",
        "coverage_mode",
        "regions",
        "availability",
        "validated_scopes",
        "last_validated_at",
        "account_login",
        "repository_count",
    }
)


def connection_summary(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if key in SUMMARY_FIELDS}


def shared_summary(row: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in row.items() if key in SHARED_FIELDS}


def setup_summary(row: dict[str, Any]) -> dict[str, Any]:
    """Only explicit UI onboarding identifiers; no opaque configuration or state."""

    provider = row["provider"]
    configuration = row.get("configuration") or {}
    credential = row.get("credential_reference") or {}
    fields = {
        "aws": (
            "account_id",
            "partition",
            "deployment_region",
            "coverage_mode",
            "regions",
            "role_name",
        ),
        "azure": ("tenant_id", "cloud", "coverage_mode"),
        "entra": ("tenant_id", "coverage_mode"),
        "gcp": ("coverage_mode",),
        "github": ("coverage_mode",),
        "azure_repos": ("tenant_id", "organization", "coverage_mode"),
        "google_workspace": ("admin_email", "domain", "coverage_mode"),
    }.get(provider, ())
    setup = {field: configuration[field] for field in fields if field in configuration}
    public_identity_fields = {
        "aws": ("role_arn", "platform_connection_id"),
        "azure": ("client_id", "service_principal_id"),
        "entra": ("client_id",),
        "google_workspace": ("oauth_client_id", "service_account"),
        "gcp": ("principal_email", "principal_unique_id"),
        "github": ("app_id", "app_slug", "installation_id"),
        "azure_repos": ("client_id",),
    }.get(provider, ())
    setup.update(
        {field: credential[field] for field in public_identity_fields if field in credential}
    )
    if provider == "google_workspace":
        setup["required_oauth_scope"] = GOOGLE_WORKSPACE_AUDIT_SCOPE
    nested_fields = {
        "subscriptions": ("id", "name"),
        "projects": ("id", "number", "name"),
        "repositories": (
            "id",
            "node_id",
            "full_name",
            "name",
            "owner_id",
            "owner_login",
            "project_id",
            "project_name",
        ),
        "repository_candidates": ("id", "name", "project_id", "project_name"),
    }
    for field, allowed in nested_fields.items():
        values = configuration.get(field)
        if isinstance(values, list):
            setup[field] = [
                {key: item[key] for key in allowed if key in item}
                for item in values[:500]
                if isinstance(item, dict)
            ]
            setup[f"{field}_has_more"] = len(values) > 500
    onboarding = configuration.get("onboarding") or {}
    setup["onboarding"] = {
        key: onboarding[key]
        for key in (
            "method",
            "status",
            "completed_at",
            "url_expires_at",
            "consent_expires_at",
            "install_expires_at",
            "oauth_expires_at",
            "selection_expires_at",
        )
        if key in onboarding
    }
    return {"connection": connection_summary(row), "setup": setup}
