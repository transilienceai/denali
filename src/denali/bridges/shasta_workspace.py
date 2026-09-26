"""One-customer Google Workspace snapshot handoff to Shasta.

The binding is operator-configured in Modal Secrets, never selected by an HTTP caller.
Only the receipt is returned; delegated credentials and raw provider payloads stay in
the Denali worker process.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from uuid import UUID

SHASTA_PILOT_URL = "https://shasta.transilience.cloud/pilot"

_CONFIG_KEYS = (
    "DENALI_SHASTA_WORKSPACE_TENANT_ID",
    "DENALI_SHASTA_WORKSPACE_CONNECTION_ID",
    "DENALI_SHASTA_WORKSPACE_SOURCE_ID",
    "DENALI_SHASTA_WORKSPACE_BRIDGE_SECRET",
)


def _safe_google_error(error: Exception) -> dict[str, str]:
    """Return only bounded diagnostic labels, never provider exception text."""

    message = str(error).lower()
    known_codes = (
        "unauthorized_client",
        "invalid_grant",
        "invalid_scope",
        "permission_denied",
        "access_denied",
    )
    return {
        "error_type": type(error).__name__,
        "error_code": next((code for code in known_codes if code in message), "unclassified"),
    }


def diagnose_pilot_workspace() -> dict[str, object]:
    """Probe fixed Workspace read planes from the deployed app without returning data."""

    from datetime import UTC, datetime, timedelta

    from google.auth import default
    from google.auth.impersonated_credentials import Credentials
    from google.auth.transport.requests import AuthorizedSession, Request

    from denali.store.repository import PostgresInventoryRepository

    if not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"):
        return {"stage": "adc_configuration", "state": "missing"}
    tenant_id = str(UUID(os.environ["DENALI_SHASTA_WORKSPACE_TENANT_ID"]))
    connection_id = str(UUID(os.environ["DENALI_SHASTA_WORKSPACE_CONNECTION_ID"]))
    repository = PostgresInventoryRepository(os.environ["DENALI_DSN"])
    connection = repository.get_connection_validation_target(tenant_id, connection_id)
    if not connection or connection["lifecycle_state"] != "active":
        return {"stage": "connection", "state": "unavailable"}
    if connection["provider"] != "google_workspace":
        return {"stage": "connection", "state": "provider_mismatch"}
    configuration = connection["configuration"]
    domain = str(configuration["domain"])
    admin_email = str(configuration["admin_email"])
    service_account = os.environ["DENALI_GOOGLE_WORKSPACE_SERVICE_ACCOUNT"]
    transport = Request()
    try:
        source, _ = default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        source.refresh(transport)
    except Exception as error:
        return {"stage": "workload_identity", "state": "failed", **_safe_google_error(error)}

    now = datetime.now(UTC)
    start = now - timedelta(hours=1)
    probes = (
        ("directory.users.read", "https://www.googleapis.com/auth/admin.directory.user.readonly",
         "/admin/directory/v1/users", {"domain": domain, "maxResults": "1"}),
        ("directory.groups.read", "https://www.googleapis.com/auth/admin.directory.group.readonly",
         "/admin/directory/v1/groups", {"domain": domain, "maxResults": "1"}),
        ("reports.login.read", "https://www.googleapis.com/auth/admin.reports.audit.readonly",
         "/admin/reports/v1/activity/users/all/applications/login",
         {"startTime": start.isoformat(), "endTime": now.isoformat(), "maxResults": "1"}),
        ("reports.admin.read", "https://www.googleapis.com/auth/admin.reports.audit.readonly",
         "/admin/reports/v1/activity/users/all/applications/admin",
         {"startTime": start.isoformat(), "endTime": now.isoformat(), "maxResults": "1"}),
    )
    results: dict[str, int] = {}
    for capability, scope, path, params in probes:
        try:
            delegated = Credentials(
                source_credentials=source,
                target_principal=service_account,
                target_scopes=[scope],
                subject=admin_email,
                lifetime=900,
            )
            delegated.refresh(transport)
        except Exception as error:
            return {
                "stage": "delegated_token", "state": "failed", "capability": capability,
                **_safe_google_error(error),
            }
        try:
            response = AuthorizedSession(delegated).get(
                f"https://admin.googleapis.com{path}", params=params, timeout=20
            )
        except Exception as error:
            return {
                "stage": "provider_request", "state": "failed", "capability": capability,
                **_safe_google_error(error),
            }
        results[capability] = response.status_code
    return {"stage": "provider_request", "state": "complete", "http_statuses": results}


def collect_pilot_workspace(
    *,
    environment: Mapping[str, str] | None = None,
    publisher: Callable[..., dict] | None = None,
) -> dict:
    """Collect one fixed, tenant-bound Workspace source and publish a signed snapshot."""

    settings = os.environ if environment is None else environment
    values = {name: settings.get(name, "").strip() for name in _CONFIG_KEYS}
    if any(not value for value in values.values()):
        raise RuntimeError("The Shasta Workspace bridge configuration is incomplete")
    tenant_id = str(UUID(values["DENALI_SHASTA_WORKSPACE_TENANT_ID"]))
    connection_id = str(UUID(values["DENALI_SHASTA_WORKSPACE_CONNECTION_ID"]))
    source_id = str(UUID(values["DENALI_SHASTA_WORKSPACE_SOURCE_ID"]))
    secret = values["DENALI_SHASTA_WORKSPACE_BRIDGE_SECRET"].encode()
    if len(secret) < 32:
        raise RuntimeError("The Shasta Workspace bridge secret is too short")
    if publisher is None:
        from denali.bridges.shasta_workspace_snapshot import collect_and_publish

        publisher = collect_and_publish
    return publisher(
        provider="google_workspace",
        tenant_id=tenant_id,
        connection_id=connection_id,
        source_id=source_id,
        shasta_url=SHASTA_PILOT_URL,
        bridge_secret=secret,
    )
