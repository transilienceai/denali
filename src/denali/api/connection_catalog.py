"""Server-owned connection presentation and conservative onboarding policy.

Feature flags admit a pilot; they are never evidence of provider parity or hosted
acceptance. Existing connection credentials remain the execution authority.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from denali.connections import (
    AWS_SCOPES,
    AZURE_REPOS_SCOPES,
    AZURE_SCOPES,
    ENTRA_SCOPES,
    GCP_SCOPES,
    GITHUB_SCOPES,
    GOOGLE_WORKSPACE_SCOPES,
)
from denali.integrations.shared_aws_session import shared_aws_selected_resource_enabled
from denali.integrations.shared_google_workspace import (
    PIN_FIELDS as WORKSPACE_PIN_FIELDS,
)
from denali.integrations.shared_google_workspace import (
    ROOT as WORKSPACE_ROOT,
)
from denali.integrations.shared_google_workspace import (
    require_ready,
    workspace_projection,
)
from denali.integrations.shared_microsoft import SHARED_AZURE_SCOPES

PROVIDERS = {
    "aws": ("Amazon Web Services", AWS_SCOPES, AWS_SCOPES),
    "azure": ("Microsoft Azure", AZURE_SCOPES, SHARED_AZURE_SCOPES),
    "entra": ("Microsoft Entra", ENTRA_SCOPES, ENTRA_SCOPES),
    "gcp": ("Google Cloud", GCP_SCOPES, GCP_SCOPES),
    "github": ("GitHub", GITHUB_SCOPES, GITHUB_SCOPES),
    "google_workspace": ("Google Workspace", GOOGLE_WORKSPACE_SCOPES, GOOGLE_WORKSPACE_SCOPES),
    "azure_repos": ("Azure Repos", AZURE_REPOS_SCOPES, AZURE_REPOS_SCOPES),
}
PARITY_GAPS = {
    "aws": ["selected_resource_coverage_requires_native"],
    "azure": [],
    "entra": [],
    "github": ["repository_changes_require_explicit_new_selection"],
    "gcp": [],
    "google_workspace": ["admitted_domain_binding_required"],
    "azure_repos": [],
}


def provider_catalog(
    *, native_available: dict[str, bool], shared_enabled: dict[str, bool], bridge_reason: str | None
) -> dict[str, Any]:
    items = []
    for provider, (label, native_scopes, shared_scopes) in PROVIDERS.items():
        shared = bool(shared_enabled.get(provider)) and bridge_reason is None
        native = bool(native_available.get(provider))
        path = "shared" if shared else "native" if native else "unavailable"
        reason_code = None if shared else bridge_reason or "shared_provider_not_enabled"
        reasons = {
            "hosting_required": "Shared connections require hosted organization sign-in.",
            "bridge_not_configured": "Shared connections are not configured in this environment.",
            "organization_not_admitted": "Shared connections are not enabled for this org.",
            "shared_provider_not_enabled": "This shared provider is not enabled here.",
            "shared_provider_not_implemented": "This provider uses Denali-managed access.",
        }
        gaps = list(PARITY_GAPS[provider])
        if provider == "aws" and shared_aws_selected_resource_enabled():
            gaps.remove("selected_resource_coverage_requires_native")
        items.append(
            {
                "provider": provider,
                "label": label,
                "onboarding_path": path,
                "shared_enabled": shared,
                "native_available": native,
                "supported_scopes": list(shared_scopes if shared else native_scopes),
                "parity_gaps": [*gaps, "hosted_acceptance_required"],
                **(
                    {
                        "supported_coverage_modes": [
                            "automatic",
                            "selected",
                            *(
                                ["selected-resource"]
                                if not shared or shared_aws_selected_resource_enabled()
                                else []
                            ),
                        ]
                    }
                    if provider == "aws"
                    else {}
                ),
                "reason_code": reason_code,
                "reason": reasons.get(reason_code),
            }
        )
    return {
        "items": items,
        "platform_only": False,
        "platform_only_blockers": [
            "provider_capability_parity_incomplete",
            "hosted_acceptance_required",
        ],
    }


def connection_presentation(
    row: dict[str, Any], *, can_write: bool, platform: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Add availability without rewriting last validated health or credential identity."""

    result = dict(row)
    reference = row.get("credential_reference") or {}
    shared = str(reference.get("type", "")).startswith("platform_shared_")
    active = row.get("lifecycle_state") == "active"
    busy = row.get("validation_state") == "running" or any(
        row.get(f"{prefix}_collection_state") == "running"
        for prefix in ("source", "evidence", "deployment", "runtime")
    )
    status = platform or {}
    availability = status.get("availability", "unknown") if shared else "not_applicable"
    result.update(
        management_source="platform" if shared else "denali",
        platform_availability=availability,
        platform_status_freshness=(
            status.get("freshness", "unavailable") if shared else "not_applicable"
        ),
        platform_last_checked_at=status.get("checked_at") if shared else None,
        platform_status_reason=status.get("reason_code") if shared else None,
    )
    usable = not shared or availability == "ready"
    last_validation = row.get("last_validation") or {}
    selected_results = last_validation.get("results") or []
    selected_ready = (
        row.get("configuration", {}).get("coverage_mode") == "selected-resource"
        and last_validation.get("credential_state") == "passed"
        and len(selected_results) == 2
        and {item.get("plane") for item in selected_results if isinstance(item, dict)}
        == {"aws_selected_lambda_configuration", "aws_selected_execution_role_policies"}
        and all(
            isinstance(item, dict) and item.get("state") == "passed" for item in selected_results
        )
    )
    result["actions"] = {
        "validate": can_write and active and not busy and usable,
        "collect": can_write
        and active
        and not busy
        and usable
        and (row.get("health_state") == "healthy" or selected_ready),
        "disconnect": can_write and active and not busy,
        "delete": can_write and not active and not busy,
        "manage_shared": can_write and shared,
        "review_scope": can_write
        and shared
        and row.get("provider") == "github"
        and active
        and not busy,
    }
    return result


def platform_statuses(
    rows: list[dict[str, Any]],
    *,
    client: Any,
    org: str | None,
    enabled: dict[str, bool] | None = None,
) -> dict[str, dict[str, Any]]:
    """One bounded metadata snapshot for the page; outages never hide native rows."""

    shared_rows = [
        row
        for row in rows
        if str((row.get("credential_reference") or {}).get("type", "")).startswith(
            "platform_shared_"
        )
    ]
    ids = {str(row["credential_reference"].get("platform_connection_id")) for row in shared_rows}
    if not ids:
        return {}
    checked = datetime.now(UTC).isoformat()
    unavailable = {"availability": "unknown", "freshness": "unavailable", "checked_at": checked}
    reason = (
        "bridge_not_configured" if client is None or org is None else "organization_not_admitted"
    )
    if client is None or org is None or not client.allows_org(org):
        return {key: {**unavailable, "reason_code": reason} for key in ids}
    result = {}
    allowed_rows = []
    for row in shared_rows:
        key = str(row["credential_reference"].get("platform_connection_id"))
        if (
            row.get("provider") == "aws"
            and row.get("configuration", {}).get("coverage_mode") == "selected-resource"
            and not shared_aws_selected_resource_enabled()
        ):
            result[key] = {**unavailable, "reason_code": "selected_resource_not_enabled"}
        elif enabled is not None and not enabled.get(row.get("provider", ""), False):
            result[key] = {**unavailable, "reason_code": "shared_provider_not_enabled"}
        else:
            allowed_rows.append(row)
    if not allowed_rows:
        return result

    generic_rows = [row for row in allowed_rows if row.get("provider") != "google_workspace"]
    try:
        listing = (
            client.request("GET", "/v1/connections", clerk_org_id=org)
            if generic_rows
            else {"items": []}
        )
        if not isinstance(listing, dict) or not isinstance(listing.get("items"), list):
            raise ValueError("invalid metadata snapshot")
        items = {
            item["id"]: item
            for item in listing["items"]
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        for row in generic_rows:
            key = str(row["credential_reference"].get("platform_connection_id"))
            item = items.get(key)
            availability = item.get("availability") if item else None
            if availability not in {
                "ready",
                "disabled",
                "needs_scope_grant",
                "requires_shared_setup",
                "unavailable",
                "needs_setup",
                "needs_validation",
            }:
                result[key] = {**unavailable, "reason_code": "platform_connection_unavailable"}
            else:
                result[key] = {
                    "availability": availability,
                    "freshness": "current",
                    "checked_at": checked,
                    "reason_code": None,
                }
    except Exception:  # No upstream transport, credential or provider detail is returned.
        for row in generic_rows:
            key = str(row["credential_reference"].get("platform_connection_id"))
            result[key] = {**unavailable, "reason_code": "platform_unavailable"}
    workspace_rows = [row for row in allowed_rows if row.get("provider") == "google_workspace"]
    if workspace_rows:
        try:
            listing = client.request(
                "GET", WORKSPACE_ROOT, clerk_org_id=org, max_response_bytes=128_000
            )
            if (
                not isinstance(listing, dict)
                or not isinstance(listing.get("items"), list)
                or len(listing["items"]) > 100
            ):
                raise ValueError("invalid Workspace inventory")
            current = {
                item["id"]: item
                for item in [workspace_projection(item, org=org) for item in listing["items"]]
            }
            for row in workspace_rows:
                key = str(row["credential_reference"].get("platform_connection_id"))
                item = current.get(key)
                pin = row.get("configuration", {}).get("platform_binding", {})
                if item is None or any(
                    item.get(field) != pin.get(field) for field in WORKSPACE_PIN_FIELDS
                ):
                    result[key] = {**unavailable, "reason_code": "platform_binding_changed"}
                    continue
                availability = (
                    "disabled" if item["lifecycle_state"] == "disabled" else "needs_scope_grant"
                )
                try:
                    require_ready(item, fresh=False)
                    availability = "ready"
                except ValueError:
                    pass
                result[key] = {
                    "availability": availability,
                    "freshness": "current",
                    "checked_at": checked,
                    "reason_code": None,
                }
        except Exception:
            for row in workspace_rows:
                key = str(row["credential_reference"].get("platform_connection_id"))
                result[key] = {**unavailable, "reason_code": "platform_unavailable"}
    return result
