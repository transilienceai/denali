"""Resolve an AWS session from a server-bound shared connection lease."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any
from uuid import UUID

from denali.integrations.shared_connections_client import SharedConnectionsClient


def leased_aws_session(
    connection: dict[str, Any],
    *,
    region: str,
    scopes: list[str],
    session_factory: Callable[..., Any],
    client: SharedConnectionsClient | None = None,
) -> Any:
    """Lease only declared scopes; never persist or return credentials to an API caller."""

    if connection.get("credential_type") != "platform_shared_aws":
        raise ValueError("connection is not a shared AWS connection")
    reference = connection.get("credential_reference") or {}
    try:
        platform_id = UUID(str(reference["platform_connection_id"]))
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("shared AWS connection reference is invalid") from error
    if str(platform_id) != str(connection.get("id")):
        raise ValueError("shared AWS connection identity is inconsistent")
    clerk_org_id = connection.get("clerk_organization_id")
    if not isinstance(clerk_org_id, str) or not re.fullmatch(r"org_[A-Za-z0-9]+", clerk_org_id):
        raise ValueError("shared AWS organization boundary is missing")
    declared = set(connection.get("declared_scopes") or [])
    if not scopes or not set(scopes) <= declared or len(scopes) != len(set(scopes)):
        raise ValueError("shared AWS scope boundary is invalid")
    configuration = connection.get("configuration") or {}
    if configuration.get("coverage_mode") != "selected" or configuration.get("regions") != [region]:
        raise ValueError("shared AWS collection requires its single selected Region")
    bridge = client or SharedConnectionsClient.from_environment()
    if bridge is None:
        raise ValueError("shared connections are not configured")
    leased = bridge.request(
        "POST",
        f"/internal/v1/connections/aws/{platform_id}/credentials",
        clerk_org_id=clerk_org_id,
        payload={"scopes": scopes, "region": region},
    )
    if not isinstance(leased, dict) or any(
        not isinstance(leased.get(key), str) or not leased[key]
        for key in ("access_key_id", "secret_access_key", "session_token")
    ):
        raise ValueError("shared AWS credential lease is invalid")
    return session_factory(
        aws_access_key_id=leased["access_key_id"],
        aws_secret_access_key=leased["secret_access_key"],
        aws_session_token=leased["session_token"],
    )
