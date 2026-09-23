"""Publish a complete, tenant-scoped AWS metadata snapshot to the platform registry.

This never exports Denali's role ARN, external ID, or other credential material.
It is an operator-triggered pilot, not an automatic onboarding or AWS broker.
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlsplit

import httpx
import psycopg
from clerk_backend_api import Clerk
from psycopg.rows import dict_row

MAX_AWS_CONNECTIONS_PER_ORG = 100


def aws_snapshot(dsn: str, clerk_org_id: str) -> dict[str, Any]:
    if not clerk_org_id.startswith("org_") or not clerk_org_id[4:].isalnum():
        raise ValueError("a valid Clerk organization ID is required")
    with psycopg.connect(dsn, row_factory=dict_row, connect_timeout=5) as connection:
        tenant = connection.execute(
            "SELECT id FROM denali_tenant WHERE clerk_organization_id = %s",
            (clerk_org_id,),
        ).fetchone()
        if tenant is None:
            raise ValueError("organization has no Denali tenant")
        rows = connection.execute(
            """
            SELECT id, lifecycle_state, health_state, declared_scopes,
                   configuration->>'account_id' AS account_id,
                   configuration->>'partition' AS partition, last_validated_at
            FROM provider_connection
            WHERE tenant_id = %s AND provider = 'aws'
            ORDER BY id
            LIMIT %s
            """,
            (tenant["id"], MAX_AWS_CONNECTIONS_PER_ORG + 1),
        ).fetchall()
    if len(rows) > MAX_AWS_CONNECTIONS_PER_ORG:
        raise ValueError("AWS connection snapshot exceeds the bounded pilot limit")
    if any(not row["account_id"] for row in rows):
        raise ValueError("AWS connection has no account ID")
    if any(row["partition"] not in ("aws", "aws-us-gov", "aws-cn") for row in rows):
        raise ValueError("AWS connection has an unsupported partition")
    return {
        "clerk_org_id": clerk_org_id,
        "items": [
            {
                "clerk_org_id": clerk_org_id,
                "source_connection_id": str(row["id"]),
                "external_account_id": row["account_id"],
                "partition": row["partition"],
                "lifecycle_state": row["lifecycle_state"],
                "health_state": row["health_state"],
                "validated_scopes": (
                    row["declared_scopes"]
                    if row["lifecycle_state"] == "active" and row["health_state"] == "healthy"
                    else []
                ),
                "last_validated_at": (
                    row["last_validated_at"].isoformat()
                    if row["last_validated_at"] is not None
                    else None
                ),
            }
            for row in rows
        ],
    }


def publish_aws_snapshot(clerk_org_id: str) -> dict[str, int]:
    """Run manually after dev platform registration and entitlement are provisioned."""

    origin = os.environ.get("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "").rstrip("/")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("DENALI_PLATFORM_CONNECTIONS_ORIGIN must be an HTTPS origin")
    machine_key = os.environ.get("DENALI_PLATFORM_MACHINE_SECRET_KEY", "")
    if not machine_key:
        raise ValueError("DENALI_PLATFORM_MACHINE_SECRET_KEY is required")
    snapshot = aws_snapshot(os.environ["DENALI_DSN"], clerk_org_id)
    token = (
        Clerk(bearer_auth=machine_key)
        .m2m.create_token(
            seconds_until_expiration=60,
            min_remaining_ttl_seconds=20,
        )
        .token
    )
    with httpx.Client(timeout=15, follow_redirects=False) as client:
        response = client.put(
            f"{origin}/internal/v1/connections/aws/legacy/snapshot",
            json=snapshot,
            headers={"Authorization": f"Bearer {token}"},
        )
        response.raise_for_status()
        result = response.json()
    return {"imported": int(result["imported"]), "tombstoned": int(result["tombstoned"])}
