"""Publish a complete, tenant-scoped AWS metadata snapshot to the platform registry.

This never exports Denali's role ARN, external ID, or other credential material.
It is an operator-triggered pilot, not an automatic onboarding or AWS broker.
"""

from __future__ import annotations

import os
from typing import Any

import psycopg
from psycopg.rows import dict_row

from denali.integrations.shared_connections_client import SharedConnectionsClient

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

    client = SharedConnectionsClient.from_environment()
    if client is None:
        raise ValueError("shared connections origin is required")
    snapshot = aws_snapshot(os.environ["DENALI_DSN"], clerk_org_id)
    result = client.request(
        "PUT", "/internal/v1/connections/aws/legacy/snapshot",
        clerk_org_id=clerk_org_id, payload=snapshot,
    )
    if not isinstance(result, dict):
        raise ValueError("shared AWS snapshot response is invalid")
    return {"imported": int(result["imported"]), "tombstoned": int(result["tombstoned"])}
