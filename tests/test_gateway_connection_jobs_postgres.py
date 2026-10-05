"""Durable gateway job idempotency and audit retention; requires DENALI_TEST_DSN."""

from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest

from denali.connections import AWS_SCOPE_BEDROCK_AGENTS, aws_coverage_plan
from denali.store.db import migrate
from denali.store.repository import (
    GatewayConnectionJobCooldown,
    PostgresInventoryRepository,
)

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


def test_gateway_jobs_are_atomic_tenant_scoped_rate_limited_and_audit_survives_delete():
    assert DSN
    migrate(DSN)
    repo = PostgresInventoryRepository(DSN)
    marker = uuid4().hex
    tenant = repo.resolve_tenant(f"org_GatewayJob{marker}")
    other = repo.resolve_tenant(f"org_GatewayJobOther{marker}")
    connection_id = str(uuid4())
    repo.create_connection(
        tenant,
        connection_id=connection_id,
        provider="aws",
        display_name=f"Gateway job {marker[:8]}",
        credential_type="platform_shared_aws",
        credential_reference={"platform_connection_id": str(uuid4())},
        declared_scopes=[AWS_SCOPE_BEDROCK_AGENTS],
        coverage_plan=aws_coverage_plan([AWS_SCOPE_BEDROCK_AGENTS], ["us-east-1"]),
        configuration={"account_id": "123456789012", "regions": ["us-east-1"]},
    )
    key = f"gateway-job-{marker}"
    args = {
        "job_type": "validation",
        "collection_kind": None,
        "actor": "user_GatewayAdmin",
        "idempotency_key": key,
    }
    first, created = repo.create_gateway_connection_job_idempotent(
        tenant, connection_id, **args
    )
    assert created and first["status"] == "started"
    same, created = repo.create_gateway_connection_job_idempotent(
        tenant, connection_id, **args
    )
    assert not created and same == first
    with pytest.raises(ValueError, match="idempotency key"):
        repo.create_gateway_connection_job_idempotent(
            tenant, connection_id, **{**args, "actor": "user_Other"}
        )
    with pytest.raises(ValueError, match="no longer active"):
        repo.create_gateway_connection_job_idempotent(
            other, connection_id, **{**args, "idempotency_key": f"other-{marker}"}
        )
    second, created = repo.create_gateway_connection_job_idempotent(
        tenant, connection_id, **{**args, "idempotency_key": f"second-{marker}"}
    )
    assert not created and second["status"] == "already_running"
    assert second["job_id"] == first["job_id"]
    for index in range(2, 10):
        repeated, created = repo.create_gateway_connection_job_idempotent(
            tenant, connection_id, **{**args, "idempotency_key": f"queued-{index}-{marker}"}
        )
        assert not created and repeated["job_id"] == first["job_id"]
    with pytest.raises(GatewayConnectionJobCooldown):
        repo.create_gateway_connection_job_idempotent(
            tenant, connection_id, **{**args, "idempotency_key": f"eleventh-{marker}"}
        )

    repo.fail_connection_validation_job(first["job_id"], "test completion")
    with pytest.raises(GatewayConnectionJobCooldown):
        repo.create_gateway_connection_job_idempotent(
            tenant, connection_id, **{**args, "idempotency_key": f"third-{marker}"}
        )
    collection, created = repo.create_gateway_connection_job_idempotent(
        tenant,
        connection_id,
        job_type="collection",
        collection_kind="aws_deployments",
        actor="user_GatewayAdmin",
        idempotency_key=f"collection-{marker}",
    )
    assert created and collection["collection_kind"] == "aws_deployments"
    repo.fail_connection_collection_job(collection["job_id"], "test completion")
    with pytest.raises(GatewayConnectionJobCooldown):
        repo.create_gateway_connection_job_idempotent(
            tenant,
            connection_id,
            job_type="collection",
            collection_kind="aws_deployments",
            actor="user_GatewayAdmin",
            idempotency_key=f"collection-again-{marker}",
        )
    assert repo.disable_connection(tenant, connection_id) is not None
    assert repo.delete_connection(tenant, connection_id) == "deleted"
    with psycopg.connect(DSN) as connection:
        rows = connection.execute(
            """
            SELECT actor_user_id, job_type, job_id, result
            FROM gateway_connection_job_action
            WHERE tenant_id = %s::uuid AND connection_id = %s::uuid
            """,
            (tenant, connection_id),
        ).fetchall()
    assert len(rows) == 11
    assert {row[1] for row in rows} == {"validation", "collection"}
    assert all(row[0] == "user_GatewayAdmin" for row in rows)
