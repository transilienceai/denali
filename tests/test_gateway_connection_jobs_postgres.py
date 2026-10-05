"""Durable gateway job idempotency and audit retention; requires DENALI_TEST_DSN."""

from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from denali.api.app import create_app
from denali.api.gateway_auth import GatewayPrincipal
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
    repo.set_connection_validation_call_id(first["job_id"], "call-test-validation")
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


def gateway_job_target():
    assert DSN
    migrate(DSN)
    repo = PostgresInventoryRepository(DSN)
    org = f"org_GatewayRecovery{uuid4().hex}"
    tenant = repo.resolve_tenant(org)
    connection_id = str(uuid4())
    repo.create_connection(
        tenant,
        connection_id=connection_id,
        provider="aws",
        display_name="Gateway recovery",
        credential_type="platform_shared_aws",
        credential_reference={"platform_connection_id": connection_id},
        declared_scopes=[AWS_SCOPE_BEDROCK_AGENTS],
        coverage_plan=aws_coverage_plan([AWS_SCOPE_BEDROCK_AGENTS], ["us-east-1"]),
        configuration={
            "account_id": "123456789012", "regions": ["us-east-1"], "coverage_mode": "selected",
        },
    )
    return repo, org, tenant, connection_id


def recovery_app(org, dispatch):
    class Authenticator:
        def authenticate(self, request):
            raise AssertionError("gateway requests must not use browser authentication")

    class Verifier:
        def verify(self, token, *, purpose):
            if token == "gateway-write" and purpose == "denali:write":
                return GatewayPrincipal("mch_Gateway1", org, "user_GatewayAdmin", purpose)
            return None

    class Memberships:
        def role(self, organization_id, user_id):
            return "admin" if (organization_id, user_id) == (org, "user_GatewayAdmin") else None

    return create_app(
        repository=PostgresInventoryRepository(DSN),
        auth_mode="clerk",
        authenticator=Authenticator(),
        results_gateway_verifier=Verifier(),
        gateway_membership_checker=Memberships(),
        validation_dispatcher=dispatch,
        collection_dispatcher=dispatch,
        migrate_on_start=False,
    )


@pytest.mark.parametrize(
    ("job_type", "collection_kind", "action"),
    [("validation", None, "validate"), ("collection", "aws_deployments", "collect")],
)
def test_gateway_replay_dispatches_committed_job_after_api_replacement(
    job_type, collection_kind, action
):
    repo, org, tenant, connection_id = gateway_job_target()
    key = str(uuid4())
    receipt, dispatch_needed = repo.create_gateway_connection_job_idempotent(
        tenant, connection_id, job_type=job_type, collection_kind=collection_kind,
        actor="user_GatewayAdmin", idempotency_key=key,
    )
    assert dispatch_needed
    # The accepting process dies here, after committing the job and audit but
    # before spawning a worker. A replacement process receives the retry.
    dispatched = []

    def dispatch(job_id):
        dispatched.append(job_id)
        return "call-recovered"

    body = {"confirm": True}
    if collection_kind:
        body["collection_kind"] = collection_kind
    headers = {"Authorization": "Bearer gateway-write", "Idempotency-Key": key}
    url = f"/internal/v1/capabilities/connections/{connection_id}/{action}"
    with TestClient(recovery_app(org, dispatch)) as client:
        recovered = client.post(url, json=body, headers=headers)
    with TestClient(recovery_app(org, dispatch)) as client:
        replay = client.post(url, json=body, headers=headers)
    assert recovered.status_code == replay.status_code == 202
    assert recovered.json() == replay.json() == receipt
    assert dispatched == [receipt["job_id"]]
    claim = getattr(repo, f"claim_connection_{job_type}_job")
    assert claim(receipt["job_id"], lease_seconds=60) is not None
    assert claim(receipt["job_id"], lease_seconds=60) is None
    with psycopg.connect(DSN) as connection:
        assert connection.execute(
            "SELECT count(*) FROM gateway_connection_job_action WHERE tenant_id = %s::uuid",
            (tenant,),
        ).fetchone()[0] == 1


@pytest.mark.parametrize(
    ("job_type", "collection_kind", "action"),
    [("validation", None, "validate"), ("collection", "aws_deployments", "collect")],
)
def test_gateway_failed_dispatch_is_not_disguised_by_replay_and_allows_deliberate_retry(
    job_type, collection_kind, action
):
    repo, org, tenant, connection_id = gateway_job_target()
    key = str(uuid4())
    headers = {"Authorization": "Bearer gateway-write", "Idempotency-Key": key}
    body = {"confirm": True}
    if collection_kind:
        body["collection_kind"] = collection_kind
    url = f"/internal/v1/capabilities/connections/{connection_id}/{action}"

    def failed_dispatch(job_id):
        raise RuntimeError("private provider details")

    with TestClient(recovery_app(org, failed_dispatch)) as client:
        failed = client.post(url, json=body, headers=headers)
    assert failed.status_code == 503
    assert "private provider details" not in failed.text
    dispatched = []

    def dispatch(job_id):
        dispatched.append(job_id)
        return "call-retry"

    with TestClient(recovery_app(org, dispatch)) as client:
        replay = client.post(url, json=body, headers=headers)
        assert replay.status_code == 409
        assert "connection job failed" in replay.text
        new_headers = {**headers, "Idempotency-Key": str(uuid4())}
        assert client.post(url, json=body, headers=new_headers).status_code == 429
        with psycopg.connect(DSN) as connection:
            connection.execute(
                """
                UPDATE gateway_connection_job_action
                SET created_at = now() - interval '6 minutes'
                WHERE tenant_id = %s::uuid
                """,
                (tenant,),
            )
        retried = client.post(url, json=body, headers=new_headers)
    assert retried.status_code == 202
    assert dispatched == [retried.json()["job_id"]]
    table = "connection_validation_job" if job_type == "validation" else "connection_collection_job"
    with psycopg.connect(DSN) as connection:
        states = connection.execute(
            f"SELECT state FROM {table} WHERE tenant_id = %s::uuid ORDER BY created_at",
            (tenant,),
        ).fetchall()
    assert [row[0] for row in states] == ["failed", "queued"]
