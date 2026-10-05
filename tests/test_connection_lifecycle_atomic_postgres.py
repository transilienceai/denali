"""Connection-row locking serializes UI/MCP durable queues against disable."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from time import monotonic, sleep
from uuid import uuid4

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")
QUEUE_KINDS = ("validation", "collection", "gateway-validation", "gateway-collection")


@pytest.fixture
def target():
    assert DSN
    migrate(DSN)
    repo = PostgresInventoryRepository(DSN)
    tenant = repo.resolve_tenant(f"org_AtomicLifecycle{uuid4().hex}")
    connection_id = str(uuid4())
    repo.create_connection(
        tenant,
        connection_id=connection_id,
        provider="aws",
        display_name="Atomic lifecycle fixture",
        credential_type="platform_shared_aws",
        credential_reference={"platform_connection_id": str(uuid4())},
        declared_scopes=[],
        coverage_plan=[],
        configuration={"account_id": "123456789012", "regions": ["us-east-1"]},
    )
    return repo, tenant, connection_id


def queue(repo, tenant, connection_id, kind):
    if kind == "validation":
        return repo.create_connection_validation_job(
            tenant, connection_id, wait_for_credentials=False, wait_for_healthy=False
        )
    if kind == "collection":
        return repo.create_connection_collection_job(
            tenant, connection_id, collection_kind="aws_deployments"
        )
    return repo.create_gateway_connection_job_idempotent(
        tenant,
        connection_id,
        job_type=kind.removeprefix("gateway-"),
        collection_kind="aws_deployments" if kind == "gateway-collection" else None,
        actor="user_AtomicAdmin",
        idempotency_key=str(uuid4()),
    )


def wait_for_row_lock(application_name):
    """Wait for a real server-side blocked statement, not a scheduling sleep."""
    assert DSN
    deadline = monotonic() + 10
    with psycopg.connect(DSN, autocommit=True) as observer:
        while monotonic() < deadline:
            row = observer.execute(
                "SELECT wait_event_type FROM pg_stat_activity WHERE application_name = %s",
                (application_name,),
            ).fetchone()
            if row is not None and row[0] == "Lock":
                return
            sleep(0.01)
    pytest.fail("operation did not reach the connection-row lock")


@pytest.mark.parametrize("kind", QUEUE_KINDS)
@pytest.mark.parametrize("first", ["queue", "disable"])
def test_concurrent_queue_and_disable_follow_connection_lock_order(target, kind, first):
    repo, tenant, connection_id = target
    assert DSN
    queue_name, disable_name = f"queue-{uuid4().hex}", f"disable-{uuid4().hex}"
    queue_repo = PostgresInventoryRepository(make_conninfo(DSN, application_name=queue_name))
    disable_repo = PostgresInventoryRepository(make_conninfo(DSN, application_name=disable_name))
    operations = {
        "queue": (queue_name, lambda: queue(queue_repo, tenant, connection_id, kind)),
        "disable": (disable_name, lambda: disable_repo.disable_connection(tenant, connection_id)),
    }
    with ThreadPoolExecutor(max_workers=2) as pool:
        with psycopg.connect(DSN) as blocker:
            blocker.execute(
                "SELECT id FROM provider_connection "
                "WHERE tenant_id = %s::uuid AND id = %s::uuid FOR UPDATE",
                (tenant, connection_id),
            )
            first_name, first_call = operations[first]
            first_result = pool.submit(first_call)
            wait_for_row_lock(first_name)
            second = "disable" if first == "queue" else "queue"
            second_name, second_call = operations[second]
            second_result = pool.submit(second_call)
            wait_for_row_lock(second_name)
        if first == "queue":
            assert first_result.result(timeout=10)[1]
            assert second_result.result(timeout=10) is None
            assert repo.get_connection(tenant, connection_id)["lifecycle_state"] == "active"
        else:
            assert first_result.result(timeout=10)["lifecycle_state"] == "disabled"
            with pytest.raises(ValueError, match="no longer active"):
                second_result.result(timeout=10)
            assert repo.connection_validation_job_state(tenant, connection_id) == "idle"
            assert (
                repo.connection_collection_status(
                    tenant, connection_id, collection_kind="aws_deployments"
                )["state"]
                == "idle"
            )


@pytest.mark.parametrize("kind", QUEUE_KINDS)
def test_disabled_connections_cannot_queue_new_jobs(target, kind):
    repo, tenant, connection_id = target
    assert repo.disable_connection(tenant, connection_id) is not None
    with pytest.raises(ValueError, match="no longer active"):
        queue(repo, tenant, connection_id, kind)


@pytest.mark.parametrize("kind", ["validation", "collection"])
@pytest.mark.parametrize("running", [False, True])
def test_disable_rechecks_all_queued_and_running_jobs_under_row_lock(target, kind, running):
    repo, tenant, connection_id = target
    job, _ = queue(repo, tenant, connection_id, kind)
    if running:
        claim = (
            repo.claim_connection_validation_job
            if kind == "validation"
            else repo.claim_connection_collection_job
        )
        assert claim(str(job["id"]), lease_seconds=60) is not None
    assert repo.disable_connection(tenant, connection_id) is None
    assert repo.get_connection(tenant, connection_id)["lifecycle_state"] == "active"
