"""Durable claims bind tenant, actor, request and action before external effects."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import psycopg
import pytest

from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


def test_durable_connection_claims_deduplicate_and_are_tenant_actor_bound():
    assert DSN
    migrate(DSN)
    repo = PostgresInventoryRepository(DSN)
    marker = uuid4().hex
    alpha = repo.resolve_tenant(f"org_LifecycleAlpha{marker}")
    beta = repo.resolve_tenant(f"org_LifecycleBeta{marker}")
    fields = {
        "idempotency_key": "same_key_1",
        "request_hash": "a" * 64,
        "actor": "user_Admin1",
        "action_kind": "create",
        "connection_id": str(uuid4()),
    }
    with ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(
            pool.map(lambda _: repo.claim_gateway_connection_action(alpha, **fields), range(4))
        )
    assert sum(fresh for fresh, _ in outcomes) == 1
    assert all(row["state"] == "claimed" for _, row in outcomes)
    assert repo.claim_gateway_connection_action(beta, **fields)[0]
    for changed in (
        {"actor": "user_Admin2"},
        {"request_hash": "b" * 64},
        {"action_kind": "disable"},
    ):
        with pytest.raises(ValueError, match="another action"):
            repo.claim_gateway_connection_action(alpha, **{**fields, **changed})
    repo.finish_gateway_connection_action(
        alpha,
        idempotency_key=fields["idempotency_key"],
        request_hash=fields["request_hash"],
        connection_id=fields["connection_id"],
        status_code=201,
    )
    fresh, replay = repo.claim_gateway_connection_action(alpha, **fields)
    assert not fresh and replay["state"] == "completed" and replay["status_code"] == 201
    assert repo.claim_gateway_connection_action(beta, **fields)[1]["state"] == "claimed"
    with psycopg.connect(DSN) as connection:
        columns = {
            row[0]
            for row in connection.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'gateway_connection_action'"
            )
        }
    assert not columns & {
        "payload",
        "request",
        "result",
        "configuration",
        "credential_reference",
        "completion_code",
    }
