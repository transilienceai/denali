"""Real PostgreSQL atomicity, concurrent replay, and tenant isolation for import submission."""

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


@pytest.fixture
def imports():
    assert DSN
    migrate(DSN)
    repo = PostgresInventoryRepository(DSN)
    marker = uuid4().hex
    alpha = repo.resolve_tenant("org_ImportAlpha" + marker)
    beta = repo.resolve_tenant("org_ImportBeta" + marker)
    with psycopg.connect(DSN) as connection:
        asset = connection.execute(
            """
            INSERT INTO asset
              (tenant_id, kind, natural_key, first_seen_at, last_seen_at, last_changed_at)
            VALUES (%s::uuid, 'ai_workload', %s, now(), now(), now()) RETURNING id
            """,
            (alpha, marker),
        ).fetchone()[0]
    return repo, alpha, beta, str(asset)


def submit(repo, tenant, asset, *, key="import-key-1", digest="a" * 64, job=None):
    job = job or str(uuid4())
    return repo.create_vulnerability_import_job_idempotent(
        tenant,
        job_id=job,
        target_asset_id=asset,
        syft_object_key=f"{tenant}/{job}/syft.json",
        grype_object_key=f"{tenant}/{job}/grype.json",
        authoritative=True,
        actor="user_ImportAdmin",
        idempotency_key=key,
        request_hash=digest,
    )


def test_import_job_audit_is_atomic_and_concurrent_duplicates_share_one_job(imports):
    repo, alpha, _, asset = imports
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: submit(repo, alpha, asset), range(4)))
    assert sum(created for _, created in results) == 1
    job_id = str(results[0][0]["id"])
    assert {str(row["id"]) for row, _ in results} == {job_id}
    replacement = PostgresInventoryRepository(DSN)
    replay = replacement.gateway_vulnerability_import_action(
        alpha, idempotency_key="import-key-1", request_hash="a" * 64
    )
    assert str(replay["id"]) == job_id
    with psycopg.connect(DSN) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM vulnerability_import_job WHERE tenant_id=%s::uuid", (alpha,)
            ).fetchone()[0]
            == 1
        )
        audit = connection.execute(
            "SELECT actor_user_id,request_hash FROM gateway_vulnerability_import_action "
            "WHERE tenant_id=%s::uuid",
            (alpha,),
        ).fetchone()
        assert audit == ("user_ImportAdmin", "a" * 64)
    claimed = repo.claim_vulnerability_import_job(job_id, lease_seconds=60)
    assert claimed is not None
    assert replacement.claim_vulnerability_import_job(job_id, lease_seconds=60) is None
    repo.complete_vulnerability_import_job(job_id, {"test": "complete"})
    replay, created = submit(repo, alpha, asset)
    assert not created and str(replay["id"]) == job_id and replay["state"] == "succeeded"


def test_import_hash_conflict_cross_tenant_reads_and_cross_tenant_audit_are_rejected(imports):
    repo, alpha, beta, asset = imports
    first, _ = submit(repo, alpha, asset)
    with pytest.raises(ValueError, match="another action"):
        submit(repo, alpha, asset, digest="b" * 64)
    assert (
        repo.gateway_vulnerability_import_action(
            beta, idempotency_key="import-key-1", request_hash="a" * 64
        )
        is None
    )
    with pytest.raises(ValueError, match="unavailable"):
        submit(repo, beta, asset)
    with psycopg.connect(DSN) as connection:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            with connection.transaction():
                connection.execute(
                    "INSERT INTO gateway_vulnerability_import_action "
                    "(tenant_id,idempotency_key,request_hash,actor_user_id,job_id) "
                    "VALUES (%s::uuid,'cross-tenant-key',%s,'user_Admin',%s::uuid)",
                    (beta, "c" * 64, first["id"]),
                )
        assert (
            connection.execute(
                "SELECT count(*) FROM gateway_vulnerability_import_action WHERE tenant_id=%s::uuid",
                (beta,),
            ).fetchone()[0]
            == 0
        )


def test_failed_audit_rolls_back_native_job_and_stale_active_job_allows_safe_replacement(imports):
    repo, alpha, _, asset = imports
    with pytest.raises(psycopg.errors.CheckViolation):
        submit(repo, alpha, asset, key="bad")
    with psycopg.connect(DSN) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM vulnerability_import_job WHERE tenant_id=%s::uuid", (alpha,)
            ).fetchone()[0]
            == 0
        )
    first, _ = submit(repo, alpha, asset)
    job_id = str(first["id"])
    repo.claim_vulnerability_import_job(job_id, lease_seconds=60)
    with psycopg.connect(DSN) as connection:
        connection.execute(
            "UPDATE vulnerability_import_job SET lease_expires_at=now()-interval '1 second' "
            "WHERE id=%s::uuid",
            (job_id,),
        )
    second, created = submit(repo, alpha, asset, key="import-key-2")
    assert created and str(second["id"]) != job_id
    previous = repo.gateway_vulnerability_import_action(
        alpha, idempotency_key="import-key-1", request_hash="a" * 64
    )
    assert previous["state"] == "failed"
