"""Disposable-PostgreSQL contracts for metadata-only GitHub continuation jobs."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import psycopg
import pytest
from psycopg.rows import dict_row

from denali.domain import Coverage, CoverageState, FindingBatch, InventoryBatch
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


@pytest.fixture
def target():
    assert DSN
    migrate(DSN)
    repository = PostgresInventoryRepository(DSN)
    tenant = repository.resolve_tenant(f"org_GithubResume{uuid4().hex}")
    connection_id = str(uuid4())
    repository.create_connection(
        tenant,
        connection_id=connection_id,
        provider="github",
        display_name="Disposable GitHub continuation fixture",
        credential_type="github_app_installation",
        credential_reference={
            "app_id": "synthetic-app",
            "app_slug": "fixture",
            "installation_id": 7,
        },
        declared_scopes=["github.repository_metadata", "github.repository_contents"],
        coverage_plan=[],
        configuration={"account_id": 3, "repositories": [{"id": 17}]},
    )
    job, created = repository.create_connection_collection_job(
        tenant, connection_id, collection_kind="github_source"
    )
    assert created
    return repository, tenant, connection_id, str(job["id"])


def job_row(job_id):
    with psycopg.connect(DSN, row_factory=dict_row) as connection:
        return connection.execute(
            "SELECT * FROM connection_collection_job WHERE id = %s::uuid", (job_id,)
        ).fetchone()


def set_due(job_id, *, expired=False):
    with psycopg.connect(DSN) as connection:
        connection.execute(
            """UPDATE connection_collection_job SET available_at = now() - interval '1 second',
                 lease_expires_at = CASE WHEN %s THEN now() - interval '1 second'
                                        ELSE lease_expires_at END
               WHERE id = %s::uuid""",
            (expired, job_id),
        )


def progress_result(completed=1):
    return {
        "state": "running",
        "repository_count": 113,
        "completed_repository_count": completed,
        "partial_count": 0,
        "failed_count": 0,
    }


def test_checkpoint_survives_restart_deferral_and_generation_is_monotonic(target):
    repo, tenant, connection_id, job_id = target
    first = repo.claim_connection_collection_job(job_id, lease_seconds=60)
    assert first and first["attempt_count"] == 1
    checkpoint = {"version": 1, "completed": {"17": {"revision": "a" * 40}}}
    assert repo.save_collection_checkpoint(job_id, 1, checkpoint)
    assert repo.defer_connection_collection_job(job_id, 1, checkpoint, progress_result(), 60)
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60) is None
    assert job_id not in repo.list_due_github_collection_jobs(limit=500)
    assert repo.save_collection_checkpoint(job_id, 1, {}) is False
    assert repo.complete_resumable_collection_job(job_id, 1, {"state": "complete"}) is False
    assert repo.retry_resumable_collection_job(job_id, 1, "sanitized") is False
    status = repo.connection_collection_status(
        tenant, connection_id, collection_kind="github_source"
    )
    assert status["last_result"] is None
    assert status["progress"]["completed_repository_count"] == 1
    assert status["progress"]["resume_pending"] is True
    assert 0 < status["progress"]["retry_after_seconds"] <= 60
    set_due(job_id)
    restarted = PostgresInventoryRepository(DSN)
    second = restarted.claim_connection_collection_job(job_id, lease_seconds=60)
    assert second and second["attempt_count"] == 2 and second["continuation_count"] == 1
    assert second["retry_count"] == 0 and second["checkpoint"] == checkpoint
    assert not repo.collection_job_is_current(job_id, 1)
    assert restarted.collection_job_is_current(job_id, 2)
    result = {"state": "complete", "repository_count": 113, "completed_repository_count": 113}
    assert restarted.complete_resumable_collection_job(job_id, 2, result)
    assert not restarted.complete_resumable_collection_job(job_id, 2, result)
    assert (
        restarted.connection_collection_status(
            tenant, connection_id, collection_kind="github_source"
        )["last_result"]["state"]
        == "complete"
    )


def test_stale_github_status_and_browser_or_gateway_queue_preserve_checkpoint(target):
    repo, tenant, connection_id, job_id = target
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60)
    assert repo.save_collection_checkpoint(job_id, 1, {"completed": [17]})
    set_due(job_id, expired=True)
    status = repo.connection_collection_status(
        tenant, connection_id, collection_kind="github_source"
    )
    assert status["state"] == "running"
    same, created = repo.create_connection_collection_job(
        tenant, connection_id, collection_kind="github_source"
    )
    assert not created and str(same["id"]) == job_id
    gateway, _ = repo.create_gateway_connection_job_idempotent(
        tenant,
        connection_id,
        job_type="collection",
        collection_kind="github_source",
        actor="fixture-user",
        idempotency_key=f"fixture-{uuid4()}",
    )
    assert gateway["job_id"] == job_id
    assert job_id in repo.list_due_github_collection_jobs(limit=500)
    resumed = repo.claim_connection_collection_job(job_id, lease_seconds=60)
    assert resumed and resumed["checkpoint"] == {"completed": [17]}
    assert resumed["attempt_count"] == 2 and resumed["retry_count"] == 1
    assert not repo.save_collection_checkpoint(job_id, 1, {"completed": []})


def test_old_queued_job_is_recoverable_not_terminalized_at_status(target):
    repo, tenant, connection_id, job_id = target
    with psycopg.connect(DSN) as connection:
        connection.execute(
            "UPDATE connection_collection_job SET created_at=now()-interval '2 hours' WHERE id=%s",
            (job_id,),
        )
    assert (
        repo.connection_collection_status(tenant, connection_id, collection_kind="github_source")[
            "state"
        ]
        == "running"
    )
    assert job_id in repo.list_due_github_collection_jobs(limit=500)
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60)


def test_retry_counter_is_separate_from_continuations_and_bounds_crashes(target):
    repo, _, _, job_id = target
    for generation in range(1, 5):
        claimed = repo.claim_connection_collection_job(job_id, lease_seconds=60)
        assert claimed and claimed["attempt_count"] == generation
        assert repo.defer_connection_collection_job(job_id, generation, {}, progress_result(), 0)
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60)["attempt_count"] == 5
    for generation in (6, 7):
        set_due(job_id, expired=True)
        claimed = repo.claim_connection_collection_job(job_id, lease_seconds=60)
        assert claimed and claimed["attempt_count"] == generation
    set_due(job_id, expired=True)
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60) is None
    terminal = job_row(job_id)
    assert terminal["state"] == "failed" and terminal["retry_count"] == 3
    assert terminal["attempt_count"] == 7


def test_explicit_retries_preserve_checkpoint_and_failure_overrides_running_result(target):
    repo, tenant, connection_id, job_id = target
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60)
    assert repo.defer_connection_collection_job(
        job_id, 1, {"completed": [17]}, progress_result(), 0
    )
    for generation in (2, 3, 4):
        assert repo.claim_connection_collection_job(job_id, lease_seconds=60)
        retry = repo.retry_resumable_collection_job(
            job_id, generation, "Sanitized fixture failure", delay_seconds=0
        )
        assert retry is (generation < 4)
    row = job_row(job_id)
    assert row["checkpoint"] == {"completed": [17]} and row["retry_count"] == 3
    status = repo.connection_collection_status(
        tenant, connection_id, collection_kind="github_source"
    )
    assert status["state"] == "idle" and status["progress"] is None
    assert status["last_result"]["state"] == "failed"
    assert status["last_result"]["resume_pending"] is False
    assert status["last_result"]["completed_repository_count"] == 1
    assert "Sanitized" in status["last_result"]["detail"]


@pytest.mark.parametrize("kind", [InventoryBatch, FindingBatch])
@pytest.mark.parametrize("fence", ["expired", "generation", "tenant", "connection", "disabled"])
def test_fenced_evidence_rejects_stale_or_wrong_context_atomically(target, kind, fence):
    repo, tenant, connection_id, job_id = target
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60)
    scoped = repo.for_collection_claim(job_id, 1)
    batch_connection = connection_id
    batch_tenant = tenant
    if fence == "expired":
        set_due(job_id, expired=True)
    elif fence == "generation":
        set_due(job_id, expired=True)
        assert repo.claim_connection_collection_job(job_id, lease_seconds=60)
    elif fence == "tenant":
        batch_tenant = repo.resolve_tenant(f"org_GithubWrong{uuid4().hex}")
    elif fence == "connection":
        batch_connection = str(uuid4())
    else:
        with psycopg.connect(DSN) as connection:
            connection.execute(
                "UPDATE provider_connection SET lifecycle_state='disabled' WHERE id=%s",
                (connection_id,),
            )
    batch = kind(
        connector_id="denali.github_repository",
        connection_id=batch_connection,
        run_id=str(uuid4()),
        scope_key="github.com/fixture/repo",
        collected_at=datetime.now(UTC),
        coverage=(Coverage("github_source_collection", CoverageState.PARTIAL, "fixture"),),
    )
    method = scoped.ingest if kind is InventoryBatch else scoped.ingest_findings
    with pytest.raises(RuntimeError, match="claim is no longer current"):
        method(batch_tenant, batch)
    with psycopg.connect(DSN) as connection:
        assert (
            connection.execute(
                "SELECT count(*) FROM collection_run WHERE tenant_id=%s AND run_id=%s",
                (batch_tenant, batch.run_id),
            ).fetchone()[0]
            == 0
        )


def test_current_fenced_ingestion_and_duplicate_claim_delivery(target):
    repo, tenant, connection_id, job_id = target
    with ThreadPoolExecutor(max_workers=4) as executor:
        claims = list(
            executor.map(
                lambda _: repo.claim_connection_collection_job(job_id, lease_seconds=60), range(4)
            )
        )
    assert len([claim for claim in claims if claim is not None]) == 1
    scoped = repo.for_collection_claim(job_id, 1)
    for kind in (InventoryBatch, FindingBatch):
        batch = kind(
            connector_id="denali.github_repository",
            connection_id=connection_id,
            run_id=str(uuid4()),
            scope_key="github.com/fixture/repo",
            collected_at=datetime.now(UTC),
            coverage=(Coverage("github_source_collection", CoverageState.PARTIAL, "fixture"),),
        )
        (scoped.ingest if kind is InventoryBatch else scoped.ingest_findings)(tenant, batch)


def test_disabled_connection_is_never_dispatched_and_job_is_terminalized(target):
    repo, _, connection_id, job_id = target
    with psycopg.connect(DSN) as connection:
        connection.execute(
            "UPDATE provider_connection SET lifecycle_state='disabled' WHERE id=%s",
            (connection_id,),
        )
    assert job_id not in repo.list_due_github_collection_jobs(limit=500)
    assert job_row(job_id)["state"] == "failed"
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60) is None
    assert not repo.save_collection_checkpoint(job_id, 1, {})


def test_progress_is_allowlisted_and_terminal_history_is_retained(target):
    repo, tenant, connection_id, job_id = target
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60)
    assert repo.complete_resumable_collection_job(
        job_id, 1, {"state": "partial", "repository_count": 1}
    )
    next_job, _ = repo.create_connection_collection_job(
        tenant, connection_id, collection_kind="github_source"
    )
    next_id = str(next_job["id"])
    assert repo.claim_connection_collection_job(next_id, lease_seconds=60)
    assert repo.defer_connection_collection_job(
        next_id,
        1,
        {"private_checkpoint": "not-public"},
        {**progress_result(), "token": "not-public", "checkpoint": "not-public"},
        30,
    )
    status = repo.connection_collection_status(
        tenant, connection_id, collection_kind="github_source"
    )
    assert status["last_result"]["state"] == "partial"
    assert status["progress"]["state"] == "running"
    assert "not-public" not in str(status)
    assert repo.connection_collection_status(
        repo.resolve_tenant(f"org_Other{uuid4().hex}"),
        connection_id,
        collection_kind="github_source",
    ) == {"state": "idle", "last_result": None, "progress": None}


def test_completed_repository_checkpoint_publishes_progress_and_resets_failure_count(target):
    repo, tenant, connection_id, job_id = target
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60)
    assert repo.retry_resumable_collection_job(job_id, 1, "sanitized", delay_seconds=0)
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60)
    checkpoint = {"boundary_hash": "synthetic", "repositories": {"17": {"revision": "a" * 40}}}
    assert repo.save_collection_checkpoint(job_id, 2, checkpoint)
    assert job_row(job_id)["retry_count"] == 1
    checkpoint["repositories"]["17"]["result"] = {"state": "complete", "private": "not-public"}
    assert repo.save_collection_checkpoint(job_id, 2, checkpoint)
    assert job_row(job_id)["retry_count"] == 0
    status = repo.connection_collection_status(
        tenant, connection_id, collection_kind="github_source"
    )
    assert status["progress"]["repository_count"] == 1
    assert status["progress"]["completed_repository_count"] == 1
    assert status["progress"]["resume_pending"] is False
    assert "not-public" not in str(status)


@pytest.mark.parametrize("recovery", ["claim", "scheduler"])
def test_absolute_run_window_expires_even_when_quota_retry_is_not_due(target, recovery):
    repo, tenant, connection_id, job_id = target
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60)
    assert repo.defer_connection_collection_job(job_id, 1, {}, progress_result(), 86_400)
    with psycopg.connect(DSN) as connection:
        connection.execute(
            "UPDATE connection_collection_job SET created_at=now()-interval '49 hours' WHERE id=%s",
            (job_id,),
        )
    if recovery == "claim":
        assert repo.claim_connection_collection_job(job_id, lease_seconds=60) is None
    else:
        assert job_id not in repo.list_due_github_collection_jobs(limit=500)
    assert job_row(job_id)["state"] == "failed"
    status = repo.connection_collection_status(
        tenant, connection_id, collection_kind="github_source"
    )
    assert status["last_result"]["state"] == "failed"
    assert status["last_result"]["completed_repository_count"] == 1
    assert status["last_result"]["detail"] == (
        "GitHub collection exceeded its resumable run window."
    )


def test_run_window_fences_active_worker_before_reconciler_runs(target):
    repo, tenant, connection_id, job_id = target
    assert repo.claim_connection_collection_job(job_id, lease_seconds=60)
    with psycopg.connect(DSN) as connection:
        connection.execute(
            "UPDATE connection_collection_job SET created_at=now()-interval '49 hours' WHERE id=%s",
            (job_id,),
        )
    assert not repo.collection_job_is_current(job_id, 1)
    assert not repo.save_collection_checkpoint(job_id, 1, {})
    batch = InventoryBatch(
        connector_id="denali.github_repository",
        connection_id=connection_id,
        run_id=str(uuid4()),
        scope_key="fixture",
        collected_at=datetime.now(UTC),
        coverage=(Coverage("github_source_collection", CoverageState.PARTIAL, "fixture"),),
    )
    with pytest.raises(RuntimeError, match="claim is no longer current"):
        repo.for_collection_claim(job_id, 1).ingest(tenant, batch)


@pytest.mark.parametrize("recovery", ["claim", "scheduler"])
def test_corrupt_provider_job_pair_is_terminalized_without_dispatch(target, recovery):
    repo, _, connection_id, job_id = target
    with psycopg.connect(DSN) as connection:
        connection.execute(
            "UPDATE provider_connection SET provider='gcp' WHERE id=%s", (connection_id,)
        )
    if recovery == "claim":
        assert repo.claim_connection_collection_job(job_id, lease_seconds=60) is None
    else:
        assert job_id not in repo.list_due_github_collection_jobs(limit=500)
    terminal = job_row(job_id)
    assert terminal["state"] == "failed" and terminal["attempt_count"] == 0
    assert not repo.collection_job_is_current(job_id, 1)


@pytest.mark.parametrize("invalid", [None, [], {"value": float("nan")}, {"value": "x" * 2_000_000}])
def test_checkpoint_metadata_is_bounded(target, invalid):
    repo, _, _, job_id = target
    with pytest.raises(ValueError):
        repo.save_collection_checkpoint(job_id, 1, invalid)
