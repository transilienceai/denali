"""Durable PostgreSQL correctness; no provider network or cloud writes."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from psycopg.conninfo import make_conninfo

from denali.resource_writes.store import RemediationStore
from denali.resource_writes.templates import RemediationError
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

pytestmark = pytest.mark.skipif(
    not os.environ.get("DENALI_TEST_DSN"), reason="disposable Postgres required"
)


@pytest.fixture
def persisted():
    base = os.environ["DENALI_TEST_DSN"]
    schema = "denali_remediation_test_" + uuid4().hex
    with psycopg.connect(base, autocommit=True) as conn:
        conn.execute(psycopg.sql.SQL("CREATE SCHEMA {}").format(psycopg.sql.Identifier(schema)))
    dsn = make_conninfo(base, options=f"-c search_path={schema},public")
    try:
        migrate(dsn)
        migrate(dsn)
        inventory = PostgresInventoryRepository(dsn)
        tenant = inventory.resolve_tenant("org_WriteTest" + uuid4().hex)
        other = inventory.resolve_tenant("org_OtherWrite" + uuid4().hex)
        with psycopg.connect(dsn) as conn:
            finding = str(
                conn.execute(
                    """
                INSERT INTO finding (tenant_id, connector_id, connection_id, scope_key,
                    source_uid, rule_uid, title, severity, state, evaluation_result,
                    class_uid, class_name, source_observed_at, evidence,
                    first_seen_at, last_seen_at, last_changed_at, last_observed_run_id)
                VALUES (%s::uuid, 'test', 'test', 'test', 'test', 'DENALI-AWS-AI-IAM-001',
                    'Test', 'medium', 'open', 'fail', 2003, 'Compliance Finding', now(),
                    '{}'::jsonb, now(), now(), now(), 'test') RETURNING id
            """,
                    (tenant,),
                ).fetchone()[0]
            )
        store = RemediationStore(dsn)
        row = {
            "id": str(uuid4()),
            "tenant_id": tenant,
            "clerk_org_id": "org_WriteTest",
            "finding_id": finding,
            "grant_id": str(uuid4()),
            "action": "aws.tighten_bedrock_inline_policy",
            "actor_user_id": "user_Admin",
            "parameters": {"model_arns": ["approved"]},
            "plan": {"safe": "metadata-only"},
            "preview_sha256": "a" * 64,
            "expires_at": datetime.now(UTC) + timedelta(minutes=15),
        }
        store.preview(row)
        yield store, row, other, dsn
    finally:
        with psycopg.connect(base, autocommit=True) as conn:
            conn.execute(
                psycopg.sql.SQL("DROP SCHEMA {} CASCADE").format(psycopg.sql.Identifier(schema))
            )


def request(store, row, *, key="resource-write-request-1", note="Approved exact model"):
    return store.request(row["tenant_id"], row["id"], "user_Admin", key, note)


def test_concurrent_requests_return_one_durable_job_and_one_audit(persisted):
    store, row, _, dsn = persisted
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: request(store, row), range(4)))
    assert len({str(result["id"]) for result in results}) == 1
    replacement = RemediationStore(dsn)
    assert str(request(replacement, row)["id"]) == str(results[0]["id"])
    with psycopg.connect(dsn) as conn:
        assert conn.execute("SELECT count(*) FROM resource_write_request").fetchone()[0] == 1
        assert conn.execute("SELECT count(*) FROM resource_write_audit_event").fetchone()[0] == 1


def test_cross_tenant_and_same_key_changed_body_are_rejected(persisted):
    store, row, other, _ = persisted
    first = request(store, row)
    assert store.get(other, str(first["id"])) is None
    assert store.get_preview(other, row["id"]) is None
    with pytest.raises(RemediationError, match="preview_not_found"):
        store.request(other, row["id"], "user_Admin", "other-key-123", "Test")
    with pytest.raises(RemediationError, match="idempotency_body_conflict"):
        request(store, row, note="Different request")


def test_self_approval_is_denied_and_duplicate_review_is_idempotent(persisted):
    store, row, _, _ = persisted
    first = request(store, row)
    with pytest.raises(RemediationError, match="self_approval_forbidden"):
        store.review(row["tenant_id"], str(first["id"]), "user_Admin", "approved", "Review")
    reviewed = store.review(
        row["tenant_id"], str(first["id"]), "user_Reviewer", "approved", "Review"
    )
    assert reviewed["state"] == "approved"
    assert (
        store.review(row["tenant_id"], str(first["id"]), "user_Reviewer", "approved", "Review")[
            "state"
        ]
        == "approved"
    )


def test_duplicate_worker_claim_and_ambiguous_failure_do_not_reexecute(persisted):
    store, row, _, dsn = persisted
    first = request(store, row)
    rid = str(first["id"])
    store.review(row["tenant_id"], rid, "user_Reviewer", "approved", "Review")
    claimed = store.claim(rid)
    assert RemediationStore(dsn).claim(rid) is None
    store.mark_provider_attempted(row["tenant_id"], rid, claimed["lease_nonce"])
    store.finish(row["tenant_id"], rid, claimed["lease_nonce"], error="provider_outcome_unknown")
    assert store.get(row["tenant_id"], rid)["state"] == "needs_manual_resolution"


def test_expired_worker_cannot_finish_as_current_success(persisted):
    store, row, _, dsn = persisted
    first = request(store, row)
    rid = str(first["id"])
    store.review(row["tenant_id"], rid, "user_Reviewer", "approved", "Review")
    claimed = store.claim(rid)
    store.mark_provider_attempted(row["tenant_id"], rid, claimed["lease_nonce"])
    with psycopg.connect(dsn) as conn:
        conn.execute(
            "UPDATE resource_write_request SET lease_expires_at=now()-interval '1 second' "
            "WHERE id=%s::uuid",
            (rid,),
        )
    store.finish(
        row["tenant_id"], rid, claimed["lease_nonce"], result={"untrusted_late_success": True}
    )
    stale = store.get(row["tenant_id"], rid)
    assert stale["state"] == "needs_manual_resolution" and stale["result"] is None
    assert store.claim(rid) is None
    store.reconcile_finish(row["tenant_id"], rid, "user_Reviewer", {"verified": True})
    assert store.get(row["tenant_id"], rid)["state"] == "succeeded"
    with psycopg.connect(dsn) as conn:
        events = conn.execute(
            "SELECT event_type FROM resource_write_audit_event ORDER BY id"
        ).fetchall()
        assert events[-1][0] == "read_only_reconciliation_succeeded"


def test_stale_worker_lease_cannot_be_reclaimed_or_mark_provider_attempted(persisted):
    store, row, _, dsn = persisted
    first = request(store, row)
    rid = str(first["id"])
    store.review(row["tenant_id"], rid, "user_Reviewer", "approved", "Review")
    claimed = store.claim(rid)
    with psycopg.connect(dsn) as conn:
        conn.execute(
            "UPDATE resource_write_request SET lease_expires_at=now()-interval '1 second' "
            "WHERE id=%s::uuid",
            (rid,),
        )
    assert store.claim(rid) is None
    with pytest.raises(RemediationError, match="worker_lease_lost"):
        store.mark_provider_attempted(row["tenant_id"], rid, claimed["lease_nonce"])
    assert store.get(row["tenant_id"], rid)["state"] == "needs_manual_resolution"


def test_expired_preview_is_not_approved_or_dispatched(persisted, monkeypatch):
    store, row, _, _ = persisted
    first = request(store, row)

    class Future(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz) + timedelta(minutes=16)

    monkeypatch.setattr("denali.resource_writes.store.datetime", Future)
    with pytest.raises(RemediationError, match="request_not_reviewable"):
        store.review(row["tenant_id"], str(first["id"]), "user_Reviewer", "approved", "Review")
    assert store.get(row["tenant_id"], str(first["id"]))["state"] == "pending_review"


def test_preview_request_identity_and_audit_are_database_immutable(persisted):
    store, row, _, dsn = persisted
    first = request(store, row)
    for sql in (
        "UPDATE resource_write_preview SET plan='{}'::jsonb",
        "UPDATE resource_write_request SET actor_user_id='user_Another'",
        "UPDATE resource_write_audit_event SET event_type='changed'",
        "DELETE FROM resource_write_audit_event",
    ):
        with psycopg.connect(dsn) as conn, pytest.raises(psycopg.errors.RaiseException):
            conn.execute(sql)
    assert store.get(row["tenant_id"], str(first["id"]))["actor_user_id"] == "user_Admin"


def test_cross_tenant_preview_foreign_key_is_enforced(persisted):
    store, row, other, _ = persisted
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        store.preview({**row, "id": str(uuid4()), "tenant_id": other})


def test_unknown_outcome_keeps_grant_fenced_against_another_approval(persisted):
    store, row, _, _ = persisted
    first = request(store, row)
    rid = str(first["id"])
    store.review(row["tenant_id"], rid, "user_Reviewer", "approved", "Review")
    claimed = store.claim(rid)
    store.mark_provider_attempted(row["tenant_id"], rid, claimed["lease_nonce"])
    store.finish(row["tenant_id"], rid, claimed["lease_nonce"], error="outcome_unknown")
    next_preview = {**row, "id": str(uuid4())}
    store.preview(next_preview)
    second = request(store, next_preview, key="another-request-key")
    with pytest.raises(RemediationError, match="another_resource_write_is_active"):
        store.review(row["tenant_id"], str(second["id"]), "user_Reviewer", "approved", "Review")
    assert store.get(row["tenant_id"], rid)["state"] == "needs_manual_resolution"
