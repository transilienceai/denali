"""Retention review against a disposable PostgreSQL database only."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest
from psycopg.types.json import Jsonb

from denali.connectors.demo import (
    demo_activity_batch,
    demo_batch,
    demo_findings_batch,
    demo_software_batch,
    demo_vulnerability_batch,
)
from denali.store import retention
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository
from denali.store.retention import retention_report

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


@pytest.fixture
def target():
    assert DSN
    migrate(DSN)
    repository = PostgresInventoryRepository(DSN)
    tenant = repository.resolve_tenant(f"org_RetentionFixture{uuid4().hex}")
    connection = str(uuid4())
    repository.create_connection(
        tenant,
        connection_id=connection,
        provider="aws",
        display_name="Disposable retention fixture",
        credential_type="assume_role",
        credential_reference={},
        declared_scopes=[],
        coverage_plan=[],
        configuration={},
    )
    return repository, tenant, connection


def job(tenant, connection, age, *, kind="aws_deployments", state="succeeded", result=None):
    identifier = str(uuid4())
    with psycopg.connect(DSN) as database:
        database.execute(
            """INSERT INTO connection_collection_job
               (id,tenant_id,connection_id,collection_kind,state,created_at,completed_at,
                lease_expires_at,result)
               VALUES (%s,%s,%s,%s,%s,now()-make_interval(days=>%s),
                 CASE WHEN %s IN ('succeeded','failed')
                      THEN now()-make_interval(days=>%s) ELSE NULL END,
                 CASE WHEN %s='running' THEN now()-interval '1 day' ELSE NULL END,%s)""",
            (
                identifier, tenant, connection, kind, state, age, state, age, state,
                Jsonb(result or {}),
            ),
        )
    return identifier


def run(tenant, connection, identifier, age, *, scope="scope", plane="plane"):
    with psycopg.connect(DSN) as database:
        database.execute(
            """INSERT INTO collection_run
               (tenant_id,connector_id,connection_id,run_id,scope_key,collected_at,completed_at)
               VALUES (%s,'fixture',%s,%s,%s,now()-make_interval(days=>%s),
                       now()-make_interval(days=>%s))""",
            (tenant, connection, identifier, scope, age, age),
        )
        database.execute(
            """INSERT INTO collection_coverage
               (tenant_id,connector_id,connection_id,run_id,plane,scope,state,collected_at)
               VALUES (%s,'fixture',%s,%s,%s,%s,'complete',now()-make_interval(days=>%s))""",
            (tenant, connection, identifier, plane, scope, age),
        )


def test_job_report_preserves_terminal_checkpoints_watermarks_audits_and_active_jobs(target):
    _repository, tenant, connection = target
    job(tenant, connection, 130)  # Review only: superseded terminal job.
    audited = job(tenant, connection, 120)
    job(tenant, connection, 100)  # Latest terminal status remains required.
    now = datetime.now(UTC)
    job(tenant, connection, 120, kind="aws_agent_runtime", result={
        "cursor_advance_safe": True, "window_end": (now-timedelta(days=10)).isoformat(),
    })
    job(tenant, connection, 110, kind="aws_agent_runtime", result={
        "cursor_advance_safe": True, "window_end": (now-timedelta(days=20)).isoformat(),
    })  # Older watermark is superseded, despite newer job creation.
    job(tenant, connection, 100, kind="aws_agent_runtime", result={"cursor_advance_safe": False})
    job(tenant, connection, 150, kind="github_source", state="failed")
    job(tenant, connection, 100, kind="github_source")  # Preserve incomplete-retry seed.
    job(tenant, connection, 200, kind="aws_agent_runtime", state="running")
    with psycopg.connect(DSN) as database:
        database.execute(
            """INSERT INTO gateway_connection_job_action
               (tenant_id,idempotency_key,request_hash,actor_user_id,connection_id,
                job_type,collection_kind,job_id,result)
               VALUES (%s,%s,'fixture','user_fixture',%s,'collection','aws_deployments',%s,'{}')""",
            (tenant, f"fixture-{uuid4()}", connection, audited),
        )
    report = retention_report(DSN, tenant_id=tenant, keep_days=30)
    jobs = report["connection_collection_job"]
    assert jobs["total_rows"] == 9
    assert jobs["older_rows"] == 8
    assert jobs["review_candidate_rows"] == 3
    assert jobs["protected_older_rows"] == 5
    assert jobs["active_rows"] == jobs["expired_running_leases"] == 1
    assert jobs["overlapping_protection_counts"] == {
        "latest_terminal_job": 3, "safe_runtime_cursor": 1, "gateway_audit_reference": 1,
    }


def test_latest_coverage_and_retained_job_metadata_protect_old_runs(target):
    _repository, tenant, connection = target
    for identifier, age, scope in [
        ("old-unreferenced", 120, "one"), ("latest-one", 100, "one"),
        ("nested-job-reference", 120, "two"), ("latest-two", 100, "two"),
        ("job-window-reference", 110, "three"), ("latest-three", 100, "three"),
        ("freshly-ingested-old-observation", 150, "four"), ("latest-four", 100, "four"),
    ]:
        run(tenant, connection, identifier, age, scope=scope)
    job(tenant, connection, 90, kind="github_source", result={
        "nested": {"run_id": "nested-job-reference", "payload": "not-for-output"},
    })
    window_job = job(tenant, connection, 111, kind="aws_agent_runtime")
    with psycopg.connect(DSN) as database:
        database.execute(
            "UPDATE connection_collection_job "
            "SET completed_at=now()-interval '109 days' WHERE id=%s",
            (window_job,),
        )
        database.execute(
            "UPDATE collection_run SET completed_at=now() WHERE tenant_id=%s AND run_id=%s",
            (tenant, "freshly-ingested-old-observation"),
        )
    report = retention_report(DSN, tenant_id=tenant, keep_days=30)
    assert report["collection_run"]["total_rows"] == 8
    assert report["collection_run"]["older_rows"] == 7
    assert report["collection_run"]["review_candidate_rows"] == 1
    assert report["collection_run"]["overlapping_protection_counts"] == {
        "latest_coverage": 4, "evidence_reference": 0,
        "retained_job_reference_or_time_window": 2,
    }
    assert report["collection_coverage"]["review_candidate_rows"] == 1
    assert "not-for-output" not in json.dumps(report)


def test_all_known_inventory_finding_vulnerability_and_activity_provenance_is_preserved(target):
    repository, tenant, _connection = target
    observed_at = datetime.now(UTC) - timedelta(days=120)
    repository.ingest(tenant, demo_batch(observed_at))
    repository.ingest(tenant, demo_software_batch(observed_at))
    repository.ingest_findings(tenant, demo_findings_batch(observed_at))
    repository.ingest_vulnerabilities(tenant, demo_vulnerability_batch(observed_at))
    repository.ingest_activity(tenant, demo_activity_batch(observed_at))
    with psycopg.connect(DSN) as database:
        database.execute(
            "UPDATE collection_run SET completed_at=collected_at WHERE tenant_id=%s", (tenant,)
        )
        # New coverage-only runs supersede every previous latest result. Old
        # evidence runs must still be protected by provenance, not just freshness.
        database.execute(
            """INSERT INTO collection_run
               (tenant_id,connector_id,connection_id,run_id,scope_key,collected_at,completed_at)
               SELECT tenant_id,connector_id,connection_id,run_id||'-newer',scope_key,
                      collected_at+interval '1 day',completed_at+interval '1 day'
               FROM collection_run WHERE tenant_id=%s""", (tenant,)
        )
        database.execute(
            """INSERT INTO collection_coverage
               (tenant_id,connector_id,connection_id,run_id,plane,scope,state,collected_at)
               SELECT tenant_id,connector_id,connection_id,run_id||'-newer',plane,scope,state,
                      collected_at+interval '1 day'
               FROM collection_coverage WHERE tenant_id=%s""", (tenant,)
        )
    report = retention_report(DSN, tenant_id=tenant, keep_days=30)
    assert report["collection_run"]["total_rows"] == 10
    assert report["collection_run"]["review_candidate_rows"] == 0
    assert report["collection_run"]["overlapping_protection_counts"]["evidence_reference"] == 5
    assert report["collection_coverage"]["review_candidate_rows"] == 0


def test_reports_are_tenant_scoped_and_do_not_create_registry_mappings(target):
    _repository, tenant, connection = target
    run(tenant, connection, "private-scope-should-not-appear", 150, scope="private-scope")
    run(tenant, connection, "latest", 120, scope="private-scope")
    other = str(uuid4())
    before = retention_report(DSN, tenant_id=other, keep_days=30)
    assert before["collection_run"]["total_rows"] == 0
    report = retention_report(DSN, tenant_id=tenant, keep_days=30)
    assert report["collection_run"]["total_rows"] == 2
    assert report["collection_run"]["review_candidate_rows"] == 1
    assert "private-scope" not in json.dumps(report)
    with psycopg.connect(DSN) as database:
        count = database.execute(
            "SELECT count(*) FROM denali_tenant WHERE id=%s", (other,)
        ).fetchone()[0]
        assert count == 0


def test_latest_coverage_timestamp_ties_are_both_protected(target):
    _repository, tenant, connection = target
    run(tenant, connection, "tied-a", 120)
    run(tenant, connection, "tied-b", 120)
    with psycopg.connect(DSN) as database:
        database.execute(
            "UPDATE collection_coverage SET collected_at='2025-01-01T00:00:00Z' WHERE tenant_id=%s",
            (tenant,),
        )
    report = retention_report(DSN, tenant_id=tenant, keep_days=30)
    assert report["collection_run"]["review_candidate_rows"] == 0
    assert report["collection_run"]["overlapping_protection_counts"]["latest_coverage"] == 2


def test_safe_runtime_cursor_ties_are_both_protected(target):
    _repository, tenant, connection = target
    now = datetime.now(UTC)
    for age, window_age in [(150, 10), (140, 10), (130, 20)]:
        job(tenant, connection, age, kind="azure_agent_runtime", result={
            "cursor_advance_safe": True,
            "window_end": (now-timedelta(days=window_age)).isoformat(),
        })
    job(tenant, connection, 120, kind="azure_agent_runtime")
    report = retention_report(DSN, tenant_id=tenant, keep_days=30)
    jobs = report["connection_collection_job"]
    assert jobs["total_rows"] == jobs["older_rows"] == 4
    assert jobs["review_candidate_rows"] == 1
    assert jobs["overlapping_protection_counts"]["safe_runtime_cursor"] == 2


def test_clean_scan_provenance_is_retained_even_without_vulnerability_observations(target):
    _repository, tenant, connection = target
    run(tenant, connection, "clean-scan", 150)
    run(tenant, connection, "newer-coverage-only", 140)
    with psycopg.connect(DSN) as database:
        database.execute(
            """INSERT INTO vulnerability_scan
               (tenant_id,connector_id,connection_id,run_id,target_kind,target_natural_key,
                artifact_kind,artifact_locator,source_observed_at,evidence)
               VALUES (%s,'fixture',%s,'clean-scan','ai_workload','fixture:workload',
                       'container_image','fixture://clean',now()-interval '150 days','{}')""",
            (tenant, connection),
        )
    report = retention_report(DSN, tenant_id=tenant, keep_days=30)
    assert report["collection_run"]["review_candidate_rows"] == 0
    assert report["collection_run"]["overlapping_protection_counts"]["evidence_reference"] == 1
    with psycopg.connect(DSN) as database:
        # Demonstrate why a blind parent purge would erase scan provenance. This
        # destructive assertion is rolled back and confined to our test tenant.
        with database.transaction(force_rollback=True):
            database.execute(
                "DELETE FROM collection_run WHERE tenant_id=%s AND run_id='clean-scan'", (tenant,)
            )
            count = database.execute(
                "SELECT count(*) FROM vulnerability_scan WHERE tenant_id=%s", (tenant,)
            ).fetchone()[0]
            assert count == 0
        count = database.execute(
            "SELECT count(*) FROM vulnerability_scan WHERE tenant_id=%s", (tenant,)
        ).fetchone()[0]
        assert count == 1


def test_terminal_age_requires_both_creation_and_completion_before_cutoff(target):
    _repository, tenant, connection = target
    recent_creation = job(tenant, connection, 120)
    recent_completion = job(tenant, connection, 110)
    with psycopg.connect(DSN) as database:
        database.execute(
            "UPDATE connection_collection_job SET created_at=now() WHERE id=%s", (recent_creation,)
        )
        database.execute(
            "UPDATE connection_collection_job SET completed_at=now() WHERE id=%s",
            (recent_completion,),
        )
    report = retention_report(DSN, tenant_id=tenant, keep_days=30)
    assert report["transaction_read_only"] is True
    assert report["transaction_isolation"] == "repeatable read"
    assert report["connection_collection_job"]["older_rows"] == 0
    assert report["connection_collection_job"]["review_candidate_rows"] == 0


def test_database_itself_rejects_a_write_even_if_report_query_regresses(target, monkeypatch):
    _repository, tenant, connection = target
    job(tenant, connection, 120)
    monkeypatch.setattr(
        retention, "_SUMMARY_QUERY",
        "DELETE FROM connection_collection_job WHERE tenant_id=%(tenant_id)s::uuid RETURNING id",
    )
    with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
        retention_report(DSN, tenant_id=tenant, keep_days=30)
    with psycopg.connect(DSN) as database:
        count = database.execute(
            "SELECT count(*) FROM connection_collection_job WHERE tenant_id=%s", (tenant,)
        ).fetchone()[0]
        assert count == 1


def test_protection_sets_do_not_become_correlated_per_row_subplans(target):
    _repository, tenant, _connection = target
    with psycopg.connect(DSN) as database:
        database.execute("SET TRANSACTION READ ONLY")
        plan = database.execute(
            "EXPLAIN (FORMAT JSON) " + retention._SUMMARY_QUERY,
            {"tenant_id": tenant, "keep_days": 30},
        ).fetchone()[0][0]["Plan"]
        database.rollback()

    def nodes(node):
        yield node
        for child in node.get("Plans", []):
            yield from nodes(child)

    # Scalar final aggregates are one-shot InitPlans. Protection sets must join
    # once, rather than sorting/scanning 90k coverage rows once per 90k runs.
    assert not any(node.get("Subplan Name", "").startswith("SubPlan ") for node in nodes(plan))
