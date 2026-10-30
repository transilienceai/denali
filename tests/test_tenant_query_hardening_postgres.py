"""Defensive reads must remain tenant-safe even with malformed legacy links.

The fixture deliberately installs only migrations 001–029 into a private test
schema. It models data permitted before tenant-composite foreign keys, without
disabling constraints or weakening the current application's schema.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from importlib.resources import files
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.rows import dict_row

from denali.domain import (
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    Coverage,
    CoverageState,
    Evidence,
    InventoryBatch,
)
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


@pytest.fixture
def legacy_repository():
    assert DSN
    schema = f"tenant_query_legacy_{uuid4().hex}"
    with psycopg.connect(DSN) as db:
        # Keep the shared extension outside the private schema's cleanup scope.
        db.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public")
        db.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    legacy_dsn = make_conninfo(DSN, options=f"-c search_path={schema},public")
    try:
        with psycopg.connect(legacy_dsn) as db:
            migrations = files("denali.store").joinpath("migrations")
            for migration in sorted(migrations.iterdir(), key=lambda item: item.name):
                if migration.name.endswith(".sql") and migration.name < "030_":
                    db.execute(migration.read_text())
        yield legacy_dsn, PostgresInventoryRepository(legacy_dsn)
    finally:
        with psycopg.connect(DSN) as db:
            db.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


def _asset(repo, tenant: str, key: str) -> str:
    observed = datetime.now(UTC)
    repo.ingest(
        tenant,
        InventoryBatch(
            connector_id="fixture",
            connection_id="tenant-query-fixture",
            run_id=uuid4().hex,
            scope_key=key,
            collected_at=observed,
            coverage=(Coverage("agents", CoverageState.COMPLETE, key),),
            assets=(
                AssetAssertion(
                    asset=AssetRef(AssetKind.AI_AGENT, key),
                    coverage_plane="agents",
                    display_name=key,
                    assertion_type=AssertionType.OBSERVED,
                    confidence=1.0,
                    evidence=Evidence("fixture", f"fixture://{key}", observed),
                ),
            ),
        ),
    )
    return str(repo.list_assets(tenant, search=key)[0]["id"])


def _relationship(db, tenant: str, source: str, target: str) -> str:
    return str(
        db.execute(
            """INSERT INTO relationship_assertion
                 (tenant_id, source_asset_id, target_asset_id, kind, category,
                  connector_id, connection_id, scope_key, coverage_plane,
                  assertion_type, confidence, evidence, first_seen_at, last_seen_at,
                  last_observed_run_id)
               VALUES (%s, %s, %s, 'uses', 'capability', 'fixture', 'fixture',
                       'fixture', 'agents', 'observed', 1.0, '{}', now(), now(), 'legacy')
               RETURNING id""",
            (tenant, source, target),
        ).fetchone()[0]
    )


@pytest.mark.parametrize("foreign_endpoint", ["source", "target"])
def test_asset_detail_and_issue_snapshot_ignore_foreign_relationship_endpoints(
    legacy_repository, foreign_endpoint: str
):
    dsn, repo = legacy_repository
    alpha, beta = str(uuid4()), str(uuid4())
    own = _asset(repo, alpha, "own-agent")
    neighbor = _asset(repo, alpha, "own-neighbor")
    foreign = _asset(repo, beta, "foreign-private-agent")
    with psycopg.connect(dsn) as db:
        valid = _relationship(db, alpha, own, neighbor)
        malformed = _relationship(
            db,
            alpha,
            foreign if foreign_endpoint == "source" else own,
            own if foreign_endpoint == "source" else foreign,
        )
    detail = repo.get_asset(alpha, own)
    assert detail is not None
    assert {str(item["id"]) for item in detail["relationships"]} == {valid}
    assert foreign not in str(detail) and "foreign-private-agent" not in str(detail)
    assert repo.get_asset(alpha, foreign) is None
    with psycopg.connect(dsn, row_factory=dict_row) as db:
        snapshot = repo._load_correlation_snapshot(db, alpha)
        assert {item.id for item in snapshot.relationships} == {valid}
        # Read-side filtering must not silently delete the historical bad row.
        assert db.execute(
            "SELECT count(*) AS n FROM relationship_assertion WHERE id=%s", (malformed,)
        ).fetchone()["n"] == 1


def _activity(db, tenant: str, name: str) -> str:
    return str(
        db.execute(
            """INSERT INTO activity_event
                 (tenant_id, connector_id, connection_id, run_id, scope_key, source_uid,
                  category, activity_name, title, outcome, provider, occurred_at,
                  source_observed_at, evidence, session_key)
               VALUES (%s, 'fixture', 'fixture', 'legacy', 'fixture', %s,
                       'agent_invocation', 'invoke', %s, 'success', 'fixture',
                       now(), now(), '{}', 'shared-session-key') RETURNING id""",
            (tenant, name, name),
        ).fetchone()[0]
    )


def _detection(db, tenant: str, name: str) -> str:
    return str(
        db.execute(
            """INSERT INTO runtime_detection
                 (tenant_id, correlation_key, rule_uid, title, description, risk,
                  investigation_guidance, severity, state, confidence,
                  first_seen_at, last_seen_at, last_changed_at, last_evaluated_at)
               VALUES (%s, %s, 'fixture', %s, 'fixture', 'fixture', 'fixture',
                       'medium', 'open', 1.0, now(), now(), now(), now()) RETURNING id""",
            (tenant, name, name),
        ).fetchone()[0]
    )


def test_runtime_correlation_loads_only_same_tenant_activity_and_asset_links(legacy_repository):
    dsn, repo = legacy_repository
    alpha, beta = str(uuid4()), str(uuid4())
    own_asset = _asset(repo, alpha, "own-agent")
    foreign_asset = _asset(repo, beta, "foreign-private-agent")
    with psycopg.connect(dsn) as db:
        own_event = _activity(db, alpha, "own-event")
        foreign_event = _activity(db, beta, "foreign-event")
        own_detection = _detection(db, alpha, "own-detection")
        foreign_detection = _detection(db, beta, "foreign-detection")
        for detection, activity in (
            (own_detection, own_event),
            (own_detection, foreign_event),
            (foreign_detection, own_event),
        ):
            db.execute(
                """INSERT INTO runtime_detection_activity
                     (tenant_id, detection_id, activity_id, role)
                   VALUES (%s, %s, %s, 'trigger')""",
                (alpha, detection, activity),
            )
        for detection, asset in (
            (own_detection, own_asset),
            (own_detection, foreign_asset),
            (foreign_detection, own_asset),
        ):
            db.execute(
                """INSERT INTO runtime_detection_asset
                     (tenant_id, detection_id, asset_id, role)
                   VALUES (%s, %s, %s, 'agent')""",
                (alpha, detection, asset),
            )
    with psycopg.connect(dsn, row_factory=dict_row) as db:
        [detection] = repo._load_correlation_runtime_detections(db, alpha)
    assert detection.id == own_detection
    assert detection.activity_ids == (own_event,)
    assert detection.asset_ids == (own_asset,)
    detail = repo.get_runtime_detection(alpha, own_detection)
    assert detail is not None
    assert [str(event["id"]) for event in detail["activities"]] == [own_event]
    assert [str(asset["id"]) for asset in detail["assets"]] == [own_asset]
