"""Tenant-composite evidence references; disposable PostgreSQL only, no providers."""

from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import UTC, datetime
from importlib.resources import files
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.types.json import Jsonb

from denali.store.db import migrate

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")

# Every formerly ID-only evidence reference and its original deletion contract.
REFERENCES = (
    ("asset_assertion", "asset_id", "asset", "CASCADE"),
    ("relationship_assertion", "source_asset_id", "asset", "CASCADE"),
    ("relationship_assertion", "target_asset_id", "asset", "CASCADE"),
    ("relationship_assertion", "principal_asset_id", "asset", "SET NULL"),
    ("relationship_assertion", "agent_asset_id", "asset", "SET NULL"),
    ("finding_resource", "finding_id", "finding", "CASCADE"),
    ("finding_compliance", "finding_id", "finding", "CASCADE"),
    ("finding_observation", "finding_id", "finding", "CASCADE"),
    ("issue_finding", "issue_id", "issue", "CASCADE"),
    ("issue_finding", "finding_id", "finding", "RESTRICT"),
    ("issue_path_node", "issue_id", "issue", "CASCADE"),
    ("issue_path_node", "asset_id", "asset", "RESTRICT"),
    ("issue_path_edge", "issue_id", "issue", "CASCADE"),
    ("issue_path_edge", "relationship_id", "relationship_assertion", "RESTRICT"),
    ("vulnerability", "component_asset_id", "asset", "SET NULL"),
    ("vulnerability", "target_asset_id", "asset", "SET NULL"),
    ("vulnerability_observation", "vulnerability_id", "vulnerability", "CASCADE"),
    ("vulnerability_scan", "target_asset_id", "asset", "SET NULL"),
    ("activity_entity", "activity_id", "activity_event", "CASCADE"),
    ("activity_entity", "asset_id", "asset", "SET NULL"),
    ("runtime_detection_activity", "detection_id", "runtime_detection", "CASCADE"),
    ("runtime_detection_activity", "activity_id", "activity_event", "RESTRICT"),
    ("runtime_detection_asset", "detection_id", "runtime_detection", "CASCADE"),
    ("runtime_detection_asset", "asset_id", "asset", "RESTRICT"),
    ("issue_detection", "issue_id", "issue", "CASCADE"),
    ("issue_detection", "detection_id", "runtime_detection", "RESTRICT"),
    ("issue_activity", "issue_id", "issue", "CASCADE"),
    ("issue_activity", "activity_id", "activity_event", "RESTRICT"),
)
MIGRATION = "030_tenant_evidence_relationships.sql"


@contextmanager
def isolated_schema():
    """Use a private disposable-test schema; never inspect another test's rows."""
    assert DSN
    schema = "denali_tenant_fk_" + uuid4().hex
    with psycopg.connect(DSN, autocommit=True) as conn:
        conn.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    dsn = make_conninfo(DSN, options=f"-c search_path={schema},public")
    try:
        yield dsn
    finally:
        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


@pytest.fixture(scope="module")
def schema_dsn():
    with isolated_schema() as dsn:
        migrate(dsn)
        migrate(dsn)  # The ordinary migration runner must remain idempotent.
        yield dsn


@pytest.fixture
def connection(schema_dsn):
    with psycopg.connect(schema_dsn) as conn:
        yield conn
        conn.rollback()


def insert(conn, table, values):
    conn.execute(
        sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
            sql.Identifier(table),
            sql.SQL(", ").join(map(sql.Identifier, values)),
            sql.SQL(", ").join(sql.Placeholder() for _ in values),
        ),
        [Jsonb(value) if isinstance(value, dict) else value for value in values.values()],
    )


def key_where(conn, table, values):
    columns = conn.execute(
        """SELECT a.attname FROM pg_constraint c
           CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY k(attnum, position)
           JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
           WHERE c.conrelid=%s::regclass AND c.contype='p' ORDER BY k.position""",
        (table,),
    ).fetchall()
    return (
        sql.SQL(" AND ").join(
            sql.SQL("{} = %s").format(sql.Identifier(name)) for (name,) in columns
        ),
        [values[name] for (name,) in columns],
    )


def migrate_legacy(conn):
    migration_dir = files("denali.store").joinpath("migrations")
    for item in sorted(migration_dir.iterdir(), key=lambda path: path.name):
        if item.name.endswith(".sql") and item.name < MIGRATION:
            conn.execute(item.read_text())
            conn.execute("INSERT INTO schema_migration(version) VALUES(%s)", (item.name,))


def vulnerability_values(tenant, asset_id, at):
    return dict(
        id=uuid4(), tenant_id=tenant, canonical_key=uuid4().hex,
        vulnerability_id="CVE-fixture", component_kind="software_component",
        component_natural_key="component", component_asset_id=asset_id,
        target_kind="ai_agent", target_natural_key="target", target_asset_id=asset_id,
        state="open", first_seen_at=at, last_seen_at=at, last_changed_at=at,
    )


def relationship_values(tenant, asset_id, at):
    return dict(
        id=uuid4(), tenant_id=tenant, source_asset_id=asset_id, target_asset_id=asset_id,
        principal_asset_id=asset_id, agent_asset_id=asset_id, kind="uses", category="topology",
        connector_id="fixture", connection_id="fixture", scope_key="fixture",
        coverage_plane="fixture", assertion_type="observed", confidence=1.0, evidence={},
        first_seen_at=at, last_seen_at=at, last_observed_run_id="run",
    )


def seed_parents(conn, tenant):
    """Deliberately omit denali_tenant mappings, preserving local Compose mode."""
    at = datetime.now(UTC)
    ids = {table: uuid4() for table in (
        "asset", "finding", "issue", "activity_event", "runtime_detection"
    )}
    insert(conn, "collection_run", dict(
        tenant_id=tenant, connector_id="fixture", connection_id="fixture", run_id="run",
        scope_key="fixture", collected_at=at,
    ))
    insert(conn, "asset", dict(
        id=ids["asset"], tenant_id=tenant, kind="ai_agent", natural_key=uuid4().hex,
        first_seen_at=at, last_seen_at=at, last_changed_at=at,
    ))
    insert(conn, "finding", dict(
        id=ids["finding"], tenant_id=tenant, connector_id="fixture", connection_id="fixture",
        scope_key="fixture", source_uid="fixture", rule_uid="fixture", title="Fixture",
        severity="medium", state="open", evaluation_result="fail", class_uid=2003,
        class_name="Finding", source_observed_at=at, evidence={}, first_seen_at=at,
        last_seen_at=at, last_changed_at=at, last_observed_run_id="run",
    ))
    base = dict(
        tenant_id=tenant, correlation_key=uuid4().hex, rule_uid="fixture", title="Fixture",
        description="Fixture", risk="Fixture", severity="medium", state="open", confidence=1.0,
        first_seen_at=at, last_seen_at=at, last_changed_at=at, last_evaluated_at=at,
    )
    insert(conn, "issue", dict(base, id=ids["issue"], remediation="Fixture"))
    insert(conn, "runtime_detection", dict(
        base, id=ids["runtime_detection"], investigation_guidance="Fixture"
    ))
    insert(conn, "activity_event", dict(
        id=ids["activity_event"], tenant_id=tenant, connector_id="fixture",
        connection_id="fixture", run_id="run", scope_key="fixture", source_uid="fixture",
        category="other", activity_name="fixture", title="Fixture", outcome="unknown",
        provider="fixture", occurred_at=at, source_observed_at=at, evidence={},
    ))
    relationship = relationship_values(tenant, ids["asset"], at)
    relationship["kind"] = "parent_fixture"
    insert(conn, "relationship_assertion", relationship)
    ids["relationship_assertion"] = relationship["id"]
    vulnerability = vulnerability_values(tenant, ids["asset"], at)
    insert(conn, "vulnerability", vulnerability)
    ids["vulnerability"] = vulnerability["id"]
    return ids


def child_values(table, tenant, parents):
    at = datetime.now(UTC)
    p = parents
    shared = dict(tenant_id=tenant, connector_id="fixture", connection_id="fixture")
    choices = {
        "asset_assertion": dict(
            shared, asset_id=p["asset"], scope_key="fixture", coverage_plane="fixture",
            assertion_type="observed", confidence=1.0, display_name="Fixture", evidence={},
            lifecycle_state="active", first_seen_at=at, last_seen_at=at,
            last_observed_run_id="run",
        ),
        "relationship_assertion": relationship_values(tenant, p["asset"], at),
        "finding_resource": dict(
            tenant_id=tenant, finding_id=p["finding"], resource_uid="fixture"
        ),
        "finding_compliance": dict(
            tenant_id=tenant, finding_id=p["finding"], framework="fixture", control="fixture"
        ),
        "finding_observation": dict(
            shared, finding_id=p["finding"], run_id="run", scope_key="fixture", collected_at=at,
            source_observed_at=at, severity="medium", state="open", evaluation_result="fail",
            evidence={},
        ),
        "issue_finding": dict(
            tenant_id=tenant, issue_id=p["issue"], finding_id=p["finding"], role="evidence"
        ),
        "issue_path_node": dict(
            tenant_id=tenant, issue_id=p["issue"], position=0, asset_id=p["asset"], role="evidence"
        ),
        "issue_path_edge": dict(
            tenant_id=tenant, issue_id=p["issue"], position=0,
            relationship_id=p["relationship_assertion"],
        ),
        "vulnerability": vulnerability_values(tenant, p["asset"], at),
        "vulnerability_observation": dict(
            shared, vulnerability_id=p["vulnerability"], source_uid="fixture", scope_key="fixture",
            severity="medium", state="open", fix_state="unknown", exploit_state="unknown",
            match_method="unknown", match_confidence=1.0, source_observed_at=at, evidence={},
            first_seen_at=at, last_seen_at=at, last_observed_run_id="run",
        ),
        "vulnerability_scan": dict(
            shared, run_id="run", target_kind="ai_agent", target_natural_key="fixture",
            target_asset_id=p["asset"], artifact_kind="syft", artifact_locator="fixture",
            source_observed_at=at, evidence={},
        ),
        "activity_entity": dict(
            tenant_id=tenant, activity_id=p["activity_event"], position=0, role="agent",
            external_uid="fixture", asset_id=p["asset"], correlation="exact_identifier",
            confidence=1.0,
        ),
        "runtime_detection_activity": dict(
            tenant_id=tenant, detection_id=p["runtime_detection"],
            activity_id=p["activity_event"], role="evidence",
        ),
        "runtime_detection_asset": dict(
            tenant_id=tenant, detection_id=p["runtime_detection"], asset_id=p["asset"],
            role="evidence",
        ),
        "issue_detection": dict(
            tenant_id=tenant, issue_id=p["issue"], detection_id=p["runtime_detection"],
            role="evidence",
        ),
        "issue_activity": dict(
            tenant_id=tenant, issue_id=p["issue"], activity_id=p["activity_event"], role="evidence"
        ),
    }
    return choices[table]


@pytest.mark.parametrize("table,column,parent,action", REFERENCES)
def test_reference_rejects_cross_tenant_insert_and_reassignment(
    connection, table, column, parent, action
):
    tenant, other = uuid4(), uuid4()
    parents, foreign = seed_parents(connection, tenant), seed_parents(connection, other)
    values = child_values(table, tenant, parents)
    with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
        insert(connection, table, dict(values, **{column: foreign[parent]}))
    insert(connection, table, values)
    where, params = key_where(connection, table, values)
    with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
        connection.execute(
            sql.SQL("UPDATE {} SET {}=%s WHERE {}").format(
                sql.Identifier(table), sql.Identifier(column), where
            ),
            [foreign[parent], *params],
        )
    with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
        connection.execute(
            sql.SQL("UPDATE {} SET tenant_id=%s WHERE {}").format(
                sql.Identifier(table), where
            ),
            [other, *params],
        )
    with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
        connection.execute(
            sql.SQL("UPDATE {} SET tenant_id=%s WHERE id=%s").format(sql.Identifier(parent)),
            (uuid4(), values[column]),
        )
    assert connection.execute(
        sql.SQL("SELECT tenant_id, {} FROM {} WHERE {}").format(
            sql.Identifier(column), sql.Identifier(table), where
        ), params,
    ).fetchone() == (tenant, values[column])


@pytest.mark.parametrize("table,column,parent,action", REFERENCES)
def test_original_delete_semantics_preserve_tenant(connection, table, column, parent, action):
    tenant = uuid4()
    parents = seed_parents(connection, tenant)
    values = child_values(table, tenant, parents)
    if action == "SET NULL":
        # Avoid source/target CASCADE references to the same nullable asset.
        extra = uuid4()
        at = datetime.now(UTC)
        insert(connection, "asset", dict(
            id=extra, tenant_id=tenant, kind="ai_agent", natural_key=uuid4().hex,
            first_seen_at=at, last_seen_at=at, last_changed_at=at,
        ))
        values[column] = extra
    insert(connection, table, values)
    where, params = key_where(connection, table, values)
    delete = sql.SQL("DELETE FROM {} WHERE tenant_id=%s AND id=%s").format(sql.Identifier(parent))
    if action == "RESTRICT":
        with pytest.raises(psycopg.errors.ForeignKeyViolation), connection.transaction():
            connection.execute(delete, (tenant, values[column]))
    else:
        connection.execute(delete, (tenant, values[column]))
    row = connection.execute(
        sql.SQL("SELECT tenant_id, {} FROM {} WHERE {}").format(
            sql.Identifier(column), sql.Identifier(table), where
        ), params,
    ).fetchone()
    if action == "CASCADE":
        assert row is None
    elif action == "SET NULL":
        assert row == (tenant, None)
    else:
        assert row == (tenant, values[column])


def test_all_references_between_tenant_tables_include_tenant_and_are_validated(connection):
    rows = connection.execute(
        """SELECT c.conname, c.convalidated,
                  EXISTS(SELECT 1 FROM unnest(c.conkey) k(attnum)
                         JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
                         WHERE a.attname='tenant_id') AS child_tenant,
                  EXISTS(SELECT 1 FROM unnest(c.confkey) k(attnum)
                         JOIN pg_attribute a ON a.attrelid=c.confrelid AND a.attnum=k.attnum
                         WHERE a.attname='tenant_id') AS parent_tenant
           FROM pg_constraint c JOIN pg_class child ON child.oid=c.conrelid
           JOIN pg_namespace n ON n.oid=child.relnamespace
           WHERE c.contype='f' AND n.nspname=current_schema()
             AND EXISTS(SELECT 1 FROM pg_attribute
                        WHERE attrelid=c.conrelid AND attname='tenant_id' AND NOT attisdropped)
             AND EXISTS(SELECT 1 FROM pg_attribute
                        WHERE attrelid=c.confrelid AND attname='tenant_id' AND NOT attisdropped)"""
    ).fetchall()
    assert len(rows) == 44  # Original 45, minus one redundant connection-validation FK.
    assert all(validated and child and parent for _, validated, child, parent in rows)


def test_historical_mismatch_aborts_migration_without_repair_or_partial_ddl():
    with isolated_schema() as dsn:
        with psycopg.connect(dsn) as conn:
            migrate_legacy(conn)
            tenant, other = uuid4(), uuid4()
            parents, foreign = seed_parents(conn, tenant), seed_parents(conn, other)
            # The final upgraded reference deliberately fails after earlier DDL,
            # proving the migration and all evidence are rolled back atomically.
            insert(conn, "issue_activity", dict(
                tenant_id=tenant, issue_id=parents["issue"],
                activity_id=foreign["activity_event"], role="evidence",
            ))
        with pytest.raises(psycopg.errors.ForeignKeyViolation, match="Tenant reference mismatch"):
            migrate(dsn)
        with psycopg.connect(dsn) as conn:
            assert conn.execute("SELECT count(*) FROM issue_activity").fetchone() == (1,)
            assert conn.execute(
                "SELECT count(*) FROM schema_migration WHERE version=%s", (MIGRATION,)
            ).fetchone() == (0,)
            assert conn.execute(
                """SELECT count(*) FROM pg_constraint WHERE conrelid='asset_assertion'::regclass
                   AND conname='asset_assertion_asset_id_fkey'"""
            ).fetchone() == (1,)
            assert conn.execute(
                """SELECT count(*) FROM pg_constraint WHERE conrelid='asset_assertion'::regclass
                   AND conname='asset_assertion_tenant_asset_fk'"""
            ).fetchone() == (0,)


def test_validation_failure_after_preflight_is_sanitized_and_atomic():
    with isolated_schema() as dsn:
        with psycopg.connect(dsn) as conn:
            migrate_legacy(conn)
            tenant, other = uuid4(), uuid4()
            parents, foreign = seed_parents(conn, tenant), seed_parents(conn, other)
        with psycopg.connect(dsn) as conn:
            # Fault-inject a legacy writer's insertion after the SELECT preflight
            # and before ALTER obtains its lock. This deterministically exercises
            # VALIDATE's real PostgreSQL ForeignKeyViolation without timing races.
            late_insert = sql.SQL("""
                IF reference.child_table = 'issue_activity'
                   AND reference.child_column = 'activity_id' THEN
                    INSERT INTO issue_activity(tenant_id, issue_id, activity_id, role)
                    VALUES ({}, {}, {}, 'evidence');
                END IF;
            """).format(
                sql.Literal(tenant), sql.Literal(parents["issue"]),
                sql.Literal(foreign["activity_event"]),
            ).as_string(conn)
            text = files("denali.store").joinpath("migrations", MIGRATION).read_text()
            marker = "        delete_clause := reference.delete_action;"
            assert text.count(marker) == 1
            with pytest.raises(psycopg.errors.ForeignKeyViolation) as failure:
                with conn.transaction():
                    conn.execute(text.replace(marker, late_insert + marker))
            assert failure.value.diag.message_primary == (
                "Tenant reference validation failed in issue_activity.activity_id; "
                "migration stopped without repair"
            )
            assert failure.value.diag.message_detail is None
            for identifier in (tenant, other, parents["issue"], foreign["activity_event"]):
                assert str(identifier) not in str(failure.value)
            assert conn.execute("SELECT count(*) FROM issue_activity").fetchone() == (0,)
            assert conn.execute(
                """SELECT count(*) FROM pg_constraint WHERE conrelid='asset_assertion'::regclass
                   AND conname='asset_assertion_asset_id_fkey'"""
            ).fetchone() == (1,)


def test_legacy_same_named_constraint_in_another_schema_cannot_skip_validation_fk():
    # Use only private schemas, even when the full test suite has populated public.
    with isolated_schema() as existing_dsn, isolated_schema() as target_dsn:
        migrate(existing_dsn)
        with psycopg.connect(target_dsn) as conn:
            migrate_legacy(conn)
            # Reproduce migration 012's historical global-name collision.
            assert conn.execute(
                """SELECT count(*) FROM pg_constraint
                   WHERE conrelid='connection_validation'::regclass
                     AND conname='connection_validation_tenant_connection_fk'"""
            ).fetchone() == (0,)
        migrate(target_dsn)
        with psycopg.connect(target_dsn) as conn:
            assert conn.execute(
                """SELECT convalidated, confrelid='provider_connection'::regclass
                   FROM pg_constraint WHERE conrelid='connection_validation'::regclass
                     AND conname='connection_validation_tenant_connection_fk'"""
            ).fetchone() == (True, True)
            assert conn.execute(
                """SELECT count(*) FROM pg_constraint
                   WHERE conrelid='connection_validation'::regclass
                     AND conname='connection_validation_connection_id_fkey'"""
            ).fetchone() == (0,)
            tenant, other, connection_id = uuid4(), uuid4(), uuid4()
            insert(conn, "provider_connection", dict(
                id=connection_id, tenant_id=tenant, provider="aws", display_name="Fixture",
                credential_type="assume_role", credential_reference={},
            ))
            values = dict(
                tenant_id=other, connection_id=connection_id, started_at=datetime.now(UTC),
                completed_at=datetime.now(UTC), health_state="healthy", credential_state="passed",
                summary="Fixture",
            )
            with pytest.raises(psycopg.errors.ForeignKeyViolation), conn.transaction():
                insert(conn, "connection_validation", values)
            insert(conn, "connection_validation", dict(values, tenant_id=tenant))
