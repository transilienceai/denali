"""Read-only, tenant-scoped history-retention review for trusted operators.

This module intentionally has no deletion, repair, migration, or apply path. Its
counts are review candidates, not a deletion manifest or a storage-reclaim claim.
It is not a browser/API tenant selector and is not exposed through CLI/MCP tools.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any
from uuid import UUID

import psycopg
from psycopg.rows import dict_row

MAX_KEEP_DAYS = 3650

# Materialize the tenant boundary once. All evidence and job subqueries retain
# that boundary; no provider payload or scope text is returned to the operator.
_SUMMARY_QUERY = """
WITH params AS (
    SELECT %(tenant_id)s::uuid AS tenant_id,
           now() AS snapshot_at,
           now() - make_interval(days => %(keep_days)s) AS cutoff
), jobs AS MATERIALIZED (
    SELECT j.* FROM connection_collection_job j
    JOIN params p ON p.tenant_id = j.tenant_id
), latest_terminal AS (
    SELECT DISTINCT ON (connection_id, collection_kind) id
    FROM jobs WHERE state IN ('succeeded', 'failed')
    ORDER BY connection_id, collection_kind, created_at DESC, id DESC
), safe_runtime_watermarks AS (
    SELECT id, rank() OVER (
        PARTITION BY connection_id, collection_kind
        ORDER BY (result->>'window_end')::timestamptz DESC
    ) AS watermark_rank
    FROM jobs
    WHERE collection_kind IN ('aws_agent_runtime', 'azure_agent_runtime')
      AND state = 'succeeded'
      AND result->>'cursor_advance_safe' = 'true'
      AND result ? 'window_end'
      AND result->>'window_end' IS NOT NULL
), audited_jobs AS (
    SELECT DISTINCT a.job_id
    FROM gateway_connection_job_action a JOIN params p ON p.tenant_id = a.tenant_id
    WHERE a.job_type = 'collection'
), job_flags AS MATERIALIZED (
    SELECT j.*,
        j.state IN ('queued', 'running') AS active,
        l.id IS NOT NULL AS latest_terminal,
        w.id IS NOT NULL AS safe_runtime_cursor,
        a.job_id IS NOT NULL AS gateway_audit,
        (j.state IN ('succeeded', 'failed') AND j.created_at < p.cutoff
         AND j.completed_at < p.cutoff) AS old_terminal
    FROM jobs j CROSS JOIN params p
    LEFT JOIN latest_terminal l ON l.id = j.id
    LEFT JOIN safe_runtime_watermarks w ON w.id = j.id AND w.watermark_rank = 1
    LEFT JOIN audited_jobs a ON a.job_id = j.id
), classified_jobs AS MATERIALIZED (
    SELECT j.*, COALESCE(old_terminal AND NOT active AND NOT latest_terminal
        AND NOT safe_runtime_cursor AND NOT gateway_audit, false) AS review_candidate
    FROM job_flags j
), retained_job_run_strings AS (
    -- Exact run IDs can be nested in metadata/checkpoints. Examine strings only
    -- inside PostgreSQL; never export those JSON documents or their values.
    SELECT DISTINCT j.connection_id::text AS connection_id,
                    value #>> '{}' AS run_id
    FROM classified_jobs j
    CROSS JOIN LATERAL jsonb_path_query(
        jsonb_build_array(COALESCE(j.result, '{}'::jsonb), j.checkpoint),
        '$.** ? (@.type() == "string")'
    ) value
    WHERE NOT j.review_candidate
), retained_job_windows AS (
    -- Merge overlapping execution windows once per connection instead of
    -- rescanning thousands of terminal jobs for every historical run.
    SELECT j.connection_id::text AS connection_id, range_agg(tstzrange(
        least(j.created_at, COALESCE(j.completed_at, p.snapshot_at)),
        greatest(j.created_at, COALESCE(j.completed_at, p.snapshot_at)), '[]'
    )) AS windows
    FROM classified_jobs j CROSS JOIN params p
    WHERE NOT j.review_candidate
    GROUP BY j.connection_id
), evidence_run_refs AS (
    -- Retain historical as well as current evidence. Withdrawn evidence is not
    -- permission to erase provenance, and FK cascades must never decide policy.
    SELECT connector_id, connection_id, last_observed_run_id AS run_id
      FROM asset_assertion a JOIN params p ON p.tenant_id = a.tenant_id
    UNION
    SELECT connector_id, connection_id, last_observed_run_id
      FROM relationship_assertion a JOIN params p ON p.tenant_id = a.tenant_id
    UNION
    SELECT connector_id, connection_id, last_observed_run_id
      FROM finding a JOIN params p ON p.tenant_id = a.tenant_id
    UNION
    SELECT connector_id, connection_id, run_id
      FROM finding_observation a JOIN params p ON p.tenant_id = a.tenant_id
    UNION
    SELECT connector_id, connection_id, last_observed_run_id
      FROM vulnerability_observation a JOIN params p ON p.tenant_id = a.tenant_id
    UNION
    SELECT connector_id, connection_id, run_id
      FROM vulnerability_scan a JOIN params p ON p.tenant_id = a.tenant_id
    UNION
    SELECT connector_id, connection_id, run_id
      FROM activity_event a JOIN params p ON p.tenant_id = a.tenant_id
), coverage AS MATERIALIZED (
    SELECT c.*,
        max(collected_at) OVER (
            PARTITION BY c.connector_id, c.connection_id, c.plane, c.scope
        ) AS latest_collected_at
    FROM collection_coverage c JOIN params p ON p.tenant_id = c.tenant_id
), latest_coverage_runs AS (
    SELECT DISTINCT connector_id, connection_id, run_id
    FROM coverage WHERE collected_at = latest_collected_at
), run_flags AS MATERIALIZED (
    SELECT r.*,
        (r.collected_at < p.cutoff AND r.completed_at < p.cutoff) AS old,
        c.run_id IS NOT NULL AS latest_coverage,
        e.run_id IS NOT NULL AS evidence_reference,
        (s.run_id IS NOT NULL OR COALESCE(r.completed_at <@ j.windows, false))
            AS retained_job_reference
    FROM collection_run r JOIN params p ON p.tenant_id = r.tenant_id
    LEFT JOIN latest_coverage_runs c
      ON c.connector_id = r.connector_id AND c.connection_id = r.connection_id
     AND c.run_id = r.run_id
    LEFT JOIN evidence_run_refs e
      ON e.connector_id = r.connector_id AND e.connection_id = r.connection_id
     AND e.run_id = r.run_id
    LEFT JOIN retained_job_run_strings s
      ON s.connection_id = r.connection_id AND s.run_id = r.run_id
    LEFT JOIN retained_job_windows j ON j.connection_id = r.connection_id
), classified_runs AS MATERIALIZED (
    SELECT r.*, old AND NOT latest_coverage AND NOT evidence_reference
        AND NOT retained_job_reference AS review_candidate
    FROM run_flags r
), classified_coverage AS (
    SELECT c.*, (c.collected_at < p.cutoff) AS old,
        (c.collected_at < p.cutoff AND r.review_candidate) AS review_candidate
    FROM coverage c CROSS JOIN params p
    JOIN classified_runs r ON r.tenant_id = c.tenant_id
      AND r.connector_id = c.connector_id AND r.connection_id = c.connection_id
      AND r.run_id = c.run_id
)
SELECT
    (SELECT count(*) FROM classified_jobs) AS jobs_total,
    (SELECT count(*) FROM classified_jobs WHERE old_terminal) AS jobs_old,
    (SELECT count(*) FROM classified_jobs WHERE review_candidate) AS jobs_candidates,
    (SELECT count(*) FROM classified_jobs WHERE active) AS jobs_active,
    (SELECT count(*) FROM classified_jobs j CROSS JOIN params p
     WHERE j.state = 'running' AND j.lease_expires_at < p.snapshot_at) AS jobs_expired_running,
    (SELECT count(*) FROM classified_jobs WHERE old_terminal AND latest_terminal)
        AS jobs_latest_terminal_protected,
    (SELECT count(*) FROM classified_jobs WHERE old_terminal AND safe_runtime_cursor)
        AS jobs_cursor_protected,
    (SELECT count(*) FROM classified_jobs WHERE old_terminal AND gateway_audit)
        AS jobs_audit_protected,
    (SELECT count(*) FROM classified_runs) AS runs_total,
    (SELECT count(*) FROM classified_runs WHERE old) AS runs_old,
    (SELECT count(*) FROM classified_runs WHERE review_candidate) AS runs_candidates,
    (SELECT count(*) FROM classified_runs WHERE old AND latest_coverage)
        AS runs_latest_coverage_protected,
    (SELECT count(*) FROM classified_runs WHERE old AND evidence_reference)
        AS runs_evidence_protected,
    (SELECT count(*) FROM classified_runs WHERE old AND retained_job_reference)
        AS runs_job_protected,
    (SELECT count(*) FROM classified_coverage) AS coverage_total,
    (SELECT count(*) FROM classified_coverage WHERE old) AS coverage_old,
    (SELECT count(*) FROM classified_coverage WHERE review_candidate) AS coverage_candidates
"""


def retention_report(dsn: str, *, tenant_id: str, keep_days: int) -> dict[str, Any]:
    """Return an aggregate-only review inside one bounded read-only snapshot.

    ``tenant_id`` is supplied by a trusted operator, not accepted by a product
    route. The DSN must already authorize that operator; this is no auth bypass.
    """

    normalized_tenant = str(UUID(tenant_id))
    if type(keep_days) is not int or not 1 <= keep_days <= MAX_KEEP_DAYS:
        raise ValueError(f"keep_days must be between 1 and {MAX_KEEP_DAYS}")
    if not dsn:
        raise ValueError("database configuration is required")

    with psycopg.connect(dsn, connect_timeout=10, row_factory=dict_row) as connection:
        connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        connection.execute("SET LOCAL statement_timeout = '20s'")
        connection.execute("SET LOCAL lock_timeout = '2s'")
        snapshot = connection.execute(
            "SELECT now() AS snapshot_at, now() - make_interval(days => %s) AS cutoff, "
            "current_setting('transaction_read_only') AS read_only, "
            "current_setting('transaction_isolation') AS isolation",
            (keep_days,),
        ).fetchone()
        counts = connection.execute(
            _SUMMARY_QUERY, {"tenant_id": normalized_tenant, "keep_days": keep_days}
        ).fetchone()
        connection.rollback()

    assert snapshot is not None and counts is not None
    if snapshot["read_only"] != "on" or snapshot["isolation"] != "repeatable read":
        raise RuntimeError("retention report requires a read-only repeatable-read snapshot")

    def section(prefix: str) -> dict[str, int]:
        old, candidates = int(counts[f"{prefix}_old"]), int(counts[f"{prefix}_candidates"])
        return {
            "total_rows": int(counts[f"{prefix}_total"]),
            "older_rows": old,
            "protected_older_rows": old - candidates,
            "review_candidate_rows": candidates,
        }

    return {
        "report_version": 1,
        "mode": "read_only_review",
        "deletion_supported": False,
        "retention_policy_approved": False,
        "reclaimable_bytes": None,
        "tenant_id": normalized_tenant,
        "snapshot_at": snapshot["snapshot_at"].isoformat(),
        "cutoff": snapshot["cutoff"].isoformat(),
        "keep_days": keep_days,
        "transaction_read_only": True,
        "transaction_isolation": snapshot["isolation"],
        "connection_collection_job": {
            **section("jobs"),
            "active_rows": int(counts["jobs_active"]),
            "expired_running_leases": int(counts["jobs_expired_running"]),
            "overlapping_protection_counts": {
                "latest_terminal_job": int(counts["jobs_latest_terminal_protected"]),
                "safe_runtime_cursor": int(counts["jobs_cursor_protected"]),
                "gateway_audit_reference": int(counts["jobs_audit_protected"]),
            },
        },
        "collection_run": {
            **section("runs"),
            "overlapping_protection_counts": {
                "latest_coverage": int(counts["runs_latest_coverage_protected"]),
                "evidence_reference": int(counts["runs_evidence_protected"]),
                "retained_job_reference_or_time_window": int(counts["runs_job_protected"]),
            },
        },
        "collection_coverage": section("coverage"),
        "limitations": [
            "Review candidates are not approved or guaranteed-safe deletions; "
            "no purge is implemented.",
            "Keep-days is a sensitivity input, not an approved organization retention policy.",
            "Protection reasons overlap and must not be added together.",
            "All known evidence run references, including historical observations, are preserved.",
            "Retained-job time windows and nested exact string references "
            "conservatively protect runs.",
            "Protection covers the currently known schema, not arbitrary future references.",
            "External exports, legal holds and retention obligations require separate review.",
            "Counts do not predict reclaimed disk, index, WAL, backup or billed storage bytes.",
            "Expired running leases require investigation, not automatic failure or deletion.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", required=True, help="Internal Denali tenant UUID")
    parser.add_argument(
        "--keep-days", required=True, type=int, help="Sensitivity input, not policy"
    )
    args = parser.parse_args(argv)
    try:
        report = retention_report(
            os.environ.get("DENALI_DSN", ""), tenant_id=args.tenant_id, keep_days=args.keep_days
        )
    except (psycopg.Error, ValueError, RuntimeError):
        # Drivers can include DSNs, query text, or provider JSON in exceptions.
        # Never print exception messages, even when an operator mistypes a DSN.
        print(
            "Retention review failed; verify configuration and bounded read access.",
            file=sys.stderr,
        )
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
