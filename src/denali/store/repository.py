"""Transactional Postgres repository for canonical inventory assertions."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import psycopg
from psycopg.rows import dict_row

from denali.detections import (
    evaluate_repeated_failed_ai_signins,
    evaluate_unreviewed_ai_consent,
    evaluate_unreviewed_model_invocation,
)
from denali.domain import (
    ActivityBatch,
    AssetAssertion,
    AssetRef,
    CorrelationAsset,
    CorrelationFinding,
    CorrelationRelationship,
    CorrelationRuntimeDetection,
    CorrelationSnapshot,
    CoverageState,
    DetectionActivity,
    DetectionActivityEntity,
    DetectionAsset,
    DetectionSnapshot,
    FindingAssertion,
    FindingBatch,
    FindingSeverity,
    InventoryBatch,
    IssueCandidate,
    IssueEvaluation,
    RelationshipAssertion,
    RuntimeDetectionCandidate,
    RuntimeDetectionEvaluation,
    VulnerabilityAssertion,
    VulnerabilityBatch,
)
from denali.issues import (
    aggregate_issue_evaluation_state,
    evaluate_agent_sensitive_write,
    evaluate_deployed_bedrock_governance_gap,
    evaluate_unreviewed_ai_consent_then_use,
)

_ASSERTION_RANK_SQL = """
CASE aa.assertion_type
  WHEN 'externally_verified' THEN 4
  WHEN 'observed' THEN 3
  WHEN 'declared' THEN 2
  WHEN 'inferred' THEN 1
  ELSE 0
END
"""


def _connection_response(row: dict[str, Any]) -> dict[str, Any]:
    result = dict(row)
    credential_type = result.pop("credential_type")
    internal_reference = result.pop("credential_reference")
    credential_reference: dict[str, Any] = {"type": credential_type}
    if credential_type == "aws_assume_role":
        credential_reference["role_arn"] = internal_reference["role_arn"]
    elif credential_type == "azure_multitenant_app":
        credential_reference["client_id"] = internal_reference["client_id"]
        if internal_reference.get("service_principal_id"):
            credential_reference["service_principal_id"] = internal_reference[
                "service_principal_id"
            ]
    elif credential_type == "gcp_service_account":
        credential_reference["principal_email"] = internal_reference["principal_email"]
        if internal_reference.get("principal_unique_id"):
            credential_reference["principal_unique_id"] = internal_reference[
                "principal_unique_id"
            ]
    elif credential_type == "github_app_installation":
        credential_reference["app_id"] = internal_reference["app_id"]
        credential_reference["app_slug"] = internal_reference["app_slug"]
        if internal_reference.get("installation_id"):
            credential_reference["installation_id"] = internal_reference["installation_id"]
    result["credential_reference"] = credential_reference
    return result


def _deployment_identity_from_attributes(
    attributes: dict[str, Any], *, display_name: str
) -> dict[str, Any] | None:
    """Normalize provider inventory into the shared deployment identity record."""

    provider = attributes.get("provider")
    service = attributes.get("service")
    runtime_kind = attributes.get("runtime_kind")
    raw_identifiers = attributes.get("deployment_identifiers")

    # Preserve eligibility for AWS observations written before the shared identity
    # contract existed. New provider collectors must emit the explicit fields above.
    if (
        provider == "aws"
        and service in {"lambda", "ecs"}
        and not isinstance(raw_identifiers, dict)
    ):
        logical_id = attributes.get("logical_id")
        if not isinstance(logical_id, str) or not logical_id:
            return None
        if service == "lambda":
            runtime_kind = "serverless_function"
            raw_identifiers = {
                "cloudformation_logical_id": [logical_id],
                "function_name": [display_name],
            }
        else:
            runtime_kind = "container_task"
            raw_identifiers = {
                "cloudformation_logical_id": [logical_id],
                "container_name": attributes.get("container_names", []),
            }

    if (
        not isinstance(provider, str)
        or not provider
        or not isinstance(runtime_kind, str)
        or not runtime_kind
        or not isinstance(raw_identifiers, dict)
    ):
        return None

    identifiers: list[dict[str, str]] = []
    for name, raw_values in raw_identifiers.items():
        if not isinstance(name, str) or not name:
            return None
        values = raw_values if isinstance(raw_values, list) else [raw_values]
        if not values:
            return None
        for value in values:
            if not isinstance(value, str) or not value:
                return None
            identifiers.append(
                {"name": name, "value": value, "comparison": "exact"}
            )
    if not identifiers:
        return None
    return {
        "provider": provider,
        "runtime_kind": runtime_kind,
        "identifiers": identifiers,
    }


class PostgresInventoryRepository:
    def __init__(self, dsn: str):
        self._dsn = dsn

    def resolve_tenant(self, clerk_organization_id: str) -> str:
        """Return the stable Denali UUID for an authenticated Clerk organization."""

        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """
                INSERT INTO denali_tenant (clerk_organization_id)
                VALUES (%s)
                ON CONFLICT (clerk_organization_id) DO UPDATE
                SET last_seen_at = now()
                RETURNING id
                """,
                (clerk_organization_id,),
            ).fetchone()
        assert row is not None
        return str(row[0])

    def ingest(self, tenant_id: str, batch: InventoryBatch) -> dict[str, int]:
        """Persist a batch atomically and reconcile only completely covered planes."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            with connection.transaction():
                self._insert_run(connection, tenant_id, batch)
                asset_ids: dict[AssetRef, str] = {}
                for assertion in batch.assets:
                    asset_id = self._ensure_asset(
                        connection,
                        tenant_id,
                        assertion.asset,
                        batch.collected_at,
                    )
                    asset_ids[assertion.asset] = asset_id
                    self._upsert_asset_assertion(connection, tenant_id, batch, asset_id, assertion)

                for assertion in batch.relationships:
                    source_id = asset_ids.get(assertion.source)
                    if source_id is None:
                        source_id = self._ensure_asset(
                            connection, tenant_id, assertion.source, batch.collected_at
                        )
                        asset_ids[assertion.source] = source_id
                    target_id = asset_ids.get(assertion.target)
                    if target_id is None:
                        target_id = self._ensure_asset(
                            connection, tenant_id, assertion.target, batch.collected_at
                        )
                        asset_ids[assertion.target] = target_id
                    principal_id = self._optional_asset(
                        connection, tenant_id, assertion.principal_ref, batch.collected_at
                    )
                    agent_id = self._optional_asset(
                        connection, tenant_id, assertion.agent_ref, batch.collected_at
                    )
                    self._upsert_relationship(
                        connection,
                        tenant_id,
                        batch,
                        assertion,
                        source_id,
                        target_id,
                        principal_id,
                        agent_id,
                    )

                withdrawn_assets = 0
                withdrawn_relationships = 0
                for coverage in batch.coverage:
                    if coverage.state is not CoverageState.COMPLETE:
                        continue
                    withdrawn_assets += self._withdraw_missing_assets(
                        connection, tenant_id, batch, coverage.plane
                    )
                    withdrawn_relationships += self._withdraw_missing_relationships(
                        connection, tenant_id, batch, coverage.plane
                    )

                self._refresh_asset_lifecycle(connection, tenant_id)
                self._refresh_vulnerability_asset_links(connection, tenant_id)

        return {
            "assets": len(batch.assets),
            "relationships": len(batch.relationships),
            "withdrawn_assets": withdrawn_assets,
            "withdrawn_relationships": withdrawn_relationships,
        }

    def ingest_findings(self, tenant_id: str, batch: FindingBatch) -> dict[str, int]:
        """Persist finding observations without manufacturing inventory assets."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            with connection.transaction():
                self._insert_run(connection, tenant_id, batch)
                persisted_findings = 0
                for finding in batch.findings:
                    if finding.evaluation_result.value == "pass" and not self._finding_exists(
                        connection, tenant_id, batch, finding
                    ):
                        continue
                    finding_id = self._upsert_finding(
                        connection,
                        tenant_id,
                        batch,
                        finding,
                    )
                    persisted_findings += 1
                    self._replace_finding_resources(
                        connection,
                        tenant_id,
                        finding_id,
                        finding,
                    )
                    self._replace_finding_compliance(
                        connection,
                        tenant_id,
                        finding_id,
                        finding,
                    )
                    self._insert_finding_observation(
                        connection,
                        tenant_id,
                        finding_id,
                        batch,
                        finding,
                    )

                resolved_missing = 0
                if batch.may_resolve_missing:
                    result = connection.execute(
                        """
                        UPDATE finding
                        SET state = 'resolved',
                            evaluation_result = 'unknown',
                            resolution_reason = 'absent_from_authoritative_snapshot',
                            last_changed_at = %s
                        WHERE tenant_id = %s::uuid
                          AND connector_id = %s
                          AND connection_id = %s
                          AND scope_key = %s
                          AND last_observed_run_id <> %s
                          AND state IN ('open', 'unknown')
                        """,
                        (
                            batch.collected_at,
                            tenant_id,
                            batch.connector_id,
                            batch.connection_id,
                            batch.scope_key,
                            batch.run_id,
                        ),
                    )
                    resolved_missing = result.rowcount

        return {"findings": persisted_findings, "resolved_missing": resolved_missing}

    def ingest_vulnerabilities(self, tenant_id: str, batch: VulnerabilityBatch) -> dict[str, int]:
        """Persist scanner observations without manufacturing referenced inventory."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            with connection.transaction():
                self._insert_run(connection, tenant_id, batch)
                if batch.scan_subject is not None:
                    self._upsert_vulnerability_scan(connection, tenant_id, batch)
                canonical_ids: set[str] = set()
                for observation in batch.vulnerabilities:
                    vulnerability_id = self._upsert_vulnerability(
                        connection, tenant_id, batch, observation
                    )
                    canonical_ids.add(vulnerability_id)
                    self._upsert_vulnerability_observation(
                        connection,
                        tenant_id,
                        vulnerability_id,
                        batch,
                        observation,
                    )

                resolved_missing = 0
                if batch.may_resolve_missing:
                    result = connection.execute(
                        """
                        UPDATE vulnerability_observation
                        SET withdrawn_at = %s
                        WHERE tenant_id = %s::uuid
                          AND connector_id = %s
                          AND connection_id = %s
                          AND scope_key = %s
                          AND last_observed_run_id <> %s
                          AND withdrawn_at IS NULL
                        """,
                        (
                            batch.collected_at,
                            tenant_id,
                            batch.connector_id,
                            batch.connection_id,
                            batch.scope_key,
                            batch.run_id,
                        ),
                    )
                    resolved_missing = result.rowcount

                self._refresh_vulnerability_asset_links(connection, tenant_id)
                self._refresh_vulnerability_states(connection, tenant_id, batch.collected_at)

        return {
            "observations": len(batch.vulnerabilities),
            "vulnerabilities": len(canonical_ids),
            "resolved_missing": resolved_missing,
        }

    def ingest_activity(self, tenant_id: str, batch: ActivityBatch) -> dict[str, int]:
        """Append immutable activity observations and link only existing inventory."""

        inserted = 0
        linked_entities = 0
        unresolved_entities = 0
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            with connection.transaction():
                self._insert_run(connection, tenant_id, batch)
                for activity in batch.activities:
                    row = connection.execute(
                        """
                        INSERT INTO activity_event
                          (tenant_id, connector_id, connection_id, run_id, scope_key,
                           source_uid, category, activity_name, title, outcome, provider,
                           account_uid, region, occurred_at, source_observed_at,
                           session_uid, trace_uid, evidence, attributes)
                        VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                                %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb)
                        ON CONFLICT (tenant_id, connector_id, connection_id, source_uid)
                        DO NOTHING
                        RETURNING id
                        """,
                        (
                            tenant_id,
                            batch.connector_id,
                            batch.connection_id,
                            batch.run_id,
                            batch.scope_key,
                            activity.source_uid,
                            activity.category.value,
                            activity.activity_name,
                            activity.title,
                            activity.outcome.value,
                            activity.provider,
                            activity.account_uid,
                            activity.region,
                            activity.occurred_at,
                            activity.observed_at,
                            activity.session_uid,
                            activity.trace_uid,
                            json.dumps(_evidence_json(activity.evidence)),
                            json.dumps(dict(activity.attributes)),
                        ),
                    ).fetchone()
                    if row is None:
                        continue
                    inserted += 1
                    activity_id = str(row["id"])
                    for position, entity in enumerate(activity.entities):
                        entity_row = connection.execute(
                            """
                            INSERT INTO activity_entity
                              (tenant_id, activity_id, position, role, external_uid,
                               display_name, asset_kind, asset_natural_key, asset_id,
                               correlation, confidence, attributes)
                            VALUES (
                              %s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s,
                              (SELECT id FROM asset
                               WHERE tenant_id = %s::uuid AND kind = %s
                                 AND natural_key = %s),
                              %s, %s, %s::jsonb
                            )
                            RETURNING asset_id
                            """,
                            (
                                tenant_id,
                                activity_id,
                                position,
                                entity.role.value,
                                entity.external_uid,
                                entity.display_name,
                                entity.asset.kind.value if entity.asset else None,
                                entity.asset.natural_key if entity.asset else None,
                                tenant_id,
                                entity.asset.kind.value if entity.asset else None,
                                entity.asset.natural_key if entity.asset else None,
                                entity.correlation.value,
                                entity.confidence,
                                json.dumps(dict(entity.attributes)),
                            ),
                        ).fetchone()
                        if entity_row["asset_id"] is None:
                            unresolved_entities += 1
                        else:
                            linked_entities += 1
        return {
            "activities": inserted,
            "duplicates": len(batch.activities) - inserted,
            "linked_entities": linked_entities,
            "unresolved_entities": unresolved_entities,
        }

    def list_activity(
        self,
        tenant_id: str,
        *,
        category: str | None = None,
        outcome: str | None = None,
        asset_id: str | None = None,
        include_fixtures: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT event.*,
                       actor.external_uid AS actor_uid,
                       actor.display_name AS actor_name,
                       actor.asset_id AS actor_asset_id,
                       (SELECT count(*) FROM activity_entity entity
                        WHERE entity.tenant_id = event.tenant_id
                          AND entity.activity_id = event.id) AS entity_count,
                       (SELECT count(*) FROM activity_entity entity
                        WHERE entity.tenant_id = event.tenant_id
                          AND entity.activity_id = event.id
                          AND entity.asset_id IS NOT NULL) AS correlated_entity_count
                FROM activity_event event
                LEFT JOIN LATERAL (
                    SELECT entity.external_uid, entity.display_name, entity.asset_id
                    FROM activity_entity entity
                    WHERE entity.tenant_id = event.tenant_id
                      AND entity.activity_id = event.id AND entity.role = 'actor'
                    ORDER BY entity.position LIMIT 1
                ) actor ON true
                WHERE event.tenant_id = %s::uuid
                  AND (%s::boolean OR event.attributes->>'fixture' IS DISTINCT FROM 'true')
                  AND (%s::text IS NULL OR event.category = %s::text)
                  AND (%s::text IS NULL OR event.outcome = %s::text)
                  AND (
                    %s::uuid IS NULL OR EXISTS (
                      SELECT 1
                      FROM activity_entity related
                      WHERE related.tenant_id = event.tenant_id
                        AND related.activity_id = event.id
                        AND related.asset_id = %s::uuid
                    )
                  )
                ORDER BY event.occurred_at DESC, event.id
                LIMIT %s OFFSET %s
                """,
                (
                    tenant_id,
                    include_fixtures,
                    category,
                    category,
                    outcome,
                    outcome,
                    asset_id,
                    asset_id,
                    limit,
                    offset,
                ),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_activity(self, tenant_id: str, activity_id: str) -> dict[str, Any] | None:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            event = connection.execute(
                "SELECT * FROM activity_event WHERE tenant_id = %s::uuid AND id = %s::uuid",
                (tenant_id, activity_id),
            ).fetchone()
            if event is None:
                return None
            entities = connection.execute(
                """
                SELECT entity.*, asset.lifecycle_state, asset.governance_status,
                       view.display_name AS asset_display_name
                FROM activity_entity entity
                LEFT JOIN asset ON asset.tenant_id = entity.tenant_id
                               AND asset.id = entity.asset_id
                LEFT JOIN LATERAL (
                    SELECT assertion.display_name
                    FROM asset_assertion assertion
                    WHERE assertion.tenant_id = entity.tenant_id
                      AND assertion.asset_id = entity.asset_id
                      AND assertion.withdrawn_at IS NULL
                    ORDER BY assertion.confidence DESC, assertion.last_seen_at DESC
                    LIMIT 1
                ) view ON true
                WHERE entity.tenant_id = %s::uuid AND entity.activity_id = %s::uuid
                ORDER BY entity.position
                """,
                (tenant_id, activity_id),
            ).fetchall()
        result = dict(event)
        result["entities"] = [dict(row) for row in entities]
        return result

    def activity_summary(self, tenant_id: str, *, include_fixtures: bool = False) -> dict[str, Any]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            totals = connection.execute(
                """
                SELECT count(*) AS total,
                       count(*) FILTER (
                         WHERE occurred_at >= now() - interval '24 hours'
                       ) AS last_24h,
                       count(DISTINCT provider) AS providers,
                       count(*) FILTER (WHERE outcome = 'failure') AS failures,
                       (
                         SELECT count(*)
                         FROM activity_event fixture
                         WHERE fixture.tenant_id = %s::uuid
                           AND fixture.attributes->>'fixture' = 'true'
                       ) AS fixture_total
                FROM activity_event
                WHERE tenant_id = %s::uuid
                  AND (%s::boolean OR attributes->>'fixture' IS DISTINCT FROM 'true')
                """,
                (tenant_id, tenant_id, include_fixtures),
            ).fetchone()
            by_category = connection.execute(
                """
                SELECT category, count(*) AS count
                FROM activity_event
                WHERE tenant_id = %s::uuid
                  AND (%s::boolean OR attributes->>'fixture' IS DISTINCT FROM 'true')
                GROUP BY category ORDER BY category
                """,
                (tenant_id, include_fixtures),
            ).fetchall()
        return {
            **dict(totals),
            "by_category": {row["category"]: row["count"] for row in by_category},
        }

    def evaluate_runtime_detections(self, tenant_id: str) -> dict[str, Any]:
        """Evaluate explainable detections without mutating their source observations."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            with connection.transaction():
                snapshot = self._load_detection_snapshot(connection, tenant_id)
                sign_in_coverage = self._detection_coverage_state(
                    connection,
                    tenant_id,
                    ("entra_ai_signins", "entra_ai_application_inventory"),
                )
                consent_coverage = self._detection_coverage_state(
                    connection,
                    tenant_id,
                    ("entra_ai_directory_audits", "entra_ai_application_inventory"),
                )
                model_activity_coverage = self._detection_coverage_state(
                    connection, tenant_id, ("vertex_cloud_audit_activity",)
                )
                evaluations = (
                    evaluate_repeated_failed_ai_signins(
                        snapshot, coverage_state=sign_in_coverage
                    ),
                    evaluate_unreviewed_ai_consent(
                        snapshot, coverage_state=consent_coverage
                    ),
                    evaluate_unreviewed_model_invocation(
                        snapshot, coverage_state=model_activity_coverage
                    ),
                )
                for evaluation in evaluations:
                    active_keys: set[str] = set()
                    for candidate in evaluation.candidates:
                        detection_id = self._upsert_runtime_detection(
                            connection, tenant_id, candidate, evaluation
                        )
                        active_keys.add(candidate.correlation_key)
                        self._replace_runtime_detection_evidence(
                            connection, tenant_id, detection_id, candidate
                        )

                    # Event-backed detections remain open until an explicit analyst or
                    # remediation disposition exists. A rolling window expiring is not
                    # evidence that the observed behavior was remediated.
                    connection.execute(
                        """
                        UPDATE runtime_detection
                        SET last_evaluated_at = %s
                        WHERE tenant_id = %s::uuid AND rule_uid = %s
                          AND NOT (correlation_key = ANY(%s::text[]))
                        """,
                        (
                            evaluation.evaluated_at,
                            tenant_id,
                            evaluation.rule_uid,
                            list(active_keys),
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO runtime_detection_rule_evaluation
                          (tenant_id, rule_uid, state, confirmed_detections,
                           incomplete_candidates, detail, evaluated_at)
                        VALUES (%s::uuid, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (tenant_id, rule_uid)
                        DO UPDATE SET state = EXCLUDED.state,
                                      confirmed_detections = EXCLUDED.confirmed_detections,
                                      incomplete_candidates = EXCLUDED.incomplete_candidates,
                                      detail = EXCLUDED.detail,
                                      evaluated_at = EXCLUDED.evaluated_at
                        """,
                        (
                            tenant_id,
                            evaluation.rule_uid,
                            evaluation.state.value,
                            len(evaluation.candidates),
                            evaluation.incomplete_candidates,
                            evaluation.detail,
                            evaluation.evaluated_at,
                        ),
                    )
        return {
            "confirmed_detections": sum(len(item.candidates) for item in evaluations),
            "evaluations": [
                {
                    "rule_uid": item.rule_uid,
                    "state": item.state.value,
                    "confirmed_detections": len(item.candidates),
                    "incomplete_candidates": item.incomplete_candidates,
                    "detail": item.detail,
                }
                for item in evaluations
            ],
        }

    def list_runtime_detections(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT detection.*,
                       (SELECT count(*) FROM runtime_detection_activity link
                        WHERE link.tenant_id = detection.tenant_id
                          AND link.detection_id = detection.id) AS activity_count,
                       (SELECT count(*) FROM runtime_detection_asset link
                        WHERE link.tenant_id = detection.tenant_id
                          AND link.detection_id = detection.id) AS asset_count
                FROM runtime_detection detection
                WHERE detection.tenant_id = %s::uuid
                  AND (%s::text IS NULL OR detection.state = %s::text)
                  AND (%s::text IS NULL OR detection.severity = %s::text)
                ORDER BY
                  CASE detection.state WHEN 'open' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END,
                  CASE detection.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2 WHEN 'low' THEN 3
                    WHEN 'informational' THEN 4 ELSE 5 END,
                  detection.last_seen_at DESC, detection.correlation_key
                LIMIT %s OFFSET %s
                """,
                (tenant_id, state, state, severity, severity, limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_runtime_detection(
        self, tenant_id: str, detection_id: str
    ) -> dict[str, Any] | None:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            detection = connection.execute(
                """
                SELECT * FROM runtime_detection
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                """,
                (tenant_id, detection_id),
            ).fetchone()
            if detection is None:
                return None
            activities = connection.execute(
                """
                SELECT event.*, link.role
                FROM runtime_detection_activity link
                JOIN activity_event event
                  ON event.tenant_id = link.tenant_id AND event.id = link.activity_id
                WHERE link.tenant_id = %s::uuid AND link.detection_id = %s::uuid
                ORDER BY event.occurred_at, event.id
                """,
                (tenant_id, detection_id),
            ).fetchall()
            assets = connection.execute(
                f"""
                SELECT asset.id, asset.kind, asset.natural_key, asset.governance_status,
                       asset.lifecycle_state, link.role, winner.display_name,
                       winner.assertion_type, winner.confidence, winner.attributes,
                       winner.evidence
                FROM runtime_detection_asset link
                JOIN asset ON asset.tenant_id = link.tenant_id AND asset.id = link.asset_id
                LEFT JOIN LATERAL (
                    SELECT aa.display_name, aa.assertion_type,
                           aa.confidence, aa.attributes, aa.evidence
                    FROM asset_assertion aa
                    WHERE aa.tenant_id = asset.tenant_id
                      AND aa.asset_id = asset.id
                    ORDER BY (aa.withdrawn_at IS NULL) DESC,
                             {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC
                    LIMIT 1
                ) winner ON true
                WHERE link.tenant_id = %s::uuid AND link.detection_id = %s::uuid
                ORDER BY link.role, asset.natural_key
                """,
                (tenant_id, detection_id),
            ).fetchall()
        result = dict(detection)
        result["activities"] = [dict(row) for row in activities]
        result["assets"] = [dict(row) for row in assets]
        return result

    def runtime_detection_summary(self, tenant_id: str) -> dict[str, Any]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            by_state = connection.execute(
                """
                SELECT state, count(*) AS count FROM runtime_detection
                WHERE tenant_id = %s::uuid GROUP BY state ORDER BY state
                """,
                (tenant_id,),
            ).fetchall()
            open_by_severity = connection.execute(
                """
                SELECT severity, count(*) AS count FROM runtime_detection
                WHERE tenant_id = %s::uuid AND state = 'open'
                GROUP BY severity ORDER BY severity
                """,
                (tenant_id,),
            ).fetchall()
        return {
            "total": sum(row["count"] for row in by_state),
            "by_state": {row["state"]: row["count"] for row in by_state},
            "open_by_severity": {row["severity"]: row["count"] for row in open_by_severity},
        }

    def latest_runtime_detection_evaluations(self, tenant_id: str) -> list[dict[str, Any]]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT rule_uid, state, confirmed_detections, incomplete_candidates,
                       detail, evaluated_at
                FROM runtime_detection_rule_evaluation
                WHERE tenant_id = %s::uuid ORDER BY rule_uid
                """,
                (tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _upsert_vulnerability_scan(connection, tenant_id: str, batch: VulnerabilityBatch) -> None:
        subject = batch.scan_subject
        if subject is None:
            return
        connection.execute(
            """
            INSERT INTO vulnerability_scan
              (tenant_id, connector_id, connection_id, run_id,
               target_kind, target_natural_key, target_asset_id,
               artifact_kind, artifact_locator, artifact_digest,
               source_observed_at, evidence)
            VALUES (
              %s::uuid, %s, %s, %s, %s, %s,
              (SELECT id FROM asset
               WHERE tenant_id = %s::uuid AND kind = %s AND natural_key = %s),
              %s, %s, %s, %s, %s::jsonb
            )
            ON CONFLICT (tenant_id, connector_id, connection_id, run_id)
            DO UPDATE SET target_kind = EXCLUDED.target_kind,
                          target_natural_key = EXCLUDED.target_natural_key,
                          target_asset_id = EXCLUDED.target_asset_id,
                          artifact_kind = EXCLUDED.artifact_kind,
                          artifact_locator = EXCLUDED.artifact_locator,
                          artifact_digest = EXCLUDED.artifact_digest,
                          source_observed_at = EXCLUDED.source_observed_at,
                          evidence = EXCLUDED.evidence
            """,
            (
                tenant_id,
                batch.connector_id,
                batch.connection_id,
                batch.run_id,
                subject.target.kind.value,
                subject.target.natural_key,
                tenant_id,
                subject.target.kind.value,
                subject.target.natural_key,
                subject.artifact_kind,
                subject.artifact_locator,
                subject.artifact_digest,
                subject.evidence.observed_at,
                json.dumps(_evidence_json(subject.evidence)),
            ),
        )

    def list_vulnerabilities(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT v.*, winner.aliases, winner.title, winner.description,
                       winner.severity, winner.cvss_score, winner.cvss_vector,
                       winner.fix_state, winner.fixed_versions, winner.exploit_state,
                       winner.match_method, winner.match_confidence,
                       winner.database_version, winner.database_built_at,
                       winner.connector_id AS scanner,
                       winner.connection_id AS scanner_connection,
                       component_view.display_name AS component_name,
                       component_view.attributes AS component_attributes,
                       target_view.display_name AS target_name,
                       (v.component_asset_id IS NOT NULL) AS component_correlated,
                       (v.target_asset_id IS NOT NULL) AS target_correlated,
                       (SELECT count(*) FROM vulnerability_observation source_count
                        WHERE source_count.tenant_id = v.tenant_id
                          AND source_count.vulnerability_id = v.id
                          AND source_count.withdrawn_at IS NULL) AS source_count
                FROM vulnerability v
                JOIN LATERAL (
                    SELECT observation.*
                    FROM vulnerability_observation observation
                    WHERE observation.tenant_id = v.tenant_id
                      AND observation.vulnerability_id = v.id
                    ORDER BY observation.withdrawn_at NULLS FIRST,
                             observation.match_confidence DESC,
                             observation.last_seen_at DESC,
                             observation.connector_id,
                             observation.connection_id
                    LIMIT 1
                ) winner ON true
                LEFT JOIN LATERAL (
                    SELECT assertion.display_name, assertion.attributes
                    FROM asset_assertion assertion
                    WHERE assertion.tenant_id = v.tenant_id
                      AND assertion.asset_id = v.component_asset_id
                      AND assertion.withdrawn_at IS NULL
                    ORDER BY assertion.confidence DESC, assertion.last_seen_at DESC
                    LIMIT 1
                ) component_view ON true
                LEFT JOIN LATERAL (
                    SELECT assertion.display_name
                    FROM asset_assertion assertion
                    WHERE assertion.tenant_id = v.tenant_id
                      AND assertion.asset_id = v.target_asset_id
                      AND assertion.withdrawn_at IS NULL
                    ORDER BY assertion.confidence DESC, assertion.last_seen_at DESC
                    LIMIT 1
                ) target_view ON true
                WHERE v.tenant_id = %s::uuid
                  AND (%s::text IS NULL OR v.state = %s::text)
                  AND (%s::text IS NULL OR winner.severity = %s::text)
                ORDER BY
                  CASE v.state WHEN 'open' THEN 0 WHEN 'unknown' THEN 1
                               WHEN 'suppressed' THEN 2 ELSE 3 END,
                  CASE winner.exploit_state WHEN 'known_exploited' THEN 0
                       WHEN 'public_exploit' THEN 1 ELSE 2 END,
                  CASE winner.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                       WHEN 'medium' THEN 2 WHEN 'low' THEN 3
                       WHEN 'informational' THEN 4 ELSE 5 END,
                  v.last_seen_at DESC, v.vulnerability_id
                LIMIT %s OFFSET %s
                """,
                (tenant_id, state, state, severity, severity, limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_vulnerability(self, tenant_id: str, vulnerability_id: str) -> dict[str, Any] | None:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            vulnerability = connection.execute(
                """
                SELECT v.*,
                       component_view.display_name AS component_name,
                       component_view.attributes AS component_attributes,
                       target_view.display_name AS target_name
                FROM vulnerability v
                LEFT JOIN LATERAL (
                    SELECT assertion.display_name, assertion.attributes
                    FROM asset_assertion assertion
                    WHERE assertion.tenant_id = v.tenant_id
                      AND assertion.asset_id = v.component_asset_id
                      AND assertion.withdrawn_at IS NULL
                    ORDER BY assertion.confidence DESC, assertion.last_seen_at DESC
                    LIMIT 1
                ) component_view ON true
                LEFT JOIN LATERAL (
                    SELECT assertion.display_name
                    FROM asset_assertion assertion
                    WHERE assertion.tenant_id = v.tenant_id
                      AND assertion.asset_id = v.target_asset_id
                      AND assertion.withdrawn_at IS NULL
                    ORDER BY assertion.confidence DESC, assertion.last_seen_at DESC
                    LIMIT 1
                ) target_view ON true
                WHERE v.tenant_id = %s::uuid AND v.id = %s::uuid
                """,
                (tenant_id, vulnerability_id),
            ).fetchone()
            if vulnerability is None:
                return None
            observations = connection.execute(
                """
                SELECT connector_id, connection_id, source_uid, scope_key, aliases,
                       title, description, severity, state, cvss_score, cvss_vector,
                       fix_state, fixed_versions, exploit_state, match_method,
                       match_confidence, database_version, database_built_at,
                       source_observed_at, evidence, attributes, first_seen_at,
                       last_seen_at, last_observed_run_id, withdrawn_at
                FROM vulnerability_observation
                WHERE tenant_id = %s::uuid AND vulnerability_id = %s::uuid
                ORDER BY withdrawn_at NULLS FIRST, last_seen_at DESC,
                         connector_id, connection_id
                """,
                (tenant_id, vulnerability_id),
            ).fetchall()
        result = dict(vulnerability)
        result["component"] = {
            "kind": result.pop("component_kind"),
            "natural_key": result.pop("component_natural_key"),
            "asset_id": result.pop("component_asset_id"),
            "display_name": result.pop("component_name"),
            "attributes": result.pop("component_attributes"),
        }
        result["target"] = {
            "kind": result.pop("target_kind"),
            "natural_key": result.pop("target_natural_key"),
            "asset_id": result.pop("target_asset_id"),
            "display_name": result.pop("target_name"),
        }
        result["observations"] = [dict(row) for row in observations]
        return result

    def vulnerability_summary(self, tenant_id: str) -> dict[str, Any]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT v.state, winner.severity, winner.fix_state,
                       winner.exploit_state, count(*) AS count
                FROM vulnerability v
                JOIN LATERAL (
                    SELECT severity, fix_state, exploit_state
                    FROM vulnerability_observation observation
                    WHERE observation.tenant_id = v.tenant_id
                      AND observation.vulnerability_id = v.id
                    ORDER BY observation.withdrawn_at NULLS FIRST,
                             observation.match_confidence DESC,
                             observation.last_seen_at DESC
                    LIMIT 1
                ) winner ON true
                WHERE v.tenant_id = %s::uuid
                GROUP BY v.state, winner.severity, winner.fix_state,
                         winner.exploit_state
                """,
                (tenant_id,),
            ).fetchall()
            open_vulnerability_ids = connection.execute(
                """
                SELECT count(DISTINCT vulnerability_id) AS count
                FROM vulnerability
                WHERE tenant_id = %s::uuid AND state = 'open'
                """,
                (tenant_id,),
            ).fetchone()["count"]
        by_state: dict[str, int] = {}
        open_by_severity: dict[str, int] = {}
        open_by_fix_state: dict[str, int] = {}
        open_by_exploit_state: dict[str, int] = {}
        for row in rows:
            by_state[row["state"]] = by_state.get(row["state"], 0) + row["count"]
            if row["state"] == "open":
                open_by_severity[row["severity"]] = (
                    open_by_severity.get(row["severity"], 0) + row["count"]
                )
                open_by_fix_state[row["fix_state"]] = (
                    open_by_fix_state.get(row["fix_state"], 0) + row["count"]
                )
                open_by_exploit_state[row["exploit_state"]] = (
                    open_by_exploit_state.get(row["exploit_state"], 0) + row["count"]
                )
        return {
            "total": sum(by_state.values()),
            "by_state": by_state,
            "open_vulnerability_ids": open_vulnerability_ids,
            "open_by_severity": open_by_severity,
            "open_by_fix_state": open_by_fix_state,
            "open_by_exploit_state": open_by_exploit_state,
        }

    def list_findings(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT f.*,
                       (SELECT count(*) FROM finding_resource fr
                        WHERE fr.tenant_id = f.tenant_id AND fr.finding_id = f.id)
                           AS resource_count
                FROM finding f
                WHERE f.tenant_id = %s::uuid
                  AND (%s::text IS NULL OR f.state = %s::text)
                  AND (%s::text IS NULL OR f.severity = %s::text)
                ORDER BY
                  CASE f.state WHEN 'open' THEN 0 WHEN 'unknown' THEN 1
                               WHEN 'suppressed' THEN 2 ELSE 3 END,
                  CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                  WHEN 'medium' THEN 2 WHEN 'low' THEN 3
                                  WHEN 'informational' THEN 4 ELSE 5 END,
                  f.last_seen_at DESC, f.source_uid
                LIMIT %s OFFSET %s
                """,
                (tenant_id, state, state, severity, severity, limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_finding(self, tenant_id: str, finding_id: str) -> dict[str, Any] | None:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            finding = connection.execute(
                "SELECT * FROM finding WHERE tenant_id = %s::uuid AND id = %s::uuid",
                (tenant_id, finding_id),
            ).fetchone()
            if finding is None:
                return None
            resources = connection.execute(
                """
                SELECT resource_uid AS uid, resource_name AS name,
                       resource_type, provider, account_uid, region
                FROM finding_resource
                WHERE tenant_id = %s::uuid AND finding_id = %s::uuid
                ORDER BY resource_uid
                """,
                (tenant_id, finding_id),
            ).fetchall()
            compliance = connection.execute(
                """
                SELECT framework, control
                FROM finding_compliance
                WHERE tenant_id = %s::uuid AND finding_id = %s::uuid
                ORDER BY framework, control
                """,
                (tenant_id, finding_id),
            ).fetchall()
            observations = connection.execute(
                """
                SELECT run_id, scope_key, collected_at, source_observed_at,
                       severity, state, evaluation_result, evidence, attributes,
                       affected_resources, compliance
                FROM finding_observation
                WHERE tenant_id = %s::uuid AND finding_id = %s::uuid
                ORDER BY collected_at DESC
                LIMIT 50
                """,
                (tenant_id, finding_id),
            ).fetchall()
        result = dict(finding)
        result["resources"] = [dict(row) for row in resources]
        grouped: dict[str, list[str]] = {}
        for row in compliance:
            grouped.setdefault(row["framework"], []).append(row["control"])
        result["compliance"] = grouped
        result["observations"] = [dict(row) for row in observations]
        return result

    def finding_summary(self, tenant_id: str) -> dict[str, Any]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            by_state = connection.execute(
                """
                SELECT state, count(*) AS count
                FROM finding WHERE tenant_id = %s::uuid
                GROUP BY state ORDER BY state
                """,
                (tenant_id,),
            ).fetchall()
            open_by_severity = connection.execute(
                """
                SELECT severity, count(*) AS count
                FROM finding WHERE tenant_id = %s::uuid AND state = 'open'
                GROUP BY severity ORDER BY severity
                """,
                (tenant_id,),
            ).fetchall()
        return {
            "total": sum(row["count"] for row in by_state),
            "by_state": {row["state"]: row["count"] for row in by_state},
            "open_by_severity": {row["severity"]: row["count"] for row in open_by_severity},
        }

    def evaluate_issues(self, tenant_id: str) -> dict[str, Any]:
        """Recompute deterministic issues from currently active evidence."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            with connection.transaction():
                snapshot = self._load_correlation_snapshot(connection, tenant_id)
                detection_snapshot = self._load_detection_snapshot(connection, tenant_id)
                runtime_detections = self._load_correlation_runtime_detections(
                    connection, tenant_id
                )
                evaluations = (
                    evaluate_agent_sensitive_write(snapshot),
                    evaluate_deployed_bedrock_governance_gap(snapshot),
                    evaluate_unreviewed_ai_consent_then_use(
                        runtime_detections,
                        detection_snapshot.activities,
                        snapshot.assets,
                        coverage_state=self._cross_signal_issue_coverage_state(
                            connection, tenant_id
                        ),
                    ),
                )
                for evaluation in evaluations:
                    active_keys: set[str] = set()
                    for candidate in evaluation.candidates:
                        issue_id = self._upsert_issue(connection, tenant_id, candidate, evaluation)
                        active_keys.add(candidate.correlation_key)
                        self._replace_issue_components(connection, tenant_id, issue_id, candidate)

                    existing = connection.execute(
                        """
                        SELECT id, correlation_key
                        FROM issue
                        WHERE tenant_id = %s::uuid AND rule_uid = %s AND state <> 'resolved'
                        """,
                        (tenant_id, evaluation.rule_uid),
                    ).fetchall()
                    missing = [
                        row for row in existing if row["correlation_key"] not in active_keys
                    ]
                    for row in missing:
                        contributors = connection.execute(
                            """
                            SELECT
                              (SELECT bool_and(
                                  f.state = 'open' AND f.evaluation_result = 'fail')
                               FROM issue_finding link
                               JOIN finding f
                                 ON f.id = link.finding_id
                                AND f.tenant_id = link.tenant_id
                               WHERE link.tenant_id = %s::uuid
                                 AND link.issue_id = %s::uuid) AS findings_open,
                              (SELECT bool_and(d.state = 'open')
                               FROM issue_detection link
                               JOIN runtime_detection d
                                 ON d.id = link.detection_id
                                AND d.tenant_id = link.tenant_id
                               WHERE link.tenant_id = %s::uuid
                                 AND link.issue_id = %s::uuid) AS detections_open
                            """,
                            (tenant_id, row["id"], tenant_id, row["id"]),
                        ).fetchone()
                        current_contributor = bool(
                            contributors["findings_open"]
                            or contributors["detections_open"]
                        )
                        if (
                            current_contributor
                            and evaluation.state is not CoverageState.COMPLETE
                        ):
                            state = "unknown"
                            reason = "correlation_incomplete"
                        elif contributors["findings_open"] is False:
                            state = "resolved"
                            reason = "contributing_finding_inactive"
                        elif contributors["detections_open"] is False:
                            state = "resolved"
                            reason = "contributing_detection_inactive"
                        else:
                            state = "resolved"
                            reason = "correlation_no_longer_confirmed"
                        connection.execute(
                            """
                            UPDATE issue
                            SET state = %s, resolution_reason = %s,
                                last_changed_at = CASE WHEN state <> %s
                                    THEN %s ELSE last_changed_at END,
                                last_evaluated_at = %s
                            WHERE tenant_id = %s::uuid AND id = %s::uuid
                            """,
                            (
                                state,
                                reason,
                                state,
                                evaluation.evaluated_at,
                                evaluation.evaluated_at,
                                tenant_id,
                                row["id"],
                            ),
                        )

                    connection.execute(
                        """
                        INSERT INTO issue_rule_evaluation
                          (tenant_id, rule_uid, state, confirmed_issues,
                           incomplete_candidates, ambiguous_resource_references,
                           detail, evaluated_at)
                        VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (tenant_id, rule_uid)
                        DO UPDATE SET state = EXCLUDED.state,
                                      confirmed_issues = EXCLUDED.confirmed_issues,
                                      incomplete_candidates = EXCLUDED.incomplete_candidates,
                                      ambiguous_resource_references =
                                          EXCLUDED.ambiguous_resource_references,
                                      detail = EXCLUDED.detail,
                                      evaluated_at = EXCLUDED.evaluated_at
                        """,
                        (
                            tenant_id,
                            evaluation.rule_uid,
                            evaluation.state.value,
                            len(evaluation.candidates),
                            evaluation.incomplete_candidates,
                            evaluation.ambiguous_resource_references,
                            evaluation.detail,
                            evaluation.evaluated_at,
                        ),
                    )
        aggregate_state = aggregate_issue_evaluation_state(evaluations)
        return {
            "confirmed_issues": sum(len(item.candidates) for item in evaluations),
            "evaluation_state": aggregate_state.value,
            "incomplete_candidates": sum(
                item.incomplete_candidates for item in evaluations
            ),
            "ambiguous_resource_references": sum(
                item.ambiguous_resource_references for item in evaluations
            ),
        }

    def list_issues(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT i.*,
                       (SELECT count(*) FROM issue_finding f
                        WHERE f.tenant_id = i.tenant_id AND f.issue_id = i.id)
                           AS finding_count,
                       (SELECT count(*) FROM issue_path_node n
                        WHERE n.tenant_id = i.tenant_id AND n.issue_id = i.id)
                           AS asset_count,
                       (SELECT count(*) FROM issue_detection d
                        WHERE d.tenant_id = i.tenant_id AND d.issue_id = i.id)
                           AS detection_count,
                       (SELECT count(*) FROM issue_activity a
                        WHERE a.tenant_id = i.tenant_id AND a.issue_id = i.id)
                           AS activity_count
                FROM issue i
                WHERE i.tenant_id = %s::uuid
                  AND (%s::text IS NULL OR i.state = %s::text)
                  AND (%s::text IS NULL OR i.severity = %s::text)
                ORDER BY
                  CASE i.state WHEN 'open' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END,
                  CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                  WHEN 'medium' THEN 2 WHEN 'low' THEN 3
                                  WHEN 'informational' THEN 4 ELSE 5 END,
                  i.last_seen_at DESC, i.correlation_key
                LIMIT %s OFFSET %s
                """,
                (tenant_id, state, state, severity, severity, limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_issue(self, tenant_id: str, issue_id: str) -> dict[str, Any] | None:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            issue = connection.execute(
                "SELECT * FROM issue WHERE tenant_id = %s::uuid AND id = %s::uuid",
                (tenant_id, issue_id),
            ).fetchone()
            if issue is None:
                return None
            findings = connection.execute(
                """
                SELECT f.id, f.rule_uid, f.title, f.severity, f.state, f.evidence,
                       link.role
                FROM issue_finding link
                JOIN finding f ON f.id = link.finding_id AND f.tenant_id = link.tenant_id
                WHERE link.tenant_id = %s::uuid AND link.issue_id = %s::uuid
                ORDER BY link.role, f.rule_uid
                """,
                (tenant_id, issue_id),
            ).fetchall()
            nodes = connection.execute(
                f"""
                SELECT n.position, n.role, a.id, a.kind, a.natural_key,
                       winner.display_name, winner.assertion_type, winner.confidence,
                       winner.evidence
                FROM issue_path_node n
                JOIN asset a ON a.id = n.asset_id AND a.tenant_id = n.tenant_id
                LEFT JOIN LATERAL (
                    SELECT aa.display_name, aa.assertion_type, aa.confidence, aa.evidence
                    FROM asset_assertion aa
                    WHERE aa.tenant_id = a.tenant_id AND aa.asset_id = a.id
                    ORDER BY (aa.withdrawn_at IS NULL) DESC,
                             {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC
                    LIMIT 1
                ) winner ON true
                WHERE n.tenant_id = %s::uuid AND n.issue_id = %s::uuid
                ORDER BY n.position
                """,
                (tenant_id, issue_id),
            ).fetchall()
            edges = connection.execute(
                """
                SELECT e.position, r.id, r.kind, r.category, r.assertion_type,
                       r.confidence, r.evidence, r.withdrawn_at,
                       r.source_asset_id AS source_id, r.target_asset_id AS target_id
                FROM issue_path_edge e
                JOIN relationship_assertion r
                  ON r.id = e.relationship_id AND r.tenant_id = e.tenant_id
                WHERE e.tenant_id = %s::uuid AND e.issue_id = %s::uuid
                ORDER BY e.position
                """,
                (tenant_id, issue_id),
            ).fetchall()
            detections = connection.execute(
                """
                SELECT d.id, d.rule_uid, d.title, d.description, d.risk,
                       d.investigation_guidance, d.severity, d.state, d.confidence,
                       d.attributes, d.first_seen_at, d.last_seen_at, link.role
                FROM issue_detection link
                JOIN runtime_detection d
                  ON d.id = link.detection_id AND d.tenant_id = link.tenant_id
                WHERE link.tenant_id = %s::uuid AND link.issue_id = %s::uuid
                ORDER BY link.role, d.last_seen_at, d.id
                """,
                (tenant_id, issue_id),
            ).fetchall()
            activities = connection.execute(
                """
                SELECT event.id, event.category, event.outcome, event.activity_name,
                       event.title, event.provider, event.occurred_at, event.evidence,
                       event.attributes, link.role, actors.actors
                FROM issue_activity link
                JOIN activity_event event
                  ON event.id = link.activity_id AND event.tenant_id = link.tenant_id
                LEFT JOIN LATERAL (
                  SELECT array_agg(jsonb_build_object(
                           'external_uid', entity.external_uid,
                           'display_name', entity.display_name,
                           'asset_id', entity.asset_id,
                           'correlation', entity.correlation,
                           'confidence', entity.confidence)
                         ORDER BY entity.position) AS actors
                  FROM activity_entity entity
                  WHERE entity.tenant_id = event.tenant_id
                    AND entity.activity_id = event.id
                    AND entity.role = 'actor'
                ) actors ON true
                WHERE link.tenant_id = %s::uuid AND link.issue_id = %s::uuid
                ORDER BY event.occurred_at, event.id
                """,
                (tenant_id, issue_id),
            ).fetchall()
        result = dict(issue)
        result["findings"] = [dict(row) for row in findings]
        result["path_nodes"] = [dict(row) for row in nodes]
        result["path_edges"] = [dict(row) for row in edges]
        result["detections"] = [dict(row) for row in detections]
        result["activities"] = [dict(row) for row in activities]
        return result

    def issue_summary(self, tenant_id: str) -> dict[str, Any]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            by_state = connection.execute(
                """
                SELECT state, count(*) AS count FROM issue
                WHERE tenant_id = %s::uuid GROUP BY state ORDER BY state
                """,
                (tenant_id,),
            ).fetchall()
            open_by_severity = connection.execute(
                """
                SELECT severity, count(*) AS count FROM issue
                WHERE tenant_id = %s::uuid AND state = 'open'
                GROUP BY severity ORDER BY severity
                """,
                (tenant_id,),
            ).fetchall()
        return {
            "total": sum(row["count"] for row in by_state),
            "by_state": {row["state"]: row["count"] for row in by_state},
            "open_by_severity": {row["severity"]: row["count"] for row in open_by_severity},
        }

    def latest_issue_evaluations(self, tenant_id: str) -> list[dict[str, Any]]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT rule_uid, state, confirmed_issues, incomplete_candidates,
                       ambiguous_resource_references, detail, evaluated_at
                FROM issue_rule_evaluation
                WHERE tenant_id = %s::uuid ORDER BY rule_uid
                """,
                (tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def deployment_targets(self, tenant_id: str) -> list[dict[str, Any]]:
        """Return active, independently asserted workloads eligible for IaC correlation."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                f"""
                SELECT a.natural_key, winner.display_name, winner.attributes,
                       winner.evidence->>'locator' AS evidence_locator,
                       winner.evidence->'payload' AS evidence_payload
                FROM asset a
                JOIN LATERAL (
                    SELECT aa.display_name, aa.attributes, aa.evidence
                    FROM asset_assertion aa
                    WHERE aa.tenant_id = a.tenant_id AND aa.asset_id = a.id
                      AND aa.withdrawn_at IS NULL
                      AND aa.assertion_type IN ('observed', 'externally_verified')
                    ORDER BY {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC,
                             aa.connector_id, aa.connection_id
                    LIMIT 1
                ) winner ON true
                WHERE a.tenant_id = %s::uuid AND a.kind = 'ai_workload'
                  AND a.lifecycle_state = 'active'
                ORDER BY a.natural_key
                """,
                (tenant_id,),
            ).fetchall()
        targets: list[dict[str, Any]] = []
        for row in rows:
            attributes = dict(row["attributes"] or {})
            evidence_payload = dict(row["evidence_payload"] or {})
            if "container_names" not in attributes and isinstance(
                evidence_payload.get("container_names"), list
            ):
                attributes["container_names"] = evidence_payload["container_names"]
            identity = _deployment_identity_from_attributes(
                attributes,
                display_name=str(row["display_name"]),
            )
            service = attributes.get("service")
            if identity is None or not isinstance(service, str) or not service:
                continue
            targets.append(
                {
                    "natural_key": row["natural_key"],
                    "display_name": row["display_name"],
                    "service": service,
                    "identity": identity,
                    "evidence_locator": row["evidence_locator"],
                    "evidence_payload": evidence_payload,
                }
            )
        return targets

    def code_to_cloud_deployments(self, tenant_id: str) -> list[dict[str, Any]]:
        """Return proven repository-to-workload links and their runtime context."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                f"""
                SELECT deployment.id, deployment.assertion_type, deployment.confidence,
                       deployment.attributes, deployment.evidence,
                       workload.id AS workload_id, workload.natural_key AS workload_natural_key,
                       workload_view.display_name AS workload_name,
                       workload_view.attributes AS workload_attributes,
                       repository.id AS repository_id,
                       repository.natural_key AS repository_natural_key,
                       repository_view.display_name AS repository_name,
                       agent.item AS agent,
                       COALESCE(tools.items, '[]'::jsonb) AS tools,
                       COALESCE(models.items, '[]'::jsonb) AS models,
                       identity.item AS identity,
                       COALESCE(code_findings.items, '[]'::jsonb) AS code_findings,
                       vulnerability_coverage.item AS vulnerability_coverage,
                       COALESCE(artifact_vulnerability_summary.total, 0)
                           AS artifact_vulnerability_count,
                       COALESCE(artifact_vulnerability_summary.vulnerability_ids, 0)
                           AS artifact_vulnerability_id_count,
                       COALESCE(artifact_vulnerabilities.items, '[]'::jsonb)
                           AS artifact_vulnerabilities
                FROM relationship_assertion deployment
                JOIN asset workload ON workload.id = deployment.source_asset_id
                  AND workload.tenant_id = deployment.tenant_id
                JOIN asset repository ON repository.id = deployment.target_asset_id
                  AND repository.tenant_id = deployment.tenant_id
                JOIN LATERAL (
                    SELECT aa.display_name, aa.attributes
                    FROM asset_assertion aa
                    WHERE aa.tenant_id = workload.tenant_id AND aa.asset_id = workload.id
                      AND aa.withdrawn_at IS NULL
                      AND aa.attributes ? 'service'
                      AND (
                        aa.attributes ? 'deployment_identifiers'
                        OR aa.attributes ? 'logical_id'
                      )
                    ORDER BY {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC LIMIT 1
                ) workload_view ON true
                JOIN LATERAL (
                    SELECT aa.display_name
                    FROM asset_assertion aa
                    WHERE aa.tenant_id = repository.tenant_id AND aa.asset_id = repository.id
                      AND aa.withdrawn_at IS NULL
                    ORDER BY {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC LIMIT 1
                ) repository_view ON true
                LEFT JOIN LATERAL (
                    SELECT source.id AS agent_id,
                           jsonb_build_object(
                               'id', source.id, 'natural_key', source.natural_key,
                               'display_name', source_view.display_name,
                               'assertion_type', rel.assertion_type,
                               'confidence', rel.confidence
                           ) AS item
                    FROM relationship_assertion rel
                    JOIN asset source ON source.id = rel.source_asset_id
                      AND source.tenant_id = rel.tenant_id
                    JOIN LATERAL (
                        SELECT aa.display_name
                        FROM asset_assertion aa
                        WHERE aa.tenant_id = source.tenant_id
                          AND aa.asset_id = source.id
                          AND aa.withdrawn_at IS NULL
                        ORDER BY {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC LIMIT 1
                    ) source_view ON true
                    WHERE rel.tenant_id = deployment.tenant_id
                      AND rel.target_asset_id = repository.id
                      AND rel.kind = 'defined_in'
                      AND rel.withdrawn_at IS NULL
                      AND source.kind = 'ai_agent'
                    ORDER BY rel.confidence DESC LIMIT 1
                ) agent ON true
                LEFT JOIN LATERAL (
                    SELECT jsonb_agg(jsonb_build_object(
                        'id', tool.id,
                        'natural_key', tool.natural_key,
                        'display_name', tool_view.display_name,
                        'assertion_type', tool_rel.assertion_type,
                        'confidence', tool_rel.confidence,
                        'provider', tool_view.attributes->>'provider',
                        'operation', tool_view.attributes->>'operation',
                        'execution_status', COALESCE(
                            tool_view.attributes->>'execution_status', 'not_observed'
                        ),
                        'actions', COALESCE(actions.items, '[]'::jsonb)
                    ) ORDER BY tool_view.display_name) AS items
                    FROM relationship_assertion tool_rel
                    JOIN asset tool ON tool.id = tool_rel.target_asset_id
                      AND tool.tenant_id = tool_rel.tenant_id
                    JOIN LATERAL (
                        SELECT aa.display_name, aa.attributes
                        FROM asset_assertion aa
                        WHERE aa.tenant_id = tool.tenant_id AND aa.asset_id = tool.id
                          AND aa.withdrawn_at IS NULL
                        ORDER BY {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC LIMIT 1
                    ) tool_view ON true
                    LEFT JOIN LATERAL (
                        SELECT jsonb_agg(jsonb_build_object(
                            'relationship_id', action_rel.id,
                            'kind', action_rel.kind,
                            'assertion_type', action_rel.assertion_type,
                            'confidence', action_rel.confidence,
                            'operation', action_rel.attributes->>'operation',
                            'target_id', target.id,
                            'target_kind', target.kind,
                            'target_natural_key', target.natural_key,
                            'target_name', target_view.display_name,
                            'execution_status', COALESCE(
                                action_rel.attributes->>'execution_status', 'not_observed'
                            )
                        ) ORDER BY action_rel.kind, target_view.display_name) AS items
                        FROM relationship_assertion action_rel
                        JOIN asset target ON target.id = action_rel.target_asset_id
                          AND target.tenant_id = action_rel.tenant_id
                        JOIN LATERAL (
                            SELECT aa.display_name
                            FROM asset_assertion aa
                            WHERE aa.tenant_id = target.tenant_id
                              AND aa.asset_id = target.id
                              AND aa.withdrawn_at IS NULL
                            ORDER BY {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC LIMIT 1
                        ) target_view ON true
                        WHERE action_rel.tenant_id = deployment.tenant_id
                          AND action_rel.source_asset_id = tool.id
                          AND action_rel.kind IN ('can_read', 'can_write', 'can_invoke')
                          AND action_rel.withdrawn_at IS NULL
                    ) actions ON true
                    WHERE tool_rel.tenant_id = deployment.tenant_id
                      AND tool_rel.source_asset_id = agent.agent_id
                      AND tool_rel.kind = 'can_invoke'
                      AND tool_rel.withdrawn_at IS NULL
                      AND tool.kind = 'ai_tool'
                ) tools ON true
                LEFT JOIN LATERAL (
                    SELECT jsonb_agg(selected.item ORDER BY
                        selected.source_rank, selected.display_name) AS items
                    FROM (
                        SELECT DISTINCT ON (model.id)
                            jsonb_build_object(
                                'id', model.id, 'natural_key', model.natural_key,
                                'display_name', model_view.display_name,
                                'assertion_type', rel.assertion_type,
                                'confidence', rel.confidence,
                                'relationship_source', CASE
                                    WHEN rel.source_asset_id = workload.id
                                        THEN 'workload'
                                    ELSE 'agent'
                                END
                            ) AS item,
                            CASE WHEN rel.source_asset_id = workload.id THEN 0 ELSE 1 END
                                AS source_rank,
                            model_view.display_name
                        FROM relationship_assertion rel
                        JOIN asset model ON model.id = rel.target_asset_id
                          AND model.tenant_id = rel.tenant_id
                        JOIN LATERAL (
                            SELECT aa.display_name FROM asset_assertion aa
                            WHERE aa.tenant_id = model.tenant_id
                              AND aa.asset_id = model.id
                              AND aa.withdrawn_at IS NULL
                            ORDER BY {_ASSERTION_RANK_SQL} DESC,
                                     aa.last_seen_at DESC LIMIT 1
                        ) model_view ON true
                        WHERE rel.tenant_id = deployment.tenant_id
                          AND rel.source_asset_id IN (workload.id, agent.agent_id)
                          AND rel.kind = 'uses'
                          AND rel.withdrawn_at IS NULL
                          AND model.kind = 'ai_model'
                        ORDER BY model.id,
                            CASE WHEN rel.source_asset_id = workload.id THEN 0 ELSE 1 END,
                            rel.confidence DESC
                    ) selected
                ) models ON true
                LEFT JOIN LATERAL (
                    SELECT jsonb_build_object(
                        'id', principal.id, 'natural_key', principal.natural_key,
                        'display_name', principal_view.display_name,
                        'assertion_type', rel.assertion_type,
                        'confidence', rel.confidence
                    ) AS item
                    FROM relationship_assertion rel
                    JOIN asset principal ON principal.id = rel.target_asset_id
                      AND principal.tenant_id = rel.tenant_id
                    JOIN LATERAL (
                        SELECT aa.display_name FROM asset_assertion aa
                        WHERE aa.tenant_id = principal.tenant_id AND aa.asset_id = principal.id
                          AND aa.withdrawn_at IS NULL
                        ORDER BY {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC LIMIT 1
                    ) principal_view ON true
                    WHERE rel.tenant_id = deployment.tenant_id
                      AND rel.source_asset_id = workload.id AND rel.kind = 'runs_as'
                      AND rel.withdrawn_at IS NULL AND principal.kind = 'identity'
                    ORDER BY rel.confidence DESC LIMIT 1
                ) identity ON true
                LEFT JOIN LATERAL (
                    SELECT jsonb_agg(jsonb_build_object(
                        'id', finding.id, 'title', finding.title,
                        'severity', finding.severity, 'rule_uid', finding.rule_uid,
                        'source_path', finding.attributes->>'source_path',
                        'source_line', finding.attributes->>'source_line',
                        'applicability', CASE
                            WHEN COALESCE(
                                deployment.attributes->'reachable_source_paths', '[]'::jsonb
                            ) ? (finding.attributes->>'source_path')
                            THEN 'artifact_included'
                            ELSE 'repository_only'
                        END,
                        'import_chain', deployment.attributes->'artifact_import_chains'
                            ->(finding.attributes->>'source_path')
                    ) ORDER BY
                        CASE
                            WHEN COALESCE(
                                deployment.attributes->'reachable_source_paths', '[]'::jsonb
                            ) ? (finding.attributes->>'source_path') THEN 0 ELSE 1
                        END,
                        finding.severity DESC, finding.title) AS items
                    FROM finding
                    WHERE finding.tenant_id = deployment.tenant_id
                      AND finding.state = 'open' AND finding.evaluation_result = 'fail'
                      AND finding.attributes->>'repository' = repository.natural_key
                ) code_findings ON true
                LEFT JOIN LATERAL (
                    SELECT scan.run_id AS scan_run_id,
                           CASE
                             WHEN workload_view.attributes->'deployment_artifact'
                                    IS NULL THEN 'not_evaluated'
                             WHEN scan.artifact_kind =
                                    workload_view.attributes->'deployment_artifact'->>'kind'
                              AND scan.artifact_locator = CASE
                                WHEN scan.artifact_kind = 'container_image'
                                  THEN workload_view.attributes
                                    ->'deployment_artifact'->>'image'
                                WHEN scan.artifact_kind = 's3_object'
                                  THEN concat(
                                    's3://',
                                    workload_view.attributes
                                      ->'deployment_artifact'->>'bucket', '/',
                                    workload_view.attributes
                                      ->'deployment_artifact'->>'key'
                                  )
                                ELSE NULL
                              END THEN 'matched'
                             WHEN scan.artifact_kind =
                                    workload_view.attributes->'deployment_artifact'->>'kind'
                              AND scan.artifact_digest IS NOT NULL
                              AND scan.artifact_digest =
                                    workload_view.attributes
                                      ->'deployment_artifact'->>'code_sha256'
                               THEN 'matched'
                             ELSE 'not_matched'
                           END AS artifact_identity_status,
                           jsonb_build_object(
                        'state', coverage.state,
                        'detail', coverage.detail,
                        'connector_id', coverage.connector_id,
                        'connection_id', coverage.connection_id,
                        'run_id', coverage.run_id,
                        'collected_at', coverage.collected_at,
                        'artifact_kind', scan.artifact_kind,
                        'artifact_locator', scan.artifact_locator,
                        'artifact_digest', scan.artifact_digest,
                        'artifact_identity_status', CASE
                          WHEN workload_view.attributes->'deployment_artifact'
                                 IS NULL THEN 'not_evaluated'
                          WHEN scan.artifact_kind =
                                 workload_view.attributes->'deployment_artifact'->>'kind'
                           AND scan.artifact_locator = CASE
                             WHEN scan.artifact_kind = 'container_image'
                               THEN workload_view.attributes
                                 ->'deployment_artifact'->>'image'
                             WHEN scan.artifact_kind = 's3_object'
                               THEN concat(
                                 's3://',
                                 workload_view.attributes
                                   ->'deployment_artifact'->>'bucket', '/',
                                 workload_view.attributes
                                   ->'deployment_artifact'->>'key'
                               )
                             ELSE NULL
                           END THEN 'matched'
                          WHEN scan.artifact_kind =
                                 workload_view.attributes->'deployment_artifact'->>'kind'
                           AND scan.artifact_digest IS NOT NULL
                           AND scan.artifact_digest =
                                 workload_view.attributes
                                   ->'deployment_artifact'->>'code_sha256'
                            THEN 'matched'
                          ELSE 'not_matched'
                        END,
                        'artifact_identity_method', CASE
                          WHEN scan.artifact_kind =
                                 workload_view.attributes->'deployment_artifact'->>'kind'
                           AND scan.artifact_locator = CASE
                             WHEN scan.artifact_kind = 'container_image'
                               THEN workload_view.attributes
                                 ->'deployment_artifact'->>'image'
                             WHEN scan.artifact_kind = 's3_object'
                               THEN concat(
                                 's3://',
                                 workload_view.attributes
                                   ->'deployment_artifact'->>'bucket', '/',
                                 workload_view.attributes
                                   ->'deployment_artifact'->>'key'
                               )
                             ELSE NULL
                           END THEN 'exact_locator'
                          WHEN scan.artifact_kind =
                                 workload_view.attributes->'deployment_artifact'->>'kind'
                           AND scan.artifact_digest IS NOT NULL
                           AND scan.artifact_digest =
                                 workload_view.attributes
                                   ->'deployment_artifact'->>'code_sha256'
                            THEN 'exact_digest'
                          ELSE NULL
                        END
                    ) AS item
                    FROM vulnerability_scan scan
                    JOIN collection_coverage coverage
                      ON coverage.tenant_id = scan.tenant_id
                     AND coverage.connector_id = scan.connector_id
                     AND coverage.connection_id = scan.connection_id
                     AND coverage.run_id = scan.run_id
                     AND coverage.plane = 'vulnerabilities'
                    WHERE scan.tenant_id = deployment.tenant_id
                      AND scan.target_kind = workload.kind
                      AND scan.target_natural_key = workload.natural_key
                    ORDER BY coverage.collected_at DESC, coverage.connector_id,
                             coverage.connection_id
                    LIMIT 1
                ) vulnerability_coverage ON true
                LEFT JOIN LATERAL (
                    SELECT count(DISTINCT vulnerability.id) AS total,
                           count(DISTINCT vulnerability.vulnerability_id)
                               AS vulnerability_ids
                    FROM vulnerability
                    JOIN vulnerability_observation observation
                      ON observation.tenant_id = vulnerability.tenant_id
                     AND observation.vulnerability_id = vulnerability.id
                     AND observation.withdrawn_at IS NULL
                     AND observation.last_observed_run_id =
                           vulnerability_coverage.scan_run_id
                    WHERE vulnerability.tenant_id = deployment.tenant_id
                      AND vulnerability.target_asset_id = workload.id
                      AND vulnerability.state = 'open'
                      AND vulnerability_coverage.artifact_identity_status = 'matched'
                ) artifact_vulnerability_summary ON true
                LEFT JOIN LATERAL (
                    SELECT jsonb_agg(jsonb_build_object(
                        'id', vulnerability.id,
                        'vulnerability_id', vulnerability.vulnerability_id,
                        'title', winner.title,
                        'severity', winner.severity,
                        'state', vulnerability.state,
                        'cvss_score', winner.cvss_score,
                        'fix_state', winner.fix_state,
                        'fixed_versions', winner.fixed_versions,
                        'exploit_state', winner.exploit_state,
                        'match_method', winner.match_method,
                        'match_confidence', winner.match_confidence,
                        'scanner', winner.connector_id,
                        'source_count', (
                            SELECT count(*)
                            FROM vulnerability_observation source_count
                            WHERE source_count.tenant_id = vulnerability.tenant_id
                              AND source_count.vulnerability_id = vulnerability.id
                              AND source_count.withdrawn_at IS NULL
                        ),
                        'component_id', component.id,
                        'component_name', component_view.display_name,
                        'component_purl',
                            component_view.attributes->'component'->>'purl'
                    ) ORDER BY
                        CASE winner.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                            WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                        vulnerability.vulnerability_id,
                        component_view.display_name) AS items
                    FROM vulnerability
                    JOIN LATERAL (
                        SELECT observation.*
                        FROM vulnerability_observation observation
                        WHERE observation.tenant_id = vulnerability.tenant_id
                          AND observation.vulnerability_id = vulnerability.id
                          AND observation.withdrawn_at IS NULL
                          AND observation.last_observed_run_id =
                                vulnerability_coverage.scan_run_id
                        ORDER BY observation.match_confidence DESC,
                                 observation.last_seen_at DESC,
                                 observation.connector_id,
                                 observation.connection_id
                        LIMIT 1
                    ) winner ON true
                    LEFT JOIN asset component
                      ON component.id = vulnerability.component_asset_id
                     AND component.tenant_id = vulnerability.tenant_id
                    LEFT JOIN LATERAL (
                        SELECT aa.display_name, aa.attributes
                        FROM asset_assertion aa
                        WHERE aa.tenant_id = component.tenant_id
                          AND aa.asset_id = component.id
                          AND aa.withdrawn_at IS NULL
                        ORDER BY {_ASSERTION_RANK_SQL} DESC,
                                 aa.last_seen_at DESC
                        LIMIT 1
                    ) component_view ON true
                    WHERE vulnerability.tenant_id = deployment.tenant_id
                      AND vulnerability.target_asset_id = workload.id
                      AND vulnerability.state = 'open'
                      AND vulnerability_coverage.artifact_identity_status = 'matched'
                      AND vulnerability.id IN (
                        SELECT candidate.id
                        FROM vulnerability candidate
                        JOIN vulnerability_observation candidate_observation
                          ON candidate_observation.tenant_id = candidate.tenant_id
                         AND candidate_observation.vulnerability_id = candidate.id
                         AND candidate_observation.withdrawn_at IS NULL
                         AND candidate_observation.last_observed_run_id =
                               vulnerability_coverage.scan_run_id
                        WHERE candidate.tenant_id = deployment.tenant_id
                          AND candidate.target_asset_id = workload.id
                          AND candidate.state = 'open'
                        ORDER BY CASE candidate_observation.severity
                            WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                            WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                            candidate.vulnerability_id,
                            candidate.component_natural_key
                        LIMIT 25
                      )
                ) artifact_vulnerabilities ON true
                WHERE deployment.tenant_id = %s::uuid
                  AND deployment.kind = 'deployed_by' AND deployment.withdrawn_at IS NULL
                  AND workload.kind = 'ai_workload' AND repository.kind = 'code_repository'
                  AND workload.lifecycle_state = 'active'
                  AND repository.lifecycle_state = 'active'
                ORDER BY repository_view.display_name, workload_view.display_name
                """,
                (tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def code_to_cloud_observations(self, tenant_id: str) -> list[dict[str, Any]]:
        """Return latest source-collection and correlation disposition per repository."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                WITH latest_source AS (
                  SELECT DISTINCT ON (connection_id, scope)
                         connection_id, scope, state, detail, run_id, collected_at
                  FROM collection_coverage
                  WHERE tenant_id = %s::uuid
                    AND connector_id = 'denali.github_repository'
                    AND plane = 'github_source_collection'
                  ORDER BY connection_id, scope, collected_at DESC
                ), latest_analysis AS (
                  SELECT DISTINCT ON (connection_id, scope)
                         connection_id, scope, state, detail, run_id, collected_at
                  FROM collection_coverage
                  WHERE tenant_id = %s::uuid
                    AND connector_id = 'denali.code_to_cloud'
                    AND plane = 'code_to_cloud_deployments'
                  ORDER BY connection_id, scope, collected_at DESC
                ), combined AS (
                  SELECT COALESCE(source.connection_id, analysis.connection_id) AS connection_id,
                         COALESCE(source.scope, analysis.scope) AS scope,
                         source.state AS source_state, source.detail AS source_detail,
                         source.run_id AS source_run_id,
                         source.collected_at AS source_collected_at,
                         analysis.state AS analysis_state,
                         analysis.detail AS analysis_detail,
                         analysis.run_id AS analysis_run_id,
                         analysis.collected_at AS analysis_collected_at
                  FROM latest_source source
                  FULL OUTER JOIN latest_analysis analysis
                    ON analysis.connection_id = source.connection_id
                   AND analysis.scope = source.scope
                )
                SELECT combined.*,
                       substring(combined.scope from 12) AS repository_natural_key,
                       asset.id AS repository_id,
                       assertion.display_name AS repository_name,
                       assertion.attributes->'correlation_summary' AS correlation_summary,
                       COALESCE(
                         assertion.attributes->'correlation_candidates', '[]'::jsonb
                       ) AS correlation_candidates,
                       assertion.evidence AS evidence
                FROM combined
                LEFT JOIN asset
                  ON asset.tenant_id = %s::uuid
                 AND asset.kind = 'code_repository'
                 AND asset.natural_key = substring(combined.scope from 12)
                LEFT JOIN asset_assertion assertion
                  ON assertion.tenant_id = asset.tenant_id
                 AND assertion.asset_id = asset.id
                 AND assertion.connector_id = 'denali.code_to_cloud'
                 AND assertion.connection_id = combined.connection_id
                 AND assertion.scope_key = combined.scope
                 AND assertion.coverage_plane = 'code_to_cloud_inventory'
                 AND assertion.last_observed_run_id = combined.analysis_run_id
                 AND assertion.withdrawn_at IS NULL
                ORDER BY GREATEST(
                           combined.source_collected_at,
                           combined.analysis_collected_at
                         ) DESC NULLS LAST,
                         repository_natural_key
                """,
                (tenant_id, tenant_id, tenant_id),
            ).fetchall()
        return [dict(row) for row in rows]

    def create_connection_validation_job(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        wait_for_credentials: bool,
        wait_for_healthy: bool,
    ) -> tuple[dict[str, Any], bool]:
        """Create one durable active validation job per tenant and connection."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            with connection.transaction():
                connection.execute(
                    """
                    UPDATE connection_validation_job
                    SET state = 'failed', completed_at = now(),
                        lease_expires_at = NULL,
                        error_summary = CASE
                          WHEN state = 'queued' THEN 'Validation dispatch timed out.'
                          ELSE 'Validation worker lease expired.'
                        END
                    WHERE tenant_id = %s::uuid AND connection_id = %s::uuid
                      AND (
                        (state = 'running' AND lease_expires_at < now())
                        OR (state = 'queued' AND created_at < now() - interval '30 minutes')
                      )
                    """,
                    (tenant_id, connection_id),
                )
                row = connection.execute(
                    """
                    INSERT INTO connection_validation_job
                      (tenant_id, connection_id, wait_for_credentials, wait_for_healthy)
                    VALUES (%s::uuid, %s::uuid, %s, %s)
                    ON CONFLICT (tenant_id, connection_id)
                      WHERE state IN ('queued', 'running')
                    DO NOTHING
                    RETURNING *
                    """,
                    (
                        tenant_id,
                        connection_id,
                        wait_for_credentials,
                        wait_for_healthy,
                    ),
                ).fetchone()
                if row is not None:
                    return dict(row), True
                active = connection.execute(
                    """
                    SELECT * FROM connection_validation_job
                    WHERE tenant_id = %s::uuid AND connection_id = %s::uuid
                      AND state IN ('queued', 'running')
                    ORDER BY created_at DESC LIMIT 1
                    """,
                    (tenant_id, connection_id),
                ).fetchone()
        if active is None:
            raise RuntimeError("unable to create or find the connection validation job")
        return dict(active), False

    def claim_connection_validation_job(
        self, job_id: str, *, lease_seconds: int
    ) -> dict[str, Any] | None:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            row = connection.execute(
                """
                UPDATE connection_validation_job
                SET state = 'running', started_at = COALESCE(started_at, now()),
                    attempt_count = attempt_count + 1,
                    lease_expires_at = now() + make_interval(secs => %s)
                WHERE id = %s::uuid
                  AND (
                    state = 'queued'
                    OR (state = 'running' AND lease_expires_at < now())
                  )
                RETURNING *
                """,
                (lease_seconds, job_id),
            ).fetchone()
        return None if row is None else dict(row)

    def set_connection_validation_call_id(self, job_id: str, call_id: str) -> None:
        with psycopg.connect(self._dsn) as connection:
            connection.execute(
                """
                UPDATE connection_validation_job SET modal_call_id = %s
                WHERE id = %s::uuid AND state IN ('queued', 'running')
                """,
                (call_id, job_id),
            )

    def complete_connection_validation_job(self, job_id: str) -> None:
        with psycopg.connect(self._dsn) as connection:
            connection.execute(
                """
                UPDATE connection_validation_job
                SET state = 'succeeded', completed_at = now(), lease_expires_at = NULL,
                    error_summary = NULL
                WHERE id = %s::uuid AND state = 'running'
                """,
                (job_id,),
            )

    def fail_connection_validation_job(self, job_id: str, summary: str) -> None:
        with psycopg.connect(self._dsn) as connection:
            connection.execute(
                """
                UPDATE connection_validation_job
                SET state = 'failed', completed_at = now(), lease_expires_at = NULL,
                    error_summary = %s
                WHERE id = %s::uuid AND state IN ('queued', 'running')
                """,
                (summary[:500], job_id),
            )

    def connection_validation_job_state(self, tenant_id: str, connection_id: str) -> str:
        with psycopg.connect(self._dsn) as connection:
            connection.execute(
                """
                UPDATE connection_validation_job
                SET state = 'failed', completed_at = now(), lease_expires_at = NULL,
                    error_summary = CASE
                      WHEN state = 'queued' THEN 'Validation dispatch timed out.'
                      ELSE 'Validation worker lease expired.'
                    END
                WHERE tenant_id = %s::uuid AND connection_id = %s::uuid
                  AND (
                    (state = 'running' AND lease_expires_at < now())
                    OR (state = 'queued' AND created_at < now() - interval '30 minutes')
                  )
                """,
                (tenant_id, connection_id),
            )
            row = connection.execute(
                """
                SELECT state FROM connection_validation_job
                WHERE tenant_id = %s::uuid AND connection_id = %s::uuid
                  AND state IN ('queued', 'running')
                ORDER BY created_at DESC LIMIT 1
                """,
                (tenant_id, connection_id),
            ).fetchone()
        return "running" if row is not None else "idle"

    def create_connection(
        self,
        tenant_id: str,
        *,
        connection_id: str,
        provider: str,
        display_name: str,
        credential_type: str,
        credential_reference: dict[str, Any],
        declared_scopes: list[str],
        coverage_plan: list[dict[str, Any]],
        configuration: dict[str, Any],
    ) -> dict[str, Any]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO provider_connection
                      (id, tenant_id, provider, display_name, credential_type,
                       credential_reference, declared_scopes, coverage_plan, configuration)
                    VALUES (%s::uuid, %s::uuid, %s, %s, %s, %s::jsonb, %s::jsonb,
                            %s::jsonb, %s::jsonb)
                    """,
                    (
                        connection_id,
                        tenant_id,
                        provider,
                        display_name,
                        credential_type,
                        json.dumps(credential_reference),
                        json.dumps(declared_scopes),
                        json.dumps(coverage_plan),
                        json.dumps(configuration),
                    ),
                )
            except psycopg.errors.UniqueViolation as error:
                raise ValueError("connection display name already exists") from error
        created = self.get_connection(tenant_id, connection_id)
        if created is None:
            raise RuntimeError("created connection was not found")
        return created

    def list_connections(self, tenant_id: str) -> list[dict[str, Any]]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT c.id, c.provider, c.display_name, c.lifecycle_state, c.health_state,
                       c.credential_type, c.credential_reference,
                       c.declared_scopes, c.coverage_plan, c.configuration,
                       c.created_at, c.updated_at, c.last_validated_at,
                       latest.validation AS last_validation
                FROM provider_connection c
                LEFT JOIN LATERAL (
                    SELECT jsonb_build_object(
                        'id', v.id,
                        'started_at', v.started_at,
                        'completed_at', v.completed_at,
                        'health_state', v.health_state,
                        'credential_state', v.credential_state,
                        'account_id_observed', v.account_id_observed,
                        'results', v.results,
                        'summary', v.summary
                    ) AS validation
                    FROM connection_validation v
                    WHERE v.tenant_id = c.tenant_id AND v.connection_id = c.id
                    ORDER BY v.completed_at DESC
                    LIMIT 1
                ) latest ON true
                WHERE c.tenant_id = %s::uuid
                ORDER BY c.lifecycle_state, c.display_name, c.id
                """,
                (tenant_id,),
            ).fetchall()
        return [_connection_response(row) for row in rows]

    def get_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            row = connection.execute(
                """
                SELECT c.id, c.provider, c.display_name, c.lifecycle_state, c.health_state,
                       c.credential_type, c.credential_reference,
                       c.declared_scopes, c.coverage_plan, c.configuration,
                       c.created_at, c.updated_at, c.last_validated_at,
                       latest.validation AS last_validation
                FROM provider_connection c
                LEFT JOIN LATERAL (
                    SELECT jsonb_build_object(
                        'id', v.id,
                        'started_at', v.started_at,
                        'completed_at', v.completed_at,
                        'health_state', v.health_state,
                        'credential_state', v.credential_state,
                        'account_id_observed', v.account_id_observed,
                        'results', v.results,
                        'summary', v.summary
                    ) AS validation
                    FROM connection_validation v
                    WHERE v.tenant_id = c.tenant_id AND v.connection_id = c.id
                    ORDER BY v.completed_at DESC
                    LIMIT 1
                ) latest ON true
                WHERE c.tenant_id = %s::uuid AND c.id = %s::uuid
                """,
                (tenant_id, connection_id),
            ).fetchone()
        return None if row is None else _connection_response(row)

    def get_connection_validation_target(
        self, tenant_id: str, connection_id: str
    ) -> dict[str, Any] | None:
        """Return internal validation material; callers must never serialize this row."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            row = connection.execute(
                """
                SELECT id, provider, display_name, lifecycle_state, credential_type,
                       credential_reference, declared_scopes, coverage_plan, configuration
                FROM provider_connection
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                """,
                (tenant_id, connection_id),
            ).fetchone()
        return None if row is None else dict(row)

    def record_connection_validation(
        self,
        tenant_id: str,
        connection_id: str,
        validation: dict[str, Any],
    ) -> dict[str, Any] | None:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            with connection.transaction():
                exists = connection.execute(
                    """
                    SELECT 1 FROM provider_connection
                    WHERE tenant_id = %s::uuid AND id = %s::uuid
                    FOR UPDATE
                    """,
                    (tenant_id, connection_id),
                ).fetchone()
                if exists is None:
                    return None
                connection.execute(
                    """
                    INSERT INTO connection_validation
                      (tenant_id, connection_id, started_at, completed_at, health_state,
                       credential_state, account_id_observed, results, summary)
                    VALUES (%s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s::jsonb, %s)
                    """,
                    (
                        tenant_id,
                        connection_id,
                        validation["started_at"],
                        validation["completed_at"],
                        validation["health_state"],
                        validation["credential_state"],
                        validation.get("account_id_observed"),
                        json.dumps(validation["results"]),
                        validation["summary"],
                    ),
                )
                connection.execute(
                    """
                    UPDATE provider_connection
                    SET health_state = %s, last_validated_at = %s, updated_at = %s
                    WHERE tenant_id = %s::uuid AND id = %s::uuid
                    """,
                    (
                        validation["health_state"],
                        validation["completed_at"],
                        validation["completed_at"],
                        tenant_id,
                        connection_id,
                    ),
                )
        return self.get_connection(tenant_id, connection_id)

    def record_connection_launch(
        self,
        tenant_id: str,
        connection_id: str,
        launch: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Record launch intent without retaining the S3 URL, object key, or external ID."""

        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """
                UPDATE provider_connection
                SET configuration = jsonb_set(
                        configuration,
                        '{onboarding}',
                        %s::jsonb,
                        true
                    ),
                    updated_at = now()
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                RETURNING id
                """,
                (json.dumps(launch), tenant_id, connection_id),
            ).fetchone()
        return None if row is None else self.get_connection(tenant_id, connection_id)

    def record_connection_setup_launch(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        launch: dict[str, Any],
        setup_token_sha256: str,
    ) -> dict[str, Any] | None:
        """Record a setup artifact and only the hash of its one-time completion token."""

        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """
                UPDATE provider_connection
                SET credential_reference = jsonb_set(
                        credential_reference,
                        '{setup_token_sha256}',
                        to_jsonb(%s::text),
                        true
                    ),
                    configuration = jsonb_set(
                        configuration,
                        '{onboarding}',
                        %s::jsonb,
                        true
                    ),
                    updated_at = now()
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                  AND provider = 'azure' AND lifecycle_state = 'active'
                RETURNING id
                """,
                (
                    setup_token_sha256,
                    json.dumps(launch),
                    tenant_id,
                    connection_id,
                ),
            ).fetchone()
        return None if row is None else self.get_connection(tenant_id, connection_id)

    def complete_azure_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_setup_token_sha256: str,
        service_principal_id: str,
        subscriptions: list[dict[str, str]],
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ) -> dict[str, Any] | None:
        """Bind the selected subscriptions and consume the setup completion capability."""

        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """
                UPDATE provider_connection
                SET credential_reference = jsonb_set(
                        credential_reference - 'setup_token_sha256',
                        '{service_principal_id}',
                        to_jsonb(%s::text),
                        true
                    ),
                    configuration = jsonb_set(
                        jsonb_set(
                            configuration,
                            '{subscriptions}',
                            %s::jsonb,
                            true
                        ),
                        '{onboarding,completed_at}',
                        to_jsonb(%s::text),
                        true
                    ),
                    coverage_plan = %s::jsonb,
                    health_state = 'unknown',
                    updated_at = %s
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                  AND provider = 'azure' AND lifecycle_state = 'active'
                  AND credential_reference->>'setup_token_sha256' = %s
                RETURNING id
                """,
                (
                    service_principal_id,
                    json.dumps(subscriptions),
                    completed_at.isoformat(),
                    json.dumps(coverage_plan),
                    completed_at,
                    tenant_id,
                    connection_id,
                    expected_setup_token_sha256,
                ),
            ).fetchone()
        return None if row is None else self.get_connection(tenant_id, connection_id)

    def record_gcp_connection_setup_launch(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        launch: dict[str, Any],
        setup_token_sha256: str,
    ) -> dict[str, Any] | None:
        """Record a GCP setup artifact and only the completion-token hash."""

        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """
                UPDATE provider_connection
                SET credential_reference = jsonb_set(
                        credential_reference,
                        '{setup_token_sha256}',
                        to_jsonb(%s::text),
                        true
                    ),
                    configuration = jsonb_set(
                        configuration,
                        '{onboarding}',
                        %s::jsonb,
                        true
                    ),
                    updated_at = now()
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                  AND provider = 'gcp' AND lifecycle_state = 'active'
                RETURNING id
                """,
                (
                    setup_token_sha256,
                    json.dumps(launch),
                    tenant_id,
                    connection_id,
                ),
            ).fetchone()
        return None if row is None else self.get_connection(tenant_id, connection_id)

    def complete_gcp_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_setup_token_sha256: str,
        projects: list[dict[str, str]],
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ) -> dict[str, Any] | None:
        """Bind selected GCP projects and consume the setup completion capability."""

        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """
                UPDATE provider_connection
                SET credential_reference = credential_reference - 'setup_token_sha256',
                    configuration = jsonb_set(
                        jsonb_set(
                            configuration,
                            '{projects}',
                            %s::jsonb,
                            true
                        ),
                        '{onboarding,completed_at}',
                        to_jsonb(%s::text),
                        true
                    ),
                    coverage_plan = %s::jsonb,
                    health_state = 'unknown',
                    updated_at = %s
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                  AND provider = 'gcp' AND lifecycle_state = 'active'
                  AND credential_reference->>'setup_token_sha256' = %s
                RETURNING id
                """,
                (
                    json.dumps(projects),
                    completed_at.isoformat(),
                    json.dumps(coverage_plan),
                    completed_at,
                    tenant_id,
                    connection_id,
                    expected_setup_token_sha256,
                ),
            ).fetchone()
        return None if row is None else self.get_connection(tenant_id, connection_id)

    def record_github_install_launch(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        launch: dict[str, Any],
        state_sha256: str,
    ) -> dict[str, Any] | None:
        """Record only the hash of the one-time GitHub installation state."""

        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """
                UPDATE provider_connection
                SET credential_reference = jsonb_set(
                        credential_reference,
                        '{install_state_sha256}',
                        to_jsonb(%s::text),
                        true
                    ),
                    configuration = jsonb_set(
                        configuration, '{onboarding}', %s::jsonb, true
                    ),
                    updated_at = now()
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                  AND provider = 'github' AND lifecycle_state = 'active'
                RETURNING id
                """,
                (state_sha256, json.dumps(launch), tenant_id, connection_id),
            ).fetchone()
        return None if row is None else self.get_connection(tenant_id, connection_id)

    def record_github_install_return(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_install_state_sha256: str,
        installation_id: int,
        oauth: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Consume install state and stage short-lived OAuth/PKCE verifier state."""

        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """
                UPDATE provider_connection
                SET credential_reference =
                      jsonb_set(
                        jsonb_set(
                          jsonb_set(
                            credential_reference - 'install_state_sha256',
                            '{installation_id}', to_jsonb(%s::bigint), true
                          ),
                          '{oauth_state_sha256}', to_jsonb(%s::text), true
                        ),
                        '{pkce_verifier}', to_jsonb(%s::text), true
                      ),
                    configuration = jsonb_set(
                      jsonb_set(
                        configuration,
                        '{onboarding,installation_id}', to_jsonb(%s::bigint), true
                      ),
                      '{onboarding,oauth_expires_at}', to_jsonb(%s::text), true
                    ),
                    updated_at = now()
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                  AND provider = 'github' AND lifecycle_state = 'active'
                  AND credential_reference->>'install_state_sha256' = %s
                RETURNING id
                """,
                (
                    installation_id,
                    oauth["state_sha256"],
                    oauth["pkce_verifier"],
                    installation_id,
                    oauth["expires_at"],
                    tenant_id,
                    connection_id,
                    expected_install_state_sha256,
                ),
            ).fetchone()
        return None if row is None else self.get_connection(tenant_id, connection_id)

    def complete_github_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_oauth_state_sha256: str,
        installation: dict[str, Any],
        installer: dict[str, Any],
        repositories: list[dict[str, Any]],
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ) -> dict[str, Any] | None:
        """Bind verified installation repositories and discard transient user auth state."""

        configuration_patch = {
            "account_id": installation["account_id"],
            "account_login": installation["account_login"],
            "account_type": installation["account_type"],
            "installation_repository_selection": installation["repository_selection"],
            "repositories": repositories,
            "installer": installer,
        }
        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """
                UPDATE provider_connection
                SET credential_reference =
                      credential_reference - 'oauth_state_sha256' - 'pkce_verifier',
                    configuration =
                      jsonb_set(
                        configuration || %s::jsonb,
                        '{onboarding,completed_at}', to_jsonb(%s::text), true
                      ),
                    coverage_plan = %s::jsonb,
                    health_state = 'unknown',
                    updated_at = %s
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                  AND provider = 'github' AND lifecycle_state = 'active'
                  AND credential_reference->>'oauth_state_sha256' = %s
                RETURNING id
                """,
                (
                    json.dumps(configuration_patch),
                    completed_at.isoformat(),
                    json.dumps(coverage_plan),
                    completed_at,
                    tenant_id,
                    connection_id,
                    expected_oauth_state_sha256,
                ),
            ).fetchone()
        return None if row is None else self.get_connection(tenant_id, connection_id)

    def disable_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None:
        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """
                UPDATE provider_connection
                SET lifecycle_state = 'disabled', health_state = 'disabled', updated_at = now()
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                RETURNING id
                """,
                (tenant_id, connection_id),
            ).fetchone()
        return None if row is None else self.get_connection(tenant_id, connection_id)

    def delete_connection(self, tenant_id: str, connection_id: str) -> str:
        """Delete only disabled configuration; collected evidence remains untouched."""

        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            row = connection.execute(
                """
                SELECT lifecycle_state FROM provider_connection
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                FOR UPDATE
                """,
                (tenant_id, connection_id),
            ).fetchone()
            if row is None:
                return "not_found"
            if row["lifecycle_state"] != "disabled":
                return "active"
            connection.execute(
                """
                DELETE FROM provider_connection
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                """,
                (tenant_id, connection_id),
            )
        return "deleted"

    def list_assets(
        self,
        tenant_id: str,
        *,
        kind: str | None = None,
        lifecycle: str = "active",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        query = f"""
        SELECT a.id, a.kind, a.natural_key, a.governance_status, a.lifecycle_state,
               a.owner, a.first_seen_at, a.last_seen_at, a.last_changed_at,
               winner.display_name, winner.attributes, winner.assertion_type,
               winner.confidence, winner.connector_id, winner.connection_id
        FROM asset a
        LEFT JOIN LATERAL (
            SELECT aa.display_name, aa.attributes, aa.assertion_type, aa.confidence,
                   aa.connector_id, aa.connection_id
            FROM asset_assertion aa
            WHERE aa.tenant_id = a.tenant_id AND aa.asset_id = a.id
              AND aa.withdrawn_at IS NULL
            ORDER BY {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC,
                     aa.connector_id, aa.connection_id
            LIMIT 1
        ) winner ON true
        WHERE a.tenant_id = %s::uuid
          AND (%s::text IS NULL OR a.kind = %s::text)
          AND (%s::text IS NULL OR a.lifecycle_state = %s::text)
        ORDER BY COALESCE(winner.display_name, a.natural_key), a.kind, a.natural_key
        LIMIT %s OFFSET %s
        """
        lifecycle_filter = lifecycle or None
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                query,
                (tenant_id, kind, kind, lifecycle_filter, lifecycle_filter, limit, offset),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_asset(self, tenant_id: str, asset_id: str) -> dict[str, Any] | None:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            asset = connection.execute(
                "SELECT * FROM asset WHERE tenant_id = %s::uuid AND id = %s::uuid",
                (tenant_id, asset_id),
            ).fetchone()
            if asset is None:
                return None
            assertions = connection.execute(
                """
                SELECT connector_id, connection_id, scope_key, coverage_plane,
                       assertion_type, confidence, display_name, attributes, evidence,
                       lifecycle_state, first_seen_at, last_seen_at, withdrawn_at
                FROM asset_assertion
                WHERE tenant_id = %s::uuid AND asset_id = %s::uuid
                ORDER BY withdrawn_at NULLS FIRST, last_seen_at DESC
                """,
                (tenant_id, asset_id),
            ).fetchall()
            relationships = connection.execute(
                """
                SELECT r.id, r.kind, r.category, r.assertion_type, r.confidence,
                       r.attributes, r.evidence, r.withdrawn_at,
                       s.id AS source_id, s.kind AS source_kind,
                       s.natural_key AS source_natural_key,
                       t.id AS target_id, t.kind AS target_kind,
                       t.natural_key AS target_natural_key
                FROM relationship_assertion r
                JOIN asset s ON s.id = r.source_asset_id
                JOIN asset t ON t.id = r.target_asset_id
                WHERE r.tenant_id = %s::uuid
                  AND (r.source_asset_id = %s::uuid OR r.target_asset_id = %s::uuid)
                ORDER BY r.withdrawn_at NULLS FIRST, r.kind, s.natural_key, t.natural_key
                """,
                (tenant_id, asset_id, asset_id),
            ).fetchall()
        result = dict(asset)
        result["assertions"] = [dict(row) for row in assertions]
        result["relationships"] = [dict(row) for row in relationships]
        return result

    def summary(self, tenant_id: str) -> dict[str, Any]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            by_kind = connection.execute(
                """
                SELECT kind, count(*) AS count
                FROM asset
                WHERE tenant_id = %s::uuid AND lifecycle_state = 'active'
                GROUP BY kind ORDER BY kind
                """,
                (tenant_id,),
            ).fetchall()
            governance = connection.execute(
                """
                SELECT governance_status, count(*) AS count
                FROM asset
                WHERE tenant_id = %s::uuid AND lifecycle_state = 'active'
                GROUP BY governance_status ORDER BY governance_status
                """,
                (tenant_id,),
            ).fetchall()
        return {
            "total": sum(row["count"] for row in by_kind),
            "by_kind": {row["kind"]: row["count"] for row in by_kind},
            "by_governance": {row["governance_status"]: row["count"] for row in governance},
        }

    def latest_coverage(self, tenant_id: str) -> list[dict[str, Any]]:
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT ON (connector_id, connection_id, plane, scope)
                       connector_id, connection_id, plane, scope, state, detail,
                       run_id, collected_at
                FROM collection_coverage
                WHERE tenant_id = %s::uuid
                ORDER BY connector_id, connection_id, plane, scope, collected_at DESC
                """,
                (tenant_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def set_governance(
        self,
        tenant_id: str,
        asset_id: str,
        *,
        status: str,
        owner: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:
        if status not in {"approved", "unreviewed", "unwanted"}:
            raise ValueError("unsupported governance status")
        with psycopg.connect(self._dsn, row_factory=dict_row) as connection:
            row = connection.execute(
                """
                UPDATE asset
                SET governance_status = %s, owner = %s, notes = %s
                WHERE tenant_id = %s::uuid AND id = %s::uuid
                RETURNING id, governance_status, owner, notes
                """,
                (status, owner, notes, tenant_id, asset_id),
            ).fetchone()
        return None if row is None else dict(row)

    @staticmethod
    def _detection_coverage_state(
        connection, tenant_id: str, planes: tuple[str, ...]
    ) -> CoverageState:
        rows = connection.execute(
            """
            WITH latest AS (
              SELECT DISTINCT ON (connector_id, connection_id, plane, scope)
                     plane, state
              FROM collection_coverage
              WHERE tenant_id = %s::uuid AND plane = ANY(%s::text[])
              ORDER BY connector_id, connection_id, plane, scope, collected_at DESC
            )
            SELECT plane, array_agg(state ORDER BY state) AS states
            FROM latest GROUP BY plane
            """,
            (tenant_id, list(planes)),
        ).fetchall()
        states_by_plane = {row["plane"]: set(row["states"]) for row in rows}
        if any(plane not in states_by_plane for plane in planes):
            return CoverageState.UNKNOWN
        states = set().union(*(states_by_plane[plane] for plane in planes))
        if states == {CoverageState.COMPLETE.value}:
            return CoverageState.COMPLETE
        if states and states <= {CoverageState.FAILED.value}:
            return CoverageState.FAILED
        if states and states <= {CoverageState.NOT_SUPPORTED.value}:
            return CoverageState.NOT_SUPPORTED
        if CoverageState.FAILED.value in states or CoverageState.PARTIAL.value in states:
            return CoverageState.PARTIAL
        return CoverageState.UNKNOWN

    @classmethod
    def _cross_signal_issue_coverage_state(
        cls, connection, tenant_id: str
    ) -> CoverageState:
        """Combine sign-in collection coverage with consent-rule evaluation coverage."""

        sign_in_state = cls._detection_coverage_state(
            connection, tenant_id, ("entra_ai_signins",)
        )
        row = connection.execute(
            """
            SELECT state
            FROM runtime_detection_rule_evaluation
            WHERE tenant_id = %s::uuid
              AND rule_uid = 'DENALI-RUNTIME-ENTRA-CONSENT-001'
            """,
            (tenant_id,),
        ).fetchone()
        consent_state = CoverageState.UNKNOWN if row is None else CoverageState(row["state"])
        states = {sign_in_state, consent_state}
        if states == {CoverageState.COMPLETE}:
            return CoverageState.COMPLETE
        if states == {CoverageState.FAILED}:
            return CoverageState.FAILED
        if states == {CoverageState.NOT_SUPPORTED}:
            return CoverageState.NOT_SUPPORTED
        if CoverageState.FAILED in states or CoverageState.PARTIAL in states:
            return CoverageState.PARTIAL
        return CoverageState.UNKNOWN

    @staticmethod
    def _load_correlation_runtime_detections(
        connection, tenant_id: str
    ) -> tuple[CorrelationRuntimeDetection, ...]:
        rows = connection.execute(
            """
            SELECT id, rule_uid, title, severity, state, confidence,
                   first_seen_at, last_seen_at, attributes
            FROM runtime_detection
            WHERE tenant_id = %s::uuid
            ORDER BY last_seen_at, id
            """,
            (tenant_id,),
        ).fetchall()
        activity_rows = connection.execute(
            """
            SELECT detection_id, activity_id
            FROM runtime_detection_activity
            WHERE tenant_id = %s::uuid
            ORDER BY detection_id, activity_id
            """,
            (tenant_id,),
        ).fetchall()
        asset_rows = connection.execute(
            """
            SELECT detection_id, asset_id
            FROM runtime_detection_asset
            WHERE tenant_id = %s::uuid
            ORDER BY detection_id, asset_id
            """,
            (tenant_id,),
        ).fetchall()
        activity_ids: dict[str, list[str]] = {}
        for row in activity_rows:
            activity_ids.setdefault(str(row["detection_id"]), []).append(
                str(row["activity_id"])
            )
        asset_ids: dict[str, list[str]] = {}
        for row in asset_rows:
            asset_ids.setdefault(str(row["detection_id"]), []).append(str(row["asset_id"]))
        return tuple(
            CorrelationRuntimeDetection(
                id=str(row["id"]),
                rule_uid=row["rule_uid"],
                title=row["title"],
                severity=FindingSeverity(row["severity"]),
                state=row["state"],
                confidence=row["confidence"],
                first_seen_at=row["first_seen_at"],
                last_seen_at=row["last_seen_at"],
                activity_ids=tuple(activity_ids.get(str(row["id"]), ())),
                asset_ids=tuple(asset_ids.get(str(row["id"]), ())),
                attributes=dict(row["attributes"]),
            )
            for row in rows
        )

    @staticmethod
    def _load_detection_snapshot(connection, tenant_id: str) -> DetectionSnapshot:
        asset_rows = connection.execute(
            f"""
            SELECT asset.id, asset.kind, asset.natural_key, asset.governance_status,
                   asset.lifecycle_state, winner.display_name, winner.attributes
            FROM asset
            JOIN LATERAL (
                SELECT aa.display_name, aa.attributes
                FROM asset_assertion aa
                WHERE aa.tenant_id = asset.tenant_id
                  AND aa.asset_id = asset.id
                  AND aa.withdrawn_at IS NULL
                ORDER BY {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC,
                         aa.connector_id, aa.connection_id
                LIMIT 1
            ) winner ON true
            WHERE asset.tenant_id = %s::uuid AND asset.lifecycle_state = 'active'
            """,
            (tenant_id,),
        ).fetchall()
        activity_rows = connection.execute(
            """
            SELECT id, category, outcome, title, occurred_at, trace_uid,
                   attributes, evidence
            FROM activity_event
            WHERE tenant_id = %s::uuid
              AND category IN ('ai_app_sign_in', 'admin_change', 'model_invocation')
              AND attributes->>'fixture' IS DISTINCT FROM 'true'
            ORDER BY occurred_at, id
            """,
            (tenant_id,),
        ).fetchall()
        entity_rows = connection.execute(
            """
            SELECT entity.activity_id, entity.role, entity.external_uid,
                   entity.display_name, entity.asset_id
            FROM activity_entity entity
            JOIN activity_event event
              ON event.tenant_id = entity.tenant_id AND event.id = entity.activity_id
            WHERE entity.tenant_id = %s::uuid
              AND event.category IN ('ai_app_sign_in', 'admin_change', 'model_invocation')
              AND event.attributes->>'fixture' IS DISTINCT FROM 'true'
            ORDER BY entity.activity_id, entity.position
            """,
            (tenant_id,),
        ).fetchall()
        entities: dict[str, list[DetectionActivityEntity]] = {}
        for row in entity_rows:
            entities.setdefault(str(row["activity_id"]), []).append(
                DetectionActivityEntity(
                    role=row["role"],
                    external_uid=row["external_uid"],
                    display_name=row["display_name"],
                    asset_id=str(row["asset_id"]) if row["asset_id"] else None,
                )
            )
        return DetectionSnapshot(
            activities=tuple(
                DetectionActivity(
                    id=str(row["id"]),
                    category=row["category"],
                    outcome=row["outcome"],
                    title=row["title"],
                    occurred_at=row["occurred_at"],
                    trace_uid=row["trace_uid"],
                    attributes=dict(row["attributes"]),
                    evidence=dict(row["evidence"]),
                    entities=tuple(entities.get(str(row["id"]), ())),
                )
                for row in activity_rows
            ),
            assets=tuple(
                DetectionAsset(
                    id=str(row["id"]),
                    kind=row["kind"],
                    natural_key=row["natural_key"],
                    display_name=row["display_name"],
                    governance_status=row["governance_status"],
                    lifecycle_state=row["lifecycle_state"],
                    attributes=dict(row["attributes"]),
                )
                for row in asset_rows
            ),
        )

    @staticmethod
    def _upsert_runtime_detection(
        connection,
        tenant_id: str,
        candidate: RuntimeDetectionCandidate,
        evaluation: RuntimeDetectionEvaluation,
    ) -> str:
        row = connection.execute(
            """
            INSERT INTO runtime_detection
              (tenant_id, correlation_key, rule_uid, title, description, risk,
               investigation_guidance, severity, state, confidence, attributes,
               resolution_reason, first_seen_at, last_seen_at, last_changed_at,
               last_evaluated_at)
            VALUES
              (%s::uuid, %s, %s, %s, %s, %s, %s, %s, 'open', %s, %s::jsonb,
               NULL, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, correlation_key)
            DO UPDATE SET
              last_changed_at = CASE WHEN
                (runtime_detection.rule_uid, runtime_detection.title,
                 runtime_detection.description, runtime_detection.risk,
                 runtime_detection.investigation_guidance, runtime_detection.severity,
                 runtime_detection.state, runtime_detection.confidence,
                 runtime_detection.attributes)
                IS DISTINCT FROM
                (EXCLUDED.rule_uid, EXCLUDED.title, EXCLUDED.description, EXCLUDED.risk,
                 EXCLUDED.investigation_guidance, EXCLUDED.severity, EXCLUDED.state,
                 EXCLUDED.confidence, EXCLUDED.attributes)
                THEN EXCLUDED.last_seen_at ELSE runtime_detection.last_changed_at END,
              rule_uid = EXCLUDED.rule_uid,
              title = EXCLUDED.title,
              description = EXCLUDED.description,
              risk = EXCLUDED.risk,
              investigation_guidance = EXCLUDED.investigation_guidance,
              severity = EXCLUDED.severity,
              state = 'open',
              confidence = EXCLUDED.confidence,
              attributes = EXCLUDED.attributes,
              resolution_reason = NULL,
              first_seen_at = LEAST(runtime_detection.first_seen_at, EXCLUDED.first_seen_at),
              last_seen_at = GREATEST(runtime_detection.last_seen_at, EXCLUDED.last_seen_at),
              last_evaluated_at = EXCLUDED.last_evaluated_at
            RETURNING id
            """,
            (
                tenant_id,
                candidate.correlation_key,
                candidate.rule_uid,
                candidate.title,
                candidate.description,
                candidate.risk,
                candidate.investigation_guidance,
                candidate.severity.value,
                candidate.confidence,
                json.dumps(dict(candidate.attributes)),
                candidate.first_seen_at,
                candidate.last_seen_at,
                evaluation.evaluated_at,
                evaluation.evaluated_at,
            ),
        ).fetchone()
        return str(row["id"])

    @staticmethod
    def _replace_runtime_detection_evidence(
        connection,
        tenant_id: str,
        detection_id: str,
        candidate: RuntimeDetectionCandidate,
    ) -> None:
        connection.execute(
            """
            DELETE FROM runtime_detection_activity
            WHERE tenant_id = %s::uuid AND detection_id = %s::uuid
            """,
            (tenant_id, detection_id),
        )
        connection.execute(
            """
            DELETE FROM runtime_detection_asset
            WHERE tenant_id = %s::uuid AND detection_id = %s::uuid
            """,
            (tenant_id, detection_id),
        )
        for activity in candidate.activities:
            connection.execute(
                """
                INSERT INTO runtime_detection_activity
                  (tenant_id, detection_id, activity_id, role)
                VALUES (%s::uuid, %s::uuid, %s::uuid, %s)
                """,
                (tenant_id, detection_id, activity.activity_id, activity.role),
            )
        for asset in candidate.assets:
            connection.execute(
                """
                INSERT INTO runtime_detection_asset
                  (tenant_id, detection_id, asset_id, role)
                VALUES (%s::uuid, %s::uuid, %s::uuid, %s)
                """,
                (tenant_id, detection_id, asset.asset_id, asset.role),
            )

    @staticmethod
    def _load_correlation_snapshot(connection, tenant_id: str) -> CorrelationSnapshot:
        asset_rows = connection.execute(
            f"""
            SELECT a.id, a.kind, a.natural_key, a.governance_status,
                   a.lifecycle_state, winner.display_name,
                   winner.assertion_type, winner.confidence, winner.attributes
            FROM asset a
            JOIN LATERAL (
                SELECT aa.display_name, aa.assertion_type, aa.confidence, aa.attributes
                FROM asset_assertion aa
                WHERE aa.tenant_id = a.tenant_id AND aa.asset_id = a.id
                  AND aa.withdrawn_at IS NULL
                ORDER BY {_ASSERTION_RANK_SQL} DESC, aa.last_seen_at DESC,
                         aa.connector_id, aa.connection_id
                LIMIT 1
            ) winner ON true
            WHERE a.tenant_id = %s::uuid AND a.lifecycle_state = 'active'
            """,
            (tenant_id,),
        ).fetchall()
        relationship_rows = connection.execute(
            """
            SELECT r.id, r.source_asset_id, r.target_asset_id, r.kind, r.category,
                   r.assertion_type, r.confidence, r.attributes
            FROM relationship_assertion r
            JOIN asset source ON source.id = r.source_asset_id
            JOIN asset target ON target.id = r.target_asset_id
            WHERE r.tenant_id = %s::uuid AND r.withdrawn_at IS NULL
              AND source.lifecycle_state = 'active' AND target.lifecycle_state = 'active'
            """,
            (tenant_id,),
        ).fetchall()
        finding_rows = connection.execute(
            """
            SELECT id, source_uid, rule_uid, title, severity, state,
                   evaluation_result, attributes
            FROM finding
            WHERE tenant_id = %s::uuid
            """,
            (tenant_id,),
        ).fetchall()
        resource_rows = connection.execute(
            """
            SELECT finding_id, resource_uid
            FROM finding_resource
            WHERE tenant_id = %s::uuid ORDER BY finding_id, resource_uid
            """,
            (tenant_id,),
        ).fetchall()
        resources: dict[str, list[str]] = {}
        for row in resource_rows:
            resources.setdefault(str(row["finding_id"]), []).append(row["resource_uid"])
        return CorrelationSnapshot(
            assets=tuple(
                CorrelationAsset(
                    id=str(row["id"]),
                    kind=row["kind"],
                    natural_key=row["natural_key"],
                    display_name=row["display_name"],
                    assertion_type=row["assertion_type"],
                    confidence=row["confidence"],
                    attributes={
                        **dict(row["attributes"]),
                        "governance_status": row["governance_status"],
                        "lifecycle_state": row["lifecycle_state"],
                    },
                )
                for row in asset_rows
            ),
            relationships=tuple(
                CorrelationRelationship(
                    id=str(row["id"]),
                    source_id=str(row["source_asset_id"]),
                    target_id=str(row["target_asset_id"]),
                    kind=row["kind"],
                    category=row["category"],
                    assertion_type=row["assertion_type"],
                    confidence=row["confidence"],
                    attributes=dict(row["attributes"]),
                )
                for row in relationship_rows
            ),
            findings=tuple(
                CorrelationFinding(
                    id=str(row["id"]),
                    source_uid=row["source_uid"],
                    rule_uid=row["rule_uid"],
                    title=row["title"],
                    severity=FindingSeverity(row["severity"]),
                    state=row["state"],
                    evaluation_result=row["evaluation_result"],
                    resource_uids=tuple(resources.get(str(row["id"]), ())),
                    attributes=dict(row["attributes"]),
                )
                for row in finding_rows
            ),
        )

    @staticmethod
    def _upsert_issue(
        connection,
        tenant_id: str,
        candidate: IssueCandidate,
        evaluation: IssueEvaluation,
    ) -> str:
        row = connection.execute(
            """
            INSERT INTO issue
              (tenant_id, correlation_key, rule_uid, title, description, risk,
               remediation, severity, state, confidence, attributes, resolution_reason,
               first_seen_at, last_seen_at, last_changed_at, last_evaluated_at)
            VALUES
              (%s::uuid, %s, %s, %s, %s, %s, %s, %s, 'open', %s, %s::jsonb, NULL,
               %s, %s, %s, %s)
            ON CONFLICT (tenant_id, correlation_key)
            DO UPDATE SET
              last_changed_at = CASE WHEN
                (issue.rule_uid, issue.title, issue.description, issue.risk,
                 issue.remediation, issue.severity, issue.state, issue.confidence,
                 issue.attributes)
                IS DISTINCT FROM
                (EXCLUDED.rule_uid, EXCLUDED.title, EXCLUDED.description, EXCLUDED.risk,
                 EXCLUDED.remediation, EXCLUDED.severity, EXCLUDED.state,
                 EXCLUDED.confidence, EXCLUDED.attributes)
                THEN EXCLUDED.last_seen_at ELSE issue.last_changed_at END,
              rule_uid = EXCLUDED.rule_uid,
              title = EXCLUDED.title,
              description = EXCLUDED.description,
              risk = EXCLUDED.risk,
              remediation = EXCLUDED.remediation,
              severity = EXCLUDED.severity,
              state = 'open',
              confidence = EXCLUDED.confidence,
              attributes = EXCLUDED.attributes,
              resolution_reason = NULL,
              last_seen_at = EXCLUDED.last_seen_at,
              last_evaluated_at = EXCLUDED.last_evaluated_at
            RETURNING id
            """,
            (
                tenant_id,
                candidate.correlation_key,
                candidate.rule_uid,
                candidate.title,
                candidate.description,
                candidate.risk,
                candidate.remediation,
                candidate.severity.value,
                candidate.confidence,
                json.dumps(dict(candidate.attributes)),
                evaluation.evaluated_at,
                evaluation.evaluated_at,
                evaluation.evaluated_at,
                evaluation.evaluated_at,
            ),
        ).fetchone()
        return str(row["id"])

    @staticmethod
    def _replace_issue_components(
        connection,
        tenant_id: str,
        issue_id: str,
        candidate: IssueCandidate,
    ) -> None:
        connection.execute(
            "DELETE FROM issue_finding WHERE tenant_id = %s::uuid AND issue_id = %s::uuid",
            (tenant_id, issue_id),
        )
        connection.execute(
            "DELETE FROM issue_path_edge WHERE tenant_id = %s::uuid AND issue_id = %s::uuid",
            (tenant_id, issue_id),
        )
        connection.execute(
            "DELETE FROM issue_path_node WHERE tenant_id = %s::uuid AND issue_id = %s::uuid",
            (tenant_id, issue_id),
        )
        connection.execute(
            "DELETE FROM issue_detection WHERE tenant_id = %s::uuid AND issue_id = %s::uuid",
            (tenant_id, issue_id),
        )
        connection.execute(
            "DELETE FROM issue_activity WHERE tenant_id = %s::uuid AND issue_id = %s::uuid",
            (tenant_id, issue_id),
        )
        for finding in candidate.findings:
            connection.execute(
                """
                INSERT INTO issue_finding (tenant_id, issue_id, finding_id, role)
                VALUES (%s::uuid, %s::uuid, %s::uuid, %s)
                """,
                (tenant_id, issue_id, finding.finding_id, finding.role),
            )
        for node in candidate.path_nodes:
            connection.execute(
                """
                INSERT INTO issue_path_node (tenant_id, issue_id, position, asset_id, role)
                VALUES (%s::uuid, %s::uuid, %s, %s::uuid, %s)
                """,
                (tenant_id, issue_id, node.position, node.asset_id, node.role),
            )
        for edge in candidate.path_edges:
            connection.execute(
                """
                INSERT INTO issue_path_edge
                  (tenant_id, issue_id, position, relationship_id)
                VALUES (%s::uuid, %s::uuid, %s, %s::uuid)
                """,
                (tenant_id, issue_id, edge.position, edge.relationship_id),
            )
        for detection in candidate.detections:
            connection.execute(
                """
                INSERT INTO issue_detection (tenant_id, issue_id, detection_id, role)
                VALUES (%s::uuid, %s::uuid, %s::uuid, %s)
                """,
                (tenant_id, issue_id, detection.detection_id, detection.role),
            )
        for activity in candidate.activities:
            connection.execute(
                """
                INSERT INTO issue_activity (tenant_id, issue_id, activity_id, role)
                VALUES (%s::uuid, %s::uuid, %s::uuid, %s)
                """,
                (tenant_id, issue_id, activity.activity_id, activity.role),
            )

    @staticmethod
    def _finding_exists(
        connection,
        tenant_id: str,
        batch: FindingBatch,
        finding: FindingAssertion,
    ) -> bool:
        return (
            connection.execute(
                """
                SELECT 1 FROM finding
                WHERE tenant_id = %s::uuid AND connector_id = %s
                  AND connection_id = %s AND source_uid = %s
                """,
                (
                    tenant_id,
                    batch.connector_id,
                    batch.connection_id,
                    finding.source_uid,
                ),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _upsert_finding(
        connection,
        tenant_id: str,
        batch: FindingBatch,
        finding: FindingAssertion,
    ) -> str:
        evidence = _evidence_json(finding.evidence)
        resolution_reason = "source_status" if finding.state.value == "resolved" else None
        row = connection.execute(
            """
            INSERT INTO finding
              (tenant_id, connector_id, connection_id, scope_key, source_uid, rule_uid,
               title, description, risk, remediation, remediation_references, severity,
               state, evaluation_result, class_uid, class_name, source_observed_at,
               evidence, attributes, resolution_reason, first_seen_at, last_seen_at,
               last_changed_at, last_observed_run_id)
            VALUES
              (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s,
               %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, connector_id, connection_id, source_uid)
            DO UPDATE SET
              last_changed_at = CASE WHEN
                (finding.scope_key, finding.rule_uid, finding.title, finding.description,
                 finding.risk, finding.remediation, finding.remediation_references,
                 finding.severity, finding.state, finding.evaluation_result,
                 finding.class_uid, finding.class_name, finding.attributes)
                IS DISTINCT FROM
                (EXCLUDED.scope_key, EXCLUDED.rule_uid, EXCLUDED.title,
                 EXCLUDED.description, EXCLUDED.risk, EXCLUDED.remediation,
                 EXCLUDED.remediation_references, EXCLUDED.severity, EXCLUDED.state,
                 EXCLUDED.evaluation_result, EXCLUDED.class_uid, EXCLUDED.class_name,
                 EXCLUDED.attributes)
                THEN EXCLUDED.last_seen_at ELSE finding.last_changed_at END,
              scope_key = EXCLUDED.scope_key,
              rule_uid = EXCLUDED.rule_uid,
              title = EXCLUDED.title,
              description = EXCLUDED.description,
              risk = EXCLUDED.risk,
              remediation = EXCLUDED.remediation,
              remediation_references = EXCLUDED.remediation_references,
              severity = EXCLUDED.severity,
              state = EXCLUDED.state,
              evaluation_result = EXCLUDED.evaluation_result,
              class_uid = EXCLUDED.class_uid,
              class_name = EXCLUDED.class_name,
              source_observed_at = EXCLUDED.source_observed_at,
              evidence = EXCLUDED.evidence,
              attributes = EXCLUDED.attributes,
              resolution_reason = EXCLUDED.resolution_reason,
              last_seen_at = EXCLUDED.last_seen_at,
              last_observed_run_id = EXCLUDED.last_observed_run_id
            RETURNING id
            """,
            (
                tenant_id,
                batch.connector_id,
                batch.connection_id,
                batch.scope_key,
                finding.source_uid,
                finding.rule_uid,
                finding.title,
                finding.description,
                finding.risk,
                finding.remediation,
                json.dumps(finding.remediation_references),
                finding.severity.value,
                finding.state.value,
                finding.evaluation_result.value,
                finding.class_uid,
                finding.class_name,
                finding.observed_at,
                json.dumps(evidence),
                json.dumps(dict(finding.attributes)),
                resolution_reason,
                batch.collected_at,
                batch.collected_at,
                batch.collected_at,
                batch.run_id,
            ),
        ).fetchone()
        return str(row["id"])

    @staticmethod
    def _replace_finding_resources(
        connection,
        tenant_id: str,
        finding_id: str,
        finding: FindingAssertion,
    ) -> None:
        connection.execute(
            "DELETE FROM finding_resource WHERE tenant_id = %s::uuid AND finding_id = %s::uuid",
            (tenant_id, finding_id),
        )
        for resource in finding.affected_resources:
            connection.execute(
                """
                INSERT INTO finding_resource
                  (tenant_id, finding_id, resource_uid, resource_name, resource_type,
                   provider, account_uid, region)
                VALUES (%s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s)
                """,
                (
                    tenant_id,
                    finding_id,
                    resource.uid,
                    resource.name,
                    resource.resource_type,
                    resource.provider,
                    resource.account_uid,
                    resource.region,
                ),
            )

    @staticmethod
    def _replace_finding_compliance(
        connection,
        tenant_id: str,
        finding_id: str,
        finding: FindingAssertion,
    ) -> None:
        connection.execute(
            "DELETE FROM finding_compliance WHERE tenant_id = %s::uuid AND finding_id = %s::uuid",
            (tenant_id, finding_id),
        )
        for framework, controls in finding.compliance.items():
            for control in controls:
                connection.execute(
                    """
                    INSERT INTO finding_compliance
                      (tenant_id, finding_id, framework, control)
                    VALUES (%s::uuid, %s::uuid, %s, %s)
                    """,
                    (tenant_id, finding_id, framework, control),
                )

    @staticmethod
    def _insert_finding_observation(
        connection,
        tenant_id: str,
        finding_id: str,
        batch: FindingBatch,
        finding: FindingAssertion,
    ) -> None:
        resources = [
            {
                "uid": resource.uid,
                "name": resource.name,
                "resource_type": resource.resource_type,
                "provider": resource.provider,
                "account_uid": resource.account_uid,
                "region": resource.region,
            }
            for resource in finding.affected_resources
        ]
        connection.execute(
            """
            INSERT INTO finding_observation
              (tenant_id, finding_id, connector_id, connection_id, run_id, scope_key,
               collected_at, source_observed_at, severity, state, evaluation_result,
               evidence, attributes, affected_resources, compliance)
            VALUES
              (%s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s,
               %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb)
            ON CONFLICT
              (tenant_id, finding_id, connector_id, connection_id, run_id)
            DO UPDATE SET
              collected_at = EXCLUDED.collected_at,
              source_observed_at = EXCLUDED.source_observed_at,
              severity = EXCLUDED.severity,
              state = EXCLUDED.state,
              evaluation_result = EXCLUDED.evaluation_result,
              evidence = EXCLUDED.evidence,
              attributes = EXCLUDED.attributes,
              affected_resources = EXCLUDED.affected_resources,
              compliance = EXCLUDED.compliance
            """,
            (
                tenant_id,
                finding_id,
                batch.connector_id,
                batch.connection_id,
                batch.run_id,
                batch.scope_key,
                batch.collected_at,
                finding.observed_at,
                finding.severity.value,
                finding.state.value,
                finding.evaluation_result.value,
                json.dumps(_evidence_json(finding.evidence)),
                json.dumps(dict(finding.attributes)),
                json.dumps(resources),
                json.dumps(dict(finding.compliance)),
            ),
        )

    @staticmethod
    def _upsert_vulnerability(
        connection,
        tenant_id: str,
        batch: VulnerabilityBatch,
        observation: VulnerabilityAssertion,
    ) -> str:
        row = connection.execute(
            """
            INSERT INTO vulnerability
              (tenant_id, canonical_key, vulnerability_id,
               component_kind, component_natural_key, component_asset_id,
               target_kind, target_natural_key, target_asset_id,
               state, resolution_reason, first_seen_at, last_seen_at, last_changed_at)
            VALUES
              (%s::uuid, %s, %s, %s, %s,
               (SELECT id FROM asset WHERE tenant_id = %s::uuid AND kind = %s
                AND natural_key = %s),
               %s, %s,
               (SELECT id FROM asset WHERE tenant_id = %s::uuid AND kind = %s
                AND natural_key = %s),
               %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, canonical_key)
            DO UPDATE SET
              component_asset_id = COALESCE(
                  vulnerability.component_asset_id, EXCLUDED.component_asset_id),
              target_asset_id = COALESCE(
                  vulnerability.target_asset_id, EXCLUDED.target_asset_id),
              last_seen_at = GREATEST(vulnerability.last_seen_at, EXCLUDED.last_seen_at)
            RETURNING id
            """,
            (
                tenant_id,
                observation.canonical_key,
                observation.vulnerability_id,
                observation.component.kind.value,
                observation.component.natural_key,
                tenant_id,
                observation.component.kind.value,
                observation.component.natural_key,
                observation.target.kind.value,
                observation.target.natural_key,
                tenant_id,
                observation.target.kind.value,
                observation.target.natural_key,
                observation.state.value,
                "source_status" if observation.state.value == "resolved" else None,
                batch.collected_at,
                batch.collected_at,
                batch.collected_at,
            ),
        ).fetchone()
        return str(row["id"])

    @staticmethod
    def _upsert_vulnerability_observation(
        connection,
        tenant_id: str,
        vulnerability_id: str,
        batch: VulnerabilityBatch,
        observation: VulnerabilityAssertion,
    ) -> None:
        connection.execute(
            """
            INSERT INTO vulnerability_observation
              (tenant_id, vulnerability_id, connector_id, connection_id, source_uid,
               scope_key, aliases, title, description, severity, state, cvss_score,
               cvss_vector, fix_state, fixed_versions, exploit_state, match_method,
               match_confidence, database_version, database_built_at, source_observed_at,
               evidence, attributes, first_seen_at, last_seen_at, last_observed_run_id,
               withdrawn_at)
            VALUES
              (%s::uuid, %s::uuid, %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s,
               %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s, %s::jsonb,
               %s::jsonb, %s, %s, %s, NULL)
            ON CONFLICT (tenant_id, connector_id, connection_id, source_uid)
            DO UPDATE SET
              vulnerability_id = EXCLUDED.vulnerability_id,
              scope_key = EXCLUDED.scope_key,
              aliases = EXCLUDED.aliases,
              title = EXCLUDED.title,
              description = EXCLUDED.description,
              severity = EXCLUDED.severity,
              state = EXCLUDED.state,
              cvss_score = EXCLUDED.cvss_score,
              cvss_vector = EXCLUDED.cvss_vector,
              fix_state = EXCLUDED.fix_state,
              fixed_versions = EXCLUDED.fixed_versions,
              exploit_state = EXCLUDED.exploit_state,
              match_method = EXCLUDED.match_method,
              match_confidence = EXCLUDED.match_confidence,
              database_version = EXCLUDED.database_version,
              database_built_at = EXCLUDED.database_built_at,
              source_observed_at = EXCLUDED.source_observed_at,
              evidence = EXCLUDED.evidence,
              attributes = EXCLUDED.attributes,
              last_seen_at = EXCLUDED.last_seen_at,
              last_observed_run_id = EXCLUDED.last_observed_run_id,
              withdrawn_at = NULL
            """,
            (
                tenant_id,
                vulnerability_id,
                batch.connector_id,
                batch.connection_id,
                observation.source_uid,
                batch.scope_key,
                json.dumps(list(observation.aliases)),
                observation.title,
                observation.description,
                observation.severity.value,
                observation.state.value,
                observation.cvss_score,
                observation.cvss_vector,
                observation.fix_state.value,
                json.dumps(list(observation.fixed_versions)),
                observation.exploit_state.value,
                observation.match_method.value,
                observation.match_confidence,
                observation.database_version,
                observation.database_built_at,
                observation.observed_at,
                json.dumps(_evidence_json(observation.evidence)),
                json.dumps(dict(observation.attributes)),
                batch.collected_at,
                batch.collected_at,
                batch.run_id,
            ),
        )

    @staticmethod
    def _refresh_vulnerability_asset_links(connection, tenant_id: str) -> None:
        connection.execute(
            """
            UPDATE vulnerability v
            SET component_asset_id = component.id
            FROM asset component
            WHERE v.tenant_id = %s::uuid
              AND component.tenant_id = v.tenant_id
              AND component.kind = v.component_kind
              AND component.natural_key = v.component_natural_key
              AND v.component_asset_id IS DISTINCT FROM component.id
            """,
            (tenant_id,),
        )
        connection.execute(
            """
            WITH candidates AS (
                SELECT v.id AS vulnerability_id,
                       min(component.id::text)::uuid AS component_id
                FROM vulnerability v
                JOIN vulnerability_observation observation
                  ON observation.tenant_id = v.tenant_id
                 AND observation.vulnerability_id = v.id
                 AND observation.withdrawn_at IS NULL
                JOIN asset_assertion assertion
                  ON assertion.tenant_id = v.tenant_id
                 AND assertion.withdrawn_at IS NULL
                 AND assertion.attributes->'syft'->'artifact_ids'
                       ? (observation.evidence->'payload'->>'artifact_id')
                 AND assertion.attributes->'component'->'target'->>'kind'
                       = v.target_kind
                 AND assertion.attributes->'component'->'target'->>'natural_key'
                       = v.target_natural_key
                 AND (
                       NOT (observation.attributes ? 'component')
                       OR (
                           assertion.attributes->'component'->>'name'
                               = observation.attributes->'component'->>'name'
                           AND assertion.attributes->'component'->>'version'
                               IS NOT DISTINCT FROM
                               observation.attributes->'component'->>'version'
                           AND assertion.attributes->'component'->>'package_type'
                               = observation.attributes->'component'->>'package_type'
                       )
                 )
                JOIN asset component
                  ON component.tenant_id = assertion.tenant_id
                 AND component.id = assertion.asset_id
                 AND component.kind = 'software_component'
                WHERE v.tenant_id = %s::uuid
                  AND v.component_asset_id IS NULL
                  AND observation.evidence->'payload'->>'artifact_id' IS NOT NULL
                GROUP BY v.id
                HAVING count(DISTINCT component.id) = 1
            )
            UPDATE vulnerability v
            SET component_asset_id = candidates.component_id
            FROM candidates
            WHERE v.tenant_id = %s::uuid
              AND v.id = candidates.vulnerability_id
              AND v.component_asset_id IS NULL
            """,
            (tenant_id, tenant_id),
        )
        connection.execute(
            """
            UPDATE vulnerability_scan scan
            SET target_asset_id = target.id
            FROM asset target
            WHERE scan.tenant_id = %s::uuid
              AND target.tenant_id = scan.tenant_id
              AND target.kind = scan.target_kind
              AND target.natural_key = scan.target_natural_key
              AND scan.target_asset_id IS DISTINCT FROM target.id
            """,
            (tenant_id,),
        )
        connection.execute(
            """
            UPDATE vulnerability v
            SET target_asset_id = target.id
            FROM asset target
            WHERE v.tenant_id = %s::uuid
              AND target.tenant_id = v.tenant_id
              AND target.kind = v.target_kind
              AND target.natural_key = v.target_natural_key
              AND v.target_asset_id IS DISTINCT FROM target.id
            """,
            (tenant_id,),
        )

    @staticmethod
    def _refresh_vulnerability_states(connection, tenant_id: str, changed_at: datetime) -> None:
        connection.execute(
            """
            WITH current_state AS (
                SELECT v.id,
                       CASE
                         WHEN count(o.source_uid) = 0 THEN 'resolved'
                         WHEN bool_or(o.state = 'open') THEN 'open'
                         WHEN bool_or(o.state = 'unknown') THEN 'unknown'
                         WHEN bool_or(o.state = 'suppressed') THEN 'suppressed'
                         ELSE 'resolved'
                       END AS state,
                       CASE
                         WHEN count(o.source_uid) = 0
                           THEN 'absent_from_authoritative_snapshot'
                         WHEN bool_and(o.state = 'resolved') THEN 'source_status'
                         ELSE NULL
                       END AS resolution_reason,
                       COALESCE(max(o.last_seen_at), v.last_seen_at) AS last_seen_at
                FROM vulnerability v
                LEFT JOIN vulnerability_observation o
                  ON o.tenant_id = v.tenant_id
                 AND o.vulnerability_id = v.id
                 AND o.withdrawn_at IS NULL
                WHERE v.tenant_id = %s::uuid
                GROUP BY v.id
            )
            UPDATE vulnerability v
            SET state = current_state.state,
                resolution_reason = current_state.resolution_reason,
                last_seen_at = current_state.last_seen_at,
                last_changed_at = CASE
                    WHEN v.state IS DISTINCT FROM current_state.state
                      OR v.resolution_reason IS DISTINCT FROM current_state.resolution_reason
                    THEN %s ELSE v.last_changed_at END
            FROM current_state
            WHERE v.id = current_state.id
            """,
            (tenant_id, changed_at),
        )

    @staticmethod
    def _insert_run(
        connection,
        tenant_id: str,
        batch: InventoryBatch | FindingBatch | VulnerabilityBatch | ActivityBatch,
    ) -> None:
        connection.execute(
            """
            INSERT INTO collection_run
              (tenant_id, connector_id, connection_id, run_id, scope_key, collected_at)
            VALUES (%s::uuid, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, connector_id, connection_id, run_id) DO NOTHING
            """,
            (
                tenant_id,
                batch.connector_id,
                batch.connection_id,
                batch.run_id,
                batch.scope_key,
                batch.collected_at,
            ),
        )
        for coverage in batch.coverage:
            connection.execute(
                """
                INSERT INTO collection_coverage
                  (tenant_id, connector_id, connection_id, run_id, plane, scope, state,
                   detail, collected_at)
                VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (tenant_id, connector_id, connection_id, run_id, plane, scope)
                DO UPDATE SET state = EXCLUDED.state, detail = EXCLUDED.detail,
                              collected_at = EXCLUDED.collected_at
                """,
                (
                    tenant_id,
                    batch.connector_id,
                    batch.connection_id,
                    batch.run_id,
                    coverage.plane,
                    coverage.scope,
                    coverage.state.value,
                    coverage.detail,
                    batch.collected_at,
                ),
            )

    @staticmethod
    def _ensure_asset(connection, tenant_id: str, ref: AssetRef, seen_at: datetime) -> str:
        row = connection.execute(
            """
            INSERT INTO asset
              (tenant_id, kind, natural_key, first_seen_at, last_seen_at, last_changed_at)
            VALUES (%s::uuid, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, kind, natural_key)
            DO UPDATE SET last_seen_at = GREATEST(asset.last_seen_at, EXCLUDED.last_seen_at)
            RETURNING id
            """,
            (tenant_id, ref.kind.value, ref.natural_key, seen_at, seen_at, seen_at),
        ).fetchone()
        return str(row["id"])

    def _optional_asset(
        self, connection, tenant_id: str, ref: AssetRef | None, seen_at: datetime
    ) -> str | None:
        return None if ref is None else self._ensure_asset(connection, tenant_id, ref, seen_at)

    @staticmethod
    def _upsert_asset_assertion(
        connection,
        tenant_id: str,
        batch: InventoryBatch,
        asset_id: str,
        assertion: AssetAssertion,
    ) -> None:
        evidence = _evidence_json(assertion.evidence)
        connection.execute(
            """
            INSERT INTO asset_assertion
              (tenant_id, asset_id, connector_id, connection_id, scope_key,
               coverage_plane, assertion_type, confidence, display_name, attributes,
               evidence, lifecycle_state, first_seen_at, last_seen_at,
               last_observed_run_id, withdrawn_at)
            VALUES (%s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s::jsonb,
                    %s::jsonb, %s, %s, %s, %s, NULL)
            ON CONFLICT
              (tenant_id, asset_id, connector_id, connection_id, scope_key,
               coverage_plane, assertion_type)
            DO UPDATE SET confidence = EXCLUDED.confidence,
                          display_name = EXCLUDED.display_name,
                          attributes = EXCLUDED.attributes,
                          evidence = EXCLUDED.evidence,
                          lifecycle_state = EXCLUDED.lifecycle_state,
                          last_seen_at = EXCLUDED.last_seen_at,
                          last_observed_run_id = EXCLUDED.last_observed_run_id,
                          withdrawn_at = NULL
            """,
            (
                tenant_id,
                asset_id,
                batch.connector_id,
                batch.connection_id,
                batch.scope_key,
                assertion.coverage_plane,
                assertion.assertion_type.value,
                assertion.confidence,
                assertion.display_name,
                json.dumps(dict(assertion.attributes)),
                json.dumps(evidence),
                assertion.lifecycle.value,
                batch.collected_at,
                batch.collected_at,
                batch.run_id,
            ),
        )

    @staticmethod
    def _upsert_relationship(
        connection,
        tenant_id: str,
        batch: InventoryBatch,
        assertion: RelationshipAssertion,
        source_id: str,
        target_id: str,
        principal_id: str | None,
        agent_id: str | None,
    ) -> None:
        connection.execute(
            """
            INSERT INTO relationship_assertion
              (tenant_id, source_asset_id, target_asset_id, kind, category,
               connector_id, connection_id, scope_key, coverage_plane, assertion_type,
               confidence, attributes, evidence, principal_asset_id, agent_asset_id,
               first_seen_at, last_seen_at, last_observed_run_id, withdrawn_at)
            VALUES (%s::uuid, %s::uuid, %s::uuid, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s::jsonb, %s::jsonb, %s::uuid, %s::uuid, %s, %s, %s, NULL)
            ON CONFLICT
              (tenant_id, source_asset_id, target_asset_id, kind, connector_id,
               connection_id, scope_key, coverage_plane, assertion_type)
            DO UPDATE SET confidence = EXCLUDED.confidence,
                          attributes = EXCLUDED.attributes,
                          evidence = EXCLUDED.evidence,
                          principal_asset_id = EXCLUDED.principal_asset_id,
                          agent_asset_id = EXCLUDED.agent_asset_id,
                          last_seen_at = EXCLUDED.last_seen_at,
                          last_observed_run_id = EXCLUDED.last_observed_run_id,
                          withdrawn_at = NULL
            """,
            (
                tenant_id,
                source_id,
                target_id,
                assertion.kind.value,
                assertion.category.value,
                batch.connector_id,
                batch.connection_id,
                batch.scope_key,
                assertion.coverage_plane,
                assertion.assertion_type.value,
                assertion.confidence,
                json.dumps(dict(assertion.attributes)),
                json.dumps(_evidence_json(assertion.evidence)),
                principal_id,
                agent_id,
                batch.collected_at,
                batch.collected_at,
                batch.run_id,
            ),
        )

    @staticmethod
    def _withdraw_missing_assets(
        connection, tenant_id: str, batch: InventoryBatch, plane: str
    ) -> int:
        result = connection.execute(
            """
            UPDATE asset_assertion
            SET withdrawn_at = %s, lifecycle_state = 'withdrawn'
            WHERE tenant_id = %s::uuid AND connector_id = %s AND connection_id = %s
              AND scope_key = %s AND coverage_plane = %s AND withdrawn_at IS NULL
              AND last_observed_run_id <> %s
            """,
            (
                batch.collected_at,
                tenant_id,
                batch.connector_id,
                batch.connection_id,
                batch.scope_key,
                plane,
                batch.run_id,
            ),
        )
        return result.rowcount

    @staticmethod
    def _withdraw_missing_relationships(
        connection, tenant_id: str, batch: InventoryBatch, plane: str
    ) -> int:
        result = connection.execute(
            """
            UPDATE relationship_assertion
            SET withdrawn_at = %s
            WHERE tenant_id = %s::uuid AND connector_id = %s AND connection_id = %s
              AND scope_key = %s AND coverage_plane = %s AND withdrawn_at IS NULL
              AND last_observed_run_id <> %s
            """,
            (
                batch.collected_at,
                tenant_id,
                batch.connector_id,
                batch.connection_id,
                batch.scope_key,
                plane,
                batch.run_id,
            ),
        )
        return result.rowcount

    @staticmethod
    def _refresh_asset_lifecycle(connection, tenant_id: str) -> None:
        connection.execute(
            """
            UPDATE asset a
            SET lifecycle_state = CASE WHEN
                EXISTS (
                    SELECT 1 FROM asset_assertion aa
                    WHERE aa.tenant_id = a.tenant_id AND aa.asset_id = a.id
                      AND aa.withdrawn_at IS NULL
                ) OR EXISTS (
                    SELECT 1 FROM relationship_assertion ra
                    WHERE ra.tenant_id = a.tenant_id
                      AND (ra.source_asset_id = a.id OR ra.target_asset_id = a.id)
                      AND ra.withdrawn_at IS NULL
                ) THEN 'active' ELSE 'withdrawn' END
            WHERE a.tenant_id = %s::uuid
            """,
            (tenant_id,),
        )


def _evidence_json(evidence) -> dict[str, Any]:
    return {
        "source_type": evidence.source_type,
        "locator": evidence.locator,
        "observed_at": evidence.observed_at.isoformat(),
        "payload": dict(evidence.payload),
    }
