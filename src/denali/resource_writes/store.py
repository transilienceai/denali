"""Durable immutable plans, two-person approval, leases and append-only audit."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
from psycopg.rows import dict_row

from denali.resource_writes.templates import RemediationError, sha256


class RemediationStore:
    def __init__(self, dsn: str):
        if not dsn:
            raise ValueError("Denali remediation database required")
        self._dsn = dsn

    def _connect(self):
        return psycopg.connect(self._dsn, row_factory=dict_row, connect_timeout=5)

    def preview(self, row):
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO resource_write_preview
                    (id, tenant_id, clerk_org_id, finding_id, grant_id, action,
                     actor_user_id, parameters, plan, preview_sha256, expires_at)
                VALUES (%s::uuid, %s::uuid, %s, %s::uuid, %s::uuid, %s, %s,
                        %s::jsonb, %s::jsonb, %s, %s)
            """,
                (
                    row["id"],
                    row["tenant_id"],
                    row["clerk_org_id"],
                    row["finding_id"],
                    row["grant_id"],
                    row["action"],
                    row["actor_user_id"],
                    json.dumps(row["parameters"]),
                    json.dumps(row["plan"]),
                    row["preview_sha256"],
                    row["expires_at"],
                ),
            )

    def get_preview(self, tenant_id, preview_id):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM resource_write_preview WHERE tenant_id=%s::uuid AND id=%s::uuid",
                (tenant_id, preview_id),
            ).fetchone()
            return dict(row) if row else None

    def request(self, tenant_id, preview_id, actor, key, justification):
        request_hash = sha256(
            {"preview_id": preview_id, "actor": actor, "justification": justification}
        )
        with self._connect() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (tenant_id + ":" + key,))
            existing = conn.execute(
                "SELECT * FROM resource_write_request WHERE tenant_id=%s::uuid "
                "AND idempotency_key=%s",
                (tenant_id, key),
            ).fetchone()
            if existing:
                if existing["request_sha256"] != request_hash:
                    raise RemediationError("idempotency_body_conflict")
                return dict(existing)
            preview = conn.execute(
                "SELECT * FROM resource_write_preview WHERE tenant_id=%s::uuid AND id=%s::uuid",
                (tenant_id, preview_id),
            ).fetchone()
            if preview is None or preview["actor_user_id"] != actor:
                raise RemediationError("preview_not_found")
            if preview["expires_at"] <= datetime.now(UTC):
                raise RemediationError("preview_expired")
            try:
                row = conn.execute(
                    """
                    INSERT INTO resource_write_request
                        (tenant_id, preview_id, idempotency_key, request_sha256,
                         justification, actor_user_id, grant_id)
                    VALUES (%s::uuid, %s::uuid, %s, %s, %s, %s, %s::uuid) RETURNING *
                """,
                    (
                        tenant_id,
                        preview_id,
                        key,
                        request_hash,
                        justification,
                        actor,
                        preview["grant_id"],
                    ),
                ).fetchone()
            except psycopg.errors.UniqueViolation:
                raise RemediationError("preview_already_requested") from None
            self._audit(conn, tenant_id, str(row["id"]), "requested", actor)
            return dict(row)

    def get(self, tenant_id, request_id):
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT r.*, p.clerk_org_id, p.finding_id, p.action, p.parameters,
                       p.plan, p.preview_sha256, p.expires_at
                FROM resource_write_request r JOIN resource_write_preview p
                  ON p.id=r.preview_id AND p.tenant_id=r.tenant_id
                WHERE r.tenant_id=%s::uuid AND r.id=%s::uuid
            """,
                (tenant_id, request_id),
            ).fetchone()
            return dict(row) if row else None

    def review(self, tenant_id, request_id, reviewer, decision, note):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT r.*, p.expires_at FROM resource_write_request r "
                "JOIN resource_write_preview p ON p.id=r.preview_id AND p.tenant_id=r.tenant_id "
                "WHERE r.tenant_id=%s::uuid AND r.id=%s::uuid FOR UPDATE OF r",
                (tenant_id, request_id),
            ).fetchone()
            if row is None:
                raise RemediationError("request_not_found")
            if row["actor_user_id"] == reviewer:
                raise RemediationError("self_approval_forbidden")
            state = "approved" if decision == "approved" else "rejected"
            if (
                row["state"] == state
                and row["reviewer_user_id"] == reviewer
                and (row["review_note"] == note)
            ):
                return dict(row)
            if row["state"] != "pending_review" or row["expires_at"] <= datetime.now(UTC):
                raise RemediationError("request_not_reviewable")
            try:
                updated = conn.execute(
                    "UPDATE resource_write_request SET state=%s, "
                    "reviewer_user_id=%s, review_note=%s, updated_at=now() "
                    "WHERE tenant_id=%s::uuid AND id=%s::uuid RETURNING *",
                    (state, reviewer, note, tenant_id, request_id),
                ).fetchone()
            except psycopg.errors.UniqueViolation:
                raise RemediationError("another_resource_write_is_active") from None
            self._audit(conn, tenant_id, request_id, state, reviewer)
            return dict(updated)

    def claim(self, request_id):
        nonce = str(uuid4())
        with self._connect() as conn:
            expired = conn.execute(
                "UPDATE resource_write_request SET state='failed', error_code='preview_expired', "
                "updated_at=now() WHERE id=%s::uuid AND state='approved' AND EXISTS "
                "(SELECT 1 FROM resource_write_preview p WHERE p.id=preview_id "
                "AND p.expires_at <= now()) RETURNING tenant_id",
                (request_id,),
            ).fetchone()
            if expired:
                self._audit(
                    conn, str(expired["tenant_id"]), request_id, "preview_expired", "worker"
                )
            # Expired work is never reclaimed for mutation. Its outcome is
            # reconciled using read-only provider calls and durable markers.
            abandoned = conn.execute(
                "UPDATE resource_write_request SET state='needs_manual_resolution', "
                "error_code='worker_lease_expired', updated_at=now() "
                "WHERE id=%s::uuid AND state='running' AND lease_expires_at <= now() "
                "RETURNING tenant_id",
                (request_id,),
            ).fetchone()
            if abandoned:
                self._audit(
                    conn, str(abandoned["tenant_id"]), request_id, "worker_lease_expired", "worker"
                )
            row = conn.execute(
                """
                UPDATE resource_write_request SET state='running', lease_nonce=%s::uuid,
                    lease_expires_at=%s, updated_at=now()
                WHERE id=%s::uuid AND state='approved' AND phase='not_started'
                  AND EXISTS (SELECT 1 FROM resource_write_preview p
                              WHERE p.id=preview_id AND p.expires_at > now())
                RETURNING tenant_id
            """,
                (nonce, datetime.now(UTC) + timedelta(minutes=20), request_id),
            ).fetchone()
            if row is None:
                return None
            self._audit(conn, str(row["tenant_id"]), request_id, "claimed", "worker")
        result = self.get(str(row["tenant_id"]), request_id)
        result["lease_nonce"] = nonce
        return result

    def reconcile_finish(self, tenant_id, request_id, actor, result):
        with self._connect() as conn:
            changed = conn.execute(
                "UPDATE resource_write_request SET state='succeeded', phase='finished', "
                "result=%s::jsonb, error_code=NULL, updated_at=now() "
                "WHERE tenant_id=%s::uuid AND id=%s::uuid AND phase='provider_attempted' "
                "AND (state='needs_manual_resolution' OR "
                "(state='running' AND lease_expires_at <= now())) RETURNING id",
                (json.dumps(result), tenant_id, request_id),
            ).fetchone()
            if not changed:
                raise RemediationError("request_not_reconcilable")
            self._audit(conn, tenant_id, request_id, "read_only_reconciliation_succeeded", actor)

    def mark_provider_attempted(self, tenant_id, request_id, nonce):
        with self._connect() as conn:
            changed = conn.execute(
                "UPDATE resource_write_request SET phase='provider_attempted', "
                "provider_attempted_at=now(), updated_at=now() "
                "WHERE tenant_id=%s::uuid AND id=%s::uuid AND state='running' "
                "AND phase='not_started' AND lease_nonce=%s::uuid AND lease_expires_at > now() "
                "AND EXISTS (SELECT 1 FROM resource_write_preview p "
                "WHERE p.id=preview_id AND p.expires_at > now()) "
                "RETURNING id",
                (tenant_id, request_id, nonce),
            ).fetchone()
            if not changed:
                raise RemediationError("worker_lease_lost")
            self._audit(conn, tenant_id, request_id, "provider_attempted", "worker")

    def finish(self, tenant_id, request_id, nonce, *, result=None, error=None):
        with self._connect() as conn:
            row = conn.execute(
                "UPDATE resource_write_request SET state=CASE "
                "WHEN %s::text IS NULL THEN 'succeeded' WHEN phase='provider_attempted' "
                "THEN 'needs_manual_resolution' ELSE 'failed' END, result=%s::jsonb, "
                "error_code=%s, updated_at=now(), phase=CASE WHEN %s::text IS NULL "
                "THEN 'finished' ELSE phase END WHERE tenant_id=%s::uuid AND id=%s::uuid "
                "AND state='running' AND lease_nonce=%s::uuid AND lease_expires_at > now() "
                "RETURNING state",
                (error, json.dumps(result), error, error, tenant_id, request_id, nonce),
            ).fetchone()
            if row:
                self._audit(conn, tenant_id, request_id, row["state"], "worker")
            else:
                abandoned = conn.execute(
                    "UPDATE resource_write_request SET state='needs_manual_resolution', "
                    "error_code='worker_lease_expired', updated_at=now() "
                    "WHERE tenant_id=%s::uuid AND id=%s::uuid AND state='running' "
                    "AND lease_nonce=%s::uuid AND lease_expires_at <= now() RETURNING id",
                    (tenant_id, request_id, nonce),
                ).fetchone()
                if abandoned:
                    self._audit(conn, tenant_id, request_id, "worker_lease_expired", "worker")

    def record_dispatch(self, tenant_id, request_id, call_id):
        with self._connect() as conn:
            conn.execute(
                "UPDATE resource_write_request SET modal_call_id=%s "
                "WHERE tenant_id=%s::uuid AND id=%s::uuid AND modal_call_id IS NULL",
                (call_id, tenant_id, request_id),
            )

    @staticmethod
    def _audit(conn, tenant_id, request_id, event, actor):
        conn.execute(
            "INSERT INTO resource_write_audit_event "
            "(tenant_id, request_id, event_type, actor_user_id) VALUES "
            "(%s::uuid, %s::uuid, %s, %s)",
            (tenant_id, request_id, event, actor),
        )
