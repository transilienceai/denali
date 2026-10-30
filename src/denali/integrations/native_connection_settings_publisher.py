"""Denali-owned native identifier publication and provider-free operator checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx
import psycopg
from psycopg.rows import dict_row

from denali.integrations.clerk_connection_settings import (
    MAX_METADATA_BYTES,
    _timestamp,
    bounded_json_request,
)
from denali.integrations.native_connection_settings import (
    CONFIGURATION_FIELDS,
    NATIVE_CREDENTIAL_TYPES,
    NATIVE_NAMESPACE,
    NATIVE_PILOT_CONNECTION_COUNT,
    REFERENCE_FIELDS,
    NativeConnectionSettingsUnavailable,
    build_native_snapshot,
    enrolled_native_settings,
    native_backend_key,
    native_binding_sha256,
    native_environment,
    project_native_settings,
    validate_native_snapshot,
)
from denali.native_connection_settings_config import native_candidate_connection


class NativeSettingsPublicationUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("native connection settings publication unavailable")


def _reject() -> None:
    raise NativeSettingsPublicationUnavailable()


def _bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise NativeSettingsPublicationUnavailable() from None


def _publication_flag(environ: Mapping[str, str]) -> bool:
    value = environ.get("DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED", "false")
    if value not in {"true", "false"}:
        _reject()
    return value == "true"


@dataclass(frozen=True)
class NativePublisherConfig:
    organization_id: str
    connection_ids: frozenset[str]
    environment: str
    database_url: str = field(repr=False)
    secret_key: str = field(repr=False)
    publication_enabled: bool = False

    def __post_init__(self) -> None:
        prefix = {"production": "sk_live_", "development": "sk_test_"}.get(self.environment)
        if (not re_org(self.organization_id) or not self.database_url or prefix is None
                or not self.secret_key.startswith(prefix) or len(self.secret_key) <= len(prefix)
                or type(self.publication_enabled) is not bool):
            _reject()
        try:
            enrolled_native_settings({
                "DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS": self.organization_id,
                "DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CONNECTION_IDS":
                    ",".join(sorted(self.connection_ids)),
            })
        except Exception:
            raise NativeSettingsPublicationUnavailable() from None

    @classmethod
    def from_environment(
        cls, environ: Mapping[str, str] | None = None, *, require_enabled: bool = True,
    ) -> NativePublisherConfig | None:
        env = os.environ if environ is None else environ
        enabled = _publication_flag(env)
        if require_enabled and not enabled:
            return None
        try:
            organizations, connections = enrolled_native_settings(env)
            environment = native_environment(env)
            key = native_backend_key(env, environment)
        except NativeConnectionSettingsUnavailable:
            raise NativeSettingsPublicationUnavailable() from None
        dsn = env.get("DENALI_DSN", "")
        if not dsn:
            _reject()
        return cls(next(iter(organizations)), connections, environment, dsn, key, enabled)


def _guard(config: NativePublisherConfig, expected_clerk_org_id: str) -> None:
    if expected_clerk_org_id != config.organization_id:
        _reject()


def _configure_read_transaction(connection: Any, organization_id: str) -> None:
    connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
    connection.execute("SET LOCAL statement_timeout='5s'")
    connection.execute("SET LOCAL lock_timeout='500ms'")
    connection.execute("SET LOCAL idle_in_transaction_session_timeout='30s'")
    locked = connection.execute(
        "SELECT pg_try_advisory_xact_lock(hashtextextended(%s,0)) AS locked",
        ("denali_native_connection_settings:" + organization_id,),
    ).fetchone()
    if not locked or not locked["locked"]:
        _reject()


_RAW_TARGET_SQL = """
SELECT c.id,c.tenant_id,c.provider,c.credential_type,c.declared_scopes,c.lifecycle_state,
       c.health_state,t.clerk_organization_id,
       (SELECT COALESCE(jsonb_object_agg(entry.key,entry.value),'{}'::jsonb)
        FROM jsonb_each(CASE WHEN jsonb_typeof(c.credential_reference)='object'
                            THEN c.credential_reference ELSE '{}'::jsonb END) entry
        WHERE entry.key=ANY(%s::text[]))
         AS credential_reference,
       (SELECT COALESCE(jsonb_object_agg(entry.key,
          CASE WHEN entry.key IN ('projects','subscriptions','repositories')
                     AND jsonb_typeof(entry.value)='array'
               THEN (SELECT COALESCE(jsonb_agg(jsonb_build_object('id',item.value->'id')
                                  ORDER BY item.ordinality),'[]'::jsonb)
                     FROM jsonb_array_elements(entry.value) WITH ORDINALITY item(value,ordinality))
               ELSE entry.value END),'{}'::jsonb)
        FROM jsonb_each(CASE WHEN jsonb_typeof(c.configuration)='object'
                            THEN c.configuration ELSE '{}'::jsonb END) entry
        WHERE entry.key=ANY(%s::text[])) AS configuration
FROM provider_connection c JOIN denali_tenant t ON t.id=c.tenant_id
WHERE t.clerk_organization_id=%s AND c.id=ANY(%s::uuid[])
ORDER BY c.provider,c.id LIMIT 7
"""


def read_enrolled_native_targets(
    connection: Any, config: NativePublisherConfig, *, require_complete: bool = True,
) -> tuple[str, list[dict[str, Any]]]:
    """Raw *identifier projection* only, deliberately bypassing the consumer hook.

    No setup hashes, PKCE, operator credential profile or provider key/token columns
    are selected. Nested repository/project/subscription metadata is reduced to IDs.
    """
    reference_keys = sorted({key for fields in REFERENCE_FIELDS.values() for key in fields})
    configuration_keys = sorted({key for fields in CONFIGURATION_FIELDS.values() for key in fields}
                                | {"projects", "subscriptions", "repositories"})
    rows = connection.execute(_RAW_TARGET_SQL, (
        reference_keys, configuration_keys, config.organization_id, sorted(config.connection_ids),
    )).fetchall()
    identifiers = {str(row["id"]) for row in rows}
    if (len(rows) > NATIVE_PILOT_CONNECTION_COUNT or len(identifiers) != len(rows)
            or not identifiers <= set(config.connection_ids)
            or require_complete and identifiers != set(config.connection_ids)
            or any(row.get("clerk_organization_id") != config.organization_id for row in rows)):
        _reject()
    tenants = {str(row["tenant_id"]) for row in rows}
    if not rows:
        tenant = connection.execute(
            "SELECT id FROM denali_tenant WHERE clerk_organization_id=%s LIMIT 1",
            (config.organization_id,),
        ).fetchone()
        if tenant:
            tenants.add(str(tenant["id"]))
    if len(tenants) != 1:
        _reject()
    for row in rows:
        if (require_complete
                and NATIVE_CREDENTIAL_TYPES.get(row.get("provider")) != row.get("credential_type")):
            _reject()
    return next(iter(tenants)), [dict(row) for row in rows]


def _replacement_patch(old: Any, new: dict[str, Any]) -> dict[str, Any]:
    # Provider arrays replace atomically; nulls only delete obsolete object keys.
    old = old if isinstance(old, dict) else {}
    result = {key: None for key in old.keys() - new.keys()}
    for key, value in new.items():
        result[key] = _replacement_patch(old.get(key), value) if isinstance(value, dict) else value
    return result


def _organization(client: httpx.Client, config: NativePublisherConfig) -> dict[str, Any]:
    result = bounded_json_request(
        client, "GET", "/organizations/" + config.organization_id, config.secret_key,
    )
    if result.get("id") != config.organization_id:
        _reject()
    return result


def _measure(current: dict[str, Any], snapshot: dict[str, Any]) -> tuple[dict[str, Any], int]:
    private, public = current.get("private_metadata"), current.get("public_metadata")
    if not isinstance(private, dict) or not isinstance(public, dict):
        _reject()
    updated = {**private, NATIVE_NAMESPACE: snapshot}
    combined = len(_bytes({"private_metadata": updated, "public_metadata": public}))
    if combined > MAX_METADATA_BYTES:
        _reject()
    return private, combined


def _receipt(
    snapshot: dict[str, Any], combined_bytes: int, *, published: bool,
    omissions: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    bindings = [
        [provider, record["id"], record["binding_sha256"]]
        for provider, records in sorted(snapshot["sources"].items()) for record in records
    ]
    return {
        "ready": len(bindings) == NATIVE_PILOT_CONNECTION_COUNT,
        "partial": len(bindings) != NATIVE_PILOT_CONNECTION_COUNT,
        "expected_org_match": True, "organization_count": 1,
        "configured_connection_count": NATIVE_PILOT_CONNECTION_COUNT,
        "enrollment_count": len(bindings), "provider_count": len(snapshot["sources"]),
        "published_connection_count": len(bindings),
        "omitted_connection_count": NATIVE_PILOT_CONNECTION_COUNT - len(bindings),
        "namespace_bytes": len(_bytes(snapshot)), "combined_metadata_bytes": combined_bytes,
        "metadata_headroom_bytes": MAX_METADATA_BYTES - combined_bytes,
        "binding_digest": hashlib.sha256(_bytes(bindings)).hexdigest(),
        "write_attempted": published, "publication_acknowledged": published,
        "provider_requests": 0,
        **(omissions or {}),
    }


def _snapshot_for_targets(
    tenant_id: str, targets: list[dict[str, Any]], config: NativePublisherConfig, *,
    strict: bool, now: datetime | None,
) -> tuple[dict[str, Any], dict[str, int]]:
    valid = []
    invalid = 0
    for target in targets:
        try:
            native_binding_sha256(tenant_id, target)
            valid.append(target)
        except NativeConnectionSettingsUnavailable:
            if strict:
                raise
            invalid += 1
    snapshot = build_native_snapshot(
        tenant_id, config.organization_id, valid, config.environment, now=now, enforce_budget=False,
    )
    return snapshot, {
        "missing_connection_count": NATIVE_PILOT_CONNECTION_COUNT - len(targets),
        "invalid_connection_count": invalid, "budget_omitted_connection_count": 0,
    }


def _fit_snapshot(
    current: dict[str, Any], snapshot: dict[str, Any], *, strict: bool,
) -> tuple[dict[str, Any], int, int]:
    """Drop largest complete records deterministically; never truncate selections."""
    private, public = current.get("private_metadata"), current.get("public_metadata")
    if not isinstance(private, dict) or not isinstance(public, dict):
        _reject()
    # The entire empty envelope must fit even when every native row is omitted.
    empty = {**snapshot, "sources": {}}
    _measure(current, empty)
    candidates = sorted(
        ((len(_bytes(record)), provider, record["id"])
         for provider, records in snapshot["sources"].items() for record in records),
        key=lambda item: (-item[0], item[1], item[2]),
    )
    omitted = 0
    while True:
        try:
            private, combined = _measure(current, snapshot)
            return private, combined, omitted
        except NativeSettingsPublicationUnavailable:
            if strict or not candidates:
                raise
            _, provider, identifier = candidates.pop(0)
            snapshot["sources"][provider] = [
                record for record in snapshot["sources"][provider] if record["id"] != identifier
            ]
            if not snapshot["sources"][provider]:
                del snapshot["sources"][provider]
            omitted += 1


def _existing_snapshot_status(
    current: dict[str, Any], desired: dict[str, Any], config: NativePublisherConfig,
    *, now: datetime | None = None,
) -> dict[str, Any]:
    private = current.get("private_metadata")
    present = isinstance(private, dict) and NATIVE_NAMESPACE in private
    status: dict[str, Any] = {
        "existing_snapshot_present": present, "existing_snapshot_fresh": False,
        "existing_binding_parity": False,
    }
    if not present:
        return status
    clock = now or datetime.now(UTC)
    try:
        existing = validate_native_snapshot(
            private[NATIVE_NAMESPACE], config.organization_id, config.environment, now=clock,
        )
        status.update({
            "existing_snapshot_fresh": True,
            "existing_binding_parity": _bytes(existing["sources"]) == _bytes(desired["sources"]),
            "existing_revision_digest": hashlib.sha256(existing["revision"].encode()).hexdigest(),
            "existing_published_at": existing["published_at"],
            "existing_published_age_seconds": int(
                (clock - _timestamp(existing["published_at"])).total_seconds()
            ),
            "existing_expires_in_seconds": int(
                (_timestamp(existing["expires_at"]) - clock).total_seconds()
            ),
        })
    except Exception:
        # Invalid/expired old metadata may be replaced, never certified as ready.
        pass
    return status


def prepare_or_publish_native_settings(
    expected_clerk_org_id: str, *, publish: bool = False,
    config: NativePublisherConfig | None = None, connection_factory=None,
    transport: httpx.BaseTransport | None = None, now: datetime | None = None,
) -> dict[str, Any]:
    """No PATCH in preflight. Explicit publication retains the org lock through ACK."""
    if config is None:
        config = NativePublisherConfig.from_environment(require_enabled=publish)
    if config is None or publish and not config.publication_enabled:
        return {"ready": False, "enabled": False, "write_attempted": False,
                "publication_acknowledged": False, "provider_requests": 0}
    _guard(config, expected_clerk_org_id)
    factory = connection_factory or psycopg.connect
    strict = not (publish and os.environ.get(
        "DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE", "database",
    ) == "clerk")
    try:
        with factory(config.database_url, row_factory=dict_row, connect_timeout=3) as connection:
            _configure_read_transaction(connection, config.organization_id)
            tenant_id, targets = read_enrolled_native_targets(
                connection, config, require_complete=strict,
            )
            snapshot, omissions = _snapshot_for_targets(
                tenant_id, targets, config, strict=strict, now=now,
            )
            with httpx.Client(trust_env=False, follow_redirects=False,
                              transport=transport or httpx.HTTPTransport(retries=0)) as client:
                current = _organization(client, config)
                private, combined, budget_omitted = _fit_snapshot(current, snapshot, strict=strict)
                omissions["budget_omitted_connection_count"] = budget_omitted
                existing_status = _existing_snapshot_status(current, snapshot, config, now=now)
                if publish:
                    acknowledged = bounded_json_request(
                        client, "PATCH", "/organizations/" + config.organization_id + "/metadata",
                        config.secret_key, payload={"private_metadata": {
                            NATIVE_NAMESPACE: _replacement_patch(
                                private.get(NATIVE_NAMESPACE), snapshot,
                            ),
                        }},
                    )
                    if (acknowledged.get("id") != config.organization_id
                            or not isinstance(acknowledged.get("private_metadata"), dict)
                            or _bytes(acknowledged["private_metadata"].get(NATIVE_NAMESPACE))
                            != _bytes(snapshot)):
                        _reject()
                    validate_native_snapshot(
                        acknowledged["private_metadata"][NATIVE_NAMESPACE],
                        config.organization_id, config.environment, now=now,
                    )
                    existing_status = _existing_snapshot_status(
                        acknowledged, snapshot, config, now=now,
                    )
            return {**_receipt(snapshot, combined, published=publish, omissions=omissions),
                    **existing_status}
    except NativeSettingsPublicationUnavailable:
        raise
    except Exception:
        # A failed/timeout PATCH is unconfirmed, not a claim that no write occurred.
        raise NativeSettingsPublicationUnavailable() from None


def publish_after_native_identifier_write(
    tenant_id: str, connection_id: str, database_url: str, *,
    environ: Mapping[str, str] | None = None, connection_factory=None, publish=None,
) -> None:
    """After commit only: refresh selected native IDs before post-save validation.

    No provider is contacted and no health/state mutation occurs. A Clerk outage
    is reported as fixed lookup unavailability, never as invalid provider access.
    """
    env = os.environ if environ is None else environ
    if (env.get("DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE", "database") != "clerk"
            or env.get("DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED", "false") != "true"
            or not native_candidate_connection(env, connection_id)):
        return
    try:
        config = NativePublisherConfig.from_environment(env)
        if config is None or config.database_url != database_url:
            _reject()
        factory = connection_factory or psycopg.connect
        with factory(database_url, row_factory=dict_row, connect_timeout=3) as connection:
            connection.execute("SET TRANSACTION READ ONLY")
            connection.execute("SET LOCAL statement_timeout='5s'")
            row = connection.execute(
                "SELECT clerk_organization_id FROM denali_tenant WHERE id=%s::uuid",
                (tenant_id,),
            ).fetchone()
        if row is None or row["clerk_organization_id"] != config.organization_id:
            return
        (publish or prepare_or_publish_native_settings)(
            config.organization_id, publish=True, config=config,
        )
    except Exception:
        raise NativeConnectionSettingsUnavailable() from None


def native_settings_manifest(
    expected_clerk_org_id: str, *, environ: Mapping[str, str] | None = None,
    connection_factory=None,
) -> dict[str, Any]:
    """Unscheduled operator-only ID inventory, before exact-six enrollment.

    No connection reference/configuration is selected or returned by this function.
    """
    env = os.environ if environ is None else environ
    organizations = [item.strip() for item in env.get(
        "DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS", "",
    ).split(",") if item.strip()]
    if (len(organizations) != 1 or organizations[0] != expected_clerk_org_id
            or not re_org(expected_clerk_org_id) or not env.get("DENALI_DSN")):
        _reject()
    native_environment(env)
    factory = connection_factory or psycopg.connect
    try:
        with factory(env["DENALI_DSN"], row_factory=dict_row, connect_timeout=3) as connection:
            connection.execute("SET TRANSACTION READ ONLY")
            connection.execute("SET LOCAL statement_timeout='5s'")
            connection.execute("SET LOCAL lock_timeout='500ms'")
            rows = connection.execute(
                "SELECT c.id,c.provider,c.credential_type,c.lifecycle_state "
                "FROM provider_connection c JOIN denali_tenant t ON t.id=c.tenant_id "
                "WHERE t.clerk_organization_id=%s AND c.credential_type=ANY(%s::text[]) "
                "ORDER BY c.provider,c.id LIMIT 7",
                (expected_clerk_org_id, list(NATIVE_CREDENTIAL_TYPES.values())),
            ).fetchall()
        return {"expected_org_match": True, "ready_for_six_enrollment": len(rows) == 6,
                "items": [{"id": str(row["id"]), "provider": row["provider"],
                           "credential_type": row["credential_type"],
                           "lifecycle_state": row["lifecycle_state"]} for row in rows],
                "write_attempted": False, "provider_requests": 0}
    except Exception:
        raise NativeSettingsPublicationUnavailable() from None


def re_org(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"org_[A-Za-z0-9]{1,124}", value) is not None


def verify_native_settings_lookup(
    expected_clerk_org_id: str, *, config: NativePublisherConfig | None = None,
    connection_factory=None, repository_factory=None,
    transport: httpx.BaseTransport | None = None,
) -> dict[str, Any]:
    """Resolve real enrolled targets through the consumer hook; never start work."""
    if os.environ.get("DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE", "database") != "clerk":
        _reject()
    config = config or NativePublisherConfig.from_environment(require_enabled=False)
    if config is None:
        _reject()
    _guard(config, expected_clerk_org_id)
    factory = connection_factory or psycopg.connect
    if repository_factory is None:
        from denali.store.repository import PostgresInventoryRepository

        repository_factory = PostgresInventoryRepository
    try:
        with factory(config.database_url, row_factory=dict_row, connect_timeout=3) as connection:
            _configure_read_transaction(connection, config.organization_id)
            tenant_id, targets = read_enrolled_native_targets(connection, config)
        # No consumer network request can execute inside the raw DB read context.
        repository = repository_factory(config.database_url)
        used = 0
        deadline = time.monotonic() + 75
        for raw in targets:
            if time.monotonic() > deadline:
                _reject()
            resolved = repository.get_connection_validation_target(tenant_id, str(raw["id"]))
            if (resolved is None or resolved.get("clerk_organization_id") != config.organization_id
                    or project_native_settings(resolved) != project_native_settings(raw)
                    or native_binding_sha256(tenant_id, resolved)
                    != native_binding_sha256(tenant_id, raw)):
                _reject()
            if raw["lifecycle_state"] == "active":
                if getattr(resolved, "native_connection_settings_source", None) != "clerk":
                    _reject()
                used += 1
        with httpx.Client(trust_env=False, follow_redirects=False,
                          transport=transport or httpx.HTTPTransport(retries=0)) as client:
            current = _organization(client, config)
            private = current.get("private_metadata")
            if not isinstance(private, dict):
                _reject()
            snapshot = validate_native_snapshot(
                private.get(NATIVE_NAMESPACE), config.organization_id, config.environment,
            )
            _, combined = _measure(current, snapshot)
        receipt = _receipt(snapshot, combined, published=False)
        now = datetime.now(UTC)
        age = int((now - _timestamp(snapshot["published_at"])).total_seconds())
        remaining = int((_timestamp(snapshot["expires_at"]) - now).total_seconds())
        receipt.update({
            "source_used_count": used, "binding_parity": True,
            "active_enrollment_count": sum(row["lifecycle_state"] == "active" for row in targets),
            "provider_counts": dict(Counter(row["provider"] for row in targets)),
            "health_counts": dict(Counter(row["health_state"] for row in targets)),
            "published_age_seconds": age, "expires_in_seconds": remaining,
        })
        return receipt
    except NativeSettingsPublicationUnavailable:
        raise
    except Exception:
        raise NativeSettingsPublicationUnavailable() from None
