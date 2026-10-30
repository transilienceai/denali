from __future__ import annotations

import copy
import os
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import psycopg
import pytest
from psycopg.rows import dict_row
from test_native_connection_settings import native_targets

from denali.integrations import native_connection_settings as native
from denali.integrations import native_connection_settings_publisher as publisher
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not configured")


def records(monkeypatch):
    migrate(DSN)
    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE", "database")
    repository = PostgresInventoryRepository(DSN)
    organization = "org_NativeSql" + uuid4().hex
    tenant = repository.resolve_tenant(organization)
    targets = native_targets()
    for index, target in enumerate(targets):
        target["id"] = str(uuid4())
        target["tenant_id"] = tenant
        target["clerk_organization_id"] = organization
        repository.create_connection(
            tenant, connection_id=target["id"], provider=target["provider"],
            display_name=f"Native synthetic {index}", credential_type=target["credential_type"],
            credential_reference=target["credential_reference"],
            declared_scopes=target["declared_scopes"], coverage_plan=target["coverage_plan"],
            configuration=target["configuration"],
        )
    config = publisher.NativePublisherConfig(
        organization, frozenset(target["id"] for target in targets), "development",
        DSN, "sk_test_synthetic_native", True,
    )
    return repository, tenant, targets, config


def test_real_readonly_sql_projects_native_identifiers_not_setup_or_operator_material(monkeypatch):
    repository, tenant, targets, config = records(monkeypatch)
    with psycopg.connect(DSN, row_factory=dict_row) as connection:
        publisher._configure_read_transaction(connection, config.organization_id)
        actual_tenant, projected = publisher.read_enrolled_native_targets(connection, config)
        assert connection.execute("SHOW transaction_read_only").fetchone()["transaction_read_only"]
    assert actual_tenant == tenant and len(projected) == 6
    original_by_id = {target["id"]: target for target in targets}
    for target in projected:
        assert "setup_token_sha256" not in target["credential_reference"]
        assert "pkce_verifier" not in target["credential_reference"]
        assert "operator_credential_profile" not in target["credential_reference"]
        assert "onboarding" not in target["configuration"]
        assert native.project_native_settings(target) == native.project_native_settings(
            original_by_id[str(target["id"])]
        )
        assert native.native_binding_sha256(tenant, target) == native.native_binding_sha256(
            tenant, original_by_id[str(target["id"])]
        )
    assert repository.get_connection_validation_target("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
        targets[0]["id"]) is None


def test_real_repository_hook_preserves_native_auth_data_and_fences_stale_scope(monkeypatch):
    repository, tenant, targets, config = records(monkeypatch)
    now = datetime.now(UTC)
    document = native.build_native_snapshot(
        tenant, config.organization_id, targets, "development", now=now,
    )
    calls = []

    def clerk(request):
        calls.append(request)
        assert request.url.path == "/v1/organizations/" + config.organization_id
        return httpx.Response(200, json={"id": config.organization_id,
            "private_metadata": {native.NATIVE_NAMESPACE: document}})

    original_reader = native.NativeConnectionSettingsReader
    monkeypatch.setattr(native, "NativeConnectionSettingsReader", lambda key, environment:
        original_reader(key, environment,
            client=httpx.Client(transport=httpx.MockTransport(clerk)), now=lambda: now))
    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE", "clerk")
    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_ENVIRONMENT", "development")
    monkeypatch.setenv("MODAL_ENVIRONMENT", "denali-dev")
    monkeypatch.setenv("CLERK_SECRET_KEY", config.secret_key)
    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS",
                       config.organization_id)
    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CONNECTION_IDS",
                       ",".join(sorted(config.connection_ids)))
    for target in targets:
        resolved = repository.get_connection_validation_target(tenant, target["id"])
        assert resolved.native_connection_settings_source == "clerk"
        assert resolved["credential_reference"] == target["credential_reference"]
        assert resolved["configuration"] == target["configuration"]
        assert resolved["declared_scopes"] == target["declared_scopes"]
    assert len(calls) == 6
    with psycopg.connect(DSN) as connection:
        connection.execute("UPDATE provider_connection SET declared_scopes=%s::jsonb "
                           "WHERE tenant_id=%s AND id=%s",
                           ('["aws.changed_scope"]', tenant, targets[0]["id"]))
    with pytest.raises(native.NativeConnectionSettingsUnavailable):
        repository.get_connection_validation_target(tenant, targets[0]["id"])
    # The failed read cannot mutate any saved authentication or setup state.
    with psycopg.connect(DSN, row_factory=dict_row) as connection:
        saved = connection.execute(
            "SELECT credential_reference,configuration FROM provider_connection "
            "WHERE tenant_id=%s AND id=%s", (tenant, targets[0]["id"]),
        ).fetchone()
    assert saved["credential_reference"] == targets[0]["credential_reference"]
    assert saved["configuration"] == targets[0]["configuration"]


def test_real_publication_holds_org_lock_through_ack_and_preserves_platform_namespace(monkeypatch):
    _repository, _tenant, _targets, config = records(monkeypatch)
    organization = {"id": config.organization_id, "private_metadata": {
        "transilience_connections": {"unrelated": True},
    }, "public_metadata": {}}

    def clerk(request):
        import json

        if request.method == "GET":
            return httpx.Response(200, json=copy.deepcopy(organization))
        with psycopg.connect(DSN, row_factory=dict_row) as connection:
            with pytest.raises(publisher.NativeSettingsPublicationUnavailable):
                publisher._configure_read_transaction(connection, config.organization_id)
        patch = json.loads(request.content)
        organization["private_metadata"][native.NATIVE_NAMESPACE] = (
            patch["private_metadata"][native.NATIVE_NAMESPACE]
        )
        return httpx.Response(200, json=organization)

    receipt = publisher.prepare_or_publish_native_settings(
        config.organization_id, publish=True, config=config, transport=httpx.MockTransport(clerk),
    )
    assert receipt["publication_acknowledged"] is True
    assert receipt["enrollment_count"] == 6
    assert organization["private_metadata"]["transilience_connections"] == {"unrelated": True}
