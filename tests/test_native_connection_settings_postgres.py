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


def test_real_repository_hook_preserves_native_auth_data_and_uses_live_scope(monkeypatch):
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
    resolved = repository.get_connection_validation_target(tenant, targets[0]["id"])
    assert resolved["declared_scopes"] == ["aws.changed_scope"]
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


def test_real_postcommit_gcp_setup_publishes_before_immediate_consumer_read(monkeypatch):
    import json

    from test_native_connection_settings_publisher import merge_patch

    repository, tenant, targets, config = records(monkeypatch)
    gcp = next(target for target in targets if target["provider"] == "gcp")
    now = datetime.now(UTC)
    organization = {"id": config.organization_id, "private_metadata": {
        native.NATIVE_NAMESPACE: native.build_native_snapshot(
            tenant, config.organization_id, targets, "development", now=now,
        ),
    }, "public_metadata": {}}
    requests = []

    def clerk(request):
        requests.append(request.method)
        # A separate session must already see the completed write before HTTP.
        with psycopg.connect(DSN, row_factory=dict_row) as connection:
            saved = connection.execute(
                "SELECT configuration FROM provider_connection WHERE tenant_id=%s AND id=%s",
                (tenant, gcp["id"]),
            ).fetchone()
        assert saved["configuration"]["projects"][0]["id"] == "new-example-project"
        if request.method == "PATCH":
            merge_patch(organization, json.loads(request.content))
        return httpx.Response(200, json=copy.deepcopy(organization))

    transport = httpx.MockTransport(clerk)
    original_publish = publisher.prepare_or_publish_native_settings
    monkeypatch.setattr(publisher, "prepare_or_publish_native_settings", lambda *args, **options:
        original_publish(*args, **options, transport=transport))
    original_reader = native.NativeConnectionSettingsReader
    monkeypatch.setattr(native, "NativeConnectionSettingsReader", lambda key, environment:
        original_reader(key, environment, client=httpx.Client(transport=transport)))
    for name, value in {
        "DENALI_DSN": DSN,
        "DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE": "clerk",
        "DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED": "true",
        "DENALI_NATIVE_CONNECTION_SETTINGS_ENVIRONMENT": "development",
        "MODAL_ENVIRONMENT": "denali-dev", "CLERK_SECRET_KEY": config.secret_key,
        "DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS": config.organization_id,
        "DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CONNECTION_IDS":
            ",".join(sorted(config.connection_ids)),
    }.items():
        monkeypatch.setenv(name, value)
    changed = repository.complete_gcp_connection_setup(
        tenant, gcp["id"], expected_setup_token_sha256="0" * 64,
        projects=[{"id": "new-example-project", "name": "Database display label"}],
        coverage_plan=[], completed_at=now,
    )
    assert changed is not None
    resolved = repository.get_connection_validation_target(tenant, gcp["id"])
    assert resolved.native_connection_settings_source == "clerk"
    assert resolved["configuration"]["projects"][0]["id"] == "new-example-project"
    assert resolved["credential_reference"]["operator_credential_profile"] == "native_gcp_wif_v1"
    assert requests == ["GET", "PATCH", "GET"]
    # Existing setup transition, never a provider failure caused by publication.
    assert changed["health_state"] == "unknown"
    with psycopg.connect(DSN) as connection:
        assert connection.execute(
            "SELECT count(*) FROM connection_validation_job WHERE tenant_id=%s", (tenant,),
        ).fetchone()[0] == 0


def test_real_steady_sql_omits_deleted_and_scalar_rows_without_stalling_other_bindings(monkeypatch):
    import json

    from test_native_connection_settings_publisher import merge_patch

    repository, tenant, targets, config = records(monkeypatch)
    repository.disable_connection(tenant, targets[0]["id"])
    assert repository.delete_connection(tenant, targets[0]["id"]) == "deleted"
    with psycopg.connect(DSN) as connection:
        connection.execute(
            "UPDATE provider_connection SET credential_reference='[]'::jsonb "
            "WHERE tenant_id=%s AND id=%s", (tenant, targets[1]["id"]),
        )
    organization = {"id": config.organization_id, "private_metadata": {}, "public_metadata": {}}

    def clerk(request):
        if request.method == "PATCH":
            merge_patch(organization, json.loads(request.content))
        return httpx.Response(200, json=copy.deepcopy(organization))

    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE", "clerk")
    receipt = publisher.prepare_or_publish_native_settings(
        config.organization_id, publish=True, config=config, transport=httpx.MockTransport(clerk),
    )
    assert receipt["publication_acknowledged"] is True
    assert receipt["missing_connection_count"] == receipt["invalid_connection_count"] == 1
    assert receipt["published_connection_count"] == 4 and receipt["partial"] is True
    snapshot = organization["private_metadata"][native.NATIVE_NAMESPACE]
    assert "aws" not in snapshot["sources"]
    assert set(snapshot["sources"]) == {"gcp", "github", "azure", "entra"}


def test_callback_commit_survives_publication_failure_and_cannot_replay_consumed_state(monkeypatch):
    repository, tenant, targets, _config = records(monkeypatch)
    github = next(target for target in targets if target["provider"] == "github")
    with psycopg.connect(DSN) as connection:
        connection.execute(
            "UPDATE provider_connection SET credential_reference="
            "credential_reference || jsonb_build_object('install_state_sha256',%s::text) "
            "WHERE tenant_id=%s AND id=%s", ("0" * 64, tenant, github["id"]),
        )

    def unavailable(*_args):
        raise native.NativeConnectionSettingsUnavailable()

    monkeypatch.setattr(repository, "_publish_native_identifier_write", unavailable)
    options = {
        "expected_install_state_sha256": "0" * 64, "installation_id": 987,
        "oauth": {"state_sha256": "f" * 64, "pkce_verifier": "synthetic-new-state",
                  "expires_at": datetime.now(UTC).isoformat()},
    }
    with pytest.raises(native.NativeConnectionSettingsUnavailable):
        repository.record_github_install_return(tenant, github["id"], **options)
    with psycopg.connect(DSN, row_factory=dict_row) as connection:
        saved = connection.execute(
            "SELECT credential_reference,health_state FROM provider_connection "
            "WHERE tenant_id=%s AND id=%s", (tenant, github["id"]),
        ).fetchone()
        jobs = connection.execute(
            "SELECT count(*) AS count FROM connection_validation_job WHERE tenant_id=%s", (tenant,),
        ).fetchone()
    assert "install_state_sha256" not in saved["credential_reference"]
    assert saved["credential_reference"]["installation_id"] == 987
    assert saved["credential_reference"]["oauth_state_sha256"] == "f" * 64
    assert saved["health_state"] == "unknown" and jobs["count"] == 0
    assert repository.record_github_install_return(tenant, github["id"], **options) is None


@pytest.mark.parametrize("release", [True, False])
def test_postcommit_lock_wait_is_bounded_and_never_changes_jobs_or_health(monkeypatch, release):
    import json
    from threading import Event, Thread
    from time import monotonic

    from test_native_connection_settings_publisher import merge_patch

    _repository, tenant, targets, config = records(monkeypatch)
    env = {
        "DENALI_DSN": DSN, "CLERK_SECRET_KEY": config.secret_key,
        "MODAL_ENVIRONMENT": "denali-dev",
        "DENALI_NATIVE_CONNECTION_SETTINGS_ENVIRONMENT": "development",
        "DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE": "clerk",
        "DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED": "true",
        "DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS": config.organization_id,
        "DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CONNECTION_IDS":
            ",".join(sorted(config.connection_ids)),
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    waiting, released = Event(), Event()
    organization = {"id": config.organization_id, "private_metadata": {}, "public_metadata": {}}
    requests = []

    def clerk(request):
        requests.append(request.method)
        assert released.is_set()
        if request.method == "PATCH":
            merge_patch(organization, json.loads(request.content))
        return httpx.Response(200, json=copy.deepcopy(organization))

    class Connection:
        def __init__(self, *args, **options):
            self.connection = psycopg.connect(*args, **options)

        def __enter__(self):
            self.connection.__enter__()
            return self

        def __exit__(self, *args):
            return self.connection.__exit__(*args)

        def execute(self, query, parameters=()):
            if "SELECT pg_advisory_xact_lock" in query:
                waiting.set()
            return self.connection.execute(query, parameters)

    def publish(*args, **options):
        assert options["_post_commit_lock"] is True
        return publisher.prepare_or_publish_native_settings(
            *args, **options, connection_factory=Connection, transport=httpx.MockTransport(clerk),
        )

    with psycopg.connect(DSN, row_factory=dict_row) as locker:
        publisher._configure_read_transaction(locker, config.organization_id)

        def unlock():
            if waiting.wait(timeout=2):
                released.set()
                locker.commit()

        thread = Thread(target=unlock) if release else None
        if thread:
            thread.start()
        started = monotonic()
        if release:
            publisher.publish_after_native_identifier_write(
                tenant, targets[0]["id"], DSN, environ=env, publish=publish,
            )
            thread.join(timeout=2)
            assert released.is_set() and requests == ["GET", "PATCH"]
            assert monotonic() - started < 3
        else:
            with pytest.raises(native.NativeConnectionSettingsUnavailable,
                               match="^native connection settings unavailable$"):
                publisher.publish_after_native_identifier_write(
                    tenant, targets[0]["id"], DSN, environ=env, publish=publish,
                )
            assert 2.5 <= monotonic() - started < 5
            assert requests == []
    with psycopg.connect(DSN, row_factory=dict_row) as connection:
        states = connection.execute(
            "SELECT health_state FROM provider_connection WHERE tenant_id=%s", (tenant,),
        ).fetchall()
        jobs = connection.execute(
            "SELECT count(*) AS count FROM connection_validation_job WHERE tenant_id=%s", (tenant,),
        ).fetchone()
    assert all(row["health_state"] == "unknown" for row in states) and len(states) == 6
    assert jobs["count"] == 0
