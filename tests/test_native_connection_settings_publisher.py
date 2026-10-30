from __future__ import annotations

import copy
import json
from datetime import timedelta

import httpx
import pytest
from test_native_connection_settings import (
    IDS,
    NOW,
    ORG,
    TENANT,
    environment,
    native_targets,
    snapshot,
)
from test_native_connection_settings import (
    reader as native_reader,
)

from denali.integrations import native_connection_settings as native
from denali.integrations import native_connection_settings_publisher as publisher


def config(*, enabled=False):
    return publisher.NativePublisherConfig(
        ORG, frozenset(IDS), "development", "synthetic-unused-database",
        "sk_test_synthetic_native", enabled,
    )


class Database:
    def __init__(self, rows=None, *, locked=True):
        self.rows = native_targets() if rows is None else rows
        self.locked, self.open = locked, False
        self.queries = []

    def __enter__(self):
        self.open = True
        return self

    def __exit__(self, *_args):
        self.open = False

    def execute(self, query, parameters=()):
        self.queries.append((query, parameters))
        return self

    def fetchone(self):
        if "SELECT id FROM denali_tenant" in self.queries[-1][0]:
            return {"id": TENANT}
        if "SELECT clerk_organization_id" in self.queries[-1][0]:
            return {"clerk_organization_id": ORG}
        return {"locked": self.locked}

    def fetchall(self):
        return copy.deepcopy(self.rows)


def merge_patch(target, patch):
    for key, value in patch.items():
        if value is None:
            target.pop(key, None)
        elif isinstance(value, dict):
            if not isinstance(target.get(key), dict):
                target[key] = {}
            merge_patch(target[key], value)
        else:
            target[key] = copy.deepcopy(value)


class Clerk:
    def __init__(self, *, private=None, acknowledge=True, database=None):
        self.value = {"id": ORG, "private_metadata": private or {}, "public_metadata": {}}
        self.requests = []
        self.acknowledge, self.database = acknowledge, database

    def __call__(self, request):
        if self.database:
            assert self.database.open is True, "publisher must hold its org transaction until ACK"
        self.requests.append(request)
        assert request.url.host == "api.clerk.com"
        assert request.headers["Authorization"] == "Bearer sk_test_synthetic_native"
        if request.method == "GET":
            response = copy.deepcopy(self.value)
            self.value["private_metadata"]["concurrent_unrelated"] = {"preserve": True}
            return httpx.Response(200, json=response)
        assert request.method == "PATCH"
        patch = json.loads(request.content)
        assert set(patch) == {"private_metadata"}
        assert set(patch["private_metadata"]) == {native.NATIVE_NAMESPACE}
        if self.acknowledge:
            merge_patch(self.value, patch)
        return httpx.Response(200, json=self.value)


def test_disabled_publisher_needs_no_key_database_or_network(monkeypatch):
    monkeypatch.delenv("DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED", raising=False)
    assert publisher.NativePublisherConfig.from_environment({}) is None
    receipt = publisher.prepare_or_publish_native_settings("org_unused", publish=True,
        connection_factory=lambda *_a, **_k: pytest.fail("disabled publisher must not open DB"))
    assert receipt["enabled"] is False and receipt["write_attempted"] is False


def test_preflight_is_read_only_and_returns_no_identifier_or_credential_payload():
    database = Database()
    clerk = Clerk(database=database)
    receipt = publisher.prepare_or_publish_native_settings(
        ORG, config=config(), connection_factory=lambda *_a, **_k: database,
        transport=httpx.MockTransport(clerk), now=NOW,
    )
    assert receipt["ready"] is True
    assert receipt["enrollment_count"] == 6
    assert receipt["provider_count"] == 5
    assert receipt["combined_metadata_bytes"] <= 8192
    assert receipt["write_attempted"] is False
    assert receipt["publication_acknowledged"] is False
    assert receipt["provider_requests"] == 0
    assert len(receipt["binding_digest"]) == 64
    encoded = json.dumps(receipt)
    for forbidden in ("role_arn", "external_id", "credential_reference", "123456789012",
                      ORG, TENANT, IDS[0], "sk_test_"):
        assert forbidden not in encoded
    assert [request.method for request in clerk.requests] == ["GET"]
    assert any("REPEATABLE READ READ ONLY" in query for query, _ in database.queries)
    assert any("pg_try_advisory_xact_lock" in query for query, _ in database.queries)
    raw_query = next(query for query, _ in database.queries if "jsonb_each" in query)
    assert "SELECT *" not in raw_query and "c.*" not in raw_query
    for forbidden in ("pkce_verifier", "setup_token_sha256", "operator_credential_profile"):
        assert forbidden not in str(database.queries)


def test_publication_replaces_owned_arrays_preserves_other_namespaces_and_checks_ack():
    old = snapshot()
    old["sources"]["aws"].append({"id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"})
    old["obsolete_field"] = "remove"
    database = Database()
    clerk = Clerk(private={native.NATIVE_NAMESPACE: old,
                           "transilience_connections": {"Platform-owned": True},
                           "other": {"keep": "unchanged"}}, database=database)
    receipt = publisher.prepare_or_publish_native_settings(
        ORG, publish=True, config=config(enabled=True),
        connection_factory=lambda *_a, **_k: database,
        transport=httpx.MockTransport(clerk), now=NOW,
    )
    assert receipt["publication_acknowledged"] is True
    assert [request.method for request in clerk.requests] == ["GET", "PATCH"]
    private = clerk.value["private_metadata"]
    assert private["transilience_connections"] == {"Platform-owned": True}
    assert private["other"] == {"keep": "unchanged"}
    assert private["concurrent_unrelated"] == {"preserve": True}
    document = private[native.NATIVE_NAMESPACE]
    assert "obsolete_field" not in document
    assert len(document["sources"]["aws"]) == 2
    for record in document["sources"]["aws"]:
        assert record["id"] in IDS


def test_preflight_distinguishes_proposed_readiness_from_saved_snapshot_freshness():
    document = snapshot()
    database = Database()
    clerk = Clerk(private={native.NATIVE_NAMESPACE: document}, database=database)
    receipt = publisher.prepare_or_publish_native_settings(
        ORG, config=config(), connection_factory=lambda *_a, **_k: database,
        transport=httpx.MockTransport(clerk), now=NOW + timedelta(seconds=60),
    )
    assert receipt["ready"] is True
    assert receipt["existing_snapshot_present"] is True
    assert receipt["existing_snapshot_fresh"] is True
    assert receipt["existing_binding_parity"] is True
    assert receipt["existing_published_age_seconds"] == 60
    assert receipt["existing_expires_in_seconds"] == 240
    assert len(receipt["existing_revision_digest"]) == 64
    assert receipt["write_attempted"] is False
    expired = publisher.prepare_or_publish_native_settings(
        ORG, config=config(), connection_factory=lambda *_a, **_k: database,
        transport=httpx.MockTransport(clerk), now=NOW + timedelta(seconds=301),
    )
    assert expired["ready"] is True
    assert expired["existing_snapshot_present"] is True
    assert expired["existing_snapshot_fresh"] is False
    assert expired["existing_binding_parity"] is False
    assert "existing_revision_digest" not in expired
    assert all(request.method == "GET" for request in clerk.requests)


def test_incomplete_native_identifiers_stop_preflight_before_clerk_access():
    rows = native_targets()
    next(row for row in rows if row["provider"] == "gcp")["configuration"]["projects"] = []
    database = Database(rows)
    clerk = Clerk(database=database)
    with pytest.raises(publisher.NativeSettingsPublicationUnavailable):
        publisher.prepare_or_publish_native_settings(
            ORG, config=config(), connection_factory=lambda *_a, **_k: database,
            transport=httpx.MockTransport(clerk), now=NOW,
        )
    assert clerk.requests == []


def test_publish_with_read_only_config_does_not_open_database_or_clerk():
    result = publisher.prepare_or_publish_native_settings(
        ORG, publish=True, config=config(),
        connection_factory=lambda *_a, **_k: pytest.fail("explicit publication flag is mandatory"),
    )
    assert result["enabled"] is False


@pytest.mark.parametrize("failure", ["wrong-org", "missing-id", "shared", "different-tenant",
                                      "lock", "budget", "ack"])
def test_publication_failures_do_not_claim_success(failure):
    rows = native_targets()
    database = Database(rows, locked=failure != "lock")
    private = {"unrelated": "x" * 8192} if failure == "budget" else {}
    clerk = Clerk(private=private, database=database, acknowledge=failure != "ack")
    if failure == "missing-id":
        rows.pop()
    if failure == "shared":
        rows[0]["credential_type"] = "platform_shared_aws"
    if failure == "different-tenant":
        rows[0]["tenant_id"] = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    with pytest.raises(publisher.NativeSettingsPublicationUnavailable,
                       match="^native connection settings publication unavailable$"):
        publisher.prepare_or_publish_native_settings(
            "org_OtherSynthetic" if failure == "wrong-org" else ORG,
            publish=True, config=config(enabled=True),
            connection_factory=lambda *_a, **_k: database,
            transport=httpx.MockTransport(clerk), now=NOW,
        )
    if failure != "ack":
        assert all(request.method != "PATCH" for request in clerk.requests)


def test_preflight_stages_publication_before_consumer_cutover():
    env = {**environment(source="database"), "DENALI_DSN": "synthetic-unused"}
    result = publisher.NativePublisherConfig.from_environment(env, require_enabled=False)
    assert result.organization_id == ORG and result.publication_enabled is False
    assert publisher.NativePublisherConfig.from_environment(env) is None
    result = publisher.NativePublisherConfig.from_environment({
        **env, "DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED": "true",
    })
    assert result.publication_enabled is True
    assert result.secret_key == env["CLERK_SECRET_KEY"]
    with pytest.raises(publisher.NativeSettingsPublicationUnavailable):
        publisher.NativePublisherConfig.from_environment(
            {**env, "MODAL_ENVIRONMENT": "unrecognized-modal-environment"}, require_enabled=False,
        )


@pytest.mark.parametrize("failure", ["deleted", "malformed", "all-deleted", "scalar"])
def test_steady_publication_isolates_missing_or_invalid_records(monkeypatch, failure):
    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE", "clerk")
    rows = native_targets()
    if failure == "deleted":
        rows.pop(0)
    elif failure == "malformed":
        rows[0]["configuration"]["selected_resource"] = None
    elif failure == "scalar":
        rows[0]["credential_reference"] = []
    else:
        rows = []
    database = Database(rows)
    clerk = Clerk(database=database)
    receipt = publisher.prepare_or_publish_native_settings(
        ORG, publish=True, config=config(enabled=True),
        connection_factory=lambda *_a, **_k: database,
        transport=httpx.MockTransport(clerk), now=NOW,
    )
    published = 0 if failure == "all-deleted" else 5
    assert receipt["partial"] is True and receipt["ready"] is False
    assert receipt["published_connection_count"] == published
    assert receipt["enrollment_count"] == published
    assert receipt["omitted_connection_count"] == 6 - published
    assert receipt["publication_acknowledged"] is True
    if failure in {"deleted", "all-deleted"}:
        assert receipt["missing_connection_count"] == 6 - published
    else:
        assert receipt["invalid_connection_count"] == 1
    document = clerk.value["private_metadata"][native.NATIVE_NAMESPACE]
    client, _ = native_reader(document)
    if published:
        resolved = client.resolve(TENANT, native_targets()[1])
        assert resolved.native_connection_settings_source == "clerk"
    with pytest.raises(native.NativeConnectionSettingsUnavailable):
        client.resolve(TENANT, native_targets()[0])


def test_steady_budget_omits_largest_whole_record_without_truncation(monkeypatch):
    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE", "clerk")
    rows = native_targets()
    github = next(row for row in rows if row["provider"] == "github")
    repositories = [{"id": 10**12 + index} for index in range(500)]
    github["configuration"]["repositories"] = repositories
    database = Database(rows)
    clerk = Clerk(private={"other": "x" * 1200}, database=database)
    receipt = publisher.prepare_or_publish_native_settings(
        ORG, publish=True, config=config(enabled=True),
        connection_factory=lambda *_a, **_k: database,
        transport=httpx.MockTransport(clerk), now=NOW,
    )
    assert receipt["budget_omitted_connection_count"] == 1
    assert receipt["published_connection_count"] == 5 and receipt["partial"] is True
    assert receipt["combined_metadata_bytes"] <= 8192
    document = clerk.value["private_metadata"][native.NATIVE_NAMESPACE]
    assert "github" not in document["sources"]
    assert len(document["sources"]["aws"]) == 2
    assert github["configuration"]["repositories"] == repositories
    assert clerk.value["private_metadata"]["other"] == "x" * 1200


def test_postcommit_publication_is_scoped_and_closes_tenant_read_first():
    env = {**environment(), "DENALI_DSN": config().database_url,
           "DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED": "true"}
    database = Database()
    calls = []

    def publish(organization_id, **options):
        assert database.open is False
        assert organization_id == ORG and options["publish"] is True
        calls.append(organization_id)

    publisher.publish_after_native_identifier_write(TENANT, IDS[0], config().database_url,
        environ=env, connection_factory=lambda *_a, **_k: database, publish=publish)
    assert calls == [ORG]
    cases = (({"DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE": "database"}, IDS[0]),
             ({"DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED": "false"}, IDS[0]),
             ({}, "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"))
    for change, connection_id in cases:
        publisher.publish_after_native_identifier_write(
            TENANT, connection_id, config().database_url,
            environ={**env, **change}, connection_factory=lambda *_a, **_k: pytest.fail("read DB"),
            publish=lambda *_a, **_k: pytest.fail("published outside selected path"))


def test_postcommit_publication_failure_is_fixed_without_provider_or_health_mutation():
    env = {**environment(), "DENALI_DSN": config().database_url,
           "DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED": "true"}
    database = Database()

    def failed(*_args, **_options):
        raise RuntimeError("private-provider-payload")

    with pytest.raises(native.NativeConnectionSettingsUnavailable,
                       match="^native connection settings unavailable$"):
        publisher.publish_after_native_identifier_write(TENANT, IDS[0], config().database_url,
            environ=env, connection_factory=lambda *_a, **_k: database, publish=failed)
    assert all("UPDATE" not in sql and "INSERT" not in sql for sql, _ in database.queries)


def test_operator_manifest_selects_and_returns_ids_only():
    database = Database()
    env = {**environment(), "DENALI_DSN": "synthetic-unused"}
    result = publisher.native_settings_manifest(
        ORG, environ=env, connection_factory=lambda *_a, **_k: database,
    )
    assert result["ready_for_six_enrollment"] is True
    assert len(result["items"]) == 6
    assert set(result["items"][0]) == {"id", "provider", "credential_type", "lifecycle_state"}
    assert all("credential_reference" not in query for query, _ in database.queries)
    with pytest.raises(publisher.NativeSettingsPublicationUnavailable):
        publisher.native_settings_manifest("org_OtherSynthetic", environ=env)


def test_verify_uses_real_consumer_contract_after_raw_database_read_closes(monkeypatch):
    database = Database()
    document = snapshot()
    clerk = Clerk(private={native.NATIVE_NAMESPACE: document})
    captured = []

    class Repository:
        def __init__(self, dsn):
            assert dsn == config().database_url

        def get_connection_validation_target(self, tenant_id, connection_id):
            assert database.open is False
            captured.append((tenant_id, connection_id))
            target = next(row for row in native_targets() if row["id"] == connection_id)
            reader = native.NativeConnectionSettingsReader(
                config().secret_key, "development",
                client=httpx.Client(transport=httpx.MockTransport(clerk)), now=lambda: NOW,
            )
            return reader.resolve(tenant_id, target)

    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE", "clerk")
    monkeypatch.setattr(publisher, "datetime", type("Clock", (), {
        "now": staticmethod(lambda _tz: NOW),
    }))
    original_validator = publisher.validate_native_snapshot
    monkeypatch.setattr(publisher, "validate_native_snapshot", lambda value, org, env:
                        original_validator(value, org, env, now=NOW))
    receipt = publisher.verify_native_settings_lookup(
        ORG, config=config(), connection_factory=lambda *_a, **_k: database,
        repository_factory=Repository, transport=httpx.MockTransport(clerk),
    )
    assert len(captured) == 6
    assert receipt["source_used_count"] == 6
    assert receipt["binding_parity"] is True
    assert receipt["health_counts"] == {"healthy": 6}
    assert receipt["provider_requests"] == 0 and receipt["write_attempted"] is False
    assert all(request.method == "GET" for request in clerk.requests)
