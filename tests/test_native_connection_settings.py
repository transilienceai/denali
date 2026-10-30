from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from denali.integrations import native_connection_settings as native
from denali.store.repository import PostgresInventoryRepository

NOW = datetime(2026, 11, 2, tzinfo=UTC)
ORG = "org_NativeSynthetic"
TENANT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
IDS = [f"{index:08d}-1111-4111-8111-111111111111" for index in range(1, 7)]
CLIENT = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
SUBSCRIPTION = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"


def native_targets():
    def target(index, provider, reference, configuration):
        return {
            "id": IDS[index], "tenant_id": TENANT, "clerk_organization_id": ORG,
            "provider": provider, "credential_type": native.NATIVE_CREDENTIAL_TYPES[provider],
            "credential_reference": {**reference, "setup_token_sha256": "0" * 64},
            "configuration": {**configuration, "onboarding": {
                "completed_at": NOW.isoformat(), "status": "complete",
            }},
            "declared_scopes": [provider + ".existing_scope"],
            "coverage_plan": [{"state": "existing-database-authority"}],
            "lifecycle_state": "active", "health_state": "healthy",
        }

    aws_reference = {
        "role_arn": "arn:aws:iam::123456789012:role/SyntheticNative",
        "external_id": "synthetic-external-id",
    }
    aws_configuration = {
        "account_id": "123456789012", "partition": "aws", "regions": ["us-east-1"],
        "coverage_mode": "selected", "deployment_region": "us-east-1",
        "role_name": "SyntheticNative", "stack_scopes": ["existing-database-scope"],
    }
    return [
        target(0, "aws", aws_reference, aws_configuration),
        target(1, "aws", {**aws_reference, "external_id": "second-synthetic-id"},
               aws_configuration),
        target(2, "gcp", {
            "principal_email": "reader@example-project.iam.gserviceaccount.com",
            "principal_unique_id": "112233445566778899001",
            "operator_project_id": "example-project",
            "operator_credential_profile": "native_gcp_wif_v1",
        }, {"projects": [{"id": "example-project", "name": "Existing display label"}]}),
        target(3, "github", {
            "app_id": 123, "app_slug": "synthetic-native", "installation_id": 456,
            "pkce_verifier": "synthetic",
        }, {
            "account_id": 789, "account_login": "example",
            "repositories": [{"id": 101, "full_name": "example/repository", "private": True}],
        }),
        target(4, "azure", {"client_id": CLIENT, "service_principal_id": CLIENT}, {
            "tenant_id": CLIENT, "subscriptions": [{"id": SUBSCRIPTION, "name": "Existing"}],
        }),
        target(5, "entra", {"client_id": CLIENT}, {"tenant_id": CLIENT}),
    ]


def environment(source="clerk"):
    return {
        "DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE": source,
        "DENALI_NATIVE_CONNECTION_SETTINGS_ENVIRONMENT": "development",
        "DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS": ORG,
        "DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CONNECTION_IDS": ",".join(IDS),
        "CLERK_SECRET_KEY": "sk_test_synthetic_native",
        "MODAL_ENVIRONMENT": "denali-dev",
    }


def snapshot(targets=None):
    return native.build_native_snapshot(
        TENANT, ORG, targets or native_targets(), "development", now=NOW,
        revision="dddddddd-dddd-4ddd-8ddd-dddddddddddd",
    )


def reader(document=None, *, returned_org=ORG, response=None, before_request=None):
    calls = []
    document = snapshot() if document is None else document

    def handle(request):
        if before_request:
            before_request()
        calls.append(request)
        assert request.method == "GET"
        assert str(request.url) == "https://api.clerk.com/v1/organizations/" + ORG
        assert request.headers["Authorization"] == "Bearer sk_test_synthetic_native"
        return response if response is not None else httpx.Response(200, json={
            "id": returned_org, "private_metadata": {
                native.NATIVE_NAMESPACE: document,
                "transilience_connections": {"unrelated": "Platform-owned"},
                "other": "must-not-return",
            },
        })

    return native.NativeConnectionSettingsReader(
        "sk_test_synthetic_native", "development",
        client=httpx.Client(transport=httpx.MockTransport(handle)), now=lambda: NOW,
    ), calls


def test_projection_contains_only_stable_ids_and_preserves_operator_and_setup_state():
    targets = native_targets()
    document = snapshot(targets)
    encoded = json.dumps(document)
    for forbidden in ("setup_token_sha256", "pkce_verifier", "operator_credential_profile",
                      "operator_project_id", "onboarding", "stack_scopes", "full_name"):
        assert forbidden not in encoded
    assert native.project_native_settings(targets[2])["project_ids"] == ["example-project"]
    assert native.project_native_settings(targets[3])["repository_ids"] == [101]
    client, calls = reader(document)
    for original in targets:
        resolved = client.resolve(TENANT, original)
        assert resolved is not original
        assert resolved.native_connection_settings_source == "clerk"
        assert dict(resolved) == original
        assert "native_connection_settings_source" not in json.dumps(resolved)
    assert len(calls) == 6
    assert native_targets() == targets


def test_same_provider_multiple_connections_remain_distinct():
    document = snapshot()
    assert len(document["sources"]["aws"]) == 2
    client, _ = reader(document)
    result = client.resolve(TENANT, native_targets()[1])
    assert result["credential_reference"]["external_id"] == "second-synthetic-id"


@pytest.mark.parametrize("failure", [
    "missing", "wrong-org", "wrong-environment", "wrong-version", "wrong-source",
    "expired", "future", "long-lifetime", "wrong-id", "wrong-provider", "hash",
    "changed-setting", "unknown-field", "secret-setting", "duplicate", "wrong-revision",
])
def test_selected_native_metadata_errors_fail_closed(failure):
    document = snapshot()
    record = document["sources"]["aws"][0]
    if failure == "missing":
        document["sources"] = {}
    elif failure == "wrong-org":
        document["organization_id"] = "org_OtherSynthetic"
    elif failure == "wrong-environment":
        document["environment"] = "production"
    elif failure == "wrong-version":
        document["version"] = 2
    elif failure == "wrong-source":
        document["source_app_id"] = "platform"
    elif failure == "expired":
        document["expires_at"] = NOW.isoformat()
    elif failure == "future":
        document["published_at"] = (NOW + timedelta(seconds=1)).isoformat()
    elif failure == "long-lifetime":
        document["expires_at"] = (NOW + timedelta(seconds=301)).isoformat()
    elif failure == "wrong-id":
        record["id"] = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
    elif failure == "wrong-provider":
        document["sources"]["azure"] += document["sources"].pop("aws")
    elif failure == "hash":
        record["binding_sha256"] = "0" * 64
    elif failure == "changed-setting":
        record["settings"]["external_id"] = "cannot-retarget"
    elif failure == "unknown-field":
        record["settings"]["unrecognized"] = "not-allowed"
    elif failure == "secret-setting":
        record["settings"]["private_key"] = "synthetic-not-a-key"
    elif failure == "duplicate":
        document["sources"]["aws"].append(copy.deepcopy(record))
    elif failure == "wrong-revision":
        document["revision"] = "not-a-uuid"
    client, calls = reader(document)
    with pytest.raises(native.NativeConnectionSettingsUnavailable,
                       match="^native connection settings unavailable$"):
        client.resolve(TENANT, native_targets()[0])
    assert len(calls) == 1


def test_database_scope_or_target_change_fences_an_old_snapshot():
    client, _ = reader()
    for mutation in ("scope", "id", "tenant", "reference", "type"):
        target = native_targets()[0]
        tenant = TENANT
        if mutation == "scope":
            target["declared_scopes"].append("aws.another_scope")
        elif mutation == "id":
            target["id"] = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        elif mutation == "tenant":
            tenant = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"
        elif mutation == "reference":
            target["credential_reference"]["external_id"] = "changed-by-native-control-plane"
        elif mutation == "type":
            target["credential_type"] = "platform_shared_aws"
        with pytest.raises(native.NativeConnectionSettingsUnavailable):
            client.resolve(tenant, target)


@pytest.mark.parametrize("response", [
    httpx.Response(302, headers={"Location": "https://untrusted.example"}),
    httpx.Response(200, content=b"{}", headers={"Content-Type": "text/plain"}),
    httpx.Response(200, json={"id": ORG, "private_metadata": {}}),
    httpx.Response(200, content=b" " * 65537, headers={"Content-Type": "application/json"}),
])
def test_transport_and_missing_namespace_never_trigger_provider_or_database_fallback(response):
    client, _ = reader(response=response)
    with pytest.raises(native.NativeConnectionSettingsUnavailable):
        client.resolve(TENANT, native_targets()[0])


def test_clerk_object_org_is_bound_before_reading_native_namespace():
    client, _ = reader(returned_org="org_OtherSynthetic")
    with pytest.raises(native.NativeConnectionSettingsUnavailable):
        client.resolve(TENANT, native_targets()[0])


def test_default_other_org_unselected_shared_and_inactive_paths_remain_database_only():
    def forbidden_factory(*_args):
        pytest.fail("an unselected path must not read Clerk")

    original = native_targets()[0]
    assert native.resolve_native_connection_settings(
        TENANT, original, environ={}, reader_factory=forbidden_factory,
    ) is original
    for change in ({"clerk_organization_id": "org_OtherSynthetic"},
                   {"id": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"},
                   {"credential_type": "platform_shared_aws"}, {"lifecycle_state": "disabled"}):
        target = {**original, **change}
        assert native.resolve_native_connection_settings(
            TENANT, target, environ=environment(), reader_factory=forbidden_factory,
        ) is target

    # Even broken selected-org enrollment must not affect another organization.
    other = {**original, "clerk_organization_id": "org_OtherSynthetic"}
    assert native.resolve_native_connection_settings(
        TENANT, other, environ={**environment(),
            "DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CONNECTION_IDS": "invalid"},
        reader_factory=forbidden_factory,
    ) is other


@pytest.mark.parametrize("provider,missing", [
    ("aws", "role_arn"), ("gcp", "project_ids"), ("azure", "subscription_ids"),
    ("github", "installation_id"), ("entra", "client_id"),
])
def test_incomplete_identifier_projection_cannot_be_certified(provider, missing):
    target = next(item for item in native_targets() if item["provider"] == provider)
    settings = native.project_native_settings(target)
    settings.pop(missing)
    document = snapshot()
    record = next(record for record in document["sources"][provider]
                  if record["id"] == target["id"])
    record["settings"] = settings
    with pytest.raises(native.NativeConnectionSettingsUnavailable):
        native.validate_native_snapshot(document, ORG, "development", now=NOW)


def test_native_alias_is_only_its_existing_backend_key_and_environment_is_exact():
    client, _ = reader()
    seen = []

    def factory(key, selected_environment):
        seen.append((key, selected_environment))
        return client

    target = native_targets()[0]
    native.resolve_native_connection_settings(TENANT, target, environ=environment(),
                                              reader_factory=factory)
    assert seen == [("sk_test_synthetic_native", "development")]
    for change in (
        {"CLERK_SECRET_KEY": "sk_live_synthetic"},
        {"MODAL_ENVIRONMENT": "denali-prod"},
        {"DENALI_NATIVE_CONNECTION_SETTINGS_ENVIRONMENT": "unknown"},
        {"DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE": "unknown"},
        {"DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CONNECTION_IDS": IDS[0]},
        {"DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS": ORG + ",org_OtherSynthetic"},
    ):
        with pytest.raises(native.NativeConnectionSettingsUnavailable):
            native.resolve_native_connection_settings(
                TENANT, target, environ={**environment(), **change}, reader_factory=factory,
            )


def test_real_repository_consumer_hook_runs_after_scoped_database_context_closed(monkeypatch):
    state = {"open": False}
    target = native_targets()[0]

    class Database:
        def __enter__(self):
            state["open"] = True
            return self

        def __exit__(self, *_args):
            state["open"] = False

        def execute(self, sql, parameters):
            assert "c.tenant_id = %s::uuid AND c.id = %s::uuid" in sql
            assert parameters == (TENANT, IDS[0])
            return self

        def fetchone(self):
            return copy.deepcopy(target)

    def before_request():
        assert state["open"] is False

    client, calls = reader(before_request=before_request)
    for name, value in environment().items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr("denali.store.repository.psycopg.connect", lambda *_a, **_k: Database())
    monkeypatch.setattr(native, "NativeConnectionSettingsReader", lambda *_a, **_k: client)
    resolved = PostgresInventoryRepository("synthetic-unused").get_connection_validation_target(
        TENANT, IDS[0],
    )
    assert resolved.native_connection_settings_source == "clerk"
    assert len(calls) == 1
    assert resolved["declared_scopes"] == target["declared_scopes"]
    assert resolved["configuration"]["onboarding"] == target["configuration"]["onboarding"]


def test_missing_tenant_scoped_row_never_queries_clerk(monkeypatch):
    class Database:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def execute(self, _sql, parameters):
            assert parameters == (TENANT, IDS[0])
            return self

        def fetchone(self):
            return None

    monkeypatch.setattr("denali.store.repository.psycopg.connect", lambda *_a, **_k: Database())
    monkeypatch.setattr(native, "resolve_native_connection_settings",
                        lambda *_a, **_k: pytest.fail("no row is not a Clerk lookup"))
    assert PostgresInventoryRepository("synthetic-unused").get_connection_validation_target(
        TENANT, IDS[0],
    ) is None
