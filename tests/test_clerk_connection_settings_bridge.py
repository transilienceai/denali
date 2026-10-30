from __future__ import annotations

import json

import pytest

from denali.integrations import shared_connections_client as bridge


class SettingsReader:
    def __init__(self, result=None, *, error=None):
        self.result = {"items": []} if result is None else result
        self.error = error
        self.calls = []

    def list_connections(self, organization_id, *, providers):
        self.calls.append((organization_id, providers))
        if self.error:
            raise self.error
        return self.result


def settings_client(monkeypatch, reader):
    class NoMachineTokens:
        def __init__(self, **_options):
            self.m2m = self

        def create_token(self, **_options):
            pytest.fail("a settings lookup must not mint a Platform machine token")

    def no_platform_http(**_options):
        pytest.fail("a Clerk settings lookup must not call Platform")

    monkeypatch.setattr(bridge, "Clerk", NoMachineTokens)
    monkeypatch.setattr(bridge.httpx, "Client", no_platform_http)
    return bridge.SharedConnectionsClient(
        "https://platform.example", "test-machine-key",
        allowed_clerk_org_ids=frozenset({"org_server"}),
        connection_settings_reader=reader,
    )


@pytest.mark.parametrize(
    ("path", "providers"),
    [
        ("/v1/connections", {"aws", "github", "gcp", "azure", "entra", "azure_repos"}),
        ("/internal/v1/connections/jira", {"jira"}),
        ("/internal/v1/connections/google-workspace", {"google_workspace"}),
        ("/internal/v1/connections/azure-repos", {"azure_repos"}),
    ],
)
def test_settings_lists_go_directly_to_clerk(monkeypatch, path, providers):
    result = {"items": [{"id": "synthetic-id", "provider": "aws"}]}
    reader = SettingsReader(result)
    client = settings_client(monkeypatch, reader)
    assert client.request("GET", path, clerk_org_id="org_server") == result
    assert reader.calls == [("org_server", frozenset(providers))]


def test_empty_clerk_snapshot_is_authoritative(monkeypatch):
    reader = SettingsReader()
    client = settings_client(monkeypatch, reader)
    assert client.request("GET", "/v1/connections", clerk_org_id="org_server") == {"items": []}


def test_clerk_error_never_falls_back_or_discloses_diagnostics(monkeypatch):
    reader = SettingsReader(error=ValueError("private metadata must not escape"))
    client = settings_client(monkeypatch, reader)
    with pytest.raises(bridge.SharedConnectionsError) as caught:
        client.request("GET", "/v1/connections", clerk_org_id="org_server")
    assert caught.value.status_code == 502
    assert "private metadata" not in str(caught.value)
    assert caught.value.__cause__ is None


def test_org_allowlist_is_checked_before_clerk(monkeypatch):
    reader = SettingsReader()
    client = settings_client(monkeypatch, reader)
    with pytest.raises(bridge.SharedConnectionsError) as caught:
        client.request("GET", "/v1/connections", clerk_org_id="org_other")
    assert caught.value.status_code == 404
    assert reader.calls == []


def test_clerk_list_preserves_existing_response_bound(monkeypatch):
    reader = SettingsReader({"items": [{"display_name": "a" * 100}]})
    client = settings_client(monkeypatch, reader)
    with pytest.raises(bridge.SharedConnectionsError):
        client.request(
            "GET", "/internal/v1/connections/jira", clerk_org_id="org_server",
            max_response_bytes=50,
        )


@pytest.mark.parametrize("options", [{"expect_text": True}, {"payload": {"extra": True}}])
def test_clerk_list_rejects_unexpected_options(monkeypatch, options):
    reader = SettingsReader()
    client = settings_client(monkeypatch, reader)
    with pytest.raises(ValueError, match="connection-settings list options"):
        client.request("GET", "/v1/connections", clerk_org_id="org_server", **options)
    assert reader.calls == []


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("POST", "/internal/v1/connections/aws/11111111-1111-4111-8111-111111111111/credentials"),
        ("POST", "/internal/v1/connections/gcp/11111111-1111-4111-8111-111111111111/read"),
        ("GET", "/internal/v1/connections/google-workspace/config"),
        ("GET", "/internal/v1/connections/jira/11111111-1111-4111-8111-111111111111/status"),
    ],
)
def test_broker_operations_keep_using_platform(monkeypatch, method, path):
    requests = []

    class MachineClerk:
        def __init__(self, **_options):
            self.m2m = self

        def create_token(self, **_options):
            return type("Token", (), {"token": "synthetic-short-lived-token"})()

    class Client:
        def __init__(self, **_options):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def request(self, request_method, url, **options):
            requests.append((request_method, url, options))
            return type("Response", (), {"status_code": 200, "json": lambda _self: {"ok": True}})()

    monkeypatch.setattr(bridge, "Clerk", MachineClerk)
    monkeypatch.setattr(bridge.httpx, "Client", Client)
    reader = SettingsReader(error=AssertionError("broker operation must not read Clerk settings"))
    client = bridge.SharedConnectionsClient(
        "https://platform.example", "test-machine-key", connection_settings_reader=reader,
    )
    assert client.request(method, path, clerk_org_id="org_server") == {"ok": True}
    assert reader.calls == []
    assert requests[0][:2] == (method, "https://platform.example" + path)
    assert requests[0][2]["headers"]["Authorization"] == "Bearer synthetic-short-lived-token"


def test_environment_switch_is_explicit_and_preserves_legacy_default(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "https://platform.example")
    monkeypatch.setenv("DENALI_PLATFORM_MACHINE_SECRET_KEY", "synthetic-machine-key")
    monkeypatch.setenv("DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS", "org_server")
    monkeypatch.delenv("DENALI_CONNECTION_SETTINGS_SOURCE", raising=False)
    called = []
    reader = SettingsReader()
    monkeypatch.setattr(
        bridge.SharedConnectionsClient, "_settings_reader_from_environment",
        staticmethod(lambda: called.append(True) or reader),
    )
    legacy = bridge.SharedConnectionsClient.from_environment()
    assert legacy is not None and legacy._connection_settings_reader is None
    assert called == []
    monkeypatch.setenv("DENALI_CONNECTION_SETTINGS_SOURCE", "clerk")
    selected = bridge.SharedConnectionsClient.from_environment()
    assert selected is not None and selected._connection_settings_reader is reader
    assert called == [True]
    monkeypatch.setenv("DENALI_CONNECTION_SETTINGS_SOURCE", "unknown")
    with pytest.raises(ValueError, match="connection-settings source"):
        bridge.SharedConnectionsClient.from_environment()


def test_clerk_mode_cannot_silently_disable_the_existing_bridge(monkeypatch):
    monkeypatch.setenv("DENALI_CONNECTION_SETTINGS_SOURCE", "clerk")
    monkeypatch.delenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", raising=False)
    with pytest.raises(ValueError, match="existing shared-connections bridge"):
        bridge.SharedConnectionsClient.from_environment()


def test_reader_selection_matches_modal_environment_and_needs_its_own_key(monkeypatch):
    monkeypatch.setenv("MODAL_ENVIRONMENT", "denali-prod")
    monkeypatch.setenv("DENALI_CONNECTION_SETTINGS_ENVIRONMENT", "development")
    monkeypatch.setenv("CLERK_CONNECTION_SETTINGS_SECRET_KEY", "sk_test_synthetic")
    with pytest.raises(ValueError, match="environment differs"):
        bridge.SharedConnectionsClient._settings_reader_from_environment()

    monkeypatch.setenv("DENALI_CONNECTION_SETTINGS_ENVIRONMENT", "production")
    monkeypatch.setenv("CLERK_SECRET_KEY", "sk_live_synthetic")
    monkeypatch.delenv("CLERK_CONNECTION_SETTINGS_SECRET_KEY")
    with pytest.raises(ValueError, match="configuration invalid"):
        bridge.SharedConnectionsClient._settings_reader_from_environment()

    monkeypatch.setenv("CLERK_CONNECTION_SETTINGS_SECRET_KEY", "sk_live_synthetic")
    reader = bridge.SharedConnectionsClient._settings_reader_from_environment()
    assert reader.environment == "production"
    assert reader.app_id == "denali"


def test_request_serialization_never_contains_private_settings(monkeypatch):
    result = {"items": [{"id": "synthetic-id", "provider": "aws", "availability": "ready"}]}
    client = settings_client(monkeypatch, SettingsReader(result))
    encoded = json.dumps(client.request("GET", "/v1/connections", clerk_org_id="org_server"))
    assert "settings" not in encoded
    assert "external_id" not in encoded
    assert "role_arn" not in encoded
