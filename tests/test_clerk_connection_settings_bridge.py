from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from denali.integrations import shared_connections_client as bridge
from denali.integrations.clerk_connection_settings import (
    ClerkConnectionSettingsReader,
    ConnectionSettingsUnavailable,
)


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
    monkeypatch.setattr(bridge, "_BOUNDED_RPC_SLOTS", threading.BoundedSemaphore(8))
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
        connection_settings_org_ids=frozenset({"org_server"}),
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
    assert caught.value.__context__ is None


@pytest.mark.parametrize("error,code", [
    (ConnectionSettingsUnavailable(), "snapshot_unavailable"),
    (TypeError("sensitive diagnostic"), "reader_error"),
])
def test_lookup_failures_log_only_fixed_codes(monkeypatch, caplog, error, code):
    client = settings_client(monkeypatch, SettingsReader(error=error))
    with caplog.at_level(logging.WARNING), pytest.raises(bridge.SharedConnectionsError):
        client.request("GET", "/v1/connections", clerk_org_id="org_server")
    assert f"code={code}" in caplog.text
    assert "sensitive diagnostic" not in caplog.text
    assert "org_server" not in caplog.text


def test_clerk_lookup_respects_capacity_without_calling_reader(monkeypatch, caplog):
    class NoCapacity:
        def acquire(self, *, blocking):
            assert blocking is False
            return False

    reader = SettingsReader()
    client = settings_client(monkeypatch, reader)
    monkeypatch.setattr(bridge, "_BOUNDED_RPC_SLOTS", NoCapacity())
    with caplog.at_level(logging.WARNING), pytest.raises(bridge.SharedConnectionsError):
        client.request("GET", "/v1/connections", clerk_org_id="org_server")
    assert reader.calls == []
    assert "code=capacity" in caplog.text


@pytest.mark.parametrize("outcome", [
    "success", "response_bound", "snapshot_unavailable", "reader_error",
])
def test_each_lookup_exit_releases_its_capacity_slot(monkeypatch, caplog, outcome):
    class Slots:
        acquired = 0
        released = 0

        def acquire(self, *, blocking):
            assert blocking is False
            self.acquired += 1
            return True

        def release(self):
            self.released += 1

    error = {"snapshot_unavailable": ConnectionSettingsUnavailable(),
             "reader_error": TypeError("private")}.get(outcome)
    client = settings_client(monkeypatch, SettingsReader(error=error))
    slots = Slots()
    monkeypatch.setattr(bridge, "_BOUNDED_RPC_SLOTS", slots)
    with caplog.at_level(logging.WARNING):
        if outcome == "success":
            result = client.request("GET", "/v1/connections", clerk_org_id="org_server")
            assert result == {"items": []}
        else:
            with pytest.raises(bridge.SharedConnectionsError):
                client.request("GET", "/v1/connections", clerk_org_id="org_server",
                               max_response_bytes=1 if outcome == "response_bound" else 1000)
            assert f"code={outcome}" in caplog.text
    assert slots.acquired == slots.released == 1


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


def test_clerk_list_below_response_bound_succeeds(monkeypatch):
    result = {"items": [{"id": "synthetic-id"}]}
    client = settings_client(monkeypatch, SettingsReader(result))
    assert client.request(
        "GET", "/internal/v1/connections/jira", clerk_org_id="org_server",
        max_response_bytes=1000,
    ) == result


@pytest.mark.parametrize("path,providers", list(bridge._SETTINGS_LIST_PROVIDERS.items()))
def test_real_clerk_reader_preserves_each_listing_envelope(monkeypatch, path, providers):
    """Match the four source routes' existing items envelopes/provider composition.

    Source references: Platform api.py:list_connections, jira_api.py:jira_list,
    workspace_api.py:inventory and azure_repos_api.py:listing at 5491d3c.
    This is synthetic wire compatibility, not live provider acceptance.
    """
    now = datetime(2026, 10, 30, tzinfo=UTC)
    all_providers = ["aws", "github", "gcp", "azure", "entra", "azure_repos",
                     "jira", "google_workspace"]
    assert set(providers) <= set(all_providers)
    views = [{"id": f"00000000-0000-4000-8000-{i:012d}", "provider": provider,
              "connection_kind": f"shared_{provider}", "availability": "needs_validation",
              "validated_scopes": []} for i, provider in enumerate(all_providers, start=1)]
    snapshot = {
        "version": 1, "environment": "development", "organization_id": "org_server",
        "revision": "22222222-2222-4222-8222-222222222222",
        "published_at": now.isoformat(), "expires_at": (now + timedelta(seconds=300)).isoformat(),
        "sources": {view["provider"]: [{"id": view["id"],
                    "settings": {"external_id": "PRIVATE_SETTINGS_SENTINEL"},
                    "applications": {"denali": view, "other_app": {**view,
                    "display_name": "OTHER_APP_SENTINEL"}}}] for view in views},
    }
    clerk_http = httpx.Client(transport=httpx.MockTransport(lambda _request: httpx.Response(
        200, json={"id": "org_server", "private_metadata": {"transilience_connections": snapshot}},
    )))
    reader = ClerkConnectionSettingsReader(
        "sk_test_synthetic", "development", "denali", client=clerk_http, now=lambda: now,
    )
    client = settings_client(monkeypatch, reader)
    expected = {"items": [view for view in views if view["provider"] in providers]}
    assert expected["items"]
    try:
        result = client.request("GET", path, clerk_org_id="org_server", max_response_bytes=65536)
    finally:
        clerk_http.close()
    assert result == expected
    assert "settings" not in json.dumps(result)
    assert "PRIVATE_SETTINGS_SENTINEL" not in json.dumps(result)
    assert "OTHER_APP_SENTINEL" not in json.dumps(result)


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
        connection_settings_org_ids=frozenset({"org_server"}),
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
    monkeypatch.setenv("DENALI_CLERK_CONNECTION_SETTINGS_ORG_IDS", "org_server")
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


def test_unselected_authorized_org_keeps_platform_lookup(monkeypatch):
    calls = []

    class MachineClerk:
        def __init__(self, **_options):
            self.m2m = self

        def create_token(self, **_options):
            calls.append("machine-token")
            return type("Token", (), {"token": "synthetic-short-lived-token"})()

    class Client:
        def __init__(self, **_options):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def request(self, method, url, **options):
            calls.append((method, url, options["params"]["clerk_org_id"]))
            return type("Response", (), {
                "status_code": 200, "json": lambda _self: {"items": [{"provider": "aws"}]},
            })()

    monkeypatch.setattr(bridge, "Clerk", MachineClerk)
    monkeypatch.setattr(bridge.httpx, "Client", Client)
    reader = SettingsReader(error=AssertionError("unselected org must not query Clerk"))
    client = bridge.SharedConnectionsClient(
        "https://platform.example", "test-machine-key",
        allowed_clerk_org_ids=frozenset({"org_canary", "org_unchanged"}),
        connection_settings_reader=reader,
        connection_settings_org_ids=frozenset({"org_canary"}),
    )
    assert client.request("GET", "/v1/connections", clerk_org_id="org_unchanged") == {
        "items": [{"provider": "aws"}],
    }
    assert reader.calls == []
    assert calls[-1] == ("GET", "https://platform.example/v1/connections", "org_unchanged")


@pytest.mark.parametrize("selection", ["", "org_one,org_one", "invalid", ",".join(
    "org_test" + str(value) for value in range(21)
)])
def test_missing_duplicate_invalid_or_oversized_migration_selection_is_rejected(
    monkeypatch, selection,
):
    monkeypatch.setenv("DENALI_CLERK_CONNECTION_SETTINGS_ORG_IDS", selection)
    with pytest.raises(ValueError, match="migration selection invalid"):
        bridge.SharedConnectionsClient.settings_org_ids_from_environment()


def test_migration_selector_never_grants_broker_admission(monkeypatch):
    reader = SettingsReader()
    client = settings_client(monkeypatch, reader)
    client._connection_settings_org_ids = frozenset({"org_other"})
    with pytest.raises(bridge.SharedConnectionsError) as caught:
        client.request("GET", "/v1/connections", clerk_org_id="org_other")
    assert caught.value.status_code == 404 and reader.calls == []
