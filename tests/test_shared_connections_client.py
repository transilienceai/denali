from __future__ import annotations

import pytest

from denali.integrations import shared_connections_client


def test_server_org_overrides_request_payload(monkeypatch):
    sent = {}

    class FakeM2M:
        def create_token(self, **_options):
            return type("Token", (), {"token": "test-token"})()

    class FakeClerk:
        def __init__(self, bearer_auth):
            assert bearer_auth == "test-machine-key"
            self.m2m = FakeM2M()

    class FakeResponse:
        status_code = 201

        def json(self):
            return {"id": "test-connection"}

    class FakeClient:
        def __init__(self, **_options):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def request(self, method, url, **options):
            sent.update(method=method, url=url, **options)
            return FakeResponse()

    monkeypatch.setattr(shared_connections_client, "Clerk", FakeClerk)
    monkeypatch.setattr(shared_connections_client.httpx, "Client", FakeClient)

    client = shared_connections_client.SharedConnectionsClient(
        "https://platform.example", "test-machine-key"
    )
    assert client.request(
        "POST",
        "/internal/v1/connections/aws",
        clerk_org_id="org_server",
        payload={"clerk_org_id": "org_other", "external_account_id": "123456789012"},
    ) == {"id": "test-connection"}
    assert sent["json"] == {
        "clerk_org_id": "org_server",
        "external_account_id": "123456789012",
    }


def test_environment_client_defaults_to_no_organizations(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "https://platform.example")
    monkeypatch.setenv("DENALI_PLATFORM_MACHINE_SECRET_KEY", "test-machine-key")
    monkeypatch.delenv("DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS", raising=False)
    client = shared_connections_client.SharedConnectionsClient.from_environment()
    assert client is not None
    assert not client.allows_org("org_any")
    with pytest.raises(shared_connections_client.SharedConnectionsError) as error:
        client.request("GET", "/v1/connections", clerk_org_id="org_any")
    assert error.value.status_code == 404


def test_preprovisioned_machine_key_does_not_activate_a_dark_bridge(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "")
    monkeypatch.setenv("DENALI_PLATFORM_MACHINE_SECRET_KEY", "test-machine-key")
    assert shared_connections_client.SharedConnectionsClient.from_environment() is None

    monkeypatch.setenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "https://platform.example")
    monkeypatch.delenv("DENALI_PLATFORM_MACHINE_SECRET_KEY")
    with pytest.raises(ValueError, match="machine secret"):
        shared_connections_client.SharedConnectionsClient.from_environment()


def test_environment_allowlist_is_exact_and_rejects_invalid_ids(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "https://platform.example")
    monkeypatch.setenv("DENALI_PLATFORM_MACHINE_SECRET_KEY", "test-machine-key")
    monkeypatch.setenv("DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS", "org_pilot")
    client = shared_connections_client.SharedConnectionsClient.from_environment()
    assert client is not None
    assert client.allows_org("org_pilot")
    assert not client.allows_org("org_pilot2")
    monkeypatch.setenv("DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS", "org_pilot,not-an-org")
    with pytest.raises(ValueError, match="invalid Clerk org ID"):
        shared_connections_client.SharedConnectionsClient.from_environment()


def test_bounded_jira_broker_response_uses_existing_machine_and_rejects_oversize(monkeypatch):
    calls = []
    response_body = [b'{"projects":[]}']

    class FakeClerk:
        def __init__(self, bearer_auth):
            assert bearer_auth == "operator-test-machine"
            self.m2m = self

        def create_token(self, **options):
            assert options == {"seconds_until_expiration": 60, "min_remaining_ttl_seconds": 20}
            return type("Token", (), {"token": "ephemeral-test-token"})()

    class FakeResponse:
        status_code = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def iter_bytes(self):
            yield response_body[0]

    class FakeClient:
        def __init__(self, **options):
            assert options == {"timeout": 20, "follow_redirects": False}

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def stream(self, method, url, **options):
            calls.append((method, url, options))
            return FakeResponse()

    monkeypatch.setattr(shared_connections_client, "Clerk", FakeClerk)
    monkeypatch.setattr(shared_connections_client.httpx, "Client", FakeClient)
    client = shared_connections_client.SharedConnectionsClient(
        "https://platform.example", "operator-test-machine",
        allowed_clerk_org_ids=frozenset({"org_server"}),
    )
    path = "/internal/v1/connections/jira/11111111-1111-4111-8111-111111111111/read"
    result = client.request(
        "POST", path, clerk_org_id="org_server",
        payload={"clerk_org_id": "org_other", "operation": "projects"},
        max_response_bytes=20,
    )
    assert result == {"projects": []}
    assert calls[0][0:2] == ("POST", "https://platform.example" + path)
    assert calls[0][2]["json"] == {"clerk_org_id": "org_server", "operation": "projects"}
    assert calls[0][2]["headers"]["Authorization"] == "Bearer ephemeral-test-token"
    with pytest.raises(shared_connections_client.SharedConnectionsError) as error:
        client.request("POST", path, clerk_org_id="org_server", payload={}, max_response_bytes=5)
    assert error.value.status_code == 502
    response_body[0] = b"[" * 10_000 + b"0" + b"]" * 10_000
    with pytest.raises(shared_connections_client.SharedConnectionsError) as error:
        client.request("POST", path, clerk_org_id="org_server", payload={},
                       max_response_bytes=25_000)
    assert error.value.status_code == 502
    with pytest.raises(ValueError, match="unexpected shared connections path"):
        client.request("GET", "/arbitrary-url", clerk_org_id="org_server")
