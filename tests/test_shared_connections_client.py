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
