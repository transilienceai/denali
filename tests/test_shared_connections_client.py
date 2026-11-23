from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from denali.integrations import shared_connections_client

ORIGIN = "https://transilience-transilience-platform-dev--transilience-pla-73050c.modal.run"


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
        ORIGIN, "test-machine-key",
        modal_proxy_key="wk-synthetic", modal_proxy_secret="ws-synthetic",
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
    assert sent["headers"] == {
        "Authorization": "Bearer test-token", "Modal-Key": "wk-synthetic",
        "Modal-Secret": "ws-synthetic",
    }


@pytest.mark.parametrize("key,secret", [
    ("", ""), ("wk-synthetic", ""), ("", "ws-synthetic"),
    ("ak-unrelated", "ws-synthetic"), ("wk-synthetic", "ws-invalid\nheader"),
])
def test_proxy_pair_is_required_before_clerk_or_transport(monkeypatch, key, secret):
    monkeypatch.setattr(
        shared_connections_client, "Clerk", lambda **_kwargs: pytest.fail("Clerk called")
    )
    with pytest.raises(ValueError, match="Modal proxy"):
        shared_connections_client.SharedConnectionsClient(
            ORIGIN, "machine", modal_proxy_key=key, modal_proxy_secret=secret,
        )


@pytest.mark.parametrize("origin", [
    "https://evil.example", "https://platform.example", ORIGIN + "/path",
])
def test_proxy_credentials_never_go_to_an_unreviewed_origin(monkeypatch, origin):
    monkeypatch.setattr(
        shared_connections_client, "Clerk", lambda **_kwargs: pytest.fail("Clerk called")
    )
    with pytest.raises(ValueError):
        shared_connections_client.SharedConnectionsClient(
            origin, "machine", modal_proxy_key="wk-synthetic", modal_proxy_secret="ws-synthetic",
        )


@pytest.mark.parametrize("environment,origin,remote", [
    ("denali-prod", ORIGIN, False),
    ("denali-dev",
     "https://transilience-transilience-platform-prod--transilience-pl-8a9ce7.modal.run", False),
    ("unknown", ORIGIN, False), ("", ORIGIN, True),
])
def test_mismatched_or_unknown_remote_environment_fails_before_clerk(
    monkeypatch, environment, origin, remote,
):
    monkeypatch.setenv("MODAL_ENVIRONMENT", environment)
    monkeypatch.setenv("MODAL_IS_REMOTE", "1" if remote else "0")
    monkeypatch.setattr(
        shared_connections_client, "Clerk", lambda **_kwargs: pytest.fail("Clerk called")
    )
    with pytest.raises(ValueError, match="environment"):
        shared_connections_client.SharedConnectionsClient(
            origin, "machine", modal_proxy_key="wk-synthetic", modal_proxy_secret="ws-synthetic",
        )


def test_transport_error_drops_credential_owning_request_context(monkeypatch):
    monkeypatch.setattr(shared_connections_client, "Clerk", lambda **_kwargs: SimpleNamespace(
        m2m=SimpleNamespace(create_token=lambda **_kw: SimpleNamespace(token="private-bearer")),
    ))

    class Client:
        def __init__(self, **options):
            assert options["trust_env"] is False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def request(self, method, url, **options):
            raise httpx.ConnectError("private-marker", request=httpx.Request(
                method, url, headers=options["headers"],
            ))

    monkeypatch.setattr(shared_connections_client.httpx, "Client", Client)
    client = shared_connections_client.SharedConnectionsClient(
        ORIGIN, "machine", modal_proxy_key="wk-synthetic", modal_proxy_secret="ws-synthetic",
    )
    with pytest.raises(shared_connections_client.SharedConnectionsError) as error:
        client.request("GET", "/v1/connections", clerk_org_id="org_fixture")
    assert error.value.__context__ is None
    assert "private-marker" not in str(error.value)
