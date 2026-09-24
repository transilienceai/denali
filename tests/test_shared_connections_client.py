from __future__ import annotations

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
