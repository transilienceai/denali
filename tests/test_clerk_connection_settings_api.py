from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
from test_shared_connections_api import make_client

from denali.integrations import shared_connections_client as bridge
from denali.integrations.clerk_connection_settings import ClerkConnectionSettingsReader


def shared_client(monkeypatch, *, metadata=True):
    calls = []
    now = datetime(2026, 10, 30, tzinfo=UTC)
    connection_id = "11111111-1111-4111-8111-111111111111"
    view = {
        "id": connection_id,
        "provider": "aws",
        "connection_kind": "shared_aws",
        "availability": "ready",
        "validated_scopes": ["aws.deployments"],
    }

    def clerk_transport(request):
        assert str(request.url) == "https://api.clerk.com/v1/organizations/org_alpha"
        calls.append(request)
        document = {
            "version": 1,
            "environment": "development",
            "organization_id": "org_alpha",
            "revision": "22222222-2222-4222-8222-222222222222",
            "published_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=300)).isoformat(),
            "sources": {"aws": [{
                "id": connection_id,
                "settings": {
                    "role_arn": "arn:aws:iam::123456789012:role/Example",
                    "external_id": "example-external-id",
                },
                "applications": {"denali": view},
            }]},
        }
        return httpx.Response(200, json={
            "id": "org_alpha",
            "private_metadata": {"transilience_connections": document} if metadata else {},
        })

    reader = ClerkConnectionSettingsReader(
        "sk_test_synthetic", "development", "denali",
        client=httpx.Client(transport=httpx.MockTransport(clerk_transport)), now=lambda: now,
    )

    class NoMachineTokens:
        def __init__(self, **_kwargs):
            self.m2m = self

        def create_token(self, **_kwargs):
            raise AssertionError("Clerk metadata lookup must not call Platform")

    monkeypatch.setattr(bridge, "Clerk", NoMachineTokens)
    shared = bridge.SharedConnectionsClient(
        "https://platform.example", "synthetic-machine-key",
        allowed_clerk_org_ids=frozenset({"org_alpha"}), connection_settings_reader=reader,
    )
    return shared, calls, view


def test_authenticated_listing_keeps_org_scope_and_sanitized_response(monkeypatch):
    shared, calls, view = shared_client(monkeypatch)
    with make_client(shared) as client:
        assert client.get("/v1/shared/connections").status_code == 401
        response = client.get(
            "/v1/shared/connections?clerk_org_id=org_beta",
            headers={"Authorization": "Bearer alpha-member"},
        )
        assert response.status_code == 200
        assert response.json() == {"items": [view]}
        assert response.headers["cache-control"] == "no-store"
        assert "role_arn" not in response.text
        assert "external_id" not in response.text
        assert "settings" not in response.text
        assert client.get(
            "/v1/shared/connections", headers={"Authorization": "Bearer beta-admin"},
        ).status_code == 404
    assert len(calls) == 1


def test_missing_clerk_snapshot_is_redacted_unavailable_not_legacy_fallback(monkeypatch):
    shared, calls, _ = shared_client(monkeypatch, metadata=False)
    with make_client(shared) as client:
        response = client.get(
            "/v1/shared/connections", headers={"Authorization": "Bearer alpha-admin"},
        )
    assert response.status_code == 502
    assert response.json() == {"detail": "shared connections request failed"}
    assert len(calls) == 1
