from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from denali.integrations.clerk_connection_settings import (
    ClerkConnectionSettingsReader,
    ConnectionSettingsUnavailable,
)

NOW = datetime(2026, 10, 30, tzinfo=UTC)
CONNECTION = "11111111-1111-4111-8111-111111111111"


def document():
    return {
        "version": 1,
        "environment": "development",
        "organization_id": "org_server",
        "revision": "22222222-2222-4222-8222-222222222222",
        "published_at": NOW.isoformat(),
        "expires_at": (NOW + timedelta(seconds=300)).isoformat(),
        "sources": {
            "aws": [{
                "id": CONNECTION,
                "settings": {
                    "role_arn": "arn:aws:iam::123456789012:role/Example",
                    "external_id": "example-external-id",
                },
                "applications": {
                    "denali": {
                        "id": CONNECTION,
                        "provider": "aws",
                        "connection_kind": "shared_aws",
                        "availability": "ready",
                        "validated_scopes": ["aws.deployments"],
                    },
                    "another-app": {
                        "id": CONNECTION,
                        "provider": "aws",
                        "connection_kind": "shared_aws",
                        "availability": "needs_scope_grant",
                        "validated_scopes": [],
                    },
                },
            }],
        },
    }


def reader(value=None, *, organization_id="org_server", raw_response=None):
    value = document() if value is None else value
    calls = []

    def respond(request):
        calls.append(request)
        assert request.method == "GET"
        assert str(request.url) == "https://api.clerk.com/v1/organizations/org_server"
        assert request.headers["Authorization"] == "Bearer sk_test_synthetic"
        if raw_response is not None:
            return raw_response
        return httpx.Response(200, json={
            "id": organization_id,
            "private_metadata": {
                "unrelated_field": "never-return-this",
                "transilience_connections": value,
            },
        })

    return ClerkConnectionSettingsReader(
        "sk_test_synthetic", "development", "denali",
        client=httpx.Client(transport=httpx.MockTransport(respond)), now=lambda: NOW,
    ), calls


def test_reader_returns_only_current_app_view_not_private_settings():
    client, calls = reader()
    result = client.list_connections("org_server", providers={"aws"})
    assert result == {"items": [document()["sources"]["aws"][0]["applications"]["denali"]]}
    assert len(calls) == 1
    assert "role_arn" not in str(result)
    assert "external_id" not in str(result)
    assert "another-app" not in str(result)
    assert "never-return-this" not in str(result)


@pytest.mark.parametrize("change", [
    {"version": 2},
    {"organization_id": "org_other"},
    {"environment": "production"},
    {"expires_at": NOW.isoformat()},
    {"published_at": (NOW + timedelta(seconds=1)).isoformat()},
    {"expires_at": (NOW + timedelta(seconds=301)).isoformat()},
    {"revision": "not-a-uuid"},
])
def test_reader_rejects_wrong_org_environment_schema_and_freshness(change):
    value = document()
    value.update(change)
    client, _ = reader(value)
    with pytest.raises(ConnectionSettingsUnavailable, match="^connection settings unavailable$"):
        client.list_connections("org_server")


def test_reader_checks_clerk_response_org_before_metadata():
    client, _ = reader(organization_id="org_other")
    with pytest.raises(ConnectionSettingsUnavailable):
        client.list_connections("org_server")


def test_valid_empty_or_removed_app_is_empty_not_an_error():
    value = document()
    value["sources"] = {}
    client, _ = reader(value)
    assert client.list_connections("org_server") == {"items": []}
    value = document()
    del value["sources"]["aws"][0]["applications"]["denali"]
    client, _ = reader(value)
    assert client.list_connections("org_server") == {"items": []}


def test_credential_fields_in_any_app_view_reject_the_whole_document():
    value = document()
    value["sources"]["aws"][0]["applications"]["another-app"]["access_token"] = "synthetic"
    client, _ = reader(value)
    with pytest.raises(ConnectionSettingsUnavailable):
        client.list_connections("org_server")


def test_duplicate_connection_in_another_provider_is_invalid():
    value = document()
    record = copy.deepcopy(value["sources"]["aws"][0])
    for view in record["applications"].values():
        view["provider"] = "gcp"
        view["connection_kind"] = "shared_gcp"
    value["sources"]["gcp"] = [record]
    client, _ = reader(value)
    with pytest.raises(ConnectionSettingsUnavailable):
        client.list_connections("org_server")


def test_mail_discovery_requires_the_exact_owner_not_org_admin():
    value = document()
    value["sources"] = {"gmail": [{
        "id": CONNECTION,
        "settings": {},
        "owner_user_id": "user_owner",
        "applications": {"denali": {
            "id": CONNECTION,
            "provider": "gmail",
            "connection_kind": "shared_mail",
            "owner_user_id": "user_owner",
        }},
    }]}
    client, _ = reader(value)
    assert client.list_connections("org_server") == {"items": []}
    assert client.list_connections("org_server", owner_user_id="user_admin") == {"items": []}
    assert len(client.list_connections("org_server", owner_user_id="user_owner")["items"]) == 1


@pytest.mark.parametrize("response", [
    httpx.Response(302, headers={"Location": "https://untrusted.example"}),
    httpx.Response(200, content=b"{}", headers={"Content-Type": "text/plain"}),
    httpx.Response(200, json={"id": "org_server", "private_metadata": {}}),
    httpx.Response(200, content=b"{" + b" " * 65536, headers={"Content-Type": "application/json"}),
])
def test_transport_and_missing_metadata_fail_closed(response):
    client, _ = reader(raw_response=response)
    with pytest.raises(ConnectionSettingsUnavailable):
        client.list_connections("org_server")


@pytest.mark.parametrize(("key", "environment"), [
    ("sk_test_synthetic", "production"),
    ("sk_live_synthetic", "development"),
    ("machine-key", "development"),
    ("sk_test_synthetic", "unknown"),
])
def test_reader_configuration_rejects_cross_environment_or_machine_keys(key, environment):
    with pytest.raises(ValueError, match="configuration invalid"):
        ClerkConnectionSettingsReader(key, environment, "denali")
