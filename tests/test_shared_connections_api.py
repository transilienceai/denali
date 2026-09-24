from __future__ import annotations

from importlib import import_module

from fastapi import Request
from fastapi.testclient import TestClient

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError


class FakeAuthenticator:
    def authenticate(self, request: Request) -> AuthContext:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        identities = {
            "alpha-admin": AuthContext("user_alpha", "org_alpha", "admin"),
            "alpha-member": AuthContext("user_member", "org_alpha", "member"),
            "beta-admin": AuthContext("user_beta", "org_beta", "admin"),
        }
        if token not in identities:
            raise AuthenticationError("invalid session")
        return identities[token]


class FakeRepository:
    def resolve_tenant(self, clerk_organization_id: str) -> str:
        return {
            "org_alpha": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "org_beta": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        }[clerk_organization_id]


class FakeSharedClient:
    def __init__(self):
        self.calls = []

    def request(self, method, path, *, clerk_org_id, payload=None, expect_text=False):
        self.calls.append((method, path, clerk_org_id, payload, expect_text))
        if expect_text:
            return "AWSTemplateFormatVersion: '2010-09-09'"
        if method == "GET":
            return {"items": []}
        if path.endswith("/credentials"):
            return {
                "access_key_id": "temporary-test-key",
                "secret_access_key": "temporary-test-secret",
                "session_token": "temporary-test-token",
            }
        return {"id": "11111111-1111-1111-1111-111111111111"}


def make_client(shared):
    return TestClient(
        create_app(
            repository=FakeRepository(),
            auth_mode="clerk",
            authenticator=FakeAuthenticator(),
            shared_connections_client=shared,
            migrate_on_start=False,
        )
    )


def test_admin_creation_uses_server_resolved_clerk_org_not_client_input():
    shared = FakeSharedClient()
    with make_client(shared) as client:
        payload = {
            "account_id": "123456789012",
            "declared_scopes": ["aws.bedrock_agents"],
        }
        path = "/v1/shared/connections/aws"
        assert client.post(path, json=payload).status_code == 401
        assert (
            client.post(
                path, json=payload, headers={"Authorization": "Bearer alpha-member"}
            ).status_code
            == 403
        )
        assert client.post(
            path,
            json={**payload, "clerk_org_id": "org_beta"},
            headers={"Authorization": "Bearer alpha-admin"},
        ).status_code == 422
        assert client.post(
            path,
            json={**payload, "role_name": "OtherRole"},
            headers={"Authorization": "Bearer alpha-admin"},
        ).status_code == 422
        response = client.post(path, json=payload, headers={"Authorization": "Bearer alpha-admin"})
        assert response.status_code == 201
        assert shared.calls[-1][2] == "org_alpha"
        assert shared.calls[-1][3]["external_account_id"] == "123456789012"


def test_read_and_mutation_routes_keep_org_and_admin_boundaries():
    shared = FakeSharedClient()
    connection = "11111111-1111-1111-1111-111111111111"
    with make_client(shared) as client:
        listed = client.get(
            "/v1/shared/connections", headers={"Authorization": "Bearer alpha-member"}
        )
        assert listed.status_code == 200
        assert shared.calls[-1][2] == "org_alpha"
        template = client.get(
            f"/v1/shared/connections/aws/{connection}/cloudformation.yaml",
            headers={"Authorization": "Bearer alpha-member"},
        )
        assert template.status_code == 200
        assert template.headers["cache-control"] == "no-store"
        assert client.post(
            f"/v1/shared/connections/aws/{connection}/validate",
            headers={"Authorization": "Bearer alpha-member"},
        ).status_code == 403
        validated = client.post(
            f"/v1/shared/connections/aws/{connection}/validate",
            headers={"Authorization": "Bearer beta-admin"},
        )
        assert validated.status_code == 202
        assert shared.calls[-1][2] == "org_beta"
        status = client.get(
            f"/v1/shared/connections/aws/{connection}/validation",
            headers={"Authorization": "Bearer alpha-member"},
        )
        assert status.status_code == 200
        assert shared.calls[-1][2] == "org_alpha"


def test_admin_can_probe_shared_aws_without_exposing_leased_credentials(monkeypatch):
    shared = FakeSharedClient()
    app_module = import_module("denali.api.app")
    seen = {}

    def fake_probe(credentials, region):
        seen.update(credentials=credentials, region=region)
        return {"scope": "aws.bedrock_agents", "region": region, "read_state": "passed"}

    monkeypatch.setattr(app_module, "probe_shared_bedrock_agents", fake_probe)
    path = "/v1/shared/connections/aws/11111111-1111-1111-1111-111111111111/probe"
    with make_client(shared) as client:
        assert client.post(path, json={"region": "us-east-1"}).status_code == 401
        assert client.post(
            path,
            json={"region": "us-east-1"},
            headers={"Authorization": "Bearer alpha-member"},
        ).status_code == 403
        assert client.post(
            path,
            json={"region": "us-east-1", "clerk_org_id": "org_beta"},
            headers={"Authorization": "Bearer alpha-admin"},
        ).status_code == 422
        response = client.post(
            path,
            json={"region": "us-east-1"},
            headers={"Authorization": "Bearer alpha-admin"},
        )
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {
        "scope": "aws.bedrock_agents",
        "region": "us-east-1",
        "read_state": "passed",
    }
    assert shared.calls[-1][2] == "org_alpha"
    assert shared.calls[-1][3] == {"scopes": ["aws.bedrock_agents"], "region": "us-east-1"}
    assert seen["region"] == "us-east-1"
    assert seen["credentials"]["access_key_id"] == "temporary-test-key"
    assert "temporary-test-secret" not in response.text


def test_shared_aws_probe_hides_provider_errors(monkeypatch):
    shared = FakeSharedClient()
    app_module = import_module("denali.api.app")

    def failing_probe(_credentials, _region):
        raise RuntimeError("temporary-test-secret must not be returned")

    monkeypatch.setattr(app_module, "probe_shared_bedrock_agents", failing_probe)
    with make_client(shared) as client:
        response = client.post(
            "/v1/shared/connections/aws/11111111-1111-1111-1111-111111111111/probe",
            json={"region": "us-east-1"},
            headers={"Authorization": "Bearer alpha-admin"},
        )
    assert response.status_code == 502
    assert response.json() == {"detail": "shared AWS read failed"}
    assert "temporary-test-secret" not in response.text
