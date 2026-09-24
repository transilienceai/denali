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


def make_client(shared, repository=None):
    return TestClient(
        create_app(
            repository=repository or FakeRepository(),
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
        assert (
            client.post(
                path,
                json={**payload, "clerk_org_id": "org_beta"},
                headers={"Authorization": "Bearer alpha-admin"},
            ).status_code
            == 422
        )
        assert (
            client.post(
                path,
                json={**payload, "role_name": "OtherRole"},
                headers={"Authorization": "Bearer alpha-admin"},
            ).status_code
            == 422
        )
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
        assert listed.headers["cache-control"] == "no-store"
        assert shared.calls[-1][2] == "org_alpha"
        template = client.get(
            f"/v1/shared/connections/aws/{connection}/cloudformation.yaml",
            headers={"Authorization": "Bearer alpha-member"},
        )
        assert template.status_code == 200
        assert template.headers["cache-control"] == "no-store"
        assert (
            client.post(
                f"/v1/shared/connections/aws/{connection}/validate",
                headers={"Authorization": "Bearer alpha-member"},
            ).status_code
            == 403
        )
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
        assert (
            client.post(
                path,
                json={"region": "us-east-1"},
                headers={"Authorization": "Bearer alpha-member"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                path,
                json={"region": "us-east-1", "clerk_org_id": "org_beta"},
                headers={"Authorization": "Bearer alpha-admin"},
            ).status_code
            == 422
        )
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


def test_admin_attaches_ready_shared_aws_to_denali_without_role_credentials(monkeypatch):
    app_module = import_module("denali.api.app")
    monkeypatch.setattr(app_module, "_with_validation_state", lambda _r, _t, row: row)
    platform_id = "11111111-1111-1111-1111-111111111111"

    class ReadySharedClient(FakeSharedClient):
        def request(self, method, path, *, clerk_org_id, payload=None, expect_text=False):
            self.calls.append((method, path, clerk_org_id, payload, expect_text))
            if method == "GET":
                return {
                    "items": [
                        {
                            "id": platform_id,
                            "connection_kind": "shared_aws",
                            "availability": "ready",
                            "validated_scopes": ["aws.bedrock_agents"],
                            "partition": "aws",
                            "external_account_id": "123456789012",
                        }
                    ]
                    if clerk_org_id == "org_alpha"
                    else []
                }
            return {
                "access_key_id": "temporary-test-key",
                "secret_access_key": "temporary-test-secret",
                "session_token": "temporary-test-token",
            }

    class ConnectionRepository(FakeRepository):
        def __init__(self):
            self.created = []

        def get_connection(self, tenant_id, connection_id):
            return next(
                (
                    row
                    for row in self.created
                    if row["tenant_id"] == tenant_id and row["id"] == connection_id
                ),
                None,
            )

        def create_connection(self, tenant_id, **kwargs):
            row = {
                "tenant_id": tenant_id,
                "id": kwargs["connection_id"],
                "provider": kwargs["provider"],
                "lifecycle_state": "active",
                "credential_reference": {
                    "type": kwargs["credential_type"],
                    "platform_connection_id": kwargs["credential_reference"][
                        "platform_connection_id"
                    ],
                },
                "configuration": kwargs["configuration"],
                "declared_scopes": kwargs["declared_scopes"],
            }
            self.created.append(row)
            return row

    shared = ReadySharedClient()
    repository = ConnectionRepository()
    path = f"/v1/shared/connections/aws/{platform_id}/use-in-denali"
    payload = {"region": "us-east-1", "declared_scopes": ["aws.bedrock_agents"]}
    with make_client(shared, repository) as client:
        assert client.post(path, json=payload).status_code == 401
        assert (
            client.post(
                path, json=payload, headers={"Authorization": "Bearer alpha-member"}
            ).status_code
            == 403
        )
        assert (
            client.post(
                path, json=payload, headers={"Authorization": "Bearer beta-admin"}
            ).status_code
            == 404
        )
        assert (
            client.post(
                path,
                json={**payload, "clerk_org_id": "org_beta"},
                headers={"Authorization": "Bearer alpha-admin"},
            ).status_code
            == 422
        )
        assert (
            client.post(
                path,
                json={"region": "us-east-1", "declared_scopes": ["aws.code_to_cloud"]},
                headers={"Authorization": "Bearer alpha-admin"},
            ).status_code
            == 403
        )
        created = client.post(path, json=payload, headers={"Authorization": "Bearer alpha-admin"})
        repeated = client.post(path, json=payload, headers={"Authorization": "Bearer alpha-admin"})
    assert created.status_code == 201
    assert repeated.status_code == 201
    assert len(repository.created) == 1
    assert repository.created[0]["tenant_id"] == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    assert repository.created[0]["configuration"]["regions"] == ["us-east-1"]
    assert repository.created[0]["credential_reference"] == {
        "type": "platform_shared_aws",
        "platform_connection_id": platform_id,
    }
    assert sum(call[1].endswith("/credentials") for call in shared.calls) == 1
    assert "temporary-test-secret" not in created.text


def test_shared_aws_attach_rejects_changed_region_and_scopes(monkeypatch):
    app_module = import_module("denali.api.app")
    monkeypatch.setattr(app_module, "_with_validation_state", lambda _r, _t, row: row)
    platform_id = "11111111-1111-1111-1111-111111111111"

    class ReadySharedClient(FakeSharedClient):
        def request(self, method, path, *, clerk_org_id, payload=None, expect_text=False):
            if method == "GET":
                return {
                    "items": [
                        {
                            "id": platform_id,
                            "connection_kind": "shared_aws",
                            "availability": "ready",
                            "validated_scopes": ["aws.bedrock_agents", "aws.agentcore"],
                            "partition": "aws",
                            "external_account_id": "123456789012",
                        }
                    ]
                }
            return super().request(
                method, path, clerk_org_id=clerk_org_id, payload=payload, expect_text=expect_text
            )

    class ExistingRepository(FakeRepository):
        def get_connection(self, tenant_id, connection_id):
            return {
                "id": connection_id,
                "lifecycle_state": "active",
                "credential_reference": {
                    "type": "platform_shared_aws",
                    "platform_connection_id": connection_id,
                },
                "configuration": {"regions": ["us-east-1"]},
                "declared_scopes": ["aws.bedrock_agents"],
            }

    with make_client(ReadySharedClient(), ExistingRepository()) as client:
        path = f"/v1/shared/connections/aws/{platform_id}/use-in-denali"
        headers = {"Authorization": "Bearer alpha-admin"}
        assert client.post(path, json={"region": "us-west-2"}, headers=headers).status_code == 409
        assert (
            client.post(
                path,
                json={"region": "us-east-1", "declared_scopes": ["aws.agentcore"]},
                headers=headers,
            ).status_code
            == 409
        )
