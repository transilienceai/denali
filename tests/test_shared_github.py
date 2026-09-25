from __future__ import annotations

from importlib import import_module

import pytest
from fastapi.testclient import TestClient
from test_shared_connections_api import FakeAuthenticator, FakeRepository

from denali.api.app import create_app
from denali.connections.github import github_coverage_plan
from denali.integrations.shared_github import (
    GitHubValidatorRouter,
    SharedGitHubAppClient,
    normalize_shared_repositories,
)

CONNECTION_ID = "11111111-1111-1111-1111-111111111111"
SCOPES = ["github.repository_metadata", "github.repository_contents", "github.actions_workflows"]
REPOSITORY = {
    "id": 42,
    "node_id": "R_kg42",
    "name": "demo",
    "full_name": "transilienceai/demo",
    "owner_id": 7,
    "owner_login": "transilienceai",
    "private": True,
    "archived": False,
    "default_branch": "main",
}
LIST_ITEM = {
    "id": CONNECTION_ID,
    "connection_kind": "shared_github",
    "provider": "github",
    "account_id": 7,
    "account_login": "transilienceai",
    "installation_id": 99,
    "repository_selection": "selected",
    "repository_count": 1,
    "availability": "ready",
    "validated_scopes": SCOPES,
}


class Platform:
    def __init__(self):
        self.calls = []
        self.ready = True
        self.repository = REPOSITORY

    def request(self, method, path, *, clerk_org_id, payload=None, expect_text=False):
        self.calls.append((method, path, clerk_org_id, payload))
        if path == "/v1/connections":
            return {"items": [{**LIST_ITEM, "availability": "ready" if self.ready else "disabled"}]}
        if path.endswith("/repositories"):
            return {"items": [self.repository]}
        if path.endswith("/token"):
            return {
                "token": "ghs_temporary-test-token",
                "repository_ids": payload["repository_ids"],
            }
        if path.endswith("/setup"):
            return {
                "install_url": "https://github.com/apps/transilience-platform-dev/installations/new"
            }
        raise AssertionError(path)


class Repository(FakeRepository):
    def __init__(self):
        self.created = []

    def get_connection(self, tenant_id, connection_id):
        return next(
            (
                item
                for item in self.created
                if item["tenant_id"] == tenant_id and item["id"] == connection_id
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
                **kwargs["credential_reference"],
            },
            "configuration": kwargs["configuration"],
            "declared_scopes": kwargs["declared_scopes"],
            "coverage_plan": kwargs["coverage_plan"],
        }
        self.created.append(row)
        return row


def _client(platform, repository):
    return TestClient(
        create_app(
            repository=repository,
            auth_mode="clerk",
            authenticator=FakeAuthenticator(),
            shared_connections_client=platform,
            migrate_on_start=False,
        )
    )


def test_shared_github_attach_is_admin_org_bound_and_never_persists_token(monkeypatch):
    monkeypatch.setattr(
        import_module("denali.api.app"), "_with_validation_state", lambda _r, _t, row: row
    )
    platform = Platform()
    repository = Repository()
    path = f"/v1/shared/connections/github/{CONNECTION_ID}/use-in-denali"
    with _client(platform, repository) as client:
        assert client.post(path, json={}).status_code == 401
        assert (
            client.post(path, json={}, headers={"Authorization": "Bearer alpha-member"}).status_code
            == 403
        )
        assert (
            client.post(
                path,
                json={"clerk_org_id": "org_beta"},
                headers={"Authorization": "Bearer alpha-admin"},
            ).status_code
            == 422
        )
        created = client.post(path, json={}, headers={"Authorization": "Bearer alpha-admin"})
        repeated = client.post(path, json={}, headers={"Authorization": "Bearer alpha-admin"})
    assert created.status_code == 201
    assert repeated.status_code == 201
    assert len(repository.created) == 1
    assert repository.created[0]["credential_reference"] == {
        "type": "platform_shared_github",
        "platform_connection_id": CONNECTION_ID,
        "installation_id": 99,
    }
    assert repository.created[0]["configuration"]["repositories"][0]["id"] == 42
    assert len(repository.created[0]["coverage_plan"]) == 3
    assert "ghs_temporary-test-token" not in str(repository.created)
    assert "ghs_temporary-test-token" not in created.text
    token_calls = [item for item in platform.calls if item[1].endswith("/token")]
    assert len(token_calls) == 1
    assert token_calls[0][2] == "org_alpha"
    assert token_calls[0][3] == {"repository_ids": [42], "scopes": SCOPES}


def test_shared_github_setup_is_platform_owned_and_admin_only():
    platform = Platform()
    with _client(platform, Repository()) as client:
        path = "/v1/shared/connections/github/setup"
        assert (
            client.post(path, headers={"Authorization": "Bearer alpha-member"}).status_code == 403
        )
        response = client.post(path, headers={"Authorization": "Bearer alpha-admin"})
    assert response.status_code == 201
    assert platform.calls[-1] == ("POST", "/internal/v1/connections/github/setup", "org_alpha", {})


def test_shared_github_attach_fails_closed_on_revocation_scope_and_owner(monkeypatch):
    monkeypatch.setattr(
        import_module("denali.api.app"), "_with_validation_state", lambda _r, _t, row: row
    )
    platform = Platform()
    repository = Repository()
    path = f"/v1/shared/connections/github/{CONNECTION_ID}/use-in-denali"
    headers = {"Authorization": "Bearer alpha-admin"}
    with _client(platform, repository) as client:
        platform.ready = False
        assert client.post(path, json={}, headers=headers).status_code == 409
        platform.ready = True
        assert (
            client.post(
                path,
                json={
                    "declared_scopes": [
                        "github.repository_metadata",
                        "github.repository_metadata",
                    ]
                },
                headers=headers,
            ).status_code
            == 422
        )
        assert (
            client.post(
                path,
                json={"declared_scopes": ["github.repository_metadata", "github.unknown"]},
                headers=headers,
            ).status_code
            == 422
        )
        platform.repository = {**REPOSITORY, "owner_id": 8}
        assert client.post(path, json={}, headers=headers).status_code == 502
    assert not repository.created


def test_denali_app_setup_cannot_mutate_shared_github_binding():
    class SharedRepository(FakeRepository):
        def get_connection_validation_target(self, _tenant_id, _connection_id):
            return {
                "provider": "github",
                "credential_type": "platform_shared_github",
                "lifecycle_state": "active",
            }

    path = f"/v1/connections/{CONNECTION_ID}/github/setup/launch"
    with _client(Platform(), SharedRepository()) as client:
        response = client.post(path, headers={"Authorization": "Bearer alpha-admin"})
    assert response.status_code == 404


def test_shared_github_broker_rejects_revoked_or_out_of_boundary_repository():
    platform = Platform()
    target = {
        "id": CONNECTION_ID,
        "credential_type": "platform_shared_github",
        "credential_reference": {
            "platform_connection_id": CONNECTION_ID,
            "installation_id": 99,
        },
        "clerk_organization_id": "org_alpha",
        "configuration": {
            "account_id": 7,
            "account_login": "transilienceai",
            "repositories": [REPOSITORY],
        },
        "declared_scopes": SCOPES,
        "coverage_plan": [],
    }
    app = SharedGitHubAppClient(platform, target)
    assert app.get_installation(99)["account_id"] == 7
    assert app.create_installation_token(installation_id=99, repository_id=42).startswith("ghs_")
    with pytest.raises(RuntimeError):
        app.create_installation_token(installation_id=99, repository_id=43)
    platform.ready = False
    with pytest.raises(RuntimeError):
        app.get_installation(99)
    validation = GitHubValidatorRouter(None, platform).validate(target)
    assert validation["credential_state"] == "failed"
    assert validation["health_state"] == "unhealthy"


def test_shared_github_validator_reads_exact_repository_through_broker(monkeypatch):
    from denali.integrations import shared_github

    class Response:
        status_code = 200

        def __init__(self, data):
            self.data = data

        def raise_for_status(self):
            return None

        def json(self):
            return self.data

    paths = []

    def github_read(method, url, **options):
        assert method == "GET"
        assert options["headers"]["Authorization"] == "Bearer ghs_temporary-test-token"
        paths.append(url)
        if url.endswith("/repos/transilienceai/demo"):
            return Response(
                {
                    "id": 42,
                    "node_id": "R_kg42",
                    "full_name": "transilienceai/demo",
                    "owner": {"id": 7, "login": "transilienceai"},
                    "default_branch": "main",
                }
            )
        return Response({"total_count": 0})

    monkeypatch.setattr(shared_github.httpx, "request", github_read)
    platform = Platform()
    target = {
        "id": CONNECTION_ID,
        "provider": "github",
        "credential_type": "platform_shared_github",
        "credential_reference": {
            "platform_connection_id": CONNECTION_ID,
            "installation_id": 99,
        },
        "clerk_organization_id": "org_alpha",
        "configuration": {
            "account_id": 7,
            "account_login": "transilienceai",
            "repositories": [REPOSITORY],
        },
        "declared_scopes": SCOPES,
        "coverage_plan": github_coverage_plan(SCOPES, [REPOSITORY]),
    }
    result = GitHubValidatorRouter(None, platform).validate(target)
    assert result["credential_state"] == "passed"
    assert result["health_state"] == "healthy"
    assert len(result["results"]) == 3
    assert len(paths) == 3
    assert "ghs_temporary-test-token" not in str(result)


def test_shared_github_repositories_reject_missing_identity_and_count_change():
    with pytest.raises(ValueError):
        normalize_shared_repositories({"items": [REPOSITORY]}, expected_count=2)
    with pytest.raises(RuntimeError):
        normalize_shared_repositories(
            {"items": [{**REPOSITORY, "owner_login": "other"}]}, expected_count=1
        )
