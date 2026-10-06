from __future__ import annotations

from datetime import UTC, datetime, timedelta
from importlib import import_module

import httpx
import pytest
from fastapi.testclient import TestClient
from test_shared_connections_api import FakeAuthenticator, FakeRepository

from denali.api.app import create_app
from denali.connections.github import github_coverage_plan
from denali.integrations.shared_github import (
    GitHubCollectorRouter,
    GitHubValidatorRouter,
    SharedGitHubAppClient,
    normalize_shared_repositories,
    safe_install_url,
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


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_GITHUB_ENABLED", "true")


class Platform:
    def __init__(self):
        self.calls = []
        self.ready = True
        self.repository = dict(REPOSITORY)

    def allows_org(self, org):
        return org == "org_alpha"

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
                "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            }
        if path.endswith("/setup"):
            return {
                "install_url": "https://github.com/apps/transilience-platform-dev/installations/new"
            }
        if path.endswith("/disable"):
            return {"status": "disabled"}
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


def test_shared_member_reads_and_admin_disable_are_server_authorized():
    platform = Platform()
    with _client(platform, Repository()) as client:
        path = f"/v1/shared/connections/github/{CONNECTION_ID}/disable"
        assert client.post(path).status_code == 401
        assert (
            client.post(path, headers={"Authorization": "Bearer alpha-member"}).status_code
            == 403
        )
        assert not platform.calls
        listing = client.get(
            "/v1/shared/connections/github", headers={"Authorization": "Bearer alpha-member"}
        )
        disabled = client.post(path, headers={"Authorization": "Bearer alpha-admin"})
    assert listing.status_code == 200 and listing.headers["Cache-Control"] == "no-store"
    assert disabled.status_code == 200 and disabled.json() == {"status": "disabled"}
    assert platform.calls[-1] == (
        "POST", f"/internal/v1/connections/github/{CONNECTION_ID}/disable", "org_alpha", None
    )


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
        "provider": "github",
        "lifecycle_state": "active",
        "credential_type": "platform_shared_github",
        "credential_reference": {
            "platform_connection_id": CONNECTION_ID,
            "installation_id": 99,
        },
        "clerk_organization_id": "org_alpha",
        "configuration": {
            "coverage_mode": "exact-installation-repositories",
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
        "lifecycle_state": "active",
        "credential_type": "platform_shared_github",
        "credential_reference": {
            "platform_connection_id": CONNECTION_ID,
            "installation_id": 99,
        },
        "clerk_organization_id": "org_alpha",
        "configuration": {
            "coverage_mode": "exact-installation-repositories",
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


def target():
    return {
        "id": CONNECTION_ID,
        "provider": "github",
        "lifecycle_state": "active",
        "credential_type": "platform_shared_github",
        "credential_reference": {"platform_connection_id": CONNECTION_ID, "installation_id": 99},
        "clerk_organization_id": "org_alpha",
        "declared_scopes": SCOPES,
        "configuration": {
            "coverage_mode": "exact-installation-repositories",
            "account_id": 7,
            "account_login": "transilienceai",
            "repositories": [REPOSITORY],
        },
        "coverage_plan": github_coverage_plan(SCOPES, [REPOSITORY]),
    }


def test_shared_github_is_default_off_and_non_pilot_hidden(monkeypatch):
    platform = Platform()
    monkeypatch.delenv("DENALI_PLATFORM_GITHUB_ENABLED", raising=False)
    with _client(platform, Repository()) as client:
        assert (
            client.get(
                "/v1/shared/connections/github", headers={"Authorization": "Bearer alpha-admin"}
            ).status_code
            == 404
        )
    with pytest.raises(ValueError, match="disabled"):
        SharedGitHubAppClient(platform, target())
    monkeypatch.setenv("DENALI_PLATFORM_GITHUB_ENABLED", "true")
    with _client(platform, Repository()) as client:
        assert (
            client.get(
                "/v1/shared/connections/github", headers={"Authorization": "Bearer beta-admin"}
            ).status_code
            == 404
        )
    assert not platform.calls


@pytest.mark.parametrize(
    "change",
    [
        {"id": "not-a-uuid"},
        {"clerk_organization_id": "org_beta"},
        {"clerk_organization_id": "org_alpha/other"},
        {"lifecycle_state": "disabled"},
        {
            "credential_reference": {
                "platform_connection_id": CONNECTION_ID,
                "installation_id": True,
            }
        },
        {"declared_scopes": SCOPES + [SCOPES[0]]},
        {"declared_scopes": ["github.admin"]},
        {"configuration": {"coverage_mode": "all-repositories", "repositories": []}},
    ],
)
def test_shared_reference_rejected_before_network_without_native_fallback(change):
    class Legacy:
        def validate(self, _connection):
            pytest.fail("shared failure must not use native credentials")

    platform = Platform()
    with pytest.raises((ValueError, RuntimeError)):
        GitHubValidatorRouter(Legacy(), platform).validate({**target(), **change})
    assert not platform.calls


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/apps/platform/installations/new",
        "https://github.com.evil/apps/platform/installations/new",
        "https://user:password@github.com/apps/platform/installations/new",
        "https://github.com/apps/platform/installations/new#secret",
        "https://github.com/apps/platform/../installations/new",
        "javascript:alert(1)",
    ],
)
def test_install_link_cannot_redirect_to_other_origin_or_embed_credentials(url):
    with pytest.raises(ValueError):
        safe_install_url(url)


def test_rejected_credentials_are_never_reflected_and_metadata_is_projected():
    secret_marker = "synthetic-secret-MUST-NOT-REFLECT"

    class ExtraPlatform(Platform):
        def request(self, *args, **kwargs):
            result = super().request(*args, **kwargs)
            if "items" in result:
                for row in result["items"]:
                    row["private_key"] = secret_marker
            else:
                result["token"] = secret_marker
            return result

    with _client(ExtraPlatform(), Repository()) as client:
        headers = {"Authorization": "Bearer alpha-admin"}
        listing = client.get("/v1/shared/connections/github", headers=headers)
        repos = client.get(
            f"/v1/shared/connections/github/{CONNECTION_ID}/repositories", headers=headers
        )
        setup = client.post("/v1/shared/connections/github/setup", headers=headers)
        rejected = client.post(
            f"/v1/shared/connections/github/{CONNECTION_ID}/use-in-denali",
            headers=headers,
            json={"private_key": secret_marker},
        )
        invalid_id = client.get(
            f"/v1/shared/connections/github/{secret_marker}/repositories", headers=headers
        )
    assert listing.status_code == repos.status_code == 200
    assert setup.status_code == 201 and rejected.status_code == invalid_id.status_code == 422
    assert all(
        secret_marker not in result.text for result in [listing, repos, setup, rejected, invalid_id]
    )


def test_broker_token_expiry_repository_boundary_and_http_read_allowlist(monkeypatch):
    app = SharedGitHubAppClient(Platform(), target())
    token = app.create_installation_token(installation_id=99, repository_id=42)
    requests = []

    def read(*args, **kwargs):
        requests.append((args, kwargs))
        return httpx.Response(
            200,
            json={**REPOSITORY, "owner": {"id": 7, "login": "transilienceai"}},
            request=httpx.Request(*args),
        )

    monkeypatch.setattr(
        "denali.integrations.shared_github.httpx.request",
        read,
    )
    app.installation_request("GET", "/repos/transilienceai/demo", token=token)
    assert requests[0][1]["follow_redirects"] is False
    for method, path, options in [
        ("POST", "/repos/transilienceai/demo", {}),
        ("GET", "//evil.com", {}),
        ("GET", "/repos/transilienceai/other", {}),
        ("GET", "/repos/transilienceai/demo/actions/secrets", {}),
        ("GET", "/repos/transilienceai/demo/git/ref/heads/%2e%2e/other", {}),
        ("GET", "/repos/transilienceai/demo", {"follow_redirects": True}),
        ("GET", "/repos/transilienceai/demo", {"headers": {"Authorization": "override"}}),
    ]:
        with pytest.raises(ValueError):
            app.installation_request(method, path, token=token, **options)
    with pytest.raises(ValueError):
        app.installation_request("GET", "/repos/transilienceai/demo", token="unknown")
    assert len(requests) == 1

    class Expired(Platform):
        def request(self, *args, **kwargs):
            result = super().request(*args, **kwargs)
            if "expires_at" in result:
                result["expires_at"] = "2020-01-01T00:00:00Z"
            return result

    with pytest.raises(RuntimeError, match="expiry"):
        SharedGitHubAppClient(Expired(), target()).create_installation_token(
            installation_id=99, repository_id=42
        )


def test_reconsent_cannot_silently_expand_or_replace_existing_selected_repo():
    platform = Platform()
    app = SharedGitHubAppClient(platform, target())
    platform.repository = {**REPOSITORY, "id": 43, "node_id": "R_other"}
    with pytest.raises(RuntimeError, match="selection changed"):
        app.get_installation(99)
    assert not any(call[1].endswith("/token") for call in platform.calls)


def test_native_routers_remain_unchanged_when_shared_flag_off(monkeypatch):
    monkeypatch.delenv("DENALI_PLATFORM_GITHUB_ENABLED", raising=False)

    class Native:
        def validate(self, connection):
            return {"native": connection["id"]}

        def collect(self, **values):
            return {"native": values["connection"]["id"]}

    connection = {"id": "native", "credential_type": "github_app_installation"}
    assert GitHubValidatorRouter(Native(), Platform()).validate(connection) == {"native": "native"}
    assert GitHubCollectorRouter(Native(), Platform()).collect(
        tenant_id="tenant", connection=connection, repository=None
    ) == {"native": "native"}


def test_shared_source_collector_uses_existing_bounded_metadata_analysis(monkeypatch):
    from denali.integrations import shared_github

    class Response:
        status_code = 200
        headers = {}

        def raise_for_status(self):
            pass

        def json(self):
            return {
                **REPOSITORY,
                "owner": {"id": 7, "login": "transilienceai"},
                "default_branch": None,
            }

    monkeypatch.setattr(shared_github.httpx, "request", lambda *args, **kwargs: Response())

    class Sink:
        def deployment_targets(self, _tenant):
            return []

        def ingest(self, _tenant, _batch):
            return {"assets": 0, "relationships": 0}

        def ingest_findings(self, _tenant, _batch):
            return {"findings": 0}

    result = GitHubCollectorRouter(None, Platform()).collect(
        tenant_id="tenant", connection=target(), repository=Sink()
    )
    assert result["repository_count"] == 1 and result["failed_count"] == 0
    assert "ghs_" not in str(result)
