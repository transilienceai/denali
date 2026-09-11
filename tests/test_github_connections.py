from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from denali.api.app import DEFAULT_LOCAL_TENANT, create_app
from denali.connections import (
    GITHUB_SCOPES,
    GitHubAppClient,
    GitHubConnectionValidator,
    github_coverage_plan,
)

CONNECTION_ID = "77777777-7777-4777-8777-777777777777"
INSTALLATION_ID = 24680
REPOSITORIES = [
    {
        "id": 101,
        "node_id": "R_fixture_one",
        "name": "service-one",
        "full_name": "example/service-one",
        "owner_id": 44,
        "owner_login": "example",
        "private": True,
        "archived": False,
        "default_branch": "main",
    },
    {
        "id": 202,
        "node_id": "R_fixture_two",
        "name": "service-two",
        "full_name": "example/service-two",
        "owner_id": 44,
        "owner_login": "example",
        "private": False,
        "archived": False,
        "default_branch": "trunk",
    },
]


class GitHubConnectionRepositoryStub:
    def __init__(self):
        self.targets: dict[str, dict[str, Any]] = {}
        self.rows: dict[str, dict[str, Any]] = {}

    def create_connection(self, tenant_id: str, **values: Any) -> dict[str, Any]:
        assert tenant_id == DEFAULT_LOCAL_TENANT
        connection_id = values["connection_id"]
        target = {"id": connection_id, "lifecycle_state": "active", **values}
        self.targets[connection_id] = target
        self.rows[connection_id] = self._safe(target)
        return self.rows[connection_id]

    def list_connections(self, tenant_id: str) -> list[dict[str, Any]]:
        return list(self.rows.values())

    def get_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None:
        return self.rows.get(connection_id)

    def get_connection_validation_target(
        self, tenant_id: str, connection_id: str
    ) -> dict[str, Any] | None:
        return self.targets.get(connection_id)

    def record_connection_validation(
        self, tenant_id: str, connection_id: str, validation: dict[str, Any]
    ) -> dict[str, Any] | None:
        row = self.rows.get(connection_id)
        if row is None:
            return None
        row["health_state"] = validation["health_state"]
        row["last_validation"] = validation
        row["last_validated_at"] = validation["completed_at"].isoformat()
        return row

    def record_github_install_launch(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        launch: dict[str, Any],
        state_sha256: str,
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        if target is None:
            return None
        target["credential_reference"]["install_state_sha256"] = state_sha256
        target["configuration"]["onboarding"] = launch
        self.rows[connection_id] = self._safe(target)
        return self.rows[connection_id]

    def record_github_install_return(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_install_state_sha256: str,
        installation_id: int,
        oauth: dict[str, Any],
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        if target is None or target["credential_reference"].get(
            "install_state_sha256"
        ) != expected_install_state_sha256:
            return None
        target["credential_reference"].pop("install_state_sha256")
        target["credential_reference"].update(
            {
                "installation_id": installation_id,
                "oauth_state_sha256": oauth["state_sha256"],
                "pkce_verifier": oauth["pkce_verifier"],
            }
        )
        target["configuration"]["onboarding"].update(
            {
                "installation_id": installation_id,
                "oauth_expires_at": oauth["expires_at"],
            }
        )
        self.rows[connection_id] = self._safe(target)
        return self.rows[connection_id]

    def complete_github_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_oauth_state_sha256: str,
        installation: dict[str, Any],
        installer: dict[str, Any],
        repositories: list[dict[str, Any]],
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        if target is None or target["credential_reference"].get(
            "oauth_state_sha256"
        ) != expected_oauth_state_sha256:
            return None
        target["credential_reference"].pop("oauth_state_sha256")
        target["credential_reference"].pop("pkce_verifier")
        target["configuration"].update(
            {
                "account_id": installation["account_id"],
                "account_login": installation["account_login"],
                "account_type": installation["account_type"],
                "installation_repository_selection": installation[
                    "repository_selection"
                ],
                "repositories": repositories,
                "installer": installer,
            }
        )
        target["configuration"]["onboarding"]["completed_at"] = (
            completed_at.isoformat()
        )
        target["coverage_plan"] = coverage_plan
        self.rows[connection_id] = self._safe(target)
        return self.rows[connection_id]

    def disable_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None:
        row = self.rows.get(connection_id)
        if row is None:
            return None
        row["lifecycle_state"] = "disabled"
        row["health_state"] = "disabled"
        self.targets[connection_id]["lifecycle_state"] = "disabled"
        return row

    def delete_connection(self, tenant_id: str, connection_id: str) -> str:
        row = self.rows.get(connection_id)
        if row is None:
            return "not_found"
        if row["lifecycle_state"] != "disabled":
            return "active"
        del self.rows[connection_id]
        del self.targets[connection_id]
        return "deleted"

    @staticmethod
    def _safe(target: dict[str, Any]) -> dict[str, Any]:
        reference = target["credential_reference"]
        safe_reference = {
            "type": "github_app_installation",
            "app_id": reference["app_id"],
            "app_slug": reference["app_slug"],
        }
        if reference.get("installation_id"):
            safe_reference["installation_id"] = reference["installation_id"]
        return {
            "id": target["id"],
            "provider": "github",
            "display_name": target["display_name"],
            "lifecycle_state": target["lifecycle_state"],
            "health_state": "unknown",
            "credential_reference": safe_reference,
            "declared_scopes": target["declared_scopes"],
            "coverage_plan": target["coverage_plan"],
            "configuration": target["configuration"],
            "last_validation": None,
            "last_validated_at": None,
        }


class FakeGitHubApp:
    app_id = 12345
    client_id = "Iv1.fixture"
    app_slug = "denali-fixture"
    web_url = "http://127.0.0.1:3080"

    def __init__(self):
        self.exchanged: list[dict[str, str]] = []
        self.verified: list[dict[str, Any]] = []

    def create_install_launch(self, *, tenant_id: str, connection_id: str) -> dict[str, Any]:
        state = f"{tenant_id}.{connection_id}.{'i' * 48}"
        now = datetime.now(UTC)
        return {
            "install_url": f"https://github.com/apps/{self.app_slug}/installations/new?state={state}",
            "state_sha256": hashlib.sha256(state.encode()).hexdigest(),
            "created_at": now,
            "expires_at": now + timedelta(minutes=30),
        }

    def create_oauth_launch(self, *, tenant_id: str, connection_id: str) -> dict[str, Any]:
        state = f"{tenant_id}.{connection_id}.{'o' * 48}"
        now = datetime.now(UTC)
        return {
            "authorize_url": f"https://github.com/login/oauth/authorize?state={state}",
            "state_sha256": hashlib.sha256(state.encode()).hexdigest(),
            "pkce_verifier": "pkce-verifier-that-is-never-returned",
            "created_at": now,
            "expires_at": now + timedelta(minutes=30),
        }

    def exchange_user_code(self, *, code: str, pkce_verifier: str) -> str:
        self.exchanged.append({"code": code, "pkce_verifier": pkce_verifier})
        return "ghu_transient-user-token"

    def verify_user_installation(
        self, *, installation_id: int, user_token: str
    ) -> dict[str, Any]:
        self.verified.append(
            {"installation_id": installation_id, "user_token": user_token}
        )
        if installation_id != INSTALLATION_ID:
            raise RuntimeError("unexpected installation")
        return {
            "installation": {
                "id": INSTALLATION_ID,
                "account_id": 44,
                "account_login": "example",
                "account_type": "Organization",
                "repository_selection": "selected",
                "permissions": {
                    "metadata": "read",
                    "contents": "read",
                    "actions": "read",
                },
            },
            "installer": {"id": 55, "login": "installer"},
            "repositories": REPOSITORIES,
        }


class FakeGitHubRepositoryCollector:
    def __init__(self):
        self.calls: list[dict[str, Any]] = []

    def collect(self, *, tenant_id: str, connection: dict[str, Any], repository: Any):
        self.calls.append({"tenant_id": tenant_id, "connection": connection})
        return {
            "connection_id": connection["id"],
            "state": "complete",
            "completed_at": datetime.now(UTC).isoformat(),
            "repository_count": 2,
            "failed_count": 0,
            "partial_count": 0,
            "repositories": [],
        }


class PassingGitHubValidator:
    def validate(self, target: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(UTC)
        return {
            "started_at": now,
            "completed_at": now,
            "health_state": "healthy",
            "credential_state": "passed",
            "account_id_observed": str(target["configuration"]["account_id"]),
            "results": [
                {
                    "scope": item["scope"],
                    "plane": item["plane"],
                    "label": item["label"],
                    "region": item["region"],
                    "repository_id": item["repository_id"],
                    "repository_full_name": item["repository_full_name"],
                    "state": "passed",
                    "detail": "Fixture GitHub validation succeeded.",
                }
                for item in target["coverage_plan"]
            ],
            "summary": "GitHub App and exact repositories validated.",
        }


def test_github_app_setup_verifies_installer_and_discards_transient_tokens() -> None:
    repository = GitHubConnectionRepositoryStub()
    github = FakeGitHubApp()
    app = create_app(
        repository=repository,
        github_app_client=github,  # type: ignore[arg-type]
        github_connection_validator=PassingGitHubValidator(),  # type: ignore[arg-type]
        onboarding_validation_retry_seconds=0,
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        created_response = client.post(
            "/v1/connections",
            json={"provider": "github", "display_name": "Production GitHub"},
        )
        assert created_response.status_code == 201
        connection_id = created_response.json()["id"]
        launch_response = client.post(
            f"/v1/connections/{connection_id}/github/setup/launch"
        )
        assert launch_response.status_code == 201
        launch = launch_response.json()
        install_state = parse_qs(urlparse(launch["install_url"]).query)["state"][0]
        internal = repository.targets[connection_id]
        assert internal["credential_reference"]["install_state_sha256"] == (
            hashlib.sha256(install_state.encode()).hexdigest()
        )
        assert install_state not in str(repository.rows[connection_id])

        install_return = client.get(
            "/v1/connections/github/setup/callback",
            params={"state": install_state, "installation_id": INSTALLATION_ID},
            follow_redirects=False,
        )
        assert install_return.status_code == 303
        oauth_state = parse_qs(urlparse(install_return.headers["location"]).query)[
            "state"
        ][0]
        assert "pkce-verifier" not in install_return.headers["location"]

        oauth_return = client.get(
            "/v1/connections/github/oauth/callback",
            params={"state": oauth_state, "code": "fixture-oauth-code"},
            follow_redirects=False,
        )
        assert oauth_return.status_code == 303
        assert oauth_return.headers["location"].startswith(
            "http://127.0.0.1:3080/?github_setup=succeeded"
        )
        assert github.exchanged == [
            {
                "code": "fixture-oauth-code",
                "pkce_verifier": "pkce-verifier-that-is-never-returned",
            }
        ]
        assert github.verified == [
            {
                "installation_id": INSTALLATION_ID,
                "user_token": "ghu_transient-user-token",
            }
        ]
        detail = client.get(f"/v1/connections/{connection_id}").json()
        assert detail["health_state"] == "healthy"
        assert detail["credential_reference"]["installation_id"] == INSTALLATION_ID
        assert detail["configuration"]["repositories"] == REPOSITORIES
        assert len(detail["coverage_plan"]) == len(GITHUB_SCOPES) * len(REPOSITORIES)
        serialized = str(detail)
        for secret in (
            "ghu_transient-user-token",
            "pkce-verifier",
            "fixture-oauth-code",
            install_state,
            oauth_state,
        ):
            assert secret not in serialized


def test_github_source_collection_runs_in_background_and_reports_completion() -> None:
    repository = GitHubConnectionRepositoryStub()
    target = {
        "id": CONNECTION_ID,
        "provider": "github",
        "display_name": "Production GitHub",
        "lifecycle_state": "active",
        "credential_reference": {
            "app_id": 12345,
            "app_slug": "denali-fixture",
            "installation_id": INSTALLATION_ID,
        },
        "declared_scopes": list(GITHUB_SCOPES),
        "coverage_plan": github_coverage_plan(list(GITHUB_SCOPES), REPOSITORIES),
        "configuration": {
            "account_id": 44,
            "account_login": "example",
            "repositories": REPOSITORIES,
        },
    }
    repository.targets[CONNECTION_ID] = target
    repository.rows[CONNECTION_ID] = repository._safe(target)
    collector = FakeGitHubRepositoryCollector()
    app = create_app(
        repository=repository,
        github_app_client=FakeGitHubApp(),  # type: ignore[arg-type]
        github_repository_collector=collector,  # type: ignore[arg-type]
        migrate_on_start=False,
    )

    with TestClient(app) as client:
        response = client.post(f"/v1/connections/{CONNECTION_ID}/github/collect")
        assert response.status_code == 202
        assert response.json()["status"] == "started"
        detail = client.get(f"/v1/connections/{CONNECTION_ID}").json()

    assert collector.calls[0]["tenant_id"] == DEFAULT_LOCAL_TENANT
    assert detail["source_collection_state"] == "idle"
    assert detail["last_source_collection"]["state"] == "complete"


def test_github_app_setup_does_not_trust_the_returned_installation_id() -> None:
    repository = GitHubConnectionRepositoryStub()
    github = FakeGitHubApp()
    app = create_app(
        repository=repository,
        github_app_client=github,  # type: ignore[arg-type]
        github_connection_validator=PassingGitHubValidator(),  # type: ignore[arg-type]
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        created = client.post(
            "/v1/connections",
            json={"provider": "github", "display_name": "Spoof check"},
        ).json()
        connection_id = created["id"]
        launch = client.post(
            f"/v1/connections/{connection_id}/github/setup/launch"
        ).json()
        install_state = parse_qs(urlparse(launch["install_url"]).query)["state"][0]
        install_return = client.get(
            "/v1/connections/github/setup/callback",
            params={"state": install_state, "installation_id": 99999},
            follow_redirects=False,
        )
        oauth_state = parse_qs(urlparse(install_return.headers["location"]).query)[
            "state"
        ][0]
        oauth_return = client.get(
            "/v1/connections/github/oauth/callback",
            params={"state": oauth_state, "code": "fixture-oauth-code"},
            follow_redirects=False,
        )
        assert oauth_return.status_code == 303
        assert "github_setup=failed" in oauth_return.headers["location"]
        detail = client.get(f"/v1/connections/{connection_id}").json()
        assert detail["configuration"]["repositories"] == []
        assert detail["coverage_plan"] == []
        assert detail["last_validation"] is None


class FakeResponse:
    def __init__(self, payload: dict[str, Any], error: Exception | None = None):
        self._payload = payload
        self._error = error

    def raise_for_status(self) -> None:
        if self._error:
            raise self._error

    def json(self) -> dict[str, Any]:
        return self._payload


class GitHubStatusError(RuntimeError):
    def __init__(self, status_code: int):
        super().__init__(f"HTTP {status_code}")
        self.response = type("Response", (), {"status_code": status_code})()


class ValidatorGitHubApp:
    def __init__(self):
        self.token_repositories: list[int] = []

    def get_installation(self, installation_id: int) -> dict[str, Any]:
        assert installation_id == INSTALLATION_ID
        return {"account_id": 44, "account_login": "example"}

    def create_installation_token(self, *, installation_id: int, repository_id: int) -> str:
        assert installation_id == INSTALLATION_ID
        self.token_repositories.append(repository_id)
        return f"ghs_fixture-{repository_id}"

    def installation_request(
        self, method: str, path: str, *, token: str, **kwargs: Any
    ) -> FakeResponse:
        repository = next(
            item for item in REPOSITORIES if token == f"ghs_fixture-{item['id']}"
        )
        if path == f"/repos/{repository['full_name']}":
            return FakeResponse(
                {
                    **repository,
                    "owner": {
                        "id": repository["owner_id"],
                        "login": repository["owner_login"],
                    },
                }
            )
        if path.endswith("/actions/workflows") and repository["id"] == 202:
            return FakeResponse({}, RuntimeError("Actions is unavailable"))
        return FakeResponse({})


def test_github_validation_uses_one_exact_repository_token_and_isolates_planes() -> None:
    github = ValidatorGitHubApp()
    validator = GitHubConnectionValidator(github)  # type: ignore[arg-type]
    connection = {
        "id": CONNECTION_ID,
        "provider": "github",
        "credential_reference": {"installation_id": INSTALLATION_ID},
        "declared_scopes": list(GITHUB_SCOPES),
        "configuration": {
            "account_id": 44,
            "account_login": "example",
            "repositories": REPOSITORIES,
        },
        "coverage_plan": github_coverage_plan(list(GITHUB_SCOPES), REPOSITORIES),
    }
    result = validator.validate(connection)
    assert result["credential_state"] == "passed"
    assert result["health_state"] == "partial"
    assert github.token_repositories == [101, 202]
    assert len(result["results"]) == len(GITHUB_SCOPES) * len(REPOSITORIES)
    failed = [item for item in result["results"] if item["state"] == "failed"]
    assert len(failed) == 1
    assert failed[0]["repository_id"] == 202
    assert failed[0]["plane"] == "github_actions_workflows"
    assert all(
        item["state"] == "passed"
        for item in result["results"]
        if item is not failed[0]
    )


def test_github_validation_classifies_an_empty_repository_as_not_applicable() -> None:
    class EmptyRepositoryGitHubApp(ValidatorGitHubApp):
        def installation_request(
            self, method: str, path: str, *, token: str, **kwargs: Any
        ) -> FakeResponse:
            if path.endswith("/git/ref/heads/main"):
                return FakeResponse({}, GitHubStatusError(409))
            return super().installation_request(method, path, token=token, **kwargs)

    github = EmptyRepositoryGitHubApp()
    validator = GitHubConnectionValidator(github)  # type: ignore[arg-type]
    repository = REPOSITORIES[0]
    connection = {
        "id": CONNECTION_ID,
        "provider": "github",
        "credential_reference": {"installation_id": INSTALLATION_ID},
        "declared_scopes": list(GITHUB_SCOPES),
        "configuration": {
            "account_id": 44,
            "account_login": "example",
            "repositories": [repository],
        },
        "coverage_plan": github_coverage_plan(list(GITHUB_SCOPES), [repository]),
    }

    result = validator.validate(connection)

    assert result["health_state"] == "healthy"
    contents = next(
        item
        for item in result["results"]
        if item["plane"] == "github_repository_contents"
    )
    assert contents["state"] == "not_applicable"


class UserVerificationGitHubApp(GitHubAppClient):
    def __init__(self, total_count: int):
        super().__init__(
            app_id=12345,
            client_id="Iv1.fixture",
            client_secret="operator-secret",
            private_key="-----BEGIN PRIVATE KEY-----fixture",
            app_slug="denali-fixture",
            callback_url="http://127.0.0.1:8088/github/callback",
            web_url="http://127.0.0.1:3080",
        )
        self.total_count = total_count

    def get_installation(self, installation_id: int) -> dict[str, Any]:
        return {
            "id": installation_id,
            "account_id": 44,
            "account_login": "example",
            "account_type": "Organization",
            "repository_selection": "selected",
            "permissions": {
                "metadata": "read",
                "contents": "read",
                "actions": "read",
            },
        }

    def _user_request(
        self, method: str, path: str, *, user_token: str, **kwargs: Any
    ) -> FakeResponse:
        if path == "/user":
            return FakeResponse({"id": 55, "login": "installer"})
        repository = {
            "id": 101,
            "node_id": "R_fixture_one",
            "name": "service-one",
            "full_name": "example/service-one",
            "owner": {"id": 44, "login": "example"},
            "private": True,
            "archived": False,
            "default_branch": "main",
        }
        return FakeResponse(
            {
                "total_count": self.total_count,
                "repositories": [repository],
            }
        )


def test_github_installer_verification_rejects_a_truncated_repository_boundary() -> None:
    github = UserVerificationGitHubApp(total_count=501)
    with pytest.raises(RuntimeError, match="no more than 500"):
        github.verify_user_installation(
            installation_id=INSTALLATION_ID,
            user_token="ghu_transient-user-token",
        )
