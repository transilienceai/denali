from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient

from denali.api.app import DEFAULT_LOCAL_TENANT, create_app
from denali.connections import (
    AZURE_REPOS_SCOPES,
    AzureReposClient,
    AzureReposConnectionValidator,
    azure_repos_coverage_plan,
)

CONNECTION_ID = "77777777-7777-4777-8777-777777777777"
ENTRA_TENANT_ID = "11111111-1111-4111-8111-111111111111"
REPOSITORY_ID = "22222222-2222-4222-8222-222222222222"
PROJECT_ID = "33333333-3333-4333-8333-333333333333"
REPOSITORIES = [
    {
        "id": REPOSITORY_ID,
        "name": "service-one",
        "full_name": "Platform/service-one",
        "project_id": PROJECT_ID,
        "project_name": "Platform",
        "default_branch": "refs/heads/main",
        "remote_url": "https://dev.azure.com/example/Platform/_git/service-one",
    }
]


class AzureReposRepositoryStub:
    def __init__(self):
        self.targets: dict[str, dict[str, Any]] = {}
        self.rows: dict[str, dict[str, Any]] = {}

    def create_connection(self, tenant_id: str, **values: Any) -> dict[str, Any]:
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
        target = self.targets[connection_id]
        target["health_state"] = validation["health_state"]
        target["last_validation"] = validation
        target["last_validated_at"] = validation["completed_at"].isoformat()
        self.rows[connection_id] = self._safe(target)
        return self.rows[connection_id]

    def record_azure_repos_oauth_launch(
        self, tenant_id: str, connection_id: str, *, oauth: dict[str, Any]
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        if target is None:
            return None
        target["credential_reference"].update(
            {
                "oauth_state_sha256": oauth["state_sha256"],
                "pkce_verifier": oauth["pkce_verifier"],
            }
        )
        target["configuration"]["onboarding"] = {
            "method": "azure_repos_entra_oauth",
            "status": "authorizing",
            "oauth_expires_at": oauth["expires_at"],
        }
        self.rows[connection_id] = self._safe(target)
        return self.rows[connection_id]

    def stage_azure_repos_repository_selection(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_state_sha256: str,
        repositories: list[dict[str, Any]],
        authorized_at: datetime,
        expires_at: datetime,
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        if (
            target is None
            or target["credential_reference"].get("oauth_state_sha256") != expected_state_sha256
        ):
            return None
        target["credential_reference"].pop("oauth_state_sha256")
        target["credential_reference"].pop("pkce_verifier")
        target["configuration"]["repository_candidates"] = repositories
        target["configuration"]["onboarding"] = {
            "method": "azure_repos_entra_oauth",
            "status": "selection_pending",
            "authorized_at": authorized_at.isoformat(),
            "selection_expires_at": expires_at.isoformat(),
        }
        self.rows[connection_id] = self._safe(target)
        return self.rows[connection_id]

    def complete_azure_repos_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        repositories: list[dict[str, Any]],
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        if target is None:
            return None
        target["configuration"].pop("repository_candidates")
        target["configuration"]["repositories"] = repositories
        target["configuration"]["onboarding"] = {
            "method": "azure_repos_entra_oauth",
            "status": "completed",
            "completed_at": completed_at.isoformat(),
        }
        target["coverage_plan"] = coverage_plan
        self.rows[connection_id] = self._safe(target)
        return self.rows[connection_id]

    @staticmethod
    def _safe(target: dict[str, Any]) -> dict[str, Any]:
        reference = target["credential_reference"]
        return {
            "id": target["id"],
            "provider": "azure_repos",
            "display_name": target["display_name"],
            "lifecycle_state": target["lifecycle_state"],
            "health_state": target.get("health_state", "unknown"),
            "credential_reference": {
                "type": "azure_repos_service_principal",
                "client_id": reference["client_id"],
            },
            "declared_scopes": target["declared_scopes"],
            "coverage_plan": target["coverage_plan"],
            "configuration": target["configuration"],
            "last_validation": target.get("last_validation"),
            "last_validated_at": target.get("last_validated_at"),
        }


class FakeAzureReposClient:
    client_id = "44444444-4444-4444-8444-444444444444"
    web_url = "http://127.0.0.1:3080"

    def create_oauth_launch(
        self, *, denali_tenant_id: str, connection_id: str, entra_tenant_id: str
    ) -> dict[str, Any]:
        state = f"{denali_tenant_id}.{connection_id}.{'s' * 48}"
        now = datetime.now(UTC)
        return {
            "authorize_url": f"https://login.microsoftonline.com/authorize?state={state}",
            "state_sha256": hashlib.sha256(state.encode()).hexdigest(),
            "pkce_verifier": "transient-pkce-verifier",
            "created_at": now,
            "expires_at": now + timedelta(minutes=30),
        }

    def exchange_user_code(self, **values: str) -> str:
        assert values["code"] == "fixture-authorization-code"
        assert values["pkce_verifier"] == "transient-pkce-verifier"
        return "transient-user-token"

    def application_token(self, tenant_id: str) -> str:
        assert tenant_id == ENTRA_TENANT_ID
        return "application-token"

    def list_repositories(self, *, organization: str, token: str) -> list[dict[str, Any]]:
        assert organization == "example"
        assert token in {"transient-user-token", "application-token"}
        return REPOSITORIES


class PassingValidator:
    def validate(self, target: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(UTC)
        return {
            "started_at": now,
            "completed_at": now,
            "health_state": "healthy",
            "credential_state": "passed",
            "account_id_observed": "example",
            "results": [
                {**item, "state": "passed", "detail": "Fixture read succeeded."}
                for item in target["coverage_plan"]
            ],
            "summary": "Azure Repos validated.",
        }


def test_oauth_setup_discards_user_material_and_binds_exact_repository() -> None:
    repository = AzureReposRepositoryStub()
    azure_repos = FakeAzureReposClient()
    app = create_app(
        repository=repository,
        azure_repos_client=azure_repos,  # type: ignore[arg-type]
        azure_repos_connection_validator=PassingValidator(),  # type: ignore[arg-type]
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        created = client.post(
            "/v1/connections",
            json={
                "provider": "azure_repos",
                "display_name": "Production Azure Repos",
                "tenant_id": ENTRA_TENANT_ID,
                "organization": "example",
            },
        )
        assert created.status_code == 201
        connection_id = created.json()["id"]
        launch = client.post(f"/v1/connections/{connection_id}/azure-repos/setup/launch")
        assert launch.status_code == 201
        state = parse_qs(urlparse(launch.json()["authorize_url"]).query)["state"][0]
        tampered = client.get(
            "/v1/connections/azure-repos/oauth/callback",
            params={"state": f"{state}x", "code": "fixture-authorization-code"},
            follow_redirects=False,
        )
        assert tampered.status_code == 409
        callback = client.get(
            "/v1/connections/azure-repos/oauth/callback",
            params={"state": state, "code": "fixture-authorization-code"},
            follow_redirects=False,
        )
        assert callback.status_code == 303
        assert "azure_repos_setup=select" in callback.headers["location"]
        staged = client.get(f"/v1/connections/{connection_id}").json()
        assert staged["configuration"]["repository_candidates"] == REPOSITORIES
        completed = client.post(
            f"/v1/connections/{connection_id}/azure-repos/setup/complete",
            json={"repository_ids": [REPOSITORY_ID]},
        )
        assert completed.status_code == 202
        detail = client.get(f"/v1/connections/{connection_id}").json()

    assert detail["health_state"] == "healthy"
    assert detail["configuration"]["repositories"] == REPOSITORIES
    assert "repository_candidates" not in detail["configuration"]
    assert len(detail["coverage_plan"]) == len(AZURE_REPOS_SCOPES)
    for secret in (
        "transient-user-token",
        "transient-pkce-verifier",
        "fixture-authorization-code",
        state,
    ):
        assert secret not in str(detail)


def test_azure_repos_client_builds_pkce_launch_and_normalizes_repository_boundary() -> None:
    calls: list[dict[str, Any]] = []

    class Response:
        status_code = 200
        headers: dict[str, str] = {}

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {
                "count": 1,
                "value": [
                    {
                        "id": REPOSITORY_ID.upper(),
                        "name": "service-one",
                        "project": {"id": PROJECT_ID.upper(), "name": "Platform"},
                        "defaultBranch": "refs/heads/main",
                    }
                ],
            }

    def request(method: str, url: str, **kwargs: Any) -> Response:
        calls.append({"method": method, "url": url, **kwargs})
        return Response()

    client = AzureReposClient(
        client_id="44444444-4444-4444-8444-444444444444",
        client_secret="fixture-secret",
        callback_url="https://denali.example/api/v1/connections/azure-repos/oauth/callback",
        web_url="https://denali.example",
        request=request,
        token=lambda: "v" * 48,
    )
    launch = client.create_oauth_launch(
        denali_tenant_id=DEFAULT_LOCAL_TENANT,
        connection_id=CONNECTION_ID,
        entra_tenant_id=ENTRA_TENANT_ID,
    )
    query = parse_qs(urlparse(launch["authorize_url"]).query)
    assert query["code_challenge_method"] == ["S256"]
    assert "pkce_verifier" not in launch["authorize_url"]
    repositories = client.list_repositories(organization="example", token="x" * 40)
    assert repositories[0]["id"] == REPOSITORY_ID
    assert repositories[0]["project_id"] == PROJECT_ID
    assert calls[0]["headers"]["Authorization"] == f"Bearer {'x' * 40}"
    assert query["scope"] == ["https://app.vssps.visualstudio.com/.default"]


def test_coverage_plan_is_exact_repository_and_read_only() -> None:
    plan = azure_repos_coverage_plan(
        list(AZURE_REPOS_SCOPES), organization="example", repositories=REPOSITORIES
    )
    assert {item["repository_id"] for item in plan} == {REPOSITORY_ID}
    assert {permission for item in plan for permission in item["permissions"]} == {"vso.code"}
    assert all(item["coverage_mode"] == "exact-azure-repositories" for item in plan)


def test_validator_rebinds_repository_and_checks_default_revision() -> None:
    class Response:
        status_code = 200
        headers: dict[str, str] = {}

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {
                "count": 1,
                "value": [{"name": "refs/heads/main", "objectId": "a" * 40}],
            }

    class Client:
        def application_token(self, tenant_id: str) -> str:
            return "application-token"

        def list_repositories(
            self, *, organization: str, token: str
        ) -> list[dict[str, Any]]:
            return REPOSITORIES

        def request(self, method: str, **values: Any) -> Response:
            return Response()

    connection = {
        "configuration": {
            "tenant_id": ENTRA_TENANT_ID,
            "organization": "example",
            "repositories": REPOSITORIES,
            "onboarding": {"completed_at": datetime.now(UTC).isoformat()},
        },
        "declared_scopes": list(AZURE_REPOS_SCOPES),
        "coverage_plan": azure_repos_coverage_plan(
            list(AZURE_REPOS_SCOPES), organization="example", repositories=REPOSITORIES
        ),
    }
    validation = AzureReposConnectionValidator(Client()).validate(connection)  # type: ignore[arg-type]
    assert validation["health_state"] == "healthy"
    assert [item["state"] for item in validation["results"]] == ["passed", "passed"]
