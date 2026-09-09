from __future__ import annotations

from typing import Any

from denali.connectors.azure_repos_repository import AzureReposRepositoryCollector

TENANT_ID = "11111111-1111-4111-8111-111111111111"
CONNECTION_ID = "22222222-2222-4222-8222-222222222222"
REPOSITORY_ID = "33333333-3333-4333-8333-333333333333"
PROJECT_ID = "44444444-4444-4444-8444-444444444444"
COMMIT = "a" * 40
BLOB = "b" * 40
CONTENT = b'resource "azurerm_linux_function_app" "agent" {\n  name = "anna-agent"\n}\n'
BOUNDARY = {
    "id": REPOSITORY_ID,
    "name": "anna",
    "full_name": "AI/anna",
    "project_id": PROJECT_ID,
    "project_name": "AI",
    "default_branch": "refs/heads/main",
    "remote_url": "https://dev.azure.com/example/AI/_git/anna",
}


class Response:
    def __init__(self, payload: Any = None, *, content: bytes = b""):
        self.payload = payload
        self.content = content
        self.status_code = 200
        self.headers: dict[str, str] = {}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> Any:
        return self.payload


class Client:
    def __init__(self):
        self.requests: list[dict[str, Any]] = []

    def application_token(self, tenant_id: str) -> str:
        assert tenant_id == TENANT_ID
        return "short-lived-application-token"

    def list_repositories(self, *, organization: str, token: str) -> list[dict[str, Any]]:
        assert organization == "example"
        return [BOUNDARY]

    def request(self, method: str, **values: Any) -> Response:
        self.requests.append({"method": method, **values})
        path = values["path"]
        params = values.get("params", {})
        if path.endswith("/refs"):
            return Response(
                {
                    "count": 1,
                    "value": [{"name": "refs/heads/main", "objectId": COMMIT}],
                }
            )
        if path.endswith("/items"):
            return Response(
                {
                    "count": 1,
                    "value": [
                        {
                            "objectId": BLOB,
                            "gitObjectType": "blob",
                            "isFolder": False,
                            "path": "/main.tf",
                        }
                    ],
                }
            )
        if params.get("$format") == "octetStream":
            return Response(content=CONTENT)
        return Response({"objectId": BLOB, "size": len(CONTENT)})


class Repository:
    def __init__(self):
        self.inventory = []
        self.findings = []

    def deployment_targets(self, tenant_id: str) -> list[dict[str, Any]]:
        return []

    def ingest(self, tenant_id: str, batch: Any) -> dict[str, int]:
        self.inventory.append(batch)
        return {"assets": len(batch.assets), "relationships": len(batch.relationships)}

    def ingest_findings(self, tenant_id: str, batch: Any) -> dict[str, int]:
        self.findings.append(batch)
        return {"findings": len(batch.findings)}


def test_collects_immutable_bounded_source_without_retaining_token_or_blobs() -> None:
    client = Client()
    repository = Repository()
    collector = AzureReposRepositoryCollector(client)  # type: ignore[arg-type]
    connection = {
        "id": CONNECTION_ID,
        "provider": "azure_repos",
        "lifecycle_state": "active",
        "configuration": {
            "tenant_id": TENANT_ID,
            "organization": "example",
            "repositories": [BOUNDARY],
            "onboarding": {"completed_at": "2026-09-09T00:00:00+00:00"},
        },
    }

    result = collector.collect(
        tenant_id=TENANT_ID,
        connection=connection,
        repository=repository,
    )

    assert result["state"] == "partial"
    assert result["failed_count"] == 0
    assert result["repositories"][0]["revision"] == COMMIT
    assert result["repositories"][0]["files"] == 1
    source_batch = repository.inventory[0]
    assert source_batch.connector_id == "denali.azure_repos_repository"
    assert source_batch.assets[0].asset.natural_key == "dev.azure.com/example/AI/anna"
    serialized = str(repository.inventory) + str(result)
    assert "short-lived-application-token" not in serialized
    assert CONTENT.decode() not in serialized


def test_repository_identity_mismatch_is_failed_not_silently_rebound() -> None:
    client = Client()
    repository = Repository()
    collector = AzureReposRepositoryCollector(client)  # type: ignore[arg-type]
    selected = {**BOUNDARY, "project_id": "55555555-5555-4555-8555-555555555555"}
    result = collector.collect(
        tenant_id=TENANT_ID,
        connection={
            "id": CONNECTION_ID,
            "provider": "azure_repos",
            "lifecycle_state": "active",
            "configuration": {
                "tenant_id": TENANT_ID,
                "organization": "example",
                "repositories": [selected],
                "onboarding": {"completed_at": "2026-09-09T00:00:00+00:00"},
            },
        },
        repository=repository,
    )
    assert result["state"] == "partial"
    assert result["repositories"][0]["detail"] == "repository_identity_mismatch"
