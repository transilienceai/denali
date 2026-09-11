from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

import pytest

from denali.connectors.github_repository import (
    MAX_BLOB_BYTES,
    SOURCE_PLANE,
    GitHubRepositoryCollector,
    _eligible_path,
)
from denali.domain import CoverageState, InventoryBatch

COMMIT = "a" * 40
BLOB = "b" * 40
HANDLER_BLOB = "c" * 40
SOURCE = (
    "new nodejs.NodejsFunction(this, 'AgentFn', {\n"
    "  functionName: 'ni-sales-agent',\n"
    "  entry: 'src/handler.ts',\n"
    "});\n"
)
HANDLER = "export const handler = async () => ({ statusCode: 200 });\n"


def test_github_snapshot_selects_gcp_iac_inputs() -> None:
    assert _eligible_path("infra/main.tf")
    assert _eligible_path("deploy/service.yaml")
    assert _eligible_path("deploy/service.yml")


def test_github_snapshot_excludes_generated_source_artifacts() -> None:
    assert not _eligible_path("src/render/screenshots.generated.ts")
    assert not _eligible_path("src/client.generated.js")
    assert _eligible_path("src/generated-client.ts")


@dataclass
class Response:
    payload: dict[str, Any]

    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise ResponseError(self)

    def json(self) -> dict[str, Any]:
        return self.payload


class ResponseError(RuntimeError):
    def __init__(self, response: Response):
        super().__init__(f"HTTP {response.status_code}")
        self.response = response


class AppClient:
    def __init__(self, routes: dict[str, dict[str, Any] | Response]):
        self.routes = routes
        self.tokens: list[tuple[int, int]] = []
        self.requests: list[str] = []

    def get_installation(self, installation_id: int) -> dict[str, Any]:
        return {"id": installation_id, "account_id": 7}

    def create_installation_token(self, *, installation_id: int, repository_id: int) -> str:
        self.tokens.append((installation_id, repository_id))
        return "ghs_ephemeral-do-not-store"

    def installation_request(
        self, method: str, path: str, *, token: str, **kwargs: Any
    ) -> Response:
        assert method == "GET"
        assert token == "ghs_ephemeral-do-not-store"
        self.requests.append(path)
        routed = self.routes[path]
        return routed if isinstance(routed, Response) else Response(routed)


class SequencedAppClient(AppClient):
    def __init__(self, responses: list[Response]):
        super().__init__({})
        self.responses = responses
        self.calls = 0

    def installation_request(
        self, method: str, path: str, *, token: str, **kwargs: Any
    ) -> Response:
        response = self.responses[self.calls]
        self.calls += 1
        return response


class Sink:
    def __init__(self):
        self.batches: list[InventoryBatch] = []

    def deployment_targets(self, tenant_id: str) -> list[dict[str, Any]]:
        return [
            {
                "natural_key": "arn:aws:lambda:us-east-1:123:function:ni-sales-agent",
                "display_name": "ni-sales-agent",
                "service": "lambda",
                "logical_id": "AgentFnABC123",
                "evidence_locator": "aws://lambda/ni-sales-agent",
                "evidence_payload": {},
            }
        ]

    def ingest(self, tenant_id: str, batch: InventoryBatch) -> dict[str, int]:
        self.batches.append(batch)
        return {
            "assets": len(batch.assets),
            "relationships": len(batch.relationships),
            "withdrawn_assets": 0,
            "withdrawn_relationships": 0,
        }

    def ingest_findings(self, tenant_id: str, batch: Any) -> dict[str, int]:
        self.batches.append(batch)
        return {
            "findings": len(batch.findings),
            "new_observations": len(batch.findings),
            "withdrawn_findings": 0,
        }


def connection() -> dict[str, Any]:
    return {
        "id": "11111111-1111-4111-8111-111111111111",
        "provider": "github",
        "lifecycle_state": "active",
        "credential_reference": {"installation_id": 9},
        "configuration": {
            "account_id": 7,
            "repositories": [
                {
                    "id": 42,
                    "node_id": "R_repo",
                    "full_name": "acme/agent",
                    "owner_id": 7,
                    "owner_login": "acme",
                }
            ],
        },
    }


def two_repository_connection() -> dict[str, Any]:
    selected = connection()
    selected["configuration"]["repositories"].append(
        {
            "id": 43,
            "node_id": "R_platform",
            "full_name": "acme/platform",
            "owner_id": 7,
            "owner_login": "acme",
        }
    )
    return selected


def routes(*, truncated: bool = False, metadata_id: int = 42) -> dict[str, dict[str, Any]]:
    encoded = base64.b64encode(SOURCE.encode()).decode()
    handler_encoded = base64.b64encode(HANDLER.encode()).decode()
    return {
        "/repos/acme/agent": {
            "id": metadata_id,
            "node_id": "R_repo",
            "full_name": "acme/agent",
            "owner": {"id": 7, "login": "acme"},
            "default_branch": "main",
        },
        "/repos/acme/agent/git/ref/heads/main": {"object": {"sha": COMMIT}},
        f"/repos/acme/agent/git/trees/{COMMIT}": {
            "truncated": truncated,
            "tree": [
                {
                    "path": "infra/stack.ts",
                    "mode": "100644",
                    "type": "blob",
                    "sha": BLOB,
                    "size": len(SOURCE.encode()),
                },
                {
                    "path": "src/handler.ts",
                    "mode": "100644",
                    "type": "blob",
                    "sha": HANDLER_BLOB,
                    "size": len(HANDLER.encode()),
                },
                {
                    "path": "secret-link.ts",
                    "mode": "120000",
                    "type": "blob",
                    "sha": "d" * 40,
                    "size": 12,
                },
            ],
        },
        f"/repos/acme/agent/git/blobs/{BLOB}": {
            "sha": BLOB,
            "encoding": "base64",
            "content": f"{encoded[:20]}\n{encoded[20:]}",
        },
        f"/repos/acme/agent/git/blobs/{HANDLER_BLOB}": {
            "sha": HANDLER_BLOB,
            "encoding": "base64",
            "content": handler_encoded,
        },
    }


def second_repository_routes() -> dict[str, dict[str, Any]]:
    fixture = routes()
    remapped: dict[str, dict[str, Any]] = {}
    for path, payload in fixture.items():
        remapped[path.replace("/acme/agent", "/acme/platform")] = payload.copy()
    remapped["/repos/acme/platform"].update(
        {
            "id": 43,
            "node_id": "R_platform",
            "full_name": "acme/platform",
        }
    )
    return remapped


def test_collects_immutable_snapshot_and_persists_structured_correlation() -> None:
    app = AppClient(routes())
    sink = Sink()

    result = GitHubRepositoryCollector(app).collect(
        tenant_id="tenant", connection=connection(), repository=sink
    )

    assert result["state"] == "complete"
    assert result["repositories"][0]["revision"] == COMMIT
    assert result["repositories"][0]["files"] == 2
    assert result["repositories"][0]["correlation"]["proven"] == 1
    assert app.tokens == [(9, 42)]
    assert len(sink.batches) == 4
    source, inventory, posture, correlation = sink.batches
    assert source.coverage[0].plane == SOURCE_PLANE
    assert source.coverage[0].state is CoverageState.COMPLETE
    assert inventory.assets[0].evidence.locator == f"github://repositories/42/commits/{COMMIT}"
    assert "local_path" not in inventory.assets[0].attributes
    assert posture.connector_id == "denali.repository_posture"
    assert correlation.assets[0].attributes["correlation_summary"]["proven"] == 1
    assert len(correlation.relationships) == 1
    assert "ghs_ephemeral-do-not-store" not in repr(sink.batches)


def test_repository_identity_drift_is_failed_without_analyzing_source() -> None:
    sink = Sink()

    result = GitHubRepositoryCollector(AppClient(routes(metadata_id=99))).collect(
        tenant_id="tenant", connection=connection(), repository=sink
    )

    assert result["state"] == "partial"
    assert result["failed_count"] == 1
    assert result["repositories"][0]["detail"] == "repository_identity_mismatch"
    assert len(sink.batches) == 1
    assert sink.batches[0].assets == ()
    assert sink.batches[0].coverage[0].state is CoverageState.FAILED


def test_truncated_tree_is_failed_instead_of_claiming_partial_source() -> None:
    sink = Sink()

    result = GitHubRepositoryCollector(AppClient(routes(truncated=True))).collect(
        tenant_id="tenant", connection=connection(), repository=sink
    )

    assert result["repositories"][0]["detail"] == "repository_tree_incomplete"
    assert sink.batches[0].coverage[0].state is CoverageState.FAILED


def test_malformed_blob_is_failed_without_persisting_source() -> None:
    sink = Sink()
    malformed = routes()
    malformed[f"/repos/acme/agent/git/blobs/{BLOB}"]["content"] = "%%%not-base64%%%"

    result = GitHubRepositoryCollector(AppClient(malformed)).collect(
        tenant_id="tenant", connection=connection(), repository=sink
    )

    assert result["repositories"][0]["detail"] == "invalid_blob_encoding"
    assert len(sink.batches) == 1
    assert SOURCE not in repr(sink.batches)


def test_oversized_analysis_blob_is_skipped_with_partial_coverage() -> None:
    sink = Sink()
    oversized = routes()
    oversized[f"/repos/acme/agent/git/trees/{COMMIT}"]["tree"][0]["size"] = MAX_BLOB_BYTES + 1

    result = GitHubRepositoryCollector(AppClient(oversized)).collect(
        tenant_id="tenant", connection=connection(), repository=sink
    )

    assert result["state"] == "partial"
    assert result["partial_count"] == 1
    assert result["failed_count"] == 0
    assert sink.batches[0].coverage[0].state is CoverageState.PARTIAL
    assert "infra/stack.ts: larger than" in (sink.batches[0].coverage[0].detail or "")
    for batch in sink.batches[1:]:
        assert {item.state for item in batch.coverage} == {CoverageState.PARTIAL}
    assert not sink.batches[1].may_withdraw("repository_inventory")
    assert not sink.batches[2].may_resolve_missing
    assert not sink.batches[3].may_withdraw("code_to_cloud_deployments")


def test_repository_file_budget_produces_deterministic_partial_analysis(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr("denali.connectors.github_repository.MAX_SELECTED_FILES", 1)
    budgeted = routes()
    budgeted[f"/repos/acme/agent/git/trees/{COMMIT}"]["tree"] = [
        budgeted[f"/repos/acme/agent/git/trees/{COMMIT}"]["tree"][0],
        budgeted[f"/repos/acme/agent/git/trees/{COMMIT}"]["tree"][1],
    ]
    sink = Sink()

    result = GitHubRepositoryCollector(AppClient(budgeted)).collect(
        tenant_id="tenant", connection=connection(), repository=sink
    )

    assert result["failed_count"] == 0
    assert result["partial_count"] == 1
    assert result["repositories"][0]["files"] == 1
    assert "selected 1 of 2 eligible files" in (sink.batches[0].coverage[0].detail or "")


def test_connection_request_budget_is_shared_across_multiple_repositories() -> None:
    selected = two_repository_connection()
    app = AppClient({**routes(), **second_repository_routes()})
    sink = Sink()

    result = GitHubRepositoryCollector(
        app,
        max_requests=11,
        rate_limit_reserve=0,
    ).collect(tenant_id="tenant", connection=selected, repository=sink)

    assert result["github_requests"] == 11
    assert result["github_request_limit"] == 11
    assert result["request_budget_reached"] is True
    assert result["failed_count"] == 0
    assert result["partial_count"] == 2
    assert [item["files"] for item in result["repositories"]] == [1, 1]
    assert app.tokens == [(9, 42), (9, 43)]
    assert len(app.requests) == 8
    assert sum("/git/blobs/" in path for path in app.requests) == 2
    for batch in sink.batches:
        assert all(item.state is not CoverageState.COMPLETE for item in batch.coverage)


def test_provider_rate_limit_reserve_stops_all_later_repositories_as_partial() -> None:
    selected = two_repository_connection()
    limited = routes()
    limited["/repos/acme/agent"] = Response(
        limited["/repos/acme/agent"],
        headers={"x-ratelimit-remaining": "500"},
    )
    app = AppClient({**limited, **second_repository_routes()})
    sink = Sink()

    result = GitHubRepositoryCollector(app).collect(
        tenant_id="tenant", connection=selected, repository=sink
    )

    assert result["state"] == "partial"
    assert result["failed_count"] == 0
    assert result["partial_count"] == 2
    assert result["request_budget_reached"] is True
    assert app.tokens == [(9, 42)]
    assert app.requests == ["/repos/acme/agent"]
    assert {item["detail"] for item in result["repositories"]} == {
        "github_rate_limit_reserve_reached"
    }
    assert all(batch.coverage[0].state is CoverageState.PARTIAL for batch in sink.batches)


def test_empty_repository_is_a_complete_zero_source_snapshot() -> None:
    empty = routes()
    empty["/repos/acme/agent"]["default_branch"] = None
    sink = Sink()

    result = GitHubRepositoryCollector(AppClient(empty)).collect(
        tenant_id="tenant", connection=connection(), repository=sink
    )

    assert result["state"] == "complete"
    assert result["repositories"][0]["revision"] == "empty"
    assert result["repositories"][0]["files"] == 0
    assert sink.batches[0].coverage[0].detail == "repository_empty"


def test_git_ref_conflict_is_treated_as_an_empty_repository() -> None:
    empty = routes()
    empty["/repos/acme/agent/git/ref/heads/main"] = Response({}, status_code=409)
    sink = Sink()

    result = GitHubRepositoryCollector(AppClient(empty)).collect(
        tenant_id="tenant", connection=connection(), repository=sink
    )

    assert result["state"] == "complete"
    assert result["repositories"][0]["revision"] == "empty"


def test_permission_failure_keeps_a_specific_safe_error_code() -> None:
    denied = routes()
    denied["/repos/acme/agent"] = Response({}, status_code=403)
    sink = Sink()

    result = GitHubRepositoryCollector(AppClient(denied)).collect(
        tenant_id="tenant", connection=connection(), repository=sink
    )

    assert result["repositories"][0]["detail"] == "github_permission_denied"


def test_transient_github_failures_are_retried_with_a_bound() -> None:
    app = SequencedAppClient(
        [
            Response({}, status_code=503),
            Response({}, status_code=503),
            Response({"ok": True}),
        ]
    )

    payload = GitHubRepositoryCollector(app)._json("GET", "/fixture", token="token")

    assert payload == {"ok": True}
    assert app.calls == 3


@pytest.mark.parametrize(
    ("status_code", "headers"),
    [
        (429, {"Retry-After": "2100"}),
        (403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"}),
    ],
)
def test_rate_limit_wait_headers_stop_partial_without_later_repository_calls(
    status_code: int,
    headers: dict[str, str],
) -> None:
    limited = routes()
    limited["/repos/acme/agent"] = Response({}, status_code=status_code, headers=headers)
    app = AppClient({**limited, **second_repository_routes()})
    sink = Sink()

    result = GitHubRepositoryCollector(app).collect(
        tenant_id="tenant",
        connection=two_repository_connection(),
        repository=sink,
    )

    assert result["state"] == "partial"
    assert result["failed_count"] == 0
    assert result["partial_count"] == 2
    assert result["request_budget_reached"] is True
    assert app.tokens == [(9, 42)]
    assert app.requests == ["/repos/acme/agent"]
    assert {item["detail"] for item in result["repositories"]} == {"github_rate_limited"}
    assert all(batch.coverage[0].state is CoverageState.PARTIAL for batch in sink.batches)


def test_rate_limit_during_blob_fetch_marks_current_snapshot_partial() -> None:
    limited = routes()
    limited[f"/repos/acme/agent/git/blobs/{BLOB}"] = Response(
        {}, status_code=429, headers={"Retry-After": "2100"}
    )
    sink = Sink()

    result = GitHubRepositoryCollector(AppClient(limited)).collect(
        tenant_id="tenant", connection=connection(), repository=sink
    )

    assert result["state"] == "partial"
    assert result["failed_count"] == 0
    assert result["partial_count"] == 1
    assert "github_rate_limited" in (sink.batches[0].coverage[0].detail or "")
    assert all(batch.coverage[0].state is CoverageState.PARTIAL for batch in sink.batches)
