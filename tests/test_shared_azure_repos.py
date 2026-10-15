"""A Platform outage or drift can never select native Azure DevOps credentials."""

from __future__ import annotations

import base64
import copy
import hashlib
from typing import Any
from uuid import uuid4

import pytest
from test_azure_repos_repository_connector import Repository

from denali.connections.azure_repos import AZURE_REPOS_SCOPES
from denali.integrations.shared_azure_repos import (
    CREDENTIAL_TYPE,
    MAX_CHUNK_BYTES,
    ROOT,
    AzureReposCollectorRouter,
    AzureReposValidatorRouter,
    SharedAzureReposClient,
    normalize_repositories,
    shared_azure_repos_binding_id,
)

ORG = "org_AzureReposFixture"
PLATFORM_ID = "11111111-1111-4111-8111-111111111111"
TENANT = "22222222-2222-4222-8222-222222222222"
REPO_ID = "33333333-3333-4333-8333-333333333333"
PROJECT_ID = "44444444-4444-4444-8444-444444444444"
COMMIT = "a" * 40
CONTENT = b'resource "azurerm_linux_function_app" "agent" { name = "test-agent" }\n'
BOUNDARY = {
    "id": REPO_ID,
    "name": "agent",
    "project_id": PROJECT_ID,
    "project_name": "AI",
    "full_name": "AI/agent",
    "default_branch": "refs/heads/main",
}


def connection() -> dict[str, Any]:
    return {
        "id": shared_azure_repos_binding_id(ORG, PLATFORM_ID, [REPO_ID], list(AZURE_REPOS_SCOPES)),
        "clerk_organization_id": ORG,
        "provider": "azure_repos",
        "lifecycle_state": "active",
        "credential_type": CREDENTIAL_TYPE,
        "credential_reference": {"platform_connection_id": PLATFORM_ID},
        "declared_scopes": list(AZURE_REPOS_SCOPES),
        "coverage_plan": [],
        "configuration": {
            "tenant_id": TENANT,
            "organization": "example",
            "repositories": [copy.deepcopy(BOUNDARY)],
            "onboarding": {"completed_at": "2026-10-15T00:00:00Z"},
        },
    }


class Broker:
    def __init__(self, content: bytes = CONTENT):
        self.calls = []
        self.content = content
        self.blob = hashlib.sha1(f"blob {len(content)}\0".encode() + content).hexdigest()
        self.repositories = [copy.deepcopy(BOUNDARY)]
        self.selected_ids = [REPO_ID]
        self.patch: dict[str, Any] = {}
        self.fail = False

    def allows_org(self, org):
        return org == ORG

    def request(self, method, path, *, clerk_org_id, payload, max_response_bytes):
        assert method == "POST" and path == f"{ROOT}/{PLATFORM_ID}/read"
        assert clerk_org_id == ORG and max_response_bytes == 2_097_152
        self.calls.append(copy.deepcopy(payload))
        if self.fail:
            raise RuntimeError("broker unavailable")
        operation = payload["operation"]
        if operation == "repositories":
            assert payload["repository_ids"] == self.selected_ids
            return {"items": self.repositories}
        selected = next(row for row in self.repositories if row["id"] == payload["repository_id"])
        assert payload["expected_repository"] == {
            key: selected[key] for key in ("id", "project_id", "name", "project_name", "full_name")
        }
        if operation == "refs":
            return {"value": [{"name": "refs/heads/main", "objectId": COMMIT}]}
        if operation == "tree":
            assert payload["commit"] == COMMIT
            return {"value": [{"path": "/main.tf", "objectId": self.blob, "isFolder": False}]}
        assert payload["object_id"] == self.blob
        if operation == "blob_metadata":
            return {"objectId": self.blob, "size": len(self.content)}
        assert operation == "blob_chunk"
        start = payload["offset"]
        chunk = self.content[start : start + MAX_CHUNK_BYTES]
        end = start + len(chunk)
        return {
            "content_base64": base64.b64encode(chunk).decode(),
            "total_bytes": len(self.content),
            "next_offset": end if end < len(self.content) else None,
            **self.patch,
        }


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_AZURE_REPOS_ENABLED", "true")


def client_and_token(broker=None):
    client = SharedAzureReposClient(broker or Broker(), connection())
    return client, client.application_token(TENANT)


def test_validator_and_collector_use_mediated_reads_without_retaining_credentials_or_source():
    broker = Broker()
    row = connection()
    validation = AzureReposValidatorRouter(None, broker).validate(row)
    assert validation["health_state"] == "healthy"
    sink = Repository()
    result = AzureReposCollectorRouter(None, broker).collect(
        tenant_id=str(uuid4()),
        connection=row,
        repository=sink,
    )
    assert result["failed_count"] == 0
    assert result["repositories"][0]["revision"] == COMMIT
    assert result["repositories"][0]["files"] == 1
    assert {call["operation"] for call in broker.calls} == {
        "repositories",
        "refs",
        "tree",
        "blob_metadata",
        "blob_chunk",
    }
    retained = str(result) + str(sink.inventory) + str(sink.findings) + str(row)
    assert CONTENT.decode() not in retained
    assert "shared-azure-repos:" not in retained
    assert "content_base64" not in retained


def test_evidence_links_are_pinned_project_qualified_and_ignore_provider_urls():
    row = connection()
    selected = [
        {
            **BOUNDARY,
            "project_name": "AI One#",
            "name": "agent +%",
            "full_name": "AI One#/agent +%",
        },
        {
            **BOUNDARY,
            "id": "55555555-5555-4555-8555-555555555555",
            "project_id": "66666666-6666-4666-8666-666666666666",
            "project_name": "AI Two?",
            "name": "agent +%",
            "full_name": "AI Two?/agent +%",
        },
    ]
    row["configuration"]["repositories"] = copy.deepcopy(selected)
    row["id"] = shared_azure_repos_binding_id(
        ORG, PLATFORM_ID, [item["id"] for item in selected], list(AZURE_REPOS_SCOPES)
    )
    broker = Broker()
    broker.repositories = [
        {**item, "remote_url": "https://attacker.invalid/never-trusted"} for item in selected
    ]
    broker.selected_ids = sorted(item["id"] for item in selected)
    client = SharedAzureReposClient(broker, row)
    observed = client.list_repositories(
        organization="example", token=client.application_token(TENANT)
    )
    expected = {
        "https://dev.azure.com/example/AI%20One%23/_git/agent%20%2B%25",
        "https://dev.azure.com/example/AI%20Two%3F/_git/agent%20%2B%25",
    }
    assert {item["remote_url"] for item in observed} == expected
    assert all("remote_url" not in item for item in normalize_repositories({"items": observed}))
    sink = Repository()
    result = AzureReposCollectorRouter(None, broker).collect(
        tenant_id=str(uuid4()), connection=row, repository=sink
    )
    assert result["failed_count"] == 0 and result["repository_count"] == 2
    evidence_links = {
        asset.evidence.payload["remote"]
        for batch in sink.inventory
        for asset in batch.assets
        if asset.evidence.payload and "remote" in asset.evidence.payload
    }
    assert evidence_links == expected
    assert all("remote_url" not in item for item in row["configuration"]["repositories"])
    assert "attacker.invalid" not in str(sink.inventory)


def test_chunked_blob_supports_native_two_megabyte_limit_and_verifies_git_identity():
    broker = Broker(b"a" * 1_800_000)
    client, token = client_and_token(broker)
    result = client.request(
        "GET",
        organization="example",
        token=token,
        path=f"/_apis/git/repositories/{REPO_ID}/blobs/{broker.blob}",
        params={"$format": "octetStream", "download": "true"},
        accept="application/octet-stream",
    )
    assert result.content == broker.content
    assert [call["offset"] for call in broker.calls] == [0, 750_000, 1_500_000]


@pytest.mark.parametrize(
    "patch",
    [
        {"total_bytes": 2_000_001},
        {"total_bytes": True},
        {"total_bytes": -1},
        {"content_base64": "!"},
        {"content_base64": ""},
        {"next_offset": 1},
        {"content_base64": base64.b64encode(b"different").decode()},
    ],
)
def test_malformed_or_changed_blob_fails_closed(patch):
    broker = Broker()
    broker.patch = patch
    client, token = client_and_token(broker)
    with pytest.raises(ValueError):
        client.request(
            "GET",
            organization="example",
            token=token,
            path=f"/_apis/git/repositories/{REPO_ID}/blobs/{broker.blob}",
            params={"$format": "octetStream", "download": "true"},
            accept="application/octet-stream",
        )


@pytest.mark.parametrize(
    "field,value",
    [
        ("id", str(uuid4())),
        ("project_id", str(uuid4())),
        ("name", "renamed"),
        ("project_name", "Other"),
    ],
)
def test_pinned_repository_drift_never_produces_source_evidence(field, value):
    broker = Broker()
    broker.repositories[0][field] = value
    broker.repositories[0]["full_name"] = (
        f"{broker.repositories[0]['project_name']}/{broker.repositories[0]['name']}"
    )
    sink = Repository()
    result = AzureReposCollectorRouter(None, broker).collect(
        tenant_id=str(uuid4()),
        connection=connection(),
        repository=sink,
    )
    assert result["failed_count"] == 1
    assert all(call["operation"] == "repositories" for call in broker.calls)
    assert not sink.findings
    assert all(not batch.assets for batch in sink.inventory)


@pytest.mark.parametrize(
    "path,params",
    [
        (f"/_apis/git/repositories/{uuid4()}/refs", {"filter": "heads/main"}),
        (f"/_apis/git/repositories/{REPO_ID}/pushes", {}),
        (f"https://dev.azure.com/example/_apis/git/repositories/{REPO_ID}/refs", {}),
        (
            f"/_apis/git/repositories/{REPO_ID}/refs",
            {"filter": "heads/main", "url": "https://other"},
        ),
        (f"/_apis/git/repositories/{REPO_ID}/refs", {"filter": "tags/v1"}),
        (f"/_apis/git/repositories/{REPO_ID}/items", {"versionDescriptor.version": "main"}),
        (f"/_apis/git/repositories/{REPO_ID}/blobs/{'a' * 40}", {"download": "true"}),
    ],
)
def test_arbitrary_paths_queries_and_unselected_repositories_never_cross_broker(path, params):
    broker = Broker()
    client, token = client_and_token(broker)
    with pytest.raises(ValueError):
        client.request("GET", organization="example", path=path, token=token, params=params)
    assert broker.calls == []


def test_org_scope_disabled_and_broker_failure_do_not_use_native_identity(monkeypatch):
    broker = Broker()
    client, token = client_and_token(broker)
    for org, handle in [("other", token), ("example", "native-token")]:
        with pytest.raises(ValueError):
            client.list_repositories(organization=org, token=handle)
    row = connection()
    row["declared_scopes"] = [AZURE_REPOS_SCOPES[0]]
    row["id"] = shared_azure_repos_binding_id(ORG, PLATFORM_ID, [REPO_ID], row["declared_scopes"])
    narrow = SharedAzureReposClient(broker, row)
    with pytest.raises(ValueError):
        narrow.request(
            "GET",
            organization="example",
            token=narrow.application_token(TENANT),
            path=f"/_apis/git/repositories/{REPO_ID}/refs",
            params={"filter": "heads/main"},
        )
    broker.fail = True
    sink = Repository()
    result = AzureReposCollectorRouter(object(), broker).collect(
        tenant_id=str(uuid4()),
        connection=connection(),
        repository=sink,
    )
    assert result["failed_count"] == 1 and not sink.findings
    monkeypatch.delenv("DENALI_PLATFORM_AZURE_REPOS_ENABLED")
    with pytest.raises(ValueError):
        SharedAzureReposClient(broker, connection())


def test_reordered_selection_is_same_binding_but_scope_and_org_changes_are_separate():
    other = str(uuid4())
    first = shared_azure_repos_binding_id(
        ORG, PLATFORM_ID, [REPO_ID, other], list(AZURE_REPOS_SCOPES)
    )
    assert first == shared_azure_repos_binding_id(
        ORG, PLATFORM_ID, [other, REPO_ID], list(reversed(AZURE_REPOS_SCOPES))
    )
    assert first != shared_azure_repos_binding_id(
        "org_Other", PLATFORM_ID, [REPO_ID, other], list(AZURE_REPOS_SCOPES)
    )
    assert first != shared_azure_repos_binding_id(
        ORG, PLATFORM_ID, [REPO_ID], list(AZURE_REPOS_SCOPES)
    )
    with pytest.raises(ValueError):
        normalize_repositories({"items": [BOUNDARY, BOUNDARY]})
