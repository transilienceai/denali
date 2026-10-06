"""Pinned shared-installation subsets never inherit later provider consent."""

from __future__ import annotations

from copy import deepcopy
from importlib import import_module
from uuid import UUID

import httpx
import pytest
from test_shared_github import (
    CONNECTION_ID,
    LIST_ITEM,
    REPOSITORY,
    SCOPES,
    Platform,
    Repository,
    _client,
    target,
)

from denali.integrations.shared_github import (
    GitHubCollectorRouter,
    GitHubValidatorRouter,
    SharedGitHubAppClient,
    shared_github_binding_id,
)

QA_REPOSITORY = {
    **REPOSITORY,
    "id": 43,
    "node_id": "R_kg43",
    "name": "aaa-isolated-qa",
    "full_name": "transilienceai/aaa-isolated-qa",
}
PATH = f"/v1/shared/connections/github/{CONNECTION_ID}/use-in-denali"
ADMIN = {"Authorization": "Bearer alpha-admin"}


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_GITHUB_ENABLED", "true")
    monkeypatch.setattr(
        import_module("denali.api.app"), "_with_validation_state", lambda _r, _t, row: row
    )


class ExpandedPlatform(Platform):
    def __init__(self):
        super().__init__()
        self.repositories = [deepcopy(REPOSITORY), deepcopy(QA_REPOSITORY)]

    def request(self, method, path, **options):
        if path in {
            "/v1/connections",
            f"/internal/v1/connections/github/{CONNECTION_ID}/repositories",
        }:
            self.calls.append((method, path, options["clerk_org_id"], options.get("payload")))
            if path == "/v1/connections":
                return {
                    "items": [{**LIST_ITEM, "repository_count": len(self.repositories)}]
                }
            return {"items": deepcopy(self.repositories)}
        return super().request(method, path, **options)


def subset_target():
    row = deepcopy(target())
    row["configuration"]["coverage_mode"] = "exact-selected-repositories"
    row["configuration"]["repositories"] = [deepcopy(QA_REPOSITORY)]
    row["id"] = shared_github_binding_id("org_alpha", CONNECTION_ID, [43], SCOPES)
    return row


def token_calls(platform):
    return [call for call in platform.calls if call[1].endswith("/token")]


def test_installation_addition_preserves_legacy_config_probe_and_exact_token():
    platform = ExpandedPlatform()
    saved = deepcopy(target())
    snapshot = deepcopy(saved)
    app = SharedGitHubAppClient(platform, saved)
    app.get_installation(99)
    assert saved == snapshot
    # QA sorts first in the observed list. Validation must still probe saved 42.
    assert token_calls(platform)[0] == (
        "POST",
        f"/internal/v1/connections/github/{CONNECTION_ID}/token",
        "org_alpha",
        {"repository_ids": [42], "scopes": SCOPES},
    )
    with pytest.raises(RuntimeError, match="outside Denali"):
        app.create_installation_token(installation_id=99, repository_id=43)
    assert len(token_calls(platform)) == 1


@pytest.mark.parametrize(
    "change",
    [
        {"id": 44},
        {"node_id": "R_replaced"},
        {"name": "renamed", "full_name": "transilienceai/renamed"},
        {"name": "Demo", "full_name": "transilienceai/Demo"},
        {"owner_id": 8},
        {"owner_login": "other", "full_name": "other/demo"},
    ],
)
def test_refreshed_registry_identity_drift_denies_before_mint_even_after_addition(change):
    platform = ExpandedPlatform()
    platform.repositories[0].update(change)
    with pytest.raises((ValueError, RuntimeError)):
        SharedGitHubAppClient(platform, target()).get_installation(99)
    assert not token_calls(platform)


def test_explicit_subset_creates_independent_idempotent_binding_without_legacy_rebind():
    platform = ExpandedPlatform()
    repository = Repository()
    # Attach legacy selection before the installation's separately consented addition.
    platform.repositories = [deepcopy(REPOSITORY)]
    with _client(platform, repository) as client:
        legacy = client.post(PATH, json={}, headers=ADMIN)
        assert legacy.status_code == 201
        saved_legacy = deepcopy(repository.created[0])
        platform.repositories.append(deepcopy(QA_REPOSITORY))
        created = client.post(PATH, json={"repository_ids": [43]}, headers=ADMIN)
        repeated = client.post(
            PATH,
            json={"repository_ids": [43], "declared_scopes": list(reversed(SCOPES))},
            headers=ADMIN,
        )
        assert created.status_code == repeated.status_code == 201
        assert created.json()["id"] == repeated.json()["id"]
        assert created.json()["id"] != CONNECTION_ID
        UUID(created.json()["id"])
        assert created.json()["credential_reference"]["platform_connection_id"] == CONNECTION_ID
        assert created.json()["configuration"]["coverage_mode"] == "exact-selected-repositories"
        assert [row["id"] for row in created.json()["configuration"]["repositories"]] == [43]
        assert {row["repository_id"] for row in created.json()["coverage_plan"]} == {43}
        assert {row["coverage_mode"] for row in created.json()["coverage_plan"]} == {
            "exact-selected-repositories"
        }
        # Omitted selection cannot rewrite the legacy row to include the new repo.
        assert client.post(PATH, json={}, headers=ADMIN).status_code == 409
    assert len(repository.created) == 2
    assert repository.created[0] == saved_legacy
    assert [call[3]["repository_ids"] for call in token_calls(platform)] == [[42], [43]]
    assert "ghs_" not in str(repository.created)
    assert "ghs_" not in created.text


def test_explicit_selection_canonicalizes_repository_order_and_retains_platform_identity():
    platform = ExpandedPlatform()
    repository = Repository()
    with _client(platform, repository) as client:
        first = client.post(PATH, json={"repository_ids": [43, 42]}, headers=ADMIN)
        repeated = client.post(PATH, json={"repository_ids": [42, 43]}, headers=ADMIN)
    assert first.status_code == repeated.status_code == 201
    assert first.json()["id"] == repeated.json()["id"]
    assert len(repository.created) == 1
    assert token_calls(platform)[0][1] == (
        f"/internal/v1/connections/github/{CONNECTION_ID}/token"
    )
    assert first.json()["credential_reference"]["installation_id"] == 99


@pytest.mark.parametrize(
    "body",
    [
        {"repository_ids": []},
        {"repository_ids": [42, 42]},
        {"repository_ids": [0]},
        {"repository_ids": [-1]},
        {"repository_ids": [True]},
        {"repository_ids": [42.0]},
        {"repository_ids": ["42"]},
        {"repository_ids": list(range(1, 502))},
        {"repository_ids": [42], "connection_id": CONNECTION_ID},
        {"repository_ids": [42], "clerk_org_id": "org_beta"},
    ],
)
def test_explicit_selection_is_strict_and_cannot_supply_local_or_org_identity(body):
    platform = ExpandedPlatform()
    repository = Repository()
    with _client(platform, repository) as client:
        assert client.post(PATH, json=body, headers=ADMIN).status_code == 422
    assert not platform.calls
    assert not repository.created


def test_explicit_selection_requires_present_repositories_admin_and_pilot_org():
    platform = ExpandedPlatform()
    repository = Repository()
    with _client(platform, repository) as client:
        assert client.post(PATH, json={"repository_ids": [99]}, headers=ADMIN).status_code == 409
        platform.calls.clear()
        assert client.post(PATH, json={"repository_ids": [43]}).status_code == 401
        assert client.post(
            PATH, json={"repository_ids": [43]}, headers={"Authorization": "Bearer alpha-member"}
        ).status_code == 403
        assert client.post(
            PATH, json={"repository_ids": [43]}, headers={"Authorization": "Bearer beta-admin"}
        ).status_code == 404
    assert not repository.created
    assert not platform.calls


@pytest.mark.parametrize("mutation", ["id", "org", "platform", "repos", "scopes", "mode"])
def test_subset_local_binding_cannot_be_rebound_by_mutating_its_boundary(mutation):
    row = subset_target()
    if mutation == "id":
        row["id"] = "22222222-2222-4222-8222-222222222222"
    elif mutation == "org":
        row["clerk_organization_id"] = "org_beta"
    elif mutation == "platform":
        row["credential_reference"]["platform_connection_id"] = (
            "22222222-2222-4222-8222-222222222222"
        )
    elif mutation == "repos":
        row["configuration"]["repositories"] = [deepcopy(REPOSITORY)]
    elif mutation == "scopes":
        row["declared_scopes"] = [SCOPES[0]]
    else:
        row["configuration"]["coverage_mode"] = "exact-installation-repositories"
    platform = ExpandedPlatform()
    with pytest.raises(ValueError):
        SharedGitHubAppClient(platform, row)
    assert not platform.calls


def test_subset_tokens_use_platform_id_but_only_allow_saved_repo_reads(monkeypatch):
    platform = ExpandedPlatform()
    row = subset_target()
    app = SharedGitHubAppClient(platform, row)
    app.get_installation(99)
    token = app.create_installation_token(installation_id=99, repository_id=43)
    assert all(call[1].endswith(f"/{CONNECTION_ID}/token") for call in token_calls(platform))
    assert all(
        call[3] == {"repository_ids": [43], "scopes": SCOPES} for call in token_calls(platform)
    )
    with pytest.raises(RuntimeError):
        app.create_installation_token(installation_id=99, repository_id=42)
    reads = []

    def read(*args, **kwargs):
        reads.append((args, kwargs))
        return httpx.Response(
            200,
            json={**QA_REPOSITORY, "owner": {"id": 7, "login": "transilienceai"}},
            request=httpx.Request(*args),
        )

    monkeypatch.setattr(
        "denali.integrations.shared_github.httpx.request",
        read,
    )
    app.installation_request("GET", "/repos/transilienceai/aaa-isolated-qa", token=token)
    with pytest.raises(ValueError):
        app.installation_request("GET", "/repos/transilienceai/demo", token=token)
    assert len(reads) == 1


def test_local_subset_disable_delete_never_call_shared_installation_lifecycle():
    class LocalRepository(Repository):
        def create_connection(self, tenant_id, **kwargs):
            row = super().create_connection(tenant_id, **kwargs)
            row["display_name"] = kwargs["display_name"]
            return row

        def get_connection_validation_target(self, tenant_id, connection_id):
            return self.get_connection(tenant_id, connection_id)

        def disable_connection(self, tenant_id, connection_id):
            row = self.get_connection(tenant_id, connection_id)
            row["lifecycle_state"] = "disabled"
            return row

        def delete_connection(self, tenant_id, connection_id):
            row = self.get_connection(tenant_id, connection_id)
            assert row["lifecycle_state"] == "disabled"
            self.created.remove(row)
            return "deleted"

    platform = ExpandedPlatform()
    repository = LocalRepository()
    with _client(platform, repository) as client:
        legacy = client.post(PATH, json={}, headers=ADMIN).json()
        subset = client.post(PATH, json={"repository_ids": [43]}, headers=ADMIN).json()
        platform.calls.clear()
        local = f"/v1/connections/{subset['id']}"
        assert client.post(local + "/disable", headers=ADMIN).status_code == 200
        assert client.delete(
            local, params={"confirm": subset["display_name"]}, headers=ADMIN
        ).status_code == 204
        assert repository.created == [legacy]
        assert repository.created[0]["lifecycle_state"] == "active"
    assert not platform.calls


def test_binding_uuid_is_stable_and_distinct_for_each_trusted_boundary():
    expected = shared_github_binding_id("org_alpha", CONNECTION_ID, [42, 43], SCOPES)
    assert expected == shared_github_binding_id(
        "org_alpha", CONNECTION_ID, [43, 42], list(reversed(SCOPES))
    )
    assert expected != shared_github_binding_id("org_beta", CONNECTION_ID, [42, 43], SCOPES)
    assert expected != shared_github_binding_id("org_alpha", CONNECTION_ID, [42], SCOPES)
    assert expected != shared_github_binding_id("org_alpha", CONNECTION_ID, [42, 43], [SCOPES[0]])


@pytest.mark.parametrize("subset", [False, True])
def test_validator_and_collector_never_inherit_installation_additions(monkeypatch, subset):
    row = subset_target() if subset else deepcopy(target())
    selected = QA_REPOSITORY if subset else REPOSITORY
    platform = ExpandedPlatform()
    reads = []

    class Response:
        status_code = 200
        headers = {}

        def raise_for_status(self):
            pass

        def json(self):
            return {
                **selected,
                "owner": {"id": selected["owner_id"], "login": selected["owner_login"]},
                "default_branch": None,
                "total_count": 0,
            }

    def read(method, url, **_options):
        assert method == "GET"
        assert url in {
            f"https://api.github.com/repos/{selected['full_name']}",
            f"https://api.github.com/repos/{selected['full_name']}/actions/workflows",
        }
        reads.append(url)
        return Response()

    monkeypatch.setattr("denali.integrations.shared_github.httpx.request", read)

    class Sink:
        def __init__(self):
            self.batches = []

        def deployment_targets(self, _tenant):
            return []

        def ingest(self, _tenant, batch):
            self.batches.append(batch)
            return {"assets": 0, "relationships": 0}

        def ingest_findings(self, _tenant, _batch):
            return {"findings": 0}

    snapshot = deepcopy(row)
    validation = GitHubValidatorRouter(None, platform).validate(row)
    assert validation["health_state"] == "healthy"
    sink = Sink()
    collection = GitHubCollectorRouter(None, platform).collect(
        tenant_id="tenant", connection=row, repository=sink
    )
    assert collection["repository_count"] == 1 and collection["failed_count"] == 0
    assert collection["connection_id"] == row["id"]
    assert {repo["repository_id"] for repo in collection["repositories"]} == {selected["id"]}
    assert all(batch.connection_id == row["id"] for batch in sink.batches)
    assert row == snapshot
    assert reads
    assert all(call[3]["repository_ids"] == [selected["id"]] for call in token_calls(platform))
    assert "ghs_" not in str(validation) + str(collection)


@pytest.mark.parametrize("subset", [False, True])
@pytest.mark.parametrize(
    "change",
    [
        {"id": 44},
        {"node_id": "R_replaced"},
        {"full_name": "transilienceai/renamed"},
        {"case_name": True},
        {"owner": {"id": 8, "login": "transilienceai"}},
        {"owner": {"id": 7, "login": "Transilienceai"}},
        {"owner": {"id": 7, "login": "other"}},
        {"owner": None},
    ],
)
def test_stale_registry_live_identity_drift_blocks_content_workflows_and_evidence(
    monkeypatch, subset, change
):
    row = subset_target() if subset else deepcopy(target())
    selected = QA_REPOSITORY if subset else REPOSITORY
    platform = ExpandedPlatform()  # intentionally stale: saved identities remain unchanged
    observed = {
        **selected,
        "owner": {"id": selected["owner_id"], "login": selected["owner_login"]},
        "default_branch": "main",
    }
    if change.get("case_name"):
        owner, name = selected["full_name"].split("/")
        observed["full_name"] = owner + "/" + name[0].upper() + name[1:]
    else:
        observed.update(change)
    reads = []

    def read(method, url, **_options):
        assert method == "GET"
        assert url == f"https://api.github.com/repos/{selected['full_name']}"
        reads.append(url)
        return httpx.Response(200, json=observed, request=httpx.Request(method, url))

    monkeypatch.setattr("denali.integrations.shared_github.httpx.request", read)

    class Sink:
        def __init__(self):
            self.inventory, self.findings = [], []

        def deployment_targets(self, _tenant):
            return []

        def ingest(self, _tenant, batch):
            self.inventory.append(batch)
            return {"assets": 0, "relationships": 0}

        def ingest_findings(self, _tenant, batch):
            self.findings.append(batch)
            return {"findings": 0}

    saved = deepcopy(row)
    validation = GitHubValidatorRouter(None, platform).validate(row)
    assert validation["health_state"] != "healthy"
    assert all(result["state"] != "passed" for result in validation["results"])
    sink = Sink()
    collection = GitHubCollectorRouter(None, platform).collect(
        tenant_id="tenant", connection=row, repository=sink
    )
    assert collection["failed_count"] == collection["repository_count"] == 1
    assert all(not batch.assets and not batch.relationships for batch in sink.inventory)
    assert all(not batch.findings for batch in sink.findings)
    assert row == saved
    assert reads == [f"https://api.github.com/repos/{selected['full_name']}"] * 2
    assert all(call[3]["repository_ids"] == [selected["id"]] for call in token_calls(platform))
    assert "ghs_" not in str(validation) + str(collection) + str(sink.inventory)


def test_each_shared_lease_requires_root_metadata_before_any_content_or_workflow_read(monkeypatch):
    app = SharedGitHubAppClient(Platform(), deepcopy(target()))
    token = app.create_installation_token(installation_id=99, repository_id=42)
    reads = []

    def read(method, url, **_options):
        reads.append(url)
        return httpx.Response(
            200,
            json={**REPOSITORY, "owner": {"id": 7, "login": "transilienceai"}},
            request=httpx.Request(method, url),
        )

    monkeypatch.setattr("denali.integrations.shared_github.httpx.request", read)
    root = "/repos/transilienceai/demo"
    for suffix in ("/actions/workflows", "/git/ref/heads/main", "/git/trees/" + "a" * 40):
        with pytest.raises(ValueError, match="live repository verification is required"):
            app.installation_request("GET", root + suffix, token=token)
    assert not reads
    app.installation_request("GET", root, token=token)
    app.installation_request("GET", root + "/actions/workflows", token=token)
    # The fake broker intentionally reuses its token. A new lease resets proof.
    assert app.create_installation_token(installation_id=99, repository_id=42) == token
    with pytest.raises(ValueError, match="live repository verification is required"):
        app.installation_request("GET", root + "/actions/workflows", token=token)
    assert len(reads) == 2


def test_failed_root_transport_recheck_invalidates_existing_lease_proof(monkeypatch):
    app = SharedGitHubAppClient(Platform(), deepcopy(target()))
    token = app.create_installation_token(installation_id=99, repository_id=42)
    root = "/repos/transilienceai/demo"
    reads = []

    def read(method, url, **_options):
        reads.append(url)
        if len(reads) > 1:
            raise httpx.ConnectError("local simulated transport failure")
        return httpx.Response(
            200,
            json={**REPOSITORY, "owner": {"id": 7, "login": "transilienceai"}},
            request=httpx.Request(method, url),
        )

    monkeypatch.setattr("denali.integrations.shared_github.httpx.request", read)
    app.installation_request("GET", root, token=token)
    with pytest.raises(httpx.ConnectError):
        app.installation_request("GET", root, token=token)
    for suffix in ("/actions/workflows", "/git/ref/heads/main", "/git/blobs/" + "a" * 40):
        with pytest.raises(ValueError, match="live repository verification is required"):
            app.installation_request("GET", root + suffix, token=token)
    assert reads == ["https://api.github.com" + root] * 2
