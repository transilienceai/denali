"""Recovery narrows execution, never the saved installation/repository boundary."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from os import environ
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from test_gateway_capabilities import ASSET
from test_github_collection_dispatch import DispatchRepository
from test_github_repository_connector import connection as source_connection

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.connectors.github_repository import github_collection_boundary_hash
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository, _github_incomplete_retry_seed


def target():
    value = source_connection()
    value["declared_scopes"] = ["github.repository_contents"]
    value["credential_type"] = "github_app_installation"
    value["credential_reference"].update(app_id=1, app_slug="synthetic-fixture")
    first = value["configuration"]["repositories"][0]
    value["configuration"]["repositories"] = [
        {**first, "id": number, "node_id": f"R_{number}", "full_name": f"acme/repo-{number}"}
        for number in (42, 43, 44)
    ]
    return value


def checkpoint(tenant, selected):
    rows = {}
    for item, state in zip(selected["configuration"]["repositories"],
                           ("complete", "partial", "failed"), strict=True):
        result = {"repository_id": item["id"], "repository": item["full_name"],
                  "state": state, "revision": "a" * 40,
                  **{key: 0 for key in ("files", "bytes", "source_assets", "inventory_assets",
                      "inventory_relationships", "posture_findings", "deployment_relationships")},
                  "coverage": {key: "complete" for key in
                               ("source", "inventory", "posture", "correlation")},
                  "correlation": {key: 0 for key in
                                  ("declarations", "proven", "ambiguous", "unmatched",
                                   "targets_evaluated")}}
        if state == "partial":
            result["coverage"]["inventory"] = "partial"
        if state == "failed":
            result = {"repository_id": item["id"], "repository": item["full_name"],
                      "state": state, "detail": "repository_tree_request_limit_exceeded"}
        rows[str(item["id"])] = {
            "revision": "a" * 40, "default_branch": "main",
            "result": result,
        }
    return {"boundary_hash": github_collection_boundary_hash(tenant, selected),
            "repository_count": 3, "repositories": rows}


def test_seed_retains_only_complete_history_and_drops_affected_pins():
    selected = target()
    previous = checkpoint("tenant", selected)
    before = deepcopy((selected, previous))
    seed, result = _github_incomplete_retry_seed("tenant", selected, previous)
    assert set(seed["repositories"]) == {"42"}
    assert seed["retained_repository_ids"] == [42]
    assert seed["boundary_hash"] == previous["boundary_hash"]
    assert result["repository_count"] == 3
    assert result["retained_repository_count"] == 1
    assert result["retry_repository_count"] == 2
    assert result["refreshed_repository_count"] == 0
    assert (selected, previous) == before


@pytest.mark.parametrize("change", ["tenant", "installation", "scope", "repository"])
def test_retry_refuses_different_identity_or_permission_boundary(change):
    selected = target()
    previous = checkpoint("tenant", selected)
    tenant = "tenant"
    if change == "tenant":
        tenant = "other"
    elif change == "installation":
        selected["credential_reference"]["installation_id"] = 123
    elif change == "scope":
        selected["declared_scopes"].append("github.repository_metadata")
    else:
        selected["configuration"]["repositories"].pop()
    with pytest.raises(ValueError, match="compatible"):
        _github_incomplete_retry_seed(tenant, selected, previous)


def test_retry_requires_previous_checkpoint_and_an_incomplete_result():
    selected = target()
    with pytest.raises(ValueError):
        _github_incomplete_retry_seed("tenant", selected, None)
    previous = checkpoint("tenant", selected)
    complete = deepcopy(previous["repositories"]["42"]["result"])
    for item in selected["configuration"]["repositories"]:
        previous["repositories"][str(item["id"])]["result"] = {
            **deepcopy(complete), "repository_id": item["id"], "repository": item["full_name"]
        }
    with pytest.raises(ValueError, match="no incomplete"):
        _github_incomplete_retry_seed("tenant", selected, previous)


class RetryRepository(DispatchRepository):
    def __init__(self):
        super().__init__(stage="ok")
        self.retry_calls = []

    def create_connection_collection_job(self, tenant_id, connection_id, *, collection_kind,
                                         retry_incomplete=False, retry_of=None):
        self.retry_calls.append((tenant_id, retry_incomplete, retry_of))
        return super().create_connection_collection_job(
            tenant_id, connection_id, collection_kind=collection_kind
        )


def test_browser_retry_reuses_existing_admin_collection_boundary_and_dispatch():
    repo = RetryRepository()
    app = create_app(repository=repo, auth_mode="local", github_repository_collector=object(),
                     collection_dispatcher=repo.dispatch, migrate_on_start=False)
    connection_id = ASSET
    retry_of = str(uuid4())
    with TestClient(app) as client:
        first = client.post(f"/v1/connections/{connection_id}/github/collect",
                            json={"retry_of": retry_of})
        again = client.post(f"/v1/connections/{connection_id}/github/collect",
                            json={"retry_of": retry_of})
        expanded = client.post(f"/v1/connections/{connection_id}/github/collect",
                               json={"retry_of": retry_of, "repository_ids": [999]})
    assert first.status_code == again.status_code == 202
    assert again.json()["status"] == "already_running"
    assert repo.retry_calls[0][1:] == (True, retry_of)
    assert len(repo.dispatches) == 1
    assert expanded.status_code == 422


def test_retry_keeps_auth_admin_and_cross_organization_guards():
    class Authenticator:
        def authenticate(self, request):
            token = request.headers.get("authorization", "")
            if token == "Bearer member":
                return AuthContext("synthetic-user", "org_Alpha1", "member")
            if token == "Bearer admin":
                return AuthContext("synthetic-user", "org_Alpha1", "admin")
            if token == "Bearer other":
                return AuthContext("synthetic-other", "org_Beta2", "admin")
            raise AuthenticationError("invalid session")

    class HostedRetryRepository(RetryRepository):
        def resolve_tenant(self, org):
            return {"org_Alpha1": "tenant-alpha", "org_Beta2": "tenant-beta"}[org]

    repo = HostedRetryRepository()
    app = create_app(repository=repo, auth_mode="clerk", authenticator=Authenticator(),
                     github_repository_collector=object(), collection_dispatcher=repo.dispatch,
                     migrate_on_start=False)
    with TestClient(app) as client:
        for token, status in ((None, 401), ("member", 403), ("other", 404), ("admin", 202)):
            response = client.post(f"/v1/connections/{ASSET}/github/collect",
                json={"retry_of": str(uuid4())},
                headers={} if token is None else {"Authorization": f"Bearer {token}"})
            assert response.status_code == status
    assert len(repo.retry_calls) == 1


@pytest.mark.skipif(not environ.get("DENALI_TEST_DSN"), reason="DENALI_TEST_DSN is not set")
def test_postgres_retry_is_atomic_tenant_scoped_and_preserves_connection():
    dsn = environ["DENALI_TEST_DSN"]
    migrate(dsn)
    repo = PostgresInventoryRepository(dsn)
    tenant = repo.resolve_tenant(f"org_Retry{uuid4().hex}")
    other = repo.resolve_tenant(f"org_OtherRetry{uuid4().hex}")
    selected = target()
    selected["id"] = str(uuid4())
    repo.create_connection(tenant, connection_id=selected["id"], provider="github",
        display_name="Synthetic retry fixture", credential_type=selected["credential_type"],
        credential_reference=selected["credential_reference"],
        declared_scopes=selected["declared_scopes"], coverage_plan=[],
        configuration=selected["configuration"])
    selected = repo.get_connection_validation_target(tenant, selected["id"])
    before = deepcopy(selected)
    first, _ = repo.create_connection_collection_job(tenant, selected["id"],
                                                    collection_kind="github_source")
    first_id = str(first["id"])
    claimed = repo.claim_connection_collection_job(first_id, lease_seconds=60)
    assert repo.save_collection_checkpoint(first_id, claimed["attempt_count"],
                                          checkpoint(tenant, selected))
    assert repo.complete_resumable_collection_job(first_id, claimed["attempt_count"],
                                                  {"state": "partial"})
    with pytest.raises(ValueError):
        repo.create_connection_collection_job(other, selected["id"],
            collection_kind="github_source", retry_incomplete=True, retry_of=first_id)
    with pytest.raises(ValueError):
        repo.create_connection_collection_job(tenant, selected["id"],
            collection_kind="github_source", retry_incomplete=True, retry_of=str(uuid4()))
    def request_retry(_index):
        return repo.create_connection_collection_job(tenant, selected["id"],
            collection_kind="github_source", retry_incomplete=True, retry_of=first_id)

    with ThreadPoolExecutor(max_workers=2) as pool:
        concurrent = list(pool.map(request_retry, range(2)))
    assert sorted(created for _, created in concurrent) == [False, True]
    assert concurrent[0][0]["id"] == concurrent[1][0]["id"]
    retry, created = next(pair for pair in concurrent if pair[1])
    assert created and retry["checkpoint"]["retained_repository_ids"] == [42]
    assert set(retry["checkpoint"]["repositories"]) == {"42"}
    duplicate, created = repo.create_connection_collection_job(tenant, selected["id"],
        collection_kind="github_source", retry_incomplete=True, retry_of=first_id)
    assert not created and duplicate["id"] == retry["id"]
    assert repo.get_connection_validation_target(tenant, selected["id"]) == before
    claim = repo.claim_connection_collection_job(str(retry["id"]), lease_seconds=60)
    assert claim and repo.complete_resumable_collection_job(
        str(retry["id"]), claim["attempt_count"], {"state": "partial"}
    )
    # A delayed duplicate from the old page cannot start another retry after the
    # first one finishes: its optimistic parent-job guard is now stale.
    with pytest.raises(ValueError, match="no longer current"):
        repo.create_connection_collection_job(tenant, selected["id"],
            collection_kind="github_source", retry_incomplete=True, retry_of=first_id)
    with psycopg.connect(dsn) as conn:
        assert conn.execute("SELECT count(*) FROM connection_collection_job WHERE connection_id=%s",
                            (selected["id"],)).fetchone()[0] == 2
