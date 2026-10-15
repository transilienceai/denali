"""Durable repository handoffs survive replacement without switching tenant or plan."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from test_shared_azure_repos_api import (
    AUTH,
    BASE,
    BETA,
    MEMBER,
    Platform,
    launch_payload,
    use_payload,
)
from test_shared_connections_api import FakeAuthenticator

from denali.api.app import _require_gateway_connection_job_ready, create_app
from denali.api.connection_workflows import new_return_state
from denali.integrations.shared_azure_repos import CREDENTIAL_TYPE
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


@pytest.fixture
def repo():
    assert DSN
    migrate(DSN)
    return PostgresInventoryRepository(DSN)


def test_azure_repos_workflow_pins_provider_local_and_platform_identity(repo):
    marker = uuid4().hex
    alpha = repo.resolve_tenant(f"org_RepositoryAlpha{marker}")
    beta = repo.resolve_tenant(f"org_RepositoryBeta{marker}")
    platform_id, local_id, request_id = str(uuid4()), str(uuid4()), str(uuid4())
    repo.create_connection(
        alpha,
        connection_id=local_id,
        provider="azure_repos",
        display_name=f"source-{marker}",
        credential_type=CREDENTIAL_TYPE,
        credential_reference={"platform_connection_id": platform_id},
        declared_scopes=["azure_repos.repository_metadata"],
        configuration={},
        coverage_plan=[],
    )
    state, first_digest = new_return_state()
    first = repo.begin_connection_onboarding(
        alpha,
        provider="azure_repos",
        request_id=request_id,
        connection_id=local_id,
        platform_connection_id=platform_id,
        return_state_sha256=first_digest,
    )
    assert first["expires_at"] > first["created_at"]
    assert (first["expires_at"] - first["created_at"]).total_seconds() <= 30 * 60 + 1
    receipt = repo.get_connection_onboarding(alpha, str(first["id"]))
    assert receipt["provider"] == "azure_repos"
    assert receipt["platform_connection_id"] == UUID(platform_id)
    assert receipt["connection_id"] == UUID(local_id)
    assert "return_state" not in str(receipt) and state not in str(receipt)
    assert repo.get_connection_onboarding(beta, str(first["id"])) is None
    assert repo.list_connection_onboarding(beta) == []

    # Provider is part of the idempotency namespace, but the original binding is immutable.
    github = repo.begin_connection_onboarding(
        alpha,
        provider="github",
        request_id=request_id,
        return_state_sha256=new_return_state()[1],
    )
    assert github["id"] != first["id"]
    for binding in (
        {"connection_id": None, "platform_connection_id": platform_id},
        {"connection_id": local_id, "platform_connection_id": str(uuid4())},
    ):
        with pytest.raises(ValueError, match="another connection"):
            repo.begin_connection_onboarding(
                alpha,
                provider="azure_repos",
                request_id=request_id,
                return_state_sha256=new_return_state()[1],
                **binding,
            )
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        repo.begin_connection_onboarding(
            beta,
            provider="azure_repos",
            request_id=str(uuid4()),
            connection_id=local_id,
            platform_connection_id=platform_id,
            return_state_sha256=new_return_state()[1],
        )
    _, latest_digest = new_return_state()
    replacement = PostgresInventoryRepository(DSN)
    latest = replacement.begin_connection_onboarding(
        alpha,
        provider="azure_repos",
        request_id=request_id,
        connection_id=local_id,
        platform_connection_id=platform_id,
        return_state_sha256=latest_digest,
    )
    assert latest["id"] == first["id"]
    assert replacement.consume_connection_onboarding_return(first_digest, succeeded=True) is None
    # A delayed failure for the old launch cannot invalidate the latest return state.
    repo.fail_connection_onboarding(alpha, str(first["id"]), return_state_sha256=first_digest)
    assert repo.get_connection_onboarding(alpha, str(first["id"]))["status"] == "in_progress"
    repo.fail_connection_onboarding(beta, str(first["id"]), return_state_sha256=latest_digest)
    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(
            workers.map(
                lambda _: replacement.consume_connection_onboarding_return(
                    latest_digest, succeeded=True
                ),
                range(2),
            )
        )
    assert sum(outcome is not None for outcome in outcomes) == 1
    assert repo.get_connection_onboarding(alpha, str(first["id"]))["status"] == "returned"


def test_azure_repos_callback_after_api_replacement_uses_original_tenant(repo):
    alpha = repo.resolve_tenant("org_alpha")
    beta = repo.resolve_tenant("org_beta")
    state, digest = new_return_state()
    workflow = repo.begin_connection_onboarding(
        alpha,
        provider="azure_repos",
        request_id=str(uuid4()),
        platform_connection_id=str(uuid4()),
        return_state_sha256=digest,
    )
    app = create_app(
        repository=PostgresInventoryRepository(DSN),
        auth_mode="clerk",
        authenticator=FakeAuthenticator(),
        migrate_on_start=False,
    )
    with TestClient(app) as web:
        path = f"/v1/connections/onboarding/{workflow['id']}"
        assert web.get(path, headers=BETA).status_code == 404
        # Even a currently authenticated other organization cannot redirect ownership.
        callback = web.get(
            "/v1/connections/onboarding/callback",
            headers=BETA,
            params={"state": state, "status": "succeeded"},
            follow_redirects=False,
        )
        assert callback.status_code == 303
        assert callback.headers["location"] == f"/connections?onboarding={workflow['id']}"
        assert state not in callback.headers["location"]
        resumed = web.get(path, headers=MEMBER)
        assert resumed.status_code == 200 and resumed.json()["provider"] == "azure_repos"
        assert resumed.json()["status"] == "returned"
        assert web.get(path, headers=BETA).status_code == 404
    assert repo.get_connection_onboarding(beta, str(workflow["id"])) is None
    expired = repo.begin_connection_onboarding(
        alpha,
        provider="azure_repos",
        request_id=str(uuid4()),
        platform_connection_id=str(uuid4()),
        return_state_sha256=new_return_state()[1],
    )
    with psycopg.connect(DSN) as db:
        db.execute(
            "UPDATE connection_onboarding_workflow "
            "SET expires_at=now()-interval '1 second' WHERE id=%s",
            (expired["id"],),
        )
    assert (
        repo.consume_connection_onboarding_return(expired["return_state_sha256"], succeeded=True)
        is None
    )


def test_real_azure_repos_attachment_projection_resume_jobs_and_local_disable(repo, monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_AZURE_REPOS_ENABLED", "true")
    platform = Platform()
    platform_id = str(uuid4())
    platform.source["id"] = platform_id
    dispatches = []
    app = create_app(
        repository=repo,
        auth_mode="clerk",
        authenticator=FakeAuthenticator(),
        shared_connections_client=platform,
        migrate_on_start=False,
        validation_dispatcher=lambda job: dispatches.append(("validation", job)),
        collection_dispatcher=lambda job: dispatches.append(("collection", job)),
    )
    alpha, beta = repo.resolve_tenant("org_alpha"), repo.resolve_tenant("org_beta")
    with TestClient(app) as web:
        attach_path = f"{BASE}/{platform_id}/use-in-denali"
        first = web.post(attach_path, headers=AUTH, json=use_payload())
        assert first.status_code == 201
        local_id = first.json()["id"]
        assert local_id != platform_id
        assert first.json()["credential_reference"] == {
            "type": CREDENTIAL_TYPE,
            "platform_connection_id": platform_id,
        }
        assert web.post(attach_path, headers=AUTH, json=use_payload()).json()["id"] == local_id
        assert repo.get_connection(beta, local_id) is None
        target = repo.get_connection_validation_target(alpha, local_id)
        assert target["clerk_organization_id"] == "org_alpha"
        assert target["credential_reference"] == {"platform_connection_id": platform_id}
        _require_gateway_connection_job_ready(target, collection_kind="azure_repos_source")
        launch = web.post(
            f"{BASE}/{platform_id}/setup",
            headers=AUTH,
            json={**launch_payload(), "connection_id": local_id},
        )
        assert launch.status_code == 201
        receipt = repo.get_connection_onboarding(alpha, launch.json()["workflow_id"])
        assert str(receipt["connection_id"]) == local_id
        assert str(receipt["platform_connection_id"]) == platform_id
        assert web.post(f"/v1/connections/{local_id}/validate", headers=AUTH).status_code == 202
        collect = f"/v1/connections/{local_id}/azure-repos/collect"
        assert web.post(collect, headers=AUTH).status_code == 202
        before = list(dispatches)
        assert web.post(collect, headers=MEMBER).status_code == 403
        assert web.post(collect, headers=BETA).status_code == 404
        assert dispatches == before
        assert [kind for kind, _ in dispatches] == ["validation", "collection"]
        restarted = PostgresInventoryRepository(DSN)
        assert (
            restarted.connection_collection_status(
                alpha, local_id, collection_kind="azure_repos_source"
            )["state"]
            == "running"
        )
        assert web.post(f"/v1/connections/{local_id}/disable", headers=AUTH).status_code == 409
        validation_id, collection_id = dispatches[0][1], dispatches[1][1]
        assert restarted.claim_connection_validation_job(validation_id, lease_seconds=60)[
            "tenant_id"
        ] == UUID(alpha)
        restarted.complete_connection_validation_job(validation_id)
        # Active collection retains the same native disable guard after validation finishes.
        assert web.post(f"/v1/connections/{local_id}/disable", headers=AUTH).status_code == 409
        assert restarted.claim_connection_collection_job(collection_id, lease_seconds=60)[
            "tenant_id"
        ] == UUID(alpha)
        restarted.complete_connection_collection_job(collection_id, {"state": "complete"})
        assert web.post(f"/v1/connections/{local_id}/disable", headers=AUTH).status_code == 200
        assert repo.get_connection(alpha, local_id)["lifecycle_state"] == "disabled"
        assert platform.source["lifecycle_state"] == "active"
        assert not any(call[1].endswith("/disable") for call in platform.calls)
        assert web.post(collect, headers=AUTH).status_code == 409
        assert web.post(attach_path, headers=AUTH, json=use_payload()).status_code == 409
        assert len(dispatches) == len(before)
    assert "never-browser" not in str(repo.get_connection(alpha, local_id))
