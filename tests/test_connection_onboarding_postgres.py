"""PostgreSQL is the authority across API replacement, replay and tenant switches."""

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import psycopg
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.api.connection_workflows import new_return_state
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


def test_onboarding_receipt_is_durable_atomic_and_tenant_scoped():
    assert DSN
    migrate(DSN)
    marker = uuid4().hex
    org_alpha, org_beta = f"org_OnboardingA{marker}", f"org_OnboardingB{marker}"
    repo = PostgresInventoryRepository(DSN)
    alpha, beta = repo.resolve_tenant(org_alpha), repo.resolve_tenant(org_beta)
    state, digest = new_return_state()
    request_id = str(uuid4())
    workflow = repo.begin_connection_onboarding(
        alpha, request_id=request_id, return_state_sha256=digest
    )
    assert repo.get_connection_onboarding(beta, str(workflow["id"])) is None
    assert repo.list_connection_onboarding(beta) == []
    with psycopg.connect(DSN) as db:
        stored = db.execute(
            "SELECT return_state_sha256 FROM connection_onboarding_workflow WHERE id = %s",
            (workflow["id"],),
        ).fetchone()
    assert stored == (digest,)
    assert state not in str(stored)

    class Authenticator:
        def authenticate(self, request: Request):
            identity = request.headers.get("authorization", "")
            if identity == "Bearer alpha":
                return AuthContext("user_a", org_alpha, "admin")
            if identity == "Bearer beta":
                return AuthContext("user_b", org_beta, "admin")
            raise AuthenticationError("invalid test token")

    # No process-local receipt survives; replacing app/repository must preserve it.
    app = create_app(
        repository=PostgresInventoryRepository(DSN),
        auth_mode="clerk",
        authenticator=Authenticator(),
        migrate_on_start=False,
    )
    with TestClient(app) as web:
        path = f"/v1/connections/onboarding/{workflow['id']}"
        assert web.get(path).status_code == 401
        assert web.get(path, headers={"Authorization": "Bearer beta"}).status_code == 404
        assert repo.get_connection_onboarding(alpha, str(workflow["id"]))["status"] == "in_progress"
        callback = web.get(
            "/v1/connections/onboarding/callback",
            params={"state": state, "status": "succeeded"},
            follow_redirects=False,
        )
        assert callback.status_code == 303
        assert callback.headers["location"] == f"/connections?onboarding={workflow['id']}"
        resumed = web.get(path, headers={"Authorization": "Bearer alpha"})
        assert resumed.json()["stage"] == "select_repositories"
        assert "return_state" not in resumed.text
        assert web.get(path, headers={"Authorization": "Bearer beta"}).status_code == 404
    assert repo.consume_connection_onboarding_return(digest, succeeded=True) is None

    state2, digest2 = new_return_state()
    relaunched = repo.begin_connection_onboarding(
        alpha, request_id=request_id, return_state_sha256=digest2
    )
    assert relaunched["id"] == workflow["id"]
    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(
            pool.map(
                lambda _: repo.consume_connection_onboarding_return(digest2, succeeded=False),
                range(2),
            )
        )
    assert sum(item is not None for item in receipts) == 1
    assert (
        repo.get_connection_onboarding(alpha, str(workflow["id"]))["error_code"]
        == "authorization_failed"
    )
    assert state2 not in str(repo.list_connection_onboarding(alpha))


def test_expired_return_and_cross_tenant_source_are_rejected():
    assert DSN
    migrate(DSN)
    repo = PostgresInventoryRepository(DSN)
    marker = uuid4().hex
    alpha, beta = (
        repo.resolve_tenant(f"org_ExpiredA{marker}"),
        repo.resolve_tenant(f"org_ExpiredB{marker}"),
    )
    _, digest = new_return_state()
    workflow = repo.begin_connection_onboarding(
        alpha, request_id=str(uuid4()), return_state_sha256=digest
    )
    with psycopg.connect(DSN) as db:
        db.execute(
            """UPDATE connection_onboarding_workflow
               SET expires_at = now() - interval '1 second' WHERE id = %s""",
            (workflow["id"],),
        )
    assert repo.consume_connection_onboarding_return(digest, succeeded=True) is None
    local_id = str(uuid4())
    repo.create_connection(
        alpha,
        connection_id=local_id,
        provider="github",
        display_name=f"onboarding-{marker}",
        credential_type="platform_shared_github",
        credential_reference={"platform_connection_id": local_id, "installation_id": 99},
        declared_scopes=["github.repository_metadata"],
        coverage_plan=[],
        configuration={},
    )
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        repo.begin_connection_onboarding(
            beta,
            request_id=str(uuid4()),
            return_state_sha256=new_return_state()[1],
            connection_id=local_id,
        )


def test_github_reverification_receipt_pins_platform_source_across_replacement():
    assert DSN
    migrate(DSN)
    repo = PostgresInventoryRepository(DSN)
    marker = uuid4().hex
    tenant = repo.resolve_tenant(f"org_GithubReverify{marker}")
    other = repo.resolve_tenant(f"org_GithubOther{marker}")
    request_id, platform_id = str(uuid4()), str(uuid4())
    _, digest = new_return_state()
    workflow = repo.begin_connection_onboarding(
        tenant,
        request_id=request_id,
        return_state_sha256=digest,
        platform_connection_id=platform_id,
    )
    for different in (None, str(uuid4())):
        with pytest.raises(ValueError):
            repo.begin_connection_onboarding(
                tenant,
                request_id=request_id,
                return_state_sha256=new_return_state()[1],
                platform_connection_id=different,
            )
    replacement = PostgresInventoryRepository(DSN)
    assert replacement.get_connection_onboarding(other, str(workflow["id"])) is None
    assert replacement.consume_connection_onboarding_return(digest, succeeded=True)
    resumed = replacement.get_connection_onboarding(tenant, str(workflow["id"]))
    assert str(resumed["platform_connection_id"]) == platform_id
    assert resumed["connection_id"] is None and resumed["status"] == "returned"
    assert replacement.consume_connection_onboarding_return(digest, succeeded=True) is None
