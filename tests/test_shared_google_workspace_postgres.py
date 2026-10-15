"""Real tenant rows and existing leased workers execute mediated Workspace reads."""

import os
from uuid import uuid4

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from test_shared_google_workspace import Broker

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.api.collection import run_durable_collection_job
from denali.api.validation import run_durable_validation_job
from denali.integrations.shared_google_workspace import (
    WorkspaceCollectorRouter,
    WorkspaceValidatorRouter,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


def test_shared_workspace_tenant_attachment_and_duplicate_durable_worker_delivery(monkeypatch):
    assert DSN
    monkeypatch.setenv("DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED", "true")
    migrate(DSN)
    repo = PostgresInventoryRepository(DSN)
    marker = uuid4().hex
    alpha_org = f"org_WorkspaceAlpha{marker}"
    beta_org = f"org_WorkspaceBeta{marker}"
    broker = Broker()
    broker.status.update(id=str(uuid4()), clerk_org_id=alpha_org)
    broker.allows_org = lambda org: org == alpha_org
    local_id = broker.status["id"]

    class Authenticator:
        def authenticate(self, request: Request) -> AuthContext:
            identity = request.headers.get("authorization", "")
            if identity == "Bearer alpha":
                return AuthContext("user_test", alpha_org, "admin")
            if identity == "Bearer beta":
                return AuthContext("user_other", beta_org, "admin")
            raise AuthenticationError("invalid test session")

    with TestClient(
        create_app(
            repository=repo,
            auth_mode="clerk",
            authenticator=Authenticator(),
            shared_connections_client=broker,
            migrate_on_start=False,
        )
    ) as web:
        base = f"/v1/shared/connections/google-workspace/{local_id}"
        response = web.post(
            f"{base}/use-in-denali", headers={"Authorization": "Bearer alpha"}, json={}
        )
        assert response.status_code == 201, response.text
        assert (
            web.post(
                f"{base}/use-in-denali", headers={"Authorization": "Bearer beta"}, json={}
            ).status_code
            == 404
        )
        assert (
            web.post(
                f"/v1/connections/{local_id}/google-workspace/setup/complete",
                headers={"Authorization": "Bearer alpha"},
            ).status_code
            == 409
        )
    alpha, beta = repo.lookup_tenant(alpha_org), repo.lookup_tenant(beta_org)
    assert alpha and beta and alpha != beta
    assert repo.get_connection(beta, local_id) is None
    target = repo.get_connection_validation_target(alpha, local_id)
    assert target and target["clerk_organization_id"] == alpha_org
    assert target["credential_reference"] == {"platform_connection_id": local_id}
    job, created = repo.create_connection_validation_job(
        alpha, local_id, wait_for_credentials=False, wait_for_healthy=False
    )
    assert created
    validator = WorkspaceValidatorRouter(None, broker)
    run_durable_validation_job(
        repo, {"google_workspace": validator}, str(job["id"]), timeout_seconds=60, retry_seconds=2
    )
    count = len(broker.calls)
    run_durable_validation_job(
        repo, {"google_workspace": validator}, str(job["id"]), timeout_seconds=60, retry_seconds=2
    )
    assert len(broker.calls) == count
    row = repo.get_connection(alpha, local_id)
    assert row and row["health_state"] == "healthy"
    assert row["last_validation"]["account_id_observed"] is None
    broker.records = True
    collection, created = repo.create_connection_collection_job(
        alpha, local_id, collection_kind="google_workspace_ai"
    )
    assert created
    collectors = {"google_workspace_ai": WorkspaceCollectorRouter(None, broker)}
    run_durable_collection_job(repo, collectors, str(collection["id"]))
    count = len(broker.calls)
    run_durable_collection_job(repo, collectors, str(collection["id"]))
    assert len(broker.calls) == count
    status = repo.connection_collection_status(
        alpha, local_id, collection_kind="google_workspace_ai"
    )
    assert status["last_result"]["state"] == "complete"
    assert status["last_result"]["matched_ai_applications"] == 2
    assert repo.get_connection_validation_target(beta, local_id) is None
