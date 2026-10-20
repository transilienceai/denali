"""PostgreSQL is the authority across API replacement, replay and tenant switches."""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import psycopg
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.api.connection_workflows import new_return_state
from denali.connections.gcp import gcp_coverage_plan
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


def test_native_gcp_profile_survives_atomic_setup_and_worker_repository_replacement():
    assert DSN
    migrate(DSN)
    repo = PostgresInventoryRepository(DSN)
    marker = uuid4().hex
    tenant = repo.resolve_tenant(f"org_GcpProfile{marker}")
    other_tenant = repo.resolve_tenant(f"org_GcpProfileOther{marker}")
    connection_id, legacy_id = str(uuid4()), str(uuid4())
    reference = {
        "principal_email": "denali-reader@native-operator.iam.gserviceaccount.com",
        "principal_unique_id": "123456789012345678901",
        "operator_project_id": "native-operator",
        "operator_credential_profile": "native_gcp_wif_v1",
    }
    legacy_reference = {
        key: value for key, value in reference.items() if key != "operator_credential_profile"
    }
    for identifier, name, saved_reference in (
        (connection_id, "Isolated native reader", reference),
        (legacy_id, "Existing legacy reader", legacy_reference),
    ):
        public = repo.create_connection(
            tenant,
            connection_id=identifier,
            provider="gcp",
            display_name=name,
            credential_type="gcp_service_account",
            credential_reference=saved_reference,
            declared_scopes=["gcp.code_to_cloud"],
            coverage_plan=[],
            configuration={"coverage_mode": "selected-projects", "projects": []},
        )
        assert "operator_credential_profile" not in str(public)
        assert "native_gcp_wif_v1" not in str(public)
    legacy_before = repo.get_connection_validation_target(tenant, legacy_id)
    _, digest = new_return_state()
    launch = {
        "method": "google_cloud_shell",
        "status": "pending",
        "script_version": "synthetic-script",
        "script_sha256": "0" * 64,
    }
    assert (
        repo.record_gcp_connection_setup_launch(
            other_tenant, connection_id, launch=launch, setup_token_sha256=digest
        )
        is None
    )
    launched = repo.record_gcp_connection_setup_launch(
        tenant, connection_id, launch=launch, setup_token_sha256=digest
    )
    assert launched is not None
    assert "operator_credential_profile" not in str(launched)
    after_launch = PostgresInventoryRepository(DSN).get_connection_validation_target(
        tenant, connection_id
    )
    assert after_launch["credential_reference"] == {**reference, "setup_token_sha256": digest}
    projects = [{"id": "customer-ai-project", "number": "123456789012", "name": "Customer AI"}]
    plan = gcp_coverage_plan(["gcp.code_to_cloud"], projects)

    def complete(_attempt):
        return PostgresInventoryRepository(DSN).complete_gcp_connection_setup(
            tenant,
            connection_id,
            expected_setup_token_sha256=digest,
            projects=projects,
            coverage_plan=plan,
            completed_at=datetime.now(UTC),
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        completions = list(pool.map(complete, range(2)))
    assert sum(value is not None for value in completions) == 1
    for public in (value for value in completions if value is not None):
        assert "operator_credential_profile" not in str(public)
        assert "setup_token_sha256" not in str(public)
    replacement = PostgresInventoryRepository(DSN)
    worker_target = replacement.get_connection_validation_target(tenant, connection_id)
    assert str(worker_target["id"]) == connection_id
    assert worker_target["credential_reference"] == reference
    assert worker_target["configuration"]["projects"] == projects
    assert worker_target["coverage_plan"] == plan
    assert replacement.get_connection_validation_target(other_tenant, connection_id) is None
    assert replacement.get_connection_validation_target(tenant, legacy_id) == legacy_before
    assert complete("replay") is None
