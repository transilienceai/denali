"""Safe exact-job polling through the same browser and named receiver handlers."""

from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from test_gateway_capabilities import Memberships, Repository, Verifier

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.api.gateway_auth import GatewayPrincipal
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTION = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
JOB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
FIELDS = {
    "job_id", "connection_id", "job_type", "collection_kind", "state", "attempt_count",
    "created_at", "started_at", "completed_at", "error_code",
}


class Authenticator:
    def authenticate(self, request):
        if request.headers.get("authorization") == "Bearer browser-member":
            return AuthContext("user_Member1", "org_Alpha1", "member")
        raise AuthenticationError("invalid session")


class MemberVerifier(Verifier):
    def verify(self, token, *, purpose):
        if token == "member-read" and purpose == "results:read":
            return GatewayPrincipal("mch_Gateway1", "org_Alpha1", "user_Member1", purpose)
        return super().verify(token, purpose=purpose)


def make_app(repo):
    return create_app(
        repository=repo, auth_mode="clerk", authenticator=Authenticator(),
        results_gateway_verifier=MemberVerifier(), gateway_membership_checker=Memberships(),
        migrate_on_start=False,
    )


class Jobs(Repository):
    def resolve_tenant(self, org):
        return self.lookup_tenant(org)

    def connection_job_status(self, tenant, connection_id, job_id, *, job_type):
        self.calls.append((job_type, tenant, connection_id, job_id))
        if (tenant, connection_id, job_id) != ("tenant-alpha", CONNECTION, JOB):
            return None
        return {
            "job_id": JOB, "connection_id": CONNECTION, "job_type": job_type,
            "collection_kind": "aws_deployments" if job_type == "collection" else None,
            "state": "failed", "attempt_count": 1, "created_at": "2026-10-06T00:00:00Z",
            "started_at": None, "completed_at": None, "error_code": "job_failed",
            "modal_call_id": "PRIVATE", "error_summary": "PRIVATE", "result": {"PRIVATE": 1},
        }


@pytest.mark.parametrize("kind", ["validation", "collection"])
def test_browser_and_member_receiver_share_safe_tenant_scoped_job_read(kind):
    repo = Jobs()
    with TestClient(make_app(repo)) as client:
        browser = client.get(
            f"/v1/connections/{CONNECTION}/{kind}-jobs/{JOB}",
            headers={"Authorization": "Bearer browser-member"},
        )
        gateway = client.get(
            f"/internal/v1/capabilities/connection-{kind}-job",
            params={"id": JOB, "connection_id": CONNECTION},
            headers={"Authorization": "Bearer member-read"},
        )
        assert browser.status_code == gateway.status_code == 200
        assert browser.json() == gateway.json() and set(gateway.json()) == FIELDS
        assert "PRIVATE" not in gateway.text
        assert gateway.headers["cache-control"] == "no-store"
        for params, token in (
            ({"id": str(uuid4()), "connection_id": CONNECTION}, "member-read"),
            ({"id": JOB, "connection_id": str(uuid4())}, "member-read"),
            ({"id": JOB, "connection_id": CONNECTION}, "other-read"),
        ):
            denied = client.get(
                f"/internal/v1/capabilities/connection-{kind}-job", params=params,
                headers={"Authorization": f"Bearer {token}"},
            )
            assert denied.status_code == 404
            assert denied.json() == {"detail": "connection job not found"}
    assert repo.calls[:2] == [(kind, "tenant-alpha", CONNECTION, JOB)] * 2


@pytest.mark.parametrize("params", [
    {"id": JOB}, {"id": JOB, "connection_id": "bad"},
    {"id": JOB, "connection_id": CONNECTION.upper()},
    {"id": JOB, "connection_id": CONNECTION, "tenant_id": str(uuid4())},
    {"id": JOB, "connection_id": CONNECTION, "job_type": "anything"},
])
def test_invalid_job_read_never_queries_repository(params):
    repo = Jobs()
    with TestClient(make_app(repo)) as client:
        response = client.get(
            "/internal/v1/capabilities/connection-validation-job", params=params,
            headers={"Authorization": "Bearer member-read"},
        )
    assert response.status_code == 422 and not repo.calls


def test_browser_job_read_auth_canonical_ids_and_query_injection():
    repo = Jobs()
    with TestClient(make_app(repo)) as client:
        path = f"/v1/connections/{CONNECTION}/validation-jobs/{JOB}"
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.get(path + "?tenant_id=other", headers={
            "Authorization": "Bearer browser-member"}).status_code == 422
        assert client.get(path.replace(CONNECTION, CONNECTION.upper()), headers={
            "Authorization": "Bearer browser-member"}).status_code == 422
    assert not repo.calls


@pytest.mark.skipif(not os.environ.get("DENALI_TEST_DSN"), reason="DENALI_TEST_DSN not set")
@pytest.mark.parametrize("kind", ["validation", "collection"])
def test_real_postgres_job_states_exact_association_and_privacy(kind):
    dsn = os.environ["DENALI_TEST_DSN"]
    migrate(dsn)
    repo = PostgresInventoryRepository(dsn)
    tenant = repo.resolve_tenant(f"org_JobPoll{uuid4().hex}")
    other = repo.resolve_tenant(f"org_JobPollOther{uuid4().hex}")
    connection_id = str(uuid4())
    repo.create_connection(
        tenant, connection_id=connection_id, provider="aws", display_name="Job poll test",
        credential_type="aws_assume_role", credential_reference={
            "role_arn": "arn:aws:iam::123456789012:role/Test", "external_id": "test"
        },
        declared_scopes=["aws.bedrock_agents"], coverage_plan=[], configuration={},
    )
    if kind == "validation":
        job, _ = repo.create_connection_validation_job(
            tenant, connection_id, wait_for_credentials=False, wait_for_healthy=False
        )
    else:
        job, _ = repo.create_connection_collection_job(
            tenant, connection_id, collection_kind="aws_deployments"
        )
    job_id = str(job["id"])
    # Fixed test SQL mirrors the two fixed production queries, never an input table name.
    query = (
        "UPDATE connection_validation_job SET state=%s, error_summary='PRIVATE', "
        "modal_call_id='PRIVATE' WHERE id=%s::uuid"
        if kind == "validation" else
        "UPDATE connection_collection_job SET state=%s, error_summary='PRIVATE', "
        "modal_call_id='PRIVATE', result='{\"PRIVATE\":true}' WHERE id=%s::uuid"
    )
    for state in ("queued", "running", "succeeded", "failed"):
        with psycopg.connect(dsn) as connection:
            connection.execute(query, (state, job_id))
        result = repo.connection_job_status(tenant, connection_id, job_id, job_type=kind)
        assert result and set(result) == FIELDS and result["state"] == state
        assert str(result["job_id"]) == job_id and str(result["connection_id"]) == connection_id
        assert result["job_type"] == kind
        assert result["collection_kind"] == ("aws_deployments" if kind == "collection" else None)
        assert result["error_code"] == ("job_failed" if state == "failed" else None)
        assert "PRIVATE" not in str(result)
    assert repo.connection_job_status(other, connection_id, job_id, job_type=kind) is None
    assert repo.connection_job_status(tenant, str(uuid4()), job_id, job_type=kind) is None
    assert repo.connection_job_status(tenant, connection_id, str(uuid4()), job_type=kind) is None
    opposite = "collection" if kind == "validation" else "validation"
    assert repo.connection_job_status(tenant, connection_id, job_id, job_type=opposite) is None
    with pytest.raises(ValueError, match="unsupported"):
        repo.connection_job_status(tenant, connection_id, job_id, job_type="injected")
