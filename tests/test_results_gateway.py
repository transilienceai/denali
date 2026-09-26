from __future__ import annotations

from types import SimpleNamespace

import clerk_backend_api
from fastapi.testclient import TestClient

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.api.gateway_auth import (
    ClerkResultsGatewayVerifier,
    GatewayPrincipal,
)


class SessionAuthenticator:
    def authenticate(self, request):
        if request.headers.get("authorization") == "Bearer browser-session":
            return AuthContext("user_Browser1", "org_Alpha1", "admin")
        raise AuthenticationError("invalid session")


class FakeGatewayVerifier:
    def verify(self, token):
        return {
            "alpha": GatewayPrincipal("mch_Gateway1", "org_Alpha1", "user_Alice1"),
            "beta": GatewayPrincipal("mch_Gateway1", "org_Beta2", "user_Bob2"),
            "unmapped": GatewayPrincipal("mch_Gateway1", "org_Unknown3", "user_Carol3"),
        }.get(token)


class ResultsRepository:
    def __init__(self):
        self.created = False
        self.seen: list[str] = []

    def resolve_tenant(self, clerk_organization_id):
        self.created = True
        raise AssertionError("gateway reads must not create tenants")

    def lookup_tenant(self, clerk_organization_id):
        return {"org_Alpha1": "tenant-alpha", "org_Beta2": "tenant-beta"}.get(
            clerk_organization_id
        )

    def summary(self, tenant_id):
        self.seen.append(tenant_id)
        return {"tenant": tenant_id, "assets": 2}

    def finding_summary(self, tenant_id):
        self.seen.append(tenant_id)
        return {"open": 1}

    def issue_summary(self, tenant_id):
        self.seen.append(tenant_id)
        return {"open": 0}

    def list_findings(self, tenant_id, *, state, severity, limit, offset):
        self.seen.append(tenant_id)
        return [{"tenant": tenant_id, "id": "finding-1"}]

    def latest_coverage(self, tenant_id):
        self.seen.append(tenant_id)
        return [{"tenant": tenant_id, "plane": "github"}]


_DEFAULT_VERIFIER = FakeGatewayVerifier()


def _app(repository, verifier=_DEFAULT_VERIFIER):
    return create_app(
        repository=repository,
        auth_mode="clerk",
        authenticator=SessionAuthenticator(),
        results_gateway_verifier=verifier,
        migrate_on_start=False,
    )


def test_gateway_results_are_read_only_and_org_scoped():
    repository = ResultsRepository()
    with TestClient(_app(repository)) as client:
        alpha = client.get(
            "/internal/v1/results/summary", headers={"Authorization": "Bearer alpha"}
        )
        beta = client.get(
            "/internal/v1/results/findings", headers={"Authorization": "Bearer beta"}
        )
        coverage = client.get(
            "/internal/v1/results/coverage", headers={"Authorization": "Bearer alpha"}
        )
        assert alpha.status_code == beta.status_code == coverage.status_code == 200
        assert alpha.json()["inventory"]["tenant"] == "tenant-alpha"
        assert beta.json()["items"][0]["tenant"] == "tenant-beta"
        assert coverage.json()["items"][0]["tenant"] == "tenant-alpha"
        assert alpha.headers["cache-control"] == "no-store"
        assert repository.seen == [
            "tenant-alpha", "tenant-alpha", "tenant-alpha", "tenant-beta", "tenant-alpha"
        ]
        assert not repository.created


def test_gateway_rejects_browser_session_unmapped_org_and_unconfigured_verifier():
    repository = ResultsRepository()
    with TestClient(_app(repository)) as client:
        assert client.get("/internal/v1/results/summary").status_code == 401
        assert client.get(
            "/internal/v1/results/summary",
            headers={"Authorization": "Bearer browser-session"},
        ).status_code == 401
        assert client.get(
            "/internal/v1/results/summary",
            headers={"Authorization": "Bearer unmapped"},
        ).status_code == 404
        assert client.get(
            "/internal/v1/results/findings?limit=101",
            headers={"Authorization": "Bearer alpha"},
        ).status_code == 422
    with TestClient(_app(repository, verifier=None)) as client:
        assert client.get(
            "/internal/v1/results/summary", headers={"Authorization": "Bearer alpha"}
        ).status_code == 404
    assert not repository.created


def test_clerk_gateway_verifier_requires_subject_scope_and_bound_claims(monkeypatch):
    result = SimpleNamespace(
        revoked=False,
        expired=False,
        subject="mch_Gateway1",
        scopes=["mch_Denali1"],
        created_at=1_000_000,
        expiration=1_300_000,
        claims={"purpose": "results:read", "org_id": "org_Alpha1", "user_id": "user_Alice1"},
    )
    machine = SimpleNamespace(m2m=SimpleNamespace(verify_token=lambda **_: result))
    monkeypatch.setattr(clerk_backend_api, "Clerk", lambda **_: machine)
    verifier = ClerkResultsGatewayVerifier("ak_test", "mch_Gateway1", "mch_Denali1")
    assert verifier.verify("token") == GatewayPrincipal(
        "mch_Gateway1", "org_Alpha1", "user_Alice1"
    )
    result.scopes = ["mch_Other1"]
    assert verifier.verify("token") is None
    result.scopes = ["mch_Denali1"]
    result.expiration = result.created_at + 16 * 60 * 1000
    assert verifier.verify("token") is None
    result.expiration = result.created_at + 5 * 60 * 1000
    result.claims = {"purpose": "results:read", "org_id": "org_Other1"}
    assert verifier.verify("token") is None
    result.claims = {"purpose": "results:read", "org_id": "org_Alpha1", "user_id": "user_Alice1"}
    result.revoked = True
    assert verifier.verify("token") is None
