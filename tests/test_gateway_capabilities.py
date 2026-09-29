from __future__ import annotations

from types import SimpleNamespace

import clerk_backend_api
import pytest
from fastapi.testclient import TestClient

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.api.capabilities import READ_CAPABILITIES
from denali.api.gateway_auth import ClerkGatewayVerifier, ClerkMembershipChecker, GatewayPrincipal

ASSET = "11111111-1111-4111-8111-111111111111"


class SessionAuthenticator:
    def authenticate(self, request):
        if request.headers.get("authorization") == "Bearer browser":
            return AuthContext("user_Browser1", "org_Alpha1", "admin")
        raise AuthenticationError("invalid session")


class Verifier:
    def verify(self, token, *, purpose):
        identities = {
            "admin-read": ("org_Alpha1", "user_Admin1", "results:read"),
            "admin-write": ("org_Alpha1", "user_Admin1", "denali:write"),
            "member-write": ("org_Alpha1", "user_Member1", "denali:write"),
            "removed-read": ("org_Alpha1", "user_Removed1", "results:read"),
            "other-read": ("org_Beta2", "user_Admin2", "results:read"),
            "other-write": ("org_Beta2", "user_Admin2", "denali:write"),
            "unmapped-read": ("org_Unknown3", "user_Admin3", "results:read"),
        }
        identity = identities.get(token)
        if identity is None or identity[2] != purpose:
            return None
        return GatewayPrincipal("mch_Gateway1", *identity)


class Memberships:
    def role(self, organization_id, user_id):
        return {
            ("org_Alpha1", "user_Admin1"): "admin",
            ("org_Alpha1", "user_Member1"): "member",
            ("org_Beta2", "user_Admin2"): "admin",
            ("org_Unknown3", "user_Admin3"): "admin",
        }.get((organization_id, user_id))


class Repository:
    def __init__(self):
        self.calls = []
        self.actions = {}

    def lookup_tenant(self, org):
        return {"org_Alpha1": "tenant-alpha", "org_Beta2": "tenant-beta"}.get(org)

    def resolve_tenant(self, org):
        raise AssertionError("machine traffic must not create tenant")

    def __getattr__(self, name):
        if name == "count_assets":

            def count(tenant, *args, **kwargs):
                self.calls.append((name, tenant, args, kwargs))
                return 1

            return count
        if name.startswith(("list_", "latest_", "code_to_cloud_")):

            def rows(tenant, *args, **kwargs):
                self.calls.append((name, tenant, args, kwargs))
                return [{"tenant": tenant}]

            return rows
        if name.startswith(
            (
                "get_",
                "summary",
                "activity_summary",
                "finding_summary",
                "issue_summary",
                "runtime_detection_summary",
                "vulnerability_summary",
                "vulnerability_import_status",
            )
        ):

            def item(tenant, *args, **kwargs):
                self.calls.append((name, tenant, args, kwargs))
                return {"tenant": tenant}

            return item
        raise AttributeError(name)

    def set_governance_idempotent(
        self, tenant, asset, *, status, owner, notes, actor, idempotency_key
    ):
        key = (tenant, idempotency_key)
        payload = (asset, status, owner, notes, actor)
        self.calls.append(("set_governance_idempotent", tenant, payload, {}))
        if key in self.actions:
            if self.actions[key] != payload:
                raise ValueError("idempotency key was already used for another action")
        elif asset != ASSET:
            return None
        else:
            self.actions[key] = payload
        return {"id": asset, "governance_status": status, "tenant": tenant}


def app(repository):
    return create_app(
        repository=repository,
        auth_mode="clerk",
        authenticator=SessionAuthenticator(),
        results_gateway_verifier=Verifier(),
        gateway_membership_checker=Memberships(),
        migrate_on_start=False,
    )


def test_read_catalog_is_explicit_org_scoped_and_never_creates_tenant():
    repo = Repository()
    with TestClient(app(repo)) as client:
        alpha = client.get(
            "/internal/v1/capabilities/inventory-summary",
            headers={"Authorization": "Bearer admin-read"},
        )
        beta = client.get(
            "/internal/v1/capabilities/finding-detail",
            params={"id": ASSET},
            headers={"Authorization": "Bearer other-read"},
        )
        assert alpha.status_code == beta.status_code == 200
        assert alpha.json()["tenant"] == "tenant-alpha"
        assert beta.json()["tenant"] == "tenant-beta"
        assert alpha.headers["cache-control"] == "no-store"
        assert (
            client.get(
                "/internal/v1/capabilities/connections",
                headers={"Authorization": "Bearer admin-read"},
            ).status_code
            == 404
        )
        assert (
            client.get(
                "/internal/v1/capabilities/assets",
                params={"limit": 101},
                headers={"Authorization": "Bearer admin-read"},
            ).status_code
            == 422
        )
        assert (
            client.get(
                "/internal/v1/capabilities/asset-detail",
                params={"id": "bad"},
                headers={"Authorization": "Bearer admin-read"},
            ).status_code
            == 422
        )
    assert len(READ_CAPABILITIES) == 26
    assert all(call[1] in {"tenant-alpha", "tenant-beta"} for call in repo.calls)


@pytest.mark.parametrize("operation", sorted(READ_CAPABILITIES))
def test_every_named_read_resolves_to_an_existing_tenant_scoped_handler(operation):
    repo = Repository()
    identifier = "a" * 64 if operation == "runtime-session-detail" else ASSET
    params = {"id": identifier} if READ_CAPABILITIES[operation].identifier else {}
    with TestClient(app(repo)) as client:
        response = client.get(
            f"/internal/v1/capabilities/{operation}",
            params=params,
            headers={"Authorization": "Bearer admin-read"},
        )
    assert response.status_code == 200, (operation, response.text)
    assert response.headers["cache-control"] == "no-store"
    assert repo.calls and all(call[1] == "tenant-alpha" for call in repo.calls)


def test_gateway_write_requires_distinct_purpose_current_admin_and_idempotency():
    repo = Repository()
    url = f"/internal/v1/capabilities/assets/{ASSET}/governance"
    body = {"status": "approved", "owner": "security"}
    key = "action-abc123"
    with TestClient(app(repo)) as client:
        assert (
            client.patch(
                url,
                json=body,
                headers={"Authorization": "Bearer admin-read", "Idempotency-Key": key},
            ).status_code
            == 401
        )
        assert (
            client.patch(
                url,
                json=body,
                headers={"Authorization": "Bearer member-write", "Idempotency-Key": key},
            ).status_code
            == 403
        )
        assert (
            client.patch(
                url, json=body, headers={"Authorization": "Bearer admin-write"}
            ).status_code
            == 422
        )
        result = client.patch(
            url, json=body, headers={"Authorization": "Bearer admin-write", "Idempotency-Key": key}
        )
        assert result.status_code == 200
        assert result.json()["tenant"] == "tenant-alpha"
        assert result.headers["cache-control"] == "no-store"
        assert (
            client.patch(
                url,
                json=body,
                headers={"Authorization": "Bearer admin-write", "Idempotency-Key": key},
            ).status_code
            == 200
        )
        assert (
            client.patch(
                url,
                json={"status": "unwanted"},
                headers={"Authorization": "Bearer admin-write", "Idempotency-Key": key},
            ).status_code
            == 409
        )
        assert (
            client.patch(
                url.replace(ASSET, "bad"),
                json=body,
                headers={"Authorization": "Bearer admin-write", "Idempotency-Key": "another-key"},
            ).status_code
            == 422
        )
        assert (
            client.patch(
                url,
                json={"status": "invalid"},
                headers={"Authorization": "Bearer admin-write", "Idempotency-Key": "another-key"},
            ).status_code
            == 422
        )
        beta = client.patch(
            url, json=body, headers={"Authorization": "Bearer other-write", "Idempotency-Key": key}
        )
        assert beta.status_code == 200
        assert beta.json()["tenant"] == "tenant-beta"


def test_gateway_rejects_removed_member_unmapped_org_and_unconfigured_auth():
    repo = Repository()
    url = "/internal/v1/capabilities/inventory-summary"
    with TestClient(app(repo)) as client:
        for token, expected in (("removed-read", 403), ("unmapped-read", 404), ("browser", 401)):
            assert (
                client.get(url, headers={"Authorization": f"Bearer {token}"}).status_code
                == expected
            )
    no_gateway = create_app(
        repository=repo,
        auth_mode="clerk",
        authenticator=SessionAuthenticator(),
        migrate_on_start=False,
    )
    with TestClient(no_gateway) as client:
        assert client.get(url, headers={"Authorization": "Bearer admin-read"}).status_code == 404


def test_clerk_machine_verifier_and_live_membership_are_bounded(monkeypatch):
    token = SimpleNamespace(
        revoked=False,
        expired=False,
        subject="mch_Gateway1",
        scopes=["mch_Denali1"],
        created_at=1_000_000,
        expiration=1_300_000,
        claims={"purpose": "denali:write", "org_id": "org_Alpha1", "user_id": "user_Admin1"},
    )
    membership = SimpleNamespace(
        role="org:admin", public_user_data=SimpleNamespace(user_id="user_Admin1")
    )
    client = SimpleNamespace(
        m2m=SimpleNamespace(verify_token=lambda **_: token),
        organization_memberships=SimpleNamespace(
            list=lambda **_: SimpleNamespace(data=[membership])
        ),
    )
    monkeypatch.setattr(clerk_backend_api, "Clerk", lambda **_: client)
    verifier = ClerkGatewayVerifier("ak_test", "mch_Gateway1", "mch_Denali1")
    assert verifier.verify("token", purpose="denali:write") == GatewayPrincipal(
        "mch_Gateway1", "org_Alpha1", "user_Admin1", "denali:write"
    )
    assert verifier.verify("token", purpose="results:read") is None
    assert ClerkMembershipChecker("sk_test").role("org_Alpha1", "user_Admin1") == "admin"
    token.subject = "mch_Other1"
    assert verifier.verify("token", purpose="denali:write") is None
    token.subject = "mch_Gateway1"
    token.scopes = ["mch_Other1"]
    assert verifier.verify("token", purpose="denali:write") is None
    token.scopes = ["mch_Denali1"]
    token.claims = {"purpose": "denali:write", "org_id": "org_Alpha1", "user_id": "bad"}
    assert verifier.verify("token", purpose="denali:write") is None
    token.claims = {"purpose": "denali:write", "org_id": "org_Alpha1", "user_id": "user_Admin1"}
    token.revoked = True
    assert verifier.verify("token", purpose="denali:write") is None
    token.revoked = False
    token.expiration = token.created_at + 16 * 60 * 1000
    assert verifier.verify("token", purpose="denali:write") is None
