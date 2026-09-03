from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import clerk_backend_api
import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from denali.api.app import create_app
from denali.api.auth import (
    AuthContext,
    AuthenticationError,
    AuthorizationError,
    ClerkAuthenticator,
)
from denali.api.clerk_admin import ClerkAdminError

ASSET_ID = "11111111-1111-4111-8111-111111111111"
TENANTS = {
    "org_alpha": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "org_beta": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
}


class HeaderAuthenticator:
    def authenticate(self, request: Request) -> AuthContext:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        if token == "alpha-admin":
            return AuthContext("user_alpha", "org_alpha", "admin")
        if token == "alpha-member":
            return AuthContext("user_member", "org_alpha", "member")
        if token == "beta-admin":
            return AuthContext("user_beta", "org_beta", "admin")
        raise AuthenticationError("invalid session")


class TenantRepository:
    def __init__(self):
        self.seen_tenants: list[str] = []
        self.governance_updates = 0

    def resolve_tenant(self, clerk_organization_id: str) -> str:
        return TENANTS[clerk_organization_id]

    def summary(self, tenant_id: str) -> dict[str, Any]:
        self.seen_tenants.append(tenant_id)
        return {"total": 0, "by_kind": {}, "by_governance": {}}

    def set_governance(
        self,
        tenant_id: str,
        asset_id: str,
        *,
        status: str,
        owner: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:
        self.seen_tenants.append(tenant_id)
        self.governance_updates += 1
        return {"id": asset_id, "governance_status": status, "owner": owner, "notes": notes}


class FakeClerkOrganizationAdmin:
    def __init__(self) -> None:
        self.invites: list[dict[str, str]] = []
        self.users: list[dict[str, str | None]] = []

    def invite_member(
        self,
        *,
        organization_id: str,
        inviter_user_id: str,
        email: str,
        role: str,
    ) -> str:
        if email == "rejected@example.com":
            raise ClerkAdminError("invitation_rejected")
        self.invites.append(
            {
                "organization_id": organization_id,
                "inviter_user_id": inviter_user_id,
                "email": email,
                "role": role,
            }
        )
        return f"invitation_{len(self.invites)}"

    def create_user_and_membership(
        self,
        *,
        organization_id: str,
        email: str,
        password: str,
        first_name: str | None,
        last_name: str | None,
        role: str,
    ) -> str:
        if email == "existing@example.com":
            raise ClerkAdminError("user_rejected")
        self.users.append(
            {
                "organization_id": organization_id,
                "email": email,
                "password": password,
                "first_name": first_name,
                "last_name": last_name,
                "role": role,
            }
        )
        return "user_created"


def _client(
    repository: TenantRepository,
    clerk_organization_admin: FakeClerkOrganizationAdmin | None = None,
) -> TestClient:
    return TestClient(
        create_app(
            repository=repository,  # type: ignore[arg-type]
            auth_mode="clerk",
            authenticator=HeaderAuthenticator(),
            clerk_organization_admin=clerk_organization_admin,
            migrate_on_start=False,
        )
    )


def test_clerk_mode_requires_a_session_but_leaves_health_public() -> None:
    with _client(TenantRepository()) as client:
        assert client.get("/healthz").status_code == 200
        response = client.get("/v1/inventory/summary")
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"


def test_active_organization_selects_an_isolated_denali_tenant() -> None:
    repository = TenantRepository()
    with _client(repository) as client:
        alpha = client.get(
            "/v1/context", headers={"Authorization": "Bearer alpha-admin"}
        )
        beta = client.get(
            "/v1/context", headers={"Authorization": "Bearer beta-admin"}
        )
        client.get(
            "/v1/inventory/summary", headers={"Authorization": "Bearer alpha-admin"}
        )
        client.get(
            "/v1/inventory/summary", headers={"Authorization": "Bearer beta-admin"}
        )

    assert alpha.json() == {
        "tenant_id": TENANTS["org_alpha"],
        "organization_id": "org_alpha",
        "role": "admin",
        "can_write": True,
    }
    assert beta.json()["tenant_id"] == TENANTS["org_beta"]
    assert repository.seen_tenants == [TENANTS["org_alpha"], TENANTS["org_beta"]]


def test_members_can_read_but_only_admins_can_mutate() -> None:
    repository = TenantRepository()
    with _client(repository) as client:
        read = client.get(
            "/v1/inventory/summary", headers={"Authorization": "Bearer alpha-member"}
        )
        denied = client.patch(
            f"/v1/inventory/assets/{ASSET_ID}/governance",
            headers={"Authorization": "Bearer alpha-member"},
            json={"status": "approved"},
        )
        allowed = client.patch(
            f"/v1/inventory/assets/{ASSET_ID}/governance",
            headers={"Authorization": "Bearer alpha-admin"},
            json={"status": "approved"},
        )

    assert read.status_code == 200
    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert repository.governance_updates == 1


def test_bulk_invites_use_the_authenticated_organization_and_require_admin() -> None:
    repository = TenantRepository()
    clerk_admin = FakeClerkOrganizationAdmin()
    body = {
        "emails": [" FIRST@example.com ", "first@example.com", "rejected@example.com"],
        "role": "org:member",
    }
    with _client(repository, clerk_admin) as client:
        denied = client.post(
            "/v1/profile/organization/invitations/bulk",
            headers={"Authorization": "Bearer alpha-member"},
            json=body,
        )
        response = client.post(
            "/v1/profile/organization/invitations/bulk",
            headers={"Authorization": "Bearer alpha-admin"},
            json=body,
        )

    assert denied.status_code == 403
    assert response.status_code == 200
    assert response.json() == {
        "sent": 1,
        "failed": 1,
        "results": [
            {
                "email": "first@example.com",
                "status": "sent",
                "invitation_id": "invitation_1",
            },
            {
                "email": "rejected@example.com",
                "status": "failed",
                "error": "Clerk rejected this invitation",
            },
        ],
    }
    assert clerk_admin.invites == [
        {
            "organization_id": "org_alpha",
            "inviter_user_id": "user_alpha",
            "email": "first@example.com",
            "role": "org:member",
        }
    ]


def test_direct_user_creation_keeps_password_out_of_the_response() -> None:
    repository = TenantRepository()
    clerk_admin = FakeClerkOrganizationAdmin()
    password = "Only-for-Clerk-123!"
    with _client(repository, clerk_admin) as client:
        response = client.post(
            "/v1/profile/organization/users",
            headers={"Authorization": "Bearer beta-admin"},
            json={
                "email": " NEW.USER@example.com ",
                "password": password,
                "first_name": " New ",
                "last_name": " User ",
                "role": "org:admin",
            },
        )

    assert response.status_code == 201
    assert response.json() == {
        "user_id": "user_created",
        "email": "new.user@example.com",
        "role": "org:admin",
    }
    assert password not in response.text
    assert clerk_admin.users == [
        {
            "organization_id": "org_beta",
            "email": "new.user@example.com",
            "password": password,
            "first_name": "New",
            "last_name": "User",
            "role": "org:admin",
        }
    ]


def test_profile_member_endpoints_reject_invalid_input_and_sanitize_clerk_errors() -> None:
    repository = TenantRepository()
    clerk_admin = FakeClerkOrganizationAdmin()
    with _client(repository, clerk_admin) as client:
        invalid = client.post(
            "/v1/profile/organization/invitations/bulk",
            headers={"Authorization": "Bearer alpha-admin"},
            json={"emails": ["not-an-email"], "role": "org:member"},
        )
        rejected = client.post(
            "/v1/profile/organization/users",
            headers={"Authorization": "Bearer alpha-admin"},
            json={
                "email": "existing@example.com",
                "password": "Safe-password-123!",
                "role": "org:member",
            },
        )
        short_password = client.post(
            "/v1/profile/organization/users",
            headers={"Authorization": "Bearer alpha-admin"},
            json={
                "email": "short@example.com",
                "password": "secret",
                "role": "org:member",
            },
        )

    assert invalid.status_code == 422
    assert rejected.status_code == 502
    assert "Safe-password-123!" not in rejected.text
    assert "Clerk could not create the user" in rejected.json()["detail"]
    assert short_password.status_code == 422
    assert "secret" not in short_password.text


def test_clerk_authenticator_passes_authorized_parties_and_rejects_pending_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def authenticate_request(request: Request, options: Any) -> Any:
        captured["options"] = options
        return SimpleNamespace(
            is_signed_in=True,
            reason=None,
            payload={
                "sub": "user_pending",
                "sts": "pending",
                "o": {"id": "org_alpha", "rol": "admin"},
            },
        )

    monkeypatch.setattr(clerk_backend_api, "authenticate_request", authenticate_request)
    authenticator = ClerkAuthenticator(
        secret_key="sk_test_fixture",
        jwt_key="public-key",
        authorized_parties=["https://denali.example"],
        allowed_organizations={"org_alpha"},
    )
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})

    with pytest.raises(AuthorizationError, match="pending"):
        authenticator.authenticate(request)

    options = captured["options"]
    assert options.authorized_parties == ["https://denali.example"]
    assert options.accepts_token == ["session_token"]


def test_clerk_authenticator_rejects_expired_or_unapproved_sessions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = SimpleNamespace(
        is_signed_in=False,
        reason=SimpleNamespace(name="token-expired"),
        payload=None,
    )
    monkeypatch.setattr(clerk_backend_api, "authenticate_request", lambda *_: state)
    authenticator = ClerkAuthenticator(
        secret_key="sk_test_fixture",
        jwt_key=None,
        authorized_parties=["https://denali.example"],
        allowed_organizations={"org_alpha"},
    )
    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    with pytest.raises(AuthenticationError, match="token-expired"):
        authenticator.authenticate(request)

    state.is_signed_in = True
    state.reason = None
    state.payload = {
        "sub": "user_beta",
        "sts": "active",
        "o": {"id": "org_beta", "rol": "org:member"},
    }
    with pytest.raises(AuthorizationError, match="not approved"):
        authenticator.authenticate(request)
