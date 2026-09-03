from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from denali.api.clerk_admin import ClerkAdminError, ClerkBackendOrganizationAdmin


class FakeEndpoint:
    def __init__(self, result: Any = None, error: Exception | None = None) -> None:
        self.result = result
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


class FakeUsers(FakeEndpoint):
    def __init__(self, result: Any, delete_error: Exception | None = None) -> None:
        super().__init__(result=result)
        self.delete_error = delete_error
        self.deleted: list[str] = []

    def delete(self, *, user_id: str) -> None:
        self.deleted.append(user_id)
        if self.delete_error is not None:
            raise self.delete_error


def _admin(client: Any) -> ClerkBackendOrganizationAdmin:
    admin = object.__new__(ClerkBackendOrganizationAdmin)
    admin._client = client
    return admin


def test_clerk_admin_invites_with_the_server_selected_organization() -> None:
    invitations = FakeEndpoint(result=SimpleNamespace(id="inv_123"))
    admin = _admin(SimpleNamespace(organization_invitations=invitations))

    invitation_id = admin.invite_member(
        organization_id="org_alpha",
        inviter_user_id="user_admin",
        email="member@example.com",
        role="org:member",
    )

    assert invitation_id == "inv_123"
    assert invitations.calls == [
        {
            "organization_id": "org_alpha",
            "inviter_user_id": "user_admin",
            "email_address": "member@example.com",
            "role": "org:member",
            "notify": True,
        }
    ]


def test_clerk_admin_rolls_back_a_new_user_when_membership_creation_fails() -> None:
    users = FakeUsers(result=SimpleNamespace(id="user_new"))
    memberships = FakeEndpoint(error=RuntimeError("membership failed"))
    admin = _admin(
        SimpleNamespace(users=users, organization_memberships=memberships)
    )

    with pytest.raises(ClerkAdminError, match="membership_rejected"):
        admin.create_user_and_membership(
            organization_id="org_alpha",
            email="new@example.com",
            password="Only-for-Clerk-123!",
            first_name="New",
            last_name="Member",
            role="org:member",
        )

    assert users.deleted == ["user_new"]
    assert memberships.calls == [
        {"organization_id": "org_alpha", "user_id": "user_new", "role": "org:member"}
    ]
