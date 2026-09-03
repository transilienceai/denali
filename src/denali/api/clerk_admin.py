"""Server-side Clerk organization administration.

The browser must never receive the Clerk secret key. This module keeps the small
set of privileged Clerk operations used by Denali's custom profile UI behind the
authenticated FastAPI boundary.
"""

from __future__ import annotations

import logging
import os
from typing import Protocol

logger = logging.getLogger(__name__)


class ClerkAdminError(RuntimeError):
    """A sanitized Clerk administration failure safe for API classification."""


class ClerkOrganizationAdmin(Protocol):
    def invite_member(
        self,
        *,
        organization_id: str,
        inviter_user_id: str,
        email: str,
        role: str,
    ) -> str: ...

    def create_user_and_membership(
        self,
        *,
        organization_id: str,
        email: str,
        password: str,
        first_name: str | None,
        last_name: str | None,
        role: str,
    ) -> str: ...


class ClerkBackendOrganizationAdmin:
    """Privileged organization operations backed by Clerk's official SDK."""

    def __init__(self, secret_key: str) -> None:
        # Keep the optional Clerk dependency out of local-only import paths.
        from clerk_backend_api import Clerk

        self._client = Clerk(bearer_auth=secret_key)

    @classmethod
    def from_environment(cls) -> ClerkBackendOrganizationAdmin:
        secret_key = os.environ.get("CLERK_SECRET_KEY", "").strip()
        if not secret_key:
            raise ValueError("CLERK_SECRET_KEY is required for Clerk administration")
        return cls(secret_key)

    def invite_member(
        self,
        *,
        organization_id: str,
        inviter_user_id: str,
        email: str,
        role: str,
    ) -> str:
        try:
            invitation = self._client.organization_invitations.create(
                organization_id=organization_id,
                inviter_user_id=inviter_user_id,
                email_address=email,
                role=role,
                notify=True,
            )
        except Exception as error:
            raise ClerkAdminError("invitation_rejected") from error
        return str(invitation.id)

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
        try:
            user = self._client.users.create(
                email_address=[email],
                password=password,
                first_name=first_name,
                last_name=last_name,
            )
        except Exception as error:
            raise ClerkAdminError("user_rejected") from error

        user_id = str(user.id)
        try:
            self._client.organization_memberships.create(
                organization_id=organization_id,
                user_id=user_id,
                role=role,
            )
        except Exception as error:
            # The user was created only for this membership. Roll it back so a
            # retry does not leave an orphaned Clerk account.
            try:
                self._client.users.delete(user_id=user_id)
            except Exception:
                logger.error(
                    "failed to roll back Clerk user after membership failure",
                    extra={"clerk_user_id": user_id, "clerk_organization_id": organization_id},
                )
            raise ClerkAdminError("membership_rejected") from error
        return user_id
