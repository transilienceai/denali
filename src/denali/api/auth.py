"""Clerk session authentication and organization authorization."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol

from fastapi import Request


@dataclass(frozen=True)
class AuthContext:
    """Authenticated Clerk identity before it is mapped to a Denali tenant."""

    user_id: str
    organization_id: str
    role: str

    @property
    def can_write(self) -> bool:
        return self.role == "admin"


class AuthenticationError(RuntimeError):
    """A request does not carry an acceptable Clerk organization session."""


class AuthorizationError(RuntimeError):
    """The authenticated session cannot enter the requested organization context."""


class RequestAuthenticator(Protocol):
    def authenticate(self, request: Request) -> AuthContext: ...


class ClerkAuthenticator:
    """Verify Clerk session JWTs with the official backend SDK."""

    def __init__(
        self,
        *,
        secret_key: str,
        jwt_key: str | None,
        authorized_parties: list[str],
        audience: str | list[str] | None = None,
        allowed_organizations: set[str] | None = None,
    ):
        if not secret_key:
            raise ValueError("CLERK_SECRET_KEY is required when Clerk authentication is enabled")
        if not authorized_parties:
            raise ValueError(
                "CLERK_AUTHORIZED_PARTIES is required when Clerk authentication is enabled"
            )
        self._secret_key = secret_key
        self._jwt_key = jwt_key
        self._authorized_parties = authorized_parties
        self._audience = audience
        self._allowed_organizations = allowed_organizations

    @classmethod
    def from_environment(cls) -> ClerkAuthenticator:
        organizations = _csv_environment("DENALI_CLERK_ORGANIZATIONS")
        audiences = _csv_environment("CLERK_AUDIENCE")
        jwt_key = os.environ.get("CLERK_JWT_KEY")
        return cls(
            secret_key=os.environ.get("CLERK_SECRET_KEY", ""),
            jwt_key=jwt_key.replace("\\n", "\n") if jwt_key else None,
            authorized_parties=_csv_environment("CLERK_AUTHORIZED_PARTIES"),
            audience=audiences or None,
            allowed_organizations=set(organizations) if organizations else None,
        )

    def authenticate(self, request: Request) -> AuthContext:
        # Keep the optional Clerk dependency outside the local-development import path.
        from clerk_backend_api import AuthenticateRequestOptions, authenticate_request

        state = authenticate_request(
            request,
            AuthenticateRequestOptions(
                secret_key=self._secret_key,
                jwt_key=self._jwt_key,
                audience=self._audience,
                authorized_parties=self._authorized_parties,
                accepts_token=["session_token"],
            ),
        )
        if not state.is_signed_in:
            reason = getattr(state.reason, "name", None) or "invalid session"
            raise AuthenticationError(str(reason))
        payload = state.payload
        if not isinstance(payload, dict):
            raise AuthenticationError("invalid session claims")
        if payload.get("sts") == "pending":
            raise AuthorizationError("organization membership is pending")

        organization_id, role = _organization_claims(payload)
        user_id = payload.get("sub")
        if not isinstance(user_id, str) or not user_id:
            raise AuthenticationError("session has no user identity")
        if not organization_id:
            raise AuthorizationError("select an organization to access Denali")
        if role not in {"admin", "member"}:
            raise AuthorizationError("organization role is not supported")
        if (
            self._allowed_organizations is not None
            and organization_id not in self._allowed_organizations
        ):
            raise AuthorizationError("organization is not approved for this Denali pilot")
        return AuthContext(
            user_id=user_id,
            organization_id=organization_id,
            role=role,
        )


def _organization_claims(payload: dict[str, Any]) -> tuple[str | None, str | None]:
    """Support Clerk session-token v2 claims and the legacy flattened shape."""

    organization = payload.get("o")
    if isinstance(organization, dict):
        organization_id = organization.get("id")
        role = organization.get("rol")
    else:
        organization_id = payload.get("org_id")
        role = payload.get("org_role")
    if isinstance(role, str) and role.startswith("org:"):
        role = role.removeprefix("org:")
    return (
        organization_id if isinstance(organization_id, str) else None,
        role if isinstance(role, str) else None,
    )


def _csv_environment(name: str) -> list[str]:
    return [item.strip() for item in os.environ.get(name, "").split(",") if item.strip()]
