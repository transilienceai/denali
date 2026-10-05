"""Clerk machine verification and live organization membership for the gateway."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

import httpx
from clerk_backend_api.models import ClerkBaseError


@dataclass(frozen=True)
class GatewayPrincipal:
    machine_id: str
    organization_id: str
    user_id: str
    purpose: str


class GatewayVerifier(Protocol):
    def verify(self, token: str, *, purpose: str) -> GatewayPrincipal | None: ...


class MembershipChecker(Protocol):
    def role(self, organization_id: str, user_id: str) -> str | None: ...


class ClerkGatewayVerifier:
    """Accept only short-lived tokens from the configured platform machine."""

    def __init__(self, machine_secret_key: str, gateway_machine_id: str, receiver_machine_id: str):
        if not all((machine_secret_key, gateway_machine_id, receiver_machine_id)):
            raise ValueError("gateway machine configuration is incomplete")
        from clerk_backend_api import Clerk

        self._clerk = Clerk(bearer_auth=machine_secret_key)
        self._gateway_machine_id = gateway_machine_id
        self._receiver_machine_id = receiver_machine_id

    def verify(self, token: str, *, purpose: str) -> GatewayPrincipal | None:
        if not token or purpose not in {
            "results:read",
            "denali:write",
            "denali:connections:destructive",
        }:
            return None
        try:
            verified = self._clerk.m2m.verify_token(token=token)
        except (ClerkBaseError, httpx.RequestError):
            return None
        if (
            verified.revoked
            or verified.expired
            or verified.subject != self._gateway_machine_id
            or self._receiver_machine_id not in verified.scopes
            or verified.expiration is None
            or not 0 < verified.expiration - verified.created_at <= 15 * 60 * 1000
        ):
            return None
        claims = verified.claims
        if not isinstance(claims, dict) or claims.get("purpose") != purpose:
            return None
        organization_id = claims.get("org_id")
        user_id = claims.get("user_id")
        if (
            not isinstance(organization_id, str)
            or re.fullmatch(r"org_[A-Za-z0-9]+", organization_id) is None
            or not isinstance(user_id, str)
            or re.fullmatch(r"user_[A-Za-z0-9]+", user_id) is None
        ):
            return None
        return GatewayPrincipal(verified.subject, organization_id, user_id, purpose)


class ClerkMembershipChecker:
    """Resolve current membership; a token claim alone cannot authorize an action."""

    def __init__(self, secret_key: str):
        if not secret_key:
            raise ValueError("CLERK_SECRET_KEY is required for gateway membership checks")
        from clerk_backend_api import Clerk

        self._clerk = Clerk(bearer_auth=secret_key)

    def role(self, organization_id: str, user_id: str) -> str | None:
        memberships = self._clerk.organization_memberships.list(
            organization_id=organization_id, user_id=[user_id], limit=1
        )
        for membership in memberships.data:
            member = membership.public_user_data
            if member is not None and member.user_id == user_id:
                role = membership.role
                return role.removeprefix("org:") if isinstance(role, str) else None
        return None
