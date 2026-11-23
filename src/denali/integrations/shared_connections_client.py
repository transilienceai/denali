"""Server-only bridge from an authenticated Denali org to shared connections."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from clerk_backend_api import Clerk
from clerk_backend_api.models import ClerkBaseError

_BROKER_ORIGINS = frozenset({
    "https://transilience-transilience-platform-dev--transilience-pla-73050c.modal.run",
    "https://transilience-transilience-platform-prod--transilience-pl-8a9ce7.modal.run",
})


def shared_modal_proxy_headers(origin: str, key: str, secret: str) -> dict[str, str]:
    if origin not in _BROKER_ORIGINS:
        raise ValueError("shared connections origin must be a reviewed Platform origin")
    environment = os.environ.get("MODAL_ENVIRONMENT", "")
    expected = {
        "denali-prod": "https://transilience-transilience-platform-prod--transilience-pl-8a9ce7.modal.run",
        "denali-dev": "https://transilience-transilience-platform-dev--transilience-pla-73050c.modal.run",
    }.get(environment)
    if expected is None and (environment or os.environ.get("MODAL_IS_REMOTE") == "1"):
        raise ValueError("shared connections require a recognized Modal environment")
    if expected is not None and origin != expected:
        raise ValueError("shared connections origin differs from the Modal environment")
    if (not re.fullmatch(r"wk-[A-Za-z0-9_-]{1,256}", key)
            or not re.fullmatch(r"ws-[A-Za-z0-9_-]{1,256}", secret)):
        raise ValueError("Denali shared-connections Modal proxy credentials are required")
    return {"Modal-Key": key, "Modal-Secret": secret}


@dataclass(frozen=True)
class SharedConnectionsError(Exception):
    status_code: int


class SharedConnectionsClient:
    def __init__(
        self,
        origin: str,
        machine_secret_key: str,
        *,
        modal_proxy_key: str,
        modal_proxy_secret: str,
        allowed_clerk_org_ids: frozenset[str] | None = None,
    ):
        origin = origin.rstrip("/")
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("shared connections origin must be an HTTPS origin")
        if not machine_secret_key:
            raise ValueError("Denali shared-connections machine secret is required")
        self._origin = origin
        self._modal_proxy_headers = shared_modal_proxy_headers(
            origin, modal_proxy_key, modal_proxy_secret,
        )
        self._clerk = Clerk(bearer_auth=machine_secret_key)
        self._allowed_clerk_org_ids = allowed_clerk_org_ids

    @staticmethod
    def allowed_org_ids_from_environment() -> frozenset[str]:
        org_ids = frozenset(
            value.strip()
            for value in os.environ.get("DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS", "").split(",")
            if value.strip()
        )
        if any(not re.fullmatch(r"org_[A-Za-z0-9]+", value) for value in org_ids):
            raise ValueError("shared Microsoft allowlist contains an invalid Clerk org ID")
        return org_ids

    def allows_org(self, clerk_org_id: str) -> bool:
        # Microsoft-only admission: preserve this dev branch's existing AWS/GitHub
        # request/from_environment behavior and their Platform entitlement checks.
        allowed = self._allowed_clerk_org_ids
        if allowed is None:
            allowed = self.allowed_org_ids_from_environment()
        return clerk_org_id in allowed

    @classmethod
    def from_environment(cls) -> SharedConnectionsClient | None:
        origin = os.environ.get("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "")
        key = os.environ.get("DENALI_PLATFORM_MACHINE_SECRET_KEY", "")
        if not origin and not key:
            return None
        if not origin or not key:
            raise ValueError(
                "shared connections origin and machine secret must be configured together"
            )
        return cls(
            origin, key,
            modal_proxy_key=os.environ.get("DENALI_PLATFORM_MODAL_PROXY_KEY", ""),
            modal_proxy_secret=os.environ.get("DENALI_PLATFORM_MODAL_PROXY_SECRET", ""),
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        clerk_org_id: str,
        payload: dict[str, Any] | None = None,
        expect_text: bool = False,
    ) -> dict[str, Any] | str:
        if path != "/v1/connections" and not path.startswith("/internal/v1/connections/"):
            raise ValueError("unexpected shared connections path")
        try:
            token = self._clerk.m2m.create_token(
                seconds_until_expiration=60, min_remaining_ttl_seconds=20
            ).token
            with httpx.Client(timeout=20, follow_redirects=False, trust_env=False) as client:
                response = client.request(
                    method,
                    f"{self._origin}{path}",
                    params=(
                        {"clerk_org_id": clerk_org_id}
                        if method == "GET" or payload is None
                        else None
                    ),
                    json={**payload, "clerk_org_id": clerk_org_id} if payload is not None else None,
                    headers={"Authorization": f"Bearer {token}", **self._modal_proxy_headers},
                )
        except (httpx.RequestError, ClerkBaseError):
            response = None
        if response is None:
            # Unwind the credential-bearing transport exception before raising
            # a fixed error at the application boundary.
            raise SharedConnectionsError(502)
        if not 200 <= response.status_code < 300:
            safe_status = response.status_code if response.status_code in {404, 409, 422} else 502
            raise SharedConnectionsError(safe_status)
        return response.text if expect_text else response.json()
