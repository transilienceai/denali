"""Server-only bridge from an authenticated Denali org to shared connections."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from clerk_backend_api import Clerk
from clerk_backend_api.models import ClerkBaseError


@dataclass(frozen=True)
class SharedConnectionsError(Exception):
    status_code: int


class SharedConnectionsClient:
    def __init__(self, origin: str, machine_secret_key: str):
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
        self._clerk = Clerk(bearer_auth=machine_secret_key)

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
        return cls(origin, key)

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
            with httpx.Client(timeout=20, follow_redirects=False) as client:
                response = client.request(
                    method,
                    f"{self._origin}{path}",
                    params=(
                        {"clerk_org_id": clerk_org_id}
                        if method == "GET" or payload is None
                        else None
                    ),
                    json={**payload, "clerk_org_id": clerk_org_id} if payload is not None else None,
                    headers={"Authorization": f"Bearer {token}"},
                )
        except (httpx.RequestError, ClerkBaseError) as error:
            raise SharedConnectionsError(502) from error
        if not 200 <= response.status_code < 300:
            safe_status = response.status_code if response.status_code in {404, 409, 422} else 502
            raise SharedConnectionsError(safe_status)
        return response.text if expect_text else response.json()
