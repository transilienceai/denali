"""Server-only bridge from an authenticated Denali org to shared connections."""

from __future__ import annotations

import json
import logging
import os
import queue
import re
import threading
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

import httpx
from clerk_backend_api import Clerk
from clerk_backend_api.models import ClerkBaseError

from denali.integrations.clerk_connection_settings import ConnectionSettingsUnavailable

_LOGGER = logging.getLogger(__name__)
_BOUNDED_RPC_SLOTS = threading.BoundedSemaphore(8)
_BOUNDED_RPC_SECONDS = 60
_SETTINGS_LIST_PROVIDERS = {
    "/v1/connections": frozenset({"aws", "github", "gcp", "azure", "entra", "azure_repos"}),
    "/internal/v1/connections/jira": frozenset({"jira"}),
    "/internal/v1/connections/google-workspace": frozenset({"google_workspace"}),
    "/internal/v1/connections/azure-repos": frozenset({"azure_repos"}),
}


@dataclass(frozen=True)
class SharedConnectionsError(Exception):
    status_code: int


class _BoundedRPCFailure(Exception):
    """Mutable exception for HTTP context managers; converted only after unwind."""

    def __init__(self, status: int = 502):
        self.status_code = status
        super().__init__(status)


class SharedConnectionsClient:
    def __init__(
        self,
        origin: str,
        machine_secret_key: str,
        *,
        allowed_clerk_org_ids: frozenset[str] | None = None,
        connection_settings_reader: Any | None = None,
        connection_settings_org_ids: frozenset[str] | None = None,
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
        self._clerk = Clerk(bearer_auth=machine_secret_key)
        self._allowed_clerk_org_ids = allowed_clerk_org_ids
        self._connection_settings_reader = connection_settings_reader
        if connection_settings_reader is not None and (
            not connection_settings_org_ids or len(connection_settings_org_ids) > 20
            or any(not re.fullmatch(r"org_[A-Za-z0-9]{1,124}", org)
                   for org in connection_settings_org_ids)
        ):
            raise ValueError("Clerk connection-settings migration selection invalid")
        self._connection_settings_org_ids = connection_settings_org_ids or frozenset()

    @staticmethod
    def allowed_org_ids_from_environment() -> frozenset[str]:
        raw = os.environ.get("DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS", "")
        org_ids = frozenset(value.strip() for value in raw.split(",") if value.strip())
        if any(not re.fullmatch(r"org_[A-Za-z0-9]+", value) for value in org_ids):
            raise ValueError("shared connections allowlist contains an invalid Clerk org ID")
        return org_ids

    def allows_org(self, clerk_org_id: str) -> bool:
        return self._allowed_clerk_org_ids is None or clerk_org_id in self._allowed_clerk_org_ids

    @staticmethod
    def settings_org_ids_from_environment() -> frozenset[str]:
        values = [value.strip() for value in os.environ.get(
            "DENALI_CLERK_CONNECTION_SETTINGS_ORG_IDS", "",
        ).split(",") if value.strip()]
        if (not 1 <= len(values) <= 20 or len(values) != len(set(values))
                or any(not re.fullmatch(r"org_[A-Za-z0-9]{1,124}", org) for org in values)):
            raise ValueError("Clerk connection-settings migration selection invalid")
        return frozenset(values)

    @property
    def origin(self) -> str:
        """Public, deployment-owned origin for validating provider callback metadata."""
        return self._origin

    @classmethod
    def from_environment(cls) -> SharedConnectionsClient | None:
        source = os.environ.get("DENALI_CONNECTION_SETTINGS_SOURCE", "platform")
        if source not in {"platform", "clerk"}:
            raise ValueError("invalid Denali connection-settings source")
        origin = os.environ.get("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "")
        key = os.environ.get("DENALI_PLATFORM_MACHINE_SECRET_KEY", "")
        # Provisioning the sender secret alone must not activate the bridge.
        if not origin:
            if source == "clerk":
                raise ValueError("Clerk settings require the existing shared-connections bridge")
            return None
        if not key:
            raise ValueError(
                "shared connections origin and machine secret must be configured together"
            )
        return cls(
            origin,
            key,
            allowed_clerk_org_ids=cls.allowed_org_ids_from_environment(),
            connection_settings_reader=(
                cls._settings_reader_from_environment() if source == "clerk" else None
            ),
            connection_settings_org_ids=(
                cls.settings_org_ids_from_environment() if source == "clerk" else None
            ),
        )

    @staticmethod
    def _settings_reader_from_environment():
        from denali.integrations.clerk_connection_settings import ClerkConnectionSettingsReader

        environment = os.environ.get("DENALI_CONNECTION_SETTINGS_ENVIRONMENT", "")
        modal_environment = os.environ.get("MODAL_ENVIRONMENT")
        expected = {"denali-prod": "production", "denali-dev": "development"}.get(
            modal_environment or ""
        )
        if expected is not None and environment != expected:
            raise ValueError("Denali connection-settings environment differs")
        return ClerkConnectionSettingsReader(
            os.environ.get("CLERK_CONNECTION_SETTINGS_SECRET_KEY", ""),
            environment,
            "denali",
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        clerk_org_id: str,
        payload: dict[str, Any] | None = None,
        expect_text: bool = False,
        max_response_bytes: int | None = None,
    ) -> dict[str, Any] | str:
        if not self.allows_org(clerk_org_id):
            raise SharedConnectionsError(404)
        if path != "/v1/connections" and not path.startswith("/internal/v1/connections/"):
            raise ValueError("unexpected shared connections path")
        if max_response_bytes is not None:
            if (
                type(max_response_bytes) is not int
                or not 1 <= max_response_bytes <= 2_097_152
                or expect_text
            ):
                raise ValueError("invalid bounded shared response selection")
        if (method == "GET" and path in _SETTINGS_LIST_PROVIDERS
                and self._connection_settings_reader is not None
                and clerk_org_id in self._connection_settings_org_ids):
            if expect_text or payload is not None:
                raise ValueError("unexpected connection-settings list options")
            if not _BOUNDED_RPC_SLOTS.acquire(blocking=False):
                _LOGGER.warning("connection_settings_lookup_failed code=capacity")
                raise SharedConnectionsError(502)
            failure_code = "reader_error"
            try:
                result = self._connection_settings_reader.list_connections(
                    clerk_org_id, providers=_SETTINGS_LIST_PROVIDERS[path],
                )
                if (max_response_bytes is not None
                        and len(json.dumps(result).encode("utf-8")) > max_response_bytes):
                    failure_code = "response_bound"
                else:
                    return result
            except ConnectionSettingsUnavailable:
                failure_code = "snapshot_unavailable"
            except Exception:  # noqa: BLE001 - never log credential-owning diagnostics.
                pass
            finally:
                _BOUNDED_RPC_SLOTS.release()
            # Fixed codes only; raise after exception unwinding so raw transport
            # exceptions are not retained as this bridge error's context.
            _LOGGER.warning("connection_settings_lookup_failed code=%s", failure_code)
            raise SharedConnectionsError(502)
        if max_response_bytes is not None:
            return self._bounded_request(method, path, clerk_org_id, payload, max_response_bytes)
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

    def _bounded_request(
        self, method: str, path: str, org: str, payload: dict[str, Any] | None, limit: int
    ) -> dict[str, Any]:
        """Opt-in bounded JSON RPC; legacy providers retain their existing path.

        The deadline includes M2M minting, transport and parsing. A bounded pool
        also caps timed-out SDK calls which have not yet returned. No provider
        token or raw transport/parser exception escapes this private boundary.
        """
        deadline = time.monotonic() + _BOUNDED_RPC_SECONDS
        result: queue.Queue[tuple[bool, Any]] = queue.Queue(maxsize=1)
        cancelled = threading.Event()
        if not _BOUNDED_RPC_SLOTS.acquire(blocking=False):
            raise SharedConnectionsError(502)

        def check() -> None:
            if cancelled.is_set() or time.monotonic() >= deadline:
                raise _BoundedRPCFailure()

        def perform() -> None:
            try:
                check()
                token = self._clerk.m2m.create_token(
                    seconds_until_expiration=120, min_remaining_ttl_seconds=90
                ).token
                check()
                with httpx.Client(
                    timeout=max(0.001, deadline - time.monotonic()),
                    follow_redirects=False,
                    trust_env=False,
                    transport=httpx.HTTPTransport(retries=0),
                ) as client:
                    with client.stream(
                        method,
                        f"{self._origin}{path}",
                        params={"clerk_org_id": org}
                        if method == "GET" or payload is None
                        else None,
                        json={**payload, "clerk_org_id": org} if payload is not None else None,
                        headers={
                            "Authorization": f"Bearer {token}",
                            "Accept": "application/json",
                            "Accept-Encoding": "identity",
                        },
                    ) as response:
                        check()
                        if not 200 <= response.status_code < 300:
                            status = (
                                response.status_code
                                if response.status_code in {404, 409, 422}
                                else 502
                            )
                            raise _BoundedRPCFailure(status)
                        if response.headers.get("content-encoding", "identity") != "identity":
                            raise _BoundedRPCFailure()
                        length = response.headers.get("content-length")
                        if length is not None and (not length.isdigit() or int(length) > limit):
                            raise _BoundedRPCFailure()
                        body = bytearray()
                        for chunk in response.iter_bytes():
                            check()
                            if len(body) + len(chunk) > limit:
                                raise _BoundedRPCFailure()
                            body.extend(chunk)
                        check()
                        value = json.loads(body)
                        check()
                        if not isinstance(value, dict):
                            raise _BoundedRPCFailure()
                        result.put((True, value))
            except Exception as error:  # noqa: BLE001 - no raw credential-owning exception escapes.
                safe = SharedConnectionsError(
                    error.status_code if isinstance(error, _BoundedRPCFailure) else 502
                )
                result.put((False, safe))
            finally:
                _BOUNDED_RPC_SLOTS.release()

        threading.Thread(target=perform, name="shared-bounded-rpc", daemon=True).start()
        try:
            success, value = result.get(timeout=max(0.001, deadline - time.monotonic()))
        except queue.Empty:
            cancelled.set()
            raise SharedConnectionsError(502) from None
        if cancelled.is_set() or time.monotonic() >= deadline:
            raise SharedConnectionsError(502)
        if not success:
            raise value from None
        return value
