"""Bounded, credential-free Google Workspace facts for Shasta's v1 source bridge.

This is a deliberately small outbound contract. Google credentials are minted in the
Denali worker; only allowlisted directory and audit fields cross the bridge. Shasta
remains authoritative for source identity, freshness, and compliance review.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import httpx

API_ROOT = "https://admin.googleapis.com"
MAX_PAGES = 20
MAX_FACTS = 1000
MAX_SNAPSHOT_BYTES = 5 * 1024 * 1024
SCOPES = {
    "directory.users.read": "https://www.googleapis.com/auth/admin.directory.user.readonly",
    "directory.groups.read": "https://www.googleapis.com/auth/admin.directory.group.readonly",
    "reports.login.read": "https://www.googleapis.com/auth/admin.reports.audit.readonly",
    "reports.admin.read": "https://www.googleapis.com/auth/admin.reports.audit.readonly",
}


def delegated_requests(service_account: str, admin_email: str):
    """Create scope-specific authenticated requests from Denali's existing WIF identity."""

    if not service_account.endswith(".iam.gserviceaccount.com"):
        raise ValueError("Google Workspace service account is invalid")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+", admin_email):
        raise ValueError("Google Workspace delegated administrator is invalid")
    sessions: dict[str, Any] = {}

    def request_for_scope(scope: str):
        if scope not in SCOPES.values():
            raise ValueError("Google Workspace scope is not allowlisted")
        if scope not in sessions:
            from google.auth import default
            from google.auth.impersonated_credentials import Credentials
            from google.auth.transport.requests import AuthorizedSession

            source, _ = default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            delegated = Credentials(
                source_credentials=source,
                target_principal=service_account,
                target_scopes=[scope],
                subject=admin_email,
                lifetime=900,
            )
            sessions[scope] = AuthorizedSession(delegated)
        session = sessions[scope]

        def request(method: str, url: str, **kwargs):
            if method != "GET" or not url.startswith(f"{API_ROOT}/"):
                raise ValueError("Google Workspace request is outside its read-only boundary")
            return session.get(url, timeout=30, **kwargs)

        return request

    return request_for_scope


def _pages(request, path: str, params: dict[str, str], item_key: str):
    records: list[dict] = []
    token = None
    for _ in range(MAX_PAGES):
        query = dict(params)
        if token:
            query["pageToken"] = token
        response = request("GET", f"{API_ROOT}{path}", params=query)
        if response.status_code >= 400:
            return records, False, response.status_code
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get(item_key, []), list):
            raise ValueError("Google Workspace returned an invalid collection")
        records.extend(item for item in payload.get(item_key, []) if isinstance(item, dict))
        if len(records) > MAX_FACTS:
            return records[:MAX_FACTS], False, None
        token = payload.get("nextPageToken")
        if token is None:
            return records, True, None
        if not isinstance(token, str) or not token:
            raise ValueError("Google Workspace returned an invalid page token")
    return records, False, None


def _text(value: Any, maximum: int, default: str | None = None) -> str | None:
    if value is None:
        return default
    result = str(value).strip()
    return result[:maximum] if result else default


def _instant(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC).isoformat() if parsed.tzinfo else None


def _user(item: dict, observed_at: str):
    email = _text(item.get("primaryEmail"), 320)
    if not email:
        return None
    data: dict[str, Any] = {
        "primary_email": email.lower(),
        "account_type": "user",
        "suspended": bool(item.get("suspended", False)),
        "archived": bool(item.get("archived", False)),
        "is_admin": bool(item.get("isAdmin", False)),
    }
    name = item.get("name")
    if isinstance(name, dict) and _text(name.get("fullName"), 200):
        data["full_name"] = _text(name.get("fullName"), 200)
    if isinstance(item.get("isEnrolledIn2Sv"), bool):
        data["mfa_enrolled"] = item["isEnrolledIn2Sv"]
    if _text(item.get("orgUnitPath"), 500):
        data["org_unit_path"] = _text(item.get("orgUnitPath"), 500)
    return {"kind": "directory.user", "subject": email.lower(),
            "observed_at": observed_at, "data": data}


def _group(item: dict, observed_at: str):
    email = _text(item.get("email"), 320)
    if not email:
        return None
    data: dict[str, Any] = {"email": email.lower()}
    for key, maximum in (("name", 200), ("description", 1000)):
        if _text(item.get(key), maximum):
            data[key] = _text(item.get(key), maximum)
    count = item.get("directMembersCount")
    if isinstance(count, int) and count >= 0:
        data["direct_members_count"] = count
    elif isinstance(count, str) and count.isdigit():
        data["direct_members_count"] = int(count)
    return {"kind": "directory.group", "subject": email.lower(),
            "observed_at": observed_at, "data": data}


def _events(items: list[dict], application: str, collected_at: str):
    kind = f"reports.{application}_event"
    for item in items:
        identity = item.get("id") if isinstance(item.get("id"), dict) else {}
        when = _instant(identity.get("time"))
        qualifier = _text(identity.get("uniqueQualifier"), 120, "0")
        actor = item.get("actor") if isinstance(item.get("actor"), dict) else {}
        events = item.get("events") if isinstance(item.get("events"), list) else []
        for index, event in enumerate(events):
            if not isinstance(event, dict):
                continue
            data = {
                "actor": _text(actor.get("email"), 320, "unknown"),
                "event_name": _text(event.get("name"), 200, "unknown"),
            }
            if application == "login" and _text(item.get("ipAddress"), 64):
                data["ip_address"] = _text(item.get("ipAddress"), 64)
            subject = f"{application}:{when or 'unknown'}:{qualifier}:{index}"
            yield {"kind": kind, "subject": subject,
                   "observed_at": when or collected_at, "data": data}


def collect_snapshot(
    request_for_scope: Callable[[str], Callable],
    *,
    domain: str,
    collected_at: datetime | None = None,
) -> dict:
    """Collect four required capabilities with explicit permission/pagination outcomes."""

    if not re.fullmatch(r"[A-Za-z0-9.-]{3,253}", domain):
        raise ValueError("Google Workspace domain is invalid")
    now = (collected_at or datetime.now(UTC)).astimezone(UTC)
    start = now - timedelta(days=30)
    at = now.isoformat()
    facts: list[dict] = []
    identities: set[tuple[str, str]] = set()
    status: dict[str, tuple[str, str | None]] = {}

    def add(fact: dict | None) -> bool:
        if fact is None:
            return True
        identity = fact["kind"], fact["subject"]
        if len(facts) >= MAX_FACTS or identity in identities:
            return False
        facts.append(fact)
        identities.add(identity)
        return True

    plans = (
        ("directory.users.read", "/admin/directory/v1/users",
         {"domain": domain, "maxResults": "500", "orderBy": "email", "projection": "full"},
         "users", lambda items: (_user(item, at) for item in items)),
        ("directory.groups.read", "/admin/directory/v1/groups",
         {"domain": domain, "maxResults": "200"}, "groups",
         lambda items: (_group(item, at) for item in items)),
        ("reports.login.read", "/admin/reports/v1/activity/users/all/applications/login",
         {"startTime": start.isoformat().replace("+00:00", "Z"),
          "endTime": at.replace("+00:00", "Z"), "maxResults": "1000"},
         "items", lambda items: _events(items, "login", at)),
        ("reports.admin.read", "/admin/reports/v1/activity/users/all/applications/admin",
         {"startTime": start.isoformat().replace("+00:00", "Z"),
          "endTime": at.replace("+00:00", "Z"), "maxResults": "1000"},
         "items", lambda items: _events(items, "admin", at)),
    )
    for capability, path, params, key, normalize in plans:
        try:
            items, complete, http_status = _pages(
                request_for_scope(SCOPES[capability]), path, params, key
            )
            if http_status is not None:
                status[capability] = (
                    "missing" if http_status in {401, 403} else "failed",
                    None if http_status in {401, 403} else "Provider collection request failed",
                )
                continue
            bounded = all(add(fact) for fact in normalize(items))
            status[capability] = (
                "complete" if complete and bounded else "failed",
                None if complete and bounded else "Provider collection exceeded its bound",
            )
        except Exception:
            status[capability] = ("failed", "Provider collection request failed")

    observed = sorted(name for name, (state, _) in status.items() if state == "complete")
    missing = sorted(name for name, (state, _) in status.items() if state != "complete")
    errors = [message for name in sorted(status) if (message := status[name][1])]
    collection_state = (
        "failed" if not observed and errors else "partial" if missing else "complete"
    )
    idempotency_key = (
        f"google_workspace-{domain.lower()}-{now.strftime('%Y%m%dT%H%M%SZ')}"
    )[:128]
    return {
        "schema_version": "shasta-source-snapshot-1",
        "idempotency_key": idempotency_key,
        "collection_state": collection_state,
        "observed_identity": domain.lower(),
        "collected_at": at,
        "period_start": start.isoformat(),
        "period_end": at,
        "pagination_complete": not missing,
        "capabilities_observed": observed,
        "missing_permissions": missing,
        "adapter_name": "denali-shasta-google-workspace-bridge",
        "adapter_version": "1.0.0",
        "errors": errors,
        "facts": facts,
    }


def publish_snapshot(
    snapshot: dict,
    *,
    source_id: str,
    bridge_secret: bytes,
    transport: httpx.BaseTransport | None = None,
) -> dict:
    """Sign exact bounded bytes for Shasta's per-source HTTPS ingress."""

    source_id = str(UUID(source_id))
    if len(bridge_secret) < 32:
        raise ValueError("Shasta bridge secret is too short")
    raw = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Shasta snapshot exceeds the bounded bridge limit")
    timestamp = int(time.time())
    digest = hashlib.sha256(raw).hexdigest()
    message = f"{timestamp}\n{source_id}\n{digest}".encode()
    signature = hmac.new(bridge_secret, message, hashlib.sha256).hexdigest()
    with httpx.Client(timeout=30, transport=transport) as client:
        response = client.post(
            f"https://shasta.transilience.cloud/pilot/api/bridge/sources/{source_id}/snapshots",
            content=raw,
            headers={
                "Content-Type": "application/json",
                "X-Shasta-Timestamp": str(timestamp),
                "X-Shasta-Signature": f"sha256={signature}",
            },
        )
    if response.status_code not in {200, 201}:
        raise RuntimeError(
            f"Shasta snapshot bridge rejected the request with HTTP {response.status_code}"
        )
    result = response.json()
    return {
        "source_id": source_id,
        "snapshot_id": str(UUID(result["snapshot_id"])),
        "replayed": bool(result["replayed"]),
        "body_sha256": result.get("body_sha256"),
    }


def collect_and_publish(
    *,
    provider: str,
    tenant_id: str,
    connection_id: str,
    source_id: str,
    shasta_url: str,
    bridge_secret: bytes,
) -> dict:
    """Resolve exactly one active Denali connection before minting delegated credentials."""

    from denali.store.repository import PostgresInventoryRepository

    if provider != "google_workspace" or shasta_url != "https://shasta.transilience.cloud/pilot":
        raise ValueError("Unsupported Shasta bridge binding")
    tenant_id = str(UUID(tenant_id))
    connection_id = str(UUID(connection_id))
    dsn = os.environ.get("DENALI_DSN", "").strip()
    service_account = os.environ.get("DENALI_GOOGLE_WORKSPACE_SERVICE_ACCOUNT", "").strip()
    if not dsn or not service_account:
        raise RuntimeError("Denali Workspace worker configuration is incomplete")
    connection = PostgresInventoryRepository(dsn).get_connection_validation_target(
        tenant_id, connection_id
    )
    if not connection or connection["lifecycle_state"] != "active":
        raise RuntimeError("The Denali connection is unavailable or disabled")
    if connection["provider"] != "google_workspace":
        raise RuntimeError("The Denali connection provider does not match")
    configuration = connection["configuration"]
    request_for_scope = delegated_requests(
        service_account, str(configuration.get("admin_email", ""))
    )
    snapshot = collect_snapshot(
        request_for_scope, domain=str(configuration.get("domain", ""))
    )
    return publish_snapshot(snapshot, source_id=source_id, bridge_secret=bridge_secret)
