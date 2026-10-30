"""Server-only reader for the version-1 Clerk connection-settings projection.

This is discovery, never an authorization or provider-credential source. Keep
the private settings dictionary out of all product/client response objects.
"""

from __future__ import annotations

import copy
import json
import re
import time
from collections.abc import Callable, Collection
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import httpx

NAMESPACE = "transilience_connections"
PROVIDERS = frozenset({
    "aws", "gcp", "azure", "entra", "github", "azure_repos",
    "google_workspace", "jira", "gmail", "outlook",
})
MAX_METADATA_BYTES = 8192
MAX_RESPONSE_BYTES = 65536
MAX_LIFETIME_SECONDS = 300
_ROOT_FIELDS = {
    "version", "environment", "organization_id", "revision", "published_at", "expires_at",
    "sources",
}
_COMMON_VIEW = {
    "id", "provider", "connection_kind", "display_name", "availability", "declared_scopes",
    "validated_scopes", "last_validated_at", "lifecycle_state", "setup_state", "health_state",
}
_VIEW_FIELDS = {
    "aws": {"partition", "external_account_id", "deployment_region", "coverage_mode", "regions",
            "selected_resource", "resource_type", "resource_arn", "account_id", "role_arn",
            "role_name", "credential_state"},
    "gcp": {"projects"},
    "azure": {"tenant_id", "subscriptions", "operator_client_id", "application_client_id",
              "credential_state"},
    "entra": {"tenant_id", "client_id"},
    "github": {"external_account_id", "account_id", "account_login", "repository_selection",
               "installation_id", "repository_count", "organization_scope_status"},
    "azure_repos": {"target_id", "tenant_id", "organization", "application_client_id",
                    "repository_count", "authority_revision"},
    "google_workspace": {"clerk_org_id", "target_id", "customer_id", "domain", "admin_email",
                         "service_account", "oauth_client_id", "binding_revision",
                         "validation_results", "observed_customer_id", "management_allowed"},
    "jira": {"site_url", "cloud_id", "project_ids", "available_scopes", "management_allowed",
             "verified_at"},
    "gmail": {"owner_user_id", "mailbox_address", "verified_at"},
    "outlook": {"owner_user_id", "mailbox_address", "verified_at"},
}
_SETTINGS_FIELDS = {
    "role_arn", "external_id", "principal_arn", "role_name", "partition", "external_account_id",
    "deployment_region", "coverage_mode", "regions", "declared_scopes", "projects",
    "principal_email", "principal_unique_id", "service_account", "service_account_unique_id",
    "tenant_id", "subscriptions", "operator_client_id", "application_client_id", "client_id",
    "installation_id", "account_id", "account_login", "repository_selection", "repository_ids",
    "target_id", "organization", "customer_id", "domain", "admin_email", "oauth_client_id",
    "site_url", "cloud_id", "project_ids", "resource_arn", "resource_type", "selected_resource",
    "provider_subject", "operator_project_id",
}
_SENSITIVE_KEY = re.compile(
    r"(?:password|secret|token|private.?key|sealed.?credentials|authorization|cookie|dsn|sa.?key)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|\b(?:sk_(?:live|test)_|gh[pousr]_|github_pat_|"
    r"AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|Bearer\s))"
)


class ConnectionSettingsUnavailable(RuntimeError):
    """A fixed-message exception: never retain credential-owning HTTP errors."""

    def __init__(self) -> None:
        super().__init__("connection settings unavailable")


def _reject() -> None:
    raise ConnectionSettingsUnavailable()


def _uuid(value: Any) -> bool:
    try:
        return isinstance(value, str) and str(UUID(value)) == value and UUID(value).int != 0
    except (ValueError, TypeError, AttributeError):
        return False


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith(("Z", "+00:00")):
        _reject()
    try:
        result = datetime.fromisoformat(value)
    except ValueError:
        raise ConnectionSettingsUnavailable() from None
    if result.tzinfo is None or result.utcoffset().total_seconds() != 0:
        _reject()
    return result


def _safe_json(value: Any, depth: int = 0) -> None:
    if depth > 12:
        _reject()
    if isinstance(value, dict):
        if len(value) > 1000:
            _reject()
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 128 or _SENSITIVE_KEY.search(key):
                _reject()
            _safe_json(item, depth + 1)
    elif isinstance(value, list):
        if len(value) > 1000:
            _reject()
        for item in value:
            _safe_json(item, depth + 1)
    elif isinstance(value, str):
        if len(value) > 4096 or _SENSITIVE_VALUE.search(value):
            _reject()
    elif (type(value) is int and not -(2**53 - 1) <= value <= 2**53 - 1
          or value is not None and type(value) not in {int, bool}):
        _reject()


def validate_document(
    value: Any, *, organization_id: str, environment: str, now: datetime | None = None,
) -> dict[str, Any]:
    """Validate all app views before any private record is returned or published."""
    if (not isinstance(value, dict) or set(value) != _ROOT_FIELDS
            or type(value.get("version")) is not int or value["version"] != 1
            or environment not in {"production", "development"}
            or value.get("environment") != environment
            or not isinstance(organization_id, str)
            or not re.fullmatch(r"org_[A-Za-z0-9]{1,124}", organization_id)
            or value.get("organization_id") != organization_id
            or not _uuid(value.get("revision"))):
        _reject()
    try:
        encoded = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), allow_nan=False,
        ).encode()
    except (TypeError, ValueError, UnicodeError, RecursionError):
        raise ConnectionSettingsUnavailable() from None
    if len(encoded) > MAX_METADATA_BYTES:
        _reject()
    published, expiry = _timestamp(value["published_at"]), _timestamp(value["expires_at"])
    clock = now or datetime.now(UTC)
    if clock.tzinfo is None or not published <= clock < expiry:
        _reject()
    if not 0 < (expiry - published).total_seconds() <= MAX_LIFETIME_SECONDS:
        _reject()
    sources = value["sources"]
    if not isinstance(sources, dict) or not set(sources) <= PROVIDERS:
        _reject()
    seen: set[str] = set()
    for provider, records in sources.items():
        if not isinstance(records, list) or len(records) > 100:
            _reject()
        for record in records:
            if not isinstance(record, dict):
                _reject()
            connection_id = record.get("id")
            if (not _uuid(connection_id) or connection_id in seen
                    or not {"id", "settings", "applications"} <= set(record)
                    or set(record) - {"id", "settings", "applications", "owner_user_id"}):
                _reject()
            seen.add(connection_id)
            settings, applications = record["settings"], record["applications"]
            if (not isinstance(settings, dict) or not set(settings) <= _SETTINGS_FIELDS
                    or not isinstance(applications, dict) or len(applications) > 20):
                _reject()
            _safe_json(settings)
            mail = provider in {"gmail", "outlook"}
            owner = record.get("owner_user_id")
            if mail:
                if (not isinstance(owner, str)
                        or not re.fullmatch(r"user_[A-Za-z0-9]{1,123}", owner)):
                    _reject()
            elif owner is not None:
                _reject()
            for app_id, view in applications.items():
                if (not isinstance(app_id, str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", app_id)
                        or not isinstance(view, dict)
                        or not {"id", "provider", "connection_kind"} <= set(view)
                        or set(view) - (_COMMON_VIEW | _VIEW_FIELDS[provider])
                        or view["id"] != connection_id or view["provider"] != provider):
                    _reject()
                if mail and view.get("owner_user_id") != owner:
                    _reject()
                if "clerk_org_id" in view and view["clerk_org_id"] != organization_id:
                    _reject()
                _safe_json(view)
    return value


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def bounded_json_request(
    client: httpx.Client, method: str, path: str, secret_key: str,
    *, payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Only caller-built Clerk organization paths; no redirects or implicit retries."""
    if not re.fullmatch(r"/organizations/org_[A-Za-z0-9]{1,124}(?:/metadata)?", path):
        _reject()
    try:
        deadline = time.monotonic() + 8.0
        with client.stream(
            method, "https://api.clerk.com/v1" + path,
            headers={"Authorization": "Bearer " + secret_key, "Accept": "application/json",
                     "Accept-Encoding": "identity"}, json=payload,
            timeout=httpx.Timeout(5.0, connect=3.0), follow_redirects=False,
        ) as response:
            if (response.status_code != 200
                    or response.headers.get("content-type", "").split(";")[0] != "application/json"
                    or response.headers.get("content-encoding", "identity") != "identity"):
                _reject()
            raw = bytearray()
            for chunk in response.iter_bytes():
                if time.monotonic() > deadline or len(raw) + len(chunk) > MAX_RESPONSE_BYTES:
                    _reject()
                raw.extend(chunk)
        value = json.loads(raw, object_pairs_hook=_object, parse_constant=lambda _: _reject())
        if not isinstance(value, dict):
            _reject()
        return value
    except ConnectionSettingsUnavailable:
        raise
    except (httpx.HTTPError, ValueError, TypeError, RecursionError):
        raise ConnectionSettingsUnavailable() from None


def views_for_organization(
    organization: dict[str, Any], *, organization_id: str, environment: str, app_id: str,
    providers: Collection[str] | None = None, owner_user_id: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Shared pure validation for synchronous and asynchronous backend transports."""
    if (not isinstance(organization, dict) or organization.get("id") != organization_id
            or not isinstance(app_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", app_id)
            or providers is not None and (isinstance(providers, str)
                                          or not set(providers) <= PROVIDERS)):
        _reject()
    if owner_user_id is not None and (
        not isinstance(owner_user_id, str)
        or not re.fullmatch(r"user_[A-Za-z0-9]{1,123}", owner_user_id)
    ):
        _reject()
    metadata = organization.get("private_metadata")
    if not isinstance(metadata, dict):
        _reject()
    document = validate_document(
        metadata.get(NAMESPACE), organization_id=organization_id,
        environment=environment, now=now,
    )
    selected = PROVIDERS if providers is None else frozenset(providers)
    items: list[dict[str, Any]] = []
    for provider, records in document["sources"].items():
        if provider not in selected:
            continue
        for record in records:
            if provider in {"gmail", "outlook"} and record["owner_user_id"] != owner_user_id:
                continue
            view = record["applications"].get(app_id)
            if view is not None:
                items.append(copy.deepcopy(view))
    return {"items": items}


class ClerkConnectionSettingsReader:
    """Use only after product membership/org/app checks, never in a public client."""

    def __init__(
        self, secret_key: str, environment: str, app_id: str, *,
        client: httpx.Client | None = None, now: Callable[[], datetime] | None = None,
    ):
        prefix = {"production": "sk_live_", "development": "sk_test_"}.get(environment)
        if (prefix is None or not isinstance(secret_key, str) or not secret_key.startswith(prefix)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", app_id)):
            raise ValueError("Clerk connection settings configuration invalid")
        self._secret_key, self.environment, self.app_id = secret_key, environment, app_id
        self._client, self._now = client, now or (lambda: datetime.now(UTC))

    def list_connections(
        self, organization_id: str, providers: Collection[str] | None = None, *,
        owner_user_id: str | None = None,
    ) -> dict[str, Any]:
        if (not isinstance(organization_id, str)
                or not re.fullmatch(r"org_[A-Za-z0-9]{1,124}", organization_id)
                or providers is not None and (isinstance(providers, str)
                                              or not set(providers) <= PROVIDERS)):
            _reject()
        if owner_user_id is not None and (
            not isinstance(owner_user_id, str)
            or not re.fullmatch(r"user_[A-Za-z0-9]{1,123}", owner_user_id)
        ):
            _reject()
        path = "/organizations/" + organization_id
        if self._client is not None:
            organization = bounded_json_request(self._client, "GET", path, self._secret_key)
        else:
            with httpx.Client(trust_env=False, transport=httpx.HTTPTransport(retries=0)) as client:
                organization = bounded_json_request(client, "GET", path, self._secret_key)
        return views_for_organization(
            organization, organization_id=organization_id, environment=self.environment,
            app_id=self.app_id, providers=providers, owner_user_id=owner_user_id, now=self._now(),
        )
