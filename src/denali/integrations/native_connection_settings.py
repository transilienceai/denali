"""Clerk lookup of enrolled native Denali identifiers, never provider credentials.

The native namespace is Denali-owned and cannot be mistaken for a Platform
shared connection. PostgreSQL still fences identity, scope, lifecycle and jobs.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import re
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import httpx

from denali.integrations.clerk_connection_settings import (
    MAX_METADATA_BYTES,
    _safe_json,
    _timestamp,
    bounded_json_request,
)

NATIVE_NAMESPACE = "transilience_native_connections"
NATIVE_SNAPSHOT_TTL_SECONDS = 300
NATIVE_PILOT_CONNECTION_COUNT = 6
NATIVE_CREDENTIAL_TYPES = {
    "aws": "aws_assume_role",
    "gcp": "gcp_service_account",
    "azure": "azure_multitenant_app",
    "entra": "entra_multitenant_app",
    "github": "github_app_installation",
    "google_workspace": "google_workspace_domain_wide_delegation",
    "azure_repos": "azure_repos_service_principal",
}
REFERENCE_FIELDS = {
    "aws": ("role_arn", "external_id"),
    "gcp": ("principal_email", "principal_unique_id"),
    "azure": ("client_id", "service_principal_id"),
    "entra": ("client_id",),
    "github": ("app_id", "installation_id"),
    "google_workspace": ("service_account", "oauth_client_id"),
    "azure_repos": ("client_id",),
}
CONFIGURATION_FIELDS = {
    "aws": ("account_id", "partition", "deployment_region", "coverage_mode", "regions",
            "role_name", "selected_resource"),
    "gcp": (),
    "azure": ("tenant_id",),
    "entra": ("tenant_id",),
    "github": ("account_id",),
    "google_workspace": ("domain", "admin_email"),
    "azure_repos": ("tenant_id", "organization"),
}
NESTED_IDENTIFIER_FIELDS = {
    "gcp": ("projects", "project_ids"),
    "azure": ("subscriptions", "subscription_ids"),
    "github": ("repositories", "repository_ids"),
    "azure_repos": ("repositories", "repository_ids"),
}
REQUIRED_SETTINGS = {
    "aws": {"role_arn", "external_id", "account_id"},
    "gcp": {"principal_email", "project_ids"},
    "azure": {"client_id", "tenant_id", "subscription_ids"},
    "entra": {"client_id", "tenant_id"},
    "github": {"app_id", "installation_id", "account_id", "repository_ids"},
    "google_workspace": {"service_account", "oauth_client_id", "domain", "admin_email"},
    "azure_repos": {"client_id", "tenant_id", "organization", "repository_ids"},
}
_ORG = re.compile(r"org_[A-Za-z0-9]{1,124}")
_ROOT_FIELDS = {
    "version", "source_app_id", "environment", "organization_id", "revision",
    "published_at", "expires_at", "sources",
}


class NativeConnectionSettingsUnavailable(RuntimeError):
    """A fixed public/worker failure, containing no private connection fields."""

    def __init__(self) -> None:
        super().__init__("native connection settings unavailable")


class NativeResolvedTarget(dict[str, Any]):
    """Internal provenance is an attribute, never an API/SDK dictionary field."""

    __slots__ = ()

    @property
    def native_connection_settings_source(self) -> str:
        return "clerk"


def _reject() -> None:
    raise NativeConnectionSettingsUnavailable()


def _uuid(value: Any) -> str:
    try:
        if not isinstance(value, (str, UUID)):
            _reject()
        normalized = str(UUID(str(value)))
        if normalized != str(value) or UUID(normalized).int == 0:
            _reject()
        return normalized
    except (ValueError, TypeError, AttributeError):
        raise NativeConnectionSettingsUnavailable() from None


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise NativeConnectionSettingsUnavailable() from None


def _safe(value: Any) -> None:
    try:
        _safe_json(value)
    except Exception:
        raise NativeConnectionSettingsUnavailable() from None


def _native_provider(target: Mapping[str, Any]) -> str:
    provider = target.get("provider")
    if (provider not in NATIVE_CREDENTIAL_TYPES
            or target.get("credential_type") != NATIVE_CREDENTIAL_TYPES[provider]):
        _reject()
    return str(provider)


def _settings_fields(provider: str) -> set[str]:
    fields = set(REFERENCE_FIELDS[provider]) | set(CONFIGURATION_FIELDS[provider])
    if provider in NESTED_IDENTIFIER_FIELDS:
        fields.add(NESTED_IDENTIFIER_FIELDS[provider][1])
    return fields


def _validate_identifiers(provider: str, settings: Mapping[str, Any]) -> None:
    if not REQUIRED_SETTINGS[provider] <= set(settings):
        _reject()
    for key in REQUIRED_SETTINGS[provider]:
        value = settings[key]
        if key.endswith("_ids"):
            if not isinstance(value, list) or not value:
                _reject()
            if any(type(item) not in {str, int} or not item for item in value):
                _reject()
        elif provider == "github" and key in {"app_id", "installation_id", "account_id"}:
            if type(value) is not int or value < 1:
                _reject()
        elif not isinstance(value, str) or not value.strip():
            _reject()


def project_native_settings(target: Mapping[str, Any]) -> dict[str, Any]:
    """Canonical stable identifier projection shared by publisher and consumer.

    In particular, GCP operator profiles/federation, onboarding state, setup hashes,
    PKCE and all provider/private-key/token material remain outside this projection.
    """
    provider = _native_provider(target)
    reference, configuration = target.get("credential_reference"), target.get("configuration")
    if not isinstance(reference, dict) or not isinstance(configuration, dict):
        _reject()
    result = {
        key: copy.deepcopy(reference[key]) for key in REFERENCE_FIELDS[provider] if key in reference
    }
    result.update({
        key: copy.deepcopy(configuration[key])
        for key in CONFIGURATION_FIELDS[provider] if key in configuration
    })
    if provider == "aws" and "selected_resource" in result:
        selected = result["selected_resource"]
        if (not isinstance(selected, dict) or set(selected) != {
            "kind", "function_arn", "execution_role_arn", "expected_model_id",
        }):
            _reject()
    nested = NESTED_IDENTIFIER_FIELDS.get(provider)
    if nested and nested[0] in configuration:
        records = configuration[nested[0]]
        if not isinstance(records, list) or len(records) > 500:
            _reject()
        identifiers = []
        for record in records:
            if not isinstance(record, dict) or "id" not in record:
                _reject()
            identifier = record["id"]
            if (type(identifier) not in {str, int} or isinstance(identifier, str)
                    and not identifier or type(identifier) is int and identifier < 1):
                _reject()
            identifiers.append(copy.deepcopy(identifier))
        if len(set(identifiers)) != len(identifiers):
            _reject()
        result[nested[1]] = identifiers
    _safe(result)
    _validate_identifiers(provider, result)
    return result


def native_binding_sha256(tenant_id: str, target: Mapping[str, Any]) -> str:
    """Fence the snapshot to current database identity/scopes, never trust its hash alone."""
    organization_id = target.get("clerk_organization_id")
    if not isinstance(organization_id, str) or not _ORG.fullmatch(organization_id):
        _reject()
    scopes = target.get("declared_scopes")
    if (not isinstance(scopes, list) or any(not isinstance(scope, str) for scope in scopes)
            or len(scopes) > 100 or len(set(scopes)) != len(scopes)):
        _reject()
    value = {
        "version": 1, "source_app_id": "denali", "organization_id": organization_id,
        "tenant_id": _uuid(tenant_id), "id": _uuid(target.get("id")),
        "provider": _native_provider(target), "credential_type": target["credential_type"],
        "declared_scopes": scopes, "settings": project_native_settings(target),
    }
    _safe(value)
    return hashlib.sha256(_canonical(value)).hexdigest()


def build_native_snapshot(
    tenant_id: str, organization_id: str, targets: list[Mapping[str, Any]], environment: str, *,
    now: datetime | None = None, revision: str | None = None,
) -> dict[str, Any]:
    """Build identifiers only. Does not read Clerk, write metadata, or invoke providers."""
    if (environment not in {"production", "development"}
            or not isinstance(organization_id, str) or not _ORG.fullmatch(organization_id)
            or not 1 <= len(targets) <= 100):
        _reject()
    _uuid(tenant_id)
    clock = now or datetime.now(UTC)
    if clock.tzinfo is None or clock.utcoffset() != timedelta(0):
        _reject()
    sources: dict[str, list[dict[str, Any]]] = {}
    ordered = sorted(targets, key=lambda item: (str(item.get("provider")), str(item.get("id"))))
    for target in ordered:
        if target.get("clerk_organization_id") != organization_id:
            _reject()
        if target.get("tenant_id") is not None and _uuid(target["tenant_id"]) != tenant_id:
            _reject()
        provider = _native_provider(target)
        sources.setdefault(provider, []).append({
            "id": _uuid(target.get("id")),
            "binding_sha256": native_binding_sha256(tenant_id, target),
            "settings": project_native_settings(target),
        })
    result = {
        "version": 1, "source_app_id": "denali", "environment": environment,
        "organization_id": organization_id, "revision": _uuid(revision or str(uuid4())),
        "published_at": clock.isoformat(),
        "expires_at": (clock + timedelta(seconds=NATIVE_SNAPSHOT_TTL_SECONDS)).isoformat(),
        "sources": sources,
    }
    return validate_native_snapshot(result, organization_id, environment, now=clock)


def validate_native_snapshot(
    value: Any, organization_id: str, environment: str, *, now: datetime | None = None,
) -> dict[str, Any]:
    if (not isinstance(value, dict) or set(value) != _ROOT_FIELDS
            or type(value.get("version")) is not int or value["version"] != 1
            or value.get("source_app_id") != "denali"
            or environment not in {"production", "development"}
            or value.get("environment") != environment
            or value.get("organization_id") != organization_id
            or not isinstance(organization_id, str) or not _ORG.fullmatch(organization_id)
            or len(_canonical(value)) > MAX_METADATA_BYTES):
        _reject()
    _uuid(value.get("revision"))
    try:
        published, expiry = _timestamp(value["published_at"]), _timestamp(value["expires_at"])
    except Exception:
        raise NativeConnectionSettingsUnavailable() from None
    clock = now or datetime.now(UTC)
    if (clock.tzinfo is None or not published <= clock < expiry
            or not 0 < (expiry - published).total_seconds() <= NATIVE_SNAPSHOT_TTL_SECONDS):
        _reject()
    sources, seen = value["sources"], set()
    if not isinstance(sources, dict) or not set(sources) <= set(NATIVE_CREDENTIAL_TYPES):
        _reject()
    for provider, records in sources.items():
        if not isinstance(records, list) or len(records) > 100:
            _reject()
        for record in records:
            if not isinstance(record, dict) or set(record) != {"id", "binding_sha256", "settings"}:
                _reject()
            identifier = _uuid(record["id"])
            if (identifier in seen or not isinstance(record["binding_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", record["binding_sha256"])
                    or not isinstance(record["settings"], dict)
                    or not set(record["settings"]) <= _settings_fields(provider)):
                _reject()
            seen.add(identifier)
            _safe(record["settings"])
            _validate_identifiers(provider, record["settings"])
    if len(seen) > 100:
        _reject()
    return value


def _overlay(target: Mapping[str, Any], settings: Mapping[str, Any]) -> dict[str, Any]:
    provider = _native_provider(target)
    result = copy.deepcopy(dict(target))
    for key in REFERENCE_FIELDS[provider]:
        if key in settings:
            result["credential_reference"][key] = copy.deepcopy(settings[key])
    for key in CONFIGURATION_FIELDS[provider]:
        if key in settings:
            result["configuration"][key] = copy.deepcopy(settings[key])
    nested = NESTED_IDENTIFIER_FIELDS.get(provider)
    if nested and nested[1] in settings:
        existing = result["configuration"][nested[0]]
        result["configuration"][nested[0]] = [
            {**record, "id": copy.deepcopy(identifier)}
            for record, identifier in zip(existing, settings[nested[1]], strict=True)
        ]
    return result


class NativeConnectionSettingsReader:
    def __init__(
        self, secret_key: str, environment: str, *, client: httpx.Client | None = None,
        now: Callable[[], datetime] | None = None,
    ):
        prefix = {"production": "sk_live_", "development": "sk_test_"}.get(environment)
        if (prefix is None or not isinstance(secret_key, str) or not secret_key.startswith(prefix)
                or len(secret_key) <= len(prefix)):
            _reject()
        self._secret_key, self.environment = secret_key, environment
        self._client, self._now = client, now or (lambda: datetime.now(UTC))

    def resolve(self, tenant_id: str, target: Mapping[str, Any]) -> dict[str, Any]:
        organization_id = target.get("clerk_organization_id")
        if not isinstance(organization_id, str) or not _ORG.fullmatch(organization_id):
            _reject()
        try:
            if self._client is not None:
                organization = bounded_json_request(
                    self._client, "GET", "/organizations/" + organization_id, self._secret_key,
                )
            else:
                with httpx.Client(
                    trust_env=False, transport=httpx.HTTPTransport(retries=0),
                ) as client:
                    organization = bounded_json_request(
                        client, "GET", "/organizations/" + organization_id, self._secret_key,
                    )
            if organization.get("id") != organization_id:
                _reject()
            private = organization.get("private_metadata")
            if not isinstance(private, dict):
                _reject()
            document = validate_native_snapshot(
                private.get(NATIVE_NAMESPACE), organization_id, self.environment, now=self._now(),
            )
            provider, identifier = _native_provider(target), _uuid(target.get("id"))
            matches = [record for record in document["sources"].get(provider, [])
                       if record["id"] == identifier]
            if len(matches) != 1:
                _reject()
            record = matches[0]
            if (not hmac.compare_digest(record["binding_sha256"],
                                        native_binding_sha256(tenant_id, target))
                    or record["settings"] != project_native_settings(target)):
                _reject()
            return NativeResolvedTarget(_overlay(target, record["settings"]))
        except NativeConnectionSettingsUnavailable:
            raise
        except Exception:
            raise NativeConnectionSettingsUnavailable() from None


def enrolled_native_settings(
    environ: Mapping[str, str],
) -> tuple[frozenset[str], frozenset[str]]:
    def values(name: str) -> list[str]:
        result = [item.strip() for item in environ.get(name, "").split(",") if item.strip()]
        if len(set(result)) != len(result):
            _reject()
        return result

    organizations = values("DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS")
    connections = values("DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CONNECTION_IDS")
    if (len(organizations) != 1 or not _ORG.fullmatch(organizations[0])
            or len(connections) != NATIVE_PILOT_CONNECTION_COUNT):
        _reject()
    return frozenset(organizations), frozenset(_uuid(value) for value in connections)


def native_environment(environ: Mapping[str, str]) -> str:
    environment = environ.get("DENALI_NATIVE_CONNECTION_SETTINGS_ENVIRONMENT", "")
    expected = {"denali-prod": "production", "denali-dev": "development"}.get(
        environ.get("MODAL_ENVIRONMENT", "")
    )
    if (environment not in {"production", "development"}
            or expected is not None and environment != expected):
        _reject()
    return environment


def native_backend_key(environ: Mapping[str, str], environment: str) -> str:
    # This explicit alias remains inside Denali, never copied to another service.
    key = (environ.get("DENALI_NATIVE_CONNECTION_SETTINGS_SECRET_KEY")
           or environ.get("CLERK_SECRET_KEY", ""))
    prefix = "sk_live_" if environment == "production" else "sk_test_"
    if not key.startswith(prefix) or len(key) <= len(prefix):
        _reject()
    return key


def resolve_native_connection_settings(
    tenant_id: str, target: dict[str, Any], *, environ: Mapping[str, str] | None = None,
    reader_factory: Callable[..., NativeConnectionSettingsReader] | None = None,
) -> dict[str, Any]:
    """Run only after the tenant-scoped DB read has closed its connection/context."""
    env = os.environ if environ is None else environ
    source = env.get("DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE", "database")
    if source == "database":
        return target
    configured_orgs = {item.strip() for item in env.get(
        "DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS", "",
    ).split(",") if item.strip()}
    if target.get("clerk_organization_id") not in configured_orgs:
        # A selected organization's configuration failure cannot affect another org.
        return target
    if source != "clerk":
        _reject()
    organizations, connections = enrolled_native_settings(env)
    if (target.get("clerk_organization_id") not in organizations
            or str(target.get("id")) not in connections
            or str(target.get("credential_type", "")).startswith("platform_shared_")
            or target.get("lifecycle_state") != "active"):
        return target
    environment = native_environment(env)
    key = native_backend_key(env, environment)
    factory = reader_factory or NativeConnectionSettingsReader
    try:
        return factory(key, environment).resolve(tenant_id, target)
    except NativeConnectionSettingsUnavailable:
        raise
    except Exception:
        raise NativeConnectionSettingsUnavailable() from None
