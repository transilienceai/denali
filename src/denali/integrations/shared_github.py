"""Denali's server-only adapter for platform-owned GitHub installations."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote, urlsplit
from uuid import NAMESPACE_URL, UUID, uuid5

import httpx

from denali.connections.github import (
    GITHUB_API_BASE,
    GITHUB_API_VERSION,
    GITHUB_REQUIRED_PERMISSIONS,
    GITHUB_SCOPES,
    GitHubConnectionValidator,
    _repository_boundary,
)
from denali.connectors.github_repository import GitHubRepositoryCollector
from denali.integrations.shared_connections_client import SharedConnectionsClient


def shared_github_enabled() -> bool:
    return os.environ.get("DENALI_PLATFORM_GITHUB_ENABLED", "false").lower() == "true"


def safe_install_url(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError("shared GitHub installation URL is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.fragment
        or not re.fullmatch(r"/apps/[a-z0-9-]+/installations/new", parsed.path)
    ):
        raise ValueError("shared GitHub installation URL is invalid")
    return value


def normalize_shared_repositories(payload: Any, *, expected_count: int) -> list[dict[str, Any]]:
    """Reject incomplete or mutable repository identities at the Denali boundary."""

    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError("shared GitHub repository list is invalid")
    items = payload["items"]
    if (
        type(expected_count) is not int
        or not 1 <= len(items) <= 500
        or len(items) != expected_count
    ):
        raise ValueError("shared GitHub repository count changed")
    repositories: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("shared GitHub repository is invalid")
        if type(item.get("id")) is not int or type(item.get("owner_id")) is not int:
            raise ValueError("shared GitHub repository identity is invalid")
        repository = _repository_boundary(
            {
                **item,
                "owner": {"id": item.get("owner_id"), "login": item.get("owner_login")},
            }
        )
        if not isinstance(item.get("private"), bool) or not isinstance(item.get("archived"), bool):
            raise ValueError("shared GitHub repository flags are invalid")
        branch = item.get("default_branch")
        if branch is not None and (not isinstance(branch, str) or len(branch) > 255):
            raise ValueError("shared GitHub default branch is invalid")
        repositories.append(repository)
    if len({item["id"] for item in repositories}) != len(repositories):
        raise ValueError("shared GitHub repository IDs are duplicated")
    return sorted(repositories, key=lambda item: item["full_name"].lower())


def shared_github_binding_id(
    organization_id: str,
    platform_connection_id: str,
    repository_ids: list[int],
    scopes: list[str],
) -> str:
    """Derive a local binding from trusted org and a pinned, public boundary.

    The request cannot supply a local ID. Reordered selections are idempotent,
    while another selection/org/scope boundary receives an independent row.
    """

    if (
        not isinstance(organization_id, str)
        or not re.fullmatch(r"org_[A-Za-z0-9]+", organization_id)
        or not isinstance(repository_ids, list)
        or not 1 <= len(repository_ids) <= 500
        or any(type(value) is not int or value <= 0 for value in repository_ids)
        or len(set(repository_ids)) != len(repository_ids)
        or not isinstance(scopes, list)
        or not scopes
        or any(not isinstance(scope, str) for scope in scopes)
        or len(set(scopes)) != len(scopes)
        or not set(scopes) <= set(GITHUB_SCOPES)
    ):
        raise ValueError("shared GitHub binding boundary is invalid")
    try:
        platform_id = str(UUID(platform_connection_id))
    except (TypeError, ValueError, AttributeError) as error:
        raise ValueError("shared GitHub reference is invalid") from error
    boundary = json.dumps(
        [organization_id, platform_id, sorted(repository_ids), sorted(scopes)],
        separators=(",", ":"),
    )
    return str(
        uuid5(NAMESPACE_URL, f"https://denali.transilience.cloud/shared-github-bindings/v1/{boundary}")
    )


class SharedGitHubAppClient:
    """Supply the existing read-only GitHub flow with brokered installation tokens."""

    def __init__(self, platform: SharedConnectionsClient, connection: dict[str, Any]):
        if not shared_github_enabled():
            raise ValueError("shared GitHub is disabled")
        reference = connection.get("credential_reference") or {}
        organization_id = connection.get("clerk_organization_id")
        try:
            connection_id = str(UUID(str(connection.get("id"))))
            platform_connection_id = str(UUID(str(reference.get("platform_connection_id"))))
        except (TypeError, ValueError, AttributeError) as error:
            raise ValueError("shared GitHub reference is invalid") from error
        scopes = connection.get("declared_scopes")
        if (
            connection.get("credential_type") != "platform_shared_github"
            or connection.get("provider") != "github"
            or connection.get("lifecycle_state") != "active"
            or not isinstance(organization_id, str)
            or not re.fullmatch(r"org_[A-Za-z0-9]+", organization_id)
            or reference.get("platform_connection_id") != platform_connection_id
            or type(reference.get("installation_id")) is not int
            or reference["installation_id"] <= 0
            or not isinstance(scopes, list)
            or not scopes
            or any(not isinstance(scope, str) for scope in scopes)
            or len(set(scopes)) != len(scopes)
            or not set(scopes) <= set(GITHUB_SCOPES)
            or not platform.allows_org(organization_id)
        ):
            raise ValueError("shared GitHub connection boundary is invalid")
        configuration = connection.get("configuration") or {}
        selected = configuration.get("repositories")
        self._repositories = normalize_shared_repositories(
            {"items": selected}, expected_count=len(selected) if isinstance(selected, list) else 0
        )
        if (
            type(configuration.get("account_id")) is not int
            or configuration["account_id"] <= 0
            or any(
                repo["owner_id"] != configuration["account_id"]
                or repo["owner_login"].lower() != str(configuration.get("account_login")).lower()
                for repo in self._repositories
            )
        ):
            raise ValueError("shared GitHub account boundary is invalid")
        mode = configuration.get("coverage_mode")
        if mode == "exact-installation-repositories":
            expected_local_id = platform_connection_id
        elif mode == "exact-selected-repositories":
            expected_local_id = shared_github_binding_id(
                organization_id,
                platform_connection_id,
                [repo["id"] for repo in self._repositories],
                scopes,
            )
        else:
            raise ValueError("shared GitHub coverage boundary is invalid")
        if connection_id != expected_local_id:
            raise ValueError("shared GitHub local binding is invalid")
        self._platform = platform
        self._connection = connection
        self._organization_id = organization_id
        self._connection_id = platform_connection_id
        self._token_repositories: dict[str, dict[str, Any]] = {}
        self._verified_token_repositories: set[str] = set()

    def get_installation(self, installation_id: int) -> dict[str, Any]:
        reference = self._connection["credential_reference"]
        configuration = self._connection["configuration"]
        if installation_id != reference.get("installation_id"):
            raise RuntimeError("shared GitHub installation changed")
        listing = self._platform.request(
            "GET", "/v1/connections", clerk_org_id=self._organization_id
        )
        if not isinstance(listing, dict) or not isinstance(listing.get("items"), list):
            raise RuntimeError("shared GitHub listing is invalid")
        shared = next(
            (
                item
                for item in listing["items"]
                if isinstance(item, dict) and item.get("id") == self._connection_id
            ),
            None,
        )
        if (
            shared is None
            or shared.get("connection_kind") != "shared_github"
            or shared.get("availability") != "ready"
            or shared.get("installation_id") != installation_id
            or shared.get("account_id") != configuration.get("account_id")
            or str(shared.get("account_login", "")).lower()
            != str(configuration.get("account_login", "")).lower()
            or not set(self._connection["declared_scopes"])
            <= set(shared.get("validated_scopes") or [])
        ):
            raise RuntimeError("shared GitHub installation is unavailable or changed")
        observed = self._platform.request(
            "GET",
            f"/internal/v1/connections/github/{self._connection_id}/repositories",
            clerk_org_id=self._organization_id,
        )
        repositories = normalize_shared_repositories(
            observed, expected_count=shared.get("repository_count")
        )

        def identity(repo: dict[str, Any]) -> tuple[Any, ...]:
            return (
                repo["id"],
                repo["node_id"],
                repo["full_name"],
                repo["owner_id"],
                repo["owner_login"],
            )

        # Installation consent may add repositories, but an existing Denali row
        # never inherits them. All pinned identities must still exist unchanged.
        if not {identity(repo) for repo in self._repositories} <= {
            identity(repo) for repo in repositories
        }:
            raise RuntimeError("shared GitHub repository selection changed")
        # The broker rechecks GitHub's *current* installation before every token.
        # A listed but uninstalled/suspended App must fail credential validation.
        self.create_installation_token(
            installation_id=installation_id, repository_id=self._repositories[0]["id"]
        )
        return {
            "id": installation_id,
            "account_id": shared["account_id"],
            "account_login": shared["account_login"],
            "repository_selection": shared.get("repository_selection"),
            "permissions": GITHUB_REQUIRED_PERMISSIONS,
        }

    def create_installation_token(self, *, installation_id: int, repository_id: int) -> str:
        if installation_id != self._connection["credential_reference"].get("installation_id"):
            raise RuntimeError("shared GitHub installation changed")
        if repository_id not in {
            item["id"] for item in self._connection["configuration"].get("repositories", [])
        }:
            raise RuntimeError("repository is outside Denali's exact GitHub boundary")
        leased = self._platform.request(
            "POST",
            f"/internal/v1/connections/github/{self._connection_id}/token",
            clerk_org_id=self._organization_id,
            payload={
                "repository_ids": [repository_id],
                "scopes": self._connection["declared_scopes"],
            },
        )
        if (
            not isinstance(leased, dict)
            or not isinstance(leased.get("token"), str)
            or not leased["token"].startswith("ghs_")
            or len(leased["token"]) > 8192
            or leased.get("repository_ids") != [repository_id]
        ):
            raise RuntimeError("shared GitHub broker returned an invalid lease")
        try:
            expiry = datetime.fromisoformat(leased["expires_at"].replace("Z", "+00:00"))
            now = datetime.now(UTC)
            if expiry.tzinfo is None or not now < expiry <= now + timedelta(hours=2):
                raise ValueError("invalid expiry")
        except (KeyError, AttributeError, TypeError, ValueError) as error:
            raise RuntimeError("shared GitHub broker returned an invalid expiry") from error
        token_hash = hashlib.sha256(leased["token"].encode()).hexdigest()
        self._token_repositories[token_hash] = next(
            repo for repo in self._repositories if repo["id"] == repository_id
        )
        # Even a provider-reused token must reverify live metadata for this lease.
        self._verified_token_repositories.discard(token_hash)
        return leased["token"]

    def installation_request(
        self, method: str, path: str, *, token: str, **kwargs: Any
    ) -> httpx.Response:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        repo = self._token_repositories.get(token_hash)
        prefix = f"/repos/{repo['full_name']}" if repo else ""
        suffix = path[len(prefix) :] if prefix and path.startswith(prefix) else None
        decoded = unquote(path)
        allowed_suffix = suffix is not None and (
            suffix in {"", "/actions/workflows"}
            or (suffix.startswith("/git/ref/heads/") and len(suffix) > len("/git/ref/heads/"))
            or re.fullmatch(r"/git/(?:trees|blobs)/[a-f0-9]{40,64}", suffix)
        )
        if (
            method != "GET"
            or len(path) > 2048
            or not allowed_suffix
            or any(part in {".", ".."} for part in decoded.split("/"))
            or any(char in decoded for char in ("?", "#", "\\", "\r", "\n", "\x00"))
            or set(kwargs) - {"params", "timeout"}
        ):
            raise ValueError("unexpected GitHub read")
        if suffix != "" and token_hash not in self._verified_token_repositories:
            raise ValueError("shared GitHub live repository verification is required")
        timeout = kwargs.pop("timeout", 10.0)
        if not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise ValueError("unexpected GitHub timeout")
        if suffix == "":
            # A transport failure on recheck must not leave earlier proof usable.
            self._verified_token_repositories.discard(token_hash)
        response = httpx.request(
            method,
            f"{GITHUB_API_BASE}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
            timeout=timeout,
            follow_redirects=False,
            **kwargs,
        )
        if suffix == "":
            # Registry metadata can be stale after provider rename/transfer.
            # A fresh exact-ID lease is not itself proof of the saved live name.
            try:
                response.raise_for_status()
                observed = response.json()
                owner = observed.get("owner") if isinstance(observed, dict) else None
                if (
                    not isinstance(observed, dict)
                    or type(observed.get("id")) is not int
                    or observed["id"] != repo["id"]
                    or observed.get("node_id") != repo["node_id"]
                    or observed.get("full_name") != repo["full_name"]
                    or not isinstance(owner, dict)
                    or type(owner.get("id")) is not int
                    or owner["id"] != repo["owner_id"]
                    or owner.get("login") != repo["owner_login"]
                ):
                    raise ValueError("identity changed")
            except Exception:
                raise ValueError(
                    "shared GitHub live repository identity is unavailable or changed"
                ) from None
            self._verified_token_repositories.add(token_hash)
        return response


class GitHubValidatorRouter:
    def __init__(
        self,
        legacy: GitHubConnectionValidator | None,
        platform: SharedConnectionsClient | None,
    ):
        self._legacy = legacy
        self._platform = platform

    def validate(self, connection: dict[str, Any]) -> dict[str, Any]:
        if connection.get("credential_type") == "platform_shared_github":
            if self._platform is None:
                raise RuntimeError("shared GitHub broker is not configured")
            return GitHubConnectionValidator(
                SharedGitHubAppClient(self._platform, connection)
            ).validate(connection)
        if self._legacy is None:
            raise RuntimeError("Denali GitHub App is not configured")
        return self._legacy.validate(connection)


class GitHubCollectorRouter:
    def __init__(
        self,
        legacy: GitHubRepositoryCollector | None,
        platform: SharedConnectionsClient | None,
    ):
        self._legacy = legacy
        self._platform = platform

    def collect(
        self, *, tenant_id: str, connection: dict[str, Any], repository: Any
    ) -> dict[str, Any]:
        if connection.get("credential_type") == "platform_shared_github":
            if self._platform is None:
                raise RuntimeError("shared GitHub broker is not configured")
            return GitHubRepositoryCollector(
                SharedGitHubAppClient(self._platform, connection)
            ).collect(tenant_id=tenant_id, connection=connection, repository=repository)
        if self._legacy is None:
            raise RuntimeError("Denali GitHub App is not configured")
        return self._legacy.collect(
            tenant_id=tenant_id, connection=connection, repository=repository
        )
