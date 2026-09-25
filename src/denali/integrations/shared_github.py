"""Denali's server-only adapter for platform-owned GitHub installations."""

from __future__ import annotations

from typing import Any

import httpx

from denali.connections.github import (
    GITHUB_API_BASE,
    GITHUB_API_VERSION,
    GITHUB_REQUIRED_PERMISSIONS,
    GitHubConnectionValidator,
    _repository_boundary,
)
from denali.connectors.github_repository import GitHubRepositoryCollector
from denali.integrations.shared_connections_client import SharedConnectionsClient


def normalize_shared_repositories(payload: Any, *, expected_count: int) -> list[dict[str, Any]]:
    """Reject incomplete or mutable repository identities at the Denali boundary."""

    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError("shared GitHub repository list is invalid")
    items = payload["items"]
    if not 1 <= len(items) <= 500 or len(items) != expected_count:
        raise ValueError("shared GitHub repository count changed")
    repositories: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("shared GitHub repository is invalid")
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


class SharedGitHubAppClient:
    """Supply the existing read-only GitHub flow with brokered installation tokens."""

    def __init__(self, platform: SharedConnectionsClient, connection: dict[str, Any]):
        reference = connection.get("credential_reference") or {}
        organization_id = connection.get("clerk_organization_id")
        if (
            connection.get("credential_type") != "platform_shared_github"
            or not isinstance(organization_id, str)
            or not organization_id.startswith("org_")
            or reference.get("platform_connection_id") != str(connection.get("id"))
        ):
            raise ValueError("shared GitHub connection boundary is invalid")
        self._platform = platform
        self._connection = connection
        self._organization_id = organization_id
        self._connection_id = str(connection["id"])

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
        repositories = configuration.get("repositories") or []
        if not repositories:
            raise RuntimeError("shared GitHub repository boundary is empty")
        # The broker rechecks GitHub's *current* installation before every token.
        # A listed but uninstalled/suspended App must fail credential validation.
        self.create_installation_token(
            installation_id=installation_id, repository_id=repositories[0]["id"]
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
            or leased.get("repository_ids") != [repository_id]
        ):
            raise RuntimeError("shared GitHub broker returned an invalid lease")
        return leased["token"]

    def installation_request(
        self, method: str, path: str, *, token: str, **kwargs: Any
    ) -> httpx.Response:
        if not path.startswith("/") or path.startswith("//") or method != "GET":
            raise ValueError("unexpected GitHub read")
        return httpx.request(
            method,
            f"{GITHUB_API_BASE}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
            },
            timeout=kwargs.pop("timeout", 10.0),
            **kwargs,
        )


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
