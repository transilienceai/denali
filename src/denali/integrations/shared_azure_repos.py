"""Pinned Azure Repos reads through Platform; provider credentials stay there."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from denali.connections.azure_repos import (
    AZURE_REPOS_SCOPE_CONTENTS,
    AZURE_REPOS_SCOPE_METADATA,
    AZURE_REPOS_SCOPES,
    AzureReposConnectionValidator,
    _same_repository,
    valid_azure_devops_organization,
)
from denali.connectors.azure_repos_repository import AzureReposRepositoryCollector
from denali.integrations.shared_connections_client import SharedConnectionsClient

ROOT = "/internal/v1/connections/azure-repos"
CREDENTIAL_TYPE = "platform_shared_azure_repos"
MAX_BLOB_BYTES = 2_000_000
MAX_CHUNK_BYTES = 750_000
_OBJECT_ID = re.compile(r"^[0-9a-fA-F]{40}$")


def shared_azure_repos_enabled() -> bool:
    return os.environ.get("DENALI_PLATFORM_AZURE_REPOS_ENABLED", "false").lower() == "true"


def normalize_repositories(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise ValueError("invalid shared Azure Repos repository list")
    if not 1 <= len(payload["items"]) <= 500:
        raise ValueError("shared Azure Repos repository count is out of bounds")
    result = []
    for item in payload["items"]:
        if not isinstance(item, dict):
            raise ValueError("invalid shared Azure Repos repository")
        repository_id = str(UUID(item.get("id", "")))
        project_id = str(UUID(item.get("project_id", "")))
        if item["id"] != repository_id or item["project_id"] != project_id:
            raise ValueError("noncanonical shared repository identity")
        for field in ("name", "project_name"):
            value = item.get(field)
            if (
                not isinstance(value, str)
                or not 1 <= len(value) <= 256
                or any(ord(char) < 32 for char in value)
                or "/" in value
                or "\\" in value
            ):
                raise ValueError("invalid shared repository name")
        if item.get("full_name") != f"{item['project_name']}/{item['name']}":
            raise ValueError("inconsistent shared repository name")
        branch = item.get("default_branch")
        if branch is not None and (not isinstance(branch, str) or len(branch) > 512):
            raise ValueError("invalid shared repository branch")
        result.append(
            {
                key: item.get(key)
                for key in (
                    "id",
                    "project_id",
                    "name",
                    "project_name",
                    "full_name",
                    "default_branch",
                )
            }
        )
    if len({item["id"] for item in result}) != len(result):
        raise ValueError("duplicate shared repository identity")
    return sorted(result, key=lambda item: item["id"])


def shared_azure_repos_binding_id(
    org: str, platform_id: str, repository_ids: list[str], scopes: list[str]
) -> str:
    if not isinstance(org, str) or not re.fullmatch(r"org_[A-Za-z0-9]+", org):
        raise ValueError("invalid shared Azure Repos organization")
    normalized = [str(UUID(value)) for value in repository_ids]
    if not 1 <= len(normalized) <= 500 or len(set(normalized)) != len(normalized):
        raise ValueError("invalid shared Azure Repos selection")
    if (
        not scopes
        or len(set(scopes)) != len(scopes)
        or not set(scopes) <= set(AZURE_REPOS_SCOPES)
        or AZURE_REPOS_SCOPE_METADATA not in scopes
    ):
        raise ValueError("invalid shared Azure Repos scopes")
    boundary = json.dumps([org, str(UUID(platform_id)), sorted(normalized), sorted(scopes)])
    return str(
        uuid5(NAMESPACE_URL, f"https://denali.transilience.cloud/shared-azure-repos/v1/{boundary}")
    )


@dataclass(frozen=True)
class _Response:
    payload: dict[str, Any] | None = None
    content: bytes = b""
    status_code: int = 200

    @property
    def headers(self) -> dict[str, str]:
        return {}

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self.payload or {}


class SharedAzureReposClient:
    """Translate the existing collector's reads to a closed, exact-repository API."""

    def __init__(self, platform: SharedConnectionsClient, connection: dict[str, Any]):
        if not shared_azure_repos_enabled():
            raise ValueError("shared Azure Repos is disabled")
        reference = connection.get("credential_reference") or {}
        configuration = connection.get("configuration") or {}
        self._org = connection.get("clerk_organization_id")
        self._platform_id = str(UUID(str(reference.get("platform_connection_id"))))
        self._tenant = str(UUID(str(configuration.get("tenant_id"))))
        self._organization = configuration.get("organization")
        self._scopes = connection.get("declared_scopes") or []
        self._repositories = normalize_repositories({"items": configuration.get("repositories")})
        expected_id = shared_azure_repos_binding_id(
            self._org, self._platform_id, [row["id"] for row in self._repositories], self._scopes
        )
        if (
            connection.get("provider") != "azure_repos"
            or connection.get("credential_type") != CREDENTIAL_TYPE
            or connection.get("lifecycle_state") != "active"
            or reference.get("platform_connection_id") != self._platform_id
            or str(connection.get("id")) != expected_id
            or not isinstance(self._organization, str)
            or not valid_azure_devops_organization(self._organization)
            or not platform.allows_org(self._org)
        ):
            raise ValueError("invalid shared Azure Repos binding")
        self._platform = platform
        # The existing native interfaces pass a string between calls. This is a
        # process-local handle, never a provider token, credential or lease.
        self._handle = f"shared-azure-repos:{uuid4()}"

    def application_token(self, tenant_id: str) -> str:
        if tenant_id != self._tenant:
            raise ValueError("shared Azure Repos tenant does not match")
        return self._handle

    def list_repositories(self, *, organization: str, token: str) -> list[dict[str, Any]]:
        self._check(organization, token)
        payload = self._read("repositories", repository_ids=[r["id"] for r in self._repositories])
        repositories = normalize_repositories(payload)
        current = {row["id"]: row for row in repositories}
        if set(current) != {row["id"] for row in self._repositories} or any(
            not _same_repository(saved, current[saved["id"]]) for saved in self._repositories
        ):
            raise ValueError("shared Azure Repos repository identity changed")
        pinned = {row["id"]: row for row in self._repositories}
        # Native collection uses this link in evidence. Derive it only after the
        # immutable identity check; never trust or persist a provider-supplied URL.
        return [
            {
                **row,
                "remote_url": (
                    f"https://dev.azure.com/{quote(self._organization, safe='')}/"
                    f"{quote(pinned[row['id']]['project_name'], safe='')}/_git/"
                    f"{quote(pinned[row['id']]['name'], safe='')}"
                ),
            }
            for row in repositories
        ]

    def _check(self, organization: str, token: str) -> None:
        if organization != self._organization or token != self._handle:
            raise ValueError("shared Azure Repos request does not match its binding")

    def _read(self, operation: str, **selection: Any) -> dict[str, Any]:
        scope = (
            AZURE_REPOS_SCOPE_METADATA
            if operation == "repositories"
            else AZURE_REPOS_SCOPE_CONTENTS
        )
        if scope not in self._scopes:
            raise ValueError("shared Azure Repos read is outside declared scopes")
        if operation != "repositories":
            repository = next(
                row for row in self._repositories if row["id"] == selection["repository_id"]
            )
            selection["expected_repository"] = {
                key: repository[key]
                for key in ("id", "project_id", "name", "project_name", "full_name")
            }
        payload = self._platform.request(
            "POST",
            f"{ROOT}/{self._platform_id}/read",
            clerk_org_id=self._org,
            payload={"operation": operation, **selection},
            max_response_bytes=2_097_152,
        )
        if not isinstance(payload, dict):
            raise ValueError("invalid shared Azure Repos response")
        return payload

    def request(
        self, method: str, *, organization: str, path: str, token: str, **kwargs: Any
    ) -> _Response:
        self._check(organization, token)
        if method != "GET" or set(kwargs) - {"params", "accept", "timeout"}:
            raise ValueError("unsupported shared Azure Repos request")
        match = re.fullmatch(
            r"/_apis/git/repositories/([a-f0-9-]{36})/(refs|items|blobs/([a-fA-F0-9]{40}))", path
        )
        if not match or match[1] not in {row["id"] for row in self._repositories}:
            raise ValueError("shared Azure Repos repository read is outside its boundary")
        repository_id = match[1]
        params = kwargs.get("params") or {}
        if not isinstance(params, dict):
            raise ValueError("invalid shared Azure Repos selection")
        if match[2] == "refs":
            if set(params) != {"filter"} or not isinstance(params["filter"], str):
                raise ValueError("invalid shared Azure Repos ref selection")
            ref = params["filter"]
            if (
                not 1 <= len(ref) <= 512
                or not ref.startswith("heads/")
                or any(ord(c) < 32 for c in ref)
            ):
                raise ValueError("invalid shared Azure Repos ref")
            return _Response(self._read("refs", repository_id=repository_id, ref=ref))
        if match[2] == "items":
            if (
                set(params)
                != {
                    "recursionLevel",
                    "includeContentMetadata",
                    "versionDescriptor.version",
                    "versionDescriptor.versionType",
                }
                or params["recursionLevel"] != "Full"
                or params["includeContentMetadata"] != "true"
                or params["versionDescriptor.versionType"] != "commit"
                or not isinstance(params["versionDescriptor.version"], str)
                or not _OBJECT_ID.fullmatch(params["versionDescriptor.version"])
            ):
                raise ValueError("shared Azure Repos tree requires an immutable revision")
            return _Response(
                self._read(
                    "tree", repository_id=repository_id, commit=params["versionDescriptor.version"]
                )
            )
        object_id = match[3].lower()
        if not params and kwargs.get("accept", "application/json") == "application/json":
            return _Response(
                self._read("blob_metadata", repository_id=repository_id, object_id=object_id)
            )
        if (
            params != {"$format": "octetStream", "download": "true"}
            or kwargs.get("accept") != "application/octet-stream"
        ):
            raise ValueError("invalid shared Azure Repos blob selection")
        content = bytearray()
        total = None
        while True:
            payload = self._read(
                "blob_chunk", repository_id=repository_id, object_id=object_id, offset=len(content)
            )
            size, next_offset = payload.get("total_bytes"), payload.get("next_offset")
            if (
                type(size) is not int
                or not 0 <= size <= MAX_BLOB_BYTES
                or (total is not None and total != size)
            ):
                raise ValueError("invalid shared Azure Repos blob size")
            total = size
            encoded = payload.get("content_base64")
            if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_CHUNK_BYTES + 2) // 3):
                raise ValueError("invalid shared Azure Repos blob chunk")
            chunk = base64.b64decode(encoded, validate=True)
            if len(chunk) > MAX_CHUNK_BYTES or len(content) + len(chunk) > size:
                raise ValueError("shared Azure Repos blob exceeds its bound")
            content.extend(chunk)
            if len(content) == size:
                if next_offset is not None:
                    raise ValueError("unexpected shared Azure Repos continuation")
                break
            if not chunk or type(next_offset) is not int or next_offset != len(content):
                raise ValueError("incomplete shared Azure Repos blob")
        digest = hashlib.sha1(
            f"blob {len(content)}\0".encode() + content, usedforsecurity=False
        ).hexdigest()
        if digest != object_id:
            raise ValueError("shared Azure Repos blob identity changed")
        return _Response(content=bytes(content))


class AzureReposValidatorRouter:
    def __init__(self, native: Any, platform: SharedConnectionsClient | None):
        self._native, self._platform = native, platform

    def validate(self, connection: dict[str, Any]) -> dict[str, Any]:
        if connection.get("credential_type") == CREDENTIAL_TYPE:
            if self._platform is None:
                raise ValueError("shared Azure Repos broker is unavailable")
            return AzureReposConnectionValidator(
                SharedAzureReposClient(self._platform, connection)
            ).validate(connection)
        if self._native is None:
            raise ValueError("native Azure Repos is unavailable")
        return self._native.validate(connection)


class AzureReposCollectorRouter:
    def __init__(self, native: Any, platform: SharedConnectionsClient | None):
        self._native, self._platform = native, platform

    def collect(
        self, *, tenant_id: str, connection: dict[str, Any], repository: Any
    ) -> dict[str, Any]:
        if connection.get("credential_type") == CREDENTIAL_TYPE:
            if self._platform is None:
                raise ValueError("shared Azure Repos broker is unavailable")
            return AzureReposRepositoryCollector(
                SharedAzureReposClient(self._platform, connection)
            ).collect(
                tenant_id=tenant_id,
                connection=connection,
                repository=repository,
            )
        if self._native is None:
            raise ValueError("native Azure Repos is unavailable")
        return self._native.collect(
            tenant_id=tenant_id, connection=connection, repository=repository
        )
