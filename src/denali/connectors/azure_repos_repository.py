"""Bounded Azure Repos source collection at an immutable Git revision."""

from __future__ import annotations

import re
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Protocol
from urllib.parse import quote

from denali.connections.azure_repos import AzureReposClient
from denali.connectors.code_to_cloud import CodeToCloudConnector, DeploymentTarget
from denali.connectors.repository import RepositoryConnector
from denali.connectors.repository_posture import RepositoryPostureConnector
from denali.domain import (
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    Coverage,
    CoverageState,
    Evidence,
    FindingBatch,
    InventoryBatch,
)

CONNECTOR_ID = "denali.azure_repos_repository"
SOURCE_PLANE = "azure_repos_source_collection"
MAX_TREE_ENTRIES = 20_000
MAX_SELECTED_FILES = 2_000
MAX_BLOB_BYTES = 2_000_000
MAX_TOTAL_BYTES = 25_000_000
MAX_BLOB_FETCH_WORKERS = 8

_OBJECT_ID = re.compile(r"^[0-9a-fA-F]{40}$")
_SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".mts",
        ".cts",
        ".tf",
        ".bicep",
        ".json",
        ".yaml",
        ".yml",
    }
)
_EXCLUDED_PARTS = frozenset(
    {".git", ".hg", ".venv", "build", "dist", "fixtures", "node_modules", "test", "tests", "vendor"}
)


class InventorySink(Protocol):
    def ingest(self, tenant_id: str, batch: InventoryBatch) -> dict[str, int]: ...

    def deployment_targets(self, tenant_id: str) -> list[dict[str, Any]]: ...

    def ingest_findings(self, tenant_id: str, batch: FindingBatch) -> dict[str, int]: ...


class AzureReposSourceError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class AzureReposSnapshot:
    repository_id: str
    repository_name: str
    default_branch: str
    commit: str
    remote: str
    source_locator: str
    files: tuple[tuple[str, bytes], ...]
    warnings: tuple[str, ...] = ()

    @property
    def total_bytes(self) -> int:
        return sum(len(content) for _, content in self.files)


class AzureReposRepositoryCollector:
    """Collect exact selected Azure Repos without retaining tokens or source blobs."""

    def __init__(self, client: AzureReposClient):
        self._client = client

    def collect(
        self, *, tenant_id: str, connection: dict[str, Any], repository: InventorySink
    ) -> dict[str, Any]:
        configuration = connection.get("configuration", {})
        selected = configuration.get("repositories", [])
        if connection.get("provider") != "azure_repos":
            raise ValueError("connection is not an Azure Repos connection")
        if connection.get("lifecycle_state") != "active":
            raise ValueError("disabled Azure Repos connections cannot collect source")
        if not selected or not configuration.get("onboarding", {}).get("completed_at"):
            raise ValueError("complete Azure Repos repository selection before collecting source")

        organization = str(configuration.get("organization", ""))
        try:
            token = self._client.application_token(str(configuration.get("tenant_id", "")))
            observed = self._client.list_repositories(organization=organization, token=token)
            observed_by_id = {item["id"]: item for item in observed}
        except Exception:
            return self._failed_collection(
                tenant_id, connection, repository, "application_identity_validation_failed"
            )

        targets = tuple(
            DeploymentTarget.from_record(item) for item in repository.deployment_targets(tenant_id)
        )
        results: list[dict[str, Any]] = []
        for selected_repository in selected:
            try:
                current = observed_by_id.get(selected_repository.get("id"))
                if current is None or not _same_repository(selected_repository, current):
                    raise AzureReposSourceError("repository_identity_mismatch")
                snapshot = self._snapshot(
                    organization=organization,
                    repository=current,
                    token=token,
                )
                result = self._analyze_snapshot(
                    tenant_id=tenant_id,
                    connection_id=str(connection["id"]),
                    snapshot=snapshot,
                    targets=targets,
                    repository=repository,
                )
            except Exception as error:
                code = (
                    error.code
                    if isinstance(error, AzureReposSourceError)
                    else "source_collection_failed"
                )
                full_name = str(selected_repository.get("full_name", "unknown/unknown"))
                canonical = f"dev.azure.com/{organization}/{full_name}"
                repository.ingest(
                    tenant_id,
                    _source_batch(
                        connection_id=str(connection["id"]),
                        repository_name=canonical,
                        repository_id=selected_repository.get("id"),
                        project_id=selected_repository.get("project_id"),
                        organization=organization,
                        state=CoverageState.FAILED,
                        detail=code,
                    ),
                )
                result = {
                    "repository_id": selected_repository.get("id"),
                    "repository": full_name,
                    "state": "failed",
                    "detail": code,
                }
            results.append(result)
        failed = sum(item["state"] == "failed" for item in results)
        partial = sum(item["state"] == "partial" for item in results)
        return {
            "connection_id": str(connection["id"]),
            "state": "complete" if failed == 0 and partial == 0 else "partial",
            "completed_at": datetime.now(UTC).isoformat(),
            "repositories": results,
            "repository_count": len(results),
            "failed_count": failed,
            "partial_count": partial,
        }

    def _failed_collection(
        self,
        tenant_id: str,
        connection: dict[str, Any],
        repository: InventorySink,
        code: str,
    ) -> dict[str, Any]:
        organization = str(connection.get("configuration", {}).get("organization", "unknown"))
        results = []
        for item in connection.get("configuration", {}).get("repositories", []):
            repository.ingest(
                tenant_id,
                _source_batch(
                    connection_id=str(connection["id"]),
                    repository_name=(
                        f"dev.azure.com/{organization}/{item.get('full_name', 'unknown/unknown')}"
                    ),
                    repository_id=item.get("id"),
                    project_id=item.get("project_id"),
                    organization=organization,
                    state=CoverageState.FAILED,
                    detail=code,
                ),
            )
            results.append(
                {
                    "repository_id": item.get("id"),
                    "repository": item.get("full_name"),
                    "state": "failed",
                    "detail": code,
                }
            )
        return {
            "connection_id": str(connection["id"]),
            "state": "failed",
            "completed_at": datetime.now(UTC).isoformat(),
            "repositories": results,
            "repository_count": len(results),
            "failed_count": len(results),
            "partial_count": 0,
        }

    def _snapshot(
        self, *, organization: str, repository: dict[str, Any], token: str
    ) -> AzureReposSnapshot:
        repository_id = repository["id"]
        default_branch = repository.get("default_branch")
        if not default_branch:
            raise AzureReposSourceError("default_branch_missing")
        refs = self._json(
            organization,
            f"/_apis/git/repositories/{repository_id}/refs",
            token,
            params={"filter": default_branch.removeprefix("refs/")},
        )
        values = refs.get("value")
        if not isinstance(values, list):
            raise AzureReposSourceError("default_branch_not_resolved")
        exact = [
            item for item in values if isinstance(item, dict) and item.get("name") == default_branch
        ]
        if len(exact) != 1:
            raise AzureReposSourceError("default_branch_not_resolved")
        commit = str(exact[0].get("objectId", ""))
        if not _OBJECT_ID.fullmatch(commit):
            raise AzureReposSourceError("invalid_immutable_revision")
        items = self._json(
            organization,
            f"/_apis/git/repositories/{repository_id}/items",
            token,
            params={
                "recursionLevel": "Full",
                "includeContentMetadata": "true",
                "versionDescriptor.version": commit,
                "versionDescriptor.versionType": "commit",
            },
        )
        entries = items.get("value")
        if not isinstance(entries, list) or len(entries) > MAX_TREE_ENTRIES:
            raise AzureReposSourceError("repository_tree_limit_exceeded")
        candidates: list[tuple[str, str]] = []
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("isFolder") is True:
                continue
            path = _safe_repository_path(str(entry.get("path", "")).removeprefix("/"))
            if path is None or not _eligible_path(path):
                continue
            object_id = str(entry.get("objectId", ""))
            if not _OBJECT_ID.fullmatch(object_id):
                raise AzureReposSourceError("invalid_blob_identity")
            candidates.append((path, object_id))
        candidates.sort()
        if len(candidates) > MAX_SELECTED_FILES:
            raise AzureReposSourceError("repository_file_limit_exceeded")

        sized: list[tuple[str, str, int]] = []
        warnings: list[str] = []
        for path, object_id in candidates:
            metadata = self._json(
                organization,
                f"/_apis/git/repositories/{repository_id}/blobs/{object_id}",
                token,
            )
            size = metadata.get("size")
            if metadata.get("objectId") != object_id or not isinstance(size, int) or size < 0:
                raise AzureReposSourceError("invalid_blob_response")
            if size > MAX_BLOB_BYTES:
                warnings.append(f"{path}: larger than {MAX_BLOB_BYTES} bytes")
                continue
            sized.append((path, object_id, size))
        if sum(item[2] for item in sized) > MAX_TOTAL_BYTES:
            raise AzureReposSourceError("repository_byte_limit_exceeded")

        def fetch_blob(entry: tuple[str, str, int]) -> tuple[str, bytes]:
            path, object_id, expected_size = entry
            try:
                response = self._client.request(
                    "GET",
                    organization=organization,
                    path=f"/_apis/git/repositories/{repository_id}/blobs/{object_id}",
                    token=token,
                    params={"$format": "octetStream", "download": "true"},
                    accept="application/octet-stream",
                    timeout=30.0,
                )
                response.raise_for_status()
                content = bytes(getattr(response, "content", b""))
            except Exception as error:
                raise AzureReposSourceError("azure_devops_api_request_failed") from error
            if len(content) != expected_size or len(content) > MAX_BLOB_BYTES:
                raise AzureReposSourceError("blob_size_mismatch")
            return path, content

        with ThreadPoolExecutor(max_workers=MAX_BLOB_FETCH_WORKERS) as executor:
            files = list(executor.map(fetch_blob, sized))
        if sum(len(content) for _, content in files) > MAX_TOTAL_BYTES:
            raise AzureReposSourceError("repository_byte_limit_exceeded")
        full_name = repository["full_name"]
        canonical = f"dev.azure.com/{organization}/{full_name}"
        return AzureReposSnapshot(
            repository_id=repository_id,
            repository_name=canonical,
            default_branch=default_branch,
            commit=commit.lower(),
            remote=repository.get("remote_url")
            or f"https://dev.azure.com/{organization}/_git/{quote(repository['name'])}",
            source_locator=(
                f"azure-repos://organizations/{organization}/projects/{repository['project_id']}"
                f"/repositories/{repository_id}/commits/{commit.lower()}"
            ),
            files=tuple(files),
            warnings=tuple(warnings),
        )

    def _analyze_snapshot(
        self,
        *,
        tenant_id: str,
        connection_id: str,
        snapshot: AzureReposSnapshot,
        targets: tuple[DeploymentTarget, ...],
        repository: InventorySink,
    ) -> dict[str, Any]:
        organization = snapshot.repository_name.split("/", 3)[1]
        with tempfile.TemporaryDirectory(prefix="denali-azure-repos-") as directory:
            root = Path(directory)
            for relative, content in snapshot.files:
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
            metadata = {
                "repository_name": snapshot.repository_name,
                "remote": snapshot.remote,
                "commit": snapshot.commit,
                "dirty": False,
                "source_type": "azure_repos_repository_snapshot",
                "source_locator": snapshot.source_locator,
            }
            source_batch = _source_batch(
                connection_id=connection_id,
                repository_name=snapshot.repository_name,
                repository_id=snapshot.repository_id,
                project_id=snapshot.source_locator.split("/projects/", 1)[1].split("/", 1)[0],
                organization=organization,
                state=CoverageState.PARTIAL if snapshot.warnings else CoverageState.COMPLETE,
                detail="; ".join(snapshot.warnings)[:4_000] or None,
                commit=snapshot.commit,
                default_branch=snapshot.default_branch,
                file_count=len(snapshot.files),
                total_bytes=snapshot.total_bytes,
            )
            inventory_batch = RepositoryConnector(root, **metadata).collect(
                connection_id=connection_id
            )
            posture_batch = RepositoryPostureConnector(root, **metadata).collect(
                connection_id=connection_id
            )
            correlation_batch = CodeToCloudConnector(root, targets=targets, **metadata).collect(
                connection_id=connection_id
            )
            source_result = repository.ingest(tenant_id, source_batch)
            inventory_result = repository.ingest(tenant_id, inventory_batch)
            posture_result = repository.ingest_findings(tenant_id, posture_batch)
            correlation_result = repository.ingest(tenant_id, correlation_batch)
        summary = dict(correlation_batch.assets[0].attributes["correlation_summary"])
        coverage_states = {
            "source": source_batch.coverage[0].state.value,
            "inventory": inventory_batch.coverage[0].state.value,
            "posture": posture_batch.coverage[0].state.value,
            "correlation": correlation_batch.coverage[0].state.value,
        }
        state = (
            "complete"
            if all(value == CoverageState.COMPLETE.value for value in coverage_states.values())
            else "partial"
        )
        return {
            "repository_id": snapshot.repository_id,
            "repository": snapshot.repository_name.split("/", 2)[-1],
            "state": state,
            "revision": snapshot.commit,
            "files": len(snapshot.files),
            "bytes": snapshot.total_bytes,
            "source_assets": source_result["assets"],
            "inventory_assets": inventory_result["assets"],
            "inventory_relationships": inventory_result["relationships"],
            "posture_findings": posture_result["findings"],
            "deployment_relationships": correlation_result["relationships"],
            "correlation": summary,
            "coverage": coverage_states,
        }

    def _json(self, organization: str, path: str, token: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self._client.request(
                "GET", organization=organization, path=path, token=token, **kwargs
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as error:
            raise AzureReposSourceError("azure_devops_api_request_failed") from error
        if not isinstance(payload, dict):
            raise AzureReposSourceError("invalid_azure_devops_response")
        return payload


def _source_batch(
    *,
    connection_id: str,
    repository_name: str,
    repository_id: Any,
    project_id: Any,
    organization: str,
    state: CoverageState,
    detail: str | None = None,
    commit: str | None = None,
    default_branch: str | None = None,
    file_count: int = 0,
    total_bytes: int = 0,
) -> InventoryBatch:
    observed_at = datetime.now(UTC)
    revision = commit or "unresolved"
    scope = f"repository:{repository_name}"
    assets: tuple[AssetAssertion, ...] = ()
    if (
        state in {CoverageState.COMPLETE, CoverageState.PARTIAL}
        and "unknown/unknown" not in repository_name
    ):
        assets = (
            AssetAssertion(
                asset=AssetRef(AssetKind.CODE_REPOSITORY, repository_name),
                coverage_plane=SOURCE_PLANE,
                display_name=repository_name.rsplit("/", 1)[-1],
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                evidence=Evidence(
                    source_type="azure_repos_repository_snapshot",
                    locator=(
                        f"azure-repos://organizations/{organization}/projects/{project_id}"
                        f"/repositories/{repository_id}/commits/{revision}"
                    ),
                    observed_at=observed_at,
                    payload={
                        "organization": organization,
                        "project_id": project_id,
                        "repository_id": repository_id,
                        "commit": commit,
                        "default_branch": default_branch,
                    },
                ),
                attributes={
                    "provider": "azure_repos",
                    "organization": organization,
                    "project_id": project_id,
                    "repository_id": repository_id,
                    "commit": commit,
                    "default_branch": default_branch,
                    "selected_file_count": file_count,
                    "selected_bytes": total_bytes,
                    "collection_state": state.value,
                    "collection_detail": detail,
                },
            ),
        )
    return InventoryBatch(
        connector_id=CONNECTOR_ID,
        connection_id=connection_id,
        run_id=f"azure-repos-{repository_id}-{revision}-{observed_at.isoformat()}",
        scope_key=scope,
        collected_at=observed_at,
        coverage=(Coverage(SOURCE_PLANE, state, scope, detail),),
        assets=assets,
    )


def _safe_repository_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def _eligible_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if any(part in _EXCLUDED_PARTS or part.startswith(".") for part in parts[:-1]):
        return False
    name = parts[-1]
    if ".generated." in name.lower():
        return False
    suffix = PurePosixPath(name).suffix.lower()
    return (
        suffix in _SOURCE_SUFFIXES
        or name in {"mcp.json", "claude_desktop_config.json", "package.json"}
        or name.lower().startswith("dockerfile")
        or name.endswith(".assets.json")
    )


def _same_repository(expected: dict[str, Any], observed: dict[str, Any]) -> bool:
    return (
        expected.get("id") == observed.get("id")
        and expected.get("project_id") == observed.get("project_id")
        and str(expected.get("name", "")).casefold() == str(observed.get("name", "")).casefold()
        and str(expected.get("project_name", "")).casefold()
        == str(observed.get("project_name", "")).casefold()
    )
