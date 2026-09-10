"""Bounded GitHub App source collection at an immutable repository revision."""

from __future__ import annotations

import base64
import binascii
import re
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Protocol
from urllib.parse import quote

from denali.connections.github import GitHubAppClient
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

CONNECTOR_ID = "denali.github_repository"
SOURCE_PLANE = "github_source_collection"
MAX_TREE_ENTRIES = 20_000
MAX_SELECTED_FILES = 2_000
MAX_BLOB_BYTES = 2_000_000
MAX_TOTAL_BYTES = 25_000_000
MAX_BLOB_FETCH_WORKERS = 8

_COMMIT_SHA = re.compile(r"^[0-9a-f]{40,64}$")
_BLOB_SHA = re.compile(r"^[0-9a-f]{40,64}$")
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
    {
        ".git",
        ".hg",
        ".venv",
        "build",
        "dist",
        "fixtures",
        "node_modules",
        "test",
        "tests",
        "vendor",
    }
)


class InventorySink(Protocol):
    def ingest(self, tenant_id: str, batch: InventoryBatch) -> dict[str, int]: ...

    def deployment_targets(self, tenant_id: str) -> list[dict[str, Any]]: ...

    def ingest_findings(self, tenant_id: str, batch: FindingBatch) -> dict[str, int]: ...


class GitHubSourceError(RuntimeError):
    """A stable, non-secret source collection failure."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class GitHubSnapshot:
    repository_id: int
    repository_name: str
    default_branch: str | None
    commit: str
    remote: str
    source_locator: str
    files: tuple[tuple[str, bytes], ...]
    warnings: tuple[str, ...] = ()
    detail: str | None = None

    @property
    def total_bytes(self) -> int:
        return sum(len(content) for _, content in self.files)


class GitHubRepositoryCollector:
    """Collect exact selected repositories without retaining tokens or source blobs."""

    def __init__(self, app_client: GitHubAppClient):
        self._app = app_client

    def collect(
        self,
        *,
        tenant_id: str,
        connection: dict[str, Any],
        repository: InventorySink,
    ) -> dict[str, Any]:
        installation_id = connection.get("credential_reference", {}).get("installation_id")
        selected = connection.get("configuration", {}).get("repositories", [])
        if connection.get("provider") != "github":
            raise ValueError("connection is not a GitHub connection")
        if connection.get("lifecycle_state") != "active":
            raise ValueError("disabled GitHub connections cannot collect source")
        if not isinstance(installation_id, int) or not isinstance(selected, list) or not selected:
            raise ValueError("complete GitHub App installation before collecting source")

        try:
            installation = self._app.get_installation(installation_id)
            expected_account = connection.get("configuration", {}).get("account_id")
            if installation.get("account_id") != expected_account:
                raise GitHubSourceError("installation_account_mismatch")
        except Exception as error:
            code = (
                error.code
                if isinstance(error, GitHubSourceError)
                else "installation_validation_failed"
            )
            results = []
            for selected_repository in selected:
                full_name = str(selected_repository.get("full_name", "unknown/unknown"))
                repository.ingest(
                    tenant_id,
                    _source_batch(
                        connection_id=str(connection["id"]),
                        repository_name=f"github.com/{full_name}",
                        repository_id=selected_repository.get("id"),
                        state=CoverageState.FAILED,
                        detail=code,
                    ),
                )
                results.append(
                    {
                        "repository_id": selected_repository.get("id"),
                        "repository": full_name,
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

        targets = tuple(
            DeploymentTarget.from_record(item)
            for item in repository.deployment_targets(tenant_id)
        )
        results: list[dict[str, Any]] = []
        for selected_repository in selected:
            try:
                snapshot = self._snapshot(
                    installation_id=installation_id,
                    repository=selected_repository,
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
                    if isinstance(error, GitHubSourceError)
                    else "source_collection_failed"
                )
                full_name = str(selected_repository.get("full_name", "unknown/unknown"))
                canonical_name = f"github.com/{full_name}"
                repository.ingest(
                    tenant_id,
                    _source_batch(
                        connection_id=str(connection["id"]),
                        repository_name=canonical_name,
                        repository_id=selected_repository.get("id"),
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

    def _snapshot(
        self,
        *,
        installation_id: int,
        repository: dict[str, Any],
    ) -> GitHubSnapshot:
        repository_id = repository.get("id")
        full_name = repository.get("full_name")
        if not isinstance(repository_id, int) or not isinstance(full_name, str):
            raise GitHubSourceError("invalid_repository_boundary")
        token = self._app.create_installation_token(
            installation_id=installation_id,
            repository_id=repository_id,
        )
        metadata = self._json("GET", f"/repos/{full_name}", token=token)
        owner = metadata.get("owner")
        if (
            metadata.get("id") != repository_id
            or str(metadata.get("node_id", "")) != str(repository.get("node_id", ""))
            or str(metadata.get("full_name", "")).lower() != full_name.lower()
            or not isinstance(owner, dict)
            or owner.get("id") != repository.get("owner_id")
            or str(owner.get("login", "")).lower()
            != str(repository.get("owner_login", "")).lower()
        ):
            raise GitHubSourceError("repository_identity_mismatch")
        default_branch = metadata.get("default_branch")
        if not isinstance(default_branch, str) or not default_branch:
            return _empty_snapshot(repository_id, full_name, default_branch=None)
        try:
            ref = self._json(
                "GET",
                f"/repos/{full_name}/git/ref/{quote(f'heads/{default_branch}', safe='/')}",
                token=token,
            )
        except GitHubSourceError as error:
            if error.code == "github_conflict":
                return _empty_snapshot(
                    repository_id,
                    full_name,
                    default_branch=default_branch,
                )
            raise
        commit = ref.get("object", {}).get("sha")
        if not isinstance(commit, str) or not _COMMIT_SHA.fullmatch(commit):
            raise GitHubSourceError("invalid_immutable_revision")
        tree = self._json(
            "GET",
            f"/repos/{full_name}/git/trees/{commit}",
            token=token,
            params={"recursive": "1"},
        )
        entries = tree.get("tree")
        if tree.get("truncated") is not False or not isinstance(entries, list):
            raise GitHubSourceError("repository_tree_incomplete")
        if len(entries) > MAX_TREE_ENTRIES:
            raise GitHubSourceError("repository_tree_limit_exceeded")

        selected_entries: list[tuple[str, str, int]] = []
        warnings: list[str] = []
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("type") != "blob":
                continue
            path = _safe_repository_path(entry.get("path"))
            if path is None or entry.get("mode") not in {"100644", "100755"}:
                continue
            if not _eligible_path(path):
                continue
            sha = entry.get("sha")
            size = entry.get("size")
            if not isinstance(sha, str) or not _BLOB_SHA.fullmatch(sha):
                raise GitHubSourceError("invalid_blob_identity")
            if not isinstance(size, int) or size < 0:
                raise GitHubSourceError("repository_blob_limit_exceeded")
            if size > MAX_BLOB_BYTES:
                warnings.append(f"{path}: larger than {MAX_BLOB_BYTES} bytes")
                continue
            selected_entries.append((path, sha, size))

        eligible_count = len(selected_entries)
        selected_entries.sort(key=lambda item: (_analysis_priority(item[0]), item[0]))
        budgeted_entries: list[tuple[str, str, int]] = []
        selected_bytes = 0
        byte_skipped = 0
        for entry in selected_entries:
            if len(budgeted_entries) >= MAX_SELECTED_FILES:
                break
            if selected_bytes + entry[2] > MAX_TOTAL_BYTES:
                byte_skipped += 1
                continue
            budgeted_entries.append(entry)
            selected_bytes += entry[2]
        file_skipped = eligible_count - len(budgeted_entries) - byte_skipped
        if file_skipped > 0 or byte_skipped > 0:
            warnings.append(
                "repository analysis budget selected "
                f"{len(budgeted_entries)} of {eligible_count} eligible files; "
                f"{file_skipped} exceeded the file budget and {byte_skipped} exceeded "
                "the byte budget"
            )
        selected_entries = budgeted_entries

        def fetch_blob(entry: tuple[str, str, int]) -> tuple[str, bytes]:
            path, sha, expected_size = entry
            blob = self._json("GET", f"/repos/{full_name}/git/blobs/{sha}", token=token)
            if blob.get("sha") != sha or blob.get("encoding") != "base64":
                raise GitHubSourceError("invalid_blob_response")
            try:
                encoded = re.sub(r"\s+", "", str(blob.get("content", "")))
                content = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as error:
                raise GitHubSourceError("invalid_blob_encoding") from error
            if len(content) != expected_size or len(content) > MAX_BLOB_BYTES:
                raise GitHubSourceError("blob_size_mismatch")
            return path, content

        with ThreadPoolExecutor(max_workers=MAX_BLOB_FETCH_WORKERS) as executor:
            files = list(executor.map(fetch_blob, selected_entries))
        if sum(len(content) for _, content in files) > MAX_TOTAL_BYTES:
            raise GitHubSourceError("repository_byte_limit_exceeded")

        return GitHubSnapshot(
            repository_id=repository_id,
            repository_name=f"github.com/{full_name}",
            default_branch=default_branch,
            commit=commit,
            remote=f"https://github.com/{full_name}.git",
            source_locator=f"github://repositories/{repository_id}/commits/{commit}",
            files=tuple(files),
            warnings=tuple(warnings),
        )

    def _analyze_snapshot(
        self,
        *,
        tenant_id: str,
        connection_id: str,
        snapshot: GitHubSnapshot,
        targets: tuple[DeploymentTarget, ...],
        repository: InventorySink,
    ) -> dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="denali-github-source-") as directory:
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
                "source_type": "github_repository_snapshot",
                "source_locator": snapshot.source_locator,
            }
            source_batch = _source_batch(
                connection_id=connection_id,
                repository_name=snapshot.repository_name,
                repository_id=snapshot.repository_id,
                state=(
                    CoverageState.PARTIAL
                    if snapshot.warnings
                    else CoverageState.COMPLETE
                ),
                detail=(
                    "; ".join((*snapshot.warnings, snapshot.detail or ""))[:4_000]
                    or None
                ),
                commit=snapshot.commit,
                default_branch=snapshot.default_branch,
                file_count=len(snapshot.files),
                total_bytes=snapshot.total_bytes,
                source_locator=snapshot.source_locator,
            )
            inventory_batch = RepositoryConnector(root, **metadata).collect(
                connection_id=connection_id
            )
            posture_batch = RepositoryPostureConnector(root, **metadata).collect(
                connection_id=connection_id
            )
            correlation_batch = CodeToCloudConnector(
                root,
                targets=targets,
                **metadata,
            ).collect(connection_id=connection_id)
            if snapshot.warnings:
                upstream_detail = "Source snapshot is partial: " + "; ".join(
                    snapshot.warnings
                )[:3_900]
                inventory_batch = _with_partial_coverage(inventory_batch, upstream_detail)
                posture_batch = _with_partial_coverage(posture_batch, upstream_detail)
                correlation_batch = _with_partial_coverage(correlation_batch, upstream_detail)
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
            "repository": snapshot.repository_name.removeprefix("github.com/"),
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

    def _json(self, method: str, path: str, *, token: str, **kwargs: Any) -> dict[str, Any]:
        for attempt in range(3):
            try:
                response = self._app.installation_request(
                    method, path, token=token, timeout=20.0, **kwargs
                )
                response.raise_for_status()
                payload = response.json()
                break
            except Exception as error:
                code = _github_request_error_code(error)
                if code in {
                    "github_rate_limited",
                    "github_timeout",
                    "github_upstream_unavailable",
                } and attempt < 2:
                    time.sleep(0.25 * (2**attempt))
                    continue
                raise GitHubSourceError(code) from error
        if not isinstance(payload, dict):
            raise GitHubSourceError("invalid_github_response")
        return payload


def _empty_snapshot(
    repository_id: int,
    full_name: str,
    *,
    default_branch: str | None,
) -> GitHubSnapshot:
    return GitHubSnapshot(
        repository_id=repository_id,
        repository_name=f"github.com/{full_name}",
        default_branch=default_branch,
        commit="empty",
        remote=f"https://github.com/{full_name}.git",
        source_locator=f"github://repositories/{repository_id}/empty",
        files=(),
        detail="repository_empty",
    )


def _analysis_priority(path: str) -> int:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in {".tf", ".bicep", ".yaml", ".yml"}:
        return 0
    if suffix in {
        ".py",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".mts",
        ".cts",
    }:
        return 1
    return 2


def _github_request_error_code(error: Exception) -> str:
    response = getattr(error, "response", None)
    status = getattr(response, "status_code", None)
    headers = getattr(response, "headers", {})
    if (
        status == 429
        or (status == 403 and str(headers.get("x-ratelimit-remaining", "")) == "0")
        or headers.get("retry-after")
    ):
        return "github_rate_limited"
    if status == 403:
        return "github_permission_denied"
    if status == 404:
        return "github_resource_not_found"
    if status == 409:
        return "github_conflict"
    if isinstance(status, int) and status >= 500:
        return "github_upstream_unavailable"
    if isinstance(error, TimeoutError) or "timeout" in type(error).__name__.lower():
        return "github_timeout"
    return "github_api_request_failed"


def _with_partial_coverage(batch: Any, detail: str) -> Any:
    coverage = tuple(
        Coverage(
            item.plane,
            (
                CoverageState.PARTIAL
                if item.state is CoverageState.COMPLETE
                else item.state
            ),
            item.scope,
            "; ".join(part for part in (item.detail, detail) if part)[:4_000],
        )
        for item in batch.coverage
    )
    return replace(batch, coverage=coverage)


def _source_batch(
    *,
    connection_id: str,
    repository_name: str,
    repository_id: Any,
    state: CoverageState,
    detail: str | None = None,
    commit: str | None = None,
    default_branch: str | None = None,
    file_count: int = 0,
    total_bytes: int = 0,
    source_locator: str | None = None,
) -> InventoryBatch:
    observed_at = datetime.now(UTC)
    revision = commit or "unresolved"
    scope = f"repository:{repository_name}"
    assets: tuple[AssetAssertion, ...] = ()
    if state in {CoverageState.COMPLETE, CoverageState.PARTIAL} and repository_name != (
        "github.com/unknown/unknown"
    ):
        assets = (
            AssetAssertion(
                asset=AssetRef(AssetKind.CODE_REPOSITORY, repository_name),
                coverage_plane=SOURCE_PLANE,
                display_name=repository_name.rsplit("/", 1)[-1],
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                evidence=Evidence(
                    source_type="github_repository_snapshot",
                    locator=source_locator
                    or f"github://repositories/{repository_id}/commits/{revision}",
                    observed_at=observed_at,
                    payload={
                        "repository_id": repository_id,
                        "commit": commit,
                        "default_branch": default_branch,
                    },
                ),
                attributes={
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
        run_id=f"github-source-{repository_id}-{revision}-{observed_at.isoformat()}",
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
