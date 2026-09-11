"""Bounded GitHub App source collection at an immutable repository revision."""

from __future__ import annotations

import base64
import binascii
import re
import tempfile
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from threading import Lock
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
MAX_CONNECTION_REQUESTS = 4_000
GITHUB_RATE_LIMIT_RESERVE = 500
COLLECTION_DEADLINE_SECONDS = 2_100
_SNAPSHOT_METADATA_REQUESTS = 4
_MIN_USEFUL_REPOSITORY_REQUESTS = _SNAPSHOT_METADATA_REQUESTS + 1

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


class _GitHubRequestBudgetReached(GitHubSourceError):
    """The connection must stop issuing GitHub requests and retain partial evidence."""


@dataclass(slots=True)
class _GitHubRequestBudget:
    limit: int
    rate_limit_reserve: int
    deadline: float
    monotonic: Callable[[], float]
    requests: int = 0
    provider_remaining: int | None = None
    reached: bool = False
    _lock: Lock = field(default_factory=Lock, repr=False)

    def acquire(self) -> None:
        with self._lock:
            if self.monotonic() >= self.deadline:
                self.reached = True
                raise _GitHubRequestBudgetReached("github_collection_deadline_reached")
            if self.requests >= self.limit:
                self.reached = True
                raise _GitHubRequestBudgetReached("github_request_budget_reached")
            if (
                self.provider_remaining is not None
                and self.provider_remaining <= self.rate_limit_reserve
            ):
                self.reached = True
                raise _GitHubRequestBudgetReached("github_rate_limit_reserve_reached")
            self.requests += 1
            if self.requests >= self.limit:
                self.reached = True

    def observe(self, response: Any) -> None:
        headers = {
            str(key).lower(): str(value) for key, value in getattr(response, "headers", {}).items()
        }
        remaining = _optional_nonnegative_int(headers.get("x-ratelimit-remaining"))
        with self._lock:
            if remaining is not None:
                self.provider_remaining = (
                    remaining
                    if self.provider_remaining is None
                    else min(self.provider_remaining, remaining)
                )
                if self.provider_remaining <= self.rate_limit_reserve:
                    self.reached = True

    def capacity(self) -> int:
        with self._lock:
            local = max(0, self.limit - self.requests)
            if self.provider_remaining is None:
                return local
            provider = max(0, self.provider_remaining - self.rate_limit_reserve)
            return min(local, provider)

    def blob_allowance(self, repositories_remaining: int) -> int:
        """Share remaining requests while reserving one useful snapshot per later repo."""

        capacity = self.capacity()
        later_reserve = max(0, repositories_remaining - 1) * (_MIN_USEFUL_REPOSITORY_REQUESTS)
        if capacity <= later_reserve:
            return 0
        return 1 + (capacity - later_reserve - 1) // max(1, repositories_remaining)

    def reopen_after_reset(self) -> None:
        with self._lock:
            if (
                self.provider_remaining is not None
                and self.provider_remaining <= self.rate_limit_reserve
            ):
                self.provider_remaining = None
            self.reached = self.requests >= self.limit

    def mark_reached(self) -> None:
        with self._lock:
            self.reached = True


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

    def __init__(
        self,
        app_client: GitHubAppClient,
        *,
        max_requests: int | None = None,
        rate_limit_reserve: int | None = None,
        deadline_seconds: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._app = app_client
        self._max_requests = MAX_CONNECTION_REQUESTS if max_requests is None else max_requests
        self._rate_limit_reserve = (
            GITHUB_RATE_LIMIT_RESERVE if rate_limit_reserve is None else rate_limit_reserve
        )
        self._deadline_seconds = (
            COLLECTION_DEADLINE_SECONDS if deadline_seconds is None else deadline_seconds
        )
        if self._max_requests < 1 or self._rate_limit_reserve < 0:
            raise ValueError("GitHub request budget values must be non-negative")
        if self._deadline_seconds <= 0:
            raise ValueError("GitHub collection deadline must be positive")
        self._monotonic = monotonic
        self._wall_clock = wall_clock
        self._sleep = sleep

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

        budget = self._new_request_budget()
        try:
            installation = self._budgeted_call(
                lambda: self._app.get_installation(installation_id), budget=budget
            )
            expected_account = connection.get("configuration", {}).get("account_id")
            if installation.get("account_id") != expected_account:
                raise GitHubSourceError("installation_account_mismatch")
        except _GitHubRequestBudgetReached as error:
            results = [
                self._record_partial_repository(
                    tenant_id=tenant_id,
                    connection_id=str(connection["id"]),
                    selected_repository=selected_repository,
                    repository=repository,
                    detail=error.code,
                )
                for selected_repository in selected
            ]
            return {
                "connection_id": str(connection["id"]),
                "state": "partial",
                "completed_at": datetime.now(UTC).isoformat(),
                "repositories": results,
                "repository_count": len(results),
                "failed_count": 0,
                "partial_count": len(results),
                "github_requests": budget.requests,
                "github_request_limit": budget.limit,
                "request_budget_reached": True,
            }
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
            DeploymentTarget.from_record(item) for item in repository.deployment_targets(tenant_id)
        )
        results: list[dict[str, Any]] = []
        for index, selected_repository in enumerate(selected):
            try:
                snapshot = self._snapshot(
                    installation_id=installation_id,
                    repository=selected_repository,
                    budget=budget,
                    repositories_remaining=len(selected) - index,
                )
                result = self._analyze_snapshot(
                    tenant_id=tenant_id,
                    connection_id=str(connection["id"]),
                    snapshot=snapshot,
                    targets=targets,
                    repository=repository,
                )
            except _GitHubRequestBudgetReached as error:
                result = self._record_partial_repository(
                    tenant_id=tenant_id,
                    connection_id=str(connection["id"]),
                    selected_repository=selected_repository,
                    repository=repository,
                    detail=error.code,
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
            "github_requests": budget.requests,
            "github_request_limit": budget.limit,
            "request_budget_reached": budget.reached,
        }

    def _new_request_budget(self) -> _GitHubRequestBudget:
        return _GitHubRequestBudget(
            limit=self._max_requests,
            rate_limit_reserve=self._rate_limit_reserve,
            deadline=self._monotonic() + self._deadline_seconds,
            monotonic=self._monotonic,
        )

    def _snapshot(
        self,
        *,
        installation_id: int,
        repository: dict[str, Any],
        budget: _GitHubRequestBudget,
        repositories_remaining: int,
    ) -> GitHubSnapshot:
        repository_id = repository.get("id")
        full_name = repository.get("full_name")
        if not isinstance(repository_id, int) or not isinstance(full_name, str):
            raise GitHubSourceError("invalid_repository_boundary")
        token = self._budgeted_call(
            lambda: self._app.create_installation_token(
                installation_id=installation_id,
                repository_id=repository_id,
            ),
            budget=budget,
        )
        metadata = self._json("GET", f"/repos/{full_name}", token=token, budget=budget)
        owner = metadata.get("owner")
        if (
            metadata.get("id") != repository_id
            or str(metadata.get("node_id", "")) != str(repository.get("node_id", ""))
            or str(metadata.get("full_name", "")).lower() != full_name.lower()
            or not isinstance(owner, dict)
            or owner.get("id") != repository.get("owner_id")
            or str(owner.get("login", "")).lower() != str(repository.get("owner_login", "")).lower()
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
                budget=budget,
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
            budget=budget,
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

        blob_allowance = budget.blob_allowance(repositories_remaining)
        fetch_entries = selected_entries[:blob_allowance]
        request_skipped = len(selected_entries) - len(fetch_entries)
        if request_skipped > 0:
            warnings.append(
                "connection GitHub request budget selected "
                f"{len(fetch_entries)} of {len(selected_entries)} repository-budgeted files"
            )

        def fetch_blob(entry: tuple[str, str, int]) -> tuple[str, bytes] | None:
            path, sha, expected_size = entry
            try:
                blob = self._json(
                    "GET",
                    f"/repos/{full_name}/git/blobs/{sha}",
                    token=token,
                    budget=budget,
                )
            except _GitHubRequestBudgetReached:
                return None
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
            fetched = list(executor.map(fetch_blob, fetch_entries))
        files = [item for item in fetched if item is not None]
        if len(files) < len(fetch_entries):
            warnings.append(
                "GitHub rate-limit reserve or collection deadline stopped source retrieval; "
                f"collected {len(files)} of {len(fetch_entries)} allocated files"
            )
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

    def _record_partial_repository(
        self,
        *,
        tenant_id: str,
        connection_id: str,
        selected_repository: dict[str, Any],
        repository: InventorySink,
        detail: str,
    ) -> dict[str, Any]:
        full_name = str(selected_repository.get("full_name", "unknown/unknown"))
        repository.ingest(
            tenant_id,
            _source_batch(
                connection_id=connection_id,
                repository_name=f"github.com/{full_name}",
                repository_id=selected_repository.get("id"),
                state=CoverageState.PARTIAL,
                detail=detail,
            ),
        )
        return {
            "repository_id": selected_repository.get("id"),
            "repository": full_name,
            "state": "partial",
            "detail": detail,
            "files": 0,
            "bytes": 0,
        }

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
                state=(CoverageState.PARTIAL if snapshot.warnings else CoverageState.COMPLETE),
                detail=("; ".join((*snapshot.warnings, snapshot.detail or ""))[:4_000] or None),
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
                upstream_detail = (
                    "Source snapshot is partial: " + "; ".join(snapshot.warnings)[:3_900]
                )
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

    def _json(
        self,
        method: str,
        path: str,
        *,
        token: str,
        budget: _GitHubRequestBudget | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        for attempt in range(3):
            try:
                if budget is not None:
                    budget.acquire()
                response = self._app.installation_request(
                    method, path, token=token, timeout=20.0, **kwargs
                )
                if budget is not None:
                    budget.observe(response)
                response.raise_for_status()
                payload = response.json()
                break
            except Exception as error:
                if isinstance(error, _GitHubRequestBudgetReached):
                    raise
                code = _github_request_error_code(error)
                if self._retry_github_error(
                    error=error,
                    code=code,
                    attempt=attempt,
                    budget=budget,
                ):
                    continue
                raise GitHubSourceError(code) from error
        if not isinstance(payload, dict):
            raise GitHubSourceError("invalid_github_response")
        return payload

    def _budgeted_call(
        self,
        action: Callable[[], Any],
        *,
        budget: _GitHubRequestBudget,
    ) -> Any:
        """Bound and retry GitHub client methods that return parsed domain payloads."""

        for attempt in range(3):
            budget.acquire()
            try:
                return action()
            except Exception as error:
                response = getattr(error, "response", None)
                if response is not None:
                    budget.observe(response)
                code = _github_request_error_code(error)
                if self._retry_github_error(
                    error=error,
                    code=code,
                    attempt=attempt,
                    budget=budget,
                ):
                    continue
                raise
        raise AssertionError("bounded GitHub retry loop did not return")

    def _retry_github_error(
        self,
        *,
        error: Exception,
        code: str,
        attempt: int,
        budget: _GitHubRequestBudget | None,
    ) -> bool:
        if code == "github_rate_limited" and budget is not None:
            delay = _rate_limit_delay(error, wall_clock=self._wall_clock)
            if attempt >= 2:
                budget.mark_reached()
                raise _GitHubRequestBudgetReached("github_rate_limit_reserve_reached") from error
            if delay is not None:
                if self._monotonic() + delay >= budget.deadline:
                    budget.mark_reached()
                    raise _GitHubRequestBudgetReached(
                        "github_rate_limit_wait_exceeds_deadline"
                    ) from error
                self._sleep(delay)
                budget.reopen_after_reset()
                return True
        if (
            code
            in {
                "github_rate_limited",
                "github_timeout",
                "github_upstream_unavailable",
            }
            and attempt < 2
        ):
            self._sleep(0.25 * (2**attempt))
            return True
        return False


def _optional_nonnegative_int(value: Any) -> int | None:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _optional_nonnegative_float(value: Any) -> float | None:
    try:
        parsed = float(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _rate_limit_delay(error: Exception, *, wall_clock: Callable[[], float]) -> float | None:
    response = getattr(error, "response", None)
    headers = {
        str(key).lower(): str(value) for key, value in getattr(response, "headers", {}).items()
    }
    retry_after = _optional_nonnegative_float(headers.get("retry-after"))
    if retry_after is not None:
        return retry_after
    reset_at = _optional_nonnegative_float(headers.get("x-ratelimit-reset"))
    if reset_at is not None:
        return max(0.0, reset_at - float(wall_clock()) + 1.0)
    return None


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
    headers = {
        str(key).lower(): str(value) for key, value in getattr(response, "headers", {}).items()
    }
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
            (CoverageState.PARTIAL if item.state is CoverageState.COMPLETE else item.state),
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
