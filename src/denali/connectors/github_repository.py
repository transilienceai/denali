"""Bounded GitHub App source collection at an immutable repository revision."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import tempfile
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from threading import Lock
from typing import Any, Protocol
from urllib.parse import quote

from denali.connections.github import GITHUB_SCOPES, GitHubAppClient, _repository_boundary
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
MAX_REPOSITORIES_PER_SLICE = 5
MAX_TREE_REQUESTS = 256
MAX_TREE_WALK_DEPTH = 64
MAX_TREE_INSPECTED_ENTRIES = 100_000
MAX_RESUME_DELAY_SECONDS = 3_660
MAX_REPOSITORY_INTERRUPTION_COUNT = 3
_SNAPSHOT_METADATA_REQUESTS = 4
_MIN_USEFUL_REPOSITORY_REQUESTS = _SNAPSHOT_METADATA_REQUESTS + 1
_TERMINAL_SOURCE_ERRORS = frozenset(
    {
        "installation_account_mismatch",
        "invalid_repository_boundary",
        "repository_identity_mismatch",
        "invalid_immutable_revision",
        "repository_tree_incomplete",
        "repository_tree_limit_exceeded",
        "invalid_blob_identity",
        "repository_blob_limit_exceeded",
        "invalid_blob_response",
        "invalid_blob_encoding",
        "blob_size_mismatch",
        "repository_byte_limit_exceeded",
        "repository_tree_request_limit_exceeded",
        "repository_tree_inspection_limit_exceeded",
        "invalid_tree_entry",
        "invalid_tree_path",
        "invalid_tree_mode",
        "invalid_tree_identity",
        "invalid_github_response",
        "github_permission_denied",
        "github_resource_not_found",
        "github_conflict",
        "invalid_default_branch",
        "github_collection_retry_limit_reached",
    }
)

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


class GitHubCheckpointRejected(GitHubSourceError):
    """The durable claim was lost; no further reads or writes may follow."""


@dataclass(slots=True)
class _GitHubRequestBudget:
    limit: int
    rate_limit_reserve: int
    deadline: float
    monotonic: Callable[[], float]
    requests: int = 0
    provider_remaining: int | None = None
    reached: bool = False
    blocked_code: str | None = None
    retry_after_seconds: int | None = None
    _lock: Lock = field(default_factory=Lock, repr=False)

    def acquire(self) -> None:
        with self._lock:
            if self.blocked_code is not None:
                raise _GitHubRequestBudgetReached(self.blocked_code)
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
        retry_after = _optional_nonnegative_int(headers.get("retry-after"))
        reset = _optional_nonnegative_int(headers.get("x-ratelimit-reset"))
        if reset is not None:
            reset_delay = max(0, reset - int(datetime.now(UTC).timestamp())) + 60
            retry_after = max(retry_after or 0, reset_delay)
        with self._lock:
            if retry_after is not None:
                self.retry_after_seconds = max(60, min(MAX_RESUME_DELAY_SECONDS, retry_after))
            if remaining is not None:
                self.provider_remaining = (
                    remaining
                    if self.provider_remaining is None
                    else min(self.provider_remaining, remaining)
                )
                if self.provider_remaining <= self.rate_limit_reserve:
                    self.reached = True
                    self.blocked_code = "github_rate_limit_reserve_reached"

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

    def block(self, code: str) -> None:
        with self._lock:
            self.reached = True
            self.blocked_code = code


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

    def collect_resumable(
        self,
        *,
        tenant_id: str,
        connection: dict[str, Any],
        repository: InventorySink,
        checkpoint: dict[str, Any],
        save_checkpoint: Callable[[dict[str, Any]], bool],
    ) -> dict[str, Any]:
        """Finish whole bounded repositories, yielding without persisting source or tokens.

        The caller owns durable dispatch, rate-limit scheduling and claim-fenced sink
        transactions. Checkpoint saves are also fences: rejection aborts immediately.
        A paused repository restarts its transient download at the *same* saved commit.
        """

        boundary_hash = github_collection_boundary_hash(tenant_id, connection)
        selected = connection["configuration"]["repositories"]
        saved = _validated_checkpoint(checkpoint, boundary_hash, selected)

        def fence() -> None:
            if save_checkpoint(deepcopy(saved)) is not True:
                raise GitHubCheckpointRejected("github_collection_claim_lost")

        fence()
        deadline = self._monotonic() + self._deadline_seconds
        targets = tuple(
            DeploymentTarget.from_record(item) for item in repository.deployment_targets(tenant_id)
        )
        processed = requests = 0
        budget_reached = False

        def result(*, pending: bool, delay: int = 0) -> dict[str, Any]:
            completed = [
                saved["repositories"][str(item["id"])]["result"]
                for item in selected
                if "result" in saved["repositories"].get(str(item["id"]), {})
            ]
            failed = sum(item["state"] == "failed" for item in completed)
            partial = sum(item["state"] == "partial" for item in completed)
            return {
                "connection_id": str(connection["id"]),
                "state": "running" if pending else "partial" if failed or partial else "complete",
                "repositories": deepcopy(completed),
                "repository_count": len(selected),
                "selected_repository_count": len(selected),
                "completed_repository_count": len(completed),
                "failed_count": failed,
                "partial_count": partial,
                "github_requests": requests,
                "github_request_limit": self._max_requests * MAX_REPOSITORIES_PER_SLICE,
                "github_per_repository_request_limit": self._max_requests,
                "github_request_budget_scope": "slice",
                "request_budget_reached": budget_reached,
                "resume_pending": pending,
                "retry_after_seconds": delay,
                **({"completed_at": datetime.now(UTC).isoformat()} if not pending else {}),
            }

        for selected_repository in selected:
            key = str(selected_repository["id"])
            progress = saved["repositories"].get(key, {})
            if "result" in progress:
                continue
            if processed >= MAX_REPOSITORIES_PER_SLICE or self._monotonic() >= deadline:
                return result(pending=True)
            fence()
            if progress.get("interruption_count", 0) >= MAX_REPOSITORY_INTERRUPTION_COUNT:
                # A previous container can die after saving the final interruption
                # but before ingesting its honest terminal coverage. Do not restart
                # provider work or persist an out-of-range fourth interruption.
                progress["result"] = self._record_partial_repository(
                    tenant_id=tenant_id,
                    connection_id=str(connection["id"]),
                    selected_repository=selected_repository,
                    repository=repository,
                    detail="github_collection_retry_limit_reached",
                    revision=progress.get("revision"),
                    default_branch=progress.get("default_branch"),
                )
                fence()
                processed += 1
                continue
            budget = _GitHubRequestBudget(
                limit=self._max_requests,
                rate_limit_reserve=self._rate_limit_reserve,
                deadline=deadline,
                monotonic=self._monotonic,
            )

            def pin(commit: str, branch: str | None, *, repo_key: str = key) -> None:
                if branch is not None and (
                    not isinstance(branch, str)
                    or not branch
                    or len(branch) > 255
                    or any(ord(char) < 32 for char in branch)
                ):
                    raise GitHubSourceError("invalid_default_branch")
                saved["repositories"].setdefault(repo_key, {}).update(
                    {"revision": commit, "default_branch": branch}
                )
                fence()

            try:
                installation_id = connection["credential_reference"]["installation_id"]
                installation = self._budgeted_call(
                    lambda install_id=installation_id: self._app.get_installation(install_id),
                    budget=budget,
                )
                if installation.get("account_id") != connection["configuration"]["account_id"]:
                    raise GitHubSourceError("installation_account_mismatch")
                snapshot = self._snapshot(
                    installation_id=installation_id,
                    repository=selected_repository,
                    budget=budget,
                    repositories_remaining=1,
                    pinned_revision=progress.get("revision"),
                    pinned_default_branch=progress.get("default_branch"),
                    on_revision=pin,
                    resumable=True,
                )
            except GitHubCheckpointRejected:
                raise
            except _GitHubRequestBudgetReached as error:
                budget_reached = True
                if error.code in {"github_rate_limited", "github_rate_limit_reserve_reached"}:
                    requests += budget.requests
                    return result(
                        pending=True,
                        delay=budget.retry_after_seconds or MAX_RESUME_DELAY_SECONDS,
                    )
                current_progress = saved["repositories"].setdefault(key, {})
                count = current_progress.get("interruption_count", 0) + 1
                current_progress["interruption_count"] = count
                fence()
                if count < MAX_REPOSITORY_INTERRUPTION_COUNT:
                    requests += budget.requests
                    return result(pending=True)
                completed = self._record_partial_repository(
                    tenant_id=tenant_id,
                    connection_id=str(connection["id"]),
                    selected_repository=selected_repository,
                    repository=repository,
                    detail="github_collection_retry_limit_reached",
                    revision=current_progress.get("revision"),
                    default_branch=current_progress.get("default_branch"),
                )
            except Exception as error:
                code = (
                    error.code
                    if isinstance(error, GitHubSourceError)
                    else _github_request_error_code(error)
                )
                if code not in _TERMINAL_SOURCE_ERRORS:
                    # Unexpected/provider transient failures are durable worker retries,
                    # never a fabricated source conclusion or a completed repository.
                    raise
                fence()
                full_name = selected_repository["full_name"]
                repository.ingest(
                    tenant_id,
                    _source_batch(
                        connection_id=str(connection["id"]),
                        repository_name=f"github.com/{full_name}",
                        repository_id=selected_repository["id"],
                        state=CoverageState.FAILED,
                        detail=code,
                    ),
                )
                completed = {
                    "repository_id": selected_repository["id"],
                    "repository": full_name,
                    "state": "failed",
                    "detail": code,
                }
            else:
                fence()
                completed = self._analyze_snapshot(
                    tenant_id=tenant_id,
                    connection_id=str(connection["id"]),
                    snapshot=snapshot,
                    targets=targets,
                    repository=repository,
                    before_ingest=fence,
                )
            requests += budget.requests
            budget_reached = budget_reached or budget.reached
            saved["repositories"].setdefault(key, {})["result"] = completed
            fence()
            processed += 1
        return result(pending=False)

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
        pinned_revision: str | None = None,
        pinned_default_branch: str | None = None,
        on_revision: Callable[[str, str | None], None] | None = None,
        resumable: bool = False,
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
        default_branch = (
            pinned_default_branch if pinned_revision is not None else metadata.get("default_branch")
        )
        if pinned_revision == "empty":
            return _empty_snapshot(repository_id, full_name, default_branch=default_branch)
        if pinned_revision is None and (not isinstance(default_branch, str) or not default_branch):
            if on_revision is not None:
                on_revision("empty", None)
            return _empty_snapshot(repository_id, full_name, default_branch=None)
        commit = pinned_revision
        if commit is None:
            try:
                ref = self._json(
                    "GET",
                    f"/repos/{full_name}/git/ref/{quote(f'heads/{default_branch}', safe='/')}",
                    token=token,
                    budget=budget,
                )
            except GitHubSourceError as error:
                if error.code == "github_conflict":
                    if on_revision is not None:
                        on_revision("empty", default_branch)
                    return _empty_snapshot(repository_id, full_name, default_branch=default_branch)
                raise
            commit = ref.get("object", {}).get("sha")
        if not isinstance(commit, str) or not _COMMIT_SHA.fullmatch(commit):
            raise GitHubSourceError("invalid_immutable_revision")
        if on_revision is not None and pinned_revision is None:
            on_revision(commit, default_branch)
        tree = self._json(
            "GET",
            f"/repos/{full_name}/git/trees/{commit}",
            token=token,
            budget=budget,
            params={"recursive": "1"},
        )
        entries = tree.get("tree")
        if not isinstance(entries, list):
            raise GitHubSourceError("repository_tree_incomplete")
        if tree.get("truncated") is not False or len(entries) > MAX_TREE_ENTRIES:
            if resumable and (tree.get("truncated") is True or len(entries) > MAX_TREE_ENTRIES):
                entries = self._walk_tree(full_name, commit, token=token, budget=budget)
            elif tree.get("truncated") is not False:
                raise GitHubSourceError("repository_tree_incomplete")
            else:
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

        blob_allowance = (
            len(selected_entries) if resumable else budget.blob_allowance(repositories_remaining)
        )
        fetch_entries = selected_entries[:blob_allowance]
        request_skipped = len(selected_entries) - len(fetch_entries)
        if request_skipped > 0:
            warnings.append(
                "connection GitHub request budget selected "
                f"{len(fetch_entries)} of {len(selected_entries)} repository-budgeted files"
            )

        def fetch_blob(
            entry: tuple[str, str, int],
        ) -> tuple[str, bytes] | _GitHubRequestBudgetReached:
            path, sha, expected_size = entry
            try:
                blob = self._json(
                    "GET",
                    f"/repos/{full_name}/git/blobs/{sha}",
                    token=token,
                    budget=budget,
                )
            except _GitHubRequestBudgetReached as error:
                return error
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
        files = [item for item in fetched if isinstance(item, tuple)]
        stop_codes = sorted(
            {item.code for item in fetched if isinstance(item, _GitHubRequestBudgetReached)}
        )
        if resumable and stop_codes:
            # A concurrent blob can exhaust the local budget while another sees
            # provider throttling; honor the cooldown whenever either saw it.
            rate_stop = next(
                (
                    code
                    for code in stop_codes
                    if code in {"github_rate_limited", "github_rate_limit_reserve_reached"}
                ),
                None,
            )
            raise _GitHubRequestBudgetReached(rate_stop or stop_codes[0])
        if len(files) < len(fetch_entries):
            warnings.append(
                "GitHub source retrieval stopped"
                f" ({', '.join(stop_codes) or 'github_request_budget_reached'}); "
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

    def _walk_tree(
        self, full_name: str, commit: str, *, token: str, budget: _GitHubRequestBudget
    ) -> list[dict[str, Any]]:
        """Walk immutable non-recursive trees, pruning before requesting child trees."""

        pending = deque([("", commit, 0)])
        entries: list[dict[str, Any]] = []
        paths: set[str] = set()
        requests = inspected = relevant = 0
        while pending:
            if requests >= MAX_TREE_REQUESTS:
                raise GitHubSourceError("repository_tree_request_limit_exceeded")
            prefix, sha, depth = pending.popleft()
            # Omitting recursive is intentional; even recursive=0 enables recursion.
            payload = self._json(
                "GET", f"/repos/{full_name}/git/trees/{sha}", token=token, budget=budget
            )
            requests += 1
            children = payload.get("tree")
            observed_sha = payload.get("sha")
            if (
                payload.get("truncated") is not False
                or not isinstance(children, list)
                or not isinstance(observed_sha, str)
                or not _BLOB_SHA.fullmatch(observed_sha)
                or (prefix and observed_sha != sha)
            ):
                raise GitHubSourceError("repository_tree_incomplete")
            inspected += len(children)
            if inspected > MAX_TREE_INSPECTED_ENTRIES:
                raise GitHubSourceError("repository_tree_inspection_limit_exceeded")
            for child in children:
                if not isinstance(child, dict):
                    raise GitHubSourceError("invalid_tree_entry")
                name = child.get("path")
                if (
                    not isinstance(name, str)
                    or name in {"", ".", ".."}
                    or "/" in name
                    or len(name) > 255
                    or any(ord(char) < 32 for char in name)
                    or _safe_repository_path(name) != name
                ):
                    raise GitHubSourceError("invalid_tree_path")
                path = f"{prefix}/{name}" if prefix else name
                if len(path) > 1024 or path in paths:
                    raise GitHubSourceError("invalid_tree_path")
                paths.add(path)
                kind, mode = child.get("type"), child.get("mode")
                if kind == "tree":
                    if mode != "040000":
                        raise GitHubSourceError("invalid_tree_mode")
                    if name in _EXCLUDED_PARTS or name.startswith("."):
                        continue
                    child_sha = child.get("sha")
                    if not isinstance(child_sha, str) or not _BLOB_SHA.fullmatch(child_sha):
                        raise GitHubSourceError("invalid_tree_identity")
                    if depth >= MAX_TREE_WALK_DEPTH or len(pending) + requests >= MAX_TREE_REQUESTS:
                        raise GitHubSourceError("repository_tree_request_limit_exceeded")
                    pending.append((path, child_sha, depth + 1))
                elif kind == "blob":
                    if mode == "120000":
                        continue
                    if mode not in {"100644", "100755"}:
                        raise GitHubSourceError("invalid_tree_mode")
                    if not _eligible_path(path):
                        continue
                    child_sha, size = child.get("sha"), child.get("size")
                    if (
                        not isinstance(child_sha, str)
                        or not _BLOB_SHA.fullmatch(child_sha)
                        or type(size) is not int
                        or size < 0
                    ):
                        raise GitHubSourceError("invalid_blob_identity")
                    entries.append({**child, "path": path})
                elif kind == "commit" and mode == "160000":
                    continue
                else:
                    raise GitHubSourceError("invalid_tree_entry")
                relevant += 1
                if relevant > MAX_TREE_ENTRIES:
                    raise GitHubSourceError("repository_tree_limit_exceeded")
        return entries

    def _record_partial_repository(
        self,
        *,
        tenant_id: str,
        connection_id: str,
        selected_repository: dict[str, Any],
        repository: InventorySink,
        detail: str,
        revision: str | None = None,
        default_branch: str | None = None,
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
                commit=revision,
                default_branch=default_branch,
            ),
        )
        return {
            "repository_id": selected_repository.get("id"),
            "repository": full_name,
            "state": "partial",
            "detail": detail,
            "files": 0,
            "bytes": 0,
            **({"revision": revision} if revision is not None else {}),
        }

    def _analyze_snapshot(
        self,
        *,
        tenant_id: str,
        connection_id: str,
        snapshot: GitHubSnapshot,
        targets: tuple[DeploymentTarget, ...],
        repository: InventorySink,
        before_ingest: Callable[[], None] | None = None,
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
            if before_ingest is not None:
                before_ingest()
            source_result = repository.ingest(tenant_id, source_batch)
            if before_ingest is not None:
                before_ingest()
            inventory_result = repository.ingest(tenant_id, inventory_batch)
            if before_ingest is not None:
                before_ingest()
            posture_result = repository.ingest_findings(tenant_id, posture_batch)
            if before_ingest is not None:
                before_ingest()
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
        code: str,
        attempt: int,
        budget: _GitHubRequestBudget | None,
    ) -> bool:
        if code == "github_rate_limited" and budget is not None:
            budget.block("github_rate_limited")
            raise _GitHubRequestBudgetReached("github_rate_limited")
        if (
            code
            in {
                "github_timeout",
                "github_upstream_unavailable",
            }
            and attempt < 2
        ):
            return True
        return False


def github_collection_boundary_hash(tenant_id: str, connection: dict[str, Any]) -> str:
    """Bind a durable run to exact saved identities, not a mutable installation catalog."""

    reference = connection.get("credential_reference")
    configuration = connection.get("configuration")
    if (
        connection.get("provider") != "github"
        or connection.get("lifecycle_state") != "active"
        or not isinstance(reference, dict)
        or not isinstance(configuration, dict)
        or type(reference.get("installation_id")) is not int
        or reference["installation_id"] <= 0
        or type(configuration.get("account_id")) is not int
        or configuration["account_id"] <= 0
    ):
        raise GitHubSourceError("invalid_collection_boundary")
    selected = configuration.get("repositories")
    scopes = connection.get("declared_scopes", [])
    if (
        not isinstance(selected, list)
        or not 1 <= len(selected) <= 500
        or not isinstance(scopes, list)
        or "github.repository_contents" not in scopes
        or any(not isinstance(scope, str) or scope not in GITHUB_SCOPES for scope in scopes)
        or len(set(scopes)) != len(scopes)
    ):
        raise GitHubSourceError("invalid_collection_boundary")
    identities = []
    for item in selected:
        if (
            not isinstance(item, dict)
            or type(item.get("id")) is not int
            or type(item.get("owner_id")) is not int
            or not isinstance(item.get("full_name"), str)
        ):
            raise GitHubSourceError("invalid_repository_boundary")
        try:
            normalized = _repository_boundary(
                {
                    **item,
                    "name": item["full_name"].rsplit("/", 1)[-1],
                    "owner": {"id": item.get("owner_id"), "login": item.get("owner_login")},
                }
            )
        except Exception:
            raise GitHubSourceError("invalid_repository_boundary") from None
        identities.append(
            {
                key: normalized[key]
                for key in ("id", "node_id", "full_name", "owner_id", "owner_login")
            }
        )
        if normalized["owner_id"] != configuration["account_id"]:
            raise GitHubSourceError("invalid_repository_boundary")
    if len({item["id"] for item in identities}) != len(identities):
        raise GitHubSourceError("invalid_repository_boundary")
    boundary = {
        "collection_policy": "github-resumable-source-v1",
        "tenant_id": tenant_id,
        "connection_id": str(connection["id"]),
        "credential_type": connection.get("credential_type"),
        "installation_id": reference["installation_id"],
        "app_id": reference.get("app_id"),
        "app_slug": reference.get("app_slug"),
        "platform_connection_id": reference.get("platform_connection_id"),
        "account_id": configuration["account_id"],
        "account_login": configuration.get("account_login"),
        "repositories": sorted(identities, key=lambda item: item["id"]),
        "scopes": sorted(scopes),
    }
    return hashlib.sha256(
        json.dumps(boundary, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _validated_checkpoint(
    checkpoint: dict[str, Any], boundary_hash: str, selected: list[dict[str, Any]]
) -> dict[str, Any]:
    if not isinstance(checkpoint, dict):
        raise GitHubSourceError("invalid_collection_checkpoint")
    if not checkpoint:
        return {
            "boundary_hash": boundary_hash,
            "repository_count": len(selected),
            "repositories": {},
        }
    if (
        not {"boundary_hash", "repositories"} <= set(checkpoint)
        or not set(checkpoint) <= {"boundary_hash", "repositories", "repository_count"}
        or checkpoint["boundary_hash"] != boundary_hash
        or not isinstance(checkpoint["repositories"], dict)
        or (
            "repository_count" in checkpoint
            and (
                type(checkpoint["repository_count"]) is not int
                or checkpoint["repository_count"] != len(selected)
            )
        )
    ):
        raise GitHubSourceError("collection_checkpoint_boundary_changed")
    by_id = {str(item["id"]): item for item in selected}
    for key, progress in checkpoint["repositories"].items():
        if (
            key not in by_id
            or not isinstance(progress, dict)
            or not set(progress) <= {"revision", "default_branch", "result", "interruption_count"}
        ):
            raise GitHubSourceError("invalid_collection_checkpoint")
        if "interruption_count" in progress and (
            type(progress["interruption_count"]) is not int
            or not 0 <= progress["interruption_count"] <= MAX_REPOSITORY_INTERRUPTION_COUNT
        ):
            raise GitHubSourceError("invalid_collection_checkpoint")
        if "revision" in progress or "default_branch" in progress:
            revision, branch = progress.get("revision"), progress.get("default_branch")
            if (
                not {"revision", "default_branch"} <= set(progress)
                or not isinstance(revision, str)
                or (revision != "empty" and not _COMMIT_SHA.fullmatch(revision))
                or (
                    branch is not None
                    and (
                        not isinstance(branch, str)
                        or not branch
                        or len(branch) > 255
                        or any(ord(char) < 32 for char in branch)
                    )
                )
                or (revision != "empty" and branch is None)
            ):
                raise GitHubSourceError("invalid_collection_checkpoint")
        if "result" in progress:
            _validate_checkpoint_result(progress["result"], by_id[key], progress.get("revision"))
    normalized = deepcopy(checkpoint)
    normalized["repository_count"] = len(selected)
    return normalized


def _validate_checkpoint_result(
    result: Any, selected: dict[str, Any], revision: str | None
) -> None:
    counts = {
        "files",
        "bytes",
        "source_assets",
        "inventory_assets",
        "inventory_relationships",
        "posture_findings",
        "deployment_relationships",
    }
    if (
        not isinstance(result, dict)
        or not set(result)
        <= counts
        | {"repository_id", "repository", "state", "revision", "detail", "coverage", "correlation"}
        or type(result.get("repository_id")) is not int
        or result["repository_id"] != selected["id"]
        or result.get("repository") != selected["full_name"]
        or not isinstance(result.get("state"), str)
        or result["state"] not in {"complete", "partial", "failed"}
        or (
            result["state"] != "failed"
            and revision is None
            and result.get("detail") != "github_collection_retry_limit_reached"
        )
        or (
            result.get("detail") == "github_collection_retry_limit_reached"
            and result["state"] != "partial"
        )
        or ("revision" in result and result["revision"] != revision)
        or any(
            type(result[key]) is not int or not 0 <= result[key] <= 1_000_000_000
            for key in counts & set(result)
        )
        or result.get("files", 0) > MAX_SELECTED_FILES
        or result.get("bytes", 0) > MAX_TOTAL_BYTES
        or (
            "detail" in result
            and (
                not isinstance(result["detail"], str)
                or result["detail"] not in _TERMINAL_SOURCE_ERRORS
            )
        )
    ):
        raise GitHubSourceError("invalid_collection_checkpoint")
    coverage = result.get("coverage", {})
    correlation = result.get("correlation", {})
    coverage_keys = {"source", "inventory", "posture", "correlation"}
    correlation_keys = {"declarations", "proven", "ambiguous", "unmatched", "targets_evaluated"}
    if (
        not isinstance(coverage, dict)
        or not set(coverage) <= coverage_keys
        or any(
            not isinstance(value, str) or value not in {state.value for state in CoverageState}
            for value in coverage.values()
        )
        or not isinstance(correlation, dict)
        or not set(correlation) <= correlation_keys
        or any(
            type(value) is not int or not 0 <= value <= 1_000_000_000
            for value in correlation.values()
        )
    ):
        raise GitHubSourceError("invalid_collection_checkpoint")
    base = {"repository_id", "repository", "state"}
    if result["state"] == "failed":
        valid = set(result) == base | {"detail"}
    elif result.get("detail") == "github_collection_retry_limit_reached":
        valid = (
            set(result)
            == base | {"detail", "files", "bytes"} | ({"revision"} if revision else set())
            and result["files"] == result["bytes"] == 0
        )
    else:
        valid = (
            set(result) == base | counts | {"revision", "coverage", "correlation"}
            and result["revision"] == revision
            and set(coverage) == coverage_keys
            and set(correlation) == correlation_keys
            and (result["state"] == "complete")
            == all(value == CoverageState.COMPLETE.value for value in coverage.values())
        )
    if not valid:
        raise GitHubSourceError("invalid_collection_checkpoint")


def _optional_nonnegative_int(value: Any) -> int | None:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


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
    name = PurePosixPath(path).name
    suffix = PurePosixPath(path).suffix.lower()
    if _is_dependency_manifest(name):
        return 0
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
        or name in {"mcp.json", "claude_desktop_config.json"}
        or _is_dependency_manifest(name)
        or name.lower().startswith("dockerfile")
        or name.endswith(".assets.json")
    )


def _is_dependency_manifest(name: str) -> bool:
    lowered = name.lower()
    return lowered in {"package.json", "pyproject.toml"} or (
        lowered.startswith("requirements") and lowered.endswith(".txt")
    )
