"""Durable provider collection execution."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class Collector(Protocol):
    def collect(
        self, *, tenant_id: str, connection: dict[str, Any], repository: Any
    ) -> dict[str, Any]: ...


class CollectionRepository(Protocol):
    def claim_connection_collection_job(
        self, job_id: str, *, lease_seconds: int
    ) -> dict[str, Any] | None: ...

    def get_connection_validation_target(
        self, tenant_id: str, connection_id: str
    ) -> dict[str, Any] | None: ...

    def complete_connection_collection_job(self, job_id: str, result: dict[str, Any]) -> None: ...

    def record_connection_collection_failure(
        self, job_id: str, summary: str, *, max_attempts: int
    ) -> bool: ...


class RuntimeScheduleRepository(Protocol):
    def list_due_aws_agent_runtime_connections(
        self, *, interval_minutes: int, limit: int
    ) -> list[dict[str, str]]: ...


def queue_due_aws_agent_runtime_collections(
    repository: RuntimeScheduleRepository,
    queue: Callable[[str, str], None],
    *,
    interval_minutes: int = 5,
    limit: int = 200,
) -> dict[str, int]:
    """Dispatch durable jobs for bounded healthy AWS runtime targets."""

    refs = repository.list_due_aws_agent_runtime_connections(
        interval_minutes=interval_minutes, limit=limit
    )
    queued = 0
    failed = 0
    for ref in refs:
        try:
            queue(ref["tenant_id"], ref["connection_id"])
            queued += 1
        except Exception as error:
            failed += 1
            logger.warning(
                "scheduled AWS runtime collection dispatch failed (%s)",
                type(error).__name__,
                extra={
                    "tenant_id": ref["tenant_id"],
                    "connection_id": ref["connection_id"],
                    "collection_kind": "aws_agent_runtime",
                    "error_type": type(error).__name__,
                },
            )
    return {"eligible": len(refs), "queued": queued, "failed": failed}


def run_durable_collection_job(
    repository: CollectionRepository,
    collectors: Mapping[str, Collector | None],
    job_id: str,
    *,
    lease_seconds: int = 2700,
    max_attempts: int = 3,
    on_succeeded: Callable[[str, str, str, dict[str, Any]], None] | None = None,
) -> None:
    """Claim and execute a durable collection job with bounded idempotent retries."""

    if not 1 <= max_attempts <= 5:
        raise ValueError("collection attempts must be between 1 and 5")
    for _attempt in range(max_attempts):
        job = repository.claim_connection_collection_job(job_id, lease_seconds=lease_seconds)
        if job is None:
            return
        tenant_id = str(job["tenant_id"])
        connection_id = str(job["connection_id"])
        collection_kind = str(job["collection_kind"])
        try:
            target = repository.get_connection_validation_target(tenant_id, connection_id)
            if target is None or target["lifecycle_state"] != "active":
                raise RuntimeError("connection is unavailable for collection")
            collector = collectors.get(collection_kind)
            if collector is None:
                raise RuntimeError("connection collector is not configured")
            result = collector.collect(
                tenant_id=tenant_id,
                connection=target,
                repository=repository,
            )
            if on_succeeded is not None:
                on_succeeded(tenant_id, connection_id, collection_kind, result)
            repository.complete_connection_collection_job(job_id, result)
            return
        except Exception as error:
            error_type = type(error).__name__
            logger.warning(
                "connection collection attempt failed (%s)",
                error_type,
                extra={
                    "tenant_id": tenant_id,
                    "connection_id": connection_id,
                    "job_id": job_id,
                    "collection_kind": collection_kind,
                    "error_type": error_type,
                },
            )
            retry = repository.record_connection_collection_failure(
                job_id,
                f"Collection worker could not complete the declared read planes ({error_type}).",
                max_attempts=max_attempts,
            )
            if not retry:
                return
