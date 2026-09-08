"""Bounded operator maintenance over durable provider jobs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol


class MaintenanceRepository(Protocol):
    def list_active_connection_refs(self, *, limit: int) -> list[dict[str, str]]: ...

    def create_connection_validation_job(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        wait_for_credentials: bool,
        wait_for_healthy: bool,
    ) -> tuple[dict[str, Any], bool]: ...

    def set_connection_validation_call_id(self, job_id: str, call_id: str) -> None: ...

    def fail_connection_validation_job(self, job_id: str, summary: str) -> None: ...


def dispatch_active_connection_refresh(
    repository: MaintenanceRepository,
    spawn_validation: Callable[[str], str],
    *,
    limit: int,
) -> dict[str, int]:
    """Create durable validation jobs for a bounded operator-selected global set."""

    rows = repository.list_active_connection_refs(limit=limit)
    summary = {"active": len(rows), "dispatched": 0, "already_running": 0, "failed": 0}
    for row in rows:
        tenant_id = str(row["tenant_id"])
        connection_id = str(row["connection_id"])
        job, created = repository.create_connection_validation_job(
            tenant_id,
            connection_id,
            wait_for_credentials=False,
            wait_for_healthy=False,
        )
        if not created:
            summary["already_running"] += 1
            continue
        job_id = str(job["id"])
        try:
            call_id = spawn_validation(job_id)
            repository.set_connection_validation_call_id(job_id, call_id)
            summary["dispatched"] += 1
        except Exception:
            repository.fail_connection_validation_job(
                job_id, "Unable to dispatch operator-requested validation worker."
            )
            summary["failed"] += 1
    return summary
