"""Bounded operator maintenance over durable provider jobs."""

from __future__ import annotations

import argparse
import json
import subprocess
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


def invoke_deployed_maintenance(
    action: str,
    *,
    limit: int,
    function_loader: Callable[..., Any] | None = None,
) -> Any:
    """Call the deployed production graph instead of creating an ephemeral Modal app."""

    if action not in {"refresh", "status"}:
        raise ValueError("maintenance action must be refresh or status")
    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    if function_loader is None:
        import modal

        function_loader = modal.Function.from_name
    function_name = (
        "refresh_active_connections" if action == "refresh" else "active_connection_status"
    )
    function = function_loader(
        "denali-production",
        function_name,
        environment_name="denali-prod",
    )
    return function.remote(limit)


def _git_output(*args: str) -> str:
    return subprocess.run(
        ("git", *args),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _require_clean_current_main() -> None:
    if _git_output("status", "--porcelain"):
        raise RuntimeError("production maintenance requires a clean worktree")
    _git_output("fetch", "--quiet", "origin", "main")
    head = _git_output("rev-parse", "HEAD")
    remote_main = _git_output("rev-parse", "origin/main")
    if head != remote_main:
        raise RuntimeError("production maintenance requires the current origin/main revision")


def operator_main() -> None:
    parser = argparse.ArgumentParser(
        description="Invoke the deployed Denali production connection maintenance functions"
    )
    parser.add_argument("action", choices=("refresh", "status"))
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--confirm-production", action="store_true")
    args = parser.parse_args()
    if not args.confirm_production:
        raise SystemExit("refusing production maintenance without --confirm-production")
    try:
        _require_clean_current_main()
        result = invoke_deployed_maintenance(args.action, limit=args.limit)
    except (RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from error
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    operator_main()
