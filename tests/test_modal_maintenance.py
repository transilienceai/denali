from __future__ import annotations

from typing import Any

from denali.api.maintenance import dispatch_active_connection_refresh


class MaintenanceRepository:
    def __init__(self, *, already_running: set[str] | None = None) -> None:
        self.already_running = already_running or set()
        self.call_ids: list[tuple[str, str]] = []
        self.failures: list[tuple[str, str]] = []

    def list_active_connection_refs(self, *, limit: int) -> list[dict[str, str]]:
        assert limit == 10
        return [
            {
                "tenant_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "connection_id": "11111111-1111-4111-8111-111111111111",
                "provider": "aws",
                "health_state": "healthy",
            },
            {
                "tenant_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                "connection_id": "22222222-2222-4222-8222-222222222222",
                "provider": "gcp",
                "health_state": "partial",
            },
        ]

    def create_connection_validation_job(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        wait_for_credentials: bool,
        wait_for_healthy: bool,
    ) -> tuple[dict[str, Any], bool]:
        assert wait_for_credentials is False
        assert wait_for_healthy is False
        return (
            {"id": f"job-{connection_id}", "tenant_id": tenant_id},
            connection_id not in self.already_running,
        )

    def set_connection_validation_call_id(self, job_id: str, call_id: str) -> None:
        self.call_ids.append((job_id, call_id))

    def fail_connection_validation_job(self, job_id: str, summary: str) -> None:
        self.failures.append((job_id, summary))


def test_operator_refresh_dispatches_bounded_durable_jobs() -> None:
    repository = MaintenanceRepository(
        already_running={"22222222-2222-4222-8222-222222222222"}
    )

    result = dispatch_active_connection_refresh(
        repository,
        lambda job_id: f"call-{job_id}",
        limit=10,
    )

    assert result == {"active": 2, "dispatched": 1, "already_running": 1, "failed": 0}
    assert repository.call_ids == [
        (
            "job-11111111-1111-4111-8111-111111111111",
            "call-job-11111111-1111-4111-8111-111111111111",
        )
    ]
    assert repository.failures == []


def test_operator_refresh_fails_closed_per_job_without_stopping_the_batch() -> None:
    repository = MaintenanceRepository()

    def spawn(job_id: str) -> str:
        if "11111111" in job_id:
            raise RuntimeError("provider-secret-material")
        return f"call-{job_id}"

    result = dispatch_active_connection_refresh(repository, spawn, limit=10)

    assert result == {"active": 2, "dispatched": 1, "already_running": 0, "failed": 1}
    assert repository.call_ids == [
        (
            "job-22222222-2222-4222-8222-222222222222",
            "call-job-22222222-2222-4222-8222-222222222222",
        )
    ]
    assert repository.failures == [
        (
            "job-11111111-1111-4111-8111-111111111111",
            "Unable to dispatch operator-requested validation worker.",
        )
    ]
