from __future__ import annotations

from typing import Any

import pytest

from denali.api.collection import (
    queue_due_aws_agent_runtime_collections,
    run_durable_collection_job,
)


class DurableCollectionRepository:
    def __init__(self, *, stale_running: bool = False, collection_kind: str = "entra_ai"):
        self.job = {
            "tenant_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "connection_id": "11111111-1111-4111-8111-111111111111",
            "collection_kind": collection_kind,
            "state": "running" if stale_running else "queued",
            "lease_expired": stale_running,
            "attempt_count": 0,
        }
        self.completed: dict[str, Any] | None = None
        self.failures: list[str] = []

    def claim_connection_collection_job(
        self, job_id: str, *, lease_seconds: int
    ) -> dict[str, Any] | None:
        assert lease_seconds > 0
        if self.job["state"] == "queued" or (
            self.job["state"] == "running" and self.job["lease_expired"]
        ):
            self.job.update(
                state="running",
                lease_expired=False,
                attempt_count=self.job["attempt_count"] + 1,
            )
            return dict(self.job)
        return None

    def get_connection_validation_target(
        self, tenant_id: str, connection_id: str
    ) -> dict[str, Any] | None:
        return {"id": connection_id, "provider": "entra", "lifecycle_state": "active"}

    def complete_connection_collection_job(self, job_id: str, result: dict[str, Any]) -> None:
        self.completed = result
        self.job["state"] = "succeeded"

    def record_connection_collection_failure(
        self, job_id: str, summary: str, *, max_attempts: int
    ) -> bool:
        self.failures.append(summary)
        retry = self.job["attempt_count"] < max_attempts
        self.job["state"] = "queued" if retry else "failed"
        return retry


class Collector:
    def __init__(self, failures: list[Exception] | None = None):
        self.failures = failures or []
        self.calls = 0

    def collect(
        self, *, tenant_id: str, connection: dict[str, Any], repository: Any
    ) -> dict[str, Any]:
        self.calls += 1
        if self.failures:
            raise self.failures.pop(0)
        return {"state": "complete", "connection_id": connection["id"]}


def test_collection_job_survives_api_replacement_and_duplicate_worker_delivery() -> None:
    repository = DurableCollectionRepository()
    collector = Collector()

    run_durable_collection_job(repository, {"entra_ai": collector}, "job-fixture")
    run_durable_collection_job(repository, {"entra_ai": collector}, "job-fixture")

    assert collector.calls == 1
    assert repository.completed == {
        "state": "complete",
        "connection_id": "11111111-1111-4111-8111-111111111111",
    }


@pytest.mark.parametrize(
    "collection_kind",
    [
        "aws_deployments",
        "aws_agent_runtime",
        "azure_deployments",
        "entra_ai",
        "gcp_deployments",
        "github_source",
        "azure_repos_source",
    ],
)
def test_every_provider_collection_kind_uses_the_durable_worker(
    collection_kind: str,
) -> None:
    repository = DurableCollectionRepository(collection_kind=collection_kind)
    collector = Collector()

    run_durable_collection_job(
        repository,
        {collection_kind: collector},
        "job-fixture",
    )

    assert collector.calls == 1
    assert repository.job["state"] == "succeeded"


def test_collection_job_reclaims_a_stale_worker_lease() -> None:
    repository = DurableCollectionRepository(stale_running=True)

    run_durable_collection_job(repository, {"entra_ai": Collector()}, "job-fixture")

    assert repository.job["state"] == "succeeded"
    assert repository.job["attempt_count"] == 1


@pytest.mark.parametrize("failure", [TimeoutError("timeout"), RuntimeError("worker failed")])
def test_collection_job_retries_transient_timeout_and_worker_failure(failure: Exception) -> None:
    repository = DurableCollectionRepository()
    collector = Collector([failure])

    run_durable_collection_job(repository, {"entra_ai": collector}, "job-fixture")

    assert collector.calls == 2
    assert repository.job["state"] == "succeeded"
    assert repository.failures == [
        f"Collection worker could not complete the declared read planes ({type(failure).__name__})."
    ]


def test_collection_job_stops_after_bounded_failures_without_leaking_error() -> None:
    repository = DurableCollectionRepository()
    collector = Collector(
        [
            RuntimeError("secret-provider-payload-one"),
            RuntimeError("secret-provider-payload-two"),
            RuntimeError("secret-provider-payload-three"),
        ]
    )

    run_durable_collection_job(
        repository,
        {"entra_ai": collector},
        "job-fixture",
        max_attempts=3,
    )

    assert collector.calls == 3
    assert repository.job["state"] == "failed"
    assert all("secret-provider" not in summary for summary in repository.failures)
    assert (
        repository.failures
        == ["Collection worker could not complete the declared read planes (RuntimeError)."] * 3
    )


def test_successful_collection_runs_post_processing_before_completion() -> None:
    repository = DurableCollectionRepository(collection_kind="gcp_deployments")
    calls: list[tuple[str, str, str, dict[str, Any]]] = []

    run_durable_collection_job(
        repository,
        {"gcp_deployments": Collector()},
        "job-fixture",
        on_succeeded=lambda *values: calls.append(values),
    )

    assert calls == [
        (
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "11111111-1111-4111-8111-111111111111",
            "gcp_deployments",
            {
                "state": "complete",
                "connection_id": "11111111-1111-4111-8111-111111111111",
            },
        )
    ]
    assert repository.job["state"] == "succeeded"


def test_failed_post_processing_retries_the_durable_collection() -> None:
    repository = DurableCollectionRepository()
    collector = Collector()
    attempts = 0

    def post_process(*_values: Any) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("temporary evaluation failure")

    run_durable_collection_job(
        repository,
        {"entra_ai": collector},
        "job-fixture",
        on_succeeded=post_process,
    )

    assert collector.calls == 2
    assert attempts == 2
    assert repository.job["state"] == "succeeded"


class RuntimeScheduleRepository:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int]] = []

    def list_due_aws_agent_runtime_connections(
        self, *, interval_minutes: int, limit: int
    ) -> list[dict[str, str]]:
        self.calls.append((interval_minutes, limit))
        return [
            {"tenant_id": "tenant-1", "connection_id": "connection-1"},
            {"tenant_id": "tenant-2", "connection_id": "connection-2"},
        ]


def test_runtime_schedule_only_queues_durable_connection_identifiers() -> None:
    repository = RuntimeScheduleRepository()
    queued: list[tuple[str, str]] = []

    result = queue_due_aws_agent_runtime_collections(
        repository,
        lambda tenant_id, connection_id: queued.append((tenant_id, connection_id)),
    )

    assert repository.calls == [(5, 200)]
    assert queued == [
        ("tenant-1", "connection-1"),
        ("tenant-2", "connection-2"),
    ]
    assert result == {"eligible": 2, "queued": 2, "failed": 0}


def test_runtime_schedule_isolates_one_dispatch_failure() -> None:
    repository = RuntimeScheduleRepository()
    queued: list[str] = []

    def queue(_tenant_id: str, connection_id: str) -> None:
        if connection_id == "connection-1":
            raise RuntimeError("dispatch unavailable")
        queued.append(connection_id)

    result = queue_due_aws_agent_runtime_collections(repository, queue)

    assert queued == ["connection-2"]
    assert result == {"eligible": 2, "queued": 1, "failed": 1}
