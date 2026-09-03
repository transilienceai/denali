from __future__ import annotations

from typing import Any

import pytest

from denali.api.collection import run_durable_collection_job


class DurableCollectionRepository:
    def __init__(self, *, stale_running: bool = False):
        self.job = {
            "tenant_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "connection_id": "11111111-1111-4111-8111-111111111111",
            "collection_kind": "entra_ai",
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

    def complete_connection_collection_job(
        self, job_id: str, result: dict[str, Any]
    ) -> None:
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
        "Collection worker could not complete the declared read planes."
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
