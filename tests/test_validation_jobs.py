from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from denali.api.validation import run_durable_validation_job


class JobRepository:
    def __init__(self):
        self.claimed = False
        self.validation: dict[str, Any] | None = None
        self.completed = False
        self.failure: str | None = None

    def claim_connection_validation_job(
        self, job_id: str, *, lease_seconds: int
    ) -> dict[str, Any] | None:
        if self.claimed:
            return None
        self.claimed = True
        assert lease_seconds > 300
        return {
            "tenant_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "connection_id": "11111111-1111-4111-8111-111111111111",
            "wait_for_credentials": False,
            "wait_for_healthy": False,
        }

    def get_connection_validation_target(
        self, tenant_id: str, connection_id: str
    ) -> dict[str, Any] | None:
        return {"id": connection_id, "provider": "aws", "lifecycle_state": "active"}

    def record_connection_validation(
        self, tenant_id: str, connection_id: str, validation: dict[str, Any]
    ) -> dict[str, Any] | None:
        self.validation = validation
        return {}

    def complete_connection_validation_job(self, job_id: str) -> None:
        self.completed = True

    def fail_connection_validation_job(self, job_id: str, summary: str) -> None:
        self.failure = summary


class PassingValidator:
    def validate(self, target: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(UTC)
        return {
            "started_at": now,
            "completed_at": now,
            "health_state": "healthy",
            "credential_state": "passed",
            "results": [],
            "summary": "Validation passed.",
        }


class RetryThenPassValidator(PassingValidator):
    def __init__(self):
        self.attempts = 0

    def validate(self, target: dict[str, Any]) -> dict[str, Any]:
        self.attempts += 1
        if self.attempts == 1:
            raise TimeoutError("temporary provider timeout")
        return super().validate(target)


def test_durable_validation_job_claims_records_and_completes_once() -> None:
    repository = JobRepository()
    validators = {"aws": PassingValidator()}

    run_durable_validation_job(
        repository,
        validators,
        "22222222-2222-4222-8222-222222222222",
        timeout_seconds=60,
        retry_seconds=2,
    )
    run_durable_validation_job(
        repository,
        validators,
        "22222222-2222-4222-8222-222222222222",
        timeout_seconds=60,
        retry_seconds=2,
    )

    assert repository.validation is not None
    assert repository.completed is True
    assert repository.failure is None


def test_durable_validation_job_retries_transient_provider_errors() -> None:
    repository = JobRepository()
    validator = RetryThenPassValidator()

    run_durable_validation_job(
        repository,
        {"aws": validator},
        "33333333-3333-4333-8333-333333333333",
        timeout_seconds=60,
        retry_seconds=0,
    )

    assert validator.attempts == 2
    assert repository.completed is True
    assert repository.failure is None


def test_healthy_validation_triggers_collection_before_completion() -> None:
    repository = JobRepository()
    calls: list[tuple[str, str, str]] = []

    run_durable_validation_job(
        repository,
        {"aws": PassingValidator()},
        "44444444-4444-4444-8444-444444444444",
        timeout_seconds=60,
        retry_seconds=0,
        on_healthy=lambda tenant_id, connection_id, provider: calls.append(
            (tenant_id, connection_id, provider)
        ),
    )

    assert calls == [
        (
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "11111111-1111-4111-8111-111111111111",
            "aws",
        )
    ]
    assert repository.completed is True


def test_non_healthy_validation_does_not_trigger_collection() -> None:
    class PartialValidator(PassingValidator):
        def validate(self, target: dict[str, Any]) -> dict[str, Any]:
            result = super().validate(target)
            result["health_state"] = "partial"
            return result

    repository = JobRepository()
    calls: list[tuple[str, str, str]] = []
    run_durable_validation_job(
        repository,
        {"aws": PartialValidator()},
        "55555555-5555-4555-8555-555555555555",
        timeout_seconds=60,
        retry_seconds=0,
        on_healthy=lambda *values: calls.append(values),
    )

    assert calls == []
    assert repository.completed is True


def test_collection_dispatch_failure_does_not_relabel_healthy_validation() -> None:
    repository = JobRepository()

    def fail_dispatch(*_values: str) -> None:
        raise RuntimeError("temporary dispatcher failure")

    run_durable_validation_job(
        repository,
        {"aws": PassingValidator()},
        "66666666-6666-4666-8666-666666666666",
        timeout_seconds=60,
        retry_seconds=0,
        on_healthy=fail_dispatch,
    )

    assert repository.validation is not None
    assert repository.completed is True
    assert repository.failure is None
