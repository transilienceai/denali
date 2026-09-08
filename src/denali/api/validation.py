"""Durable provider-connection validation execution."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from time import monotonic, sleep
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class Validator(Protocol):
    def validate(self, target: dict[str, Any]) -> dict[str, Any]: ...


class ValidationRepository(Protocol):
    def claim_connection_validation_job(
        self, job_id: str, *, lease_seconds: int
    ) -> dict[str, Any] | None: ...

    def get_connection_validation_target(
        self, tenant_id: str, connection_id: str
    ) -> dict[str, Any] | None: ...

    def record_connection_validation(
        self, tenant_id: str, connection_id: str, validation: dict[str, Any]
    ) -> dict[str, Any] | None: ...

    def complete_connection_validation_job(self, job_id: str) -> None: ...

    def fail_connection_validation_job(self, job_id: str, summary: str) -> None: ...


def run_durable_validation_job(
    repository: ValidationRepository,
    validators: Mapping[str, Validator | None],
    job_id: str,
    *,
    timeout_seconds: int,
    retry_seconds: int,
    max_error_attempts: int = 3,
    on_healthy: Callable[[str, str, str], None] | None = None,
) -> None:
    """Claim and execute a database-backed validation job exactly once per lease."""

    job = repository.claim_connection_validation_job(
        job_id, lease_seconds=timeout_seconds + 300
    )
    if job is None:
        return
    tenant_id = str(job["tenant_id"])
    connection_id = str(job["connection_id"])
    try:
        target = repository.get_connection_validation_target(tenant_id, connection_id)
        if target is None:
            raise RuntimeError("connection no longer exists")
        if target["lifecycle_state"] != "active":
            raise RuntimeError("connection is disabled")
        validator = validators.get(str(target["provider"]))
        if validator is None:
            raise RuntimeError("connection validator is not configured")

        deadline = monotonic() + timeout_seconds
        consecutive_errors = 0
        while True:
            try:
                validation = validator.validate(target)
                consecutive_errors = 0
            except Exception:
                consecutive_errors += 1
                if consecutive_errors >= max_error_attempts or monotonic() >= deadline:
                    raise
                logger.warning(
                    "connection validation attempt failed; retrying",
                    extra={
                        "tenant_id": tenant_id,
                        "connection_id": connection_id,
                        "validation_job_id": job_id,
                        "attempt": consecutive_errors,
                    },
                    exc_info=True,
                )
                sleep(min(retry_seconds, max(0, deadline - monotonic())))
                continue
            credentials_pending = (
                bool(job["wait_for_credentials"])
                and validation["credential_state"] != "passed"
            )
            coverage_pending = (
                bool(job["wait_for_healthy"])
                and validation["health_state"] != "healthy"
            )
            if not (credentials_pending or coverage_pending) or monotonic() >= deadline:
                repository.record_connection_validation(
                    tenant_id, connection_id, validation
                )
                if (
                    on_healthy is not None
                    and validation["credential_state"] == "passed"
                    and validation["health_state"] == "healthy"
                ):
                    try:
                        on_healthy(tenant_id, connection_id, str(target["provider"]))
                    except Exception as error:
                        logger.warning(
                            "automatic collection dispatch failed after healthy validation",
                            extra={
                                "tenant_id": tenant_id,
                                "connection_id": connection_id,
                                "validation_job_id": job_id,
                                "error_type": type(error).__name__,
                            },
                        )
                repository.complete_connection_validation_job(job_id)
                return
            sleep(min(retry_seconds, max(0, deadline - monotonic())))
    except Exception as error:
        logger.exception(
            "connection validation failed",
            extra={
                "tenant_id": tenant_id,
                "connection_id": connection_id,
                "validation_job_id": job_id,
            },
        )
        repository.fail_connection_validation_job(
            job_id, f"Validation failed ({type(error).__name__})."
        )
