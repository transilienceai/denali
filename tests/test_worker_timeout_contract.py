"""Durable leases outlive the actual Modal hard timeout, not a soft deadline."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from denali import worker_limits
from denali.api.collection import run_durable_collection_job
from denali.api.evidence_import import run_durable_vulnerability_import_job
from denali.api.validation import run_durable_validation_job


class LeaseRecorder:
    lease_seconds: int | None = None

    def claim_connection_validation_job(self, _job_id, *, lease_seconds):
        self.lease_seconds = lease_seconds
        return None

    claim_connection_collection_job = claim_connection_validation_job
    claim_vulnerability_import_job = claim_connection_validation_job


@pytest.mark.parametrize(
    "worker,timeout_name,lease_name,expected_timeout,expected_lease",
    [
        (
            "validation_worker",
            "VALIDATION_WORKER_TIMEOUT_SECONDS",
            "VALIDATION_WORKER_LEASE_SECONDS",
            2400,
            2700,
        ),
        (
            "collection_worker",
            "COLLECTION_WORKER_TIMEOUT_SECONDS",
            "COLLECTION_WORKER_LEASE_SECONDS",
            2400,
            2700,
        ),
        (
            "vulnerability_import_worker",
            "VULNERABILITY_IMPORT_WORKER_TIMEOUT_SECONDS",
            "VULNERABILITY_IMPORT_WORKER_LEASE_SECONDS",
            1200,
            1500,
        ),
    ],
)
def test_modal_hard_timeout_and_actual_default_claim_share_aligned_limits(
    worker, timeout_name, lease_name, expected_timeout, expected_lease
):
    source = Path(__file__).resolve().parents[1] / "modal_app.py"
    module = ast.parse(source.read_text())
    function = next(
        node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == worker
    )
    decorator = next(
        node
        for node in function.decorator_list
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "app"
        and node.func.attr == "function"
    )
    timeout = next(keyword.value for keyword in decorator.keywords if keyword.arg == "timeout")
    assert isinstance(timeout, ast.Name) and timeout.id == timeout_name
    assert any(
        isinstance(node, ast.ImportFrom)
        and node.module == "denali.worker_limits"
        and any(alias.name == timeout_name and alias.asname is None for alias in node.names)
        for node in module.body
    )
    runner = {
        "validation_worker": "run_durable_validation_job",
        "collection_worker": "run_durable_collection_job",
        "vulnerability_import_worker": "run_durable_vulnerability_import_job",
    }[worker]
    invocation = next(
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == runner
    )
    # The deployed invocation must use the default claim verified below, not
    # silently override it with a shorter lease or unknown expanded kwargs.
    assert not any(keyword.arg in {"lease_seconds", None} for keyword in invocation.keywords)
    hard_timeout = getattr(worker_limits, timeout_name)
    lease = getattr(worker_limits, lease_name)
    assert hard_timeout == expected_timeout
    assert lease == expected_lease
    assert lease >= hard_timeout + worker_limits.WORKER_LEASE_GRACE_SECONDS

    repository = LeaseRecorder()
    if worker == "validation_worker":
        run_durable_validation_job(repository, {}, "job", timeout_seconds=60, retry_seconds=0)
    elif worker == "collection_worker":
        run_durable_collection_job(repository, {}, "job")
    else:
        run_durable_vulnerability_import_job(repository, None, "job")
    assert repository.lease_seconds == lease


def test_validation_retains_longer_native_soft_deadline_lease():
    repository = LeaseRecorder()
    run_durable_validation_job(repository, {}, "job", timeout_seconds=3600, retry_seconds=0)
    assert repository.lease_seconds == 3600 + worker_limits.WORKER_LEASE_GRACE_SECONDS
