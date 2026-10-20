"""An ambiguous first GitHub delivery never terminalizes its durable job."""

from __future__ import annotations

import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from test_gateway_capabilities import (
    ASSET,
    JobRepository,
    Memberships,
    SessionAuthenticator,
    Verifier,
)

from denali.api.app import DEFAULT_LOCAL_TENANT, create_app
from denali.api.collection import queue_due_github_collection_jobs

JOB_ID = "22222222-2222-4222-8222-222222222222"


class DispatchRepository(JobRepository):
    def __init__(self, *, provider="github", stage="spawn"):
        super().__init__()
        self.provider = provider
        self.stage = stage
        self.state = "queued"
        self.created = False
        self.dispatches = []
        self.failed = []
        self.checkpoint = {"version": 1, "completed": {}}

    def get_connection_validation_target(self, tenant_id, connection_id):
        if tenant_id not in {DEFAULT_LOCAL_TENANT, "tenant-alpha"} or connection_id != ASSET:
            return None
        return {
            "id": ASSET,
            "provider": self.provider,
            "lifecycle_state": "active",
            "configuration": {"repositories": [{"id": 17}], "subscriptions": [{"id": ASSET}]},
            "declared_scopes": [
                "github.repository_contents" if self.provider == "github" else "azure.ai_services"
            ],
        }

    def create_connection_collection_job(self, tenant_id, connection_id, *, collection_kind):
        assert connection_id == ASSET
        assert collection_kind == (
            "github_source" if self.provider == "github" else "azure_deployments"
        )
        created = not self.created
        self.created = True
        return {"id": JOB_ID}, created

    def set_connection_collection_call_id(self, job_id, call_id):
        if self.stage == "call_id":
            raise TimeoutError("private acknowledgement material")
        super().set_connection_collection_call_id(job_id, call_id)

    def fail_connection_collection_job(self, job_id, summary):
        self.failed.append((job_id, summary))
        self.state = "failed"

    def dispatch(self, job_id):
        self.dispatches.append(job_id)
        if self.stage == "spawn":
            raise TimeoutError("private dispatch material")
        # A worker may claim or even finish before spawn acknowledgement returns.
        self.state = "succeeded" if self.stage == "finished" else "running"
        if self.stage in {"ack", "finished"}:
            raise TimeoutError("private acknowledgement material")
        return "call-fixture"

    def list_due_github_collection_jobs(self, *, limit):
        assert limit == 100
        return [JOB_ID] if self.state == "queued" else []


@pytest.mark.parametrize("stage", ["spawn", "ack", "call_id", "finished"])
def test_browser_github_acceptance_survives_lost_dispatch_or_call_id_write(stage, caplog):
    repository = DispatchRepository(stage=stage)
    app = create_app(
        repository=repository,
        auth_mode="local",
        github_repository_collector=object(),
        collection_dispatcher=repository.dispatch,
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        response = client.post(f"/v1/connections/{ASSET}/github/collect")
        # A later explicit refresh is allowed after a terminal run. Only active
        # duplicate starts share the existing job at the browser boundary.
        duplicate = (
            client.post(f"/v1/connections/{ASSET}/github/collect") if stage != "finished" else None
        )
    assert response.status_code == 202
    assert response.json() == {"status": "started", "connection_id": ASSET}
    if duplicate is not None:
        assert duplicate.status_code == 202
        assert duplicate.json() == {"status": "already_running", "connection_id": ASSET}
    assert repository.failed == []
    assert repository.state == {"spawn": "queued", "finished": "succeeded"}.get(stage, "running")
    assert repository.dispatches == [JOB_ID]
    assert repository.checkpoint == {"version": 1, "completed": {}}
    assert "private" not in caplog.text
    if stage == "spawn":
        recovered = []
        assert queue_due_github_collection_jobs(repository, recovered.append)["queued"] == 1
        assert recovered == [JOB_ID]


@pytest.mark.parametrize("stage", ["spawn", "ack", "call_id", "finished"])
def test_gateway_github_keeps_same_idempotent_receipt_when_delivery_is_ambiguous(stage, caplog):
    repository = DispatchRepository(stage=stage)
    app = create_app(
        repository=repository,
        auth_mode="clerk",
        authenticator=SessionAuthenticator(),
        results_gateway_verifier=Verifier(),
        gateway_membership_checker=Memberships(),
        github_repository_collector=object(),
        collection_dispatcher=repository.dispatch,
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        arguments = {
            "json": {"confirm": True, "collection_kind": "github_source"},
            "headers": {
                "Authorization": "Bearer admin-write",
                "Idempotency-Key": "github-dispatch-001",
            },
        }
        first = client.post(f"/internal/v1/capabilities/connections/{ASSET}/collect", **arguments)
        replay = client.post(f"/internal/v1/capabilities/connections/{ASSET}/collect", **arguments)
    assert first.status_code == replay.status_code == 202
    assert (
        first.json()
        == replay.json()
        == {
            "status": "started",
            "connection_id": ASSET,
            "job_id": JOB_ID,
            "job_type": "collection",
            "collection_kind": "github_source",
        }
    )
    assert repository.failed == []
    assert repository.dispatches == [JOB_ID]
    assert repository.state == {"spawn": "queued", "finished": "succeeded"}.get(stage, "running")
    assert "private" not in caplog.text


@pytest.mark.parametrize("stage", ["spawn", "ack", "call_id", "finished"])
def test_automatic_github_acceptance_preserves_job_after_ambiguous_delivery(stage, caplog):
    module = runpy.run_path(str(Path(__file__).parents[1] / "modal_app.py"))
    repository = DispatchRepository(stage=stage)
    worker = SimpleNamespace(
        spawn=lambda job_id: SimpleNamespace(object_id=repository.dispatch(job_id))
    )
    module["_queue_collection"].__globals__["collection_worker"] = worker
    module["_queue_collection"](repository, "tenant-alpha", ASSET, "github_source")
    if stage != "finished":
        module["_queue_collection"](repository, "tenant-alpha", ASSET, "github_source")
    assert repository.failed == []
    assert repository.dispatches == [JOB_ID]
    assert repository.state == {"spawn": "queued", "finished": "succeeded"}.get(stage, "running")
    assert "private" not in caplog.text


def test_other_browser_and_gateway_provider_dispatch_failures_keep_existing_behavior():
    for gateway in (False, True):
        repository = DispatchRepository(provider="azure")
        app = create_app(
            repository=repository,
            auth_mode="clerk" if gateway else "local",
            authenticator=SessionAuthenticator(),
            results_gateway_verifier=Verifier(),
            gateway_membership_checker=Memberships(),
            collection_dispatcher=repository.dispatch,
            migrate_on_start=False,
        )
        with TestClient(app) as client:
            response = (
                client.post(
                    f"/internal/v1/capabilities/connections/{ASSET}/collect",
                    json={"confirm": True, "collection_kind": "azure_deployments"},
                    headers={
                        "Authorization": "Bearer admin-write",
                        "Idempotency-Key": "azure-dispatch-001",
                    },
                )
                if gateway
                else client.post(f"/v1/connections/{ASSET}/azure/collect-deployments")
            )
        assert response.status_code == 503
        assert repository.state == "failed"
        assert repository.failed == [(JOB_ID, "Unable to dispatch collection worker.")]


def test_other_automatic_provider_dispatch_failure_still_fails_and_raises():
    module = runpy.run_path(str(Path(__file__).parents[1] / "modal_app.py"))
    repository = DispatchRepository(provider="azure")
    module["_queue_collection"].__globals__["collection_worker"] = SimpleNamespace(
        spawn=repository.dispatch
    )
    with pytest.raises(TimeoutError):
        module["_queue_collection"](repository, "tenant-alpha", ASSET, "azure_deployments")
    assert repository.state == "failed"
    assert repository.failed == [(JOB_ID, "Unable to dispatch automatic collection worker.")]


def test_local_without_modal_dispatcher_retains_the_single_run_collector():
    class LocalRepository(DispatchRepository):
        def claim_connection_collection_job(self, job_id, *, lease_seconds):
            if self.state != "queued":
                return None
            self.state = "running"
            return {
                "id": job_id,
                "tenant_id": DEFAULT_LOCAL_TENANT,
                "connection_id": ASSET,
                "collection_kind": "github_source",
                "attempt_count": 1,
            }

        def complete_connection_collection_job(self, job_id, result):
            assert job_id == JOB_ID and result["state"] == "complete"
            self.state = "succeeded"

    class Collector:
        calls = 0

        def collect(self, **_kwargs):
            self.calls += 1
            return {"state": "complete", "repository_count": 113}

        def collect_resumable(self, **_kwargs):
            raise AssertionError("Local Compose cannot rely on the Modal reconciler")

    repository = LocalRepository()
    collector = Collector()
    app = create_app(
        repository=repository,
        auth_mode="local",
        github_repository_collector=collector,
        collection_dispatcher=None,
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        response = client.post(f"/v1/connections/{ASSET}/github/collect")
    assert response.status_code == 202
    assert collector.calls == 1
    assert repository.state == "succeeded"
