from __future__ import annotations

import json

import pytest
from test_native_connection_settings import (
    IDS,
    TENANT,
    environment,
    native_targets,
    reader,
    snapshot,
)
from test_shared_connections_api import FakeRepository, FakeSharedClient, make_client

from denali.api.collection import run_durable_collection_job
from denali.api.validation import run_durable_validation_job
from denali.integrations import native_connection_settings as native


class Repository:
    def __init__(self, client):
        self.reader = client
        self.failed, self.completed, self.validation = [], False, None

    def get_connection_validation_target(self, tenant_id, connection_id):
        assert (tenant_id, connection_id) == (TENANT, IDS[0])
        return native.resolve_native_connection_settings(
            tenant_id, native_targets()[0], environ=environment(),
            reader_factory=lambda *_args: self.reader,
        )

    def claim_connection_validation_job(self, _job, **_options):
        return {"tenant_id": TENANT, "connection_id": IDS[0],
                "wait_for_credentials": False, "wait_for_healthy": False}

    def record_connection_validation(self, _tenant, _connection, result):
        self.validation = result

    def complete_connection_validation_job(self, _job):
        self.completed = True

    def fail_connection_validation_job(self, _job, summary):
        self.failed.append(summary)

    def claim_connection_collection_job(self, _job, **_options):
        return {"tenant_id": TENANT, "connection_id": IDS[0],
                "collection_kind": "aws_deployments", "attempt_count": 1}

    def complete_connection_collection_job(self, _job, _result):
        self.completed = True

    def record_connection_collection_failure(self, _job, summary, **_options):
        self.failed.append(summary)
        return False


class ProviderAdapter:
    def __init__(self):
        self.targets = []

    def validate(self, target):
        self.targets.append(target)
        return {"health_state": "healthy", "credential_state": "passed"}

    def collect(self, *, connection, **_options):
        self.targets.append(connection)
        return {"state": "complete"}


@pytest.mark.parametrize("operation", ["validation", "collection"])
def test_native_worker_uses_clerk_ids_without_changing_its_existing_provider_adapter(operation):
    client, calls = reader()
    repository, provider = Repository(client), ProviderAdapter()
    if operation == "validation":
        run_durable_validation_job(repository, {"aws": provider}, "synthetic-job",
                                   timeout_seconds=1, retry_seconds=0, max_error_attempts=1)
    else:
        run_durable_collection_job(repository, {"aws_deployments": provider}, "synthetic-job",
                                   max_attempts=1)
    assert repository.completed is True and not repository.failed
    assert len(calls) == 1 and len(provider.targets) == 1
    target = provider.targets[0]
    assert target.native_connection_settings_source == "clerk"
    assert dict(target) == native_targets()[0]
    assert "native_connection_settings_source" not in json.dumps(target)


@pytest.mark.parametrize("operation", ["validation", "collection"])
def test_missing_native_snapshot_stops_before_any_provider_call(operation, caplog):
    document = snapshot()
    document["sources"] = {}
    client, _calls = reader(document)
    repository, provider = Repository(client), ProviderAdapter()
    if operation == "validation":
        run_durable_validation_job(repository, {"aws": provider}, "synthetic-job",
                                   timeout_seconds=1, retry_seconds=0, max_error_attempts=1)
    else:
        run_durable_collection_job(repository, {"aws_deployments": provider}, "synthetic-job",
                                   max_attempts=1)
    assert repository.completed is False and len(repository.failed) == 1
    assert provider.targets == []
    assert "NativeConnectionSettingsUnavailable" in repository.failed[0]
    assert "synthetic-external-id" not in caplog.text
    assert "arn:aws:iam::123456789012" not in caplog.text


def test_native_lookup_error_is_fixed_api_503_not_bad_credentials_or_private_payload():
    class UnavailableRepository(FakeRepository):
        def get_connection_validation_target(self, _tenant, _connection):
            raise native.NativeConnectionSettingsUnavailable()

    with make_client(FakeSharedClient(), UnavailableRepository()) as client:
        route = f"/v1/connections/{IDS[0]}/aws/cloudformation.yaml"
        assert client.get(route).status_code == 401
        response = client.get(route, headers={"Authorization": "Bearer alpha-member"})
    assert response.status_code == 503
    assert response.json() == {"detail": "native connection settings unavailable"}
    assert response.headers["cache-control"] == "no-store"
