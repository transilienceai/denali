"""A stale active UI snapshot becomes a safe conflict before dispatch."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from test_connections import ConnectionRepositoryStub

from denali.api.app import create_app
from denali.connections import AWS_SCOPE_BEDROCK_AGENTS


class ChangedConnectionRepository(ConnectionRepositoryStub):
    def create_connection_validation_job(self, *_args, **_kwargs):
        raise ValueError("private backend diagnostic")

    def create_connection_collection_job(self, *_args, **_kwargs):
        raise ValueError("private backend diagnostic")


@pytest.mark.parametrize("operation", ["validate", "aws/collect-deployments"])
def test_queue_helpers_return_conflict_and_do_not_dispatch_after_disable(operation):
    dispatched = []
    app = create_app(
        repository=ChangedConnectionRepository(),
        validation_dispatcher=lambda job: dispatched.append(job),
        collection_dispatcher=lambda job: dispatched.append(job),
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/connections",
            json={
                "provider": "aws",
                "display_name": "Atomic queue fixture",
                "account_id": "123456789012",
                "declared_scopes": [AWS_SCOPE_BEDROCK_AGENTS],
            },
        )
        assert response.status_code == 201
        connection_id = response.json()["id"]
        result = client.post(f"/v1/connections/{connection_id}/{operation}")
    assert result.status_code == 409
    assert result.json() == {"detail": "connection is no longer active"}
    assert not dispatched
