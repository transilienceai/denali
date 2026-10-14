"""API and remote worker imports select the same native/shared routers."""

import runpy
from pathlib import Path

from fastapi.testclient import TestClient
from test_shared_gcp_api import Authenticator, Repository
from test_shared_google_workspace import Broker

from denali.api.app import create_app
from denali.integrations.shared_connections_client import SharedConnectionsClient
from denali.integrations.shared_google_workspace import (
    WorkspaceCollectorRouter,
    WorkspaceValidatorRouter,
)


def test_api_and_modal_workers_support_shared_access_without_native_google_identity(monkeypatch):
    import denali.api.app as app_module
    import denali.api.collection as collection_module

    broker = Broker()
    monkeypatch.setattr(app_module, "_google_workspace_operator_from_environment", lambda: None)
    monkeypatch.setattr(
        SharedConnectionsClient, "from_environment", classmethod(lambda cls: broker)
    )
    monkeypatch.setenv("DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED", "true")
    monkeypatch.setenv("DENALI_DSN", "postgresql://unused-local-test")
    for key in (
        "DENALI_GCP_WORKLOAD_IDENTITY_PROVIDER",
        "DENALI_GCP_RUNTIME_SERVICE_ACCOUNT",
        "DENALI_MODAL_AWS_ROLE_ARN",
    ):
        monkeypatch.delenv(key, raising=False)
    app = create_app(
        repository=Repository(),
        auth_mode="clerk",
        authenticator=Authenticator(),
        shared_connections_client=broker,
        migrate_on_start=False,
    )
    with TestClient(app):
        assert isinstance(app.state.google_workspace_connection_validator, WorkspaceValidatorRouter)
        assert isinstance(app.state.google_workspace_connection_collector, WorkspaceCollectorRouter)
        assert app.state.google_workspace_operator is None
    module = runpy.run_path(str(Path(__file__).parents[1] / "modal_app.py"))
    assert isinstance(module["_validators"]()["google_workspace"], WorkspaceValidatorRouter)
    captured = []
    monkeypatch.setattr(
        collection_module,
        "run_durable_collection_job",
        lambda repo, collectors, job, **kwargs: captured.append(collectors),
    )
    module["collection_worker"].local("test-job")
    assert isinstance(captured[0]["google_workspace_ai"], WorkspaceCollectorRouter)
    assert len(module["runtime_secrets"]) == 3
    assert len(module["shasta_bridge_secrets"]) == 4
