"""Platform-mediated Google metadata: no ADC/token/native fallbacks."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from denali.connections.gcp import GcpConnectionValidator
from denali.connectors.gcp_deployments import (
    CLOUD_RUN_ASSET_TYPE,
    GcpConnectionDeploymentCollector,
    GcpDeploymentDiscoveryError,
)
from denali.domain import CoverageState
from denali.integrations.shared_gcp import SharedGcpReader, selected_projects

CONNECTION = "11111111-1111-4111-8111-111111111111"
PROJECT = "shared-ai-project"
NUMBER = "123456789012"


def connection(scopes: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": CONNECTION,
        "provider": "gcp",
        "lifecycle_state": "active",
        "credential_type": "platform_shared_gcp",
        "credential_reference": {"platform_connection_id": CONNECTION},
        "clerk_organization_id": "org_alpha",
        "declared_scopes": scopes or ["gcp.code_to_cloud"],
        "configuration": {
            "coverage_mode": "selected-projects",
            "projects": [{"id": PROJECT, "number": NUMBER, "name": PROJECT}],
        },
    }


class Broker:
    def __init__(self, handler=None):
        self.calls = []
        self.handler = handler

    def allows_org(self, org):
        return org == "org_alpha"

    def request(self, method, path, *, clerk_org_id, payload):
        self.calls.append((method, path, clerk_org_id, deepcopy(payload)))
        if self.handler:
            return self.handler(payload)
        return {
            "project_id": payload["project_id"],
            "operation": payload["operation"],
            "items": [],
            "next_page_token": None,
        }


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_GCP_ENABLED", "true")


def test_shared_reader_is_default_off(monkeypatch):
    monkeypatch.delenv("DENALI_PLATFORM_GCP_ENABLED", raising=False)
    with pytest.raises(ValueError, match="disabled"):
        SharedGcpReader(connection(), client=Broker())


@pytest.mark.parametrize(
    "change",
    [
        {"id": "22222222-2222-4222-8222-222222222222"},
        {"credential_type": "gcp_connection_principal"},
        {"credential_reference": {"principal_email": "native@operator.iam.gserviceaccount.com"}},
        {"clerk_organization_id": "org_beta"},
        {"clerk_organization_id": "tenant_alpha"},
        {"lifecycle_state": "disabled"},
        {"declared_scopes": ["gcp.code_to_cloud", "gcp.code_to_cloud"]},
        {"declared_scopes": ["gcp.cloud_admin"]},
        {"configuration": {"coverage_mode": "all-projects", "projects": []}},
    ],
)
def test_reference_and_entitlement_boundaries_fail_before_network(change):
    broker = Broker()
    with pytest.raises(ValueError):
        SharedGcpReader({**connection(), **change}, client=broker)
    assert not broker.calls


@pytest.mark.parametrize(
    "projects",
    [
        [],
        [{"id": "*", "number": NUMBER}],
        [{"id": PROJECT, "number": 123}],
        [{"id": PROJECT, "number": "1"}],
        [{"id": PROJECT, "number": NUMBER}] * 2,
        [{"id": PROJECT, "number": NUMBER}, {"id": "other-project", "number": NUMBER}],
    ],
)
def test_project_boundary_is_explicit_unique_and_immutable(projects):
    with pytest.raises(ValueError):
        selected_projects(projects)


def test_fixed_reads_send_only_server_org_connection_project_and_operation():
    broker = Broker()
    reader = SharedGcpReader(connection(), client=broker)
    assert (
        reader.read(PROJECT, "deployment_resources", asset_type=CLOUD_RUN_ASSET_TYPE)["items"] == []
    )
    assert broker.calls == [
        (
            "POST",
            f"/internal/v1/connections/gcp/{CONNECTION}/read",
            "org_alpha",
            {
                "project_id": PROJECT,
                "operation": "deployment_resources",
                "page_size": 100,
                "asset_type": CLOUD_RUN_ASSET_TYPE,
            },
        )
    ]
    for project, operation, asset_type in [
        ("other-project", "deployment_resources", None),
        (PROJECT, "vertex_resources", None),
        (PROJECT, "https://arbitrary.test", None),
        (PROJECT, "deployment_resources", "aiplatform.googleapis.com/Endpoint"),
    ]:
        with pytest.raises(ValueError):
            reader.read(project, operation, asset_type=asset_type)
    assert len(broker.calls) == 1


@pytest.mark.parametrize(
    "result",
    [
        {"project_id": "other-project", "operation": "deployment_resources", "items": []},
        {"project_id": PROJECT, "operation": "vertex_resources", "items": []},
        {"project_id": PROJECT, "operation": "deployment_resources", "items": [1]},
        {
            "project_id": PROJECT,
            "operation": "deployment_resources",
            "items": [],
            "next_page_token": 1,
        },
    ],
)
def test_malformed_broker_metadata_does_not_become_inventory(result):
    reader = SharedGcpReader(connection(), client=Broker(lambda _: result))
    with pytest.raises(ValueError, match="response"):
        reader.read(PROJECT, "deployment_resources")


def test_asset_paging_is_fixed_bounded_and_repeated_cursor_fails():
    asset = {"name": "metadata-name", "assetType": CLOUD_RUN_ASSET_TYPE, "resource": {"data": {}}}
    broker = Broker(
        lambda payload: {
            "project_id": PROJECT,
            "operation": "deployment_resources",
            "items": [{"asset": asset}],
            "next_page_token": "next" if not payload.get("page_token") else None,
        }
    )
    reader = SharedGcpReader(connection(), client=broker)
    assert reader.list_assets(project_id=PROJECT, asset_type=CLOUD_RUN_ASSET_TYPE) == (asset, asset)
    assert broker.calls[1][3] == {**broker.calls[0][3], "page_token": "next"}
    broker.handler = lambda _: {
        "project_id": PROJECT,
        "operation": "deployment_resources",
        "items": [],
        "next_page_token": "loop",
    }
    with pytest.raises(GcpDeploymentDiscoveryError, match="unavailable"):
        reader.list_assets(project_id=PROJECT, asset_type=CLOUD_RUN_ASSET_TYPE)


def test_activity_pages_preserve_one_exact_24_hour_query_and_project():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = start + timedelta(hours=24)
    entry = {
        "timestamp": start.isoformat(),
        "protoPayload": {"serviceName": "aiplatform.googleapis.com"},
    }
    broker = Broker(
        lambda payload: {
            "project_id": PROJECT,
            "operation": "ai_activity",
            "items": [{"entry": entry}],
            "next_page_token": "next" if not payload.get("page_token") else None,
        }
    )
    reader = SharedGcpReader(connection(["gcp.ai_activity"]), client=broker)
    entries = list(
        reader.list_entries(
            resource_names=[f"projects/{PROJECT}"],
            filter_=(
                'protoPayload.serviceName="aiplatform.googleapis.com" '
                f'AND timestamp>="{start.isoformat()}" '
                f'AND timestamp<="{end.isoformat()}"'
            ),
            order_by="timestamp asc",
            page_size=1000,
        )
    )
    assert entries == [entry, entry]
    assert broker.calls[1][3] == {**broker.calls[0][3], "page_token": "next"}
    assert broker.calls[0][3]["window_start"] == start.isoformat()
    assert broker.calls[0][3]["window_end"] == end.isoformat()
    with pytest.raises(ValueError):
        reader.read(
            PROJECT, "ai_activity", window_start=start, window_end=end + timedelta(seconds=1)
        )
    with pytest.raises(ValueError):
        list(
            reader.list_entries(
                resource_names=["organizations/123"], filter_="*", order_by="", page_size=1
            )
        )


def test_shared_validation_reuses_product_planes_without_native_credentials():
    broker = Broker()
    native_calls = []
    validator = GcpConnectionValidator(
        credential_factory=lambda principal: native_calls.append(principal),
        shared_reader_factory=lambda target: SharedGcpReader(target, client=broker),
    )
    result = validator.validate(connection(["gcp.vertex_ai", "gcp.code_to_cloud"]))
    assert result["health_state"] == "healthy"
    assert result["credential_state"] == "passed"
    assert len(result["results"]) == 3
    assert {call[3]["operation"] for call in broker.calls} == {
        "vertex_resources",
        "deployment_resources",
    }
    assert not native_calls


def test_broker_failure_is_validation_failure_never_adc_fallback():
    def unavailable(_):
        raise RuntimeError("unavailable")

    native_calls = []
    validator = GcpConnectionValidator(
        credential_factory=lambda principal: native_calls.append(principal),
        shared_reader_factory=lambda target: SharedGcpReader(target, client=Broker(unavailable)),
    )
    result = validator.validate(connection())
    assert result["health_state"] == "unhealthy"
    assert result["credential_state"] == "failed"
    assert not native_calls


def test_shared_collection_uses_existing_normalizers_and_org_bound_broker_only():
    asset = {
        "name": f"//run.googleapis.com/projects/{PROJECT}/locations/us-central1/services/demo",
        "assetType": CLOUD_RUN_ASSET_TYPE,
        "ancestors": [f"projects/{NUMBER}"],
        "resource": {
            "data": {
                "name": f"projects/{PROJECT}/locations/us-central1/services/demo",
                "uid": "demo-uid",
                "template": {"containers": [{"image": "gcr.io/shared-ai-project/demo@sha256:abc"}]},
            }
        },
    }
    broker = Broker(
        lambda payload: {
            "project_id": PROJECT,
            "operation": payload["operation"],
            "next_page_token": None,
            "items": [{"asset": asset}]
            if payload.get("asset_type") == CLOUD_RUN_ASSET_TYPE
            else [],
        }
    )

    class Sink:
        batches = []

        def ingest(self, tenant_id, batch):
            assert tenant_id == "tenant_alpha"
            self.batches.append(batch)
            return {"assets": len(batch.assets)}

    native_calls = []
    sink = Sink()
    collector = GcpConnectionDeploymentCollector(
        asset_client_factory=lambda principal: native_calls.append(principal),
        shared_reader_factory=lambda target: SharedGcpReader(target, client=broker),
    )
    result = collector.collect(tenant_id="tenant_alpha", connection=connection(), repository=sink)
    assert result["state"] == "complete"
    assert {coverage.state for batch in sink.batches for coverage in batch.coverage} == {
        CoverageState.COMPLETE
    }
    assert any(item.display_name == "demo" for batch in sink.batches for item in batch.assets)
    assert len(broker.calls) == 3
    assert not native_calls


def test_collection_broker_errors_record_failed_coverage_not_native_inventory():
    def unavailable(_):
        raise RuntimeError("unavailable")

    class Sink:
        batches = []

        def ingest(self, tenant_id, batch):
            self.batches.append(batch)
            return {"assets": len(batch.assets)}

    sink = Sink()
    collector = GcpConnectionDeploymentCollector(
        asset_client_factory=lambda _: pytest.fail("native ADC fallback is forbidden"),
        shared_reader_factory=lambda target: SharedGcpReader(target, client=Broker(unavailable)),
    )
    result = collector.collect(tenant_id="tenant_alpha", connection=connection(), repository=sink)
    assert result["state"] == "failed"
    assert all(not batch.assets for batch in sink.batches)
    assert {row.state for batch in sink.batches for row in batch.coverage} == {CoverageState.FAILED}


def test_all_shared_gcp_planes_reach_fixed_broker_operations_and_separate_activity_sink():
    class Sink:
        def __init__(self):
            self.inventory = []
            self.activity = []

        def ingest(self, tenant, batch):
            self.inventory.append(batch)
            return {"assets": len(batch.assets)}

        def ingest_activity(self, tenant, batch):
            self.activity.append(batch)
            return {"activities": len(batch.activities)}

    sink = Sink()
    broker = Broker()
    collector = GcpConnectionDeploymentCollector(
        asset_client_factory=lambda _: pytest.fail("native Google credential access is forbidden"),
        shared_reader_factory=lambda target: SharedGcpReader(target, client=broker),
    )
    target = connection(
        [
            "gcp.vertex_ai",
            "gcp.agent_builder",
            "gcp.code_to_cloud",
            "gcp.ai_activity",
        ]
    )
    result = collector.collect(tenant_id="tenant_alpha", connection=target, repository=sink)
    assert result["state"] == "complete"
    assert len(sink.inventory) == 5 and len(sink.activity) == 1
    assert len(broker.calls) == 18
    assert {call[3]["operation"] for call in broker.calls} == {
        "vertex_resources",
        "agent_resources",
        "deployment_resources",
        "ai_activity",
    }
    assert all(call[2] == "org_alpha" and call[3]["project_id"] == PROJECT for call in broker.calls)
    activity_payload = broker.calls[-1][3]
    assert datetime.fromisoformat(activity_payload["window_end"]) - datetime.fromisoformat(
        activity_payload["window_start"]
    ) == timedelta(hours=24)
