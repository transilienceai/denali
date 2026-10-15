"""Azure runtime parity uses exact component pins and the existing metadata normalizer."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest
from test_azure_agent_runtime_activity_connector import (
    APP_ID,
    COMPONENT,
    SUBSCRIPTION,
    TENANT,
    Sink,
    _row,
)

from denali.connections import azure_coverage_plan
from denali.integrations.shared_azure_runtime import (
    AzureRuntimeCollectorRouter,
    SharedAzureRuntimeClient,
)
from denali.integrations.shared_microsoft import MicrosoftValidatorRouter

ID = "11111111-1111-4111-8111-111111111111"


def connection():
    scopes = ["azure.agent_runtime_activity"]
    subscriptions = [{"id": SUBSCRIPTION, "name": "Selected"}]
    return {
        "id": ID,
        "provider": "azure",
        "lifecycle_state": "active",
        "credential_type": "platform_shared_azure",
        "credential_reference": {"platform_connection_id": ID},
        "clerk_organization_id": "org_alpha",
        "declared_scopes": scopes,
        "configuration": {
            "tenant_id": TENANT,
            "coverage_mode": "selected-subscriptions",
            "subscriptions": subscriptions,
        },
        "coverage_plan": azure_coverage_plan(scopes, subscriptions),
    }


class Broker:
    def __init__(self):
        self.calls = []
        self.rows = [_row("chat", "2" * 16, timestamp=datetime.now(UTC).isoformat())]
        self.change = None

    def allows_org(self, org):
        return org == "org_alpha"

    def request(self, method, path, *, clerk_org_id, payload, **_kwargs):
        assert method == "POST" and clerk_org_id == "org_alpha"
        self.calls.append((path, deepcopy(payload)))
        operation = payload["operation"]
        if operation == "subscription_metadata":
            return {
                "operation": operation,
                "tenant_id": TENANT,
                "subscription_id": SUBSCRIPTION,
                "items": [{"subscriptionId": SUBSCRIPTION, "tenantId": TENANT}],
                "next_page_token": None,
            }
        assert path == f"/internal/v1/connections/azure/{ID}/runtime/read"
        items = (
            [deepcopy(COMPONENT)]
            if operation == "components"
            else deepcopy(self.rows)
            if operation == "spans"
            else []
        )
        response = {
            "operation": operation,
            "connection_id": ID,
            "tenant_id": TENANT,
            "subscription_id": SUBSCRIPTION,
            "items": items,
            "next_page_token": None,
            "truncated": False,
        }
        return self.change(response) if self.change else response


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_AZURE_ENABLED", "true")


def test_shared_runtime_validation_and_collection_never_use_native_credentials():
    broker, sink = Broker(), Sink()
    proof = MicrosoftValidatorRouter("azure", None, broker).validate(connection())
    assert proof["health_state"] == "healthy"
    assert proof["results"][0]["state"] == "passed"
    assert any(payload["operation"] == "probe" for _, payload in broker.calls)
    result = AzureRuntimeCollectorRouter(None, broker).collect(
        tenant_id="internal-tenant", connection=connection(), repository=sink
    )
    assert result["state"] == "complete"
    assert result["activities"] == 1
    assert sink.batches[0][1].activities[0].content_policy == "metadata_only"
    spans = next(payload for _, payload in broker.calls if payload["operation"] == "spans")
    assert spans["component_resource_id"] == COMPONENT["resource_id"]
    assert spans["app_id"] == APP_ID and spans["subscription_id"] == SUBSCRIPTION
    assert set(spans) == {
        "operation",
        "subscription_id",
        "component_resource_id",
        "app_id",
        "window_start",
        "window_end",
        "limit",
    }
    assert "query" not in spans and "token" not in spans


@pytest.mark.parametrize(
    "mutation",
    [
        lambda response: {**response, "tenant_id": "00000000-0000-4000-8000-000000000000"},
        lambda response: {**response, "connection_id": "00000000-0000-4000-8000-000000000000"},
        lambda response: {**response, "subscription_id": "00000000-0000-4000-8000-000000000000"},
        lambda response: (
            {**response, "items": [{**response["items"][0], "prompt": "private-content"}]}
            if response["operation"] == "spans"
            else response
        ),
    ],
)
def test_runtime_broker_binding_or_content_projection_failure_never_persists_activity(mutation):
    broker, sink = Broker(), Sink()
    broker.change = mutation
    result = AzureRuntimeCollectorRouter(None, broker).collect(
        tenant_id="internal-tenant", connection=connection(), repository=sink
    )
    assert result["state"] == "failed"
    assert result["activities"] == 0
    assert all(not batch.activities for _, batch in sink.batches)
    assert "private-content" not in repr(sink.batches)


def test_runtime_exact_discovered_app_window_and_scope_boundary(monkeypatch):
    broker = Broker()
    client = SharedAzureRuntimeClient(connection(), client=broker)
    end = datetime.now(UTC)
    with pytest.raises(ValueError, match="not discovered"):
        client.query_spans(
            app_id=APP_ID, start_time=end - timedelta(hours=1), end_time=end, limit=1
        )
    client.list_components(subscription_id=SUBSCRIPTION)
    with pytest.raises(ValueError, match="window"):
        client.query_spans(
            app_id=APP_ID, start_time=end - timedelta(hours=25), end_time=end, limit=1
        )
    with pytest.raises(ValueError, match="not selected"):
        client.list_components(subscription_id="00000000-0000-4000-8000-000000000000")
    monkeypatch.setenv("DENALI_PLATFORM_AZURE_ENABLED", "false")
    with pytest.raises(ValueError, match="disabled"):
        AzureRuntimeCollectorRouter(None, broker).collect(
            tenant_id="tenant", connection=connection(), repository=Sink()
        )
