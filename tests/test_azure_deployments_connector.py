from datetime import UTC, datetime, timedelta
from typing import Any

from denali.connectors.azure_deployments import (
    AKS_CLUSTER_RESOURCE_TYPE,
    CONTAINER_APP_INVENTORY_PLANE,
    CONTAINER_APP_RESOURCE_TYPE,
    FUNCTION_APP_INVENTORY_PLANE,
    FUNCTION_APP_RESOURCE_TYPE,
    AzureConnectionDeploymentCollector,
    AzureDeploymentConnector,
    AzureDeploymentDiscoveryError,
    AzureResourceGraphRestClient,
    _azure_ai_activity_batch,
    _azure_ai_inventory_batch,
)
from denali.domain import AssetKind, CoverageState, RelationshipKind

SUBSCRIPTION = "8cd2b4cc-c789-466d-a8f7-8f51fb20985d"


def container_app(*, name: str, ai: bool) -> dict[str, Any]:
    environment = (
        [{"name": "AZURE_OPENAI_DEPLOYMENT_ID", "value": "secret-deployment"}]
        if ai
        else [{"name": "LOG_LEVEL", "value": "debug"}]
    )
    return {
        "id": (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/Denali-Test/providers/"
            f"Microsoft.App/containerApps/{name}"
        ),
        "name": name,
        "type": "microsoft.app/containerapps",
        "kind": "containerapp",
        "location": "West US 2",
        "resourceGroup": "Denali-Test",
        "subscriptionId": SUBSCRIPTION,
        "tags": {"denali_ai_workload": "true"} if ai else {},
        "identity": {
            "type": "SystemAssigned",
            "principalId": "1025e4ad-06a5-4a54-b617-c61c3195f619",
        },
        "properties": {
            "provisioningState": "Succeeded",
            "latestReadyRevisionName": f"{name}--abc",
            "configuration": {"ingress": {"fqdn": f"{name}.example.test"}},
            "template": {
                "containers": [
                    {
                        "name": name,
                        "image": f"registry.example/{name}@sha256:abc",
                        "env": environment,
                    }
                ]
            },
        },
    }


def function_app() -> dict[str, Any]:
    name = "denali-function"
    return {
        "id": (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/Denali-Test/providers/"
            f"Microsoft.Web/sites/{name}"
        ),
        "name": name,
        "type": "microsoft.web/sites",
        "kind": "functionapp,linux",
        "location": "West US 2",
        "resourceGroup": "Denali-Test",
        "subscriptionId": SUBSCRIPTION,
        "tags": {
            "denali_ai_workload": "true",
            "secret": "must-not-persist",
        },
        "identity": {
            "type": "SystemAssigned",
            "principalId": "2025e4ad-06a5-4a54-b617-c61c3195f619",
        },
        "properties": {
            "state": "Running",
            "defaultHostName": f"{name}.azurewebsites.net",
        },
    }


def aks_cluster() -> dict[str, Any]:
    name = "model-cluster"
    return {
        "id": (
            f"/subscriptions/{SUBSCRIPTION}/resourceGroups/Denali-Test/providers/"
            f"Microsoft.ContainerService/managedClusters/{name}"
        ),
        "name": name,
        "type": AKS_CLUSTER_RESOURCE_TYPE,
        "location": "West US 2",
        "resourceGroup": "Denali-Test",
        "subscriptionId": SUBSCRIPTION,
        "tags": {"denali_ai_workload": "true"},
        "properties": {
            "provisioningState": "Succeeded",
            "fqdn": "model-cluster.example.test",
            "currentKubernetesVersion": "1.34.1",
        },
    }


class FakeResourceClient:
    def __init__(self, records: dict[str, tuple[dict[str, Any], ...]]):
        self.records = records
        self.calls: list[tuple[str, str]] = []

    def list_resources(
        self, *, subscription_id: str, resource_type: str
    ) -> tuple[dict[str, Any], ...]:
        self.calls.append((subscription_id, resource_type))
        return self.records.get(resource_type, ())


def test_collects_bounded_azure_deployments_without_configuration_values() -> None:
    client = FakeResourceClient(
        {
            CONTAINER_APP_RESOURCE_TYPE: (
                container_app(name="denali-ai", ai=True),
                container_app(name="ordinary", ai=False),
            ),
            FUNCTION_APP_RESOURCE_TYPE: (function_app(),),
            AKS_CLUSTER_RESOURCE_TYPE: (aks_cluster(),),
        }
    )

    batch = AzureDeploymentConnector(
        subscription_id=SUBSCRIPTION,
        resource_client=client,
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    assert client.calls == [
        (SUBSCRIPTION, CONTAINER_APP_RESOURCE_TYPE),
        (SUBSCRIPTION, FUNCTION_APP_RESOURCE_TYPE),
        (SUBSCRIPTION, AKS_CLUSTER_RESOURCE_TYPE),
    ]
    workloads = [item for item in batch.assets if item.asset.kind is AssetKind.AI_WORKLOAD]
    cloud_resources = [item for item in batch.assets if item.asset.kind is AssetKind.CLOUD_RESOURCE]
    assert {item.display_name for item in workloads} == {
        "denali-ai",
        "denali-function",
    }
    assert {item.display_name for item in cloud_resources} == {
        "denali-ai",
        "ordinary",
        "denali-function",
        "model-cluster",
    }
    app = next(item for item in workloads if item.display_name == "denali-ai")
    assert app.attributes["deployment_identifiers"] == {
        "subscription_id": [SUBSCRIPTION],
        "resource_group": ["denali-test"],
        "location": ["westus2"],
        "container_app_name": ["denali-ai"],
    }
    assert app.attributes["deployment_artifact"]["image"].endswith("@sha256:abc")
    assert app.attributes["model_configuration_keys"] == ["AZURE_OPENAI_DEPLOYMENT_ID"]
    serialized = repr(batch)
    assert "secret-deployment" not in serialized
    assert "must-not-persist" not in serialized
    assert {item.kind for item in batch.relationships} == {
        RelationshipKind.HOSTED_ON,
        RelationshipKind.RUNS_AS,
    }


def test_resource_type_failures_are_isolated_by_coverage_plane() -> None:
    class PartiallyBrokenClient(FakeResourceClient):
        def list_resources(
            self, *, subscription_id: str, resource_type: str
        ) -> tuple[dict[str, Any], ...]:
            if resource_type == CONTAINER_APP_RESOURCE_TYPE:
                raise AzureDeploymentDiscoveryError("resourcegraph:Resources:AuthorizationFailed")
            return (function_app(),)

    batch = AzureDeploymentConnector(
        subscription_id=SUBSCRIPTION,
        resource_client=PartiallyBrokenClient({}),
    ).collect()
    by_plane = {item.plane: item for item in batch.coverage}

    assert by_plane[CONTAINER_APP_INVENTORY_PLANE].state is CoverageState.FAILED
    assert by_plane[FUNCTION_APP_INVENTORY_PLANE].state is CoverageState.COMPLETE
    assert "AuthorizationFailed" in (by_plane[CONTAINER_APP_INVENTORY_PLANE].detail or "")


def test_mismatched_resource_identity_is_partial_and_not_ingested() -> None:
    escaped = container_app(name="denali-ai", ai=True)
    escaped["id"] = escaped["id"].replace(SUBSCRIPTION, "11111111-1111-4111-8111-111111111111")
    client = FakeResourceClient({CONTAINER_APP_RESOURCE_TYPE: (escaped,)})

    batch = AzureDeploymentConnector(
        subscription_id=SUBSCRIPTION,
        resource_client=client,
    ).collect()
    by_plane = {item.plane: item for item in batch.coverage}

    assert by_plane[CONTAINER_APP_INVENTORY_PLANE].state is CoverageState.PARTIAL
    assert "escaped the selected subscription" in (
        by_plane[CONTAINER_APP_INVENTORY_PLANE].detail or ""
    )
    assert batch.assets == ()


def test_rest_client_paginates_with_exact_subscription_and_resource_type() -> None:
    calls: list[dict[str, Any]] = []

    class Response:
        def __init__(self, payload: dict[str, Any]):
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self.payload

    pages = [
        Response({"data": [container_app(name="one", ai=False)], "$skipToken": "next"}),
        Response({"data": [container_app(name="two", ai=False)]}),
    ]

    def request(method: str, url: str, **kwargs: Any) -> Response:
        calls.append({"method": method, "url": url, **kwargs})
        return pages.pop(0)

    records = AzureResourceGraphRestClient(request).list_resources(
        subscription_id=SUBSCRIPTION,
        resource_type=CONTAINER_APP_RESOURCE_TYPE,
    )

    assert len(records) == 2
    assert calls[0]["json"]["subscriptions"] == [SUBSCRIPTION]
    assert "microsoft.app/containerapps" in calls[0]["json"]["query"]
    assert calls[1]["json"]["options"]["$skipToken"] == "next"


def test_connection_collector_requires_scope_and_reports_each_subscription() -> None:
    client = FakeResourceClient(
        {CONTAINER_APP_RESOURCE_TYPE: (container_app(name="denali-ai", ai=True),)}
    )
    ingested = []

    class Sink:
        def ingest(self, tenant_id: str, batch: Any) -> dict[str, int]:
            ingested.append((tenant_id, batch))
            return {"assets": len(batch.assets)}

    connection = {
        "id": "connection-id",
        "provider": "azure",
        "lifecycle_state": "active",
        "declared_scopes": ["azure.code_to_cloud"],
        "configuration": {
            "tenant_id": "017c6f31-f951-4bda-a50a-c168c0e6f815",
            "subscriptions": [{"id": SUBSCRIPTION, "name": "Test"}],
        },
    }

    result = AzureConnectionDeploymentCollector(
        resource_client_factory=lambda tenant: client
    ).collect(tenant_id="tenant", connection=connection, repository=Sink())

    assert result["state"] == "complete"
    assert result["subscription_count"] == 1
    assert result["subscriptions"][0]["ai_workloads"] == 1
    assert len(ingested) == 1


def test_ai_inventory_keeps_exact_resource_boundary_without_raw_properties() -> None:
    resource_type = "microsoft.botservice/botservices"
    resource_id = (
        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/Denali-Test/providers/"
        "Microsoft.BotService/botServices/support-agent"
    )
    client = FakeResourceClient(
        {
            resource_type: (
                {
                    "id": resource_id,
                    "name": "support-agent",
                    "type": resource_type,
                    "location": "global",
                    "subscriptionId": SUBSCRIPTION,
                    "properties": {"endpoint": "must-not-be-retained"},
                },
            )
        }
    )

    batch = _azure_ai_inventory_batch(
        subscription_id=SUBSCRIPTION,
        connection_id="connection",
        client=client,
        plane="azure_bot_services",
        resource_type=resource_type,
        kind=AssetKind.AI_AGENT,
    )

    assert len(batch.assets) == 1
    assert batch.assets[0].asset.kind is AssetKind.AI_AGENT
    assert batch.assets[0].asset.natural_key == resource_id.lower()
    assert "must-not-be-retained" not in str(batch)
    assert batch.coverage[0].state is CoverageState.COMPLETE


def test_ai_activity_is_bounded_to_known_providers_and_omits_callers() -> None:
    now = datetime.now(UTC)

    class ActivityClient(FakeResourceClient):
        def list_activity(self, **_kwargs: Any) -> tuple[dict[str, Any], ...]:
            return (
                {
                    "eventDataId": "event-1",
                    "eventTimestamp": now.isoformat(),
                    "resourceProviderName": {"value": "Microsoft.CognitiveServices"},
                    "operationName": {
                        "value": "Microsoft.CognitiveServices/accounts/write",
                        "localizedValue": "Update AI services account",
                    },
                    "status": {"value": "Succeeded"},
                    "caller": "must-not-be-retained@example.com",
                    "resourceId": (
                        f"/subscriptions/{SUBSCRIPTION}/resourceGroups/test/providers/"
                        "Microsoft.CognitiveServices/accounts/ai"
                    ),
                },
                {
                    "eventDataId": "event-2",
                    "eventTimestamp": now.isoformat(),
                    "resourceProviderName": {"value": "Microsoft.Storage"},
                    "operationName": {
                        "value": "Microsoft.Storage/storageAccounts/write",
                        "localizedValue": "Update storage account",
                    },
                    "status": {"value": "Succeeded"},
                },
            )

    batch = _azure_ai_activity_batch(
        subscription_id=SUBSCRIPTION,
        connection_id="connection",
        client=ActivityClient({}),
        start_time=now - timedelta(hours=24),
        end_time=now,
    )

    assert len(batch.activities) == 1
    assert batch.activities[0].source_uid == "event-1"
    assert "must-not-be-retained" not in str(batch)
    assert batch.coverage[0].state is CoverageState.COMPLETE
