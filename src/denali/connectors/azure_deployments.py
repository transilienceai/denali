"""Bounded Azure Container Apps, Function Apps, and AKS deployment inventory."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from denali.connections.azure import (
    AZURE_ACTIVITY_API_VERSION,
    AZURE_MANAGEMENT_ENDPOINT,
    AZURE_RESOURCE_GRAPH_API_VERSION,
    AZURE_SCOPE_AI_ACTIVITY,
    AZURE_SCOPE_AI_PLATFORM,
    AZURE_SCOPE_AI_SERVICES,
    AZURE_SCOPE_CODE_TO_CLOUD,
    authorized_azure_request,
    valid_azure_uuid,
)
from denali.domain import (
    ActivityBatch,
    ActivityCategory,
    ActivityOutcome,
    ActivityRecord,
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    Evidence,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
)

CONNECTOR_ID = "denali.azure_deployments"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True)
CONTAINER_APP_RESOURCE_TYPE = "microsoft.app/containerapps"
FUNCTION_APP_RESOURCE_TYPE = "microsoft.web/sites"
AKS_CLUSTER_RESOURCE_TYPE = "microsoft.containerservice/managedclusters"
CONTAINER_APP_INVENTORY_PLANE = "azure_container_apps_inventory"
CONTAINER_APP_RELATIONSHIP_PLANE = "azure_container_apps_relationships"
FUNCTION_APP_INVENTORY_PLANE = "azure_function_apps_inventory"
FUNCTION_APP_RELATIONSHIP_PLANE = "azure_function_apps_relationships"
AKS_CLUSTER_INVENTORY_PLANE = "azure_aks_cluster_inventory"
AKS_CLUSTER_RELATIONSHIP_PLANE = "azure_aks_cluster_relationships"
MAX_RESOURCES_PER_TYPE = 10_000
MAX_PAGES_PER_TYPE = 100
PAGE_SIZE = 1_000

_AZURE_AI_PLANES = {
    AZURE_SCOPE_AI_SERVICES: (
        (
            "azure_ai_services_accounts",
            "microsoft.cognitiveservices/accounts",
            AssetKind.CLOUD_RESOURCE,
        ),
        (
            "azure_ai_search_services",
            "microsoft.search/searchservices",
            AssetKind.AI_DATASTORE,
        ),
    ),
    AZURE_SCOPE_AI_PLATFORM: (
        (
            "azure_machine_learning_workspaces",
            "microsoft.machinelearningservices/workspaces",
            AssetKind.CLOUD_RESOURCE,
        ),
        (
            "azure_bot_services",
            "microsoft.botservice/botservices",
            AssetKind.AI_AGENT,
        ),
    ),
}

_MODEL_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*(?:MODEL|DEPLOYMENT)_ID$")
_RESOURCE_ID_RE = re.compile(
    r"^/subscriptions/(?P<subscription>[0-9a-f-]{36})/resourceGroups/"
    r"(?P<resource_group>[^/]+)/providers/"
    r"(?P<provider>Microsoft\.(?:App|Web|ContainerService))/"
    r"(?P<kind>containerApps|sites|managedClusters)/(?P<name>[^/]+)$",
    re.IGNORECASE,
)


class AzureDeploymentDiscoveryError(RuntimeError):
    """A stable Azure discovery failure without response or credential material."""


class AzureResourceClient(Protocol):
    def list_resources(
        self, *, subscription_id: str, resource_type: str
    ) -> tuple[dict[str, Any], ...]: ...

    def list_activity(
        self, *, subscription_id: str, start_time: datetime, end_time: datetime
    ) -> tuple[dict[str, Any], ...]: ...


class InventorySink(Protocol):
    def ingest(self, tenant_id: str, batch: InventoryBatch) -> dict[str, int]: ...

    def ingest_activity(self, tenant_id: str, batch: ActivityBatch) -> dict[str, int]: ...


class AzureResourceGraphRestClient:
    """Small bounded Azure Resource Graph client for exact resource types."""

    def __init__(self, request: Callable[..., Any]):
        self._request = request

    def list_resources(
        self, *, subscription_id: str, resource_type: str
    ) -> tuple[dict[str, Any], ...]:
        if resource_type not in {
            CONTAINER_APP_RESOURCE_TYPE,
            FUNCTION_APP_RESOURCE_TYPE,
            AKS_CLUSTER_RESOURCE_TYPE,
            *(
                resource_type
                for planes in _AZURE_AI_PLANES.values()
                for _, resource_type, _ in planes
            ),
        }:
            raise ValueError("unsupported Azure deployment resource type")
        kind_filter = (
            " | where kind contains 'functionapp'"
            if resource_type == FUNCTION_APP_RESOURCE_TYPE
            else ""
        )
        query = (
            f"Resources | where type =~ '{resource_type}'{kind_filter} "
            "| project id, name, type, kind, location, resourceGroup, "
            "subscriptionId, tags, identity, properties | order by id asc"
        )
        records: list[dict[str, Any]] = []
        skip_token: str | None = None
        for _ in range(MAX_PAGES_PER_TYPE):
            options: dict[str, Any] = {
                "$top": PAGE_SIZE,
                "resultFormat": "objectArray",
            }
            if skip_token:
                options["$skipToken"] = skip_token
            try:
                response = self._request(
                    "POST",
                    f"{AZURE_MANAGEMENT_ENDPOINT}/providers/Microsoft.ResourceGraph/resources",
                    params={"api-version": AZURE_RESOURCE_GRAPH_API_VERSION},
                    json={
                        "subscriptions": [subscription_id],
                        "query": query,
                        "options": options,
                    },
                    timeout=30.0,
                )
                response.raise_for_status()
                payload = response.json()
            except Exception as error:
                raise AzureDeploymentDiscoveryError(
                    f"resourcegraph:Resources:{_safe_error_code(error)}"
                ) from None
            if not isinstance(payload, dict) or not isinstance(payload.get("data", []), list):
                raise AzureDeploymentDiscoveryError(
                    "resourcegraph:Resources:invalid_response_shape"
                )
            for item in payload.get("data", []):
                if isinstance(item, dict):
                    records.append(item)
                    if len(records) > MAX_RESOURCES_PER_TYPE:
                        raise AzureDeploymentDiscoveryError(
                            f"resourcegraph:Resources:record_limit_{MAX_RESOURCES_PER_TYPE}"
                        )
            raw_skip_token = payload.get("$skipToken")
            if raw_skip_token in {None, ""}:
                return tuple(records)
            if not isinstance(raw_skip_token, str):
                raise AzureDeploymentDiscoveryError("resourcegraph:Resources:invalid_skip_token")
            skip_token = raw_skip_token
        raise AzureDeploymentDiscoveryError(
            f"resourcegraph:Resources:page_limit_{MAX_PAGES_PER_TYPE}"
        )

    def list_activity(
        self, *, subscription_id: str, start_time: datetime, end_time: datetime
    ) -> tuple[dict[str, Any], ...]:
        records: list[dict[str, Any]] = []
        url = (
            f"{AZURE_MANAGEMENT_ENDPOINT}/subscriptions/{subscription_id}/providers/"
            "microsoft.insights/eventtypes/management/values"
        )
        params: dict[str, str] | None = {
            "api-version": AZURE_ACTIVITY_API_VERSION,
            "$filter": (
                f"eventTimestamp ge '{start_time.isoformat()}' and "
                f"eventTimestamp le '{end_time.isoformat()}'"
            ),
        }
        for _ in range(MAX_PAGES_PER_TYPE):
            try:
                response = self._request("GET", url, params=params, timeout=30.0)
                response.raise_for_status()
                payload = response.json()
            except Exception as error:
                raise AzureDeploymentDiscoveryError(
                    f"activitylog:List:{_safe_error_code(error)}"
                ) from None
            if not isinstance(payload, dict) or not isinstance(payload.get("value", []), list):
                raise AzureDeploymentDiscoveryError("activitylog:List:invalid_response_shape")
            records.extend(item for item in payload.get("value", []) if isinstance(item, dict))
            if len(records) > MAX_RESOURCES_PER_TYPE:
                raise AzureDeploymentDiscoveryError(
                    f"activitylog:List:record_limit_{MAX_RESOURCES_PER_TYPE}"
                )
            next_link = payload.get("nextLink")
            if not next_link:
                return tuple(records)
            if not isinstance(next_link, str) or not next_link.startswith(
                AZURE_MANAGEMENT_ENDPOINT
            ):
                raise AzureDeploymentDiscoveryError("activitylog:List:invalid_next_link")
            url = next_link
            params = None
        raise AzureDeploymentDiscoveryError(f"activitylog:List:page_limit_{MAX_PAGES_PER_TYPE}")


class AzureConnectionDeploymentCollector:
    """Collect every exact subscription selected on one active Azure connection."""

    def __init__(
        self,
        resource_client_factory: Callable[[str], AzureResourceClient] | None = None,
    ):
        self._resource_client_factory = resource_client_factory or (
            lambda tenant: AzureResourceGraphRestClient(authorized_azure_request(tenant))
        )

    def collect(
        self,
        *,
        tenant_id: str,
        connection: dict[str, Any],
        repository: InventorySink,
    ) -> dict[str, Any]:
        if connection.get("provider") != "azure":
            raise ValueError("connection is not an Azure connection")
        if connection.get("lifecycle_state") != "active":
            raise ValueError("disabled Azure connections cannot collect")
        scopes = set(connection.get("declared_scopes", []))
        if not scopes & {
            AZURE_SCOPE_CODE_TO_CLOUD,
            AZURE_SCOPE_AI_SERVICES,
            AZURE_SCOPE_AI_PLATFORM,
            AZURE_SCOPE_AI_ACTIVITY,
        }:
            raise ValueError("Azure connection has no supported collection scope")
        subscriptions = connection.get("configuration", {}).get("subscriptions", [])
        customer_tenant = connection.get("configuration", {}).get("tenant_id")
        if (
            not isinstance(subscriptions, list)
            or not subscriptions
            or not isinstance(customer_tenant, str)
        ):
            raise ValueError("complete Azure subscription selection before collecting")

        client = self._resource_client_factory(customer_tenant)
        subscription_results: list[dict[str, Any]] = []
        failed = 0
        partial = 0
        for subscription in subscriptions:
            subscription_id = subscription.get("id") if isinstance(subscription, dict) else None
            if not isinstance(subscription_id, str) or not valid_azure_uuid(subscription_id):
                failed += 1
                subscription_results.append(
                    {"subscription_id": str(subscription_id), "state": "failed"}
                )
                continue
            subscription_id = subscription_id.lower()
            batches: list[InventoryBatch] = []
            for scope_name, planes in _AZURE_AI_PLANES.items():
                if scope_name not in scopes:
                    continue
                for plane, resource_type, kind in planes:
                    batches.append(
                        _azure_ai_inventory_batch(
                            subscription_id=subscription_id,
                            connection_id=str(connection["id"]),
                            client=client,
                            plane=plane,
                            resource_type=resource_type,
                            kind=kind,
                        )
                    )
            if AZURE_SCOPE_CODE_TO_CLOUD in scopes:
                batches.append(
                    AzureDeploymentConnector(
                        subscription_id=subscription_id,
                        resource_client=client,
                    ).collect(connection_id=str(connection["id"]))
                )
            for batch in batches:
                repository.ingest(tenant_id, batch)
            activity_count = 0
            activity_coverage: tuple[Coverage, ...] = ()
            if AZURE_SCOPE_AI_ACTIVITY in scopes:
                end_time = datetime.now(UTC)
                activity_batch = _azure_ai_activity_batch(
                    subscription_id=subscription_id,
                    connection_id=str(connection["id"]),
                    client=client,
                    start_time=end_time - timedelta(hours=24),
                    end_time=end_time,
                )
                repository.ingest_activity(tenant_id, activity_batch)
                activity_count = len(activity_batch.activities)
                activity_coverage = activity_batch.coverage
            states = {item.state for batch in batches for item in batch.coverage}
            states.update(item.state for item in activity_coverage)
            if CoverageState.FAILED in states:
                state = "failed"
                failed += 1
            elif CoverageState.PARTIAL in states:
                state = "partial"
                partial += 1
            else:
                state = "complete"
            subscription_results.append(
                {
                    "subscription_id": subscription_id,
                    "state": state,
                    "assets": sum(len(batch.assets) for batch in batches),
                    "ai_workloads": sum(
                        item.asset.kind is AssetKind.AI_WORKLOAD
                        for batch in batches
                        for item in batch.assets
                    ),
                    "activity_events": activity_count,
                }
            )
        completed_at = datetime.now(UTC).isoformat()
        overall_state = (
            "failed"
            if failed == len(subscriptions)
            else "partial"
            if failed or partial
            else "complete"
        )
        return {
            "connection_id": str(connection["id"]),
            "state": overall_state,
            "completed_at": completed_at,
            "subscription_count": len(subscriptions),
            "failed_count": failed,
            "partial_count": partial,
            "subscriptions": subscription_results,
        }


class AzureDeploymentConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(self, *, subscription_id: str, resource_client: AzureResourceClient):
        if not valid_azure_uuid(subscription_id):
            raise ValueError("Azure subscription ID must be a UUID")
        self.subscription_id = subscription_id.lower()
        self.resource_client = resource_client

    def collect(self, *, connection_id: str | None = None) -> InventoryBatch:
        observed_at = datetime.now(UTC)
        connection = connection_id or f"azure:{self.subscription_id}"
        scope = f"azure:subscription:{self.subscription_id}"
        assets: dict[tuple[AssetRef, str], AssetAssertion] = {}
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, str], RelationshipAssertion
        ] = {}
        coverage: list[Coverage] = []

        for resource_type, inventory_plane, relationship_plane in (
            (
                CONTAINER_APP_RESOURCE_TYPE,
                CONTAINER_APP_INVENTORY_PLANE,
                CONTAINER_APP_RELATIONSHIP_PLANE,
            ),
            (
                FUNCTION_APP_RESOURCE_TYPE,
                FUNCTION_APP_INVENTORY_PLANE,
                FUNCTION_APP_RELATIONSHIP_PLANE,
            ),
            (
                AKS_CLUSTER_RESOURCE_TYPE,
                AKS_CLUSTER_INVENTORY_PLANE,
                AKS_CLUSTER_RELATIONSHIP_PLANE,
            ),
        ):
            warnings: list[str] = []
            try:
                raw_resources = self.resource_client.list_resources(
                    subscription_id=self.subscription_id,
                    resource_type=resource_type,
                )
            except AzureDeploymentDiscoveryError as error:
                coverage.extend(
                    (
                        Coverage(inventory_plane, CoverageState.FAILED, scope, str(error)),
                        Coverage(relationship_plane, CoverageState.FAILED, scope, str(error)),
                    )
                )
                continue

            ai_workloads = 0
            for position, raw in enumerate(raw_resources):
                try:
                    parsed = _parse_resource(
                        raw,
                        subscription_id=self.subscription_id,
                        resource_type=resource_type,
                    )
                except ValueError as error:
                    warnings.append(f"{resource_type} item {position}: {error}")
                    continue
                cloud_ref, cloud_assertion, workload_assertion, identity_assertion = (
                    _asset_assertions(parsed, observed_at, inventory_plane)
                )
                assets[(cloud_ref, inventory_plane)] = cloud_assertion
                if workload_assertion is None:
                    continue
                ai_workloads += 1
                workload_ref = workload_assertion.asset
                assets[(workload_ref, inventory_plane)] = workload_assertion
                self._add_relationship(
                    relationships,
                    workload_ref,
                    cloud_ref,
                    RelationshipKind.HOSTED_ON,
                    relationship_plane,
                    workload_assertion.evidence,
                )
                if identity_assertion is not None:
                    identity_ref = identity_assertion.asset
                    assets[(identity_ref, inventory_plane)] = identity_assertion
                    self._add_relationship(
                        relationships,
                        workload_ref,
                        identity_ref,
                        RelationshipKind.RUNS_AS,
                        relationship_plane,
                        workload_assertion.evidence,
                    )

            state = CoverageState.PARTIAL if warnings else CoverageState.COMPLETE
            summary = (
                f"Observed {len(raw_resources)} {resource_type} resources; "
                f"classified {ai_workloads} as AI workloads."
            )
            coverage.extend(
                (
                    Coverage(
                        inventory_plane,
                        state,
                        scope,
                        "; ".join([summary, *warnings[:10]]),
                    ),
                    Coverage(
                        relationship_plane,
                        state,
                        scope,
                        "; ".join([summary, *warnings[:10]]),
                    ),
                )
            )

        return InventoryBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=f"azure-deployments-{self.subscription_id}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=tuple(coverage),
            assets=tuple(assets.values()),
            relationships=tuple(relationships.values()),
        )

    @staticmethod
    def _add_relationship(
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, str], RelationshipAssertion
        ],
        source: AssetRef,
        target: AssetRef,
        kind: RelationshipKind,
        plane: str,
        evidence: Evidence,
    ) -> None:
        relationships[(source, target, kind, plane)] = RelationshipAssertion(
            source=source,
            target=target,
            coverage_plane=plane,
            kind=kind,
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=evidence,
        )


def _azure_ai_inventory_batch(
    *,
    subscription_id: str,
    connection_id: str,
    client: AzureResourceClient,
    plane: str,
    resource_type: str,
    kind: AssetKind,
) -> InventoryBatch:
    observed_at = datetime.now(UTC)
    scope = f"azure:subscription:{subscription_id}"
    warnings: list[str] = []
    assertions: list[AssetAssertion] = []
    try:
        records = client.list_resources(
            subscription_id=subscription_id, resource_type=resource_type
        )
    except AzureDeploymentDiscoveryError as error:
        return InventoryBatch(
            connector_id="denali.azure_ai_inventory",
            connection_id=connection_id,
            run_id=f"azure-ai-inventory-{plane}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=(Coverage(plane, CoverageState.FAILED, scope, str(error)),),
        )
    prefix = f"/subscriptions/{subscription_id}/"
    for position, raw in enumerate(records):
        resource_id = raw.get("id") if isinstance(raw, dict) else None
        observed_type = str(raw.get("type", "")).lower() if isinstance(raw, dict) else ""
        observed_subscription = (
            str(raw.get("subscriptionId", "")).lower() if isinstance(raw, dict) else ""
        )
        if (
            not isinstance(resource_id, str)
            or not resource_id.lower().startswith(prefix)
            or observed_type != resource_type
            or observed_subscription != subscription_id
        ):
            warnings.append(f"{resource_type} item {position}: invalid resource boundary")
            continue
        name = raw.get("name")
        if not isinstance(name, str) or not name:
            warnings.append(f"{resource_type} item {position}: resource name is missing")
            continue
        evidence = Evidence(
            source_type="azure_resource_graph",
            locator=f"azure://resourcegraph{resource_id}",
            observed_at=observed_at,
            payload={
                "subscription_id": subscription_id,
                "resource_id": resource_id,
                "resource_type": resource_type,
                "location": raw.get("location"),
            },
        )
        assertions.append(
            AssetAssertion(
                asset=AssetRef(kind, resource_id.lower()),
                coverage_plane=plane,
                display_name=name,
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                evidence=evidence,
                attributes={
                    "provider": "azure",
                    "subscription_id": subscription_id,
                    "resource_id": resource_id,
                    "resource_type": resource_type,
                    "location": raw.get("location"),
                },
            )
        )
    state = CoverageState.PARTIAL if warnings else CoverageState.COMPLETE
    detail = "; ".join([f"Observed {len(assertions)} {resource_type} resources.", *warnings[:10]])
    return InventoryBatch(
        connector_id="denali.azure_ai_inventory",
        connection_id=connection_id,
        run_id=f"azure-ai-inventory-{plane}-{observed_at.isoformat()}",
        scope_key=scope,
        collected_at=observed_at,
        coverage=(Coverage(plane, state, scope, detail),),
        assets=tuple(assertions),
    )


_AZURE_AI_ACTIVITY_PROVIDERS = {
    "microsoft.cognitiveservices",
    "microsoft.search",
    "microsoft.machinelearningservices",
    "microsoft.botservice",
    "microsoft.app",
    "microsoft.web",
    "microsoft.containerservice",
}


def _azure_ai_activity_batch(
    *,
    subscription_id: str,
    connection_id: str,
    client: AzureResourceClient,
    start_time: datetime,
    end_time: datetime,
) -> ActivityBatch:
    observed_at = datetime.now(UTC)
    scope = f"azure:subscription:{subscription_id}:activity-log"
    run_id = f"azure-ai-activity-{subscription_id}-{observed_at.isoformat()}"
    try:
        records = client.list_activity(
            subscription_id=subscription_id, start_time=start_time, end_time=end_time
        )
    except AzureDeploymentDiscoveryError as error:
        return ActivityBatch(
            connector_id="denali.azure_ai_activity",
            connection_id=connection_id,
            run_id=run_id,
            scope_key=scope,
            collected_at=observed_at,
            coverage=(
                Coverage("azure_ai_management_activity", CoverageState.FAILED, scope, str(error)),
            ),
        )
    activities: list[ActivityRecord] = []
    warnings: list[str] = []
    for position, raw in enumerate(records):
        provider = raw.get("resourceProviderName")
        provider_value = provider.get("value") if isinstance(provider, dict) else None
        if (
            not isinstance(provider_value, str)
            or provider_value.lower() not in _AZURE_AI_ACTIVITY_PROVIDERS
        ):
            continue
        source_uid = raw.get("eventDataId")
        occurred_at = _azure_timestamp(raw.get("eventTimestamp"))
        operation = raw.get("operationName")
        operation_name = operation.get("value") if isinstance(operation, dict) else None
        title = operation.get("localizedValue") if isinstance(operation, dict) else None
        if (
            not all(
                isinstance(value, str) and value for value in (source_uid, operation_name, title)
            )
            or occurred_at is None
        ):
            warnings.append(f"activity item {position}: missing stable identity")
            continue
        status = raw.get("status")
        status_value = str(status.get("value", "")).lower() if isinstance(status, dict) else ""
        outcome = (
            ActivityOutcome.SUCCESS
            if status_value in {"succeeded", "success", "accepted"}
            else ActivityOutcome.FAILURE
            if status_value in {"failed", "failure"}
            else ActivityOutcome.UNKNOWN
        )
        resource_id = raw.get("resourceId")
        activities.append(
            ActivityRecord(
                source_uid=source_uid,
                category=ActivityCategory.ADMIN_CHANGE,
                activity_name=operation_name,
                title=title,
                occurred_at=occurred_at,
                observed_at=observed_at,
                outcome=outcome,
                provider="Microsoft Azure",
                account_uid=subscription_id,
                region=raw.get("resourceRegion")
                if isinstance(raw.get("resourceRegion"), str)
                else None,
                evidence=Evidence(
                    source_type="azure_activity_log",
                    locator=f"azure://activity/{subscription_id}/{source_uid}",
                    observed_at=observed_at,
                    payload={
                        "subscription_id": subscription_id,
                        "event_id": source_uid,
                        "operation": operation_name,
                        "resource_provider": provider_value,
                        "resource_id": resource_id if isinstance(resource_id, str) else None,
                    },
                ),
            )
        )
    state = CoverageState.PARTIAL if warnings else CoverageState.COMPLETE
    detail = "; ".join(
        [
            f"Collected {len(activities)} bounded AI management events from the last 24 hours.",
            *warnings[:10],
        ]
    )
    return ActivityBatch(
        connector_id="denali.azure_ai_activity",
        connection_id=connection_id,
        run_id=run_id,
        scope_key=scope,
        collected_at=observed_at,
        coverage=(Coverage("azure_ai_management_activity", state, scope, detail),),
        activities=tuple(activities),
    )


def _azure_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _parse_resource(
    raw: dict[str, Any], *, subscription_id: str, resource_type: str
) -> dict[str, Any]:
    observed_type = str(raw.get("type", "")).lower()
    if observed_type != resource_type:
        raise ValueError("resource type did not match the requested boundary")
    resource_id = raw.get("id")
    if not isinstance(resource_id, str):
        raise ValueError("resource ID is missing")
    match = _RESOURCE_ID_RE.fullmatch(resource_id)
    if match is None or match.group("subscription").lower() != subscription_id:
        raise ValueError("resource ID escaped the selected subscription")
    expected_kind = {
        CONTAINER_APP_RESOURCE_TYPE: "containerapps",
        FUNCTION_APP_RESOURCE_TYPE: "sites",
        AKS_CLUSTER_RESOURCE_TYPE: "managedclusters",
    }[resource_type]
    if match.group("kind").lower() != expected_kind:
        raise ValueError("resource ID kind did not match the requested boundary")
    if str(raw.get("subscriptionId", "")).lower() != subscription_id:
        raise ValueError("resource subscription did not match the selected subscription")
    name = raw.get("name")
    location = raw.get("location")
    resource_group = raw.get("resourceGroup")
    if not all(isinstance(item, str) and item for item in (name, location, resource_group)):
        raise ValueError("resource name, group, or location is missing")
    if name.lower() != match.group("name").lower():
        raise ValueError("resource content identity did not match resource ID")
    if resource_group.lower() != match.group("resource_group").lower():
        raise ValueError("resource group did not match resource ID")
    kind = str(raw.get("kind", "")).lower()
    if resource_type == FUNCTION_APP_RESOURCE_TYPE and "functionapp" not in kind:
        raise ValueError("Microsoft.Web site is not a Function App")

    tags = raw.get("tags") if isinstance(raw.get("tags"), dict) else {}
    properties = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
    identity = raw.get("identity") if isinstance(raw.get("identity"), dict) else {}
    model_keys = _model_configuration_keys(properties, resource_type)
    classification: list[str] = []
    if str(tags.get("denali_ai_workload", "")).lower() == "true":
        classification.append("explicit_ai_workload_tag")
    if model_keys:
        classification.append("model_configuration_key")
    if resource_type == AKS_CLUSTER_RESOURCE_TYPE:
        classification = []

    containers = _containers(properties) if resource_type == CONTAINER_APP_RESOURCE_TYPE else []
    images = [
        item.get("image")
        for item in containers
        if isinstance(item, dict) and isinstance(item.get("image"), str)
    ]
    principal_id = identity.get("principalId")
    if not isinstance(principal_id, str) or not principal_id:
        principal_id = None
    revision = (
        properties.get("latestReadyRevisionName")
        or properties.get("latestRevisionName")
        or properties.get("deploymentId")
    )
    endpoint = (
        _nested(properties, "configuration", "ingress", "fqdn")
        if resource_type == CONTAINER_APP_RESOURCE_TYPE
        else properties.get("defaultHostName")
    )
    if resource_type == AKS_CLUSTER_RESOURCE_TYPE:
        revision = properties.get("currentKubernetesVersion")
        endpoint = properties.get("fqdn")
    return {
        "natural_key": resource_id.lower(),
        "name": name,
        "location": location.lower().replace(" ", ""),
        "resource_group": resource_group.lower(),
        "subscription_id": subscription_id,
        "resource_type": resource_type,
        "service": {
            CONTAINER_APP_RESOURCE_TYPE: "azure_container_apps",
            FUNCTION_APP_RESOURCE_TYPE: "azure_functions",
            AKS_CLUSTER_RESOURCE_TYPE: "aks",
        }[resource_type],
        "runtime_kind": {
            CONTAINER_APP_RESOURCE_TYPE: "container_service",
            FUNCTION_APP_RESOURCE_TYPE: "serverless_function",
            AKS_CLUSTER_RESOURCE_TYPE: "kubernetes_cluster",
        }[resource_type],
        "resource_uid": properties.get("resourceGuid") or properties.get("environmentId"),
        "state": properties.get("provisioningState") or properties.get("state"),
        "revision": revision if isinstance(revision, str) else None,
        "managed_identity_principal_id": principal_id,
        "endpoint": endpoint if isinstance(endpoint, str) else None,
        "images": images,
        "model_configuration_keys": model_keys,
        "classification": classification,
    }


def _asset_assertions(
    parsed: dict[str, Any], observed_at: datetime, plane: str
) -> tuple[AssetRef, AssetAssertion, AssetAssertion | None, AssetAssertion | None]:
    cloud_ref = AssetRef(AssetKind.CLOUD_RESOURCE, parsed["natural_key"])
    evidence_payload = {
        "resource_type": parsed["resource_type"],
        "resource_id": parsed["natural_key"],
        "subscription_id": parsed["subscription_id"],
        "resource_group": parsed["resource_group"],
        "location": parsed["location"],
        "resource_uid": parsed["resource_uid"],
        "revision": parsed["revision"],
        "ai_classification": parsed["classification"],
        "model_configuration_keys": parsed["model_configuration_keys"],
    }
    evidence = Evidence(
        source_type="azure_resource_graph",
        locator=f"azure://resource{parsed['natural_key']}",
        observed_at=observed_at,
        payload=evidence_payload,
    )
    shared_attributes = {
        "provider": "azure",
        "service": parsed["service"],
        "runtime_kind": parsed["runtime_kind"],
        "subscription_id": parsed["subscription_id"],
        "resource_group": parsed["resource_group"],
        "location": parsed["location"],
        "resource_uid": parsed["resource_uid"],
        "state": parsed["state"],
        "revision": parsed["revision"],
        "managed_identity_principal_id": parsed["managed_identity_principal_id"],
        "endpoint": parsed["endpoint"],
        "model_configuration_keys": parsed["model_configuration_keys"],
        "ai_classification": parsed["classification"],
    }
    cloud_assertion = AssetAssertion(
        asset=cloud_ref,
        coverage_plane=plane,
        display_name=parsed["name"],
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=evidence,
        attributes=shared_attributes,
    )
    if not parsed["classification"]:
        return cloud_ref, cloud_assertion, None, None

    name_identifier = (
        "container_app_name" if parsed["service"] == "azure_container_apps" else "function_app_name"
    )
    workload_attributes = {
        **shared_attributes,
        "deployment_identifiers": {
            "subscription_id": [parsed["subscription_id"]],
            "resource_group": [parsed["resource_group"]],
            "location": [parsed["location"]],
            name_identifier: [parsed["name"].lower()],
        },
        **(
            {
                "deployment_artifact": {
                    "kind": "container_image",
                    "image": parsed["images"][0],
                }
            }
            if parsed["images"]
            else {}
        ),
    }
    workload_assertion = AssetAssertion(
        asset=AssetRef(AssetKind.AI_WORKLOAD, parsed["natural_key"]),
        coverage_plane=plane,
        display_name=parsed["name"],
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=evidence,
        attributes=workload_attributes,
    )
    identity_assertion = None
    if parsed["managed_identity_principal_id"]:
        principal_id = parsed["managed_identity_principal_id"].lower()
        identity_assertion = AssetAssertion(
            asset=AssetRef(AssetKind.IDENTITY, f"azure:principal:{principal_id}"),
            coverage_plane=plane,
            display_name=principal_id,
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=evidence,
            attributes={
                "provider": "azure",
                "identity_type": "managed_identity",
                "subscription_id": parsed["subscription_id"],
            },
        )
    return cloud_ref, cloud_assertion, workload_assertion, identity_assertion


def _containers(properties: dict[str, Any]) -> list[Any]:
    template = properties.get("template")
    if not isinstance(template, dict):
        return []
    containers = template.get("containers")
    return containers if isinstance(containers, list) else []


def _model_configuration_keys(properties: dict[str, Any], resource_type: str) -> list[str]:
    keys: set[str] = set()
    if resource_type == CONTAINER_APP_RESOURCE_TYPE:
        for container in _containers(properties):
            if not isinstance(container, dict):
                continue
            environment = container.get("env")
            if not isinstance(environment, list):
                continue
            for item in environment:
                if isinstance(item, dict) and isinstance(item.get("name"), str):
                    keys.add(item["name"])
    return sorted(item for item in keys if _MODEL_KEY_RE.fullmatch(item))


def _nested(value: dict[str, Any], *path: str) -> Any:
    current: Any = value
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _safe_error_code(error: Exception) -> str:
    response = getattr(error, "response", None)
    if response is not None:
        try:
            payload = response.json()
        except Exception:
            payload = None
        if isinstance(payload, dict):
            nested = payload.get("error")
            if isinstance(nested, dict) and nested.get("code"):
                return str(nested["code"])
        status = getattr(response, "status_code", None)
        if status is not None:
            return str(status)
    return error.__class__.__name__
