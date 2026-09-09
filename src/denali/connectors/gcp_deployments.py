"""Bounded Cloud Run, Cloud Run functions, and GKE deployment inventory."""

from __future__ import annotations

import argparse
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from denali.connections.gcp import (
    GCP_SCOPE_AGENT_BUILDER,
    GCP_SCOPE_AI_ACTIVITY,
    GCP_SCOPE_CODE_TO_CLOUD,
    GCP_SCOPE_VERTEX_AI,
    authorized_gcp_credential,
    authorized_gcp_request,
    valid_gcp_project_id,
)
from denali.connectors.container_images import image_digests
from denali.connectors.gcp_vertex_activity import GcpVertexActivityConnector
from denali.domain import (
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
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.gcp_deployments"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True)
CLOUD_RUN_ASSET_TYPE = "run.googleapis.com/Service"
CLOUD_FUNCTION_ASSET_TYPE = "cloudfunctions.googleapis.com/Function"
GKE_CLUSTER_ASSET_TYPE = "container.googleapis.com/Cluster"
CLOUD_RUN_INVENTORY_PLANE = "gcp_cloud_run_inventory"
CLOUD_RUN_RELATIONSHIP_PLANE = "gcp_cloud_run_relationships"
CLOUD_FUNCTION_INVENTORY_PLANE = "gcp_cloud_functions_gen2_inventory"
CLOUD_FUNCTION_RELATIONSHIP_PLANE = "gcp_cloud_functions_gen2_relationships"
GKE_CLUSTER_INVENTORY_PLANE = "gcp_gke_cluster_inventory"
GKE_CLUSTER_RELATIONSHIP_PLANE = "gcp_gke_cluster_relationships"
MAX_ASSETS_PER_TYPE = 10_000
MAX_PAGES_PER_TYPE = 100
PAGE_SIZE = 1_000

_GCP_AI_PLANES = {
    GCP_SCOPE_VERTEX_AI: (
        (
            "gcp_vertex_ai_runtime_inventory",
            (
                "aiplatform.googleapis.com/Endpoint",
                "aiplatform.googleapis.com/ReasoningEngine",
                "aiplatform.googleapis.com/CachedContent",
            ),
        ),
        (
            "gcp_vertex_ai_development_inventory",
            (
                "aiplatform.googleapis.com/Model",
                "aiplatform.googleapis.com/Dataset",
                "aiplatform.googleapis.com/PipelineJob",
                "aiplatform.googleapis.com/CustomJob",
                "aiplatform.googleapis.com/NotebookRuntime",
            ),
        ),
    ),
    GCP_SCOPE_AGENT_BUILDER: (
        (
            "gcp_agent_builder_inventory",
            (
                "discoveryengine.googleapis.com/Assistant",
                "discoveryengine.googleapis.com/DataStore",
                "discoveryengine.googleapis.com/Engine",
            ),
        ),
        (
            "gcp_dialogflow_inventory",
            (
                "dialogflow.googleapis.com/Agent",
                "dialogflow.googleapis.com/ConversationProfile",
                "dialogflow.googleapis.com/KnowledgeBase",
            ),
        ),
    ),
}

_GCP_AI_KINDS = {
    "aiplatform.googleapis.com/Endpoint": AssetKind.AI_WORKLOAD,
    "aiplatform.googleapis.com/ReasoningEngine": AssetKind.AI_AGENT,
    "aiplatform.googleapis.com/Model": AssetKind.AI_MODEL,
    "aiplatform.googleapis.com/Dataset": AssetKind.AI_DATASTORE,
    "aiplatform.googleapis.com/PipelineJob": AssetKind.AI_PIPELINE,
    "aiplatform.googleapis.com/CustomJob": AssetKind.AI_WORKLOAD,
    "discoveryengine.googleapis.com/Assistant": AssetKind.AI_AGENT,
    "discoveryengine.googleapis.com/DataStore": AssetKind.AI_DATASTORE,
    "discoveryengine.googleapis.com/Engine": AssetKind.AI_APPLICATION,
    "dialogflow.googleapis.com/Agent": AssetKind.AI_AGENT,
    "dialogflow.googleapis.com/ConversationProfile": AssetKind.AI_APPLICATION,
    "dialogflow.googleapis.com/KnowledgeBase": AssetKind.AI_DATASTORE,
}

_MODEL_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*MODEL_ID$")
_SAFE_MODEL_VALUE_KEYS = frozenset({"VERTEX_MODEL_ID", "GEMINI_MODEL_ID", "GOOGLE_MODEL_ID"})
_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_RESOURCE_NAMES = {
    CLOUD_RUN_ASSET_TYPE: re.compile(
        r"^//run\.googleapis\.com/projects/(?P<project>[^/]+)/locations/"
        r"(?P<location>[^/]+)/services/(?P<name>[^/]+)$"
    ),
    CLOUD_FUNCTION_ASSET_TYPE: re.compile(
        r"^//cloudfunctions\.googleapis\.com/projects/(?P<project>[^/]+)/locations/"
        r"(?P<location>[^/]+)/functions/(?P<name>[^/]+)$"
    ),
    GKE_CLUSTER_ASSET_TYPE: re.compile(
        r"^//container\.googleapis\.com/projects/(?P<project>[^/]+)/locations/"
        r"(?P<location>[^/]+)/clusters/(?P<name>[^/]+)$"
    ),
}


class GcpDeploymentDiscoveryError(RuntimeError):
    """A stable Google Cloud discovery failure without response or credential material."""


class GcpAssetClient(Protocol):
    def list_assets(self, *, project_id: str, asset_type: str) -> tuple[dict[str, Any], ...]: ...


class InventorySink(Protocol):
    def ingest(self, tenant_id: str, batch: InventoryBatch) -> dict[str, int]: ...

    def ingest_activity(self, tenant_id: str, batch: Any) -> dict[str, int]: ...


class GcpCloudAssetRestClient:
    """Small bounded Cloud Asset Inventory RESOURCE client."""

    def __init__(self, request: Callable[..., Any]):
        self._request = request

    def list_assets(self, *, project_id: str, asset_type: str) -> tuple[dict[str, Any], ...]:
        records: list[dict[str, Any]] = []
        page_token: str | None = None
        for _ in range(MAX_PAGES_PER_TYPE):
            params: list[tuple[str, str]] = [
                ("assetTypes", asset_type),
                ("contentType", "RESOURCE"),
                ("pageSize", str(PAGE_SIZE)),
            ]
            if page_token:
                params.append(("pageToken", page_token))
            try:
                response = self._request(
                    "GET",
                    f"https://cloudasset.googleapis.com/v1/projects/{project_id}/assets",
                    params=params,
                    timeout=30.0,
                )
                response.raise_for_status()
                payload = response.json()
            except Exception as error:
                raise GcpDeploymentDiscoveryError(
                    f"cloudasset:ListAssets:{_safe_error_code(error)}"
                ) from None
            if not isinstance(payload, dict) or not isinstance(payload.get("assets", []), list):
                raise GcpDeploymentDiscoveryError("cloudasset:ListAssets:invalid_response_shape")
            for item in payload.get("assets", []):
                if isinstance(item, dict):
                    records.append(item)
                    if len(records) > MAX_ASSETS_PER_TYPE:
                        raise GcpDeploymentDiscoveryError(
                            f"cloudasset:ListAssets:record_limit_{MAX_ASSETS_PER_TYPE}"
                        )
            next_token = payload.get("nextPageToken")
            if next_token is None or next_token == "":
                return tuple(records)
            if not isinstance(next_token, str):
                raise GcpDeploymentDiscoveryError("cloudasset:ListAssets:invalid_page_token")
            page_token = next_token
        raise GcpDeploymentDiscoveryError(f"cloudasset:ListAssets:page_limit_{MAX_PAGES_PER_TYPE}")


class GcpConnectionDeploymentCollector:
    """Collect every exact project selected on one active GCP connection."""

    def __init__(
        self,
        asset_client_factory: Callable[[str], GcpAssetClient] | None = None,
    ):
        self._asset_client_factory = asset_client_factory or (
            lambda principal: GcpCloudAssetRestClient(authorized_gcp_request(principal))
        )

    def collect(
        self,
        *,
        tenant_id: str,
        connection: dict[str, Any],
        repository: InventorySink,
    ) -> dict[str, Any]:
        if connection.get("provider") != "gcp":
            raise ValueError("connection is not a Google Cloud connection")
        if connection.get("lifecycle_state") != "active":
            raise ValueError("disabled Google Cloud connections cannot collect")
        scopes = set(connection.get("declared_scopes", []))
        if not scopes & {
            GCP_SCOPE_CODE_TO_CLOUD,
            GCP_SCOPE_AI_ACTIVITY,
            GCP_SCOPE_VERTEX_AI,
            GCP_SCOPE_AGENT_BUILDER,
        }:
            raise ValueError("Google Cloud connection has no supported collection scope")
        configuration = connection.get("configuration", {})
        projects = configuration.get("projects", [])
        configured_resource_names = configuration.get("resource_names")
        configured_display_names = configuration.get("resource_display_names")
        principal = connection.get("credential_reference", {}).get("principal_email")
        if not isinstance(projects, list) or not projects or not isinstance(principal, str):
            raise ValueError("complete Google Cloud project selection before collecting")
        if configured_resource_names is not None and (
            not isinstance(configured_resource_names, list)
            or not configured_resource_names
            or any(not isinstance(item, str) for item in configured_resource_names)
        ):
            raise ValueError("Google Cloud resource_names must be a non-empty string list")
        if configured_display_names is not None and (
            not isinstance(configured_display_names, dict)
            or any(
                not isinstance(key, str) or not isinstance(value, str) or not value.strip()
                for key, value in configured_display_names.items()
            )
        ):
            raise ValueError("Google Cloud resource_display_names must map strings to names")
        if configured_resource_names is not None and configured_display_names is not None:
            undeclared_names = set(configured_display_names) - set(configured_resource_names)
            if undeclared_names:
                raise ValueError(
                    "Google Cloud resource_display_names must stay inside resource_names"
                )

        client = self._asset_client_factory(principal)
        activity_credentials = None
        cloud_logging = None
        if GCP_SCOPE_AI_ACTIVITY in scopes:
            from google.cloud import logging as cloud_logging_module

            activity_credentials = authorized_gcp_credential(principal)
            cloud_logging = cloud_logging_module
        project_results: list[dict[str, Any]] = []
        failed = 0
        partial = 0
        for project in projects:
            project_id = project.get("id") if isinstance(project, dict) else None
            project_number = project.get("number") if isinstance(project, dict) else None
            if not isinstance(project_id, str) or not isinstance(project_number, str):
                failed += 1
                project_results.append({"project_id": str(project_id), "state": "failed"})
                continue
            batch = None
            all_coverage: list[Coverage] = []
            ai_inventory_assets = 0
            for scope_name, plane_groups in _GCP_AI_PLANES.items():
                if scope_name not in scopes:
                    continue
                for plane, asset_types in plane_groups:
                    ai_batch = _gcp_ai_inventory_batch(
                        project_id=project_id,
                        project_number=project_number,
                        connection_id=str(connection["id"]),
                        client=client,
                        plane=plane,
                        asset_types=asset_types,
                    )
                    repository.ingest(tenant_id, ai_batch)
                    ai_inventory_assets += len(ai_batch.assets)
                    all_coverage.extend(ai_batch.coverage)
            if GCP_SCOPE_CODE_TO_CLOUD in scopes:
                batch = GcpDeploymentConnector(
                    project_id=project_id,
                    project_number=project_number,
                    asset_client=client,
                    included_resource_names=(
                        tuple(configured_resource_names)
                        if configured_resource_names is not None
                        else None
                    ),
                    resource_display_names=configured_display_names,
                ).collect(connection_id=str(connection["id"]))
                repository.ingest(tenant_id, batch)
                all_coverage.extend(batch.coverage)
            activity_count = 0
            if GCP_SCOPE_AI_ACTIVITY in scopes and cloud_logging is not None:
                end_time = datetime.now(UTC)
                activity_batch = GcpVertexActivityConnector(
                    project_id=project_id,
                    logging_client=cloud_logging.Client(
                        project=project_id, credentials=activity_credentials
                    ),
                ).collect(
                    start_time=end_time - timedelta(hours=24),
                    end_time=end_time,
                    connection_id=str(connection["id"]),
                )
                repository.ingest_activity(tenant_id, activity_batch)
                activity_count = len(activity_batch.activities)
                all_coverage.extend(activity_batch.coverage)
            states = {item.state for item in all_coverage}
            if CoverageState.FAILED in states:
                state = "failed"
                failed += 1
            elif CoverageState.PARTIAL in states:
                state = "partial"
                partial += 1
            else:
                state = "complete"
            project_results.append(
                {
                    "project_id": project_id,
                    "project_number": project_number,
                    "state": state,
                    "assets": (len(batch.assets) if batch else 0) + ai_inventory_assets,
                    "ai_workloads": sum(
                        item.asset.kind is AssetKind.AI_WORKLOAD
                        for item in (batch.assets if batch else ())
                    ),
                    "activity_events": activity_count,
                }
            )
        completed_at = datetime.now(UTC).isoformat()
        overall_state = (
            "failed" if failed == len(projects) else "partial" if failed or partial else "complete"
        )
        return {
            "connection_id": str(connection["id"]),
            "state": overall_state,
            "completed_at": completed_at,
            "project_count": len(projects),
            "failed_count": failed,
            "partial_count": partial,
            "projects": project_results,
        }


class GcpDeploymentConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        *,
        project_id: str,
        asset_client: GcpAssetClient,
        project_number: str | None = None,
        included_resource_names: tuple[str, ...] | None = None,
        resource_display_names: dict[str, str] | None = None,
    ):
        if not valid_gcp_project_id(project_id):
            raise ValueError("Google Cloud project ID has an invalid shape")
        if project_number is not None and not project_number.isdigit():
            raise ValueError("Google Cloud project number must contain only digits")
        self.project_id = project_id
        self.project_number = project_number
        self.asset_client = asset_client
        self.included_resource_names = (
            frozenset(included_resource_names) if included_resource_names is not None else None
        )
        self.resource_display_names = dict(resource_display_names or {})

    def collect(self, *, connection_id: str | None = None) -> InventoryBatch:
        observed_at = datetime.now(UTC)
        connection = connection_id or f"gcp:{self.project_id}"
        scope = f"gcp:project:{self.project_id}"
        assets: dict[tuple[AssetRef, str], AssetAssertion] = {}
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, str], RelationshipAssertion
        ] = {}
        coverage: list[Coverage] = []

        for asset_type, inventory_plane, relationship_plane in (
            (
                CLOUD_RUN_ASSET_TYPE,
                CLOUD_RUN_INVENTORY_PLANE,
                CLOUD_RUN_RELATIONSHIP_PLANE,
            ),
            (
                CLOUD_FUNCTION_ASSET_TYPE,
                CLOUD_FUNCTION_INVENTORY_PLANE,
                CLOUD_FUNCTION_RELATIONSHIP_PLANE,
            ),
            (
                GKE_CLUSTER_ASSET_TYPE,
                GKE_CLUSTER_INVENTORY_PLANE,
                GKE_CLUSTER_RELATIONSHIP_PLANE,
            ),
        ):
            warnings: list[str] = []
            try:
                raw_assets = self.asset_client.list_assets(
                    project_id=self.project_id,
                    asset_type=asset_type,
                )
            except GcpDeploymentDiscoveryError as error:
                detail = str(error)
                coverage.extend(
                    (
                        Coverage(inventory_plane, CoverageState.FAILED, scope, detail),
                        Coverage(relationship_plane, CoverageState.FAILED, scope, detail),
                    )
                )
                continue

            ai_workloads = 0
            selected_resources = 0
            for position, raw in enumerate(raw_assets):
                if (
                    self.included_resource_names is not None
                    and raw.get("name") not in self.included_resource_names
                ):
                    continue
                selected_resources += 1
                try:
                    parsed = _parse_asset(
                        raw,
                        project_id=self.project_id,
                        project_number=self.project_number,
                        asset_type=asset_type,
                    )
                except ValueError as error:
                    warnings.append(f"{asset_type} item {position}: {error}")
                    continue
                if parsed is None:
                    continue
                parsed["display_name"] = self.resource_display_names.get(
                    parsed["natural_key"], parsed["name"]
                )
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
                for configuration_key, model_id in parsed["model_configuration"].items():
                    model_ref = AssetRef(AssetKind.AI_MODEL, f"gcp:vertex:model:{model_id}")
                    model_evidence = Evidence(
                        source_type="gcp_cloud_asset_inventory",
                        locator=(f"gcp://cloudasset/{parsed['natural_key'].removeprefix('//')}"),
                        observed_at=observed_at,
                        payload={
                            "model_id": model_id,
                            "configuration_key": configuration_key,
                            "classification": "allow_listed_model_configuration",
                            "workload": parsed["natural_key"],
                        },
                    )
                    assets.setdefault(
                        (model_ref, inventory_plane),
                        AssetAssertion(
                            asset=model_ref,
                            coverage_plane=inventory_plane,
                            display_name=model_id,
                            assertion_type=AssertionType.OBSERVED,
                            confidence=1.0,
                            evidence=model_evidence,
                            attributes={
                                "provider": "gcp_vertex_ai",
                                "model_id": model_id,
                            },
                        ),
                    )
                    self._add_relationship(
                        relationships,
                        workload_ref,
                        model_ref,
                        RelationshipKind.USES,
                        relationship_plane,
                        model_evidence,
                    )

            state = CoverageState.PARTIAL if warnings else CoverageState.COMPLETE
            summary = (
                f"Observed {len(raw_assets)} {asset_type} resources; "
                + (
                    f"selected {selected_resources} by exact resource name; "
                    if self.included_resource_names is not None
                    else ""
                )
                + f"classified {ai_workloads} as AI workloads."
            )
            detail = "; ".join([summary, *warnings[:10]])
            coverage.extend(
                (
                    Coverage(inventory_plane, state, scope, detail),
                    Coverage(relationship_plane, state, scope, detail),
                )
            )

        return InventoryBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=f"gcp-deployments-{self.project_id}-{observed_at.isoformat()}",
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


def _gcp_ai_inventory_batch(
    *,
    project_id: str,
    project_number: str,
    connection_id: str,
    client: GcpAssetClient,
    plane: str,
    asset_types: tuple[str, ...],
) -> InventoryBatch:
    observed_at = datetime.now(UTC)
    scope = f"gcp:project:{project_id}"
    assertions: list[AssetAssertion] = []
    warnings: list[str] = []
    failed_types = 0
    for asset_type in asset_types:
        try:
            records = client.list_assets(project_id=project_id, asset_type=asset_type)
        except GcpDeploymentDiscoveryError as error:
            failed_types += 1
            warnings.append(str(error))
            continue
        for position, raw in enumerate(records):
            natural_key = raw.get("name") if isinstance(raw, dict) else None
            observed_type = raw.get("assetType") if isinstance(raw, dict) else None
            if observed_type != asset_type or not isinstance(natural_key, str):
                warnings.append(f"{asset_type} item {position}: invalid resource identity")
                continue
            project_markers = (f"/projects/{project_id}/", f"/projects/{project_number}/")
            if not any(marker in natural_key for marker in project_markers):
                warnings.append(f"{asset_type} item {position}: resource escaped project")
                continue
            resource = raw.get("resource") if isinstance(raw.get("resource"), dict) else {}
            data = resource.get("data") if isinstance(resource.get("data"), dict) else {}
            display_name = next(
                (
                    value
                    for value in (data.get("displayName"), data.get("name"))
                    if isinstance(value, str) and value
                ),
                natural_key.rsplit("/", 1)[-1],
            )
            evidence = Evidence(
                source_type="gcp_cloud_asset_inventory",
                locator=f"gcp://cloudasset/{natural_key.removeprefix('//')}",
                observed_at=observed_at,
                payload={
                    "project_id": project_id,
                    "project_number": project_number,
                    "asset_type": asset_type,
                    "resource_name": natural_key,
                },
            )
            assertions.append(
                AssetAssertion(
                    asset=AssetRef(
                        _GCP_AI_KINDS.get(asset_type, AssetKind.CLOUD_RESOURCE), natural_key
                    ),
                    coverage_plane=plane,
                    display_name=display_name,
                    assertion_type=AssertionType.OBSERVED,
                    confidence=1.0,
                    evidence=evidence,
                    attributes={
                        "provider": "gcp",
                        "project_id": project_id,
                        "project_number": project_number,
                        "asset_type": asset_type,
                        "resource_name": natural_key,
                    },
                )
            )
    state = (
        CoverageState.FAILED
        if failed_types == len(asset_types)
        else CoverageState.PARTIAL
        if failed_types or warnings
        else CoverageState.COMPLETE
    )
    detail = "; ".join(
        [
            f"Observed {len(assertions)} resources across {len(asset_types)} AI resource types.",
            *warnings[:10],
        ]
    )
    return InventoryBatch(
        connector_id="denali.gcp_ai_inventory",
        connection_id=connection_id,
        run_id=f"gcp-ai-inventory-{plane}-{project_id}-{observed_at.isoformat()}",
        scope_key=scope,
        collected_at=observed_at,
        coverage=(Coverage(plane, state, scope, detail),),
        assets=tuple(assertions),
    )


def _parse_asset(
    raw: dict[str, Any],
    *,
    project_id: str,
    project_number: str | None,
    asset_type: str,
) -> dict[str, Any] | None:
    if raw.get("assetType") != asset_type:
        raise ValueError("asset type did not match the requested boundary")
    natural_key = raw.get("name")
    if not isinstance(natural_key, str):
        raise ValueError("resource name is missing")
    match = _RESOURCE_NAMES[asset_type].fullmatch(natural_key)
    if match is None or match.group("project") != project_id:
        raise ValueError("resource name escaped the selected project")
    resource = raw.get("resource")
    data = resource.get("data") if isinstance(resource, dict) else None
    if not isinstance(data, dict):
        raise ValueError("RESOURCE content is missing")
    expected_name = natural_key.split(".com/", 1)[-1]
    ancestor_number = _project_number(raw.get("ancestors"))
    if project_number and ancestor_number and project_number != ancestor_number:
        raise ValueError("resource project number did not match the selected project")
    observed_project_number = project_number or ancestor_number
    if asset_type == CLOUD_RUN_ASSET_TYPE and not observed_project_number:
        metadata = data.get("metadata")
        namespace = metadata.get("namespace") if isinstance(metadata, dict) else None
        if isinstance(namespace, str) and namespace.isdigit():
            observed_project_number = namespace

    if asset_type == CLOUD_RUN_ASSET_TYPE:
        data = _normalize_cloud_run_data(
            data,
            expected_name=expected_name,
            service_name=match.group("name"),
            project_id=project_id,
            project_number=observed_project_number,
        )
    elif data.get("name") != expected_name:
        raise ValueError("resource content identity did not match asset identity")

    if asset_type == CLOUD_FUNCTION_ASSET_TYPE and data.get("environment") != "GEN_2":
        return None
    if asset_type == GKE_CLUSTER_ASSET_TYPE:
        return {
            "natural_key": natural_key,
            "name": match.group("name"),
            "location": match.group("location"),
            "project_id": project_id,
            "project_number": observed_project_number,
            "asset_type": asset_type,
            "service": "gke",
            "runtime_kind": "kubernetes_cluster",
            "resource_uid": data.get("id") or data.get("selfLink"),
            "state": data.get("status"),
            "update_time": data.get("createTime"),
            "revision": data.get("currentMasterVersion"),
            "service_account": None,
            "endpoint": data.get("endpoint"),
            "images": [],
            "model_configuration_keys": [],
            "model_configuration": {},
            "classification": [],
        }
    labels = data.get("labels") if isinstance(data.get("labels"), dict) else {}
    model_configuration = _model_configuration(data, asset_type)
    model_keys = _model_configuration_keys(data, asset_type)
    classification = []
    if str(labels.get("denali_ai_workload", "")).lower() == "true":
        classification.append("explicit_ai_workload_label")
    if model_keys:
        classification.append("model_configuration_key")
    template = data.get("template") if isinstance(data.get("template"), dict) else {}
    service_config = (
        data.get("serviceConfig") if isinstance(data.get("serviceConfig"), dict) else {}
    )
    containers = template.get("containers") if isinstance(template.get("containers"), list) else []
    images = [
        item.get("image")
        for item in containers
        if isinstance(item, dict) and isinstance(item.get("image"), str)
    ]
    service_account = (
        template.get("serviceAccount")
        if asset_type == CLOUD_RUN_ASSET_TYPE
        else service_config.get("serviceAccountEmail")
    )
    return {
        "natural_key": natural_key,
        "name": match.group("name"),
        "location": match.group("location"),
        "project_id": project_id,
        "project_number": observed_project_number,
        "asset_type": asset_type,
        "service": "cloud_run" if asset_type == CLOUD_RUN_ASSET_TYPE else "cloud_functions",
        "runtime_kind": (
            "container_service" if asset_type == CLOUD_RUN_ASSET_TYPE else "serverless_function"
        ),
        "resource_uid": data.get("uid"),
        "state": data.get("state") or _condition_state(data),
        "update_time": data.get("updateTime"),
        "revision": data.get("latestReadyRevision") or service_config.get("revision"),
        "service_account": service_account if isinstance(service_account, str) else None,
        "endpoint": data.get("uri") or service_config.get("uri") or data.get("url"),
        "images": images,
        "model_configuration_keys": model_keys,
        "model_configuration": model_configuration,
        "classification": classification,
    }


def _asset_assertions(
    parsed: dict[str, Any], observed_at: datetime, plane: str
) -> tuple[AssetRef, AssetAssertion, AssetAssertion | None, AssetAssertion | None]:
    cloud_ref = AssetRef(AssetKind.CLOUD_RESOURCE, parsed["natural_key"])
    evidence_payload = {
        "asset_type": parsed["asset_type"],
        "resource_name": parsed["natural_key"],
        "project_id": parsed["project_id"],
        "project_number": parsed["project_number"],
        "location": parsed["location"],
        "resource_uid": parsed["resource_uid"],
        "revision": parsed["revision"],
        "update_time": parsed["update_time"],
        "ai_classification": parsed["classification"],
        "model_configuration_keys": parsed["model_configuration_keys"],
        "model_configuration": parsed["model_configuration"],
    }
    evidence = Evidence(
        source_type="gcp_cloud_asset_inventory",
        locator=f"gcp://cloudasset/{parsed['natural_key'].removeprefix('//')}",
        observed_at=observed_at,
        payload=evidence_payload,
    )
    shared_attributes = {
        "provider": "gcp",
        "service": parsed["service"],
        "runtime_kind": parsed["runtime_kind"],
        "project_id": parsed["project_id"],
        "project_number": parsed["project_number"],
        "location": parsed["location"],
        "resource_uid": parsed["resource_uid"],
        "state": parsed["state"],
        "revision": parsed["revision"],
        "service_account": parsed["service_account"],
        "endpoint": parsed["endpoint"],
        "model_configuration_keys": parsed["model_configuration_keys"],
        "model_configuration": parsed["model_configuration"],
        "ai_classification": parsed["classification"],
        "image_digests": image_digests(parsed["images"]),
    }
    cloud_assertion = AssetAssertion(
        asset=cloud_ref,
        coverage_plane=plane,
        display_name=parsed["display_name"],
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=evidence,
        attributes=shared_attributes,
    )
    if not parsed["classification"]:
        return cloud_ref, cloud_assertion, None, None

    identifier_name = "service_name" if parsed["service"] == "cloud_run" else "function_name"
    deployment_identifiers = {
        "project": [parsed["project_id"]],
        "location": [parsed["location"]],
        identifier_name: [parsed["name"]],
    }
    if parsed["project_number"]:
        deployment_identifiers["project_number"] = [parsed["project_number"]]
    workload_attributes = {
        **shared_attributes,
        "deployment_identifiers": deployment_identifiers,
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
        display_name=parsed["display_name"],
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=evidence,
        attributes=workload_attributes,
    )
    identity_assertion = None
    if parsed["service_account"]:
        identity_assertion = AssetAssertion(
            asset=AssetRef(AssetKind.IDENTITY, f"gcp:service-account:{parsed['service_account']}"),
            coverage_plane=plane,
            display_name=parsed["service_account"],
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=evidence,
            attributes={
                "provider": "gcp",
                "identity_type": "service_account",
                "project_id": parsed["project_id"],
            },
        )
    return cloud_ref, cloud_assertion, workload_assertion, identity_assertion


def _model_configuration_keys(data: dict[str, Any], asset_type: str) -> list[str]:
    if asset_type == CLOUD_RUN_ASSET_TYPE:
        template = data.get("template")
        containers = template.get("containers", []) if isinstance(template, dict) else []
        keys = {
            item.get("name")
            for container in containers
            if isinstance(container, dict)
            for item in container.get("env", [])
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        }
    elif asset_type == CLOUD_FUNCTION_ASSET_TYPE:
        service_config = data.get("serviceConfig")
        environment = (
            service_config.get("environmentVariables", {})
            if isinstance(service_config, dict)
            else {}
        )
        keys = set(environment) if isinstance(environment, dict) else set()
    else:
        keys = set()
    return sorted(item for item in keys if isinstance(item, str) and _MODEL_KEY_RE.fullmatch(item))


def _model_configuration(data: dict[str, Any], asset_type: str) -> dict[str, str]:
    """Retain only explicit, non-secret model identifiers from supported runtimes."""

    entries: list[tuple[Any, Any]] = []
    if asset_type == CLOUD_RUN_ASSET_TYPE:
        template = data.get("template")
        containers = template.get("containers", []) if isinstance(template, dict) else []
        entries = [
            (item.get("name"), item.get("value"))
            for container in containers
            if isinstance(container, dict)
            for item in container.get("env", [])
            if isinstance(item, dict)
        ]
    elif asset_type == CLOUD_FUNCTION_ASSET_TYPE:
        service_config = data.get("serviceConfig")
        environment = (
            service_config.get("environmentVariables", {})
            if isinstance(service_config, dict)
            else {}
        )
        if isinstance(environment, dict):
            entries = list(environment.items())
    return {
        key: value
        for key, value in sorted(entries)
        if key in _SAFE_MODEL_VALUE_KEYS
        and isinstance(value, str)
        and _MODEL_ID_RE.fullmatch(value)
    }


def _normalize_cloud_run_data(
    data: dict[str, Any],
    *,
    expected_name: str,
    service_name: str,
    project_id: str,
    project_number: str | None,
) -> dict[str, Any]:
    """Normalize Cloud Asset's supported Cloud Run v1 or v2 resource shape."""

    if data.get("name") == expected_name:
        return data
    metadata = data.get("metadata")
    spec = data.get("spec")
    status = data.get("status")
    if (
        data.get("apiVersion") != "serving.knative.dev/v1"
        or data.get("kind") != "Service"
        or not isinstance(metadata, dict)
        or not isinstance(spec, dict)
        or not isinstance(status, dict)
        or metadata.get("name") != service_name
    ):
        raise ValueError("resource content identity did not match asset identity")
    namespace = str(metadata.get("namespace", ""))
    if namespace not in {project_id, project_number}:
        raise ValueError("Cloud Run namespace did not match the selected project")
    revision_template = spec.get("template")
    revision_spec = revision_template.get("spec") if isinstance(revision_template, dict) else None
    revision_spec = revision_spec if isinstance(revision_spec, dict) else {}
    conditions = status.get("conditions") if isinstance(status.get("conditions"), list) else []
    ready = next(
        (
            item.get("status")
            for item in conditions
            if isinstance(item, dict) and item.get("type") == "Ready"
        ),
        None,
    )
    return {
        "name": expected_name,
        "uid": metadata.get("uid"),
        "labels": metadata.get("labels"),
        "updateTime": metadata.get("creationTimestamp"),
        "latestReadyRevision": status.get("latestReadyRevisionName"),
        "uri": status.get("url"),
        "terminalCondition": {"state": ready} if ready else None,
        "template": {
            "serviceAccount": revision_spec.get("serviceAccountName"),
            "containers": revision_spec.get("containers", []),
        },
    }


def _condition_state(data: dict[str, Any]) -> str | None:
    condition = data.get("terminalCondition")
    return condition.get("state") if isinstance(condition, dict) else None


def _project_number(raw: Any) -> str | None:
    if not isinstance(raw, list):
        return None
    for ancestor in raw:
        if isinstance(ancestor, str) and ancestor.startswith("projects/"):
            value = ancestor.removeprefix("projects/")
            if value.isdigit():
                return value
    return None


def _safe_error_code(error: Exception) -> str:
    response = getattr(error, "response", None)
    status = getattr(response, "status_code", None)
    if isinstance(status, int):
        return str(status)
    return error.__class__.__name__


def scan_main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect Google Cloud Run and Cloud Run functions deployments"
    )
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--project-number")
    parser.add_argument("--principal-email", required=True)
    parser.add_argument("--connection-id")
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        raise SystemExit("--dsn or DENALI_DSN is required")
    request = authorized_gcp_request(args.principal_email)
    connector = GcpDeploymentConnector(
        project_id=args.project_id,
        project_number=args.project_number,
        asset_client=GcpCloudAssetRestClient(request),
    )
    batch = connector.collect(connection_id=args.connection_id)
    migrate(args.dsn)
    result = PostgresInventoryRepository(args.dsn).ingest(args.tenant_id, batch)
    states = ",".join(f"{item.plane}={item.state.value}" for item in batch.coverage)
    print(f"Collected {result['assets']} GCP deployment assets; {states}")
