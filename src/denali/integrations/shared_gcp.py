"""Org-bound metadata reads from Platform; Google credentials never reach Denali."""

from __future__ import annotations

import os
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from denali.connections.gcp import GCP_SCOPES, valid_gcp_project_id
from denali.integrations.shared_connections_client import SharedConnectionsClient

OPERATIONS = {
    "gcp.vertex_ai": "vertex_resources",
    "gcp.agent_builder": "agent_resources",
    "gcp.code_to_cloud": "deployment_resources",
    "gcp.ai_activity": "ai_activity",
}
ASSET_OPERATIONS = {
    "aiplatform.googleapis.com/Endpoint": "vertex_resources",
    "aiplatform.googleapis.com/ReasoningEngine": "vertex_resources",
    "aiplatform.googleapis.com/CachedContent": "vertex_resources",
    "aiplatform.googleapis.com/Model": "vertex_resources",
    "aiplatform.googleapis.com/Dataset": "vertex_resources",
    "aiplatform.googleapis.com/PipelineJob": "vertex_resources",
    "aiplatform.googleapis.com/CustomJob": "vertex_resources",
    "aiplatform.googleapis.com/NotebookRuntime": "vertex_resources",
    "discoveryengine.googleapis.com/Assistant": "agent_resources",
    "discoveryengine.googleapis.com/DataStore": "agent_resources",
    "discoveryengine.googleapis.com/Engine": "agent_resources",
    "dialogflow.googleapis.com/Agent": "agent_resources",
    "dialogflow.googleapis.com/ConversationProfile": "agent_resources",
    "dialogflow.googleapis.com/KnowledgeBase": "agent_resources",
    "run.googleapis.com/Service": "deployment_resources",
    "cloudfunctions.googleapis.com/Function": "deployment_resources",
    "container.googleapis.com/Cluster": "deployment_resources",
}


def shared_gcp_enabled() -> bool:
    return os.environ.get("DENALI_PLATFORM_GCP_ENABLED", "false").lower() == "true"


def selected_projects(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        raise ValueError("shared Google Cloud project boundary is invalid")
    projects: list[dict[str, str]] = []
    for project in value:
        if (
            not isinstance(project, dict)
            or not isinstance(project.get("id"), str)
            or not valid_gcp_project_id(project["id"])
            or not isinstance(project.get("number"), str)
            or not re.fullmatch(r"[0-9]{6,20}", project["number"])
        ):
            raise ValueError("shared Google Cloud project boundary is invalid")
        projects.append({"id": project["id"], "number": project["number"], "name": project["id"]})
    if len({p["id"] for p in projects}) != len(projects) or len(
        {p["number"] for p in projects}
    ) != len(projects):
        raise ValueError("shared Google Cloud project boundary is duplicated")
    return sorted(projects, key=lambda project: project["id"])


class SharedGcpReader:
    def __init__(
        self, connection: dict[str, Any], *, client: SharedConnectionsClient | None = None
    ):
        if not shared_gcp_enabled():
            raise ValueError("shared Google Cloud is disabled")
        if connection.get("credential_type") != "platform_shared_gcp":
            raise ValueError("connection is not shared Google Cloud")
        try:
            platform_id = UUID(str(connection["credential_reference"]["platform_connection_id"]))
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("shared Google Cloud reference is invalid") from error
        org = connection.get("clerk_organization_id")
        if (
            str(platform_id) != str(connection.get("id"))
            or not isinstance(org, str)
            or not re.fullmatch(r"org_[A-Za-z0-9]+", org)
            or connection.get("lifecycle_state") != "active"
            or connection.get("configuration", {}).get("coverage_mode") != "selected-projects"
        ):
            raise ValueError("shared Google Cloud identity boundary is invalid")
        scopes = connection.get("declared_scopes")
        if (
            not isinstance(scopes, list)
            or not scopes
            or any(not isinstance(s, str) for s in scopes)
            or len(set(scopes)) != len(scopes)
            or not set(scopes) <= set(GCP_SCOPES)
        ):
            raise ValueError("shared Google Cloud scope boundary is invalid")
        self.projects = selected_projects(connection["configuration"].get("projects"))
        self.scopes = frozenset(scopes)
        self._org = org
        self._id = platform_id
        self._client = client or SharedConnectionsClient.from_environment()
        if self._client is None or not self._client.allows_org(org):
            raise ValueError("shared Google Cloud organization is not enabled")

    def read(
        self,
        project_id: str,
        operation: str,
        *,
        asset_type: str | None = None,
        page_token: str | None = None,
        page_size: int = 100,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
    ) -> dict[str, Any]:
        scope = next((s for s, op in OPERATIONS.items() if op == operation), None)
        if (
            scope not in self.scopes
            or project_id not in {p["id"] for p in self.projects}
            or not 1 <= page_size <= 100
            or (asset_type is not None and ASSET_OPERATIONS.get(asset_type) != operation)
        ):
            raise ValueError("shared Google Cloud read selection is invalid")
        payload: dict[str, Any] = {
            "project_id": project_id,
            "operation": operation,
            "page_size": page_size,
        }
        if asset_type:
            payload["asset_type"] = asset_type
        if operation == "ai_activity":
            end = window_end or datetime.now(UTC)
            start = window_start or end - timedelta(hours=24)
            if (
                start.tzinfo is None
                or end.tzinfo is None
                or not timedelta(0) < end - start <= timedelta(hours=24)
                or end > datetime.now(UTC) + timedelta(minutes=5)
            ):
                raise ValueError("shared Google Cloud activity window is invalid")
            payload.update(window_start=start.isoformat(), window_end=end.isoformat())
        if page_token:
            if not isinstance(page_token, str) or len(page_token) > 2048:
                raise ValueError("shared Google Cloud page token is invalid")
            payload["page_token"] = page_token
        result = self._client.request(
            "POST",
            f"/internal/v1/connections/gcp/{self._id}/read",
            clerk_org_id=self._org,
            payload=payload,
        )
        if (
            not isinstance(result, dict)
            or result.get("project_id") != project_id
            or result.get("operation") != operation
            or not isinstance(result.get("items"), list)
            or len(result["items"]) > page_size
            or any(not isinstance(item, dict) for item in result["items"])
            or result.get("next_page_token") is not None
            and (
                not isinstance(result["next_page_token"], str)
                or len(result["next_page_token"]) > 2048
            )
        ):
            raise ValueError("shared Google Cloud read response is invalid")
        return result

    def list_assets(self, *, project_id: str, asset_type: str) -> tuple[dict[str, Any], ...]:
        from denali.connectors.gcp_deployments import GcpDeploymentDiscoveryError

        operation = ASSET_OPERATIONS.get(asset_type)
        records: list[dict[str, Any]] = []
        token = None
        seen: set[str] = set()
        try:
            for _ in range(100):
                result = self.read(
                    project_id, str(operation), asset_type=asset_type, page_token=token
                )
                for item in result["items"]:
                    asset = item.get("asset")
                    if not isinstance(asset, dict) or asset.get("assetType") != asset_type:
                        raise ValueError("shared Google Cloud asset projection is invalid")
                    records.append(asset)
                if len(records) > 10_000:
                    raise ValueError("shared Google Cloud asset limit reached")
                token = result.get("next_page_token")
                if not token:
                    return tuple(records)
                if token in seen:
                    raise ValueError("shared Google Cloud page token repeated")
                seen.add(token)
            raise ValueError("shared Google Cloud page limit reached")
        except Exception as error:
            raise GcpDeploymentDiscoveryError("platform:ListAssets:unavailable") from error

    def list_entries(
        self, *, resource_names: list[str], filter_: str, order_by: str, page_size: int
    ) -> Iterator[dict[str, Any]]:
        # The originating connector supplies its known query, not arbitrary user filters.
        # Platform owns the fixed 24-hour AI audit metadata query and never accepts it.
        if len(resource_names) != 1 or not resource_names[0].startswith("projects/"):
            raise ValueError("shared Google Cloud logging boundary is invalid")
        project_id = resource_names[0].removeprefix("projects/")
        match = re.fullmatch(
            r'protoPayload.serviceName="aiplatform.googleapis.com" '
            r'AND timestamp>="([^"]+)" AND timestamp<="([^"]+)"',
            filter_,
        )
        if match is None or order_by != "timestamp asc" or page_size != 1000:
            raise ValueError("shared Google Cloud activity query is invalid")
        start = datetime.fromisoformat(match.group(1))
        end = datetime.fromisoformat(match.group(2))
        token = None
        seen: set[str] = set()
        count = 0
        for _ in range(51):
            result = self.read(
                project_id,
                "ai_activity",
                page_token=token,
                page_size=100,
                window_start=start,
                window_end=end,
            )
            for item in result["items"]:
                entry = item.get("entry")
                if not isinstance(entry, dict):
                    raise ValueError("shared Google Cloud activity projection is invalid")
                # Denali's existing normalizer implements Vertex AI activity semantics.
                proto = entry.get("protoPayload")
                if not isinstance(proto, dict):
                    raise ValueError("shared Google Cloud activity projection is invalid")
                if proto.get("serviceName") == "aiplatform.googleapis.com":
                    yield entry
                    count += 1
                    if count > 5000:
                        return
            token = result.get("next_page_token")
            if not token:
                return
            if token in seen:
                raise ValueError("shared Google Cloud page token repeated")
            seen.add(token)
        raise ValueError("shared Google Cloud logging page limit reached")
