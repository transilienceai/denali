"""Bounded Google Cloud service-account connection validation."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol

GCP_SCOPE_VERTEX_AI = "gcp.vertex_ai"
GCP_SCOPE_AGENT_BUILDER = "gcp.agent_builder"
GCP_SCOPE_AI_ACTIVITY = "gcp.ai_activity"
GCP_SCOPE_CODE_TO_CLOUD = "gcp.code_to_cloud"
GCP_SCOPES = (
    GCP_SCOPE_VERTEX_AI,
    GCP_SCOPE_AGENT_BUILDER,
    GCP_SCOPE_AI_ACTIVITY,
    GCP_SCOPE_CODE_TO_CLOUD,
)
GCP_CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
GCP_RESOURCE_MANAGER_ENDPOINT = "https://cloudresourcemanager.googleapis.com/v3"
GCP_CLOUD_ASSET_ENDPOINT = "https://cloudasset.googleapis.com/v1"
GCP_LOGGING_ENDPOINT = "https://logging.googleapis.com/v2/entries:list"
GCP_PROJECT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
GCP_SERVICE_ACCOUNT_PATTERN = re.compile(
    r"^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$"
)

_SCOPE_METADATA: dict[str, tuple[dict[str, Any], ...]] = {
    GCP_SCOPE_VERTEX_AI: (
        {
            "plane": "gcp_vertex_ai_runtime_inventory",
            "label": "Vertex AI runtime inventory",
            "permission": "cloudasset.assets.searchAllResources",
            "asset_types": [
                "aiplatform.googleapis.com/Endpoint",
                "aiplatform.googleapis.com/ReasoningEngine",
                "aiplatform.googleapis.com/CachedContent",
            ],
        },
        {
            "plane": "gcp_vertex_ai_development_inventory",
            "label": "Vertex AI development inventory",
            "permission": "cloudasset.assets.searchAllResources",
            "asset_types": [
                "aiplatform.googleapis.com/Model",
                "aiplatform.googleapis.com/Dataset",
                "aiplatform.googleapis.com/PipelineJob",
                "aiplatform.googleapis.com/CustomJob",
                "aiplatform.googleapis.com/NotebookRuntime",
            ],
        },
    ),
    GCP_SCOPE_AGENT_BUILDER: (
        {
            "plane": "gcp_agent_builder_inventory",
            "label": "Vertex AI Agent Builder inventory",
            "permission": "cloudasset.assets.searchAllResources",
            "asset_types": [
                "discoveryengine.googleapis.com/Assistant",
                "discoveryengine.googleapis.com/DataStore",
                "discoveryengine.googleapis.com/Engine",
            ],
        },
        {
            "plane": "gcp_dialogflow_inventory",
            "label": "Dialogflow agent inventory",
            "permission": "cloudasset.assets.searchAllResources",
            "asset_types": [
                "dialogflow.googleapis.com/Agent",
                "dialogflow.googleapis.com/ConversationProfile",
                "dialogflow.googleapis.com/KnowledgeBase",
            ],
        },
    ),
    GCP_SCOPE_AI_ACTIVITY: (
        {
            "plane": "gcp_ai_management_activity",
            "label": "Google Cloud AI management activity",
            "permission": "logging.logEntries.list",
            "asset_types": None,
        },
    ),
    GCP_SCOPE_CODE_TO_CLOUD: (
        {
            "plane": "gcp_deployment_inventory",
            "label": "Cloud Run, Cloud Run functions, and GKE deployment inventory",
            "permission": "cloudasset.assets.listResource",
            "validation_method": "list_assets_resource",
            "asset_types": [
                "run.googleapis.com/Service",
                "cloudfunctions.googleapis.com/Function",
                "container.googleapis.com/Cluster",
            ],
        },
    ),
}


class GcpHttpResponse(Protocol):
    def raise_for_status(self) -> None: ...

    def json(self) -> Any: ...


class GcpCredential(Protocol): ...


GcpRequest = Callable[..., GcpHttpResponse]
CredentialFactory = Callable[[str], GcpCredential]


def gcp_coverage_plan(
    scopes: list[str], projects: list[dict[str, str]]
) -> list[dict[str, Any]]:
    """Expand GCP scopes across the exact customer-selected projects."""

    return [
        {
            "scope": f"projects/{project['id']}",
            "declared_scope": scope,
            "plane": plane["plane"],
            "label": plane["label"],
            "region": "all-locations",
            "project_id": project["id"],
            "project_name": project["name"],
            "project_number": project["number"],
            "permissions": [plane["permission"]],
            "validation_state": "not_validated",
            "coverage_mode": "selected-projects",
        }
        for project in projects
        for scope in scopes
        for plane in _SCOPE_METADATA[scope]
    ]


class GcpConnectionValidator:
    """Validate exact project binding and every declared project-wide read entrypoint."""

    def __init__(
        self,
        credential_factory: CredentialFactory | None = None,
        request: GcpRequest | None = None,
    ):
        self._credential_factory = credential_factory or _default_credential
        self._request = request

    def validate(self, connection: dict[str, Any]) -> dict[str, Any]:
        started_at = datetime.now(UTC)
        configuration = connection["configuration"]
        projects = configuration.get("projects", [])
        if not projects:
            return _credential_failure(connection, started_at, "projects_not_selected")
        principal_email = connection["credential_reference"]["principal_email"]
        try:
            credential = self._credential_factory(principal_email)
            request = self._request or _authorized_request(credential)
        except Exception as error:
            return _credential_failure(connection, started_at, _gcp_error_code(error))

        results: list[dict[str, Any]] = []
        observed_projects: list[str] = []
        credential_failed = False
        for project in projects:
            project_id = project["id"]
            try:
                response = request(
                    "GET",
                    f"{GCP_RESOURCE_MANAGER_ENDPOINT}/projects/{project_id}",
                    timeout=10.0,
                )
                response.raise_for_status()
                observed = response.json()
                observed_id = str(observed.get("projectId", ""))
                observed_number = str(observed.get("name", "")).removeprefix("projects/")
                if observed_id != project_id:
                    raise GcpBindingError("project_id_mismatch")
                if observed_number != project["number"]:
                    raise GcpBindingError("project_number_mismatch")
                observed_projects.append(observed_id)
            except Exception as error:
                credential_failed = True
                results.extend(
                    _unknown_project_results(
                        connection,
                        project_id,
                        f"Credential or project binding failed ({_gcp_error_code(error)}).",
                    )
                )
                continue

            plans = gcp_coverage_plan(connection["declared_scopes"], [project])
            results.extend(self._validate_plane(planned, request) for planned in plans)

        failed_count = sum(item["state"] in {"failed", "unknown"} for item in results)
        if not observed_projects:
            health = "unhealthy"
            credential_state = "failed"
        else:
            health = "healthy" if failed_count == 0 else "partial"
            credential_state = "failed" if credential_failed else "passed"
        if health == "healthy":
            summary = (
                "Credentials and project binding validated; every declared Google Cloud "
                f"control-plane check passed across all locations in {len(observed_projects)} "
                "selected project(s)."
            )
        else:
            summary = (
                f"Google Cloud validation reached {len(observed_projects)} of {len(projects)} "
                f"selected project(s); {failed_count} coverage check(s) failed or remain "
                "unknown."
            )
        return {
            "started_at": started_at,
            "completed_at": datetime.now(UTC),
            "health_state": health,
            "credential_state": credential_state,
            "account_id_observed": ",".join(sorted(observed_projects)) or None,
            "results": results,
            "summary": summary,
        }

    def _validate_plane(
        self, planned: dict[str, Any], request: GcpRequest
    ) -> dict[str, Any]:
        project_id = planned["project_id"]
        result = {
            "scope": planned["scope"],
            "plane": planned["plane"],
            "label": planned["label"],
            "region": "all-locations",
            "project_id": project_id,
            "project_name": planned["project_name"],
            "project_number": planned["project_number"],
        }
        try:
            metadata = _plane_metadata(planned["declared_scope"], planned["plane"])
            if metadata["asset_types"] is None:
                response = request(
                    "POST",
                    GCP_LOGGING_ENDPOINT,
                    json={
                        "resourceNames": [f"projects/{project_id}"],
                        "filter": (
                            'protoPayload.serviceName=("aiplatform.googleapis.com" OR '
                            '"discoveryengine.googleapis.com" OR "dialogflow.googleapis.com")'
                        ),
                        "orderBy": "timestamp desc",
                        "pageSize": 1,
                    },
                    timeout=10.0,
                )
            elif metadata.get("validation_method") == "list_assets_resource":
                response = request(
                    "GET",
                    f"{GCP_CLOUD_ASSET_ENDPOINT}/projects/{project_id}/assets",
                    params=[
                        *(("assetTypes", asset_type) for asset_type in metadata["asset_types"]),
                        ("contentType", "RESOURCE"),
                        ("pageSize", "1"),
                    ],
                    timeout=10.0,
                )
            else:
                response = request(
                    "GET",
                    (
                        f"{GCP_CLOUD_ASSET_ENDPOINT}/projects/"
                        f"{planned['project_number']}:searchAllResources"
                    ),
                    params=[
                        *(('assetTypes', asset_type) for asset_type in metadata["asset_types"]),
                        ("pageSize", "1"),
                    ],
                    timeout=10.0,
                )
            response.raise_for_status()
            response.json()
            result.update(
                state="passed",
                detail=(
                    "The project-wide read-only entrypoint succeeded. Resource-specific "
                    "reads and locations are verified during collection when resources exist."
                ),
            )
        except Exception as error:
            result.update(
                state="failed",
                detail=f"Validation call failed ({_gcp_error_code(error)}).",
            )
        return result


class GcpBindingError(RuntimeError):
    pass


def _credential_failure(
    connection: dict[str, Any], started_at: datetime, code: str
) -> dict[str, Any]:
    return {
        "started_at": started_at,
        "completed_at": datetime.now(UTC),
        "health_state": "unhealthy",
        "credential_state": "failed",
        "account_id_observed": None,
        "results": [
            {
                "scope": item["scope"],
                "plane": item["plane"],
                "label": item["label"],
                "region": item["region"],
                "state": "unknown",
                "detail": "Not attempted because credential or project binding failed.",
                **({"project_id": item["project_id"]} if item.get("project_id") else {}),
            }
            for item in connection["coverage_plan"]
        ],
        "summary": f"Unable to validate the Google Cloud connection ({code}).",
    }


def _unknown_project_results(
    connection: dict[str, Any], project_id: str, detail: str
) -> list[dict[str, Any]]:
    return [
        {
            "scope": item["scope"],
            "plane": item["plane"],
            "label": item["label"],
            "region": item["region"],
            "project_id": project_id,
            "project_name": item.get("project_name", project_id),
            "project_number": item.get("project_number"),
            "state": "unknown",
            "detail": detail,
        }
        for item in connection["coverage_plan"]
        if item.get("project_id") == project_id
    ]


def _plane_metadata(scope: str, plane: str) -> dict[str, Any]:
    return next(item for item in _SCOPE_METADATA[scope] if item["plane"] == plane)


def _gcp_error_code(error: Exception) -> str:
    if isinstance(error, GcpBindingError):
        return str(error)
    response = getattr(error, "response", None)
    if response is not None:
        try:
            payload = response.json()
        except Exception:
            payload = None
        if isinstance(payload, dict):
            nested = payload.get("error")
            if isinstance(nested, dict):
                details = nested.get("details")
                if isinstance(details, list):
                    for detail in details:
                        if not isinstance(detail, dict):
                            continue
                        reason = detail.get("reason")
                        if isinstance(reason, str) and re.fullmatch(
                            r"[A-Z][A-Z0-9_]{1,63}", reason
                        ):
                            return reason
                if nested.get("status"):
                    return str(nested["status"])
                if nested.get("code"):
                    return str(nested["code"])
    return error.__class__.__name__


def valid_gcp_project_id(value: str) -> bool:
    return bool(GCP_PROJECT_ID_PATTERN.fullmatch(value))


def valid_gcp_service_account_email(value: str) -> bool:
    return bool(GCP_SERVICE_ACCOUNT_PATTERN.fullmatch(value))


def _default_credential(principal_email: str) -> GcpCredential:
    try:
        import google.auth
        from google.auth import impersonated_credentials
    except ImportError as error:  # pragma: no cover - installation contract
        raise RuntimeError("install Denali with the gcp extra to validate Google Cloud") from error
    source, _ = google.auth.default(scopes=[GCP_CLOUD_PLATFORM_SCOPE])
    source_principal = getattr(source, "service_account_email", None) or getattr(
        source, "_target_principal", None
    )
    if source_principal == principal_email:
        return source
    return impersonated_credentials.Credentials(
        source_credentials=source,
        target_principal=principal_email,
        target_scopes=[GCP_CLOUD_PLATFORM_SCOPE],
        lifetime=900,
    )


def _authorized_request(credential: GcpCredential) -> GcpRequest:
    try:
        from google.auth.transport.requests import AuthorizedSession
    except ImportError as error:  # pragma: no cover - installation contract
        raise RuntimeError("google-auth is required for Google Cloud validation") from error
    return AuthorizedSession(credential).request


def authorized_gcp_request(principal_email: str) -> GcpRequest:
    """Create the bounded authorized request callable for one connection principal."""

    return _authorized_request(authorized_gcp_credential(principal_email))


def authorized_gcp_credential(principal_email: str) -> GcpCredential:
    """Create credentials impersonating one configured Denali reader principal."""

    return _default_credential(principal_email)
