"""Bounded Azure multi-tenant application onboarding and validation."""

from __future__ import annotations

import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import UUID

AZURE_CLOUD_PUBLIC = "AzureCloud"
AZURE_SCOPE_AI_SERVICES = "azure.ai_services"
AZURE_SCOPE_AI_PLATFORM = "azure.ai_platform"
AZURE_SCOPE_AI_ACTIVITY = "azure.ai_activity"
AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY = "azure.agent_runtime_activity"
AZURE_SCOPE_AGENT_RUNTIME_INVENTORY = "azure.agent_runtime_inventory"
AZURE_SCOPE_CODE_TO_CLOUD = "azure.code_to_cloud"
AZURE_SCOPES = (
    AZURE_SCOPE_AI_SERVICES,
    AZURE_SCOPE_AI_PLATFORM,
    AZURE_SCOPE_AI_ACTIVITY,
    AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY,
    AZURE_SCOPE_AGENT_RUNTIME_INVENTORY,
    AZURE_SCOPE_CODE_TO_CLOUD,
)
AZURE_DEFAULT_SCOPES = tuple(
    scope for scope in AZURE_SCOPES if scope != AZURE_SCOPE_AGENT_RUNTIME_INVENTORY
)
AZURE_READER_ROLE_DEFINITION_ID = "acdd72a7-3385-48ef-bd42-f606fba81ae7"
AZURE_MANAGEMENT_SCOPE = "https://management.azure.com/.default"
AZURE_MANAGEMENT_ENDPOINT = "https://management.azure.com"
AZURE_APPLICATION_INSIGHTS_SCOPE = "https://api.applicationinsights.io/.default"
AZURE_APPLICATION_INSIGHTS_ENDPOINT = "https://api.applicationinsights.io"
AZURE_FOUNDRY_SCOPE = "https://ai.azure.com/.default"
AZURE_RESOURCE_GRAPH_API_VERSION = "2022-10-01"
AZURE_SUBSCRIPTION_API_VERSION = "2022-12-01"
AZURE_ACTIVITY_API_VERSION = "2015-04-01"

_SCOPE_METADATA = {
    AZURE_SCOPE_AI_SERVICES: (
        {
            "plane": "azure_ai_services_accounts",
            "label": "Azure AI services account inventory",
            "permission": "Microsoft.ResourceGraph/resources/read",
            "query": (
                "Resources | where type =~ 'microsoft.cognitiveservices/accounts' "
                "| summarize resourceCount=count()"
            ),
        },
        {
            "plane": "azure_ai_search_services",
            "label": "Azure AI Search inventory",
            "permission": "Microsoft.ResourceGraph/resources/read",
            "query": (
                "Resources | where type =~ 'microsoft.search/searchservices' "
                "| summarize resourceCount=count()"
            ),
        },
    ),
    AZURE_SCOPE_AI_PLATFORM: (
        {
            "plane": "azure_machine_learning_workspaces",
            "label": "Azure Machine Learning workspace inventory",
            "permission": "Microsoft.ResourceGraph/resources/read",
            "query": (
                "Resources | where type =~ 'microsoft.machinelearningservices/workspaces' "
                "| summarize resourceCount=count()"
            ),
        },
        {
            "plane": "azure_bot_services",
            "label": "Azure Bot Service inventory",
            "permission": "Microsoft.ResourceGraph/resources/read",
            "query": (
                "Resources | where type =~ 'microsoft.botservice/botservices' "
                "| summarize resourceCount=count()"
            ),
        },
    ),
    AZURE_SCOPE_AI_ACTIVITY: (
        {
            "plane": "azure_ai_management_activity",
            "label": "Azure AI management activity",
            "permission": "Microsoft.Insights/eventtypes/values/read",
            "query": None,
        },
    ),
    AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY: (
        {
            "plane": "azure_foundry_agent_runtime_activity",
            "label": "Microsoft Foundry hosted-agent runtime activity",
            "permission": "Microsoft.Insights/components/query/read",
            "query": (
                "Resources | where type =~ 'microsoft.insights/components' "
                "| project id, appId=properties.AppId | take 1"
            ),
        },
    ),
    AZURE_SCOPE_AGENT_RUNTIME_INVENTORY: (
        {
            "plane": "azure_foundry_agent_inventory",
            "label": "Microsoft Foundry project and agent configuration inventory",
            "permissions": [
                "Microsoft.ResourceGraph/resources/read",
                "Microsoft.CognitiveServices/accounts/AIServices/agents/read",
            ],
            "query": (
                "Resources | where type =~ "
                "'microsoft.cognitiveservices/accounts/projects' "
                "| project id, name, type, location, resourceGroup, subscriptionId "
                "| order by id asc | take 1"
            ),
        },
    ),
    AZURE_SCOPE_CODE_TO_CLOUD: (
        {
            "plane": "azure_container_apps_inventory",
            "label": "Azure Container Apps deployment inventory",
            "permission": "Microsoft.ResourceGraph/resources/read",
            "query": (
                "Resources | where type =~ 'microsoft.app/containerapps' | project id | take 1"
            ),
        },
        {
            "plane": "azure_function_apps_inventory",
            "label": "Azure Function Apps deployment inventory",
            "permission": "Microsoft.ResourceGraph/resources/read",
            "query": (
                "Resources | where type =~ 'microsoft.web/sites' "
                "| where kind contains 'functionapp' | project id | take 1"
            ),
        },
        {
            "plane": "azure_aks_cluster_inventory",
            "label": "Azure Kubernetes Service cluster inventory",
            "permission": "Microsoft.ResourceGraph/resources/read",
            "query": (
                "Resources | where type =~ 'microsoft.containerservice/managedclusters' "
                "| project id | take 1"
            ),
        },
    ),
}


class AzureAccessToken(Protocol):
    token: str


class AzureTokenCredential(Protocol):
    def get_token(self, *scopes: str, **kwargs: Any) -> AzureAccessToken: ...


class AzureHttpResponse(Protocol):
    def raise_for_status(self) -> None: ...

    def json(self) -> Any: ...


AzureRequest = Callable[..., AzureHttpResponse]
CredentialFactory = Callable[[str], AzureTokenCredential]


def azure_coverage_plan(
    scopes: list[str], subscriptions: list[dict[str, str]]
) -> list[dict[str, Any]]:
    """Expand Azure scopes across the exact selected subscriptions."""

    return [
        {
            "scope": f"/subscriptions/{subscription['id']}",
            "declared_scope": scope,
            "plane": plane["plane"],
            "label": plane["label"],
            "region": "all-locations",
            "subscription_id": subscription["id"],
            "subscription_name": subscription["name"],
            "permissions": plane.get("permissions", [plane.get("permission")]),
            "validation_state": "not_validated",
            "coverage_mode": "selected-subscriptions",
        }
        for subscription in subscriptions
        for scope in scopes
        for plane in _SCOPE_METADATA[scope]
    ]


class AzureConnectionValidator:
    """Validate every selected subscription and declared Azure control-plane entrypoint."""

    def __init__(
        self,
        credential_factory: CredentialFactory | None = None,
        request: AzureRequest | None = None,
    ):
        self._credential_factory = credential_factory or _default_credential
        self._request = request or _httpx_request

    def validate(self, connection: dict[str, Any]) -> dict[str, Any]:
        started_at = datetime.now(UTC)
        configuration = connection["configuration"]
        subscriptions = configuration.get("subscriptions", [])
        if not subscriptions:
            return _credential_failure(connection, started_at, "subscriptions_not_selected")
        customer_tenant_id = configuration["tenant_id"]
        try:
            credential = self._credential_factory(customer_tenant_id)
            token = credential.get_token(AZURE_MANAGEMENT_SCOPE).token
            headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        except Exception as error:
            return _credential_failure(connection, started_at, _azure_error_code(error))

        monitor_headers: dict[str, str] | None = None
        monitor_error: str | None = None
        if AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY in connection.get("declared_scopes", []):
            try:
                monitor_token = credential.get_token(AZURE_APPLICATION_INSIGHTS_SCOPE).token
                monitor_headers = {
                    "Authorization": f"Bearer {monitor_token}",
                    "Content-Type": "application/json",
                }
            except Exception as error:
                monitor_error = _azure_error_code(error)

        foundry_headers: dict[str, str] | None = None
        foundry_error: str | None = None
        if AZURE_SCOPE_AGENT_RUNTIME_INVENTORY in connection.get("declared_scopes", []):
            try:
                foundry_token = credential.get_token(AZURE_FOUNDRY_SCOPE).token
                foundry_headers = {
                    "Authorization": f"Bearer {foundry_token}",
                    "Content-Type": "application/json",
                }
            except Exception as error:
                foundry_error = _azure_error_code(error)

        results: list[dict[str, Any]] = []
        observed_subscriptions: list[str] = []
        credential_failed = False
        for subscription in subscriptions:
            subscription_id = subscription["id"]
            try:
                response = self._request(
                    "GET",
                    f"{AZURE_MANAGEMENT_ENDPOINT}/subscriptions/{subscription_id}",
                    headers=headers,
                    params={"api-version": AZURE_SUBSCRIPTION_API_VERSION},
                    timeout=10.0,
                )
                response.raise_for_status()
                observed = response.json()
                observed_subscription = str(observed.get("subscriptionId", ""))
                observed_tenant = str(observed.get("tenantId", ""))
                if observed_subscription.lower() != subscription_id.lower():
                    raise AzureBindingError("subscription_mismatch")
                if observed_tenant.lower() != customer_tenant_id.lower():
                    raise AzureBindingError("tenant_mismatch")
                observed_subscriptions.append(observed_subscription)
            except Exception as error:
                credential_failed = True
                results.extend(
                    _unknown_subscription_results(
                        connection,
                        subscription_id,
                        f"Credential or subscription binding failed ({_azure_error_code(error)}).",
                    )
                )
                continue

            plans = azure_coverage_plan(connection["declared_scopes"], [subscription])
            results.extend(
                self._validate_plane(
                    planned,
                    subscription_id,
                    headers,
                    monitor_headers=monitor_headers,
                    monitor_error=monitor_error,
                    foundry_headers=foundry_headers,
                    foundry_error=foundry_error,
                )
                for planned in plans
            )

        failed_count = sum(item["state"] in {"failed", "unknown"} for item in results)
        if not observed_subscriptions:
            health = "unhealthy"
            credential_state = "failed"
        else:
            health = "healthy" if failed_count == 0 else "partial"
            credential_state = "failed" if credential_failed else "passed"
        if health == "healthy":
            summary = (
                f"Credentials and tenant binding validated; every declared Azure control-plane "
                f"check passed across all locations in {len(observed_subscriptions)} selected "
                "subscription(s)."
            )
        else:
            summary = (
                f"Azure validation reached {len(observed_subscriptions)} of {len(subscriptions)} "
                f"selected subscription(s); {failed_count} coverage check(s) failed or remain "
                "unknown."
            )
        return {
            "started_at": started_at,
            "completed_at": datetime.now(UTC),
            "health_state": health,
            "credential_state": credential_state,
            "account_id_observed": ",".join(sorted(observed_subscriptions)) or None,
            "results": results,
            "summary": summary,
        }

    def _validate_plane(
        self,
        planned: dict[str, Any],
        subscription_id: str,
        headers: dict[str, str],
        *,
        monitor_headers: dict[str, str] | None = None,
        monitor_error: str | None = None,
        foundry_headers: dict[str, str] | None = None,
        foundry_error: str | None = None,
    ) -> dict[str, Any]:
        result = {
            "scope": planned["scope"],
            "plane": planned["plane"],
            "label": planned["label"],
            "region": "all-locations",
            "subscription_id": subscription_id,
            "subscription_name": planned["subscription_name"],
        }
        try:
            metadata = _plane_metadata(planned["declared_scope"], planned["plane"])
            if planned["declared_scope"] == AZURE_SCOPE_AGENT_RUNTIME_INVENTORY:
                if foundry_headers is None:
                    raise AzureBindingError(f"foundry_token_{foundry_error or 'unavailable'}")
                graph_response = self._request(
                    "POST",
                    f"{AZURE_MANAGEMENT_ENDPOINT}/providers/Microsoft.ResourceGraph/resources",
                    headers=headers,
                    params={"api-version": AZURE_RESOURCE_GRAPH_API_VERSION},
                    json={
                        "subscriptions": [subscription_id],
                        "query": metadata["query"],
                        "options": {"$top": 1, "resultFormat": "objectArray"},
                    },
                    timeout=10.0,
                )
                graph_response.raise_for_status()
                graph_payload = graph_response.json()
                projects = graph_payload.get("data") if isinstance(graph_payload, dict) else None
                if not isinstance(projects, list):
                    raise AzureBindingError("foundry_project_query_invalid")
                if not projects:
                    result.update(
                        state="passed",
                        detail=(
                            "The subscription-wide project discovery entrypoint succeeded; no "
                            "Foundry project currently requires a data-plane probe."
                        ),
                    )
                    return result
                project_endpoint = _foundry_project_endpoint(projects[0], subscription_id)
                response = self._request(
                    "GET",
                    f"{project_endpoint}/agents",
                    headers=foundry_headers,
                    params={"api-version": "v1"},
                    timeout=10.0,
                )
            elif planned["declared_scope"] == AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY:
                if monitor_headers is None:
                    raise AzureBindingError(
                        f"application_insights_token_{monitor_error or 'unavailable'}"
                    )
                graph_response = self._request(
                    "POST",
                    f"{AZURE_MANAGEMENT_ENDPOINT}/providers/Microsoft.ResourceGraph/resources",
                    headers=headers,
                    params={"api-version": AZURE_RESOURCE_GRAPH_API_VERSION},
                    json={
                        "subscriptions": [subscription_id],
                        "query": metadata["query"],
                        "options": {"$top": 1, "resultFormat": "objectArray"},
                    },
                    timeout=10.0,
                )
                graph_response.raise_for_status()
                graph_payload = graph_response.json()
                components = graph_payload.get("data") if isinstance(graph_payload, dict) else None
                if not isinstance(components, list) or not components:
                    raise AzureBindingError("application_insights_component_not_found")
                app_id = components[0].get("appId") if isinstance(components[0], dict) else None
                if not isinstance(app_id, str) or not valid_azure_uuid(app_id):
                    raise AzureBindingError("application_insights_app_id_invalid")
                response = self._request(
                    "GET",
                    f"{AZURE_APPLICATION_INSIGHTS_ENDPOINT}/v1/apps/{app_id}/query",
                    headers=monitor_headers,
                    params={
                        "query": (
                            "dependencies | where false | project timestamp, operation_Id | take 1"
                        )
                    },
                    timeout=10.0,
                )
            elif metadata["query"] is None:
                end = datetime.now(UTC)
                start = end - timedelta(hours=1)
                response = self._request(
                    "GET",
                    (
                        f"{AZURE_MANAGEMENT_ENDPOINT}/subscriptions/{subscription_id}/providers/"
                        "microsoft.insights/eventtypes/management/values"
                    ),
                    headers=headers,
                    params={
                        "api-version": AZURE_ACTIVITY_API_VERSION,
                        "$filter": (
                            f"eventTimestamp ge '{start.isoformat()}' and "
                            f"eventTimestamp le '{end.isoformat()}'"
                        ),
                        "$top": "1",
                    },
                    timeout=10.0,
                )
            else:
                response = self._request(
                    "POST",
                    f"{AZURE_MANAGEMENT_ENDPOINT}/providers/Microsoft.ResourceGraph/resources",
                    headers=headers,
                    params={"api-version": AZURE_RESOURCE_GRAPH_API_VERSION},
                    json={
                        "subscriptions": [subscription_id],
                        "query": metadata["query"],
                        "options": {"$top": 1, "resultFormat": "objectArray"},
                    },
                    timeout=10.0,
                )
            response.raise_for_status()
            response.json()
            result.update(
                state="passed",
                detail=(
                    "The subscription-wide read-only entrypoint succeeded. Resource-specific "
                    "reads and locations are verified during collection when resources exist."
                ),
            )
        except Exception as error:
            result.update(
                state="failed",
                detail=f"Validation call failed ({_azure_error_code(error)}).",
            )
        return result


class AzureBindingError(RuntimeError):
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
                "detail": "Not attempted because credential or subscription binding failed.",
                **(
                    {"subscription_id": item["subscription_id"]}
                    if item.get("subscription_id")
                    else {}
                ),
            }
            for item in connection["coverage_plan"]
        ],
        "summary": f"Unable to validate the Azure connection ({code}).",
    }


def _unknown_subscription_results(
    connection: dict[str, Any], subscription_id: str, detail: str
) -> list[dict[str, Any]]:
    return [
        {
            "scope": item["scope"],
            "plane": item["plane"],
            "label": item["label"],
            "region": item["region"],
            "subscription_id": subscription_id,
            "subscription_name": item.get("subscription_name", subscription_id),
            "state": "unknown",
            "detail": detail,
        }
        for item in connection["coverage_plan"]
        if item.get("subscription_id") == subscription_id
    ]


def _plane_metadata(scope: str, plane: str) -> dict[str, Any]:
    return next(item for item in _SCOPE_METADATA[scope] if item["plane"] == plane)


def _azure_error_code(error: Exception) -> str:
    if isinstance(error, AzureBindingError):
        return str(error)
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
    return error.__class__.__name__


def valid_azure_uuid(value: str) -> bool:
    try:
        UUID(value)
    except ValueError:
        return False
    return True


def _default_credential(customer_tenant_id: str) -> AzureTokenCredential:
    client_id = os.environ.get("DENALI_AZURE_CLIENT_ID")
    client_secret = os.environ.get("DENALI_AZURE_CLIENT_SECRET")
    if not client_id or not client_secret:
        raise RuntimeError("Denali Azure application credentials are not configured")
    try:
        from azure.identity import ClientSecretCredential
    except ImportError as error:  # pragma: no cover - installation contract
        raise RuntimeError("install Denali with the azure extra to validate Azure") from error
    return ClientSecretCredential(
        tenant_id=customer_tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )


def authorized_azure_request(customer_tenant_id: str) -> AzureRequest:
    """Create an Azure Management request callable without exposing bearer tokens."""

    credential = _default_credential(customer_tenant_id)

    def request(method: str, url: str, **kwargs: Any) -> AzureHttpResponse:
        headers = dict(kwargs.pop("headers", {}))
        headers["Authorization"] = f"Bearer {credential.get_token(AZURE_MANAGEMENT_SCOPE).token}"
        headers.setdefault("Content-Type", "application/json")
        return _httpx_request(method, url, headers=headers, **kwargs)

    return request


def authorized_azure_monitor_request(customer_tenant_id: str) -> AzureRequest:
    """Create an Application Insights request callable without exposing bearer tokens."""

    credential = _default_credential(customer_tenant_id)

    def request(method: str, url: str, **kwargs: Any) -> AzureHttpResponse:
        if not url.startswith(f"{AZURE_APPLICATION_INSIGHTS_ENDPOINT}/v1/apps/"):
            raise ValueError("Azure Monitor request escaped the Application Insights endpoint")
        headers = dict(kwargs.pop("headers", {}))
        headers["Authorization"] = (
            f"Bearer {credential.get_token(AZURE_APPLICATION_INSIGHTS_SCOPE).token}"
        )
        headers.setdefault("Content-Type", "application/json")
        return _httpx_request(method, url, headers=headers, **kwargs)

    return request


def authorized_azure_foundry_request(customer_tenant_id: str) -> AzureRequest:
    """Create a Foundry project request callable scoped to the public data plane."""

    credential = _default_credential(customer_tenant_id)

    def request(method: str, url: str, **kwargs: Any) -> AzureHttpResponse:
        parsed = urlsplit(url)
        hostname = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or not hostname.endswith(".services.ai.azure.com")
            or not parsed.path.startswith("/api/projects/")
        ):
            raise ValueError("Azure Foundry request escaped the public project endpoint")
        headers = dict(kwargs.pop("headers", {}))
        headers["Authorization"] = f"Bearer {credential.get_token(AZURE_FOUNDRY_SCOPE).token}"
        headers.setdefault("Content-Type", "application/json")
        return _httpx_request(method, url, headers=headers, **kwargs)

    return request


def _foundry_project_endpoint(raw: Any, subscription_id: str) -> str:
    if not isinstance(raw, dict):
        raise AzureBindingError("foundry_project_invalid")
    resource_id = raw.get("id")
    if not isinstance(resource_id, str):
        raise AzureBindingError("foundry_project_id_missing")
    parts = resource_id.split("/")
    if len(parts) != 11 or any(not item for item in parts[1:]):
        raise AzureBindingError("foundry_project_id_invalid")
    expected = {
        1: "subscriptions",
        3: "resourcegroups",
        5: "providers",
        6: "microsoft.cognitiveservices",
        7: "accounts",
        9: "projects",
    }
    if any(parts[index].casefold() != value for index, value in expected.items()):
        raise AzureBindingError("foundry_project_id_invalid")
    if parts[2].casefold() != subscription_id.casefold():
        raise AzureBindingError("foundry_project_subscription_mismatch")
    account = parts[8]
    project = parts[10]
    if not _safe_foundry_segment(account) or not _safe_foundry_segment(project):
        raise AzureBindingError("foundry_project_name_invalid")
    return f"https://{account}.services.ai.azure.com/api/projects/{project}"


def _safe_foundry_segment(value: str) -> bool:
    return (
        1 <= len(value) <= 64
        and value[0].isalnum()
        and value[-1].isalnum()
        and all(character.isalnum() or character in {"-", ".", "_"} for character in value)
    )


def _httpx_request(method: str, url: str, **kwargs: Any) -> AzureHttpResponse:
    try:
        import httpx
    except ImportError as error:  # pragma: no cover - installation contract
        raise RuntimeError("httpx is required for Azure validation") from error
    return httpx.request(method, url, **kwargs)
