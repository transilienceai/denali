"""Org-bound Microsoft metadata adapters; Platform retains provider credentials.

Only named, bounded broker operations cross this boundary. Native collector
queries are translated locally and are never forwarded as provider paths/filters.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from denali.connections.azure import AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY, AZURE_SCOPES
from denali.connections.entra import ENTRA_SCOPES
from denali.integrations.shared_connections_client import SharedConnectionsClient

SHARED_AZURE_SCOPES = tuple(AZURE_SCOPES)
RESOURCE_SCOPES = {
    "microsoft.cognitiveservices/accounts": "azure.ai_services",
    "microsoft.search/searchservices": "azure.ai_services",
    "microsoft.machinelearningservices/workspaces": "azure.ai_platform",
    "microsoft.botservice/botservices": "azure.ai_platform",
    "microsoft.app/containerapps": "azure.code_to_cloud",
    "microsoft.web/sites": "azure.code_to_cloud",
    "microsoft.containerservice/managedclusters": "azure.code_to_cloud",
}
AZURE_PLAN_TYPES = {
    "azure_ai_services_accounts": "microsoft.cognitiveservices/accounts",
    "azure_ai_search_services": "microsoft.search/searchservices",
    "azure_machine_learning_workspaces": "microsoft.machinelearningservices/workspaces",
    "azure_bot_services": "microsoft.botservice/botservices",
    "azure_container_apps_inventory": "microsoft.app/containerapps",
    "azure_function_apps_inventory": "microsoft.web/sites",
    "azure_aks_cluster_inventory": "microsoft.containerservice/managedclusters",
}
ENTRA_OPERATIONS = {
    "service_principals": "entra.ai_applications",
    "oauth_grants": "entra.permissions",
    "app_role_assignments": "entra.permissions",
    "sign_ins": "entra.sign_ins",
    "directory_audits": "entra.directory_audits",
}
ENTRA_PLAN_OPERATIONS = {
    "entra_ai_application_inventory": "service_principals",
    "entra_service_principal_context": "service_principals",
    "entra_oauth_delegated_grants": "oauth_grants",
    "entra_application_permissions": "app_role_assignments",
    "entra_ai_signins": "sign_ins",
    "entra_ai_directory_audits": "directory_audits",
}


def shared_microsoft_enabled(provider: str) -> bool:
    return (
        provider in {"azure", "entra"}
        and os.environ.get(f"DENALI_PLATFORM_{provider.upper()}_ENABLED", "false").lower() == "true"
    )


def selected_subscriptions(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 8:
        raise ValueError("shared Azure subscription boundary is invalid")
    result = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("shared Azure subscription boundary is invalid")
        subscription_id = str(UUID(str(item.get("id", ""))))
        name = item.get("name") or subscription_id
        if not isinstance(name, str) or not 1 <= len(name) <= 100:
            raise ValueError("shared Azure subscription name is invalid")
        result.append({"id": subscription_id, "name": name})
    if len({item["id"] for item in result}) != len(result):
        raise ValueError("shared Azure subscription boundary is duplicated")
    return sorted(result, key=lambda item: item["id"])


def _window(start: Any, end: Any, *, maximum_hours: int = 24) -> tuple[datetime, datetime]:
    if not isinstance(start, datetime) or not isinstance(end, datetime):
        raise ValueError("shared Microsoft activity window is invalid")
    if (
        start.tzinfo is None
        or end.tzinfo is None
        or not timedelta(0) < end - start <= timedelta(hours=maximum_hours)
        or end > datetime.now(UTC) + timedelta(minutes=5)
    ):
        raise ValueError("shared Microsoft activity window is invalid")
    return start, end


class SharedMicrosoftReader:
    def __init__(
        self, connection: dict[str, Any], *, client: SharedConnectionsClient | None = None
    ):
        self.provider = str(connection.get("provider"))
        if not shared_microsoft_enabled(self.provider):
            raise ValueError("shared Microsoft provider is disabled")
        if connection.get("credential_type") != f"platform_shared_{self.provider}":
            raise ValueError("connection is not shared Microsoft")
        self._id = str(UUID(str(connection["credential_reference"]["platform_connection_id"])))
        self._org = connection.get("clerk_organization_id")
        configuration = connection.get("configuration", {})
        self.tenant_id = str(UUID(str(configuration.get("tenant_id", ""))))
        if (
            self._id != str(connection.get("id"))
            or not isinstance(self._org, str)
            or not re.fullmatch(r"org_[A-Za-z0-9]+", self._org)
            or connection.get("lifecycle_state") != "active"
            or configuration.get("coverage_mode")
            != (
                "selected-subscriptions"
                if self.provider == "azure"
                else "tenant-wide-admin-consent"
            )
        ):
            raise ValueError("shared Microsoft identity boundary is invalid")
        scopes = connection.get("declared_scopes")
        allowed = SHARED_AZURE_SCOPES if self.provider == "azure" else ENTRA_SCOPES
        if (
            not isinstance(scopes, list)
            or not scopes
            or any(not isinstance(scope, str) for scope in scopes)
            or len(set(scopes)) != len(scopes)
            or not set(scopes) <= set(allowed)
            or self.provider == "entra"
            and set(scopes) != set(ENTRA_SCOPES)
        ):
            raise ValueError("shared Microsoft scope boundary is invalid")
        self.scopes = frozenset(scopes)
        self.subscriptions = (
            selected_subscriptions(configuration.get("subscriptions"))
            if self.provider == "azure"
            else []
        )
        self._client = client or SharedConnectionsClient.from_environment()
        if self._client is None or not self._client.allows_org(self._org):
            raise ValueError("shared Microsoft organization is not enabled")

    def read(
        self,
        operation: str,
        *,
        page_size: int = 100,
        page_token: str | None = None,
        subscription_id: str | None = None,
        resource_type: str | None = None,
        scope: str | None = None,
        service_principal_id: str | None = None,
        app_ids: list[str] | None = None,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
    ) -> dict[str, Any]:
        if type(page_size) is not int or not 1 <= page_size <= 100:
            raise ValueError("shared Microsoft page size is invalid")
        payload: dict[str, Any] = {"operation": operation, "page_size": page_size}
        if self.provider == "azure":
            if subscription_id not in {item["id"] for item in self.subscriptions}:
                raise ValueError("shared Azure subscription is not selected")
            payload["subscription_id"] = subscription_id
            if operation == "resources":
                if RESOURCE_SCOPES.get(str(resource_type).lower()) not in self.scopes:
                    raise ValueError("shared Azure resource scope is not selected")
                payload["resource_type"] = str(resource_type).lower()
            elif operation == "activity":
                if "azure.ai_activity" not in self.scopes:
                    raise ValueError("shared Azure activity is not selected")
            elif operation == "subscription_metadata":
                selected_scope = scope or sorted(self.scopes)[0]
                if selected_scope not in self.scopes or page_token:
                    raise ValueError("shared Azure subscription metadata scope is invalid")
                payload["scope"] = selected_scope
            else:
                raise ValueError("shared Azure operation is invalid")
        elif ENTRA_OPERATIONS.get(operation) not in self.scopes:
            raise ValueError("shared Entra operation is invalid")
        if operation == "app_role_assignments":
            payload["service_principal_id"] = str(UUID(str(service_principal_id)))
        elif service_principal_id is not None:
            raise ValueError("shared Microsoft service principal selection is invalid")
        if operation == "sign_ins":
            if not isinstance(app_ids, list) or not 1 <= len(app_ids) <= 10:
                raise ValueError("shared Entra application selection is invalid")
            payload["app_ids"] = [str(UUID(value)) for value in app_ids]
            if len(set(payload["app_ids"])) != len(app_ids):
                raise ValueError("shared Entra application selection is duplicated")
        elif app_ids is not None:
            raise ValueError("shared Microsoft application selection is invalid")
        if operation in {"activity", "sign_ins", "directory_audits"}:
            start, end = _window(
                window_start, window_end, maximum_hours=168 if self.provider == "entra" else 24
            )
            payload.update(window_start=start.isoformat(), window_end=end.isoformat())
        elif window_start is not None or window_end is not None:
            raise ValueError("shared Microsoft activity selection is invalid")
        if self.provider == "entra" and (subscription_id is not None or resource_type is not None):
            raise ValueError("shared Entra resource selection is invalid")
        if self.provider == "azure" and operation != "resources" and resource_type is not None:
            raise ValueError("shared Azure resource selection is invalid")
        if scope is not None and (self.provider != "azure" or operation != "subscription_metadata"):
            raise ValueError("shared Microsoft scope selection is invalid")
        token_limit = 2048 if self.provider == "azure" else 8192
        if page_token is not None:
            if not isinstance(page_token, str) or not 1 <= len(page_token) <= token_limit:
                raise ValueError("shared Microsoft page token is invalid")
            payload["page_token"] = page_token
        result = self._client.request(
            "POST",
            f"/internal/v1/connections/{self.provider}/{self._id}/read",
            clerk_org_id=self._org,
            payload=payload,
        )
        # Graph can exceed the 100-item directory-audit request hint. Match the
        # broker's bounded compatibility envelope without truncating a page.
        response_limit = (
            200
            if self.provider == "entra" and operation == "directory_audits" and page_size == 100
            else page_size
        )
        if (
            not isinstance(result, dict)
            or result.get("operation") != operation
            or result.get("tenant_id") != self.tenant_id
            or self.provider == "azure"
            and result.get("subscription_id") != subscription_id
            or not isinstance(result.get("items"), list)
            or len(result["items"]) > response_limit
            or any(not isinstance(item, dict) for item in result["items"])
            or result.get("next_page_token") is not None
            and (
                not isinstance(result["next_page_token"], str)
                or len(result["next_page_token"]) > token_limit
            )
        ):
            raise ValueError("shared Microsoft read response is invalid")
        if operation == "subscription_metadata" and (
            len(result["items"]) != 1
            or result["items"][0].get("subscriptionId") != subscription_id
            or result["items"][0].get("tenantId") != self.tenant_id
        ):
            raise ValueError("shared Azure subscription metadata binding is invalid")
        return result

    def _list(
        self,
        operation: str,
        *,
        limit: int = 10_000,
        follow_pagination: bool = True,
        **parameters: Any,
    ) -> tuple[dict[str, Any], ...]:
        if not 1 <= limit <= 20_000:
            raise ValueError("shared Microsoft record limit is invalid")
        records = []
        token = None
        seen = set()
        for _ in range(200):
            result = self.read(operation, page_size=min(limit, 100), page_token=token, **parameters)
            records.extend(result["items"])
            if len(records) > limit:
                raise ValueError("shared Microsoft record limit reached")
            token = result.get("next_page_token")
            if not token or not follow_pagination:
                return tuple(records)
            if token in seen:
                raise ValueError("shared Microsoft page token repeated")
            seen.add(token)
        raise ValueError("shared Microsoft page limit reached")


class SharedAzureReader(SharedMicrosoftReader):
    def list_resources(
        self, *, subscription_id: str, resource_type: str
    ) -> tuple[dict[str, Any], ...]:
        from denali.connectors.azure_deployments import AzureDeploymentDiscoveryError

        try:
            return self._list(
                "resources", subscription_id=subscription_id, resource_type=resource_type
            )
        except Exception as error:
            raise AzureDeploymentDiscoveryError("platform:Resources:unavailable") from error

    def list_activity(
        self, *, subscription_id: str, start_time: datetime, end_time: datetime
    ) -> tuple[dict[str, Any], ...]:
        from denali.connectors.azure_deployments import AzureDeploymentDiscoveryError

        try:
            return self._list(
                "activity",
                subscription_id=subscription_id,
                window_start=start_time,
                window_end=end_time,
            )
        except Exception as error:
            raise AzureDeploymentDiscoveryError("platform:Activity:unavailable") from error


class SharedEntraReader(SharedMicrosoftReader):
    def list(
        self,
        path: str,
        *,
        params: dict[str, str] | None = None,
        limit: int = 20_000,
        follow_pagination: bool = True,
    ) -> tuple[dict[str, Any], ...]:
        params = params or {}
        parameters: dict[str, Any] = {}
        if path == "/v1.0/servicePrincipals":
            operation = "service_principals"
        elif path == "/v1.0/oauth2PermissionGrants":
            operation = "oauth_grants"
        elif match := re.fullmatch(
            r"/v1.0/servicePrincipals/([0-9a-fA-F-]{36})/appRoleAssignments", path
        ):
            operation = "app_role_assignments"
            parameters["service_principal_id"] = str(UUID(match.group(1)))
        elif path in {"/v1.0/auditLogs/signIns", "/v1.0/auditLogs/directoryAudits"}:
            operation = "sign_ins" if path.endswith("signIns") else "directory_audits"
            field = "createdDateTime" if operation == "sign_ins" else "activityDateTime"
            match = re.fullmatch(
                rf"{field} ge (\S+) and {field} lt (\S+) and (.+)", params.get("$filter", "")
            )
            if not match:
                raise ValueError("shared Entra activity query is invalid")
            parameters.update(
                window_start=datetime.fromisoformat(match.group(1).replace("Z", "+00:00")),
                window_end=datetime.fromisoformat(match.group(2).replace("Z", "+00:00")),
            )
            if operation == "sign_ins":
                app_filter = match.group(3)
                if not re.fullmatch(
                    r"\(appId eq '[0-9a-fA-F-]{36}'(?: or appId eq '[0-9a-fA-F-]{36}')*\)",
                    app_filter,
                ):
                    raise ValueError("shared Entra application query is invalid")
                parameters["app_ids"] = re.findall(r"appId eq '([^']+)'", app_filter)
            elif match.group(3) != "category eq 'ApplicationManagement'":
                raise ValueError("shared Entra audit category is invalid")
        else:
            raise ValueError("shared Entra path is not supported")
        if set(params) - {"$select", "$filter", "$orderby", "$top"}:
            raise ValueError("shared Entra query parameters are invalid")
        if operation not in {"sign_ins", "directory_audits"} and "$filter" in params:
            raise ValueError("shared Entra query filter is invalid")
        return self._list(operation, limit=limit, follow_pagination=follow_pagination, **parameters)


class MicrosoftValidatorRouter:
    def __init__(self, provider: str, native: Any, platform: SharedConnectionsClient | None):
        self.provider, self.native, self.platform = provider, native, platform

    def validate(self, connection: dict[str, Any]) -> dict[str, Any]:
        if connection.get("credential_type") != f"platform_shared_{self.provider}":
            if str(connection.get("credential_type", "")).startswith("platform_shared_"):
                raise ValueError("shared Microsoft provider reference does not match")
            if self.native is None:
                raise ValueError("native Microsoft validator is not configured")
            return self.native.validate(connection)
        started = datetime.now(UTC)
        results = []
        try:
            reader = SharedMicrosoftReader(connection, client=self.platform)
        except Exception:
            reader = None
        for planned in connection.get("coverage_plan", []):
            result = {key: planned[key] for key in ("scope", "plane", "label", "region")}
            try:
                if reader is None:
                    raise ValueError("shared Microsoft reference is unavailable")
                end = datetime.now(UTC)
                if self.provider == "azure":
                    subscription = planned["subscription_id"]
                    reader.read(
                        "subscription_metadata",
                        subscription_id=subscription,
                        scope=planned["declared_scope"],
                        page_size=1,
                    )
                    if planned["declared_scope"] == AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY:
                        from denali.integrations.shared_azure_runtime import (
                            SharedAzureRuntimeClient,
                        )

                        runtime = SharedAzureRuntimeClient(connection, client=self.platform)
                        components = runtime.list_components(subscription_id=subscription)
                        if not components:
                            raise ValueError("Application Insights component not found")
                        runtime.probe(components[0]["app_id"])
                    elif planned["declared_scope"] == "azure.ai_activity":
                        reader.read(
                            "activity",
                            subscription_id=subscription,
                            page_size=1,
                            window_start=end - timedelta(hours=1),
                            window_end=end,
                        )
                    else:
                        reader.read(
                            "resources",
                            subscription_id=subscription,
                            page_size=1,
                            resource_type=AZURE_PLAN_TYPES[planned["plane"]],
                        )
                    result["subscription_id"] = subscription
                else:
                    operation = ENTRA_PLAN_OPERATIONS[planned["plane"]]
                    parameters = {}
                    if operation == "app_role_assignments":
                        principals = reader.read("service_principals", page_size=1)["items"]
                        if not principals:
                            raise ValueError(
                                "shared Entra application permission probe unavailable"
                            )
                        parameters["service_principal_id"] = str(UUID(principals[0]["id"]))
                    if operation == "sign_ins":
                        principals = reader.read("service_principals", page_size=100)["items"]
                        app_ids = [
                            str(UUID(item["appId"])) for item in principals if item.get("appId")
                        ][:10]
                        if not app_ids:
                            # Probe a fixed, empty application boundary; no unbounded sign-in read.
                            app_ids = ["00000000-0000-0000-0000-000000000000"]
                        parameters["app_ids"] = app_ids
                    if operation in {"sign_ins", "directory_audits"}:
                        parameters.update(window_start=end - timedelta(hours=1), window_end=end)
                    reader.read(operation, page_size=1, **parameters)
                    result["tenant_id"] = reader.tenant_id
                result.update(
                    state="passed", detail="The declared Platform metadata operation was callable."
                )
            except Exception:
                result.update(
                    state="failed",
                    detail="The declared Platform metadata operation was unavailable.",
                )
            results.append(result)
        passed = sum(item["state"] == "passed" for item in results)
        health = (
            "healthy"
            if results and passed == len(results)
            else "partial"
            if passed
            else "unhealthy"
        )
        return {
            "started_at": started,
            "completed_at": datetime.now(UTC),
            "health_state": health,
            "credential_state": "passed" if reader is not None and passed else "failed",
            "account_id_observed": reader.tenant_id if reader is not None and passed else None,
            "results": results,
            "summary": (
                f"Platform Microsoft metadata validation passed {passed} "
                f"of {len(results)} declared planes."
            ),
        }


class MicrosoftCollectorRouter:
    def __init__(self, provider: str, native: Any, platform: SharedConnectionsClient | None):
        self.provider, self.native, self.platform = provider, native, platform

    def collect(
        self, *, tenant_id: str, connection: dict[str, Any], repository: Any
    ) -> dict[str, Any]:
        if connection.get("credential_type") != f"platform_shared_{self.provider}":
            if str(connection.get("credential_type", "")).startswith("platform_shared_"):
                raise ValueError("shared Microsoft provider reference does not match")
            if self.native is None:
                raise ValueError("native Microsoft collector is not configured")
            return self.native.collect(
                tenant_id=tenant_id, connection=connection, repository=repository
            )
        if self.provider == "azure":
            from denali.connectors.azure_deployments import AzureConnectionDeploymentCollector

            reader = SharedAzureReader(connection, client=self.platform)
            collector = AzureConnectionDeploymentCollector(
                resource_client_factory=lambda _tenant: reader
            )
        else:
            from denali.connectors.entra_connection import EntraConnectionCollector

            reader = SharedEntraReader(connection, client=self.platform)

            class BrokerGraphFactory:
                def graph_client(self, entra_tenant_id: str) -> SharedEntraReader:
                    if entra_tenant_id != reader.tenant_id:
                        raise ValueError("shared Entra tenant mismatch")
                    return reader

            collector = EntraConnectionCollector(BrokerGraphFactory(), lookback_hours=168)
        return collector.collect(tenant_id=tenant_id, connection=connection, repository=repository)
