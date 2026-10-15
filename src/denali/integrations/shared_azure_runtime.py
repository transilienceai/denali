"""Fixed metadata-only Azure runtime operations; no monitor token or KQL crosses apps."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from denali.connections.azure import AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY
from denali.connectors.azure_agent_runtime_activity import (
    _SAFE_ROW_KEYS,
    MAX_COMPONENT_PAGES,
    MAX_COMPONENTS_PER_SUBSCRIPTION,
    MAX_ROWS_PER_COMPONENT,
    AzureConnectionAgentRuntimeCollector,
    _component,
)
from denali.integrations.shared_connections_client import SharedConnectionsClient
from denali.integrations.shared_microsoft import SharedMicrosoftReader


class SharedAzureRuntimeClient:
    def __init__(
        self, connection: dict[str, Any], *, client: SharedConnectionsClient | None = None
    ):
        reader = SharedMicrosoftReader(connection, client=client)
        if reader.provider != "azure" or AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY not in reader.scopes:
            raise ValueError("shared Azure runtime scope is unavailable")
        self._client = reader._client
        self._id, self._org = reader._id, reader._org
        self._tenant = reader.tenant_id
        self._subscriptions = {item["id"] for item in reader.subscriptions}
        self._components: dict[str, dict[str, str]] = {}

    def _read(self, operation: str, subscription_id: str, **arguments: Any) -> dict[str, Any]:
        if subscription_id not in self._subscriptions:
            raise ValueError("Azure runtime subscription is not selected")
        result = self._client.request(
            "POST",
            f"/internal/v1/connections/azure/{self._id}/runtime/read",
            clerk_org_id=self._org,
            payload={"operation": operation, "subscription_id": subscription_id, **arguments},
            max_response_bytes=2_097_152,
        )
        if (
            not isinstance(result, dict)
            or any(
                result.get(key) != value
                for key, value in {
                    "operation": operation,
                    "connection_id": self._id,
                    "tenant_id": self._tenant,
                    "subscription_id": subscription_id,
                }.items()
            )
            or not isinstance(result.get("items"), list)
            or type(result.get("truncated")) is not bool
        ):
            raise ValueError("shared Azure runtime response binding is invalid")
        return result

    def list_components(self, *, subscription_id: str) -> tuple[dict[str, str], ...]:
        self._components = {
            key: value
            for key, value in self._components.items()
            if value["subscription_id"] != subscription_id
        }
        output: list[dict[str, str]] = []
        token = None
        seen: set[str] = set()
        for _ in range(MAX_COMPONENT_PAGES):
            result = self._read(
                "components",
                subscription_id,
                page_size=100,
                **({"page_token": token} if token else {}),
            )
            if len(result["items"]) > 100:
                raise ValueError("Azure runtime component page is too large")
            for item in result["items"]:
                if not isinstance(item, dict) or set(item) != {"resource_id", "app_id", "location"}:
                    raise ValueError("invalid Azure runtime component projection")
                component = _component(
                    {
                        "id": item["resource_id"],
                        "appId": item["app_id"],
                        "location": item["location"],
                    },
                    subscription_id,
                )
                if component is None or component != item or item["app_id"] in self._components:
                    raise ValueError("Azure runtime component identity changed")
                output.append(component)
                self._components[item["app_id"]] = {**component, "subscription_id": subscription_id}
                if len(output) > MAX_COMPONENTS_PER_SUBSCRIPTION:
                    raise ValueError("Azure runtime component bound exceeded")
            token = result.get("next_page_token")
            if not token:
                if result["truncated"]:
                    raise ValueError("Azure runtime discovery was truncated")
                return tuple(output)
            if not isinstance(token, str) or len(token) > 2048 or token in seen:
                raise ValueError("invalid Azure runtime page cursor")
            seen.add(token)
        raise ValueError("Azure runtime page bound exceeded")

    def _pins(self, app_id: str) -> dict[str, str]:
        canonical = str(UUID(app_id))
        component = self._components.get(canonical)
        if component is None or canonical != app_id:
            raise ValueError("Azure runtime component was not discovered in this boundary")
        return component

    def probe(self, app_id: str) -> None:
        component = self._pins(app_id)
        result = self._read(
            "probe",
            component["subscription_id"],
            component_resource_id=component["resource_id"],
            app_id=app_id,
        )
        if result["items"] or result["truncated"] or result.get("next_page_token"):
            raise ValueError("unexpected Azure runtime probe result")

    def query_spans(
        self, *, app_id: str, start_time: datetime, end_time: datetime, limit: int
    ) -> tuple[tuple[dict[str, Any], ...], bool]:
        component = self._pins(app_id)
        if (
            type(limit) is not int
            or not 1 <= limit <= MAX_ROWS_PER_COMPONENT
            or start_time.tzinfo is None
            or end_time.tzinfo is None
            or not timedelta(0) < end_time - start_time <= timedelta(hours=24)
            or end_time > datetime.now(UTC) + timedelta(minutes=5)
        ):
            raise ValueError("invalid Azure runtime collection window")
        result = self._read(
            "spans",
            component["subscription_id"],
            component_resource_id=component["resource_id"],
            app_id=app_id,
            window_start=start_time.isoformat(),
            window_end=end_time.isoformat(),
            limit=limit,
        )
        if len(result["items"]) > limit or result.get("next_page_token"):
            raise ValueError("Azure runtime row bound exceeded")
        for row in result["items"]:
            if not isinstance(row, dict) or set(row) - _SAFE_ROW_KEYS:
                raise ValueError("Azure runtime metadata projection changed")
            for value in row.values():
                if value is not None and (
                    type(value) not in {str, int, float, bool}
                    or isinstance(value, str)
                    and len(value) > 4096
                    or isinstance(value, float)
                    and not math.isfinite(value)
                ):
                    raise ValueError("invalid Azure runtime metadata value")
            try:
                timestamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                if timestamp.tzinfo is None or not start_time <= timestamp < end_time:
                    raise ValueError("time outside selected window")
            except (KeyError, AttributeError, TypeError, ValueError):
                raise ValueError("Azure runtime metadata time binding changed") from None
        return tuple(result["items"]), result["truncated"]


class AzureRuntimeCollectorRouter:
    def __init__(self, native: Any, platform: SharedConnectionsClient | None):
        self.native, self.platform = native, platform

    def collect(
        self, *, tenant_id: str, connection: dict[str, Any], repository: Any
    ) -> dict[str, Any]:
        if connection.get("credential_type") == "platform_shared_azure":
            reader = SharedAzureRuntimeClient(connection, client=self.platform)
            collector = AzureConnectionAgentRuntimeCollector(client_factory=lambda _tenant: reader)
        else:
            if str(connection.get("credential_type", "")).startswith("platform_shared_"):
                raise ValueError("shared Azure runtime provider reference does not match")
            collector = self.native
        if collector is None:
            raise ValueError("Azure runtime collector is unavailable")
        return collector.collect(tenant_id=tenant_id, connection=connection, repository=repository)
