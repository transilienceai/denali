"""Metadata-only Microsoft Foundry hosted-agent runtime activity.

The source query projects an explicit allowlist in Application Insights before data
crosses into Denali. Prompt, response, system-instruction, document, tool-argument,
tool-result, request-body, and response-body fields are never requested or persisted.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from denali.connections.azure import (
    AZURE_APPLICATION_INSIGHTS_ENDPOINT,
    AZURE_MANAGEMENT_ENDPOINT,
    AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY,
    authorized_azure_monitor_request,
    authorized_azure_request,
    valid_azure_uuid,
)
from denali.domain import (
    ActivityBatch,
    ActivityCategory,
    ActivityCorrelation,
    ActivityEntity,
    ActivityEntityRole,
    ActivityOutcome,
    ActivityRecord,
    AssetKind,
    AssetRef,
    Coverage,
    CoverageState,
    Evidence,
)

CONNECTOR_ID = "denali.azure_foundry_agent_runtime"
ACTIVITY_PLANE = "azure_foundry_agent_runtime_activity"
PROVIDER = "azure_foundry"
DEFAULT_LOOKBACK = timedelta(minutes=30)
COLLECTION_OVERLAP = timedelta(minutes=5)
MAX_CATCHUP = timedelta(hours=24)
MAX_COMPONENTS_PER_SUBSCRIPTION = 100
MAX_COMPONENT_PAGES = 20
MAX_ROWS_PER_COMPONENT = 10_000
MAX_ROWS_PER_SUBSCRIPTION = 50_000
APPLICATION_INSIGHTS_API_VERSION = "2020-02-02"

_HEX_ID = re.compile(r"^[0-9a-fA-F]{8,64}$")
_PROJECT_ID = re.compile(
    r"^/subscriptions/(?P<subscription>[0-9a-f-]{36})/resourcegroups/[^/]+/providers/"
    r"microsoft\.cognitiveservices/accounts/[^/]+/projects/[^/]+$",
    re.IGNORECASE,
)
_COMPONENT_ID = re.compile(
    r"^/subscriptions/(?P<subscription>[0-9a-f-]{36})/resourcegroups/[^/]+/providers/"
    r"microsoft\.insights/components/[^/]+$",
    re.IGNORECASE,
)

# These are the only columns requested from Application Insights and accepted by
# the normalizer. The source KQL contains no wildcard projection.
_SAFE_ROW_KEYS = frozenset(
    {
        "source_table",
        "timestamp",
        "span_id",
        "trace_id",
        "parent_span_id",
        "name",
        "duration_ms",
        "success",
        "result_code",
        "agent_id",
        "agent_name",
        "agent_version",
        "session_id",
        "conversation_id",
        "project_id",
        "operation",
        "request_model",
        "response_model",
        "provider",
        "response_id",
        "tool_call_id",
        "tool_name",
        "tool_type",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "reasoning_tokens",
        "error_type",
    }
)
_SAFE_ACTIVITY_ATTRIBUTES = frozenset(
    {
        "source_table",
        "result_code",
        "gen_ai.agent.id",
        "gen_ai.agent.name",
        "gen_ai.agent.version",
        "gen_ai.conversation.id",
        "gen_ai.operation.name",
        "gen_ai.provider.name",
        "gen_ai.request.model",
        "gen_ai.response.id",
        "gen_ai.response.model",
        "gen_ai.tool.call.id",
        "gen_ai.tool.name",
        "gen_ai.tool.type",
        "gen_ai.usage.cache_read.input_tokens",
        "gen_ai.usage.input_tokens",
        "gen_ai.usage.output_tokens",
        "gen_ai.usage.reasoning.output_tokens",
        "microsoft.foundry.project.id",
        "microsoft.session.id",
        "error.type",
    }
)


class AzureHttpResponse(Protocol):
    def raise_for_status(self) -> None: ...

    def json(self) -> Any: ...


AzureRequest = Callable[..., AzureHttpResponse]


class AzureFoundryRuntimeClient(Protocol):
    def list_components(self, *, subscription_id: str) -> tuple[dict[str, str], ...]: ...

    def query_spans(
        self,
        *,
        app_id: str,
        start_time: datetime,
        end_time: datetime,
        limit: int,
    ) -> tuple[tuple[dict[str, Any], ...], bool]: ...


class AzureFoundryRuntimeCollectionError(RuntimeError):
    """Stable Azure runtime collection failure without provider response content."""


class AzureFoundryRuntimeRestClient:
    """Discover exact Application Insights components and run allowlisted KQL."""

    def __init__(self, management_request: AzureRequest, monitor_request: AzureRequest):
        self._management_request = management_request
        self._monitor_request = monitor_request

    def list_components(self, *, subscription_id: str) -> tuple[dict[str, str], ...]:
        if not valid_azure_uuid(subscription_id):
            raise ValueError("Azure subscription ID must be a UUID")
        expected_prefix = (
            f"{AZURE_MANAGEMENT_ENDPOINT}/subscriptions/{subscription_id}/providers/"
            "Microsoft.Insights/components"
        )
        url = expected_prefix
        params: dict[str, str] | None = {"api-version": APPLICATION_INSIGHTS_API_VERSION}
        output: list[dict[str, str]] = []
        seen_links: set[str] = set()
        for _ in range(MAX_COMPONENT_PAGES):
            try:
                response = self._management_request("GET", url, params=params, timeout=30.0)
                response.raise_for_status()
                payload = response.json()
            except Exception as error:
                raise AzureFoundryRuntimeCollectionError(
                    f"application_insights:list:{_safe_error_code(error)}"
                ) from None
            values = payload.get("value") if isinstance(payload, dict) else None
            if not isinstance(values, list):
                raise AzureFoundryRuntimeCollectionError(
                    "application_insights:list:invalid_response_shape"
                )
            for raw in values:
                component = _component(raw, subscription_id)
                if component is None:
                    continue
                output.append(component)
                if len(output) > MAX_COMPONENTS_PER_SUBSCRIPTION:
                    raise AzureFoundryRuntimeCollectionError(
                        f"application_insights:list:component_limit_"
                        f"{MAX_COMPONENTS_PER_SUBSCRIPTION}"
                    )
            next_link = payload.get("nextLink")
            if not next_link:
                return tuple(output)
            if (
                not isinstance(next_link, str)
                or not next_link.startswith(expected_prefix)
                or next_link in seen_links
            ):
                raise AzureFoundryRuntimeCollectionError(
                    "application_insights:list:invalid_next_link"
                )
            seen_links.add(next_link)
            url = next_link
            params = None
        raise AzureFoundryRuntimeCollectionError(
            f"application_insights:list:page_limit_{MAX_COMPONENT_PAGES}"
        )

    def query_spans(
        self,
        *,
        app_id: str,
        start_time: datetime,
        end_time: datetime,
        limit: int,
    ) -> tuple[tuple[dict[str, Any], ...], bool]:
        if not valid_azure_uuid(app_id):
            raise ValueError("Application Insights app ID must be a UUID")
        if not 1 <= limit <= MAX_ROWS_PER_COMPONENT:
            raise ValueError("Application Insights row limit is invalid")
        start, end = _aware(start_time), _aware(end_time)
        if start >= end:
            raise ValueError("runtime collection start must precede end")
        query = _metadata_query(start, end, limit + 1)
        try:
            response = self._monitor_request(
                "GET",
                f"{AZURE_APPLICATION_INSIGHTS_ENDPOINT}/v1/apps/{app_id}/query",
                params={"query": query},
                timeout=45.0,
            )
            response.raise_for_status()
            payload = response.json()
        except Exception as error:
            raise AzureFoundryRuntimeCollectionError(
                f"application_insights:query:{_safe_error_code(error)}"
            ) from None
        rows = _table_rows(payload)
        truncated = len(rows) > limit
        return tuple(rows[:limit]), truncated


class AzureFoundrySpanNormalizer:
    """Normalize one server-side metadata projection into provider-neutral activity."""

    def normalize(
        self,
        row: dict[str, Any],
        *,
        subscription_id: str,
        component: dict[str, str],
        observed_at: datetime,
        session_uid: str,
    ) -> ActivityRecord | None:
        if set(row) - _SAFE_ROW_KEYS:
            raise AzureFoundryRuntimeCollectionError(
                "Application Insights returned an unexpected projected column"
            )
        trace_uid = _identifier(row.get("trace_id"))
        span_uid = _identifier(row.get("span_id"))
        parent_span_uid = _identifier(row.get("parent_span_id"))
        if trace_uid is None or span_uid is None:
            raise AzureFoundryRuntimeCollectionError(
                "Foundry runtime span has no valid trace/span identity"
            )
        occurred_at = _timestamp(row.get("timestamp"))
        if occurred_at is None:
            raise AzureFoundryRuntimeCollectionError("Foundry runtime span has no valid time")
        operation = _bounded_text(row.get("operation"), 128)
        category = _category(operation)
        if operation is None or category is None:
            return None
        duration_ms = _duration(row.get("duration_ms"))
        completed_at = (
            occurred_at + timedelta(milliseconds=duration_ms)
            if duration_ms is not None
            else None
        )
        project_id = _project_id(row.get("project_id"), subscription_id)
        agent_id = _bounded_text(row.get("agent_id"), 512)
        agent_name = _bounded_text(row.get("agent_name"), 512)
        request_model = _bounded_text(row.get("request_model"), 512)
        response_model = _bounded_text(row.get("response_model"), 512)
        tool_name = _bounded_text(row.get("tool_name"), 512)
        attributes = _activity_attributes(row)
        entities = _entities(
            category=category,
            project_id=project_id,
            agent_id=agent_id,
            agent_name=agent_name,
            request_model=request_model,
            response_model=response_model,
            tool_name=tool_name,
        )
        outcome = _outcome(row)
        source_uid = f"{component['app_id']}:{trace_uid}:{span_uid}"
        projection_digest = hashlib.sha256(
            json.dumps(
                {
                    "trace_id": trace_uid,
                    "span_id": span_uid,
                    "parent_span_id": parent_span_uid,
                    "operation": operation,
                    "outcome": outcome.value,
                    "attributes": attributes,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        return ActivityRecord(
            source_uid=source_uid,
            category=category,
            activity_name=f"azure.foundry.{operation}",
            title=_title(category, operation, response_model or request_model, tool_name),
            occurred_at=occurred_at,
            observed_at=observed_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            outcome=outcome,
            provider=PROVIDER,
            account_uid=subscription_id,
            region=component["location"],
            session_uid=session_uid,
            trace_uid=trace_uid,
            span_uid=span_uid,
            parent_span_uid=parent_span_uid,
            telemetry_convention="opentelemetry_genai",
            content_policy="metadata_only",
            entities=entities,
            evidence=Evidence(
                source_type="azure_application_insights_foundry_span",
                locator=(
                    f"azure://application-insights/{component['app_id']}"
                    f"#trace={trace_uid}&span={span_uid}"
                ),
                observed_at=observed_at,
                payload={
                    "metadata_projection_sha256": projection_digest,
                    "subscription_id": subscription_id,
                    "component_resource_id": component["resource_id"],
                    "application_id": component["app_id"],
                    "trace_id": trace_uid,
                    "span_id": span_uid,
                    "parent_span_id": parent_span_uid,
                    "operation": operation,
                    "source_projection": "server_side_allowlist",
                    "telemetry_convention": "opentelemetry_genai",
                    "content_policy": "metadata_only",
                },
            ),
            attributes=attributes,
        )


class AzureConnectionAgentRuntimeCollector:
    """Collect bounded Foundry spans across selected Azure subscriptions."""

    def __init__(
        self,
        client_factory: Callable[[str], AzureFoundryRuntimeClient] | None = None,
        *,
        now: Callable[[], datetime] | None = None,
        lookback: timedelta = DEFAULT_LOOKBACK,
    ) -> None:
        self._client_factory = client_factory or _default_client
        self._now = now or (lambda: datetime.now(UTC))
        self._lookback = lookback

    def collect(
        self,
        *,
        tenant_id: str,
        connection: dict[str, Any],
        repository: Any,
    ) -> dict[str, Any]:
        if connection.get("provider") != "azure":
            raise ValueError("connection is not an Azure connection")
        if connection.get("lifecycle_state") != "active":
            raise ValueError("disabled Azure connections cannot collect")
        if AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY not in connection.get("declared_scopes", []):
            raise ValueError("Azure Foundry runtime activity scope is not declared")
        configuration = connection.get("configuration", {})
        customer_tenant = configuration.get("tenant_id")
        subscriptions = configuration.get("subscriptions")
        if (
            not isinstance(customer_tenant, str)
            or not valid_azure_uuid(customer_tenant)
            or not isinstance(subscriptions, list)
            or not subscriptions
        ):
            raise ValueError("complete Azure subscription selection before collecting runtime")

        client = self._client_factory(customer_tenant)
        end_time = _aware(self._now())
        cursor = repository.latest_azure_agent_runtime_cursor(
            tenant_id, str(connection["id"])
        )
        start_time, catchup_capped = _collection_window(
            end_time,
            cursor=cursor,
            initial_lookback=self._lookback,
        )
        result: dict[str, Any] = {
            "state": "complete",
            "subscriptions": 0,
            "components": 0,
            "activities": 0,
            "duplicates": 0,
            "linked_entities": 0,
            "unresolved_entities": 0,
            "partial_subscriptions": 0,
            "failed_subscriptions": 0,
            "window_start": start_time.isoformat(),
            "window_end": end_time.isoformat(),
            "content_policy": "metadata_only",
            "source_projection": "server_side_allowlist",
            "catchup_capped": catchup_capped,
            "cursor_advance_safe": False,
        }
        for raw_subscription in subscriptions:
            subscription_id = (
                raw_subscription.get("id") if isinstance(raw_subscription, dict) else None
            )
            if not isinstance(subscription_id, str) or not valid_azure_uuid(subscription_id):
                result["failed_subscriptions"] += 1
                continue
            subscription_id = subscription_id.lower()
            result["subscriptions"] += 1
            batch, component_count = self._collect_subscription(
                client,
                subscription_id=subscription_id,
                connection_id=str(connection["id"]),
                start_time=start_time,
                end_time=end_time,
            )
            base_state = batch.coverage[0].state
            if catchup_capped:
                current = batch.coverage[0]
                batch = replace(
                    batch,
                    coverage=(
                        Coverage(
                            current.plane,
                            CoverageState.PARTIAL,
                            current.scope,
                            (current.detail or "")
                            + " Historical catch-up was capped at 24 hours; the earlier "
                            "gap remains explicit.",
                        ),
                    ),
                )
            ingested = repository.ingest_activity(tenant_id, batch)
            for key in ("activities", "duplicates", "linked_entities", "unresolved_entities"):
                result[key] += int(ingested.get(key, 0))
            result["components"] += component_count
            if base_state is CoverageState.FAILED:
                result["failed_subscriptions"] += 1
            elif base_state is not CoverageState.COMPLETE:
                result["partial_subscriptions"] += 1

        assessed = result["subscriptions"]
        if assessed == 0 or result["failed_subscriptions"] >= assessed:
            result["state"] = "failed"
        elif result["failed_subscriptions"] or result["partial_subscriptions"]:
            result["state"] = "partial"
        elif catchup_capped:
            result["state"] = "partial"
        else:
            result["cursor_advance_safe"] = True
        return result

    def _collect_subscription(
        self,
        client: AzureFoundryRuntimeClient,
        *,
        subscription_id: str,
        connection_id: str,
        start_time: datetime,
        end_time: datetime,
    ) -> tuple[ActivityBatch, int]:
        observed_at = datetime.now(UTC)
        scope = f"azure:subscription:{subscription_id}:application-insights:foundry-spans"
        run_id = f"azure-foundry-runtime-{subscription_id}-{observed_at.isoformat()}"
        try:
            components = client.list_components(subscription_id=subscription_id)
        except Exception as error:
            return (
                _failed_batch(
                    connection_id,
                    run_id,
                    scope,
                    observed_at,
                    f"Application Insights discovery failed ({_safe_error_code(error)}).",
                ),
                0,
            )
        if not components:
            return (
                ActivityBatch(
                    connector_id=CONNECTOR_ID,
                    connection_id=connection_id,
                    run_id=run_id,
                    scope_key=scope,
                    collected_at=observed_at,
                    coverage=(
                        Coverage(
                            ACTIVITY_PLANE,
                            CoverageState.PARTIAL,
                            scope,
                            "No Application Insights component was discovered in the selected "
                            "subscription; this is not zero runtime activity.",
                        ),
                    ),
                ),
                0,
            )

        activities: dict[str, ActivityRecord] = {}
        warnings: list[str] = []
        failed_components = 0
        queried_components = 0
        normalizer = AzureFoundrySpanNormalizer()
        for component in components:
            remaining = MAX_ROWS_PER_SUBSCRIPTION - len(activities)
            if remaining <= 0:
                warnings.append(
                    f"subscription runtime event safety limit reached at "
                    f"{MAX_ROWS_PER_SUBSCRIPTION}"
                )
                break
            try:
                rows, truncated = client.query_spans(
                    app_id=component["app_id"],
                    start_time=start_time,
                    end_time=end_time,
                    limit=min(MAX_ROWS_PER_COMPONENT, remaining),
                )
                queried_components += 1
            except Exception as error:
                failed_components += 1
                warnings.append(
                    f"{component['resource_id']}: query failed ({_safe_error_code(error)})"
                )
                continue
            if truncated:
                warnings.append(
                    f"{component['resource_id']}: span row safety limit reached"
                )
            trace_sessions = _trace_sessions(rows)
            for row in rows:
                trace_uid = _identifier(row.get("trace_id"))
                if trace_uid is None:
                    warnings.append(
                        f"{component['resource_id']}: projected row has invalid trace identity"
                    )
                    continue
                try:
                    activity = normalizer.normalize(
                        row,
                        subscription_id=subscription_id,
                        component=component,
                        observed_at=observed_at,
                        session_uid=trace_sessions.get(trace_uid, trace_uid),
                    )
                except AzureFoundryRuntimeCollectionError as error:
                    warnings.append(f"{component['resource_id']}: {error}")
                    continue
                if activity is not None:
                    activities.setdefault(activity.source_uid, activity)

        state = (
            CoverageState.FAILED
            if failed_components == len(components)
            else CoverageState.PARTIAL
            if warnings
            else CoverageState.COMPLETE
        )
        detail = (
            f"Queried {queried_components} of {len(components)} Application Insights "
            f"component(s) with a server-side metadata allowlist; normalized "
            f"{len(activities)} Foundry span(s). Prompt/response content, system instructions, "
            "documents, and tool arguments/results were not requested."
        )
        if warnings:
            detail += " " + "; ".join(dict.fromkeys(warnings))[:3_400]
        return (
            ActivityBatch(
                connector_id=CONNECTOR_ID,
                connection_id=connection_id,
                run_id=run_id,
                scope_key=scope,
                collected_at=observed_at,
                coverage=(Coverage(ACTIVITY_PLANE, state, scope, detail),),
                activities=tuple(
                    sorted(
                        activities.values(),
                        key=lambda item: (
                            item.occurred_at,
                            item.trace_uid or "",
                            item.span_uid or "",
                        ),
                    )
                ),
            ),
            len(components),
        )


def _metadata_query(start_time: datetime, end_time: datetime, limit: int) -> str:
    start = _aware(start_time).isoformat().replace("+00:00", "Z")
    end = _aware(end_time).isoformat().replace("+00:00", "Z")
    return f"""
union withsource=source_table requests, dependencies
| where timestamp >= datetime({start}) and timestamp < datetime({end})
| extend operation=tostring(customDimensions['gen_ai.operation.name'])
| where operation in ('invoke_agent', 'create_agent', 'chat', 'text_completion',
                       'generate_content', 'execute_tool', 'retrieve', 'rerank')
| where isnotempty(customDimensions['gen_ai.agent.id'])
| project source_table, timestamp, span_id=id, trace_id=operation_Id,
          parent_span_id=operation_ParentId, name, duration_ms=toreal(duration),
          success=tostring(success), result_code=tostring(resultCode),
          agent_id=tostring(customDimensions['gen_ai.agent.id']),
          agent_name=tostring(customDimensions['gen_ai.agent.name']),
          agent_version=tostring(customDimensions['gen_ai.agent.version']),
          session_id=tostring(customDimensions['microsoft.session.id']),
          conversation_id=tostring(customDimensions['gen_ai.conversation.id']),
          project_id=tostring(customDimensions['microsoft.foundry.project.id']),
          operation,
          request_model=tostring(customDimensions['gen_ai.request.model']),
          response_model=tostring(customDimensions['gen_ai.response.model']),
          provider=tostring(customDimensions['gen_ai.provider.name']),
          response_id=tostring(customDimensions['gen_ai.response.id']),
          tool_call_id=tostring(customDimensions['gen_ai.tool.call.id']),
          tool_name=tostring(customDimensions['gen_ai.tool.name']),
          tool_type=tostring(customDimensions['gen_ai.tool.type']),
          input_tokens=toint(customDimensions['gen_ai.usage.input_tokens']),
          output_tokens=toint(customDimensions['gen_ai.usage.output_tokens']),
          cache_read_tokens=toint(customDimensions['gen_ai.usage.cache_read.input_tokens']),
          reasoning_tokens=toint(customDimensions['gen_ai.usage.reasoning.output_tokens']),
          error_type=tostring(customDimensions['error.type'])
| order by timestamp asc, trace_id asc, span_id asc
| take {limit}
""".strip()


def _table_rows(payload: Any) -> list[dict[str, Any]]:
    tables = payload.get("tables") if isinstance(payload, dict) else None
    if not isinstance(tables, list) or len(tables) != 1 or not isinstance(tables[0], dict):
        raise AzureFoundryRuntimeCollectionError(
            "application_insights:query:invalid_response_shape"
        )
    columns = tables[0].get("columns")
    rows = tables[0].get("rows")
    if not isinstance(columns, list) or not isinstance(rows, list):
        raise AzureFoundryRuntimeCollectionError(
            "application_insights:query:invalid_response_shape"
        )
    names = [item.get("name") if isinstance(item, dict) else None for item in columns]
    if any(not isinstance(name, str) for name in names) or set(names) - _SAFE_ROW_KEYS:
        raise AzureFoundryRuntimeCollectionError(
            "application_insights:query:unexpected_projection"
        )
    output: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, list) or len(row) != len(names):
            raise AzureFoundryRuntimeCollectionError(
                "application_insights:query:invalid_row_shape"
            )
        output.append(dict(zip(names, row, strict=True)))
    return output


def _component(raw: Any, subscription_id: str) -> dict[str, str] | None:
    if not isinstance(raw, dict):
        return None
    resource_id = raw.get("id")
    properties = raw.get("properties") if isinstance(raw.get("properties"), dict) else {}
    app_id = properties.get("AppId") or raw.get("appId")
    location = raw.get("location")
    match = _COMPONENT_ID.fullmatch(resource_id) if isinstance(resource_id, str) else None
    if (
        match is None
        or match.group("subscription").lower() != subscription_id.lower()
        or not isinstance(app_id, str)
        or not valid_azure_uuid(app_id)
        or not isinstance(location, str)
        or not location.strip()
    ):
        return None
    return {
        "resource_id": resource_id.lower(),
        "app_id": app_id.lower(),
        "location": location.lower().replace(" ", ""),
    }


def _trace_sessions(rows: tuple[dict[str, Any], ...]) -> dict[str, str]:
    output: dict[str, str] = {}
    for row in rows:
        trace = _identifier(row.get("trace_id"))
        if trace is None:
            continue
        session = _bounded_text(row.get("session_id"), 512)
        conversation = _bounded_text(row.get("conversation_id"), 512)
        if session:
            output[trace] = session
        elif conversation and trace not in output:
            output[trace] = conversation
    return output


def _activity_attributes(row: dict[str, Any]) -> dict[str, Any]:
    mapping = {
        "source_table": "source_table",
        "result_code": "result_code",
        "agent_id": "gen_ai.agent.id",
        "agent_name": "gen_ai.agent.name",
        "agent_version": "gen_ai.agent.version",
        "conversation_id": "gen_ai.conversation.id",
        "operation": "gen_ai.operation.name",
        "provider": "gen_ai.provider.name",
        "request_model": "gen_ai.request.model",
        "response_id": "gen_ai.response.id",
        "response_model": "gen_ai.response.model",
        "tool_call_id": "gen_ai.tool.call.id",
        "tool_name": "gen_ai.tool.name",
        "tool_type": "gen_ai.tool.type",
        "cache_read_tokens": "gen_ai.usage.cache_read.input_tokens",
        "input_tokens": "gen_ai.usage.input_tokens",
        "output_tokens": "gen_ai.usage.output_tokens",
        "reasoning_tokens": "gen_ai.usage.reasoning.output_tokens",
        "project_id": "microsoft.foundry.project.id",
        "session_id": "microsoft.session.id",
        "error_type": "error.type",
    }
    output: dict[str, Any] = {}
    for source, target in mapping.items():
        value = _safe_value(row.get(source))
        if value not in {None, ""}:
            output[target] = value
    if set(output) - _SAFE_ACTIVITY_ATTRIBUTES:
        raise AssertionError("unsafe Azure runtime activity attribute escaped the allowlist")
    output["source_projection"] = "server_side_allowlist"
    return output


def _entities(
    *,
    category: ActivityCategory,
    project_id: str | None,
    agent_id: str | None,
    agent_name: str | None,
    request_model: str | None,
    response_model: str | None,
    tool_name: str | None,
) -> tuple[ActivityEntity, ...]:
    output: list[ActivityEntity] = []
    if agent_id:
        agent_key = (
            f"{project_id}/agents/{agent_id.lower()}" if project_id else None
        )
        output.append(
            ActivityEntity(
                role=ActivityEntityRole.AGENT,
                external_uid=agent_id,
                display_name=agent_name or agent_id,
                asset=AssetRef(AssetKind.AI_AGENT, agent_key) if agent_key else None,
                correlation=(
                    ActivityCorrelation.EXACT_IDENTIFIER
                    if agent_key
                    else ActivityCorrelation.UNRESOLVED
                ),
                confidence=1.0 if agent_key else 0.0,
            )
        )
    if project_id:
        output.append(
            ActivityEntity(
                role=ActivityEntityRole.RESOURCE,
                external_uid=project_id,
                display_name=project_id.rsplit("/", 1)[-1],
                asset=AssetRef(AssetKind.CLOUD_RESOURCE, project_id),
                correlation=ActivityCorrelation.EXACT_IDENTIFIER,
                confidence=1.0,
            )
        )
    model = response_model or request_model
    if model:
        output.append(
            ActivityEntity(
                role=ActivityEntityRole.MODEL,
                external_uid=model,
                display_name=model,
                asset=(
                    AssetRef(
                        AssetKind.AI_MODEL,
                        f"{project_id}/model-deployments/{request_model.casefold()}",
                    )
                    if project_id and request_model
                    else None
                ),
                correlation=(
                    ActivityCorrelation.EXACT_IDENTIFIER
                    if project_id and request_model
                    else ActivityCorrelation.UNRESOLVED
                ),
                confidence=1.0 if project_id and request_model else 0.0,
            )
        )
    if category is ActivityCategory.TOOL_INVOCATION and tool_name:
        tool_key = (
            f"{project_id}/agents/{agent_id.lower()}/tools/{tool_name.casefold()}"
            if project_id and agent_id
            else None
        )
        output.append(
            ActivityEntity(
                role=ActivityEntityRole.TOOL,
                external_uid=tool_name,
                display_name=tool_name,
                asset=AssetRef(AssetKind.AI_TOOL, tool_key) if tool_key else None,
                correlation=(
                    ActivityCorrelation.EXACT_IDENTIFIER
                    if tool_key
                    else ActivityCorrelation.UNRESOLVED
                ),
                confidence=1.0 if tool_key else 0.0,
            )
        )
    return tuple(output)


def _category(operation: str | None) -> ActivityCategory | None:
    if operation in {"invoke_agent", "create_agent"}:
        return ActivityCategory.AGENT_INVOCATION
    if operation in {"chat", "text_completion", "generate_content"}:
        return ActivityCategory.MODEL_INVOCATION
    if operation == "execute_tool":
        return ActivityCategory.TOOL_INVOCATION
    if operation in {"retrieve", "rerank"}:
        return ActivityCategory.RETRIEVAL
    return None


def _title(
    category: ActivityCategory,
    operation: str,
    model: str | None,
    tool: str | None,
) -> str:
    if category is ActivityCategory.TOOL_INVOCATION:
        return f"Tool {tool or operation} invoked"
    if category is ActivityCategory.MODEL_INVOCATION:
        return f"Model {model or operation} invoked"
    if category is ActivityCategory.RETRIEVAL:
        return "Agent retrieval executed"
    return "Foundry agent invoked"


def _outcome(row: dict[str, Any]) -> ActivityOutcome:
    error = _bounded_text(row.get("error_type"), 256)
    success = str(row.get("success", "")).casefold()
    result_code = str(row.get("result_code", ""))
    if error or success == "false":
        return ActivityOutcome.FAILURE
    try:
        if int(result_code) >= 400:
            return ActivityOutcome.FAILURE
    except ValueError:
        pass
    if success == "true":
        return ActivityOutcome.SUCCESS
    return ActivityOutcome.UNKNOWN


def _project_id(value: Any, subscription_id: str) -> str | None:
    text = _bounded_text(value, 2_048)
    match = _PROJECT_ID.fullmatch(text) if text else None
    if match is None or match.group("subscription").lower() != subscription_id.lower():
        return None
    return text.lower()


def _identifier(value: Any) -> str | None:
    text = _bounded_text(value, 64)
    return text.lower() if text and _HEX_ID.fullmatch(text) else None


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _duration(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    result = float(value)
    return result if result >= 0 and math.isfinite(result) else None


def _safe_value(value: Any) -> str | int | float | bool | None:
    if isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return value[:1_024]
    return None


def _bounded_text(value: Any, limit: int) -> str | None:
    return value.strip()[:limit] if isinstance(value, str) and value.strip() else None


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("runtime collection timestamps must be timezone-aware")
    return value


def _collection_window(
    end_time: datetime,
    *,
    cursor: datetime | None,
    initial_lookback: timedelta,
) -> tuple[datetime, bool]:
    end = _aware(end_time)
    if not timedelta(minutes=5) <= initial_lookback <= MAX_CATCHUP:
        raise ValueError("runtime collection lookback must be between 5 minutes and 24 hours")
    start = end - initial_lookback
    if cursor is None:
        return start, False
    desired = min(start, _aware(cursor) - COLLECTION_OVERLAP)
    floor = end - MAX_CATCHUP
    return max(desired, floor), desired < floor


def _failed_batch(
    connection_id: str,
    run_id: str,
    scope: str,
    observed_at: datetime,
    detail: str,
) -> ActivityBatch:
    return ActivityBatch(
        connector_id=CONNECTOR_ID,
        connection_id=connection_id,
        run_id=run_id,
        scope_key=scope,
        collected_at=observed_at,
        coverage=(Coverage(ACTIVITY_PLANE, CoverageState.FAILED, scope, detail),),
    )


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
                return str(nested["code"])[:128]
        status = getattr(response, "status_code", None)
        if status is not None:
            return str(status)
    if isinstance(error, AzureFoundryRuntimeCollectionError):
        return str(error)[:256]
    return error.__class__.__name__


def _default_client(customer_tenant_id: str) -> AzureFoundryRuntimeRestClient:
    return AzureFoundryRuntimeRestClient(
        authorized_azure_request(customer_tenant_id),
        authorized_azure_monitor_request(customer_tenant_id),
    )
