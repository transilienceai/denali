from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from denali.connectors.azure_agent_runtime_activity import (
    ACTIVITY_PLANE,
    CONNECTOR_ID,
    AzureConnectionAgentRuntimeCollector,
    AzureFoundryRuntimeCollectionError,
    AzureFoundryRuntimeRestClient,
    AzureFoundrySpanNormalizer,
    _metadata_query,
)
from denali.domain import ActivityCategory, ActivityOutcome, CoverageState

SUBSCRIPTION = "8cd2b4cc-c789-466d-a8f7-8f51fb20985d"
TENANT = "017c6f31-f951-4bda-a50a-c168c0e6f815"
APP_ID = "023d073a-6a42-4604-a401-36a118d6d9cf"
AGENT_ID = "42edfdcd-8275-4663-a258-30452fe63270"
TRACE_ID = "70f0cb239760d6bc960f9c1cabff229a"
SESSION_ID = "b" * 64
PROJECT_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/anna-aidr-lab-rg/providers/"
    "Microsoft.CognitiveServices/accounts/cog-lab/projects/anna-aidr-dev"
)
COMPONENT_ID = (
    f"/subscriptions/{SUBSCRIPTION}/resourceGroups/anna-aidr-lab-rg/providers/"
    "Microsoft.Insights/components/anna-aidr"
)
COMPONENT = {
    "resource_id": COMPONENT_ID.lower(),
    "app_id": APP_ID,
    "location": "eastus2",
}
NOW = datetime(2026, 9, 14, 15, 36, tzinfo=UTC)


def _row(operation: str, span_id: str, **overrides: Any) -> dict[str, Any]:
    value = {
        "source_table": "dependencies" if operation != "invoke_agent" else "requests",
        "timestamp": NOW.isoformat(),
        "span_id": span_id,
        "trace_id": TRACE_ID,
        "parent_span_id": "a" * 16,
        "name": operation,
        "duration_ms": 12.5,
        "success": "True",
        "result_code": "0",
        "agent_id": AGENT_ID,
        "agent_name": "anna-aidr",
        "agent_version": "3",
        "session_id": SESSION_ID if operation != "invoke_agent" else "",
        "conversation_id": "conv-safe-identifier",
        "project_id": PROJECT_ID,
        "operation": operation,
        "request_model": "gpt-5-mini" if operation == "chat" else "",
        "response_model": "gpt-5-mini-2025-08-07" if operation == "chat" else "",
        "provider": "azure.ai.foundry" if operation == "chat" else "",
        "response_id": "resp-safe-identifier" if operation == "chat" else "",
        "tool_call_id": "call-safe-identifier" if operation == "execute_tool" else "",
        "tool_name": "stage_followup" if operation == "execute_tool" else "",
        "tool_type": "function" if operation == "execute_tool" else "",
        "input_tokens": 100 if operation == "chat" else None,
        "output_tokens": 20 if operation == "chat" else None,
        "cache_read_tokens": 0 if operation == "chat" else None,
        "reasoning_tokens": 0 if operation == "chat" else None,
        "error_type": "",
    }
    value.update(overrides)
    return value


def test_normalizes_foundry_spans_with_exact_metadata_only_entities() -> None:
    normalizer = AzureFoundrySpanNormalizer()
    root = normalizer.normalize(
        _row("invoke_agent", "1" * 16),
        subscription_id=SUBSCRIPTION,
        component=COMPONENT,
        observed_at=NOW,
        session_uid=SESSION_ID,
    )
    model = normalizer.normalize(
        _row("chat", "2" * 16),
        subscription_id=SUBSCRIPTION,
        component=COMPONENT,
        observed_at=NOW,
        session_uid=SESSION_ID,
    )
    tool = normalizer.normalize(
        _row("execute_tool", "3" * 16),
        subscription_id=SUBSCRIPTION,
        component=COMPONENT,
        observed_at=NOW,
        session_uid=SESSION_ID,
    )

    assert root is not None and root.category is ActivityCategory.AGENT_INVOCATION
    assert model is not None and model.category is ActivityCategory.MODEL_INVOCATION
    assert tool is not None and tool.category is ActivityCategory.TOOL_INVOCATION
    assert model.provider == "azure_foundry"
    assert model.outcome is ActivityOutcome.SUCCESS
    assert model.content_policy == "metadata_only"
    assert model.session_uid == SESSION_ID
    assert model.entities[1].asset is not None
    assert model.entities[2].asset is not None
    assert model.entities[2].asset.natural_key == (
        f"{PROJECT_ID.lower()}/model-deployments/gpt-5-mini"
    )
    assert tool.entities[-1].asset is not None
    assert tool.entities[-1].asset.natural_key.endswith("/tools/stage_followup")
    serialized = repr((root, model, tool))
    assert "prompt" not in serialized.casefold()
    assert "tool result" not in serialized.casefold()
    assert model.evidence.payload["source_projection"] == "server_side_allowlist"


def test_rejects_any_unexpected_projected_column_before_persistence() -> None:
    row = _row("chat", "2" * 16)
    row["gen_ai.input.messages"] = "private prompt"

    with pytest.raises(
        AzureFoundryRuntimeCollectionError,
        match="unexpected projected column",
    ):
        AzureFoundrySpanNormalizer().normalize(
            row,
            subscription_id=SUBSCRIPTION,
            component=COMPONENT,
            observed_at=NOW,
            session_uid=SESSION_ID,
        )


def test_kql_is_bounded_and_projects_no_content_fields() -> None:
    query = _metadata_query(NOW - timedelta(minutes=5), NOW, 101)

    assert "take 101" in query
    assert "project source_table" in query
    for forbidden in (
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.system_instructions",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
    ):
        assert forbidden not in query


class FakeRuntimeClient:
    def __init__(self, rows: tuple[dict[str, Any], ...] = ()) -> None:
        self.rows = rows
        self.components = (COMPONENT,)
        self.calls: list[tuple[str, str]] = []

    def list_components(self, *, subscription_id: str) -> tuple[dict[str, str], ...]:
        self.calls.append(("list", subscription_id))
        return self.components

    def query_spans(self, *, app_id: str, **_kwargs: Any):
        self.calls.append(("query", app_id))
        return self.rows, False


class Sink:
    def __init__(self) -> None:
        self.batches = []

    def latest_azure_agent_runtime_cursor(self, tenant_id: str, connection_id: str):
        return None

    def ingest_activity(self, tenant_id: str, batch: Any) -> dict[str, int]:
        self.batches.append((tenant_id, batch))
        return {
            "activities": len(batch.activities),
            "duplicates": 0,
            "linked_entities": 0,
            "unresolved_entities": sum(len(item.entities) for item in batch.activities),
        }


def _connection() -> dict[str, Any]:
    return {
        "id": "connection-id",
        "provider": "azure",
        "lifecycle_state": "active",
        "declared_scopes": ["azure.agent_runtime_activity"],
        "configuration": {
            "tenant_id": TENANT,
            "subscriptions": [{"id": SUBSCRIPTION, "name": "Lab"}],
        },
    }


def test_connection_collector_propagates_session_and_reports_complete_coverage() -> None:
    client = FakeRuntimeClient(
        (
            _row("invoke_agent", "1" * 16),
            _row("execute_tool", "2" * 16),
            _row("chat", "3" * 16),
        )
    )
    sink = Sink()

    result = AzureConnectionAgentRuntimeCollector(
        client_factory=lambda _tenant: client,
        now=lambda: NOW + timedelta(minutes=1),
    ).collect(tenant_id="tenant", connection=_connection(), repository=sink)

    assert result["state"] == "complete"
    assert result["activities"] == 3
    assert result["components"] == 1
    assert result["cursor_advance_safe"] is True
    assert client.calls == [("list", SUBSCRIPTION), ("query", APP_ID)]
    [(_, batch)] = sink.batches
    assert batch.connector_id == CONNECTOR_ID
    assert batch.coverage[0].plane == ACTIVITY_PLANE
    assert batch.coverage[0].state is CoverageState.COMPLETE
    assert {item.session_uid for item in batch.activities} == {SESSION_ID}


def test_missing_application_insights_is_partial_not_zero_activity() -> None:
    client = FakeRuntimeClient()
    client.components = ()
    sink = Sink()

    result = AzureConnectionAgentRuntimeCollector(
        client_factory=lambda _tenant: client,
        now=lambda: NOW,
    ).collect(tenant_id="tenant", connection=_connection(), repository=sink)

    assert result["state"] == "partial"
    assert result["cursor_advance_safe"] is False
    [(_, batch)] = sink.batches
    assert batch.coverage[0].state is CoverageState.PARTIAL
    assert "not zero runtime activity" in (batch.coverage[0].detail or "")


class Response:
    def __init__(self, payload: dict[str, Any]):
        self.payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self.payload


def test_rest_client_discovers_exact_components_and_parses_allowlisted_rows() -> None:
    monitor_calls: list[dict[str, Any]] = []

    def management_request(method: str, url: str, **kwargs: Any) -> Response:
        assert method == "GET"
        assert f"/subscriptions/{SUBSCRIPTION}/" in url
        return Response(
            {
                "value": [
                    {
                        "id": COMPONENT_ID,
                        "location": "East US 2",
                        "properties": {"AppId": APP_ID},
                    },
                    {
                        "id": COMPONENT_ID.replace(SUBSCRIPTION, TENANT),
                        "location": "East US 2",
                        "properties": {"AppId": APP_ID},
                    },
                ]
            }
        )

    row = _row("chat", "2" * 16)

    def monitor_request(method: str, url: str, **kwargs: Any) -> Response:
        monitor_calls.append({"method": method, "url": url, **kwargs})
        columns = [{"name": key, "type": "string"} for key in row]
        return Response({"tables": [{"columns": columns, "rows": [list(row.values())]}]})

    client = AzureFoundryRuntimeRestClient(management_request, monitor_request)
    components = client.list_components(subscription_id=SUBSCRIPTION)
    rows, truncated = client.query_spans(
        app_id=APP_ID,
        start_time=NOW - timedelta(minutes=5),
        end_time=NOW,
        limit=100,
    )

    assert components == (COMPONENT,)
    assert rows == (row,)
    assert truncated is False
    assert monitor_calls[0]["url"].endswith(f"/v1/apps/{APP_ID}/query")
    assert "gen_ai.input.messages" not in monitor_calls[0]["params"]["query"]
