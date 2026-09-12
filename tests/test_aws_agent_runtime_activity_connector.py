from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import denali.connectors.aws_agent_runtime_activity as runtime_connector
from denali.connectors.aws_agent_runtime_activity import (
    ACTIVITY_PLANE,
    AwsAgentRuntimeRegionConnector,
    AwsAgentRuntimeSpanNormalizer,
    _collection_window,
)

NOW = datetime(2026, 9, 11, 12, tzinfo=UTC)
ACCOUNT = "331145994818"
REGION = "us-west-2"
RUNTIME_ARN = "arn:aws:bedrock-agentcore:us-west-2:331145994818:runtime/runtime-123"


def _event(span: dict, *, event_id: str = "event-1") -> dict:
    return {
        "eventId": event_id,
        "timestamp": int(NOW.timestamp() * 1000),
        "logStreamName": "spans",
        "message": json.dumps(span),
    }


def _span(**overrides) -> dict:
    value = {
        "traceId": "6a01eef11066751d68f90def0da1f80a",
        "spanId": "3a300b0b3fe650e4",
        "name": "invoke_agent sales-agent",
        "kind": "INTERNAL",
        "startTimeUnixNano": "1789137600000000000",
        "endTimeUnixNano": "1789137601250000000",
        "scope": {
            "name": "opentelemetry.instrumentation.openai_agents",
            "version": "0.62.1",
        },
        "attributes": {
            "gen_ai.operation.name": "invoke_agent",
            "gen_ai.agent.name": "sales-agent",
            "aws.agent.id": "runtime-123",
            "aws.resource.arn": RUNTIME_ARN,
            "session.id": "session-123",
        },
        "status": {"code": "OK"},
    }
    value.update(overrides)
    return value


def _normalize(span: dict):
    return AwsAgentRuntimeSpanNormalizer().normalize(
        _event(span),
        account_id=ACCOUNT,
        region=REGION,
        partition="aws",
        log_group="/aws/bedrock-agentcore/runtimes/runtime-123-default",
        observed_at=NOW,
    )


def test_normalizes_agentcore_session_trace_and_exact_runtime_identity() -> None:
    activity = _normalize(_span())

    assert activity is not None
    assert activity.category.value == "agent_invocation"
    assert activity.outcome.value == "success"
    assert activity.session_uid == "session-123"
    assert activity.trace_uid == "6a01eef11066751d68f90def0da1f80a"
    assert activity.span_uid == "3a300b0b3fe650e4"
    assert activity.parent_span_uid is None
    assert activity.duration_ms == 1250
    assert activity.telemetry_convention == "opentelemetry_genai"
    assert activity.content_policy == "metadata_only"
    [agent] = activity.entities
    assert agent.role.value == "agent"
    assert agent.asset is not None
    assert agent.asset.natural_key == RUNTIME_ARN

    mirrored = AwsAgentRuntimeSpanNormalizer().normalize(
        _event(_span(), event_id="mirrored-event"),
        account_id=ACCOUNT,
        region=REGION,
        partition="aws",
        log_group="aws/spans",
        observed_at=NOW,
    )
    assert mirrored is not None
    assert mirrored.source_uid == activity.source_uid


def test_tool_span_discards_arguments_results_and_prompt_content() -> None:
    span = _span(
        spanId="4a300b0b3fe650e4",
        name="execute_tool customer@example.com private proposal",
        attributes={
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": "send_proposal",
            "gen_ai.tool.type": "function",
            "gen_ai.tool.call.arguments": '{"recipient":"customer@example.com"}',
            "gen_ai.tool.call.result": '{"message":"secret response"}',
            "gen_ai.input.messages": "private prompt",
            "session.id": "session-123",
            "gateway.id": "gateway-123",
            "target.id": "target-456",
            "aws.resource.arn": (
                "arn:aws:bedrock-agentcore:us-west-2:331145994818:gateway/gateway-123"
            ),
        },
    )
    activity = _normalize(span)

    assert activity is not None
    assert activity.category.value == "tool_invocation"
    assert activity.attributes["gen_ai.tool.name"] == "send_proposal"
    assert activity.attributes["content_fields_discarded"] is True
    assert "record_sha256" not in activity.evidence.payload
    assert activity.evidence.payload["metadata_projection_sha256"]
    serialized = json.dumps(
        {"attributes": dict(activity.attributes), "evidence": dict(activity.evidence.payload)}
    )
    assert "customer@example.com" not in serialized
    assert "secret response" not in serialized
    assert "private prompt" not in serialized
    [tool] = activity.entities
    assert tool.asset is not None
    assert tool.asset.natural_key.endswith("gateway/gateway-123#target/target-456")


def test_openinference_model_span_links_exact_bedrock_model_without_content() -> None:
    span = _span(
        spanId="5a300b0b3fe650e4",
        parentSpanId="3a300b0b3fe650e4",
        attributes={
            "openinference.span.kind": "LLM",
            "llm.model_name": "global.anthropic.claude-sonnet-4-6",
            "llm.system": "bedrock",
            "llm.input_messages.0.message.content": "private",
            "output.value": "also private",
            "session.id": "session-123",
        },
    )
    activity = _normalize(span)

    assert activity is not None
    assert activity.category.value == "model_invocation"
    assert activity.telemetry_convention == "openinference"
    assert activity.parent_span_uid == "3a300b0b3fe650e4"
    [model] = activity.entities
    assert model.asset is not None
    assert model.asset.natural_key == ("aws:bedrock:model:global.anthropic.claude-sonnet-4-6")
    assert "private" not in json.dumps(dict(activity.attributes))


def test_unrecognized_transport_and_content_records_are_not_activity() -> None:
    assert _normalize({"body": {"input": "private"}}) is None
    assert (
        _normalize(
            _span(
                attributes={
                    "http.request.method": "POST",
                    "server.address": "example.internal",
                }
            )
        )
        is None
    )


def test_metadata_projection_has_a_hard_attribute_bound() -> None:
    attributes = {
        "gen_ai.operation.name": "chat",
        "gen_ai.request.model": "global.anthropic.claude-sonnet-4-6",
        "gen_ai.provider.name": "bedrock",
        **{f"gen_ai.usage.custom_{index}": index for index in range(100)},
    }
    activity = _normalize(_span(attributes=attributes))

    assert activity is not None
    assert len([key for key in activity.attributes if key.startswith("gen_ai.")]) <= 64


def test_invalid_or_non_finite_durations_are_not_persisted() -> None:
    negative = _normalize(
        _span(
            startTimeUnixNano="1789137601250000000",
            endTimeUnixNano="1789137600000000000",
        )
    )
    infinite = _normalize(
        _span(
            attributes={
                "gen_ai.operation.name": "invoke_agent",
                "latency_ms": float("inf"),
            }
        )
    )

    assert negative is not None and negative.duration_ms is None
    assert infinite is not None and infinite.duration_ms == 1250


class FakeLogs:
    def __init__(self, events: list[dict] | None = None):
        self.events = events or []
        self.describe_calls: list[dict] = []
        self.filter_calls: list[dict] = []

    def describe_log_groups(self, **request):
        self.describe_calls.append(request)
        if request["logGroupNamePrefix"].startswith("/aws/"):
            return {
                "logGroups": [
                    {"logGroupName": ("/aws/bedrock-agentcore/runtimes/runtime-123-default")}
                ]
            }
        return {"logGroups": []}

    def filter_log_events(self, **request):
        self.filter_calls.append(request)
        return {"events": self.events}


def test_region_collection_reads_only_span_streams_and_states_metadata_boundary() -> None:
    logs = FakeLogs([_event(_span())])
    batch = AwsAgentRuntimeRegionConnector(
        account_id=ACCOUNT,
        region=REGION,
        partition="aws",
        logs_client=logs,
    ).collect(
        start_time=NOW - timedelta(minutes=30),
        end_time=NOW + timedelta(minutes=1),
        connection_id="11111111-1111-4111-8111-111111111111",
    )

    assert batch.coverage[0].plane == ACTIVITY_PLANE
    assert batch.coverage[0].state.value == "complete"
    assert "Metadata-only" in batch.coverage[0].detail
    assert len(batch.activities) == 1
    assert logs.filter_calls[0]["logStreamNamePrefix"] == "spans"
    assert logs.filter_calls[0]["startTime"] < logs.filter_calls[0]["endTime"]


def test_region_event_budget_stops_before_later_pages(monkeypatch) -> None:
    class PagedLogs(FakeLogs):
        def filter_log_events(self, **request):
            self.filter_calls.append(request)
            return {
                "events": [
                    _event(_span(spanId="1a300b0b3fe650e4"), event_id="one"),
                    _event(_span(spanId="2a300b0b3fe650e4"), event_id="two"),
                ],
                "nextToken": "more",
            }

    monkeypatch.setattr(runtime_connector, "MAX_EVENTS_PER_REGION", 1)
    logs = PagedLogs()
    batch = AwsAgentRuntimeRegionConnector(
        account_id=ACCOUNT,
        region=REGION,
        partition="aws",
        logs_client=logs,
    ).collect(
        start_time=NOW - timedelta(minutes=30),
        end_time=NOW + timedelta(minutes=1),
        connection_id="11111111-1111-4111-8111-111111111111",
    )

    assert len(batch.activities) == 1
    assert batch.coverage[0].state.value == "partial"
    assert "safety limit" in batch.coverage[0].detail
    assert len(logs.filter_calls) == 1


def test_region_event_budget_counts_discarded_raw_spans_across_groups(monkeypatch) -> None:
    class MultipleGroups(FakeLogs):
        def describe_log_groups(self, **request):
            self.describe_calls.append(request)
            if request["logGroupNamePrefix"].startswith("/aws/"):
                return {
                    "logGroups": [
                        {"logGroupName": "/aws/bedrock-agentcore/runtimes/first-default"},
                        {"logGroupName": "/aws/bedrock-agentcore/runtimes/second-default"},
                    ]
                }
            return {"logGroups": []}

    monkeypatch.setattr(runtime_connector, "MAX_EVENTS_PER_REGION", 1)
    logs = MultipleGroups([_event({"body": {"input": "discarded"}})])
    batch = AwsAgentRuntimeRegionConnector(
        account_id=ACCOUNT,
        region=REGION,
        partition="aws",
        logs_client=logs,
    ).collect(
        start_time=NOW - timedelta(minutes=30),
        end_time=NOW + timedelta(minutes=1),
        connection_id="11111111-1111-4111-8111-111111111111",
    )

    assert batch.activities == ()
    assert batch.coverage[0].state.value == "partial"
    assert "safety limit" in batch.coverage[0].detail
    assert len(logs.filter_calls) == 1


def test_region_log_group_budget_is_visible_as_partial_coverage(monkeypatch) -> None:
    class ManyGroups(FakeLogs):
        def describe_log_groups(self, **request):
            self.describe_calls.append(request)
            if request["logGroupNamePrefix"].startswith("/aws/"):
                return {
                    "logGroups": [
                        {"logGroupName": "/aws/bedrock-agentcore/runtimes/first-default"}
                    ],
                    "nextToken": "more-groups",
                }
            return {"logGroups": []}

    monkeypatch.setattr(runtime_connector, "MAX_LOG_GROUPS", 1)
    logs = ManyGroups([_event(_span())])
    batch = AwsAgentRuntimeRegionConnector(
        account_id=ACCOUNT,
        region=REGION,
        partition="aws",
        logs_client=logs,
    ).collect(
        start_time=NOW - timedelta(minutes=30),
        end_time=NOW + timedelta(minutes=1),
        connection_id="11111111-1111-4111-8111-111111111111",
    )

    assert len(batch.activities) == 1
    assert batch.coverage[0].state.value == "partial"
    assert "log-group safety limit" in batch.coverage[0].detail
    assert len(logs.describe_calls) == 2


def test_missing_agentcore_observability_is_partial_not_zero_activity() -> None:
    class EmptyLogs(FakeLogs):
        def describe_log_groups(self, **request):
            return {"logGroups": []}

    batch = AwsAgentRuntimeRegionConnector(
        account_id=ACCOUNT,
        region=REGION,
        partition="aws",
        logs_client=EmptyLogs(),
    ).collect(
        start_time=NOW - timedelta(minutes=30),
        end_time=NOW,
        connection_id="11111111-1111-4111-8111-111111111111",
    )

    assert batch.activities == ()
    assert batch.coverage[0].state.value == "partial"
    assert "not zero activity" in batch.coverage[0].detail


def test_shared_span_group_requires_agentcore_anchor_but_keeps_anchored_children() -> None:
    class SharedLogs(FakeLogs):
        def describe_log_groups(self, **request):
            if request["logGroupNamePrefix"] == "aws/spans":
                return {"logGroups": [{"logGroupName": "aws/spans"}]}
            return {"logGroups": []}

    child = _span(
        spanId="5a300b0b3fe650e4",
        attributes={
            "gen_ai.operation.name": "chat",
            "gen_ai.request.model": "global.anthropic.claude-sonnet-4-6",
            "gen_ai.provider.name": "bedrock",
        },
    )
    unrelated = _span(
        traceId="7a01eef11066751d68f90def0da1f80a",
        spanId="6a300b0b3fe650e4",
        attributes={
            "gen_ai.operation.name": "chat",
            "gen_ai.request.model": "gpt-5",
            "gen_ai.provider.name": "openai",
        },
    )
    logs = SharedLogs(
        [
            _event(_span(), event_id="root"),
            _event(child, event_id="child"),
            _event(unrelated, event_id="unrelated"),
        ]
    )

    batch = AwsAgentRuntimeRegionConnector(
        account_id=ACCOUNT,
        region=REGION,
        partition="aws",
        logs_client=logs,
    ).collect(
        start_time=NOW - timedelta(minutes=30),
        end_time=NOW + timedelta(minutes=1),
        connection_id="11111111-1111-4111-8111-111111111111",
    )

    assert [activity.span_uid for activity in batch.activities] == [
        "3a300b0b3fe650e4",
        "5a300b0b3fe650e4",
    ]
    assert "logStreamNamePrefix" not in logs.filter_calls[0]


def test_aws_failures_are_sanitized_without_response_or_credentials() -> None:
    class SecretError(RuntimeError):
        response = {"Error": {"Code": "AccessDeniedException"}}

    class BrokenLogs(FakeLogs):
        def describe_log_groups(self, **request):
            raise SecretError("token=do-not-retain")

    batch = AwsAgentRuntimeRegionConnector(
        account_id=ACCOUNT,
        region=REGION,
        partition="aws",
        logs_client=BrokenLogs(),
    ).collect(
        start_time=NOW - timedelta(minutes=30),
        end_time=NOW,
        connection_id="11111111-1111-4111-8111-111111111111",
    )

    assert batch.coverage[0].state.value == "failed"
    assert batch.coverage[0].detail == "logs:DescribeLogGroups: AccessDeniedException"
    assert "do-not-retain" not in batch.coverage[0].detail


def test_collection_window_catches_up_with_overlap_and_exposes_24_hour_gap() -> None:
    recent_start, recent_capped = _collection_window(
        NOW,
        cursor=NOW - timedelta(hours=2),
        initial_lookback=timedelta(minutes=30),
    )
    assert recent_start == NOW - timedelta(hours=2, minutes=5)
    assert recent_capped is False

    capped_start, capped = _collection_window(
        NOW,
        cursor=NOW - timedelta(days=2),
        initial_lookback=timedelta(minutes=30),
    )
    assert capped_start == NOW - timedelta(hours=24)
    assert capped is True
