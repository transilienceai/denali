"""Privacy-safe AWS AgentCore runtime spans collected from Amazon CloudWatch.

AgentCore Observability delivers provider-native OTEL/OpenInference spans to CloudWatch
Logs.  This connector reads only span streams, retains an allowlisted metadata projection,
and deliberately drops prompt, response, retrieval-document, tool-argument, and tool-result
content.  Activity remains separate from inventory and security conclusions.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from denali.connections.aws import AWS_SCOPE_AGENT_RUNTIME_ACTIVITY
from denali.connectors.aws_deployments import _connection_regions
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

CONNECTOR_ID = "denali.aws_agent_runtime"
ACTIVITY_PLANE = "aws_agent_runtime_activity"
DEFAULT_LOOKBACK = timedelta(minutes=30)
COLLECTION_OVERLAP = timedelta(minutes=5)
MAX_CATCHUP = timedelta(hours=24)
MAX_LOG_GROUPS = 100
MAX_PAGES_PER_GROUP = 50
MAX_EVENTS_PER_REGION = 50_000
MAX_EVENT_BYTES_PER_REGION = 64 * 1024 * 1024
MAX_SAFE_ATTRIBUTES = 64
_AGENTCORE_PREFIX = "/aws/bedrock-agentcore/runtimes/"
_SHARED_SPAN_GROUP = "aws/spans"
_HEX_ID = re.compile(r"^[0-9a-fA-F]{8,64}$")
_AWS_ACCOUNT = re.compile(r"^[0-9]{12}$")

# This is an allowlist, not a denylist. Unknown attributes never cross the evidence boundary.
_SAFE_ATTRIBUTE_KEYS = frozenset(
    {
        "account.id",
        "aws.account.id",
        "aws.agent.id",
        "aws.endpoint.name",
        "aws.operation.name",
        "aws.region",
        "aws.request.id",
        "aws.request_id",
        "aws.resource.arn",
        "aws.resource.type",
        "aws.xray.origin",
        "cloud.account.id",
        "cloud.provider",
        "cloud.region",
        "cloud.resource_id",
        "enduser.id",
        "error.type",
        "error_type",
        "faas.id",
        "gateway.id",
        "gateway.name",
        "gen_ai.agent.id",
        "gen_ai.agent.name",
        "gen_ai.agent.version",
        "gen_ai.operation.name",
        "gen_ai.provider.name",
        "gen_ai.request.model",
        "gen_ai.response.id",
        "gen_ai.response.model",
        "gen_ai.system",
        "gen_ai.tool.call.id",
        "gen_ai.tool.id",
        "gen_ai.tool.name",
        "gen_ai.tool.type",
        "graph.node.id",
        "http.request.method",
        "http.response.status_code",
        "jsonrpc.error.code",
        "latency_ms",
        "llm.model_name",
        "llm.provider",
        "llm.system",
        "openinference.span.kind",
        "resource.id",
        "server.address",
        "service.name",
        "session.id",
        "session_id",
        "target.arn",
        "target.id",
        "target.type",
        "tool.id",
        "tool.name",
        "tool.type",
        "user.id",
    }
)
_SAFE_ATTRIBUTE_PREFIXES = ("gen_ai.usage.",)


class CloudWatchLogsClient(Protocol):
    def describe_log_groups(self, **kwargs: Any) -> dict[str, Any]: ...

    def filter_log_events(self, **kwargs: Any) -> dict[str, Any]: ...


class AwsAgentRuntimeCollectionError(RuntimeError):
    """A stable collection failure that does not expose an AWS response body."""


class AwsAgentRuntimeSpanNormalizer:
    """Normalize one CloudWatch span log event into bounded runtime activity."""

    def normalize(
        self,
        event: dict[str, Any],
        *,
        account_id: str,
        region: str,
        partition: str,
        log_group: str,
        observed_at: datetime,
    ) -> ActivityRecord | None:
        message = event.get("message")
        if not isinstance(message, str) or not message:
            return None
        try:
            span = json.loads(message)
        except json.JSONDecodeError:
            return None
        if not isinstance(span, dict):
            return None
        attributes = _attributes(span)
        category = _category(attributes)
        if category is None:
            return None

        trace_uid = _identifier(span.get("traceId") or span.get("trace_id"))
        span_uid = _identifier(span.get("spanId") or span.get("span_id"))
        parent_span_uid = _identifier(span.get("parentSpanId") or span.get("parent_span_id"))
        if trace_uid is None or span_uid is None:
            raise AwsAgentRuntimeCollectionError("runtime span has no valid trace/span identity")

        occurred_at = _span_time(span, event, "start")
        completed_at = _span_time(span, event, "end", required=False)
        if completed_at is not None and completed_at < occurred_at:
            completed_at = None
        duration_ms = _duration_ms(span, attributes, occurred_at, completed_at)
        session_uid = _bounded_text(
            attributes.get("session.id") or attributes.get("session_id"), 512
        )
        convention = _convention(attributes)
        operation = _operation(attributes)
        outcome = _outcome(span, attributes)
        safe_attributes = _safe_attributes(attributes)
        safe_attributes.update(
            {
                "span_kind": _bounded_text(span.get("kind"), 64),
                "scope_name": _scope_name(span),
                "scope_version": _scope_version(span),
                "content_fields_discarded": _contains_content(attributes, span),
            }
        )
        safe_attributes = {
            key: value for key, value in safe_attributes.items() if value is not None
        }

        entities = _entities(
            attributes,
            category=category,
            account_id=account_id,
            region=region,
            partition=partition,
        )
        source_event_id = _bounded_text(event.get("eventId"), 512)
        # A span may be mirrored between AgentCore's legacy and unified destinations.
        # Trace/span identity is the provider-stable deduplication boundary.
        source_uid = f"{trace_uid}:{span_uid}"
        projection_digest = hashlib.sha256(
            json.dumps(
                {
                    "trace_id": trace_uid,
                    "span_id": span_uid,
                    "parent_span_id": parent_span_uid,
                    "operation": operation,
                    "outcome": outcome.value,
                    "attributes": safe_attributes,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        locator = (
            f"aws://cloudwatch-logs/{region}/{log_group}"
            f"#event={source_event_id or projection_digest[:24]}"
        )
        return ActivityRecord(
            source_uid=source_uid,
            category=category,
            activity_name=f"aws.agentcore.{operation}",
            title=_title(category, operation, attributes),
            occurred_at=occurred_at,
            observed_at=observed_at,
            completed_at=completed_at,
            duration_ms=duration_ms,
            outcome=outcome,
            provider="aws_agentcore",
            account_uid=account_id,
            region=region,
            session_uid=session_uid,
            trace_uid=trace_uid,
            span_uid=span_uid,
            parent_span_uid=parent_span_uid,
            telemetry_convention=convention,
            content_policy="metadata_only",
            entities=entities,
            evidence=Evidence(
                source_type="aws_cloudwatch_agentcore_span",
                locator=locator,
                observed_at=observed_at,
                payload={
                    "metadata_projection_sha256": projection_digest,
                    "event_id": source_event_id,
                    "log_group": log_group,
                    "log_stream": _bounded_text(event.get("logStreamName"), 512),
                    "trace_id": trace_uid,
                    "span_id": span_uid,
                    "parent_span_id": parent_span_uid,
                    "operation": operation,
                    "telemetry_convention": convention,
                    "content_policy": "metadata_only",
                },
            ),
            attributes=safe_attributes,
        )


class AwsAgentRuntimeRegionConnector:
    """Collect bounded AgentCore span streams from one AWS account and Region."""

    def __init__(
        self,
        *,
        account_id: str,
        region: str,
        partition: str,
        logs_client: CloudWatchLogsClient,
        normalizer: AwsAgentRuntimeSpanNormalizer | None = None,
    ) -> None:
        if not _AWS_ACCOUNT.fullmatch(account_id):
            raise ValueError("AWS account id is invalid")
        self.account_id = account_id
        self.region = region
        self.partition = partition
        self.logs_client = logs_client
        self.normalizer = normalizer or AwsAgentRuntimeSpanNormalizer()

    def collect(
        self,
        *,
        start_time: datetime,
        end_time: datetime,
        connection_id: str,
    ) -> ActivityBatch:
        start = _aware(start_time)
        end = _aware(end_time)
        if start >= end:
            raise ValueError("runtime collection start must precede end")
        observed_at = datetime.now(UTC)
        scope = f"aws:{self.account_id}:{self.region}:agentcore:cloudwatch-spans"
        warnings: list[str] = []
        try:
            groups, discovery_warnings = self._log_groups()
            warnings.extend(discovery_warnings)
        except Exception as error:
            return self._failed(scope, observed_at, connection_id, "logs:DescribeLogGroups", error)

        if not groups:
            return ActivityBatch(
                connector_id=CONNECTOR_ID,
                connection_id=connection_id,
                run_id=f"aws-agent-runtime-{self.region}-{observed_at.isoformat()}",
                scope_key=scope,
                collected_at=observed_at,
                coverage=(
                    Coverage(
                        ACTIVITY_PLANE,
                        CoverageState.PARTIAL,
                        scope,
                        "No AgentCore span log group was discovered. AgentCore observability "
                        "or CloudWatch Transaction Search may not be enabled; this is not "
                        "zero activity.",
                    ),
                ),
            )

        activities: dict[str, ActivityRecord] = {}
        raw_events_seen = 0
        raw_bytes_seen = 0
        for group_index, group in enumerate(groups):
            try:
                events, event_bytes, group_warnings = self._events(
                    group,
                    start,
                    end,
                    max_events=MAX_EVENTS_PER_REGION - raw_events_seen,
                    max_bytes=MAX_EVENT_BYTES_PER_REGION - raw_bytes_seen,
                )
                raw_events_seen += len(events)
                raw_bytes_seen += event_bytes
                warnings.extend(group_warnings)
            except Exception as error:
                warnings.append(_safe_failure("logs:FilterLogEvents", error, group))
                continue
            group_activities: list[ActivityRecord] = []
            for event in events:
                try:
                    activity = self.normalizer.normalize(
                        event,
                        account_id=self.account_id,
                        region=self.region,
                        partition=self.partition,
                        log_group=group,
                        observed_at=observed_at,
                    )
                except AwsAgentRuntimeCollectionError as error:
                    warnings.append(str(error))
                    continue
                if activity is None:
                    continue
                group_activities.append(activity)
            if group == _SHARED_SPAN_GROUP:
                anchored_traces = {
                    item.trace_uid for item in group_activities if _is_agentcore_activity(item)
                }
                group_activities = [
                    item for item in group_activities if item.trace_uid in anchored_traces
                ]
            for activity in group_activities:
                if activity.source_uid in activities:
                    continue
                activities[activity.source_uid] = activity
                if len(activities) >= MAX_EVENTS_PER_REGION:
                    warnings.append(
                        f"runtime event safety limit reached at {MAX_EVENTS_PER_REGION}"
                    )
                    break
            if len(activities) >= MAX_EVENTS_PER_REGION:
                break
            if (
                raw_events_seen >= MAX_EVENTS_PER_REGION
                or raw_bytes_seen >= MAX_EVENT_BYTES_PER_REGION
            ):
                if group_index < len(groups) - 1 and not group_warnings:
                    warnings.append("regional runtime read safety limit reached")
                break

        failed_groups = sum(item.startswith("logs:FilterLogEvents") for item in warnings)
        state = (
            CoverageState.FAILED
            if failed_groups == len(groups)
            else CoverageState.PARTIAL
            if warnings
            else CoverageState.COMPLETE
        )
        detail = (
            "Metadata-only AgentCore span coverage; prompt/response content, retrieval documents, "
            "and tool arguments/results are intentionally excluded."
        )
        if warnings:
            detail += " " + "; ".join(dict.fromkeys(warnings))[:3_400]
        return ActivityBatch(
            connector_id=CONNECTOR_ID,
            connection_id=connection_id,
            run_id=f"aws-agent-runtime-{self.region}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=(Coverage(ACTIVITY_PLANE, state, scope, detail),),
            activities=tuple(
                sorted(
                    activities.values(),
                    key=lambda item: (item.occurred_at, item.trace_uid or "", item.span_uid or ""),
                )
            ),
        )

    def _log_groups(self) -> tuple[list[str], list[str]]:
        groups: set[str] = set()
        warnings: list[str] = []
        token: str | None = None
        seen: set[str] = set()
        while len(groups) < MAX_LOG_GROUPS:
            request: dict[str, Any] = {
                "logGroupNamePrefix": _AGENTCORE_PREFIX,
                "limit": 50,
            }
            if token:
                request["nextToken"] = token
            response = self.logs_client.describe_log_groups(**request)
            for item in response.get("logGroups", []):
                name = item.get("logGroupName") if isinstance(item, dict) else None
                if isinstance(name, str) and name.startswith(_AGENTCORE_PREFIX):
                    groups.add(name)
                    if len(groups) >= MAX_LOG_GROUPS:
                        break
            next_token = response.get("nextToken")
            if not next_token:
                break
            if len(groups) >= MAX_LOG_GROUPS:
                warnings.append(
                    f"AgentCore log-group safety limit reached at {MAX_LOG_GROUPS}"
                )
                break
            if not isinstance(next_token, str) or next_token in seen:
                raise AwsAgentRuntimeCollectionError("invalid/repeated log-group pagination token")
            seen.add(next_token)
            token = next_token

        # Older and non-unified AgentCore traces use the shared Transaction Search group.
        response = self.logs_client.describe_log_groups(
            logGroupNamePrefix=_SHARED_SPAN_GROUP,
            limit=2,
        )
        if any(
            isinstance(item, dict) and item.get("logGroupName") == _SHARED_SPAN_GROUP
            for item in response.get("logGroups", [])
        ):
            groups.add(_SHARED_SPAN_GROUP)
        if len(groups) > MAX_LOG_GROUPS:
            warnings.append(f"AgentCore log-group safety limit reached at {MAX_LOG_GROUPS}")
        return sorted(groups)[:MAX_LOG_GROUPS], warnings

    def _events(
        self,
        log_group: str,
        start_time: datetime,
        end_time: datetime,
        *,
        max_events: int,
        max_bytes: int,
    ) -> tuple[list[dict[str, Any]], int, list[str]]:
        if max_events < 1 or max_bytes < 1:
            return [], 0, [f"{log_group}: runtime read safety limit reached"]
        events: list[dict[str, Any]] = []
        event_bytes = 0
        warnings: list[str] = []
        token: str | None = None
        seen: set[str] = set()
        for _ in range(MAX_PAGES_PER_GROUP):
            request: dict[str, Any] = {
                "logGroupName": log_group,
                "startTime": int(start_time.timestamp() * 1000),
                "endTime": int(end_time.timestamp() * 1000),
                "limit": 10_000,
            }
            if log_group != _SHARED_SPAN_GROUP:
                request["logStreamNamePrefix"] = "spans"
            if token:
                request["nextToken"] = token
            response = self.logs_client.filter_log_events(**request)
            raw_events = response.get("events")
            if not isinstance(raw_events, list):
                raise AwsAgentRuntimeCollectionError("logs:FilterLogEvents returned invalid events")
            for item in raw_events:
                if not isinstance(item, dict):
                    continue
                message = item.get("message")
                size = len(message.encode("utf-8")) if isinstance(message, str) else 0
                if len(events) >= max_events or event_bytes + size > max_bytes:
                    warnings.append(f"{log_group}: runtime read safety limit reached")
                    return events, event_bytes, warnings
                events.append(item)
                event_bytes += size
            next_token = response.get("nextToken")
            if len(events) == max_events and next_token:
                warnings.append(
                    f"{log_group}: runtime event safety limit reached at {max_events}"
                )
                return events, event_bytes, warnings
            if not next_token:
                return events, event_bytes, warnings
            if not isinstance(next_token, str) or next_token in seen:
                warnings.append(f"{log_group}: invalid/repeated event pagination token")
                return events, event_bytes, warnings
            seen.add(next_token)
            token = next_token
        warnings.append(f"{log_group}: event page safety limit reached")
        return events, event_bytes, warnings

    def _failed(
        self,
        scope: str,
        observed_at: datetime,
        connection_id: str,
        operation: str,
        error: Exception,
    ) -> ActivityBatch:
        return ActivityBatch(
            connector_id=CONNECTOR_ID,
            connection_id=connection_id,
            run_id=f"aws-agent-runtime-{self.region}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=(
                Coverage(
                    ACTIVITY_PLANE,
                    CoverageState.FAILED,
                    scope,
                    _safe_failure(operation, error),
                ),
            ),
        )


class AwsConnectionAgentRuntimeCollector:
    """Assume one tenant connection role and ingest AgentCore spans across its Regions."""

    def __init__(
        self,
        session_factory: Any | None = None,
        *,
        now: Any | None = None,
        lookback: timedelta = DEFAULT_LOOKBACK,
    ) -> None:
        self._session_factory = session_factory or _boto3_session
        self._now = now or (lambda: datetime.now(UTC))
        self._lookback = lookback

    def collect(
        self,
        *,
        tenant_id: str,
        connection: dict[str, Any],
        repository: Any,
    ) -> dict[str, Any]:
        if connection.get("provider") != "aws":
            raise ValueError("connection is not an AWS connection")
        if connection.get("lifecycle_state") != "active":
            raise ValueError("disabled AWS connections cannot collect")
        if AWS_SCOPE_AGENT_RUNTIME_ACTIVITY not in connection.get("declared_scopes", []):
            raise ValueError("AWS AgentCore runtime activity scope is not declared")
        configuration = connection.get("configuration", {})
        account_id = str(configuration.get("account_id", ""))
        if not _AWS_ACCOUNT.fullmatch(account_id):
            raise ValueError("AWS account boundary is incomplete")

        session = self._assumed_session(connection, account_id)
        regions = _connection_regions(session, configuration)
        end_time = _aware(self._now())
        cursor = repository.latest_aws_agent_runtime_cursor(
            tenant_id, str(connection["id"])
        )
        start_time, catchup_capped = _collection_window(
            end_time,
            cursor=cursor,
            initial_lookback=self._lookback,
        )
        result: dict[str, Any] = {
            "state": "complete",
            "regions": len(regions),
            "activities": 0,
            "duplicates": 0,
            "linked_entities": 0,
            "unresolved_entities": 0,
            "partial_regions": 0,
            "failed_regions": 0,
            "window_start": start_time.isoformat(),
            "window_end": end_time.isoformat(),
            "content_policy": "metadata_only",
            "catchup_capped": catchup_capped,
            "cursor_advance_safe": False,
        }
        for region in regions:
            batch = AwsAgentRuntimeRegionConnector(
                account_id=account_id,
                region=region,
                partition=str(configuration.get("partition", "aws")),
                logs_client=session.client("logs", region_name=region),
            ).collect(
                start_time=start_time,
                end_time=end_time,
                connection_id=str(connection["id"]),
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
                            + " Historical catch-up was capped at 24 hours; the earlier gap "
                            "remains explicit.",
                        ),
                    ),
                )
            ingested = repository.ingest_activity(tenant_id, batch)
            for key in (
                "activities",
                "duplicates",
                "linked_entities",
                "unresolved_entities",
            ):
                result[key] += int(ingested.get(key, 0))
            if base_state is CoverageState.FAILED:
                result["failed_regions"] += 1
            elif base_state is not CoverageState.COMPLETE:
                result["partial_regions"] += 1
        if result["failed_regions"] == len(regions):
            result["state"] = "failed"
        elif result["failed_regions"] or result["partial_regions"]:
            result["state"] = "partial"
        else:
            result["cursor_advance_safe"] = True
            if catchup_capped:
                result["state"] = "partial"
        return result

    def _assumed_session(self, connection: dict[str, Any], account_id: str) -> Any:
        credential = connection["credential_reference"]
        base_session = self._session_factory()
        assumed = base_session.client("sts").assume_role(
            RoleArn=credential["role_arn"],
            RoleSessionName=f"denali-agent-runtime-{str(connection['id'])[:8]}",
            ExternalId=credential["external_id"],
            DurationSeconds=3600,
        )
        temporary = assumed["Credentials"]
        session = self._session_factory(
            aws_access_key_id=temporary["AccessKeyId"],
            aws_secret_access_key=temporary["SecretAccessKey"],
            aws_session_token=temporary["SessionToken"],
        )
        observed = str(session.client("sts").get_caller_identity().get("Account", ""))
        if observed != account_id:
            raise ValueError("AWS assumed role account did not match the connection boundary")
        return session


def _attributes(span: dict[str, Any]) -> dict[str, Any]:
    raw = span.get("attributes")
    if not isinstance(raw, dict):
        raw = {}
    output = dict(raw)
    resource = span.get("resource")
    if isinstance(resource, dict):
        resource_attributes = resource.get("attributes")
        if isinstance(resource_attributes, dict):
            for key, value in resource_attributes.items():
                output.setdefault(str(key), value)
    return output


def _category(attributes: dict[str, Any]) -> ActivityCategory | None:
    operation = _text(attributes.get("gen_ai.operation.name"))
    openinference = (_text(attributes.get("openinference.span.kind")) or "").upper()
    aws_operation = (_text(attributes.get("aws.operation.name")) or "").casefold()
    if operation == "execute_tool" or openinference == "TOOL" or "calltool" in aws_operation:
        return ActivityCategory.TOOL_INVOCATION
    if operation in {"chat", "text_completion", "generate_content"} or openinference == "LLM":
        return ActivityCategory.MODEL_INVOCATION
    if operation in {"invoke_agent", "create_agent"} or openinference in {"AGENT", "CHAIN"}:
        return ActivityCategory.AGENT_INVOCATION
    if operation in {"retrieve", "rerank"} or openinference in {"RETRIEVER", "RERANKER"}:
        return ActivityCategory.RETRIEVAL
    if aws_operation in {"invokeagentruntime", "invokeagent", "invokeinlineagent"}:
        return ActivityCategory.AGENT_INVOCATION
    if _text(attributes.get("tool.name") or attributes.get("gen_ai.tool.name")):
        return ActivityCategory.TOOL_INVOCATION
    return None


def _convention(attributes: dict[str, Any]) -> str:
    if attributes.get("openinference.span.kind"):
        return "openinference"
    if attributes.get("gen_ai.operation.name"):
        return "opentelemetry_genai"
    return "aws_agentcore"


def _operation(attributes: dict[str, Any]) -> str:
    value = _text(
        attributes.get("aws.operation.name")
        or attributes.get("gen_ai.operation.name")
        or attributes.get("openinference.span.kind")
    )
    return (value or "runtime_operation").replace(" ", "_")[:128]


def _outcome(span: dict[str, Any], attributes: dict[str, Any]) -> ActivityOutcome:
    status = span.get("status") if isinstance(span.get("status"), dict) else {}
    code = str(status.get("code", "")).upper()
    http_status = attributes.get("http.response.status_code")
    if (
        code in {"ERROR", "STATUS_CODE_ERROR", "2"}
        or attributes.get("error_type")
        or attributes.get("error.type")
    ):
        return ActivityOutcome.FAILURE
    if isinstance(http_status, int) and http_status >= 400:
        return ActivityOutcome.FAILURE
    if code in {"OK", "STATUS_CODE_OK", "1"}:
        return ActivityOutcome.SUCCESS
    return ActivityOutcome.UNKNOWN


def _entities(
    attributes: dict[str, Any],
    *,
    category: ActivityCategory,
    account_id: str,
    region: str,
    partition: str,
) -> tuple[ActivityEntity, ...]:
    output: list[ActivityEntity] = []
    actor = _bounded_text(attributes.get("enduser.id") or attributes.get("user.id"), 512)
    if actor:
        output.append(_unresolved(ActivityEntityRole.ACTOR, actor, actor))

    resource_arn = _bounded_text(attributes.get("aws.resource.arn"), 2_048)
    agent_id = _bounded_text(
        attributes.get("aws.agent.id") or attributes.get("gen_ai.agent.id"), 512
    )
    agent_name = _bounded_text(attributes.get("gen_ai.agent.name"), 512)
    agent_arn = (
        resource_arn
        if resource_arn and ":bedrock-agentcore:" in resource_arn and ":runtime/" in resource_arn
        else None
    )
    if agent_arn is None and agent_id:
        if agent_id.startswith("arn:"):
            agent_arn = agent_id
        else:
            agent_arn = (
                f"arn:{partition}:bedrock-agentcore:{region}:{account_id}:runtime/{agent_id}"
            )
    if agent_arn:
        output.append(
            _linked(
                ActivityEntityRole.AGENT,
                agent_id or agent_arn,
                agent_name or agent_id or agent_arn,
                AssetKind.AI_AGENT,
                agent_arn,
            )
        )

    model = _bounded_text(
        attributes.get("gen_ai.response.model")
        or attributes.get("gen_ai.request.model")
        or attributes.get("llm.model_name"),
        512,
    )
    if model:
        provider = (
            _bounded_text(
                attributes.get("gen_ai.provider.name")
                or attributes.get("gen_ai.system")
                or attributes.get("llm.provider")
                or attributes.get("llm.system"),
                128,
            )
            or ""
        ).casefold()
        natural_key = _model_key(provider, model)
        output.append(
            _linked(ActivityEntityRole.MODEL, model, model, AssetKind.AI_MODEL, natural_key)
            if natural_key
            else _unresolved(ActivityEntityRole.MODEL, model, model)
        )

    if category is ActivityCategory.TOOL_INVOCATION:
        tool_name = _bounded_text(
            attributes.get("gen_ai.tool.name") or attributes.get("tool.name"), 512
        )
        tool_id = _bounded_text(
            attributes.get("gen_ai.tool.id")
            or attributes.get("tool.id")
            or attributes.get("target.id"),
            512,
        )
        gateway_id = _bounded_text(attributes.get("gateway.id"), 512)
        gateway_arn = (
            resource_arn
            if resource_arn
            and ":bedrock-agentcore:" in resource_arn
            and ":gateway/" in resource_arn
            else None
        )
        if gateway_arn is None and gateway_id:
            gateway_arn = (
                f"arn:{partition}:bedrock-agentcore:{region}:{account_id}:gateway/{gateway_id}"
            )
        if gateway_arn and tool_id:
            output.append(
                _linked(
                    ActivityEntityRole.TOOL,
                    f"{gateway_id or gateway_arn}:{tool_id}",
                    tool_name or tool_id,
                    AssetKind.AI_TOOL,
                    f"{gateway_arn}#target/{tool_id}",
                )
            )
        elif tool_name:
            output.append(_unresolved(ActivityEntityRole.TOOL, tool_name, tool_name))

    target_arn = _bounded_text(
        attributes.get("target.arn")
        or attributes.get("cloud.resource_id")
        or attributes.get("faas.id"),
        2_048,
    )
    if target_arn and target_arn.startswith("arn:") and target_arn != agent_arn:
        output.append(
            _linked(
                ActivityEntityRole.RESOURCE,
                target_arn,
                target_arn,
                AssetKind.CLOUD_RESOURCE,
                target_arn,
            )
        )
    return tuple(output)


def _model_key(provider: str, model: str) -> str | None:
    lowered = provider.replace("_", ".")
    if "bedrock" in lowered or model.startswith(("global.", "us.", "eu.", "apac.")):
        return f"aws:bedrock:model:{model}"
    if provider in {"openai", "anthropic", "google_ai", "azure_openai"}:
        return f"{provider}:{model}"
    return None


def _linked(
    role: ActivityEntityRole,
    uid: str,
    name: str,
    kind: AssetKind,
    natural_key: str,
) -> ActivityEntity:
    return ActivityEntity(
        role=role,
        external_uid=uid,
        display_name=name,
        asset=AssetRef(kind, natural_key),
        correlation=ActivityCorrelation.EXACT_IDENTIFIER,
        confidence=1.0,
    )


def _unresolved(role: ActivityEntityRole, uid: str, name: str) -> ActivityEntity:
    return ActivityEntity(role=role, external_uid=uid, display_name=name)


def _safe_attributes(attributes: dict[str, Any]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in sorted(attributes.items(), key=lambda item: str(item[0])):
        key = str(key)
        if key not in _SAFE_ATTRIBUTE_KEYS and not key.startswith(_SAFE_ATTRIBUTE_PREFIXES):
            continue
        safe = _safe_value(value)
        if safe is not None:
            output[key] = safe
            if len(output) >= MAX_SAFE_ATTRIBUTES:
                break
    return output


def _safe_value(value: Any) -> str | int | float | bool | list[str | int | float | bool] | None:
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return value[:1_024]
    if isinstance(value, list) and len(value) <= 20:
        safe = [
            item
            for item in value
            if isinstance(item, bool | int | float | str)
            and not (isinstance(item, float) and not math.isfinite(item))
        ]
        return [item[:256] if isinstance(item, str) else item for item in safe]
    return None


def _contains_content(attributes: dict[str, Any], span: dict[str, Any]) -> bool:
    markers = (
        "input",
        "output",
        "prompt",
        "message",
        "content",
        "argument",
        "result",
        "document",
        "payload",
    )
    return "body" in span or any(
        any(marker in str(key).casefold() for marker in markers) for key in attributes
    )


def _is_agentcore_activity(activity: ActivityRecord) -> bool:
    attributes = activity.attributes
    resource_arn = attributes.get("aws.resource.arn")
    operation = str(attributes.get("aws.operation.name", "")).casefold()
    service = str(attributes.get("service.name", "")).casefold()
    return bool(
        attributes.get("aws.agent.id")
        or (isinstance(resource_arn, str) and ":bedrock-agentcore:" in resource_arn)
        or operation == "invokeagentruntime"
        or "agentcore" in service
    )


def _scope_name(span: dict[str, Any]) -> str | None:
    scope = span.get("scope")
    return _bounded_text(scope.get("name"), 256) if isinstance(scope, dict) else None


def _scope_version(span: dict[str, Any]) -> str | None:
    scope = span.get("scope")
    return _bounded_text(scope.get("version"), 128) if isinstance(scope, dict) else None


def _span_time(
    span: dict[str, Any], event: dict[str, Any], boundary: str, *, required: bool = True
) -> datetime | None:
    keys = (
        ("startTimeUnixNano", "start_time_unix_nano")
        if boundary == "start"
        else ("endTimeUnixNano", "end_time_unix_nano")
    )
    for key in keys:
        value = span.get(key)
        try:
            if value is not None:
                return datetime.fromtimestamp(int(value) / 1_000_000_000, tz=UTC)
        except (TypeError, ValueError, OverflowError):
            raise AwsAgentRuntimeCollectionError(
                f"runtime span has invalid {boundary} time"
            ) from None
    if not required:
        return None
    value = event.get("timestamp")
    try:
        return datetime.fromtimestamp(int(value) / 1000, tz=UTC)
    except (TypeError, ValueError, OverflowError):
        raise AwsAgentRuntimeCollectionError("runtime span has no valid start time") from None


def _duration_ms(
    span: dict[str, Any],
    attributes: dict[str, Any],
    started_at: datetime,
    completed_at: datetime | None,
) -> float | None:
    value = attributes.get("latency_ms")
    if (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and value >= 0
        and math.isfinite(value)
    ):
        return float(value)
    if completed_at is not None:
        duration = (completed_at - started_at).total_seconds() * 1000
        return duration if duration >= 0 and math.isfinite(duration) else None
    value = span.get("durationNano") or span.get("duration_nano")
    if value is not None:
        try:
            duration = int(value) / 1_000_000
        except (TypeError, ValueError):
            return None
        return duration if duration >= 0 else None
    return None


def _title(category: ActivityCategory, operation: str, attributes: dict[str, Any]) -> str:
    if category is ActivityCategory.TOOL_INVOCATION:
        name = _bounded_text(attributes.get("gen_ai.tool.name") or attributes.get("tool.name"), 256)
        return f"Tool {name or operation} invoked"
    if category is ActivityCategory.MODEL_INVOCATION:
        model = _bounded_text(
            attributes.get("gen_ai.response.model")
            or attributes.get("gen_ai.request.model")
            or attributes.get("llm.model_name"),
            256,
        )
        return f"Model {model or operation} invoked"
    if category is ActivityCategory.RETRIEVAL:
        return "Agent retrieval executed"
    return "Agent runtime invoked"


def _identifier(value: Any) -> str | None:
    text = _text(value)
    return text.lower() if text and _HEX_ID.fullmatch(text) else None


def _bounded_text(value: Any, limit: int) -> str | None:
    text = _text(value)
    return text[:limit] if text else None


def _text(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


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


def _safe_failure(operation: str, error: Exception, resource: str | None = None) -> str:
    response = getattr(error, "response", None)
    code = None
    if isinstance(response, dict) and isinstance(response.get("Error"), dict):
        candidate = response["Error"].get("Code")
        code = candidate if isinstance(candidate, str) and candidate else None
    suffix = f" for {resource}" if resource else ""
    return f"{operation}{suffix}: {code or error.__class__.__name__}"


def _boto3_session(**kwargs: Any) -> Any:
    import boto3

    return boto3.Session(**kwargs)
