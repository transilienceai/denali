"""PostgreSQL contracts for AWS AgentCore detection and response evidence."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

import denali.store.repository as repository_module
from denali.connections import AWS_SCOPE_AGENT_RUNTIME_ACTIVITY
from denali.detections import (
    AWS_RISKY_SEQUENCE_RULE_UID,
    AWS_UNAPPROVED_TOOL_RULE_UID,
    AWS_UNDECLARED_MODEL_RULE_UID,
)
from denali.domain import (
    ActivityBatch,
    ActivityCategory,
    ActivityCorrelation,
    ActivityEntity,
    ActivityEntityRole,
    ActivityOutcome,
    ActivityRecord,
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    Coverage,
    CoverageState,
    Evidence,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


@pytest.fixture
def repository():
    assert DSN
    migrate(DSN)
    return str(uuid.uuid4()), PostgresInventoryRepository(DSN)


def _exact(role: ActivityEntityRole, asset: AssetRef) -> ActivityEntity:
    return ActivityEntity(
        role=role,
        external_uid=asset.natural_key,
        display_name=asset.natural_key.rsplit("/", 1)[-1],
        asset=asset,
        correlation=ActivityCorrelation.EXACT_IDENTIFIER,
        confidence=1.0,
    )


def test_agentcore_sessions_detections_and_response_are_tenant_scoped(
    repository, monkeypatch
) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    connection_id = str(uuid.uuid4())
    agent = AssetRef(
        AssetKind.AI_AGENT,
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/sales",
    )
    model = AssetRef(
        AssetKind.AI_MODEL,
        "aws:bedrock:model:global.anthropic.claude-sonnet-4-6",
    )
    tool = AssetRef(
        AssetKind.AI_TOOL,
        "arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw#target/slack",
    )
    inventory_evidence = Evidence("aws_control_plane", "aws://agentcore/inventory", now)
    repo.ingest(
        tenant,
        InventoryBatch(
            connector_id="denali.aws_agentcore",
            connection_id=connection_id,
            run_id="inventory-1",
            scope_key="aws:123456789012:us-east-1",
            collected_at=now,
            coverage=(
                Coverage(
                    "aws_agentcore_runtime_inventory",
                    CoverageState.COMPLETE,
                    "aws:123456789012:us-east-1",
                ),
                Coverage(
                    "aws_agentcore_gateway_target_inventory",
                    CoverageState.COMPLETE,
                    "aws:123456789012:us-east-1",
                ),
            ),
            assets=tuple(
                AssetAssertion(
                    asset=asset,
                    coverage_plane=plane,
                    display_name=name,
                    assertion_type=AssertionType.OBSERVED,
                    confidence=1.0,
                    evidence=inventory_evidence,
                )
                for asset, plane, name in (
                    (agent, "aws_agentcore_runtime_inventory", "Sales agent"),
                    (model, "aws_agentcore_runtime_inventory", "Claude Sonnet 4.6"),
                    (tool, "aws_agentcore_gateway_target_inventory", "send_message"),
                )
            ),
        ),
    )

    trace_id = "a" * 32
    session_id = "agent-session-1"

    def event(
        source_uid: str,
        category: ActivityCategory,
        seconds: int,
        entities: tuple[ActivityEntity, ...],
        *,
        attributes: dict | None = None,
        parent_span_uid: str | None = None,
        outcome: ActivityOutcome = ActivityOutcome.SUCCESS,
        session_uid_override: str | None = None,
    ) -> ActivityRecord:
        occurred_at = now + timedelta(seconds=seconds)
        observed_at = now + timedelta(minutes=1)
        return ActivityRecord(
            source_uid=source_uid,
            category=category,
            activity_name=f"aws.agentcore.{category.value}",
            title=category.value,
            occurred_at=occurred_at,
            observed_at=observed_at,
            completed_at=occurred_at + timedelta(milliseconds=25),
            duration_ms=25,
            outcome=outcome,
            provider="aws_agentcore",
            account_uid="123456789012",
            region="us-east-1",
            session_uid=session_uid_override or session_id,
            trace_uid=trace_id,
            span_uid=source_uid,
            parent_span_uid=parent_span_uid,
            telemetry_convention="opentelemetry_genai",
            content_policy="metadata_only",
            entities=entities,
            evidence=Evidence(
                "aws_cloudwatch_agentcore_span",
                f"aws://cloudwatch/{source_uid}",
                observed_at,
                {"trace_id": trace_id, "span_id": source_uid},
            ),
            attributes=attributes or {},
        )

    batch = ActivityBatch(
        connector_id="denali.aws_agent_runtime",
        connection_id=connection_id,
        run_id="runtime-1",
        scope_key="aws:123456789012:us-east-1:agentcore:cloudwatch-spans",
        collected_at=now + timedelta(minutes=1),
        coverage=(
            Coverage(
                "aws_agent_runtime_activity",
                CoverageState.COMPLETE,
                "aws:123456789012:us-east-1:agentcore:cloudwatch-spans",
            ),
        ),
        activities=(
            event(
                "1" * 16,
                ActivityCategory.AGENT_INVOCATION,
                0,
                (_exact(ActivityEntityRole.AGENT, agent),),
            ),
            event(
                "2" * 16,
                ActivityCategory.MODEL_INVOCATION,
                1,
                (_exact(ActivityEntityRole.MODEL, model),),
                parent_span_uid="1" * 16,
            ),
            event("3" * 16, ActivityCategory.RETRIEVAL, 2, (), parent_span_uid="1" * 16),
            event(
                "4" * 16,
                ActivityCategory.TOOL_INVOCATION,
                3,
                (_exact(ActivityEntityRole.TOOL, tool),),
                attributes={"gen_ai.tool.name": "send_message"},
                parent_span_uid="1" * 16,
            ),
        ),
    )
    inserted = repo.ingest_activity(tenant, batch)
    assert inserted == {
        "activities": 4,
        "duplicates": 0,
        "linked_entities": 3,
        "unresolved_entities": 0,
    }
    assert repo.ingest_activity(tenant, batch)["duplicates"] == 4

    [summary] = repo.list_runtime_sessions(tenant, provider="aws_agentcore")
    assert summary["activity_count"] == 4
    assert summary["tool_invocation_count"] == 1
    assert summary["metadata_only"] is True
    detail = repo.get_runtime_session(tenant, summary["session_key"])
    assert detail is not None
    assert [item["span_uid"] for item in detail["activities"]] == [
        "1" * 16,
        "2" * 16,
        "3" * 16,
        "4" * 16,
    ]
    assert all(item["content_policy"] == "metadata_only" for item in detail["activities"])

    unknown_batch = ActivityBatch(
        connector_id="denali.aws_agent_runtime",
        connection_id=connection_id,
        run_id="runtime-unknown",
        scope_key="aws:123456789012:us-east-1:agentcore:cloudwatch-spans",
        collected_at=now + timedelta(minutes=2),
        coverage=batch.coverage,
        activities=(
            event(
                "5" * 16,
                ActivityCategory.AGENT_INVOCATION,
                30,
                (_exact(ActivityEntityRole.AGENT, agent),),
                outcome=ActivityOutcome.UNKNOWN,
                session_uid_override="agent-session-unknown",
            ),
        ),
    )
    repo.ingest_activity(tenant, unknown_batch)
    [unknown_summary] = repo.list_runtime_sessions(tenant, outcome="unknown")
    assert unknown_summary["outcome"] == "unknown"

    evaluation = repo.evaluate_runtime_detections(tenant)
    assert evaluation["confirmed_detections"] >= 3
    detections = repo.list_runtime_detections(tenant)
    rules = {item["rule_uid"] for item in detections}
    assert {
        AWS_UNDECLARED_MODEL_RULE_UID,
        AWS_UNAPPROVED_TOOL_RULE_UID,
        AWS_RISKY_SEQUENCE_RULE_UID,
    } <= rules

    drift = next(item for item in detections if item["rule_uid"] == AWS_UNDECLARED_MODEL_RULE_UID)
    drift_detail = repo.get_runtime_detection(tenant, str(drift["id"]))
    assert drift_detail is not None
    target_id = next(
        str(item["id"]) for item in drift_detail["assets"] if item["role"] == "executing_agent"
    )
    response = repo.create_runtime_response_request(
        tenant,
        str(drift["id"]),
        action_type="disable_agent_runtime",
        target_asset_id=target_id,
        justification="Contain after reviewing the exact linked session.",
        requested_by="user-requester",
    )
    assert response is not None and response["state"] == "awaiting_approval"
    assert (
        repo.create_runtime_response_request(
            tenant,
            str(drift["id"]),
            action_type="disable_agent_runtime",
            target_asset_id=None,
            justification="Missing exact target.",
            requested_by="user-requester",
        )
        is None
    )
    assert (
        repo.create_runtime_response_request(
            tenant,
            str(drift["id"]),
            action_type="block_model",
            target_asset_id=target_id,
            justification="Wrong exact target type.",
            requested_by="user-requester",
        )
        is None
    )
    assert (
        repo.review_runtime_response_request(
            tenant,
            str(drift["id"]),
            str(response["id"]),
            decision="approved",
            review_note="Evidence confirmed.",
            reviewed_by="user-requester",
        )
        is None
    )
    approved = repo.review_runtime_response_request(
        tenant,
        str(drift["id"]),
        str(response["id"]),
        decision="approved",
        review_note="Evidence confirmed.",
        reviewed_by="user-reviewer",
    )
    assert approved is not None
    assert approved["state"] == "approved"
    assert approved["execution_mode"] == "manual"

    other_tenant = str(uuid.uuid4())
    assert repo.get_runtime_session(other_tenant, summary["session_key"]) is None
    assert repo.get_runtime_detection(other_tenant, str(drift["id"])) is None

    monkeypatch.setattr(repository_module, "_MAX_DETECTION_ACTIVITIES", 1)
    monkeypatch.setattr(repository_module, "_MAX_DETECTION_ASSETS", 1)
    bounded = repo.evaluate_runtime_detections(tenant)
    aws_states = {
        item["rule_uid"]: item["state"]
        for item in bounded["evaluations"]
        if item["rule_uid"].startswith("DENALI-RUNTIME-AWS-")
    }
    assert aws_states
    assert set(aws_states.values()) == {"partial"}


def test_runtime_scheduler_only_selects_healthy_opted_in_connections(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    connection_id = str(uuid.uuid4())
    repo.create_connection(
        tenant,
        connection_id=connection_id,
        provider="aws",
        display_name=f"AWS runtime {connection_id}",
        credential_type="aws_assume_role",
        credential_reference={
            "role_arn": "arn:aws:iam::123456789012:role/Denali",
            "external_id": "fixture",
        },
        declared_scopes=[AWS_SCOPE_AGENT_RUNTIME_ACTIVITY],
        coverage_plan=[],
        configuration={"account_id": "123456789012", "regions": ["us-east-1"]},
    )
    assert repo.list_due_aws_agent_runtime_connections() == []
    repo.record_connection_validation(
        tenant,
        connection_id,
        {
            "started_at": now - timedelta(seconds=1),
            "completed_at": now,
            "health_state": "healthy",
            "credential_state": "passed",
            "account_id_observed": "123456789012",
            "results": [],
            "summary": "healthy",
        },
    )
    assert repo.list_due_aws_agent_runtime_connections() == [
        {"tenant_id": tenant, "connection_id": connection_id}
    ]
    job, created = repo.create_connection_collection_job(
        tenant, connection_id, collection_kind="aws_agent_runtime"
    )
    assert created is True
    assert str(job["connection_id"]) == connection_id
    assert repo.list_due_aws_agent_runtime_connections() == []
    claimed = repo.claim_connection_collection_job(str(job["id"]), lease_seconds=300)
    assert claimed is not None
    window_end = now.replace(microsecond=0)
    repo.complete_connection_collection_job(
        str(job["id"]),
        {
            "state": "complete",
            "window_end": window_end.isoformat(),
            "cursor_advance_safe": True,
        },
    )
    assert repo.latest_aws_agent_runtime_cursor(tenant, connection_id) == window_end


def test_exact_successful_runtime_evidence_promotes_declared_tool_action(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    evidence = Evidence("fixture", "fixture://code-to-cloud", now)
    repository_asset = AssetRef(AssetKind.CODE_REPOSITORY, "github.com/example/agent")
    workload = AssetRef(
        AssetKind.AI_WORKLOAD,
        "arn:aws:lambda:us-east-1:123456789012:function:agent",
    )
    agent = AssetRef(AssetKind.AI_AGENT, "source:github.com/example/agent:agent")
    tool = AssetRef(AssetKind.AI_TOOL, "source:github.com/example/agent:tool:slack")
    target = AssetRef(
        AssetKind.CLOUD_RESOURCE,
        "arn:aws:s3:::customer-proposals",
    )
    assets = (
        AssetAssertion(
            asset=repository_asset,
            coverage_plane="code_to_cloud_inventory",
            display_name="example/agent",
            assertion_type=AssertionType.DECLARED,
            confidence=1.0,
            evidence=evidence,
        ),
        AssetAssertion(
            asset=workload,
            coverage_plane="code_to_cloud_inventory",
            display_name="agent",
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=evidence,
            attributes={
                "service": "lambda",
                "deployment_identifiers": {"function_name": ["agent"]},
            },
        ),
        AssetAssertion(
            asset=agent,
            coverage_plane="code_to_cloud_inventory",
            display_name="Agent",
            assertion_type=AssertionType.DECLARED,
            confidence=1.0,
            evidence=evidence,
        ),
        AssetAssertion(
            asset=tool,
            coverage_plane="code_to_cloud_inventory",
            display_name="Post Slack message",
            assertion_type=AssertionType.DECLARED,
            confidence=1.0,
            evidence=evidence,
            attributes={"provider": "slack", "operation": "chat.postMessage"},
        ),
        AssetAssertion(
            asset=target,
            coverage_plane="code_to_cloud_inventory",
            display_name="Proposal bucket",
            assertion_type=AssertionType.DECLARED,
            confidence=1.0,
            evidence=evidence,
        ),
    )
    relationships = tuple(
        RelationshipAssertion(
            source=source,
            target=destination,
            coverage_plane="code_to_cloud_relationships",
            kind=kind,
            assertion_type=AssertionType.DECLARED,
            confidence=1.0,
            evidence=evidence,
            attributes=attributes,
        )
        for source, destination, kind, attributes in (
            (workload, repository_asset, RelationshipKind.DEPLOYED_BY, {}),
            (agent, repository_asset, RelationshipKind.DEFINED_IN, {}),
            (agent, tool, RelationshipKind.CAN_INVOKE, {}),
            (tool, target, RelationshipKind.CAN_WRITE, {"operation": "s3:PutObject"}),
        )
    )
    repo.ingest(
        tenant,
        InventoryBatch(
            connector_id="denali.code_to_cloud",
            connection_id="source-fixture",
            run_id="code-1",
            scope_key=repository_asset.natural_key,
            collected_at=now,
            coverage=(
                Coverage(
                    "code_to_cloud_inventory",
                    CoverageState.COMPLETE,
                    repository_asset.natural_key,
                ),
                Coverage(
                    "code_to_cloud_relationships",
                    CoverageState.COMPLETE,
                    repository_asset.natural_key,
                ),
            ),
            assets=assets,
            relationships=relationships,
        ),
    )

    [before] = repo.code_to_cloud_deployments(tenant)
    assert before["tools"][0]["execution_status"] == "not_observed"
    assert before["tools"][0]["actions"][0]["execution_status"] == "not_observed"

    repo.ingest_activity(
        tenant,
        ActivityBatch(
            connector_id="denali.aws_agent_runtime",
            connection_id="aws-fixture",
            run_id="runtime-1",
            scope_key="aws:123456789012:us-east-1",
            collected_at=now,
            coverage=(
                Coverage(
                    "aws_agent_runtime_activity",
                    CoverageState.COMPLETE,
                    "aws:123456789012:us-east-1",
                ),
            ),
            activities=(
                ActivityRecord(
                    source_uid="b" * 32,
                    category=ActivityCategory.TOOL_INVOCATION,
                    activity_name="aws.agentcore.execute_tool",
                    title="Post Slack message",
                    occurred_at=now,
                    observed_at=now,
                    outcome=ActivityOutcome.SUCCESS,
                    provider="aws_agentcore",
                    session_uid="session-observed",
                    trace_uid="c" * 32,
                    span_uid="d" * 16,
                    telemetry_convention="opentelemetry_genai",
                    entities=(
                        _exact(ActivityEntityRole.TOOL, tool),
                        _exact(ActivityEntityRole.RESOURCE, target),
                    ),
                    evidence=Evidence(
                        "aws_cloudwatch_agentcore_span",
                        "aws://cloudwatch/observed-tool",
                        now,
                    ),
                ),
            ),
        ),
    )

    [after] = repo.code_to_cloud_deployments(tenant)
    assert after["tools"][0]["execution_status"] == "observed"
    assert after["tools"][0]["actions"][0]["execution_status"] == "observed"
