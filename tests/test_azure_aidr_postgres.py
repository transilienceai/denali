"""PostgreSQL contracts for Azure Foundry runtime evidence."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from denali.connections import AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY
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


def test_azure_runtime_scheduler_cursor_and_session_are_tenant_scoped(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC).replace(microsecond=0)
    connection_id = str(uuid.uuid4())
    subscription_id = str(uuid.uuid4())
    repo.create_connection(
        tenant,
        connection_id=connection_id,
        provider="azure",
        display_name=f"Azure runtime {connection_id}",
        credential_type="azure_service_principal_federated",
        credential_reference={
            "application_id": str(uuid.uuid4()),
            "directory_tenant_id": str(uuid.uuid4()),
        },
        declared_scopes=[AZURE_SCOPE_AGENT_RUNTIME_ACTIVITY],
        coverage_plan=[],
        configuration={
            "azure_tenant_id": str(uuid.uuid4()),
            "subscription_ids": [subscription_id],
            "cloud": "azure_public",
        },
    )
    assert repo.list_due_azure_agent_runtime_connections() == []
    repo.record_connection_validation(
        tenant,
        connection_id,
        {
            "started_at": now - timedelta(seconds=1),
            "completed_at": now,
            "health_state": "healthy",
            "credential_state": "passed",
            "account_id_observed": subscription_id,
            "results": [],
            "summary": "healthy",
        },
    )
    assert repo.list_due_azure_agent_runtime_connections() == [
        {"tenant_id": tenant, "connection_id": connection_id}
    ]

    job, created = repo.create_connection_collection_job(
        tenant, connection_id, collection_kind="azure_agent_runtime"
    )
    assert created is True
    assert repo.list_due_azure_agent_runtime_connections() == []
    assert repo.claim_connection_collection_job(str(job["id"]), lease_seconds=300) is not None
    repo.complete_connection_collection_job(
        str(job["id"]),
        {
            "state": "complete",
            "window_end": now.isoformat(),
            "cursor_advance_safe": True,
        },
    )
    assert repo.latest_azure_agent_runtime_cursor(tenant, connection_id) == now

    trace_id = "a" * 32
    span_id = "b" * 16
    project_id = (
        f"/subscriptions/{subscription_id}/resourcegroups/test/providers/"
        "microsoft.cognitiveservices/accounts/foundry/projects/anna"
    )
    agent = AssetRef(AssetKind.AI_AGENT, f"{project_id}/agents/agent-123")
    inserted = repo.ingest_activity(
        tenant,
        ActivityBatch(
            connector_id="denali.azure_agent_runtime",
            connection_id=connection_id,
            run_id="azure-runtime-1",
            scope_key=f"azure:{subscription_id}:eastus2:application-insights",
            collected_at=now + timedelta(minutes=1),
            coverage=(
                Coverage(
                    "azure_foundry_agent_runtime_activity",
                    CoverageState.COMPLETE,
                    f"azure:{subscription_id}:eastus2:application-insights",
                    "Server-side metadata allowlist; generative-AI content was not requested.",
                ),
            ),
            activities=(
                ActivityRecord(
                    source_uid=f"{trace_id}:{span_id}",
                    category=ActivityCategory.AGENT_INVOCATION,
                    activity_name="invoke_agent",
                    title="Invoke Anna",
                    occurred_at=now,
                    observed_at=now + timedelta(minutes=1),
                    completed_at=now + timedelta(milliseconds=50),
                    duration_ms=50,
                    outcome=ActivityOutcome.SUCCESS,
                    provider="azure_foundry",
                    account_uid=subscription_id,
                    region="eastus2",
                    session_uid="conversation-1",
                    trace_uid=trace_id,
                    span_uid=span_id,
                    parent_span_uid=None,
                    telemetry_convention="opentelemetry_genai",
                    content_policy="metadata_only",
                    entities=(
                        ActivityEntity(
                            role=ActivityEntityRole.AGENT,
                            external_uid="agent-123",
                            display_name="Anna",
                            asset=agent,
                            correlation=ActivityCorrelation.EXACT_IDENTIFIER,
                            confidence=1.0,
                        ),
                    ),
                    evidence=Evidence(
                        "azure_application_insights_span",
                        f"azure://application-insights/{subscription_id}/{trace_id}/{span_id}",
                        now + timedelta(minutes=1),
                        {"trace_id": trace_id, "span_id": span_id},
                    ),
                    attributes={"source_projection": "server_side_allowlist"},
                ),
            ),
        ),
    )
    assert inserted["activities"] == 1
    assert inserted["unresolved_entities"] == 1
    [unlinked] = repo.list_activity(tenant)
    assert unlinked["correlated_entity_count"] == 0
    repo.ingest(
        tenant,
        InventoryBatch(
            connector_id="denali.azure_foundry_inventory",
            connection_id=connection_id,
            run_id="azure-foundry-inventory-1",
            scope_key=f"azure:subscription:{subscription_id}:foundry-projects",
            collected_at=now + timedelta(minutes=2),
            coverage=(
                Coverage(
                    "azure_foundry_agent_inventory",
                    CoverageState.COMPLETE,
                    f"azure:subscription:{subscription_id}:foundry-projects",
                ),
            ),
            assets=(
                AssetAssertion(
                    asset=agent,
                    coverage_plane="azure_foundry_agent_inventory",
                    display_name="Anna",
                    assertion_type=AssertionType.OBSERVED,
                    confidence=1.0,
                    evidence=Evidence(
                        "azure_foundry_agent_configuration",
                        "azure://foundry/anna#agent=agent-123",
                        now + timedelta(minutes=2),
                    ),
                ),
            ),
        ),
    )
    [linked] = repo.list_activity(tenant)
    assert linked["correlated_entity_count"] == 1
    [session] = repo.list_runtime_sessions(tenant, provider="azure_foundry")
    assert session["provider"] == "azure_foundry"
    assert session["metadata_only"] is True
    detail = repo.get_runtime_session(tenant, session["session_key"])
    assert detail is not None
    assert detail["coverage"][0]["plane"] == "azure_foundry_agent_runtime_activity"
    assert repo.list_runtime_sessions(str(uuid.uuid4()), provider="azure_foundry") == []
