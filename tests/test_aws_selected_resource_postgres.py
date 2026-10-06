"""Real PostgreSQL persistence/isolation; all provider responses remain local fixtures."""

import os
from uuid import UUID, uuid4

import pytest
from test_aws_selected_resource import PRIVATE, Session, collector, target

from denali.connections.aws_selected_resource import connection_selection, selected_coverage_plan
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="disposable PostgreSQL required")


def test_selected_plan_durable_job_and_evidence_are_tenant_scoped():
    assert DSN
    migrate(DSN)
    repo = PostgresInventoryRepository(DSN)
    marker = uuid4().hex
    tenant = repo.resolve_tenant(f"org_ExactLambda{marker}")
    other = repo.resolve_tenant(f"org_ExactLambdaOther{marker}")
    planned = target()
    planned["id"] = str(uuid4())
    selection = connection_selection(planned)
    assert selection is not None
    repo.create_connection(
        tenant,
        connection_id=planned["id"],
        provider="aws",
        display_name=f"Exact Lambda {marker}",
        credential_type=planned["credential_type"],
        credential_reference=planned["credential_reference"],
        declared_scopes=planned["declared_scopes"],
        configuration=planned["configuration"],
        coverage_plan=selected_coverage_plan(selection),
    )
    assert repo.get_connection_validation_target(other, planned["id"]) is None
    job, new = repo.create_connection_collection_job(
        tenant,
        planned["id"],
        collection_kind="aws_deployments",
    )
    repeated, repeat_new = repo.create_connection_collection_job(
        tenant,
        planned["id"],
        collection_kind="aws_deployments",
    )
    assert new and not repeat_new and repeated["id"] == job["id"]
    restarted = PostgresInventoryRepository(DSN)
    claimed = restarted.claim_connection_collection_job(str(job["id"]), lease_seconds=60)
    assert claimed["tenant_id"] == UUID(tenant)
    stored = restarted.get_connection_validation_target(tenant, planned["id"])
    assert connection_selection(stored) == selection
    result = collector(Session()).collect(tenant_id=tenant, connection=stored, repository=restarted)
    restarted.complete_connection_collection_job(str(job["id"]), result)
    status = repo.connection_collection_status(
        tenant,
        planned["id"],
        collection_kind="aws_deployments",
    )
    assert status["last_result"]["resource_coverage_state"] == "complete"
    assert status["last_result"]["state"] == "partial"
    assets, findings = repo.list_assets(tenant), repo.list_findings(tenant)
    assert assets and findings
    assert repo.list_assets(other) == [] and repo.list_findings(other) == []
    assert PRIVATE not in str(assets) + str(findings) + str(status)
