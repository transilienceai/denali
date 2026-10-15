"""Exact shared AWS references retain identity internally and preserve tenant reads."""

import os
from uuid import uuid4

import pytest
from test_aws_selected_resource import READER
from test_shared_aws_selected_resource import shared_target

from denali.connections.aws_selected_resource import connection_selection, selected_coverage_plan
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


def test_selected_shared_reference_projects_no_lease_or_internal_role_and_is_tenant_scoped():
    assert DSN
    migrate(DSN)
    repo = PostgresInventoryRepository(DSN)
    marker = uuid4().hex
    org = f"org_SharedResource{marker}"
    tenant, other = repo.resolve_tenant(org), repo.resolve_tenant(f"org_OtherResource{marker}")
    target = shared_target()
    local_id = str(uuid4())
    target.update(id=local_id, clerk_organization_id=org)
    target["credential_reference"]["platform_connection_id"] = local_id
    selection = connection_selection(target)
    row = repo.create_connection(
        tenant,
        connection_id=local_id,
        provider="aws",
        display_name=f"exact-{marker}",
        credential_type="platform_shared_aws",
        credential_reference=target["credential_reference"],
        configuration=target["configuration"],
        declared_scopes=["aws.code_to_cloud"],
        coverage_plan=selected_coverage_plan(selection),
    )
    assert row["credential_reference"] == {
        "type": "platform_shared_aws",
        "platform_connection_id": local_id,
    }
    internal = repo.get_connection_validation_target(tenant, local_id)
    assert internal["credential_reference"]["role_arn"] == READER
    assert internal["clerk_organization_id"] == org
    assert connection_selection(internal) == selection
    assert repo.get_connection(other, local_id) is None
    assert repo.get_connection_validation_target(other, local_id) is None
    assert not any(key in str(row) for key in ("external_id", "secret_access_key", "session_token"))
