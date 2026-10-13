"""Microsoft reference persistence and durable jobs on the isolated dev schema."""

from __future__ import annotations

import uuid

import psycopg
import pytest
from test_inventory_postgres import DSN

from denali.api.collection import run_durable_collection_job
from denali.connections import ENTRA_SCOPES, azure_coverage_plan, entra_coverage_plan
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


@pytest.fixture
def microsoft_repository():
    assert DSN
    migrate(DSN)
    return str(uuid.uuid4()), PostgresInventoryRepository(DSN)


@pytest.mark.parametrize(
    "provider,collection_kind", [("azure", "azure_deployments"), ("entra", "entra_ai")]
)
def test_shared_microsoft_reference_jobs_survive_restart_and_reject_foreign_tenant(
    microsoft_repository, provider, collection_kind
):
    from denali.integrations.shared_microsoft import SHARED_AZURE_SCOPES

    _, repo = microsoft_repository
    marker = uuid.uuid4().hex
    org = f"org_SharedMicrosoft{marker}"
    tenant = repo.resolve_tenant(org)
    other = repo.resolve_tenant(f"org_SharedMicrosoftOther{marker}")
    connection_id = str(uuid.uuid4())
    microsoft_tenant = str(uuid.uuid4())
    scopes = list(SHARED_AZURE_SCOPES if provider == "azure" else ENTRA_SCOPES)
    subscriptions = [{"id": str(uuid.uuid4()), "name": "Selected subscription"}]
    coverage = (
        azure_coverage_plan(scopes, subscriptions)
        if provider == "azure"
        else entra_coverage_plan(scopes, microsoft_tenant)
    )
    configuration = {
        "tenant_id": microsoft_tenant,
        "coverage_mode": "selected-subscriptions"
        if provider == "azure"
        else "tenant-wide-admin-consent",
    }
    if provider == "azure":
        configuration["subscriptions"] = subscriptions
    created = repo.create_connection(
        tenant,
        connection_id=connection_id,
        provider=provider,
        display_name=f"Shared {provider} contract",
        credential_type=f"platform_shared_{provider}",
        credential_reference={"platform_connection_id": connection_id},
        declared_scopes=scopes,
        coverage_plan=coverage,
        configuration=configuration,
    )
    assert created["credential_reference"] == {
        "type": f"platform_shared_{provider}",
        "platform_connection_id": connection_id,
    }
    target = repo.get_connection_validation_target(tenant, connection_id)
    assert target["clerk_organization_id"] == org
    assert target["credential_reference"] == {"platform_connection_id": connection_id}
    assert repo.get_connection(other, connection_id) is None
    assert repo.get_connection_validation_target(other, connection_id) is None
    assert repo.disable_connection(other, connection_id) is None
    validation, new = repo.create_connection_validation_job(
        tenant, connection_id, wait_for_credentials=False, wait_for_healthy=False
    )
    repeated_validation, repeated_new = repo.create_connection_validation_job(
        tenant, connection_id, wait_for_credentials=False, wait_for_healthy=False
    )
    assert new and not repeated_new and repeated_validation["id"] == validation["id"]
    repo.fail_connection_validation_job(str(validation["id"]), "Offline test terminal state.")
    job, new = repo.create_connection_collection_job(
        tenant, connection_id, collection_kind=collection_kind
    )
    duplicate, duplicate_new = repo.create_connection_collection_job(
        tenant, connection_id, collection_kind=collection_kind
    )
    assert new and not duplicate_new and job["id"] == duplicate["id"]
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        repo.create_connection_collection_job(other, connection_id, collection_kind=collection_kind)
    assert repo.connection_collection_status(
        other, connection_id, collection_kind=collection_kind
    ) == {
        "state": "idle",
        "last_result": None,
    }
    restarted = PostgresInventoryRepository(DSN)
    claimed = restarted.claim_connection_collection_job(str(job["id"]), lease_seconds=60)
    assert claimed["tenant_id"] == uuid.UUID(tenant)
    assert claimed["collection_kind"] == collection_kind
    restarted.complete_connection_collection_job(str(job["id"]), {"state": "complete"})
    retained = repo.connection_collection_status(
        tenant, connection_id, collection_kind=collection_kind
    )["last_result"]
    assert retained["state"] == "complete" and retained["completed_at"]
    repo.disable_connection(tenant, connection_id)
    # The older dev queue is retained; execution independently rejects disabled targets.
    blocked_job, new = repo.create_connection_collection_job(
        tenant, connection_id, collection_kind=collection_kind
    )
    assert new

    class Collector:
        called = False

        def collect(self, **kwargs):
            self.called = True
            return {"state": "complete"}

    collector = Collector()
    run_durable_collection_job(
        restarted, {collection_kind: collector}, str(blocked_job["id"]), max_attempts=1
    )
    assert collector.called is False
    terminal = repo.connection_collection_status(
        tenant, connection_id, collection_kind=collection_kind
    )["last_result"]
    assert terminal["state"] == "failed"


@pytest.mark.parametrize("provider", ["azure", "entra"])
def test_shared_microsoft_attachment_allows_durable_browser_jobs(
    microsoft_repository, provider, monkeypatch
):
    from fastapi.testclient import TestClient
    from test_shared_microsoft_api import AUTH, MEMBER, Authenticator, Broker, payload

    from denali.api.app import create_app

    monkeypatch.setenv(f"DENALI_PLATFORM_{provider.upper()}_ENABLED", "true")
    _, repo = microsoft_repository
    broker = Broker(provider)
    connection_id = str(uuid.uuid4())
    broker.listing[0]["id"] = connection_id
    broker.listing[0]["display_name"] = f"Shared Microsoft {connection_id[:8]}"
    dispatched = []
    application = create_app(
        repository=repo,
        auth_mode="clerk",
        authenticator=Authenticator(),
        shared_connections_client=broker,
        migrate_on_start=False,
        validation_dispatcher=lambda job: dispatched.append(("validation", job)),
        collection_dispatcher=lambda job: dispatched.append(("collection", job)),
    )
    kind = "azure_deployments" if provider == "azure" else "entra_ai"
    collect_suffix = "azure/collect-deployments" if provider == "azure" else "entra/collect"
    collect_path = f"/v1/connections/{connection_id}/{collect_suffix}"
    with TestClient(application) as test:
        attached = test.post(
            f"/v1/shared/connections/{provider}/{connection_id}/use-in-denali",
            headers=AUTH,
            json={"declared_scopes": payload(provider)["declared_scopes"]},
        )
        assert attached.status_code == 201
        local_tenant = repo.resolve_tenant("org_alpha")
        target = repo.get_connection_validation_target(local_tenant, connection_id)
        assert "onboarding" not in target["configuration"]
        assert (
            test.post(f"/v1/connections/{connection_id}/validate", headers=AUTH).status_code == 202
        )
        assert test.post(collect_path, headers=AUTH).status_code == 202
        assert test.post(collect_path, headers=MEMBER).status_code == 403
        assert (
            test.post(collect_path, headers={"Authorization": "Bearer beta-admin"}).status_code
            == 404
        )
        assert test.get(f"/v1/connections/{connection_id}", headers=MEMBER).status_code == 200
        repo.disable_connection(local_tenant, connection_id)
        assert test.post(collect_path, headers=AUTH).status_code == 409
        assert (
            test.post(f"/v1/connections/{connection_id}/validate", headers=AUTH).status_code == 409
        )
    assert [kind for kind, _job in dispatched] == ["validation", "collection"]
    # A newly constructed repository sees the queued jobs from the same tenant.
    restarted = PostgresInventoryRepository(DSN)
    assert restarted.connection_validation_job_state(local_tenant, connection_id) == "running"
    assert (
        restarted.connection_collection_status(local_tenant, connection_id, collection_kind=kind)[
            "state"
        ]
        == "running"
    )
