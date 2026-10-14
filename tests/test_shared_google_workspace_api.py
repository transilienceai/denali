from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from test_shared_gcp_api import Authenticator, Repository
from test_shared_google_workspace import ID, ROOT, TARGET, Broker, metadata

from denali.api.app import create_app

BASE = "/v1/shared/connections/google-workspace"
AUTH = {"Authorization": "Bearer alpha-admin"}


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED", "true")


def client(broker, repository=None):
    return TestClient(
        create_app(
            repository=repository or Repository(),
            auth_mode="clerk",
            authenticator=Authenticator(),
            shared_connections_client=broker,
            migrate_on_start=False,
        )
    )


def test_same_origin_onboarding_is_admin_only_uses_verified_user_and_org():
    broker = Broker()
    with client(broker) as web:
        assert web.get(f"{BASE}/config").status_code == 401
        response = web.get(f"{BASE}/config", headers=AUTH)
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        assert response.json()["items"][0]["customer_id"] == "C012345"
        assert (
            web.get(f"{BASE}/config", headers={"Authorization": "Bearer beta-admin"}).status_code
            == 404
        )
        body = {"target_id": TARGET, "request_id": TARGET}
        assert (
            web.post(
                f"{BASE}/setup", headers={"Authorization": "Bearer alpha-member"}, json=body
            ).status_code
            == 403
        )
        assert (
            web.post(
                f"{BASE}/setup", headers=AUTH, json={**body, "clerk_org_id": "org_beta"}
            ).status_code
            == 422
        )
        assert (
            web.post(
                f"{BASE}/setup", headers=AUTH, json={**body, "initiating_user_id": "user_other"}
            ).status_code
            == 422
        )
        assert web.post(f"{BASE}/setup", headers=AUTH, json=body).status_code == 201
        setup = next(call for call in broker.calls if call[1] == f"{ROOT}/setup")
        assert setup[2] == "org_alpha" and setup[3]["initiating_user_id"] == "user_alpha"
        assert web.post(f"{BASE}/{ID}/validate", headers=AUTH).status_code == 200
        assert broker.calls[-1][3] == {"initiating_user_id": "user_alpha"}


def test_inventory_uses_canonical_broker_root_not_product_inventory_suffix():
    broker = Broker()
    with client(broker) as web:
        result = web.get(f"{BASE}/inventory", headers=AUTH)
        assert result.status_code == 200
        assert result.json()["items"][0]["id"] == ID
        assert broker.calls[-1][0:3] == ("GET", ROOT, "org_alpha")


@pytest.mark.parametrize(
    "path,body",
    [
        ("/setup", {"target_id": TARGET, "request_id": TARGET, "private_key": "private-marker"}),
        (f"/{ID}/use-in-denali", {"private_key": "private-marker"}),
        ("/private-marker/validate", None),
    ],
)
def test_workspace_rejected_input_is_never_reflected(path, body):
    broker = Broker()
    with client(broker) as web:
        result = web.post(BASE + path, headers=AUTH, json=body)
        assert result.status_code == 422
        assert "private-marker" not in result.text


def test_attachment_checks_live_planes_is_idempotent_and_rejects_native_confirmation():
    broker = Broker()
    repo = Repository()
    with client(broker, repo) as web:
        for _ in range(2):
            response = web.post(f"{BASE}/{ID}/use-in-denali", headers=AUTH, json={})
            assert response.status_code == 201, response.text
            row = response.json()
            assert row["credential_reference"] == {
                "type": "platform_shared_google_workspace",
                "platform_connection_id": ID,
            }
            assert row["setup_capabilities"]["google_workspace_admin_authorization"] is False
        assert len(repo.created) == 1
        assert repo.created[0][0] == "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        assert (
            web.post(
                f"/v1/connections/{ID}/google-workspace/setup/complete", headers=AUTH
            ).status_code
            == 409
        )
        assert (
            web.post(
                f"{BASE}/{ID}/use-in-denali", headers=AUTH, json={"customer_id": "C999"}
            ).status_code
            == 422
        )
        assert (
            web.post(
                f"{BASE}/{ID}/use-in-denali",
                headers={"Authorization": "Bearer beta-admin"},
                json={},
            ).status_code
            == 404
        )
        broker.status["binding_revision"] = 2
        assert web.post(f"{BASE}/{ID}/use-in-denali", headers=AUTH, json={}).status_code == 409


@pytest.mark.parametrize(
    "mutation",
    [
        {"health_state": "partial"},
        {"validated_scopes": []},
        {"setup_state": "pending_authorization"},
        {"lifecycle_state": "disabled"},
        {"last_validated_at": (datetime.now(UTC) - timedelta(minutes=16)).isoformat()},
    ],
)
def test_pending_partial_disabled_or_stale_connection_cannot_attach(mutation):
    broker = Broker()
    broker.status.update(mutation)
    repo = Repository()
    with client(broker, repo) as web:
        assert web.post(f"{BASE}/{ID}/use-in-denali", headers=AUTH, json={}).status_code == 409
    assert repo.created == []


def test_successful_badge_with_failed_live_probe_cannot_attach():
    broker = Broker()
    broker.failed_operation = "oauth_activity"
    repo = Repository()
    with client(broker, repo) as web:
        assert web.post(f"{BASE}/{ID}/use-in-denali", headers=AUTH, json={}).status_code == 409
    assert repo.created == []


def test_native_uuid_collision_does_not_rebind_existing_connection():
    broker = Broker()
    repo = Repository()
    tenant = repo.resolve_tenant("org_alpha")
    repo.rows[(tenant, ID)] = {
        "provider": "google_workspace",
        "credential_reference": {"type": "google_workspace_domain_wide_delegation"},
    }
    with client(broker, repo) as web:
        assert web.post(f"{BASE}/{ID}/use-in-denali", headers=AUTH, json={}).status_code == 409
    assert repo.created == []


def test_default_off_and_wrong_broker_identity_do_not_become_empty_lists(monkeypatch):
    broker = Broker()
    monkeypatch.delenv("DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED")
    with client(broker) as web:
        assert web.get(f"{BASE}/config", headers=AUTH).status_code == 404
    assert not broker.calls
    monkeypatch.setenv("DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED", "true")
    broker.status = {**metadata(), "clerk_org_id": "org_beta"}
    with client(broker) as web:
        assert web.get(f"{BASE}/inventory", headers=AUTH).status_code == 502
