from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.integrations.shared_connections_client import SharedConnectionsError

ID = "11111111-1111-4111-8111-111111111111"
PROJECT = {"id": "shared-ai-project", "number": "123456789012"}
AUTH = {"Authorization": "Bearer alpha-admin"}


class Authenticator:
    def authenticate(self, request: Request) -> AuthContext:
        identities = {
            "alpha-admin": AuthContext("user_alpha", "org_alpha", "admin"),
            "alpha-member": AuthContext("user_member", "org_alpha", "member"),
            "beta-admin": AuthContext("user_beta", "org_beta", "admin"),
        }
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        if token not in identities:
            raise AuthenticationError("invalid session")
        return identities[token]


class Repository:
    def __init__(self):
        self.rows = {}
        self.created = []

    def resolve_tenant(self, org):
        return {
            "org_alpha": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "org_beta": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        }[org]

    def create_connection(self, tenant, **values):
        self.created.append((tenant, deepcopy(values)))
        row = {
            "id": values["connection_id"],
            "provider": values["provider"],
            "lifecycle_state": "active",
            "health_state": "unknown",
            "display_name": values["display_name"],
            "credential_reference": {
                "type": values["credential_type"],
                **values["credential_reference"],
            },
            "declared_scopes": values["declared_scopes"],
            "configuration": values["configuration"],
            "coverage_plan": values["coverage_plan"],
        }
        self.rows[(tenant, values["connection_id"])] = row
        return row

    def get_connection(self, tenant, connection_id):
        return self.rows.get((tenant, connection_id))

    def get_connection_validation_target(self, tenant, connection_id):
        row = self.get_connection(tenant, connection_id)
        if row is None:
            return None
        return {**row, "credential_type": row["credential_reference"]["type"]}


class Broker:
    def __init__(self):
        self.calls = []
        self.listing = [
            {
                "id": ID,
                "provider": "gcp",
                "connection_kind": "shared_gcp",
                "display_name": "Shared GCP",
                "projects": [PROJECT],
                "availability": "ready",
                "setup_state": "ready",
                "health_state": "healthy",
                "validated_scopes": ["gcp.code_to_cloud"],
                "last_validated_at": None,
            }
        ]
        self.failure = None

    def allows_org(self, org):
        return org == "org_alpha"

    def request(self, method, path, *, clerk_org_id, payload=None, expect_text=False):
        self.calls.append((method, path, clerk_org_id, payload, expect_text))
        if self.failure:
            raise SharedConnectionsError(self.failure)
        if path == "/v1/connections":
            return {"items": deepcopy(self.listing)}
        if expect_text:
            return "#!/bin/bash\n# review exact project IAM grants\n"
        if path.endswith("/validation"):
            return {
                "setup_state": "ready",
                "health_state": "healthy",
                "job_state": "succeeded",
                "internal_provider_material": "not-public",
                "results": [{"internal": True}],
                "retry_available": True,
            }
        if path.endswith("/disable"):
            return {"status": "disabled", "internal_provider_material": "not-public"}
        if method == "DELETE":
            return {"status": "deleted"}
        return {
            "id": ID,
            "job_id": "22222222-2222-4222-8222-222222222222",
            "state": "queued",
            "internal_provider_material": "not-public",
        }


def client(broker=None, repository=None):
    return TestClient(
        create_app(
            repository=repository or Repository(),
            auth_mode="clerk",
            authenticator=Authenticator(),
            shared_connections_client=broker or Broker(),
            migrate_on_start=False,
        )
    )


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_GCP_ENABLED", "true")


def create_payload():
    return {
        "request_id": ID,
        "display_name": "Shared Google Cloud",
        "projects": [PROJECT],
        "declared_scopes": ["gcp.code_to_cloud"],
    }


def test_shared_gcp_is_hidden_by_default_and_for_non_pilot_org(monkeypatch):
    broker = Broker()
    monkeypatch.delenv("DENALI_PLATFORM_GCP_ENABLED", raising=False)
    with client(broker) as test:
        assert test.get("/v1/shared/connections/gcp", headers=AUTH).status_code == 404
    monkeypatch.setenv("DENALI_PLATFORM_GCP_ENABLED", "true")
    with client(broker) as test:
        assert (
            test.get(
                "/v1/shared/connections/gcp", headers={"Authorization": "Bearer beta-admin"}
            ).status_code
            == 404
        )
    assert not broker.calls


def test_browser_creation_is_admin_only_and_cannot_supply_org_or_credentials():
    broker = Broker()
    with client(broker) as test:
        path = "/v1/shared/connections/gcp"
        assert test.post(path, json=create_payload()).status_code == 401
        assert (
            test.post(
                path, json=create_payload(), headers={"Authorization": "Bearer alpha-member"}
            ).status_code
            == 403
        )
        for extra in [
            {"clerk_org_id": "org_beta"},
            {"principal_email": "foreign@example.test"},
            {"service_account_key": {}},
            {"credential_reference": {}},
        ]:
            assert (
                test.post(path, json={**create_payload(), **extra}, headers=AUTH).status_code == 422
            )
        response = test.post(path, json=create_payload(), headers=AUTH)
    assert response.status_code == 202
    assert set(response.json()) == {"id", "job_id", "state"}
    assert broker.calls[0][2] == "org_alpha"
    assert "clerk_org_id" not in broker.calls[0][3]


def test_rejected_customer_material_is_never_reflected_from_any_gcp_validation_error():
    marker = "synthetic-rejected-material-marker"
    with client() as test:
        created = test.post(
            "/v1/shared/connections/gcp",
            json={**create_payload(), "service_account_key": {"private_key": marker}},
            headers=AUTH,
        )
        invalid_path = test.get(f"/v1/shared/connections/gcp/{marker}/validation", headers=AUTH)
        deleted = test.request(
            "DELETE",
            f"/v1/shared/connections/gcp/{ID}",
            json={"confirmation_name": "Shared GCP", "credential_material": marker},
            headers=AUTH,
        )
    for response in (created, invalid_path, deleted):
        assert response.status_code == 422
        assert marker not in response.text
        assert "private_key" not in response.text


@pytest.mark.parametrize(
    "change",
    [
        {"projects": []},
        {"projects": [PROJECT, PROJECT]},
        {"projects": [{"id": "*", "number": "123456"}]},
        {"projects": [{"id": "shared-ai-project", "number": "1"}]},
        {"declared_scopes": ["gcp.cloud_admin"]},
        {"declared_scopes": ["gcp.code_to_cloud", "gcp.code_to_cloud"]},
        {"display_name": " "},
        {"display_name": "$(arbitrary)"},
    ],
)
def test_creation_boundary_rejects_broad_duplicate_or_malformed_selection(change):
    broker = Broker()
    with client(broker) as test:
        response = test.post(
            "/v1/shared/connections/gcp", json={**create_payload(), **change}, headers=AUTH
        )
    assert response.status_code == 422
    assert not broker.calls


def test_metadata_status_and_script_are_no_store_and_provider_internals_do_not_escape():
    broker = Broker()
    broker.listing[0]["internal_provider_material"] = "not-public"
    broker.listing[0]["projects"] = [{**PROJECT, "internal_provider_material": "not-public"}]
    with client(broker) as test:
        member = {"Authorization": "Bearer alpha-member"}
        listed = test.get("/v1/shared/connections/gcp", headers=member)
        status = test.get(f"/v1/shared/connections/gcp/{ID}/validation", headers=member)
        script = test.get(f"/v1/shared/connections/gcp/{ID}/setup.sh", headers=member)
    assert listed.status_code == status.status_code == script.status_code == 200
    assert listed.json()["items"][0]["projects"] == [PROJECT]
    for response in (listed, status, script):
        assert response.headers["cache-control"] == "no-store"
        assert "not-public" not in response.text
    assert "results" not in status.json()


def test_attach_is_idempotent_tenant_scoped_reference_only_and_native_setup_is_blocked():
    repo = Repository()
    broker = Broker()
    with client(broker, repo) as test:
        path = f"/v1/shared/connections/gcp/{ID}/use-in-denali"
        payload = {"declared_scopes": ["gcp.code_to_cloud"]}
        attached = test.post(path, json=payload, headers=AUTH)
        duplicate = test.post(path, json=payload, headers=AUTH)
        assert attached.status_code == duplicate.status_code == 201
        assert attached.json()["credential_reference"] == {
            "type": "platform_shared_gcp",
            "platform_connection_id": ID,
        }
        assert attached.json()["setup_capabilities"]["gcp_cloud_shell"] is False
        assert len(repo.created) == 1
        assert repo.created[0][0] == repo.resolve_tenant("org_alpha")
        assert repo.get_connection(repo.resolve_tenant("org_beta"), ID) is None
        assert (
            test.post(
                path, json=payload, headers={"Authorization": "Bearer beta-admin"}
            ).status_code
            == 404
        )
        for suffix, body in [("launch", {}), ("complete", {"completion_code": "x" * 20})]:
            assert (
                test.post(
                    f"/v1/connections/{ID}/gcp/setup/{suffix}", json=body, headers=AUTH
                ).status_code
                == 409
            )


@pytest.mark.parametrize(
    "availability,scopes,status",
    [
        ("needs_setup", ["gcp.code_to_cloud"], 409),
        ("disabled", ["gcp.code_to_cloud"], 409),
        ("ready", ["gcp.vertex_ai"], 403),
    ],
)
def test_attach_requires_ready_and_current_app_scopes(availability, scopes, status):
    broker = Broker()
    broker.listing[0]["availability"] = availability
    repo = Repository()
    with client(broker, repo) as test:
        response = test.post(
            f"/v1/shared/connections/gcp/{ID}/use-in-denali",
            json={"declared_scopes": scopes},
            headers=AUTH,
        )
    assert response.status_code == status
    assert not repo.created


def test_attachment_conflict_does_not_change_an_existing_native_connection():
    repo = Repository()
    repo.rows[(repo.resolve_tenant("org_alpha"), ID)] = {
        "id": ID,
        "provider": "gcp",
        "credential_reference": {"type": "gcp_connection_principal"},
    }
    with client(repository=repo) as test:
        response = test.post(
            f"/v1/shared/connections/gcp/{ID}/use-in-denali",
            json={"declared_scopes": ["gcp.code_to_cloud"]},
            headers=AUTH,
        )
    assert response.status_code == 409
    assert not repo.created


def test_upstream_not_found_is_a_broker_error_not_native_fallback():
    broker = Broker()
    broker.failure = 404
    repo = Repository()
    with client(broker, repo) as test:
        response = test.get("/v1/shared/connections/gcp", headers=AUTH)
        creation = test.post("/v1/shared/connections/gcp", json=create_payload(), headers=AUTH)
    assert response.status_code == creation.status_code == 502
    assert not repo.created


def test_validate_and_global_disable_require_admin_and_preserve_server_org():
    broker = Broker()
    with client(broker) as test:
        for operation in ("validate", "disable"):
            path = f"/v1/shared/connections/gcp/{ID}/{operation}"
            assert (
                test.post(path, headers={"Authorization": "Bearer alpha-member"}).status_code == 403
            )
            result = test.post(path, headers=AUTH)
            assert result.status_code == (202 if operation == "validate" else 200)
            assert "not-public" not in result.text
    assert all(call[2] == "org_alpha" for call in broker.calls)


def test_shared_delete_requires_admin_disable_exact_name_and_server_resolved_org():
    broker = Broker()
    path = f"/v1/shared/connections/gcp/{ID}"
    payload = {"confirmation_name": "Shared GCP"}
    with client(broker) as test:
        assert test.request("DELETE", path, json=payload).status_code == 401
        assert (
            test.request(
                "DELETE", path, json=payload, headers={"Authorization": "Bearer alpha-member"}
            ).status_code
            == 403
        )
        assert test.request("DELETE", path, json=payload, headers=AUTH).status_code == 409
        broker.listing[0]["availability"] = "disabled"
        assert (
            test.request(
                "DELETE", path, json={"confirmation_name": "wrong"}, headers=AUTH
            ).status_code
            == 409
        )
        assert (
            test.request(
                "DELETE", path, json={**payload, "clerk_org_id": "org_beta"}, headers=AUTH
            ).status_code
            == 422
        )
        result = test.request("DELETE", path, json=payload, headers=AUTH)
    assert result.status_code == 200 and result.json() == {"status": "deleted"}
    assert broker.calls[-1] == (
        "DELETE",
        f"/internal/v1/connections/gcp/{ID}",
        "org_alpha",
        None,
        False,
    )


def test_failed_or_stale_provisioning_retry_uses_the_same_connection_and_no_new_plan():
    broker = Broker()
    repo = Repository()
    with client(broker, repo) as test:
        status = test.get(f"/v1/shared/connections/gcp/{ID}/validation", headers=AUTH)
        assert status.json()["retry_available"] is True
        result = test.post(f"/v1/shared/connections/gcp/{ID}/validate", headers=AUTH)
    assert result.status_code == 202
    assert not repo.created
    assert broker.calls[-1][1] == f"/internal/v1/connections/gcp/{ID}/validate"
