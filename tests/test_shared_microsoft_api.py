"""Browser Microsoft onboarding is admin-only, org-bound and credential-free."""

from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from test_shared_microsoft import ID, SUBSCRIPTION, TENANT

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.connections.entra import ENTRA_SCOPES
from denali.integrations.shared_connections_client import SharedConnectionsError
from denali.integrations.shared_microsoft import SHARED_AZURE_SCOPES


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


AUTH = {"Authorization": "Bearer alpha-admin"}
MEMBER = {"Authorization": "Bearer alpha-member"}


class Broker:
    def __init__(self, provider):
        self.calls = []
        self.failure = None
        self.deleted = False
        self.plan_name = "Shared Microsoft"
        self.plan_disabled = False
        self.listing = [
            {
                "id": ID,
                "provider": provider,
                "connection_kind": f"shared_{provider}",
                "tenant_id": TENANT,
                "subscriptions": [{"id": SUBSCRIPTION, "name": "Selected"}],
                "display_name": "Shared Microsoft",
                "availability": "ready",
                "setup_state": "ready",
                "health_state": "healthy",
                "validated_scopes": list(
                    SHARED_AZURE_SCOPES if provider == "azure" else ENTRA_SCOPES
                ),
                "internal_provider_material": "hidden",
            }
        ]

    def allows_org(self, org):
        return org == "org_alpha"

    def request(self, method, path, *, clerk_org_id, payload=None, expect_text=False):
        self.calls.append((method, path, clerk_org_id, deepcopy(payload)))
        if self.failure:
            raise SharedConnectionsError(self.failure)
        if path == "/v1/connections":
            return {"items": self.listing}
        if path.endswith("/delete"):
            if not self.plan_disabled or payload.get("confirmation_name") != self.plan_name:
                raise SharedConnectionsError(404)
            self.deleted = True
            return {"status": "deleted"}
        if expect_text:
            return "#!/usr/bin/env bash\n# Review Reader assignments before execution\n"
        if path.endswith("/setup"):
            return {
                "consent_url": f"https://login.microsoftonline.com/{TENANT}/v2.0/adminconsent?state=synthetic",
                "internal_provider_material": "hidden",
            }
        if path.endswith("/validation"):
            return {
                "setup_state": "ready",
                "health_state": "healthy",
                "job_state": "succeeded",
                "internal_provider_material": "hidden",
            }
        return {
            "id": ID,
            "status": "disabled",
            "setup_state": "pending",
            "internal_provider_material": "hidden",
        }


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


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_AZURE_ENABLED", "true")
    monkeypatch.setenv("DENALI_PLATFORM_ENTRA_ENABLED", "true")


def payload(provider):
    return {
        "request_id": ID,
        "display_name": "Shared Microsoft",
        "tenant_id": TENANT,
        "declared_scopes": list(SHARED_AZURE_SCOPES if provider == "azure" else ENTRA_SCOPES),
        **({"subscriptions": [{"id": SUBSCRIPTION}]} if provider == "azure" else {}),
    }


@pytest.mark.parametrize("provider", ["azure", "entra"])
def test_default_off_and_org_allowlist_make_no_broker_calls(provider, monkeypatch):
    broker = Broker(provider)
    monkeypatch.delenv(f"DENALI_PLATFORM_{provider.upper()}_ENABLED")
    with client(broker) as test:
        assert test.get(f"/v1/shared/connections/{provider}", headers=AUTH).status_code == 404
    monkeypatch.setenv(f"DENALI_PLATFORM_{provider.upper()}_ENABLED", "true")
    with client(broker) as test:
        assert (
            test.get(
                f"/v1/shared/connections/{provider}", headers={"Authorization": "Bearer beta-admin"}
            ).status_code
            == 404
        )
    assert not broker.calls


@pytest.mark.parametrize("provider", ["azure", "entra"])
def test_creation_requires_admin_and_rejects_credentials_or_forged_org(provider):
    broker = Broker(provider)
    path = f"/v1/shared/connections/{provider}"
    with client(broker) as test:
        assert test.post(path, json=payload(provider)).status_code == 401
        assert test.post(path, json=payload(provider), headers=MEMBER).status_code == 403
        for extra in [
            {"clerk_org_id": "org_beta"},
            {"denali_tenant_id": TENANT},
            {"client_secret": "synthetic-marker"},
            {"credential_reference": {"token": "synthetic-marker"}},
        ]:
            rejected = test.post(path, json={**payload(provider), **extra}, headers=AUTH)
            assert rejected.status_code == 422
            assert "synthetic-marker" not in rejected.text
        created = test.post(path, json=payload(provider), headers=AUTH)
    assert created.status_code == 201
    assert "hidden" not in created.text
    assert len(broker.calls) == 1 and broker.calls[0][2] == "org_alpha"


@pytest.mark.parametrize("provider", ["azure", "entra"])
def test_all_mutations_and_get_setup_state_rotation_are_admin_only(provider):
    broker = Broker(provider)
    base = f"/v1/shared/connections/{provider}/{ID}"
    with client(broker) as test:
        for suffix in ["setup", "validate", "disable", "use-in-denali"]:
            assert (
                test.post(
                    f"{base}/{suffix}",
                    headers=MEMBER,
                    json={"declared_scopes": payload(provider)["declared_scopes"]},
                ).status_code
                == 403
            )
        assert test.get(base + "/setup", headers=MEMBER).status_code == 403
        assert (
            test.request(
                "DELETE", base, json={"confirmation_name": "Shared Microsoft"}, headers=MEMBER
            ).status_code
            == 403
        )
        for suffix in ["validation"]:
            response = test.get(f"{base}/{suffix}", headers=MEMBER)
            assert response.status_code == 200
            assert response.headers["cache-control"] == "no-store"
            assert "hidden" not in response.text


@pytest.mark.parametrize("provider", ["azure", "entra"])
def test_attach_is_reference_only_and_native_setup_cannot_change_it(provider):
    broker = Broker(provider)
    repo = Repository()
    base = f"/v1/shared/connections/{provider}/{ID}"
    with client(broker, repo) as test:
        body = {"declared_scopes": payload(provider)["declared_scopes"]}
        attached = test.post(base + "/use-in-denali", json=body, headers=AUTH)
        repeated = test.post(base + "/use-in-denali", json=body, headers=AUTH)
        assert attached.status_code == repeated.status_code == 201
        assert attached.json()["credential_reference"] == {
            "type": f"platform_shared_{provider}",
            "platform_connection_id": ID,
        }
        assert len(repo.created) == 1
        assert repo.created[0][0] == repo.resolve_tenant("org_alpha")
        assert repo.get_connection(repo.resolve_tenant("org_beta"), ID) is None
        for suffix in ["launch", *(["complete"] if provider == "azure" else [])]:
            response = test.post(
                f"/v1/connections/{ID}/{provider}/setup/{suffix}",
                headers=AUTH,
                json={"completion_code": "x" * 20},
            )
            assert response.status_code == 409


@pytest.mark.parametrize("provider", ["azure", "entra"])
@pytest.mark.parametrize(
    "change",
    [
        {"availability": "needs_setup"},
        {"availability": "disabled"},
        {"health_state": "partial"},
        {"validated_scopes": []},
    ],
)
def test_attach_requires_current_healthy_entitled_plan(provider, change):
    broker = Broker(provider)
    broker.listing[0].update(change)
    repo = Repository()
    with client(broker, repo) as test:
        response = test.post(
            f"/v1/shared/connections/{provider}/{ID}/use-in-denali",
            headers=AUTH,
            json={"declared_scopes": payload(provider)["declared_scopes"]},
        )
    assert response.status_code in {403, 409}
    assert not repo.created


@pytest.mark.parametrize("provider", ["azure", "entra"])
def test_setup_posts_correct_provider_protocol_and_no_browser_callback(provider):
    broker = Broker(provider)
    with client(broker) as test:
        response = test.post(f"/v1/shared/connections/{provider}/{ID}/setup", headers=AUTH)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "hidden" not in response.text
    assert broker.calls[0][3] == {}


@pytest.mark.parametrize("provider", ["azure", "entra"])
def test_shared_delete_requires_disabled_exact_name_and_platform_body(provider):
    broker = Broker(provider)
    base = f"/v1/shared/connections/{provider}/{ID}"
    with client(broker) as test:
        assert (
            test.request(
                "DELETE", base, headers=AUTH, json={"confirmation_name": "Shared Microsoft"}
            ).status_code
            == 404
        )
        broker.listing[0]["availability"] = "disabled"
        broker.plan_disabled = True
        assert (
            test.request(
                "DELETE", base, headers=AUTH, json={"confirmation_name": "Wrong"}
            ).status_code
            == 404
        )
        assert (
            test.request(
                "DELETE", base, headers=AUTH, json={"confirmation_name": "Shared Microsoft"}
            ).status_code
            == 200
        )
    assert broker.calls[-1][:2] == ("POST", f"/internal/v1/connections/{provider}/{ID}/delete")
    assert broker.calls[-1][3] == {"confirmation_name": "Shared Microsoft"}


@pytest.mark.parametrize("provider", ["azure", "entra"])
def test_creator_cleanup_does_not_require_admission_filtered_listing(provider):
    broker = Broker(provider)
    broker.listing = []  # Trusted cloud target admission was revoked.
    broker.plan_disabled = True
    with client(broker) as test:
        result = test.request(
            "DELETE",
            f"/v1/shared/connections/{provider}/{ID}",
            headers=AUTH,
            json={"confirmation_name": "Shared Microsoft"},
        )
    assert result.status_code == 200
    assert broker.deleted
    assert len(broker.calls) == 1
    assert broker.calls[0][1].endswith("/delete")


@pytest.mark.parametrize("provider", ["azure", "entra"])
def test_shared_failure_never_creates_native_fallback(provider):
    broker = Broker(provider)
    broker.failure = 503
    repo = Repository()
    with client(broker, repo) as test:
        assert (
            test.post(
                f"/v1/shared/connections/{provider}/{ID}/use-in-denali",
                headers=AUTH,
                json={"declared_scopes": payload(provider)["declared_scopes"]},
            ).status_code
            == 503
        )
    assert not repo.created


def test_entra_only_rollout_denies_all_azure_handoffs_without_broker_calls(monkeypatch):
    monkeypatch.delenv("DENALI_PLATFORM_AZURE_ENABLED", raising=False)
    broker = Broker("entra")
    with client(broker) as test:
        assert test.get("/v1/shared/connections/entra", headers=AUTH).status_code == 200
        assert test.post(
            "/v1/shared/connections/entra", headers=AUTH, json=payload("entra")
        ).status_code == 201
        before = len(broker.calls)
        assert test.get("/v1/shared/connections/azure", headers=AUTH).status_code == 404
        assert test.post(
            "/v1/shared/connections/azure", headers=AUTH, json=payload("azure")
        ).status_code == 404
        azure = f"/v1/shared/connections/azure/{ID}"
        for path in (
            "/v1/shared/connections/azure/config",
            f"{azure}/validation", f"{azure}/setup", f"{azure}/setup.sh",
        ):
            assert test.get(path, headers=AUTH).status_code == 404
        for suffix in ("setup", "validate", "disable", "use-in-denali"):
            assert test.post(
                f"{azure}/{suffix}", headers=AUTH,
                json={"declared_scopes": payload("azure")["declared_scopes"]},
            ).status_code == 404
        assert test.request(
            "DELETE", azure, headers=AUTH, json={"confirmation_name": "Shared Microsoft"}
        ).status_code == 404
        assert len(broker.calls) == before
    assert all("/azure" not in call[1] for call in broker.calls)
