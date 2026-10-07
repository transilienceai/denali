from __future__ import annotations

import json
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.api.gateway_auth import GatewayPrincipal
from denali.resource_writes.api import INTERNAL_PATH
from denali.resource_writes.observability import observe_dependency
from denali.resource_writes.templates import AWS_ACTION, PURPOSES

ORG = "org_Alpha1"


class Auth:
    def authenticate(self, request):
        if request.headers.get("authorization") == "Bearer browser":
            return AuthContext("user_Browser1", ORG, "admin")
        raise AuthenticationError("invalid session")


class Repository:
    def lookup_tenant(self, org):
        return "tenant-alpha" if org == ORG else None

    def resolve_tenant(self, org):
        return self.lookup_tenant(org)


class Verifier:
    def verify(self, token, *, purpose):
        granted = PURPOSES[AWS_ACTION] if token.startswith("resource-") else "denali:write"
        if granted != purpose:
            return None
        user = "user_Member1" if token == "resource-member" else "user_Admin1"
        return GatewayPrincipal("mch_Gateway1", ORG, user, granted)


class Memberships:
    def role(self, org, user):
        return "member" if user == "user_Member1" else "admin" if org == ORG else None


class Service:
    def __init__(self):
        self.calls = []

    def preview(self, **kwargs):
        self.calls.append(kwargs)
        return {"preview_id": str(uuid4()), "provider_mutated": False}


def body(**changed):
    return {
        "finding_id": str(uuid4()),
        "grant_id": str(uuid4()),
        "resource_action": AWS_ACTION,
        "parameters": {"model_arns": ["approved-model"]},
        "expected_organization_id": ORG,
        **changed,
    }


def application(service):
    return create_app(
        repository=Repository(),
        authenticator=Auth(),
        auth_mode="clerk",
        results_gateway_verifier=Verifier(),
        migrate_on_start=False,
        gateway_membership_checker=Memberships(),
        resource_write_service=service,
    )


def test_browser_and_gateway_call_same_tenant_scoped_product_service():
    service = Service()
    payload = body()
    with TestClient(application(service)) as client:
        browser = client.post(
            "/v1/resource-writes/previews",
            json=payload,
            headers={"Authorization": "Bearer browser"},
        )
        gateway = client.post(
            INTERNAL_PATH,
            json={"action": "preview", "resource_action": AWS_ACTION, "payload": payload},
            headers={"Authorization": "Bearer resource-admin"},
        )
    assert browser.status_code == gateway.status_code == 200
    assert browser.headers["cache-control"] == gateway.headers["cache-control"] == "no-store"
    assert [call["tenant_id"] for call in service.calls] == ["tenant-alpha", "tenant-alpha"]
    assert [call["actor"] for call in service.calls] == ["user_Browser1", "user_Admin1"]


@pytest.mark.parametrize("token", ["ordinary-write", "resource-member", "invalid"])
def test_gateway_requires_dedicated_purpose_and_current_admin(token):
    service = Service()
    with TestClient(application(service)) as client:
        response = client.post(
            INTERNAL_PATH,
            json={"action": "preview", "resource_action": AWS_ACTION, "payload": body()},
            headers={"Authorization": "Bearer " + token},
        )
    assert response.status_code in {401, 403}
    assert service.calls == []


def test_wrong_org_and_secret_extra_fields_never_reach_service_or_echo():
    service = Service()
    with TestClient(application(service)) as client:
        wrong = client.post(
            "/v1/resource-writes/previews",
            json=body(expected_organization_id="org_Beta2"),
            headers={"Authorization": "Bearer browser"},
        )
        secret = client.post(
            "/v1/resource-writes/previews",
            json=body(token="never-echo-this-credential"),
            headers={"Authorization": "Bearer browser"},
        )
    assert wrong.status_code == 409 and secret.status_code == 422
    assert "never-echo" not in secret.text and service.calls == []


@pytest.mark.parametrize("confirm", [False, 1, "true"])
def test_request_explicit_boolean_confirmation_before_any_service_call(confirm):
    service = Service()
    with TestClient(application(service)) as client:
        response = client.post(
            "/v1/resource-writes/requests",
            json={
                "preview_id": str(uuid4()),
                "preview_sha256": "a" * 64,
                "justification": "Review",
                "expected_organization_id": ORG,
                "confirm": confirm,
            },
            headers={"Authorization": "Bearer browser", "Idempotency-Key": str(uuid4())},
        )
    assert response.status_code == 422 and service.calls == []


def test_default_off_has_no_new_worker_or_credentials():
    with TestClient(application(None)) as client:
        response = client.post(
            "/v1/resource-writes/previews", json=body(), headers={"Authorization": "Bearer browser"}
        )
    assert response.status_code == 404


def preview_events(caplog):
    return [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "denali.resource_preview"
    ]


@pytest.mark.parametrize("gateway", [False, True])
def test_authorized_preview_route_activates_only_fixed_diagnostics(caplog, gateway):
    private = "SIMULATED_PRIVATE_BODY_AND_CREDENTIAL"
    service = Service()
    payload = body(parameters={"model_arns": [private]})
    with TestClient(application(service)) as client:
        response = client.post(
            INTERNAL_PATH if gateway else "/v1/resource-writes/previews",
            json=(
                {"action": "preview", "resource_action": AWS_ACTION, "payload": payload}
                if gateway
                else payload
            ),
            headers={"Authorization": "Bearer resource-admin" if gateway else "Bearer browser"},
        )
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    assert [(row["phase"], row["category"]) for row in preview_events(caplog)] == [
        ("preview", "returned")
    ]
    assert private not in caplog.text


@pytest.mark.parametrize("operation", ["request", "review", "status", "reconcile"])
def test_other_resource_routes_do_not_activate_preview_observation(caplog, operation):
    service = Service()

    def inactive(*args, **kwargs):
        service.calls.append((args, kwargs))
        return observe_dependency("membership", lambda: {"state": "rejected"})

    service.request = service.review = service.status = service.reconcile = inactive
    service.store = SimpleNamespace(get=lambda *args: {"action": AWS_ACTION})
    request_id = str(uuid4())
    path = "/v1/resource-writes/requests"
    headers = {"Authorization": "Bearer browser", "Idempotency-Key": str(uuid4())}
    payload = {"expected_organization_id": ORG}
    if operation == "request":
        payload.update(
            preview_id=str(uuid4()), preview_sha256="a" * 64, justification="Review", confirm=True
        )
    else:
        path += "/" + request_id
        if operation != "status":
            path += "/" + operation
        if operation == "review":
            payload.update(decision="rejected", review_note="Review", confirm=True)
    with TestClient(application(service)) as client:
        response = (
            client.get(path, headers=headers)
            if operation == "status"
            else client.post(path, headers=headers, json=payload)
        )
    assert response.status_code == (201 if operation == "request" else 200)
    assert len(service.calls) == 1 and preview_events(caplog) == []


def test_preview_denied_before_product_call_does_not_log_privileged_context(caplog):
    service = Service()
    with TestClient(application(service)) as client:
        response = client.post(
            INTERNAL_PATH,
            json={"action": "preview", "resource_action": AWS_ACTION, "payload": body()},
            headers={"Authorization": "Bearer resource-member"},
        )
    assert response.status_code == 403 and service.calls == [] and preview_events(caplog) == []
