from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import Request
from fastapi.testclient import TestClient

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.connections import GoogleWorkspaceOperator

TENANTS = {
    "org_alpha": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    "org_beta": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
}


class HeaderAuthenticator:
    def authenticate(self, request: Request) -> AuthContext:
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        if token == "alpha-admin":
            return AuthContext("user_alpha", "org_alpha", "admin")
        if token == "alpha-member":
            return AuthContext("user_member", "org_alpha", "member")
        if token == "beta-admin":
            return AuthContext("user_beta", "org_beta", "admin")
        raise AuthenticationError("invalid session")


class PassingValidator:
    def validate(self, target: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(UTC)
        return {
            "started_at": now,
            "completed_at": now,
            "health_state": "healthy",
            "credential_state": "passed",
            "account_id_observed": target["configuration"]["domain"],
            "results": [],
            "summary": "Google Workspace validation passed.",
        }


class WorkspaceRepository:
    def __init__(self) -> None:
        self.targets: dict[str, dict[str, Any]] = {}
        self.rows: dict[str, dict[str, Any]] = {}

    def resolve_tenant(self, organization_id: str) -> str:
        return TENANTS[organization_id]

    def create_connection(self, tenant_id: str, **values: Any) -> dict[str, Any]:
        connection_id = values["connection_id"]
        target = {
            "id": connection_id,
            "denali_tenant_id": tenant_id,
            "lifecycle_state": "active",
            "health_state": "unknown",
            "last_validation": None,
            "last_validated_at": None,
            **values,
        }
        self.targets[connection_id] = target
        self.rows[connection_id] = self._response(target)
        return self.rows[connection_id]

    def get_connection_validation_target(self, tenant_id: str, connection_id: str):
        target = self.targets.get(connection_id)
        if target is None or target["denali_tenant_id"] != tenant_id:
            return None
        return target

    def get_connection(self, tenant_id: str, connection_id: str):
        target = self.get_connection_validation_target(tenant_id, connection_id)
        return None if target is None else self.rows[connection_id]

    def list_connections(self, tenant_id: str):
        return [
            self.rows[connection_id]
            for connection_id, target in self.targets.items()
            if target["denali_tenant_id"] == tenant_id
        ]

    def complete_google_workspace_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ):
        target = self.get_connection_validation_target(tenant_id, connection_id)
        if target is None:
            return None
        target["configuration"]["onboarding"].update(
            status="completed", completed_at=completed_at.isoformat()
        )
        target["coverage_plan"] = coverage_plan
        self.rows[connection_id] = self._response(target)
        return self.rows[connection_id]

    def record_connection_validation(
        self, tenant_id: str, connection_id: str, validation: dict[str, Any]
    ):
        target = self.get_connection_validation_target(tenant_id, connection_id)
        if target is None:
            return None
        target["health_state"] = validation["health_state"]
        target["last_validation"] = validation
        target["last_validated_at"] = validation["completed_at"].isoformat()
        self.rows[connection_id] = self._response(target)
        return self.rows[connection_id]

    @staticmethod
    def _response(target: dict[str, Any]) -> dict[str, Any]:
        reference = target["credential_reference"]
        return {
            key: value
            for key, value in target.items()
            if key not in {"credential_type", "credential_reference", "denali_tenant_id"}
        } | {
            "credential_reference": {
                "type": target["credential_type"],
                "service_account": reference["service_account"],
                "oauth_client_id": reference["oauth_client_id"],
            }
        }


def test_admin_creates_authorizes_and_validates_workspace_connection() -> None:
    repository = WorkspaceRepository()
    operator = GoogleWorkspaceOperator(
        service_account="workspace@project.iam.gserviceaccount.com",
        oauth_client_id="123456789",
        client_factory=lambda _subject: object(),
    )
    app = create_app(
        repository=repository,
        auth_mode="clerk",
        authenticator=HeaderAuthenticator(),
        google_workspace_operator=operator,
        google_workspace_connection_validator=PassingValidator(),
    )
    with TestClient(app) as client:
        created_response = client.post(
            "/v1/connections",
            headers={"Authorization": "Bearer alpha-admin"},
            json={
                "provider": "google_workspace",
                "display_name": "II Security Workspace",
                "admin_email": "KKMOOKHEY@IISECURITY.IN",
            },
        )
        assert created_response.status_code == 201
        created = created_response.json()
        assert created["configuration"]["domain"] == "iisecurity.in"
        assert created["configuration"]["admin_email"] == "kkmookhey@iisecurity.in"
        assert created["credential_reference"]["oauth_client_id"] == "123456789"

        completed = client.post(
            f"/v1/connections/{created['id']}/google-workspace/setup/complete",
            headers={"Authorization": "Bearer alpha-admin"},
        )
        assert completed.status_code == 202
        detail = client.get(
            f"/v1/connections/{created['id']}",
            headers={"Authorization": "Bearer alpha-admin"},
        ).json()
        assert detail["health_state"] == "healthy"
        assert detail["configuration"]["onboarding"]["status"] == "completed"


def test_member_and_other_tenant_cannot_complete_workspace_setup() -> None:
    repository = WorkspaceRepository()
    operator = GoogleWorkspaceOperator(
        service_account="workspace@project.iam.gserviceaccount.com",
        oauth_client_id="123456789",
        client_factory=lambda _subject: object(),
    )
    app = create_app(
        repository=repository,
        auth_mode="clerk",
        authenticator=HeaderAuthenticator(),
        google_workspace_operator=operator,
        google_workspace_connection_validator=PassingValidator(),
    )
    with TestClient(app) as client:
        created = client.post(
            "/v1/connections",
            headers={"Authorization": "Bearer alpha-admin"},
            json={
                "provider": "google_workspace",
                "display_name": "Workspace",
                "admin_email": "admin@example.com",
            },
        ).json()
        route = f"/v1/connections/{created['id']}/google-workspace/setup/complete"
        assert client.post(
            route, headers={"Authorization": "Bearer alpha-member"}
        ).status_code == 403
        assert client.post(
            route, headers={"Authorization": "Bearer beta-admin"}
        ).status_code == 404
