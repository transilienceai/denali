from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from denali.api.app import DEFAULT_LOCAL_TENANT, create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.connections import (
    ENTRA_SCOPES,
    EntraAdminConsentClient,
    EntraConnectionValidator,
    entra_coverage_plan,
)

ENTRA_TENANT_ID = "11111111-1111-4111-8111-111111111111"
OTHER_ENTRA_TENANT_ID = "22222222-2222-4222-8222-222222222222"
CLIENT_ID = "33333333-3333-4333-8333-333333333333"
AUTH_TENANTS = {
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


class FakeGraph:
    def __init__(self, failures: set[str] | None = None):
        self.failures = failures or set()
        self.calls: list[str] = []

    def list(
        self, path: str, *, params: dict[str, str] | None = None, limit: int = 20_000
    ) -> tuple[dict[str, Any], ...]:
        self.calls.append(path)
        if path in self.failures:
            raise RuntimeError("provider response must not escape")
        return ()


class PassingEntraValidator:
    def validate(self, target: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(UTC)
        return {
            "started_at": now,
            "completed_at": now,
            "health_state": "healthy",
            "credential_state": "passed",
            "account_id_observed": target["configuration"]["tenant_id"],
            "results": [],
            "summary": "Microsoft Entra validation passed.",
        }


class EntraRepositoryStub:
    def __init__(self):
        self.targets: dict[str, dict[str, Any]] = {}
        self.rows: dict[str, dict[str, Any]] = {}
        self.collection_jobs: dict[str, dict[str, Any]] = {}

    def create_connection(self, tenant_id: str, **values: Any) -> dict[str, Any]:
        connection_id = values["connection_id"]
        target = {
            "id": connection_id,
            "denali_tenant_id": tenant_id,
            "lifecycle_state": "active",
            **values,
        }
        self.targets[connection_id] = target
        self.rows[connection_id] = self._safe(target)
        return self.rows[connection_id]

    def list_connections(self, tenant_id: str) -> list[dict[str, Any]]:
        return [
            row
            for connection_id, row in self.rows.items()
            if self.targets[connection_id]["denali_tenant_id"] == tenant_id
        ]

    def get_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        if target is None or target["denali_tenant_id"] != tenant_id:
            return None
        return self.rows.get(connection_id)

    def get_connection_validation_target(
        self, tenant_id: str, connection_id: str
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        if target is None or target["denali_tenant_id"] != tenant_id:
            return None
        return target

    def resolve_tenant(self, clerk_organization_id: str) -> str:
        return AUTH_TENANTS[clerk_organization_id]

    def record_entra_consent_launch(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        launch: dict[str, Any],
        state_sha256: str,
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        if target is None or target["denali_tenant_id"] != tenant_id:
            return None
        target["credential_reference"]["consent_state_sha256"] = state_sha256
        target["configuration"]["onboarding"] = launch
        self.rows[connection_id] = self._safe(target)
        return self.rows[connection_id]

    def fail_entra_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_state_sha256: str,
        failed_at: datetime,
    ) -> bool:
        target = self.targets.get(connection_id)
        if (
            target is None
            or target["denali_tenant_id"] != tenant_id
            or target["credential_reference"].get(
            "consent_state_sha256"
            )
            != expected_state_sha256
        ):
            return False
        target["credential_reference"].pop("consent_state_sha256")
        target["configuration"]["onboarding"].update(
            {"status": "failed", "failed_at": failed_at.isoformat()}
        )
        self.rows[connection_id] = self._safe(target)
        return True

    def complete_entra_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_state_sha256: str,
        entra_tenant_id: str,
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        if (
            target is None
            or target["denali_tenant_id"] != tenant_id
            or target["credential_reference"].get(
            "consent_state_sha256"
            )
            != expected_state_sha256
        ):
            return None
        if target["configuration"]["tenant_id"] != entra_tenant_id:
            return None
        target["credential_reference"].pop("consent_state_sha256")
        target["configuration"]["onboarding"].update(
            {"status": "completed", "completed_at": completed_at.isoformat()}
        )
        target["coverage_plan"] = coverage_plan
        self.rows[connection_id] = self._safe(target)
        return self.rows[connection_id]

    def record_connection_validation(
        self, tenant_id: str, connection_id: str, validation: dict[str, Any]
    ) -> dict[str, Any] | None:
        row = self.rows.get(connection_id)
        target = self.targets.get(connection_id)
        if row is None or target is None or target["denali_tenant_id"] != tenant_id:
            return None
        row["health_state"] = validation["health_state"]
        row["last_validation"] = validation
        row["last_validated_at"] = validation["completed_at"].isoformat()
        return row

    def create_connection_collection_job(
        self, tenant_id: str, connection_id: str, *, collection_kind: str
    ) -> tuple[dict[str, Any], bool]:
        job_id = "44444444-4444-4444-8444-444444444444"
        job = self.collection_jobs.setdefault(
            job_id,
            {
                "id": job_id,
                "tenant_id": tenant_id,
                "connection_id": connection_id,
                "collection_kind": collection_kind,
                "state": "queued",
            },
        )
        return job, len(self.collection_jobs) == 1 and "modal_call_id" not in job

    def set_connection_collection_call_id(self, job_id: str, call_id: str) -> None:
        self.collection_jobs[job_id]["modal_call_id"] = call_id

    def record_connection_collection_failure(
        self, job_id: str, summary: str, *, max_attempts: int
    ) -> bool:
        self.collection_jobs[job_id].update(state="failed", error_summary=summary)
        return False

    def connection_collection_status(
        self, tenant_id: str, connection_id: str, *, collection_kind: str
    ) -> dict[str, Any]:
        active = next(
            (
                job
                for job in self.collection_jobs.values()
                if job["tenant_id"] == tenant_id
                and job["connection_id"] == connection_id
                and job["collection_kind"] == collection_kind
                and job["state"] in {"queued", "running"}
            ),
            None,
        )
        return {"state": "running" if active else "idle", "last_result": None}

    def disable_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        if target is None or target["denali_tenant_id"] != tenant_id:
            return None
        target["lifecycle_state"] = "disabled"
        self.rows[connection_id] = self._safe(target)
        self.rows[connection_id]["health_state"] = "disabled"
        return self.rows[connection_id]

    def delete_connection(self, tenant_id: str, connection_id: str) -> str:
        row = self.rows.get(connection_id)
        target = self.targets.get(connection_id)
        if row is None or target is None or target["denali_tenant_id"] != tenant_id:
            return "not_found"
        if row["lifecycle_state"] != "disabled":
            return "active"
        del self.rows[connection_id]
        del self.targets[connection_id]
        return "deleted"

    @staticmethod
    def _safe(target: dict[str, Any]) -> dict[str, Any]:
        return {
            "id": target["id"],
            "provider": "entra",
            "display_name": target["display_name"],
            "lifecycle_state": target["lifecycle_state"],
            "health_state": "unknown",
            "credential_reference": {
                "type": "entra_multitenant_app",
                "client_id": target["credential_reference"]["client_id"],
            },
            "declared_scopes": target["declared_scopes"],
            "coverage_plan": target["coverage_plan"],
            "configuration": target["configuration"],
            "last_validation": None,
            "last_validated_at": None,
        }


def _consent_client(graph: FakeGraph | None = None) -> EntraAdminConsentClient:
    return EntraAdminConsentClient(
        client_id=CLIENT_ID,
        client_secret="fixture-secret-never-persisted",
        callback_url="http://127.0.0.1:3080/api/v1/connections/entra/setup/callback",
        web_url="http://127.0.0.1:3080",
        token=lambda: "s" * 48,
        graph_client_factory=lambda _tenant_id: graph or FakeGraph(),
    )


def test_entra_launch_uses_tenant_specific_admin_consent_and_hashes_state() -> None:
    client = _consent_client()
    launch = client.create_launch(
        denali_tenant_id=DEFAULT_LOCAL_TENANT,
        connection_id="55555555-5555-4555-8555-555555555555",
        entra_tenant_id=ENTRA_TENANT_ID,
    )
    parsed = urlparse(launch["consent_url"])
    state = parse_qs(parsed.query)["state"][0]

    assert parsed.path == f"/{ENTRA_TENANT_ID}/v2.0/adminconsent"
    assert parse_qs(parsed.query)["scope"] == ["https://graph.microsoft.com/.default"]
    assert launch["state_sha256"] == hashlib.sha256(state.encode()).hexdigest()
    assert state not in str({key: value for key, value in launch.items() if key != "consent_url"})


def test_entra_operator_urls_reject_lookalike_local_hosts() -> None:
    with pytest.raises(ValueError, match="callback URL is invalid"):
        EntraAdminConsentClient(
            client_id=CLIENT_ID,
            client_secret="fixture-secret",
            callback_url="http://localhost.evil.example/callback",
            web_url="http://127.0.0.1:3080",
        )


def test_entra_api_rejects_a_partial_permission_bundle() -> None:
    app = create_app(
        repository=EntraRepositoryStub(),
        entra_consent_client=_consent_client(),
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/connections",
            json={
                "provider": "entra",
                "display_name": "Partial bundle",
                "tenant_id": ENTRA_TENANT_ID,
                "declared_scopes": ["entra.ai_applications"],
            },
        )

    assert response.status_code == 422
    assert "complete disclosed" in response.json()["detail"]


def test_entra_validator_reports_graph_planes_independently_without_provider_detail() -> None:
    graph = FakeGraph(failures={"/v1.0/auditLogs/signIns"})
    validator = EntraConnectionValidator(_consent_client(graph))
    connection = {
        "configuration": {
            "tenant_id": ENTRA_TENANT_ID,
            "onboarding": {"completed_at": datetime.now(UTC).isoformat()},
        },
        "coverage_plan": entra_coverage_plan(list(ENTRA_SCOPES), ENTRA_TENANT_ID),
    }

    result = validator.validate(connection)

    assert result["health_state"] == "partial"
    assert result["credential_state"] == "passed"
    failed = [item for item in result["results"] if item["state"] == "failed"]
    assert [item["plane"] for item in failed] == ["entra_ai_signins"]
    assert "provider response" not in str(result)


def test_entra_customer_lifecycle_create_consent_validate_collect_disable_delete() -> None:
    repository = EntraRepositoryStub()
    dispatched: list[str] = []
    app = create_app(
        repository=repository,
        entra_consent_client=_consent_client(),
        entra_connection_validator=PassingEntraValidator(),  # type: ignore[arg-type]
        collection_dispatcher=lambda job_id: dispatched.append(job_id) or "call-fixture",
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        created_response = client.post(
            "/v1/connections",
            json={
                "provider": "entra",
                "display_name": "Customer Entra",
                "tenant_id": ENTRA_TENANT_ID,
                "declared_scopes": list(ENTRA_SCOPES),
            },
        )
        assert created_response.status_code == 201
        created = created_response.json()
        connection_id = created["id"]
        assert created["coverage_plan"] == []
        assert created["setup_capabilities"]["entra_admin_consent"] is True
        assert "secret" not in str(created).casefold()

        assert client.post(f"/v1/connections/{connection_id}/validate").status_code == 409
        launch_response = client.post(
            f"/v1/connections/{connection_id}/entra/setup/launch"
        )
        assert launch_response.status_code == 201
        state = parse_qs(urlparse(launch_response.json()["consent_url"]).query)["state"][0]
        assert state not in str(repository.rows[connection_id])

        callback = client.get(
            "/v1/connections/entra/setup/callback",
            params={"state": state, "tenant": ENTRA_TENANT_ID, "admin_consent": "true"},
            follow_redirects=False,
        )
        assert callback.status_code == 303
        assert "entra_setup=succeeded" in callback.headers["location"]
        connected = client.get(f"/v1/connections/{connection_id}").json()
        assert connected["health_state"] == "healthy"
        assert len(connected["coverage_plan"]) == 6
        assert "consent_state" not in str(connected)

        replay = client.get(
            "/v1/connections/entra/setup/callback",
            params={"state": state, "tenant": ENTRA_TENANT_ID, "admin_consent": "true"},
            follow_redirects=False,
        )
        assert replay.status_code == 409

        collection = client.post(f"/v1/connections/{connection_id}/entra/collect")
        assert collection.status_code == 202
        assert dispatched == ["44444444-4444-4444-8444-444444444444"]

        blocked_disable = client.post(f"/v1/connections/{connection_id}/disable")
        repository.collection_jobs[dispatched[0]]["state"] = "succeeded"
        disabled = client.post(f"/v1/connections/{connection_id}/disable")
        assert blocked_disable.status_code == 409
        assert disabled.status_code == 200
        deleted = client.delete(
            f"/v1/connections/{connection_id}", params={"confirm": "Customer Entra"}
        )
        assert deleted.status_code == 204


def test_entra_callback_rejects_wrong_customer_tenant_and_consumes_state() -> None:
    repository = EntraRepositoryStub()
    app = create_app(
        repository=repository,
        entra_consent_client=_consent_client(),
        entra_connection_validator=PassingEntraValidator(),  # type: ignore[arg-type]
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        created = client.post(
            "/v1/connections",
            json={
                "provider": "entra",
                "display_name": "Wrong tenant fixture",
                "tenant_id": ENTRA_TENANT_ID,
            },
        ).json()
        launch = client.post(
            f"/v1/connections/{created['id']}/entra/setup/launch"
        ).json()
        state = parse_qs(urlparse(launch["consent_url"]).query)["state"][0]

        rejected = client.get(
            "/v1/connections/entra/setup/callback",
            params={
                "state": state,
                "tenant": OTHER_ENTRA_TENANT_ID,
                "admin_consent": "True",
            },
            follow_redirects=False,
        )
        replay = client.get(
            "/v1/connections/entra/setup/callback",
            params={"state": state, "tenant": ENTRA_TENANT_ID, "admin_consent": "True"},
            follow_redirects=False,
        )

    assert rejected.status_code == 303
    assert "entra_setup=failed" in rejected.headers["location"]
    assert replay.status_code == 409


def test_expired_entra_state_is_rejected() -> None:
    now = datetime.now(UTC)
    repository = EntraRepositoryStub()
    consent_client = EntraAdminConsentClient(
        client_id=CLIENT_ID,
        client_secret="fixture-secret-never-persisted",
        callback_url="http://127.0.0.1:3080/api/v1/connections/entra/setup/callback",
        web_url="http://127.0.0.1:3080",
        token=lambda: "x" * 48,
        now=lambda: now - timedelta(hours=1),
        graph_client_factory=lambda _tenant_id: FakeGraph(),
    )
    app = create_app(
        repository=repository,
        entra_consent_client=consent_client,
        entra_connection_validator=PassingEntraValidator(),  # type: ignore[arg-type]
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        created = client.post(
            "/v1/connections",
            json={
                "provider": "entra",
                "display_name": "Expired fixture",
                "tenant_id": ENTRA_TENANT_ID,
            },
        ).json()
        launch = client.post(
            f"/v1/connections/{created['id']}/entra/setup/launch"
        ).json()
        state = parse_qs(urlparse(launch["consent_url"]).query)["state"][0]
        response = client.get(
            "/v1/connections/entra/setup/callback",
            params={"state": state, "tenant": ENTRA_TENANT_ID, "admin_consent": "True"},
            follow_redirects=False,
        )

    assert response.status_code == 409
    assert response.json()["detail"] == "Microsoft Entra consent launch has expired"


def test_entra_mutations_require_admin_and_callback_uses_state_tenant() -> None:
    repository = EntraRepositoryStub()
    app = create_app(
        repository=repository,
        auth_mode="clerk",
        authenticator=HeaderAuthenticator(),
        entra_consent_client=_consent_client(),
        entra_connection_validator=PassingEntraValidator(),  # type: ignore[arg-type]
        migrate_on_start=False,
    )
    body = {
        "provider": "entra",
        "display_name": "Authenticated customer",
        "tenant_id": ENTRA_TENANT_ID,
    }
    with TestClient(app) as client:
        denied = client.post(
            "/v1/connections",
            json=body,
            headers={"Authorization": "Bearer alpha-member"},
        )
        created = client.post(
            "/v1/connections",
            json=body,
            headers={"Authorization": "Bearer alpha-admin"},
        )
        connection_id = created.json()["id"]
        cross_tenant = client.get(
            f"/v1/connections/{connection_id}",
            headers={"Authorization": "Bearer beta-admin"},
        )
        launch = client.post(
            f"/v1/connections/{connection_id}/entra/setup/launch",
            headers={"Authorization": "Bearer alpha-admin"},
        ).json()
        state = parse_qs(urlparse(launch["consent_url"]).query)["state"][0]
        callback = client.get(
            "/v1/connections/entra/setup/callback",
            params={"state": state, "tenant": ENTRA_TENANT_ID, "admin_consent": "True"},
            follow_redirects=False,
        )

    assert denied.status_code == 403
    assert created.status_code == 201
    assert cross_tenant.status_code == 404
    assert callback.status_code == 303
