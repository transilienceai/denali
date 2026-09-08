from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from denali.api.app import DEFAULT_LOCAL_TENANT, create_app
from denali.connections import (
    AZURE_SCOPE_CODE_TO_CLOUD,
    AZURE_SCOPES,
    AzureConnectionValidator,
    AzureSetupScriptLauncher,
    azure_coverage_plan,
)

TENANT_ID = "11111111-1111-4111-8111-111111111111"
CLIENT_ID = "22222222-2222-4222-8222-222222222222"
SERVICE_PRINCIPAL_ID = "33333333-3333-4333-8333-333333333333"
SUBSCRIPTION_ONE = "44444444-4444-4444-8444-444444444444"
SUBSCRIPTION_TWO = "55555555-5555-4555-8555-555555555555"
SETUP_TOKEN = "azure-setup-token-fixture-with-enough-entropy"


class AzureConnectionRepositoryStub:
    def __init__(self):
        self.targets: dict[str, dict[str, Any]] = {}
        self.rows: dict[str, dict[str, Any]] = {}

    def create_connection(self, tenant_id: str, **values: Any) -> dict[str, Any]:
        assert tenant_id == DEFAULT_LOCAL_TENANT
        connection_id = values["connection_id"]
        target = {"id": connection_id, "lifecycle_state": "active", **values}
        self.targets[connection_id] = target
        self.rows[connection_id] = self._safe(target)
        return self.rows[connection_id]

    def list_connections(self, tenant_id: str) -> list[dict[str, Any]]:
        return list(self.rows.values())

    def get_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None:
        return self.rows.get(connection_id)

    def get_connection_validation_target(
        self, tenant_id: str, connection_id: str
    ) -> dict[str, Any] | None:
        return self.targets.get(connection_id)

    def record_connection_validation(
        self, tenant_id: str, connection_id: str, validation: dict[str, Any]
    ) -> dict[str, Any] | None:
        row = self.rows.get(connection_id)
        if row is None:
            return None
        row["health_state"] = validation["health_state"]
        row["last_validation"] = validation
        row["last_validated_at"] = validation["completed_at"].isoformat()
        return row

    def record_connection_launch(
        self, tenant_id: str, connection_id: str, launch: dict[str, Any]
    ) -> dict[str, Any] | None:
        raise AssertionError("AWS launch must not be used for Azure")

    def record_connection_setup_launch(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        launch: dict[str, Any],
        setup_token_sha256: str,
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        row = self.rows.get(connection_id)
        if target is None or row is None:
            return None
        target["credential_reference"]["setup_token_sha256"] = setup_token_sha256
        target["configuration"]["onboarding"] = launch
        row["configuration"]["onboarding"] = launch
        return row

    def complete_azure_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_setup_token_sha256: str,
        service_principal_id: str,
        subscriptions: list[dict[str, str]],
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        row = self.rows.get(connection_id)
        if target is None or row is None:
            return None
        if target["credential_reference"].get("setup_token_sha256") != expected_setup_token_sha256:
            return None
        target["credential_reference"].pop("setup_token_sha256", None)
        target["credential_reference"]["service_principal_id"] = service_principal_id
        target["configuration"]["subscriptions"] = subscriptions
        target["configuration"]["onboarding"]["completed_at"] = completed_at.isoformat()
        target["coverage_plan"] = coverage_plan
        row["credential_reference"]["service_principal_id"] = service_principal_id
        row["configuration"] = target["configuration"]
        row["coverage_plan"] = coverage_plan
        return row

    def disable_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None:
        row = self.rows.get(connection_id)
        if row is None:
            return None
        row["lifecycle_state"] = "disabled"
        row["health_state"] = "disabled"
        self.targets[connection_id]["lifecycle_state"] = "disabled"
        return row

    def delete_connection(self, tenant_id: str, connection_id: str) -> str:
        row = self.rows.get(connection_id)
        if row is None:
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
            "provider": "azure",
            "display_name": target["display_name"],
            "lifecycle_state": target["lifecycle_state"],
            "health_state": "unknown",
            "credential_reference": {
                "type": "azure_multitenant_app",
                "client_id": target["credential_reference"]["client_id"],
            },
            "declared_scopes": target["declared_scopes"],
            "coverage_plan": target["coverage_plan"],
            "configuration": target["configuration"],
            "last_validation": None,
            "last_validated_at": None,
        }


class FakeS3OnboardingClient:
    def __init__(self):
        self.put: dict[str, Any] | None = None

    def put_object(self, **kwargs: Any) -> None:
        self.put = kwargs

    def generate_presigned_url(
        self, client_method: str, *, Params: dict[str, str], ExpiresIn: int
    ) -> str:
        return "https://templates.example.test/azure.sh?signature=fixture"


class PassingAzureValidator:
    def validate(self, target: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(UTC)
        return {
            "started_at": now,
            "completed_at": now,
            "health_state": "healthy",
            "credential_state": "passed",
            "account_id_observed": ",".join(
                item["id"] for item in target["configuration"]["subscriptions"]
            ),
            "results": [
                {
                    "scope": item["scope"],
                    "plane": item["plane"],
                    "label": item["label"],
                    "region": item["region"],
                    "subscription_id": item["subscription_id"],
                    "state": "passed",
                    "detail": "Fixture Azure validation succeeded.",
                }
                for item in target["coverage_plan"]
            ],
            "summary": "Azure subscriptions and every declared plane validated.",
        }


class PropagatingAzureValidator(PassingAzureValidator):
    def __init__(self):
        self.calls = 0

    def validate(self, target: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        validation = super().validate(target)
        if self.calls == 1:
            validation["health_state"] = "partial"
            validation["results"][0].update(
                state="failed",
                detail="Validation call failed (AccessDenied).",
            )
            validation["summary"] = "Azure Reader assignment is still propagating."
        return validation


class PassingAzureDeploymentCollector:
    def collect(
        self, *, tenant_id: str, connection: dict[str, Any], repository: Any
    ) -> dict[str, Any]:
        assert tenant_id == DEFAULT_LOCAL_TENANT
        assert connection["provider"] == "azure"
        return {
            "connection_id": connection["id"],
            "state": "complete",
            "completed_at": datetime.now(UTC).isoformat(),
            "subscription_count": len(connection["configuration"]["subscriptions"]),
            "failed_count": 0,
            "partial_count": 0,
            "subscriptions": [
                {
                    "subscription_id": item["id"],
                    "state": "complete",
                    "assets": 3,
                    "ai_workloads": 1,
                }
                for item in connection["configuration"]["subscriptions"]
            ],
        }


def _completion_code(subscriptions: list[dict[str, str]]) -> str:
    payload = json.dumps(
        {
            "token": SETUP_TOKEN,
            "tenant_id": TENANT_ID,
            "service_principal_id": SERVICE_PRINCIPAL_ID,
            "subscriptions": subscriptions,
        },
        separators=(",", ":"),
    ).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def test_azure_setup_enumerates_then_binds_only_selected_subscriptions() -> None:
    repository = AzureConnectionRepositoryStub()
    s3 = FakeS3OnboardingClient()
    validator = PropagatingAzureValidator()
    launcher = AzureSetupScriptLauncher(
        bucket_name="denali-onboarding",
        client_id=CLIENT_ID,
        s3_client=s3,
        now=lambda: datetime.now(UTC),
        nonce=lambda: "one-time-script",
        token=lambda: SETUP_TOKEN,
        tenant_identity_verifier=lambda tenant_id: None,
    )
    app = create_app(
        repository=repository,
        azure_connection_validator=validator,  # type: ignore[arg-type]
        azure_deployment_collector=PassingAzureDeploymentCollector(),  # type: ignore[arg-type]
        azure_setup_launcher=launcher,
        onboarding_validation_retry_seconds=0,
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        created_response = client.post(
            "/v1/connections",
            json={
                "provider": "azure",
                "display_name": "Production Azure",
                "tenant_id": TENANT_ID,
            },
        )
        assert created_response.status_code == 201
        created = created_response.json()
        connection_id = created["id"]
        assert created["coverage_plan"] == []
        assert created["configuration"]["subscriptions"] == []
        assert created["setup_capabilities"]["azure_cloud_shell"] is True
        assert "setup_token" not in created_response.text

        assert client.post(f"/v1/connections/{connection_id}/validate").status_code == 409
        launch_response = client.post(
            f"/v1/connections/{connection_id}/azure/setup/launch"
        )
        assert launch_response.status_code == 201
        launch = launch_response.json()
        assert launch["cloud_shell_url"] == "https://shell.azure.com/bash"
        assert launch["identity_prepared_in_script"] is True
        assert "consent_url" not in launch
        assert "denali-azure-onboard.sh" in launch["setup_command"]
        assert SETUP_TOKEN not in launch_response.text
        assert launch_response.headers["cache-control"] == "no-store"
        assert s3.put is not None
        script = s3.put["Body"].decode()
        assert "az account list --all" in script
        assert 'az ad sp create --id "$DENALI_CLIENT_ID"' in script
        assert "Select subscriptions by number" in script
        assert "--assignee-principal-type ServicePrincipal" in script
        assert "--role 'acdd72a7-3385-48ef-bd42-f606fba81ae7'" not in script
        assert "DENALI_READER_ROLE_ID='acdd72a7-3385-48ef-bd42-f606fba81ae7'" in script

        subscriptions = [
            {"id": SUBSCRIPTION_ONE, "name": "Production"},
            {"id": SUBSCRIPTION_TWO, "name": "AI Lab"},
        ]
        completed = client.post(
            f"/v1/connections/{connection_id}/azure/setup/complete",
            json={"completion_code": f"DENALI_SETUP_COMPLETE={_completion_code(subscriptions)}"},
        )
        assert completed.status_code == 202

        collection = client.post(
            f"/v1/connections/{connection_id}/azure/collect-deployments"
        )
        assert collection.status_code == 202
        refreshed = client.get(f"/v1/connections/{connection_id}").json()
        assert refreshed["deployment_collection_state"] == "idle"
        assert refreshed["last_deployment_collection"]["state"] == "complete"
        assert refreshed["last_deployment_collection"]["subscription_count"] == 2
        detail = client.get(f"/v1/connections/{connection_id}").json()
        assert detail["health_state"] == "healthy"
        assert validator.calls == 2
        assert detail["configuration"]["subscriptions"] == subscriptions
        assert len(detail["coverage_plan"]) == 8 * len(subscriptions)
        assert len(detail["last_validation"]["results"]) == 8 * len(subscriptions)
        assert "setup_token" not in json.dumps(detail)
        assert (
            client.post(
                f"/v1/connections/{connection_id}/azure/setup/complete",
                json={"completion_code": _completion_code(subscriptions)},
            ).status_code
            == 409
        )
        repository.targets[connection_id]["declared_scopes"] = [
            scope for scope in AZURE_SCOPES if scope != AZURE_SCOPE_CODE_TO_CLOUD
        ]
        ai_scope_collection = client.post(
            f"/v1/connections/{connection_id}/azure/collect-deployments"
        )
        assert ai_scope_collection.status_code == 202


def test_azure_completion_requires_verified_tenant_identity() -> None:
    repository = AzureConnectionRepositoryStub()

    def fail_verification(_tenant_id: str) -> None:
        raise RuntimeError("enterprise application unavailable")

    launcher = AzureSetupScriptLauncher(
        bucket_name="denali-onboarding",
        client_id=CLIENT_ID,
        s3_client=FakeS3OnboardingClient(),
        token=lambda: SETUP_TOKEN,
        tenant_identity_verifier=fail_verification,
    )
    app = create_app(
        repository=repository,
        azure_setup_launcher=launcher,
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        created = client.post(
            "/v1/connections",
            json={"provider": "azure", "display_name": "Verify tenant", "tenant_id": TENANT_ID},
        ).json()
        launched = client.post(f"/v1/connections/{created['id']}/azure/setup/launch")
        assert launched.status_code == 201
        completion = client.post(
            f"/v1/connections/{created['id']}/azure/setup/complete",
            json={
                "completion_code": _completion_code(
                    [{"id": SUBSCRIPTION_ONE, "name": "Production"}]
                )
            },
        )

    assert completion.status_code == 409
    assert completion.json()["detail"] == (
        "Denali could not verify its enterprise application in the Azure tenant"
    )
    assert repository.targets[created["id"]]["configuration"]["subscriptions"] == []
    assert "setup_token_sha256" in repository.targets[created["id"]]["credential_reference"]


class FakeToken:
    token = "azure-access-token"


class FakeCredential:
    def get_token(self, *scopes: str, **kwargs: Any) -> FakeToken:
        return FakeToken()


class FakeResponse:
    def __init__(self, payload: dict[str, Any], error: Exception | None = None):
        self.payload = payload
        self.error = error

    def raise_for_status(self) -> None:
        if self.error:
            raise self.error

    def json(self) -> dict[str, Any]:
        return self.payload


def test_azure_validation_is_subscription_specific_and_all_locations() -> None:
    subscriptions = [
        {"id": SUBSCRIPTION_ONE, "name": "Production"},
        {"id": SUBSCRIPTION_TWO, "name": "AI Lab"},
    ]
    requests: list[tuple[str, str, dict[str, Any]]] = []

    def request(method: str, url: str, **kwargs: Any) -> FakeResponse:
        requests.append((method, url, kwargs))
        if "/subscriptions/" in url and "/providers/" not in url:
            subscription_id = url.rsplit("/", 1)[1]
            return FakeResponse({"subscriptionId": subscription_id, "tenantId": TENANT_ID})
        return FakeResponse({"data": []})

    validator = AzureConnectionValidator(
        credential_factory=lambda tenant_id: FakeCredential(),
        request=request,
    )
    connection = {
        "id": "66666666-6666-4666-8666-666666666666",
        "provider": "azure",
        "declared_scopes": list(AZURE_SCOPES),
        "configuration": {"tenant_id": TENANT_ID, "subscriptions": subscriptions},
        "coverage_plan": azure_coverage_plan(list(AZURE_SCOPES), subscriptions),
    }
    validation = validator.validate(connection)
    assert validation["health_state"] == "healthy"
    assert validation["credential_state"] == "passed"
    assert len(validation["results"]) == 16
    assert all(item["region"] == "all-locations" for item in validation["results"])
    graph_calls = [item for item in requests if "ResourceGraph" in item[1]]
    assert len(graph_calls) == 14
    assert all(len(item[2]["json"]["subscriptions"]) == 1 for item in graph_calls)
