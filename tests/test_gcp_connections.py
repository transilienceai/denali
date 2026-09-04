from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from denali.api.app import DEFAULT_LOCAL_TENANT, create_app
from denali.connections import (
    GCP_SCOPES,
    GcpConnectionPrincipalProvisioner,
    GcpConnectionValidator,
    GcpSetupScriptLauncher,
    gcp_coverage_plan,
)
from denali.connections.gcp import _gcp_error_code

PRINCIPAL_EMAIL = "denali-audit@denali-operator.iam.gserviceaccount.com"
PROJECT_ONE = "production-ai-12345"
PROJECT_TWO = "ai-lab-67890"
SETUP_TOKEN = "gcp-setup-token-fixture-with-enough-entropy"


class GcpConnectionRepositoryStub:
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

    def record_gcp_connection_setup_launch(
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

    def complete_gcp_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_setup_token_sha256: str,
        projects: list[dict[str, str]],
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        row = self.rows.get(connection_id)
        if target is None or row is None:
            return None
        if target["credential_reference"].get("setup_token_sha256") != (
            expected_setup_token_sha256
        ):
            return None
        target["credential_reference"].pop("setup_token_sha256", None)
        target["configuration"]["projects"] = projects
        target["configuration"]["onboarding"]["completed_at"] = completed_at.isoformat()
        target["coverage_plan"] = coverage_plan
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
            "provider": "gcp",
            "display_name": target["display_name"],
            "lifecycle_state": target["lifecycle_state"],
            "health_state": "unknown",
            "credential_reference": {
                "type": "gcp_service_account",
                "principal_email": target["credential_reference"]["principal_email"],
                "principal_unique_id": target["credential_reference"][
                    "principal_unique_id"
                ],
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
        return "https://templates.example.test/gcp.sh?signature=fixture"


class FakeGcpPrincipalProvisioner:
    operator_project_id = "denali-operator"

    def __init__(self):
        self.calls: list[dict[str, str]] = []

    def create_principal(self, *, connection_id: str, display_name: str) -> dict[str, str]:
        self.calls.append({"connection_id": connection_id, "display_name": display_name})
        return {
            "principal_email": PRINCIPAL_EMAIL,
            "principal_unique_id": "112233445566778899001",
        }


class PassingGcpValidator:
    def validate(self, target: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(UTC)
        return {
            "started_at": now,
            "completed_at": now,
            "health_state": "healthy",
            "credential_state": "passed",
            "account_id_observed": ",".join(
                item["id"] for item in target["configuration"]["projects"]
            ),
            "results": [
                {
                    "scope": item["scope"],
                    "plane": item["plane"],
                    "label": item["label"],
                    "region": item["region"],
                    "project_id": item["project_id"],
                    "project_name": item["project_name"],
                    "state": "passed",
                    "detail": "Fixture Google Cloud validation succeeded.",
                }
                for item in target["coverage_plan"]
            ],
            "summary": "Google Cloud projects and every declared plane validated.",
        }


class PassingGcpDeploymentCollector:
    def __init__(self):
        self.calls: list[tuple[str, str]] = []

    def collect(self, *, tenant_id: str, connection: dict[str, Any], repository: Any):
        self.calls.append((tenant_id, connection["id"]))
        now = datetime.now(UTC).isoformat()
        return {
            "connection_id": connection["id"],
            "state": "complete",
            "completed_at": now,
            "project_count": len(connection["configuration"]["projects"]),
            "failed_count": 0,
            "partial_count": 0,
            "projects": [],
        }


def _completion_code(projects: list[dict[str, str]]) -> str:
    payload = json.dumps(
        {
            "token": SETUP_TOKEN,
            "principal_email": PRINCIPAL_EMAIL,
            "projects": projects,
        },
        separators=(",", ":"),
    ).encode()
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def test_gcp_setup_selects_projects_without_customer_credentials() -> None:
    repository = GcpConnectionRepositoryStub()
    s3 = FakeS3OnboardingClient()
    launcher = GcpSetupScriptLauncher(
        bucket_name="denali-onboarding",
        s3_client=s3,
        now=lambda: datetime.now(UTC),
        nonce=lambda: "one-time-script",
        token=lambda: SETUP_TOKEN,
    )
    provisioner = FakeGcpPrincipalProvisioner()
    deployment_collector = PassingGcpDeploymentCollector()
    app = create_app(
        repository=repository,
        gcp_connection_validator=PassingGcpValidator(),  # type: ignore[arg-type]
        gcp_principal_provisioner=provisioner,  # type: ignore[arg-type]
        gcp_setup_launcher=launcher,
        gcp_deployment_collector=deployment_collector,  # type: ignore[arg-type]
        onboarding_validation_retry_seconds=0,
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        created_response = client.post(
            "/v1/connections",
            json={"provider": "gcp", "display_name": "Production GCP"},
        )
        assert created_response.status_code == 201
        created = created_response.json()
        connection_id = created["id"]
        assert created["coverage_plan"] == []
        assert created["configuration"]["projects"] == []
        assert created["credential_reference"]["principal_unique_id"] == (
            "112233445566778899001"
        )
        assert provisioner.calls == [
            {"connection_id": connection_id, "display_name": "Production GCP"}
        ]
        assert created["setup_capabilities"]["gcp_cloud_shell"] is True
        assert "setup_token" not in created_response.text
        assert client.post(f"/v1/connections/{connection_id}/validate").status_code == 409

        launch_response = client.post(f"/v1/connections/{connection_id}/gcp/setup/launch")
        assert launch_response.status_code == 201
        launch = launch_response.json()
        assert launch["cloud_shell_url"].startswith("https://shell.cloud.google.com/")
        assert "denali-gcp-onboard.sh" in launch["setup_command"]
        assert SETUP_TOKEN not in launch_response.text
        assert launch_response.headers["cache-control"] == "no-store"
        assert s3.put is not None
        script = s3.put["Body"].decode()
        assert "gcloud projects list" in script
        assert "Select projects by number" in script
        assert "roles/cloudasset.viewer" in script
        assert "roles/logging.viewer" in script
        assert "cloudasset.googleapis.com" in script
        assert "logging.googleapis.com" in script
        assert "gcloud services enable" in script
        assert "service account key" not in script.lower()

        projects = [
            {"id": PROJECT_ONE, "name": "Production", "number": "123456789012"},
            {"id": PROJECT_TWO, "name": "AI Lab", "number": "210987654321"},
        ]
        completed = client.post(
            f"/v1/connections/{connection_id}/gcp/setup/complete",
            json={
                "completion_code": (
                    f"DENALI_GCP_SETUP_COMPLETE={_completion_code(projects)}"
                )
            },
        )
        assert completed.status_code == 202
        detail = client.get(f"/v1/connections/{connection_id}").json()
        assert detail["health_state"] == "healthy"
        assert detail["configuration"]["projects"] == projects
        assert len(detail["coverage_plan"]) == 6 * len(projects)
        assert len(detail["last_validation"]["results"]) == 6 * len(projects)
        assert "setup_token" not in json.dumps(detail)
        collected = client.post(
            f"/v1/connections/{connection_id}/gcp/collect-deployments"
        )
        assert collected.status_code == 202
        assert collected.json()["status"] == "started"
        after_collection = client.get(f"/v1/connections/{connection_id}").json()
        assert after_collection["deployment_collection_state"] == "idle"
        assert after_collection["last_deployment_collection"]["state"] == "complete"
        assert deployment_collector.calls == [(DEFAULT_LOCAL_TENANT, connection_id)]
        replay = client.post(
            f"/v1/connections/{connection_id}/gcp/setup/complete",
            json={"completion_code": _completion_code(projects)},
        )
        assert replay.status_code == 409


def test_gcp_principal_provisioning_creates_a_unique_keyless_service_account() -> None:
    requests: list[tuple[str, str, dict[str, Any]]] = []

    def request(method: str, url: str, **kwargs: Any) -> FakeResponse:
        requests.append((method, url, kwargs))
        account_id = kwargs["json"]["accountId"]
        return FakeResponse(
            {
                "email": f"{account_id}@denali-operator.iam.gserviceaccount.com",
                "uniqueId": "112233445566778899001",
            }
        )

    provisioner = GcpConnectionPrincipalProvisioner(
        operator_project_id="denali-operator",
        credential_factory=lambda: FakeCredential(),  # type: ignore[arg-type]
        request=request,  # type: ignore[arg-type]
    )
    principal = provisioner.create_principal(
        connection_id="12345678-1234-5678-90ab-1234567890ab",
        display_name="Production GCP",
    )
    second_principal = provisioner.create_principal(
        connection_id="abcdefab-cdef-4abc-8def-abcdefabcdef",
        display_name="Research GCP",
    )

    assert principal == {
        "principal_email": (
            "denali-123456781234567890ab@denali-operator.iam.gserviceaccount.com"
        ),
        "principal_unique_id": "112233445566778899001",
    }
    method, url, kwargs = requests[0]
    assert method == "POST"
    assert url.endswith("/projects/denali-operator/serviceAccounts")
    assert kwargs["json"]["accountId"] == "denali-123456781234567890ab"
    assert set(kwargs["json"]) == {"accountId", "serviceAccount"}
    assert set(kwargs["json"]["serviceAccount"]) == {"displayName", "description"}
    assert second_principal["principal_email"] == (
        "denali-abcdefabcdef4abc8def@denali-operator.iam.gserviceaccount.com"
    )
    assert second_principal["principal_email"] != principal["principal_email"]


class FakeCredential:
    pass


class FakeResponse:
    def __init__(self, payload: dict[str, Any], error: Exception | None = None):
        self.payload = payload
        self.error = error

    def raise_for_status(self) -> None:
        if self.error:
            raise self.error

    def json(self) -> dict[str, Any]:
        return self.payload


class FakeHttpError(RuntimeError):
    def __init__(self, payload: dict[str, Any]):
        super().__init__("provider payload must not be exposed")
        self.response = FakeResponse(payload)


def test_gcp_error_prefers_safe_provider_reason_over_generic_status() -> None:
    error = FakeHttpError(
        {
            "error": {
                "code": 403,
                "status": "PERMISSION_DENIED",
                "details": [
                    {
                        "@type": "type.googleapis.com/google.rpc.ErrorInfo",
                        "reason": "SERVICE_DISABLED",
                        "metadata": {"consumer": "projects/secret-customer-project"},
                    }
                ],
            }
        }
    )

    assert _gcp_error_code(error) == "SERVICE_DISABLED"


def test_gcp_validation_is_project_specific_and_all_locations() -> None:
    projects = [
        {"id": PROJECT_ONE, "name": "Production", "number": "123456789012"},
        {"id": PROJECT_TWO, "name": "AI Lab", "number": "210987654321"},
    ]
    requests: list[tuple[str, str, dict[str, Any]]] = []

    def request(method: str, url: str, **kwargs: Any) -> FakeResponse:
        requests.append((method, url, kwargs))
        if "cloudresourcemanager" in url:
            project_id = url.rsplit("/", 1)[1]
            project = next(item for item in projects if item["id"] == project_id)
            return FakeResponse(
                {"projectId": project_id, "name": f"projects/{project['number']}"}
            )
        return FakeResponse({"results": []})

    validator = GcpConnectionValidator(
        credential_factory=lambda principal: FakeCredential(),
        request=request,
    )
    connection = {
        "id": "66666666-6666-4666-8666-666666666666",
        "provider": "gcp",
        "credential_reference": {"principal_email": PRINCIPAL_EMAIL},
        "declared_scopes": list(GCP_SCOPES),
        "configuration": {"projects": projects},
        "coverage_plan": gcp_coverage_plan(list(GCP_SCOPES), projects),
    }
    validation = validator.validate(connection)
    assert validation["health_state"] == "healthy"
    assert validation["credential_state"] == "passed"
    assert len(validation["results"]) == 12
    assert all(item["region"] == "all-locations" for item in validation["results"])
    asset_calls = [item for item in requests if "cloudasset" in item[1]]
    logging_calls = [item for item in requests if "logging" in item[1]]
    assert len(asset_calls) == 10
    assert len(logging_calls) == 2
    assert all("projects/" in item[1] for item in asset_calls)
    resource_calls = [
        item for item in asset_calls if ("contentType", "RESOURCE") in item[2]["params"]
    ]
    assert len(resource_calls) == 2
