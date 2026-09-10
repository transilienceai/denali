from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import yaml
from fastapi.testclient import TestClient

from denali.api.app import DEFAULT_LOCAL_TENANT, create_app
from denali.connections import (
    AWS_COVERAGE_AUTOMATIC,
    AWS_COVERAGE_SELECTED,
    AWS_SCOPE_AGENTCORE,
    AWS_SCOPE_BEDROCK_ACTIVITY,
    AWS_SCOPE_BEDROCK_AGENTS,
    AWS_SCOPE_BEDROCK_LOGGING,
    AWS_SCOPE_CODE_TO_CLOUD,
    AwsCloudFormationLauncher,
    AwsConnectionValidator,
    aws_connection_role_name,
    aws_coverage_plan,
    render_cloudformation,
)


class ConnectionRepositoryStub:
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
        return row

    def record_connection_launch(
        self, tenant_id: str, connection_id: str, launch: dict[str, Any]
    ) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        row = self.rows.get(connection_id)
        if target is None or row is None:
            return None
        target["configuration"]["onboarding"] = launch
        row["configuration"]["onboarding"] = launch
        return row

    def disable_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None:
        target = self.targets.get(connection_id)
        row = self.rows.get(connection_id)
        if target is None or row is None:
            return None
        target["lifecycle_state"] = "disabled"
        row["lifecycle_state"] = "disabled"
        row["health_state"] = "disabled"
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
            "provider": target["provider"],
            "display_name": target["display_name"],
            "lifecycle_state": target["lifecycle_state"],
            "health_state": "unknown",
            "credential_reference": {
                "type": target["credential_type"],
                "role_arn": target["credential_reference"]["role_arn"],
            },
            "declared_scopes": target["declared_scopes"],
            "coverage_plan": target["coverage_plan"],
            "configuration": target["configuration"],
            "last_validation": None,
        }


class PassingValidator:
    def validate(self, target: dict[str, Any]) -> dict[str, Any]:
        now = datetime.now(UTC)
        return {
            "started_at": now,
            "completed_at": now,
            "health_state": "healthy",
            "credential_state": "passed",
            "account_id_observed": target["configuration"]["account_id"],
            "results": [
                {
                    "scope": item["scope"],
                    "plane": item["plane"],
                    "label": item["label"],
                    "region": item["region"],
                    "state": "passed",
                    "detail": "Fixture validation succeeded.",
                }
                for item in target["coverage_plan"]
            ],
            "summary": "Credentials and every declared collection plane validated.",
        }


class EventuallyPassingValidator(PassingValidator):
    def __init__(self):
        self.calls = 0

    def validate(self, target: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        if self.calls > 1:
            return super().validate(target)
        now = datetime.now(UTC)
        return {
            "started_at": now,
            "completed_at": now,
            "health_state": "unhealthy",
            "credential_state": "failed",
            "account_id_observed": None,
            "results": [],
            "summary": "Role is not available yet.",
        }


class PassingAwsDeploymentCollector:
    def collect(
        self, *, tenant_id: str, connection: dict[str, Any], repository: Any
    ) -> dict[str, Any]:
        assert tenant_id == DEFAULT_LOCAL_TENANT
        return {
            "connection_id": str(connection["id"]),
            "state": "complete",
            "completed_at": datetime.now(UTC).isoformat(),
            "region_count": 1,
            "failed_count": 0,
            "partial_count": 0,
            "regions": [{"region": "us-east-1", "state": "complete", "assets": 4}],
        }


def test_aws_connection_collects_declared_evidence_scopes() -> None:
    repository = ConnectionRepositoryStub()
    app = create_app(
        repository=repository,
        connection_validator=PassingValidator(),  # type: ignore[arg-type]
        aws_deployment_collector=PassingAwsDeploymentCollector(),  # type: ignore[arg-type]
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        created = client.post(
            "/v1/connections",
            json={
                "provider": "aws",
                "display_name": "AWS deployments",
                "account_id": "123456789012",
                "coverage_mode": "selected",
                "regions": ["us-east-1"],
                "declared_scopes": [AWS_SCOPE_CODE_TO_CLOUD],
            },
        ).json()
        response = client.post(
            f"/v1/connections/{created['id']}/aws/collect-deployments"
        )
        assert response.status_code == 202
        detail = client.get(f"/v1/connections/{created['id']}").json()
        assert detail["deployment_collection_state"] == "idle"
        assert detail["last_deployment_collection"]["region_count"] == 1

        other = client.post(
            "/v1/connections",
            json={
                "provider": "aws",
                "display_name": "No deployment scope",
                "account_id": "210987654321",
                "coverage_mode": "selected",
                "regions": ["us-east-1"],
                "declared_scopes": [AWS_SCOPE_BEDROCK_LOGGING],
            },
        ).json()
        logging_collection = client.post(
            f"/v1/connections/{other['id']}/aws/collect-deployments"
        )
        assert logging_collection.status_code == 202


def test_aws_connections_in_one_account_receive_distinct_server_owned_role_names() -> None:
    repository = ConnectionRepositoryStub()
    app = create_app(repository=repository, migrate_on_start=False)
    payload = {
        "provider": "aws",
        "display_name": "AWS account",
        "account_id": "123456789012",
    }

    with TestClient(app) as client:
        first = client.post("/v1/connections", json=payload)
        second = client.post("/v1/connections", json=payload)
        client_named = client.post(
            "/v1/connections",
            json={**payload, "role_name": "SharedPhysicalRole"},
        )

    assert first.status_code == 201
    assert second.status_code == 201
    first_role = first.json()["configuration"]["role_name"]
    second_role = second.json()["configuration"]["role_name"]
    assert first_role == aws_connection_role_name(first.json()["id"])
    assert second_role == aws_connection_role_name(second.json()["id"])
    assert first_role != second_role
    assert len(first_role) <= 64
    assert len(second_role) <= 64
    assert client_named.status_code == 422


def test_aws_connection_api_never_returns_external_id_and_requires_safe_delete() -> None:
    repository = ConnectionRepositoryStub()
    app = create_app(
        repository=repository,
        connection_validator=PassingValidator(),  # type: ignore[arg-type]
        migrate_on_start=False,
    )
    with TestClient(app) as client:
        created_response = client.post(
            "/v1/connections",
            json={
                "provider": "aws",
                "display_name": "Production AWS",
                "account_id": "123456789012",
                "deployment_region": "ap-south-1",
                "coverage_mode": "automatic",
            },
        )
        assert created_response.status_code == 201
        created = created_response.json()
        connection_id = created["id"]
        role_name = aws_connection_role_name(connection_id)
        assert created["credential_reference"]["role_arn"].endswith(f":role/{role_name}")
        assert created["configuration"]["role_name"] == role_name
        assert "external_id" not in created_response.text
        assert created["configuration"]["deployment_region"] == "ap-south-1"
        assert created["configuration"]["coverage_mode"] == "automatic"
        assert created["configuration"]["regions"] == []
        assert created["setup_capabilities"]["cloudformation_quick_create"] is False
        assert len(created["coverage_plan"]) == 13

        listed = client.get("/v1/connections").json()["items"]
        assert listed == [created]
        assert "external_id" not in client.get(f"/v1/connections/{connection_id}").text

        template_response = client.get(
            f"/v1/connections/{connection_id}/aws/cloudformation.yaml"
        )
        assert template_response.status_code == 200
        assert "NoEcho: true" in template_response.text
        assert f"RoleName: '{role_name}'" in template_response.text
        assert "sts:AssumeRole" in template_response.text
        assert "ec2:DescribeRegions" in template_response.text
        assert "lambda:ListFunctions" in template_response.text
        assert "ecs:ListTaskDefinitionFamilies" in template_response.text
        assert "eks:ListClusters" in template_response.text
        assert "sagemaker:ListEndpoints" in template_response.text
        assert "iam:Create" not in template_response.text

        launch_response = client.post(
            f"/v1/connections/{connection_id}/aws/cloudformation/launch"
        )
        assert launch_response.status_code == 503
        assert "Download template" in launch_response.json()["detail"]

        validation_started = client.post(f"/v1/connections/{connection_id}/validate")
        assert validation_started.status_code == 202
        assert validation_started.json()["status"] == "started"
        validated = client.get(f"/v1/connections/{connection_id}").json()
        assert validated["health_state"] == "healthy"
        assert all(item["state"] == "passed" for item in validated["last_validation"]["results"])

        assert (
            client.delete(
                f"/v1/connections/{connection_id}", params={"confirm": "Production AWS"}
            ).status_code
            == 409
        )
        assert client.post(f"/v1/connections/{connection_id}/disable").status_code == 200
        assert (
            client.delete(
                f"/v1/connections/{connection_id}", params={"confirm": "wrong"}
            ).status_code
            == 409
        )
        assert (
            client.delete(
                f"/v1/connections/{connection_id}", params={"confirm": "Production AWS"}
            ).status_code
            == 204
        )


class FakeS3OnboardingClient:
    def __init__(self):
        self.put: dict[str, Any] | None = None
        self.presign: dict[str, Any] | None = None

    def put_object(self, **kwargs: Any) -> None:
        self.put = kwargs

    def generate_presigned_url(
        self, client_method: str, *, Params: dict[str, str], ExpiresIn: int
    ) -> str:
        self.presign = {
            "client_method": client_method,
            "Params": Params,
            "ExpiresIn": ExpiresIn,
        }
        return "https://denali-onboarding.s3.us-east-1.amazonaws.com/template.yaml?sig=fixture"


def test_aws_quick_create_uses_private_template_and_starts_bounded_validation() -> None:
    repository = ConnectionRepositoryStub()
    s3 = FakeS3OnboardingClient()
    validator = EventuallyPassingValidator()
    launcher = AwsCloudFormationLauncher(
        bucket_name="denali-onboarding",
        principal_arn="arn:aws:iam::999999999999:role/DenaliRuntime",
        s3_client=s3,
        expires_in_seconds=3600,
        now=lambda: datetime(2026, 8, 29, 12, 0, tzinfo=UTC),
        nonce=lambda: "one-time-object",
    )
    app = create_app(
        repository=repository,
        connection_validator=validator,  # type: ignore[arg-type]
        cloudformation_launcher=launcher,
        onboarding_validation_timeout_seconds=1,
        onboarding_validation_retry_seconds=0,
        migrate_on_start=False,
    )

    with TestClient(app) as client:
        created = client.post(
            "/v1/connections",
            json={
                "provider": "aws",
                "display_name": "Production AWS",
                "account_id": "123456789012",
                "deployment_region": "ap-south-1",
            },
        ).json()
        assert created["setup_capabilities"]["cloudformation_quick_create"] is True

        response = client.post(
            f"/v1/connections/{created['id']}/aws/cloudformation/launch"
        )
        assert response.status_code == 201
        assert response.headers["cache-control"] == "no-store"
        launch = response.json()
        assert launch["launch_url"].startswith(
            "https://ap-south-1.console.aws.amazon.com/cloudformation/home?region=ap-south-1"
        )
        assert "templateURL=https%3A%2F%2Fdenali-onboarding.s3" in launch["launch_url"]
        assert (
            "param_DenaliPrincipalArn=arn%3Aaws%3Aiam%3A%3A999999999999%3Arole%2FDenaliRuntime"
            in launch["launch_url"]
        )
        assert launch["stack_name"].startswith("Denali-")
        assert launch["validation_status"] == "started"
        assert "external_id" not in response.text

        assert s3.put is not None
        assert s3.put["Bucket"] == "denali-onboarding"
        assert s3.put["CacheControl"] == "no-store"
        assert s3.put["ServerSideEncryption"] == "AES256"
        assert s3.put["Key"].endswith("/one-time-object.yaml")
        assert b"NoEcho: true" in s3.put["Body"]
        assert s3.presign is not None
        assert s3.presign["ExpiresIn"] == 3600

        current = client.get(f"/v1/connections/{created['id']}").json()
        assert validator.calls == 2
        assert current["health_state"] == "healthy"
        onboarding = current["configuration"]["onboarding"]
        assert onboarding["method"] == "cloudformation_quick_create"
        assert onboarding["template_sha256"] == launch["template_sha256"]
        assert onboarding["principal_arn"].endswith(":role/DenaliRuntime")
        assert "external_id" not in str(onboarding)


def test_aws_connection_api_rejects_non_aws_and_invalid_region_scope() -> None:
    app = create_app(repository=ConnectionRepositoryStub(), migrate_on_start=False)
    with TestClient(app) as client:
        assert (
            client.post(
                "/v1/connections",
                json={"provider": "gcp", "display_name": "GCP", "account_id": "123456789012"},
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/v1/connections",
                json={
                    "display_name": "Bad region",
                    "account_id": "123456789012",
                    "coverage_mode": "selected",
                    "regions": ["moon-1"],
                },
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/v1/connections",
                json={
                    "display_name": "Empty selected coverage",
                    "account_id": "123456789012",
                    "coverage_mode": "selected",
                    "regions": [],
                },
            ).status_code
            == 422
        )
        assert (
            client.post(
                "/v1/connections",
                json={
                    "display_name": "Bad scope",
                    "account_id": "123456789012",
                    "declared_scopes": ["aws.everything"],
                },
            ).status_code
            == 422
        )


def test_cloudformation_contains_only_declared_and_bounded_future_permissions() -> None:
    connection = {
        "declared_scopes": [AWS_SCOPE_BEDROCK_AGENTS],
        "configuration": {"role_name": "DenaliSecurityAuditRole"},
        "credential_reference": {"external_id": "denali-fixture"},
    }
    template = render_cloudformation(connection)
    assert "bedrock:ListAgents" in template
    assert "ec2:DescribeRegions" in template
    assert "bedrock-agentcore:ListAgentRuntimes" not in template
    assert "cloudformation:ListStackResources" in template
    assert "lambda:InvokeFunction" not in template
    assert "ecs:RunTask" not in template
    assert "iam:PassRole" not in template
    document = yaml.compose(template)
    assert document is not None
    action_block = template.split("                Action:\n", 1)[1].split(
        "                Resource:", 1
    )[0]
    assert all(
        line.startswith("                  - ")
        for line in action_block.splitlines()
        if line.strip()
    )


class FakeClient:
    def __init__(self, operation: str, calls: list[str], *, failure: bool = False):
        self.operation = operation
        self.calls = calls
        self.failure = failure

    def __getattr__(self, name: str):
        def call(**kwargs: Any) -> dict[str, Any]:
            self.calls.append(f"{self.operation}.{name}")
            if self.failure:
                raise PermissionError("sensitive SDK message that must not persist")
            if name == "assume_role":
                return {
                    "Credentials": {
                        "AccessKeyId": "fixture",
                        "SecretAccessKey": "fixture-secret",
                        "SessionToken": "fixture-token",
                    }
                }
            if name == "get_caller_identity":
                return {"Account": "123456789012"}
            if name == "describe_regions":
                return {
                    "Regions": [
                        {"RegionName": "us-east-1", "OptInStatus": "opt-in-not-required"},
                        {"RegionName": "us-west-2", "OptInStatus": "opted-in"},
                        {"RegionName": "ap-east-1", "OptInStatus": "not-opted-in"},
                    ]
                }
            return {}

        return call


class FakeSession:
    def __init__(self, calls: list[str], *, failed_service: str | None = None):
        self.calls = calls
        self.failed_service = failed_service

    def client(self, service: str, **kwargs: Any) -> FakeClient:
        return FakeClient(service, self.calls, failure=service == self.failed_service)


def test_aws_validation_is_per_plane_and_reduces_sdk_errors() -> None:
    calls: list[str] = []
    sessions = [FakeSession(calls), FakeSession(calls, failed_service="cloudtrail")]

    def factory(**kwargs: Any) -> FakeSession:
        return sessions.pop(0)

    scopes = [
        AWS_SCOPE_BEDROCK_AGENTS,
        AWS_SCOPE_AGENTCORE,
        AWS_SCOPE_BEDROCK_ACTIVITY,
        AWS_SCOPE_BEDROCK_LOGGING,
        AWS_SCOPE_CODE_TO_CLOUD,
    ]
    connection = {
        "id": "11111111-1111-4111-8111-111111111111",
        "credential_reference": {
            "role_arn": "arn:aws:iam::123456789012:role/DenaliSecurityAuditRole",
            "external_id": "denali-fixture",
        },
        "declared_scopes": scopes,
        "configuration": {"account_id": "123456789012"},
        "coverage_plan": aws_coverage_plan(scopes, ["us-east-1"]),
    }
    validation = AwsConnectionValidator(factory, max_workers=1).validate(connection)

    assert validation["credential_state"] == "passed"
    assert validation["health_state"] == "partial"
    discovery = validation["results"][0]
    assert discovery["plane"] == "aws_region_discovery"
    assert discovery["discovered_regions"] == ["us-east-1", "us-west-2"]
    assert discovery["not_enabled_regions"] == ["ap-east-1"]
    states = {item["plane"]: item["state"] for item in validation["results"]}
    assert states["bedrock_management_activity"] == "failed"
    assert states["bedrock_agents"] == "passed"
    assert states["bedrock_guardrails"] == "passed"
    assert "sensitive SDK message" not in str(validation)
    assert "PermissionError" in str(validation)
    assert "bedrock-agent.list_agents" in calls
    assert "bedrock.list_guardrails" in calls
    assert "bedrock-agentcore-control.list_agent_runtimes" in calls
    assert "bedrock-agentcore-control.list_gateways" in calls
    assert "bedrock-agentcore-control.list_workload_identities" in calls
    assert "bedrock-agentcore-control.list_memories" in calls
    assert "cloudtrail.lookup_events" in calls
    assert "bedrock.get_model_invocation_logging_configuration" in calls
    assert "lambda.list_functions" in calls
    assert "ecs.list_task_definition_families" in calls
    assert "eks.list_clusters" in calls
    assert "sagemaker.list_endpoints" in calls
    assert "ec2.describe_regions" in calls


def test_selected_region_coverage_records_enabled_regions_outside_scope() -> None:
    calls: list[str] = []
    sessions = [FakeSession(calls), FakeSession(calls)]

    def factory(**kwargs: Any) -> FakeSession:
        return sessions.pop(0)

    connection = {
        "id": "11111111-1111-4111-8111-111111111111",
        "credential_reference": {
            "role_arn": "arn:aws:iam::123456789012:role/DenaliSecurityAuditRole",
            "external_id": "denali-fixture",
        },
        "declared_scopes": [AWS_SCOPE_BEDROCK_LOGGING],
        "configuration": {
            "account_id": "123456789012",
            "partition": "aws",
            "deployment_region": "us-east-1",
            "coverage_mode": AWS_COVERAGE_SELECTED,
            "regions": ["us-east-1"],
        },
        "coverage_plan": aws_coverage_plan([AWS_SCOPE_BEDROCK_LOGGING], ["us-east-1"]),
    }

    validation = AwsConnectionValidator(factory, max_workers=1).validate(connection)

    assert validation["health_state"] == "healthy"
    discovery = validation["results"][0]
    assert discovery["coverage_mode"] == AWS_COVERAGE_SELECTED
    assert discovery["excluded_enabled_regions"] == ["us-west-2"]
    regional_results = validation["results"][1:]
    assert {item["region"] for item in regional_results} == {"us-east-1"}


def test_automatic_region_discovery_failure_keeps_planes_unknown() -> None:
    calls: list[str] = []
    sessions = [FakeSession(calls), FakeSession(calls, failed_service="ec2")]

    def factory(**kwargs: Any) -> FakeSession:
        return sessions.pop(0)

    connection = {
        "id": "11111111-1111-4111-8111-111111111111",
        "credential_reference": {
            "role_arn": "arn:aws:iam::123456789012:role/DenaliSecurityAuditRole",
            "external_id": "denali-fixture",
        },
        "declared_scopes": [AWS_SCOPE_BEDROCK_LOGGING],
        "configuration": {
            "account_id": "123456789012",
            "coverage_mode": AWS_COVERAGE_AUTOMATIC,
            "deployment_region": "us-east-1",
            "regions": [],
        },
        "coverage_plan": aws_coverage_plan([AWS_SCOPE_BEDROCK_LOGGING], ["all-enabled"]),
    }

    validation = AwsConnectionValidator(factory, max_workers=1).validate(connection)

    assert validation["credential_state"] == "passed"
    assert validation["health_state"] == "partial"
    assert validation["results"][0]["state"] == "failed"
    assert validation["results"][1]["state"] == "unknown"
    assert validation["results"][1]["region"] == "all-enabled"
    assert "bedrock.get_model_invocation_logging_configuration" not in calls


class UnsupportedOperationError(Exception):
    response = {"Error": {"Code": "UnsupportedOperationException"}}


class UnsupportedBedrockClient:
    def __init__(self, calls: list[str]):
        self.calls = calls

    def get_model_invocation_logging_configuration(self) -> dict[str, Any]:
        self.calls.append("bedrock.get_model_invocation_logging_configuration")
        raise UnsupportedOperationError


class UnsupportedBedrockSession(FakeSession):
    def client(self, service: str, **kwargs: Any) -> Any:
        if service == "bedrock":
            return UnsupportedBedrockClient(self.calls)
        return super().client(service, **kwargs)


def test_unsupported_service_operation_is_visible_and_not_an_empty_result() -> None:
    calls: list[str] = []
    sessions = [FakeSession(calls), UnsupportedBedrockSession(calls)]

    def factory(**kwargs: Any) -> FakeSession:
        return sessions.pop(0)

    connection = {
        "id": "11111111-1111-4111-8111-111111111111",
        "credential_reference": {
            "role_arn": "arn:aws:iam::123456789012:role/DenaliSecurityAuditRole",
            "external_id": "denali-fixture",
        },
        "declared_scopes": [AWS_SCOPE_BEDROCK_LOGGING],
        "configuration": {
            "account_id": "123456789012",
            "coverage_mode": AWS_COVERAGE_AUTOMATIC,
            "deployment_region": "us-east-1",
            "regions": [],
        },
        "coverage_plan": aws_coverage_plan([AWS_SCOPE_BEDROCK_LOGGING], ["all-enabled"]),
    }

    validation = AwsConnectionValidator(factory, max_workers=1).validate(connection)

    assert validation["health_state"] == "healthy"
    plane_results = validation["results"][1:]
    assert {item["state"] for item in plane_results} == {"not_applicable"}
    assert all("UnsupportedOperationException" in item["detail"] for item in plane_results)
    assert "not applicable" in validation["summary"]


def test_parallel_validation_preserves_declared_result_order() -> None:
    calls: list[str] = []
    sessions_created = 0

    def factory(**kwargs: Any) -> FakeSession:
        nonlocal sessions_created
        sessions_created += 1
        return FakeSession(calls)

    connection = {
        "id": "11111111-1111-4111-8111-111111111111",
        "credential_reference": {
            "role_arn": "arn:aws:iam::123456789012:role/DenaliSecurityAuditRole",
            "external_id": "denali-fixture",
        },
        "declared_scopes": [AWS_SCOPE_BEDROCK_LOGGING],
        "configuration": {
            "account_id": "123456789012",
            "coverage_mode": AWS_COVERAGE_AUTOMATIC,
            "deployment_region": "us-east-1",
            "regions": [],
        },
        "coverage_plan": aws_coverage_plan([AWS_SCOPE_BEDROCK_LOGGING], ["all-enabled"]),
    }

    validation = AwsConnectionValidator(factory, max_workers=2).validate(connection)

    assert validation["health_state"] == "healthy"
    assert [item["region"] for item in validation["results"][1:]] == [
        "us-east-1",
        "us-west-2",
    ]
    assert sessions_created >= 3


def test_failed_agentcore_probe_outside_documented_regions_is_not_applicable() -> None:
    validator = AwsConnectionValidator(max_workers=1)
    result = validator._validate_plane(
        FakeSession([], failed_service="bedrock-agentcore-control"),
        {
            "scope": AWS_SCOPE_AGENTCORE,
            "plane": "agentcore_runtimes",
            "label": "AgentCore runtime inventory",
            "region": "ap-northeast-3",
        },
        {"partition": "aws"},
    )

    assert result["state"] == "not_applicable"
    assert "does not document" in result["detail"]
