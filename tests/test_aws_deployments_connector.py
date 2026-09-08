from __future__ import annotations

from typing import Any

from denali.connectors.aws_deployments import (
    AwsConnectionDeploymentCollector,
    AwsDeploymentConnector,
    _agentcore_batch,
    _bedrock_logging_batch,
)
from denali.domain import AssetKind, CoverageState, RelationshipKind


class LambdaClient:
    def list_functions(self, **kwargs: Any) -> dict[str, Any]:
        return {"Functions": [{"FunctionName": "agent"}, {"FunctionName": "ordinary"}]}

    def get_function_configuration(self, *, FunctionName: str) -> dict[str, Any]:
        return {
            "FunctionName": FunctionName,
            "FunctionArn": f"arn:aws:lambda:us-east-1:123456789012:function:{FunctionName}",
            "Role": "arn:aws:iam::123456789012:role/lambda-role",
            "Runtime": "python3.13",
            "Environment": {
                "Variables": {
                    "BEDROCK_MODEL_ID": "global.anthropic.claude-sonnet-4-5-v1:0",
                    "API_TOKEN": "never-retained",
                }
                if FunctionName == "agent"
                else {"LOG_LEVEL": "debug"}
            },
        }

    def list_tags(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "Tags": {
                "aws:cloudformation:logical-id": "AgentFunctionA1B2C3D4",
            }
        }


class EcsClient:
    def list_task_definition_families(self, **kwargs: Any) -> dict[str, Any]:
        return {"families": ["worker"]}

    def describe_task_definition(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "taskDefinition": {
                "taskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/worker:7",
                "family": "worker",
                "revision": 7,
                "taskRoleArn": "arn:aws:iam::123456789012:role/ecs-role",
                "containerDefinitions": [
                    {
                        "name": "worker",
                        "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/worker@sha256:abc",
                        "environment": [
                            {
                                "name": "PROPOSAL_CRITIC_MODEL_ID",
                                "value": "global.anthropic.claude-opus-4-6-v1",
                            },
                            {"name": "API_TOKEN", "value": "never-retained"},
                        ],
                    }
                ],
            },
            "tags": [
                {
                    "key": "aws:cloudformation:logical-id",
                    "value": "WorkerTaskDefinitionA1B2C3D4",
                }
            ],
        }


class EksClient:
    def list_clusters(self, **kwargs: Any) -> dict[str, Any]:
        return {"clusters": ["ai-cluster", "ordinary-cluster"]}

    def describe_cluster(self, *, name: str) -> dict[str, Any]:
        return {
            "cluster": {
                "name": name,
                "arn": f"arn:aws:eks:us-east-1:123456789012:cluster/{name}",
                "roleArn": "arn:aws:iam::123456789012:role/eks-role",
                "status": "ACTIVE",
                "tags": {"denali_ai_workload": "true"} if name == "ai-cluster" else {},
            }
        }


class SageMakerClient:
    def list_endpoints(self, **kwargs: Any) -> dict[str, Any]:
        return {"Endpoints": [{"EndpointName": "classifier"}]}

    def describe_endpoint(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "EndpointName": "classifier",
            "EndpointArn": "arn:aws:sagemaker:us-east-1:123456789012:endpoint/classifier",
            "EndpointConfigName": "classifier-config",
            "EndpointStatus": "InService",
        }

    def describe_endpoint_config(self, **kwargs: Any) -> dict[str, Any]:
        return {"ProductionVariants": [{"ModelName": "classifier-model"}]}

    def describe_model(self, **kwargs: Any) -> dict[str, Any]:
        return {"ExecutionRoleArn": "arn:aws:iam::123456789012:role/sagemaker-role"}


class Session:
    clients = {
        "lambda": LambdaClient(),
        "ecs": EcsClient(),
        "eks": EksClient(),
        "sagemaker": SageMakerClient(),
    }

    def client(self, service: str, **kwargs: Any) -> Any:
        return self.clients[service]


class IamClient:
    def list_role_policies(self, *, RoleName: str, **kwargs: Any) -> dict[str, Any]:
        policies = ["InvokeModels"] if RoleName in {"lambda-role", "ecs-role"} else []
        return {"PolicyNames": policies, "IsTruncated": False}

    def get_role_policy(self, **kwargs: Any) -> dict[str, Any]:
        return {
            "PolicyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "bedrock:InvokeModel",
                    "Resource": "arn:aws:bedrock:*::foundation-model/anthropic.*",
                }
            }
        }

    def list_attached_role_policies(self, **kwargs: Any) -> dict[str, Any]:
        return {"AttachedPolicies": [], "IsTruncated": False}


class StsClient:
    def __init__(self, *, assumed: bool):
        self.assumed = assumed

    def assume_role(self, **kwargs: Any) -> dict[str, Any]:
        assert not self.assumed
        return {
            "Credentials": {
                "AccessKeyId": "temporary",
                "SecretAccessKey": "temporary",
                "SessionToken": "temporary",
            }
        }

    def get_caller_identity(self) -> dict[str, str]:
        assert self.assumed
        return {"Account": "123456789012"}


class AssumedSession(Session):
    clients = {**Session.clients, "iam": IamClient(), "sts": StsClient(assumed=True)}


class BaseSession:
    def client(self, service: str, **kwargs: Any) -> Any:
        assert service == "sts"
        return StsClient(assumed=False)


class Repository:
    def __init__(self):
        self.inventory: list[Any] = []
        self.findings: list[Any] = []

    def ingest(self, tenant_id: str, batch: Any) -> dict[str, int]:
        self.inventory.append(batch)
        return {"assets": len(batch.assets)}

    def ingest_findings(self, tenant_id: str, batch: Any) -> dict[str, int]:
        self.findings.append(batch)
        return {"findings": len(batch.findings)}

    def ingest_activity(self, tenant_id: str, batch: Any) -> dict[str, int]:
        raise AssertionError("activity was not requested")


def test_collects_four_explicit_aws_deployment_contracts_without_secret_values() -> None:
    batch = AwsDeploymentConnector(
        account_id="123456789012",
        region="us-east-1",
        session=Session(),
    ).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    workloads = [item for item in batch.assets if item.asset.kind is AssetKind.AI_WORKLOAD]
    assert {item.attributes["service"] for item in workloads} == {
        "lambda",
        "ecs",
        "eks",
        "sagemaker",
    }
    identities = {
        (item.attributes["runtime_kind"], tuple(item.attributes["deployment_identifiers"]))
        for item in workloads
    }
    assert identities == {
        (
            "serverless_function",
            ("account_id", "region", "function_name", "cloudformation_logical_id"),
        ),
        (
            "container_task",
            (
                "account_id",
                "region",
                "task_family",
                "cloudformation_logical_id",
                "container_name",
            ),
        ),
        ("kubernetes_cluster", ("account_id", "region", "cluster_name")),
        ("model_endpoint", ("account_id", "region", "endpoint_name")),
    }
    assert "never-retained" not in str(batch)
    assert sum(item.kind is RelationshipKind.HOSTED_ON for item in batch.relationships) == 4
    assert sum(item.kind is RelationshipKind.RUNS_AS for item in batch.relationships) == 4
    assert sum(item.kind is RelationshipKind.USES for item in batch.relationships) == 2
    assert {
        item.attributes["model_id"]
        for item in batch.assets
        if item.asset.kind is AssetKind.AI_MODEL
    } == {
        "global.anthropic.claude-sonnet-4-5-v1:0",
        "global.anthropic.claude-opus-4-6-v1",
    }
    ordinary = [
        item
        for item in batch.assets
        if item.asset.kind is AssetKind.CLOUD_RESOURCE and item.display_name == "ordinary"
    ]
    assert len(ordinary) == 1


def test_connection_collection_ingests_model_links_and_iam_findings() -> None:
    repository = Repository()

    result = AwsConnectionDeploymentCollector(
        session_factory=lambda **credentials: AssumedSession() if credentials else BaseSession()
    ).collect(
        tenant_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        connection={
            "id": "11111111-1111-4111-8111-111111111111",
            "provider": "aws",
            "lifecycle_state": "active",
            "declared_scopes": ["aws.code_to_cloud"],
            "configuration": {
                "account_id": "123456789012",
                "coverage_mode": "selected",
                "regions": ["us-east-1"],
                "partition": "aws",
            },
            "credential_reference": {
                "role_arn": "arn:aws:iam::123456789012:role/denali",
                "external_id": "external",
            },
        },
        repository=repository,
    )

    assert result["state"] == "complete"
    assert result["regions"][0]["iam_findings"] == 2
    assert len(repository.findings) == 1
    assert len(repository.findings[0].findings) == 2
    assert any(
        relationship.kind is RelationshipKind.USES
        for batch in repository.inventory
        for relationship in batch.relationships
    )


def test_agentcore_marks_undocumented_regions_without_false_failures() -> None:
    class UnsupportedSession:
        def client(self, *_args: Any, **_kwargs: Any) -> Any:
            raise AssertionError("unsupported AgentCore Regions must not create a client")

    batch = _agentcore_batch(
        session=UnsupportedSession(),
        account_id="123456789012",
        region="ap-east-1",
        partition="aws",
        connection_id="connection",
    )

    assert {item.state for item in batch.coverage} == {CoverageState.NOT_SUPPORTED}
    assert batch.assets == ()


def test_bedrock_logging_records_presence_without_configuration_payload() -> None:
    class Client:
        def get_model_invocation_logging_configuration(self) -> dict[str, Any]:
            return {"loggingConfig": {"cloudWatchConfig": {"logGroupName": "private"}}}

    batch = _bedrock_logging_batch(
        account_id="123456789012",
        region="us-east-1",
        connection_id="connection",
        client=Client(),
    )

    assert batch.coverage[0].state is CoverageState.COMPLETE
    assert "present" in (batch.coverage[0].detail or "")
    assert "private" not in str(batch)
