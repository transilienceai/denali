from __future__ import annotations

from typing import Any

from denali.connectors.aws_deployments import (
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
                "Variables": {"BEDROCK_MODEL_ID": "never-retained"}
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
                        "environment": [{"name": "MODEL_ENDPOINT_NAME", "value": "never-retained"}],
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
    ordinary = [
        item
        for item in batch.assets
        if item.asset.kind is AssetKind.CLOUD_RESOURCE and item.display_name == "ordinary"
    ]
    assert len(ordinary) == 1


def test_agentcore_marks_sdk_unsupported_regions_without_false_failures() -> None:
    class UnsupportedSession:
        def get_available_regions(self, *_args: Any, **_kwargs: Any) -> list[str]:
            return ["us-east-1"]

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
