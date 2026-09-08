from collections import deque
from typing import Any

from denali.connectors.aws_agentcore import (
    ENDPOINT_INVENTORY_PLANE,
    GATEWAY_INVENTORY_PLANE,
    GATEWAY_RELATIONSHIP_PLANE,
    IDENTITY_INVENTORY_PLANE,
    MEMORY_INVENTORY_PLANE,
    MEMORY_RELATIONSHIP_PLANE,
    RUNTIME_INVENTORY_PLANE,
    RUNTIME_RELATIONSHIP_PLANE,
    TARGET_INVENTORY_PLANE,
    AwsAgentCoreRegionConnector,
)
from denali.domain import AssetKind, CoverageState, RelationshipKind

ACCOUNT = "123456789012"
REGION = "us-east-1"
RUNTIME_ID = "customer-agent-AbCdEf1234"
RUNTIME_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime/{RUNTIME_ID}"
ENDPOINT_ID = "endpoint01"
ENDPOINT_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:runtime-endpoint/{ENDPOINT_ID}"
GATEWAY_ID = "customer-tools-abcdefghij"
GATEWAY_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:gateway/{GATEWAY_ID}"
TARGET_ID = "AbCdEf1234"
WORKLOAD_NAME = "customer-agent"
WORKLOAD_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:workload-identity/{WORKLOAD_NAME}"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/agentcore-runtime-role"
MEMORY_ID = "customer-memory-AbCdEf1234"
MEMORY_ARN = f"arn:aws:bedrock-agentcore:{REGION}:{ACCOUNT}:memory/{MEMORY_ID}"


class FakeClient:
    def __init__(self, **operations: list[dict[str, Any] | Exception]) -> None:
        self.operations = {name: deque(values) for name, values in operations.items()}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def __getattr__(self, operation: str):
        def invoke(**parameters: Any) -> dict[str, Any]:
            self.calls.append((operation, parameters))
            values = self.operations.get(operation)
            if values is None or not values:
                raise AssertionError(f"unexpected {operation} call")
            value = values.popleft()
            if isinstance(value, Exception):
                raise value
            return value

        return invoke


def complete_client() -> FakeClient:
    return FakeClient(
        list_workload_identities=[
            {"workloadIdentities": [{"name": WORKLOAD_NAME, "workloadIdentityArn": WORKLOAD_ARN}]}
        ],
        list_agent_runtimes=[
            {
                "agentRuntimes": [
                    {
                        "agentRuntimeId": RUNTIME_ID,
                        "agentRuntimeArn": RUNTIME_ARN,
                        "agentRuntimeName": "customer-agent",
                        "agentRuntimeVersion": "3",
                        "status": "READY",
                    }
                ]
            }
        ],
        get_agent_runtime=[
            {
                "agentRuntimeId": RUNTIME_ID,
                "agentRuntimeArn": RUNTIME_ARN,
                "agentRuntimeName": "customer-agent",
                "agentRuntimeVersion": "3",
                "status": "READY",
                "roleArn": ROLE_ARN,
                "workloadIdentityDetails": {"workloadIdentityArn": WORKLOAD_ARN},
                "networkConfiguration": {
                    "networkMode": "VPC",
                    "networkModeConfig": {
                        "subnets": ["subnet-sensitive"],
                        "securityGroups": ["sg-sensitive"],
                    },
                },
                "protocolConfiguration": {"serverProtocol": "HTTP"},
                "lifecycleConfiguration": {
                    "idleRuntimeSessionTimeout": 900,
                    "maxLifetime": 28_800,
                },
                "environmentVariables": {"CUSTOMER_SECRET": "never-store-this-environment-value"},
                "agentRuntimeArtifact": {
                    "codeConfiguration": {"code": "never-store-this-source-artifact"}
                },
                "authorizerConfiguration": {
                    "customJWTAuthorizer": {
                        "discoveryUrl": "https://private-idp.example/.well-known",
                        "allowedAudience": ["secret-audience"],
                    }
                },
                "requestHeaderConfiguration": {
                    "requestHeaderAllowlist": ["x-private-customer-header"]
                },
            }
        ],
        list_agent_runtime_endpoints=[
            {
                "runtimeEndpoints": [
                    {
                        "id": ENDPOINT_ID,
                        "name": "production",
                        "agentRuntimeEndpointArn": ENDPOINT_ARN,
                        "agentRuntimeArn": RUNTIME_ARN,
                        "status": "READY",
                        "liveVersion": "3",
                        "targetVersion": "3",
                    }
                ]
            }
        ],
        list_gateways=[
            {
                "items": [
                    {
                        "gatewayId": GATEWAY_ID,
                        "name": "customer-tools",
                        "status": "READY",
                        "protocolType": "MCP",
                        "authorizerType": "CUSTOM_JWT",
                    }
                ]
            }
        ],
        get_gateway=[
            {
                "gatewayId": GATEWAY_ID,
                "gatewayArn": GATEWAY_ARN,
                "name": "customer-tools",
                "status": "READY",
                "protocolType": "MCP",
                "authorizerType": "CUSTOM_JWT",
                "gatewayUrl": "https://customer-tools.gateway.example/mcp",
                "roleArn": ROLE_ARN,
                "workloadIdentityDetails": {"workloadIdentityArn": WORKLOAD_ARN},
                "authorizerConfiguration": {
                    "customJWTAuthorizer": {"allowedClients": ["secret-client"]}
                },
                "kmsKeyArn": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/secret-key-id",
                "interceptorConfigurations": [{"interceptor": {"lambda": "secret-interceptor"}}],
                "policyEngineConfiguration": {"arn": "secret-policy-engine"},
            }
        ],
        list_gateway_targets=[
            {
                "items": [
                    {
                        "targetId": TARGET_ID,
                        "name": "orders-api",
                        "status": "READY",
                    }
                ]
            }
        ],
        get_gateway_target=[
            {
                "gatewayArn": GATEWAY_ARN,
                "targetId": TARGET_ID,
                "name": "orders-api",
                "status": "READY",
                "protocolType": "MCP",
                "targetConfiguration": {
                    "mcp": {"openApiSchema": {"inlinePayload": "never-store-this-api-schema"}}
                },
                "credentialProviderConfigurations": [
                    {
                        "credentialProviderType": "OAUTH",
                        "credentialProvider": {"secretArn": "secret-credential-id"},
                    }
                ],
                "authorizationData": {"oauth2": {"authorizationUrl": "secret-auth-url"}},
                "metadataConfiguration": {
                    "allowedRequestHeaders": ["x-private-header"],
                    "allowedQueryParameters": ["private-query"],
                    "allowedResponseHeaders": ["x-private-response"],
                },
            }
        ],
        list_memories=[{"memories": [{"id": MEMORY_ID, "arn": MEMORY_ARN, "status": "ACTIVE"}]}],
        get_memory=[
            {
                "memory": {
                    "id": MEMORY_ID,
                    "arn": MEMORY_ARN,
                    "name": "customer-memory",
                    "status": "ACTIVE",
                    "description": "never-store-this-memory-description",
                    "encryptionKeyArn": f"arn:aws:kms:{REGION}:{ACCOUNT}:key/memory-key",
                    "memoryExecutionRoleArn": ROLE_ARN,
                    "eventExpiryDuration": 30,
                    "strategies": [
                        {
                            "strategyId": "strategy-secret-id",
                            "type": "SEMANTIC",
                            "namespaces": ["customer/secret/namespace"],
                            "namespaceTemplates": ["/{actorId}/secret"],
                            "configuration": {"prompt": "never-store-memory-prompt"},
                        }
                    ],
                    "indexedKeys": [{"key": "privateCustomerId", "type": "STRING"}],
                    "streamDeliveryResources": {
                        "resources": [{"topicArn": "secret-delivery-topic"}]
                    },
                }
            }
        ],
    )


def connector(client: FakeClient) -> AwsAgentCoreRegionConnector:
    return AwsAgentCoreRegionConnector(
        account_id=ACCOUNT,
        region=REGION,
        client=client,
    )


def coverage_by_plane(batch) -> dict[str, CoverageState]:
    return {item.plane: item.state for item in batch.coverage}


def test_discovers_agentcore_assets_relationships_and_minimizes_sensitive_data() -> None:
    client = complete_client()

    batch = connector(client).collect()

    assert set(coverage_by_plane(batch).values()) == {CoverageState.COMPLETE}
    assert {item.asset.kind for item in batch.assets} == {
        AssetKind.AI_AGENT,
        AssetKind.APPLICATION_ENDPOINT,
        AssetKind.MCP_SERVER,
        AssetKind.AI_TOOL,
        AssetKind.IDENTITY,
        AssetKind.AI_DATASTORE,
    }
    assert {item.kind for item in batch.relationships} == {
        RelationshipKind.RUNS_AS,
        RelationshipKind.EXPOSES,
    }
    runtime = next(item for item in batch.assets if item.asset.kind is AssetKind.AI_AGENT)
    assert runtime.attributes["network_mode"] == "VPC"
    assert runtime.attributes["environment_variable_count"] == 1
    assert runtime.attributes["artifact_type"] == "codeConfiguration"
    target = next(item for item in batch.assets if item.asset.kind is AssetKind.AI_TOOL)
    assert target.attributes["granularity"] == "gateway_target"
    assert target.attributes["target_kind"] == "openApiSchema"
    gateway = next(item for item in batch.assets if item.asset.kind is AssetKind.MCP_SERVER)
    assert gateway.attributes["gateway_url"] == "https://customer-tools.gateway.example/mcp"
    memory = next(item for item in batch.assets if item.asset.kind is AssetKind.AI_DATASTORE)
    assert memory.attributes["strategy_types"] == ["SEMANTIC"]
    assert memory.attributes["indexed_key_types"] == ["STRING"]
    assert ("get_memory", {"memoryId": MEMORY_ID, "view": "without_decryption"}) in client.calls

    serialized = str(batch)
    for forbidden in (
        "CUSTOMER_SECRET",
        "never-store-this-environment-value",
        "subnet-sensitive",
        "sg-sensitive",
        "private-idp",
        "secret-audience",
        "x-private-customer-header",
        "never-store-this-source-artifact",
        "secret-client",
        "secret-key-id",
        "secret-policy-engine",
        "never-store-this-api-schema",
        "secret-credential-id",
        "x-private-header",
        "private-query",
        "never-store-this-memory-description",
        "strategy-secret-id",
        "customer/secret/namespace",
        "privateCustomerId",
        "secret-delivery-topic",
    ):
        assert forbidden not in serialized


def test_skips_memory_planes_when_feature_is_not_available() -> None:
    client = complete_client()

    batch = connector(client).collect(include_memories=False)

    states = coverage_by_plane(batch)
    assert states[MEMORY_INVENTORY_PLANE] is CoverageState.NOT_SUPPORTED
    assert states[MEMORY_RELATIONSHIP_PLANE] is CoverageState.NOT_SUPPORTED
    assert not any(
        operation in {"list_memories", "get_memory"}
        for operation, _parameters in client.calls
    )


def test_endpoint_and_target_failures_are_isolated_from_parent_inventory() -> None:
    client = complete_client()
    client.operations["list_agent_runtime_endpoints"] = deque(
        [PermissionError("credential-shaped endpoint failure")]
    )
    client.operations["list_gateway_targets"] = deque(
        [RuntimeError("credential-shaped target failure")]
    )

    batch = connector(client).collect()
    states = coverage_by_plane(batch)

    assert states[RUNTIME_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert states[ENDPOINT_INVENTORY_PLANE] is CoverageState.PARTIAL
    assert states[RUNTIME_RELATIONSHIP_PLANE] is CoverageState.PARTIAL
    assert states[GATEWAY_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert states[TARGET_INVENTORY_PLANE] is CoverageState.PARTIAL
    assert states[GATEWAY_RELATIONSHIP_PLANE] is CoverageState.PARTIAL
    assert states[IDENTITY_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert states[MEMORY_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert batch.may_withdraw(RUNTIME_INVENTORY_PLANE)
    assert not batch.may_withdraw(ENDPOINT_INVENTORY_PLANE)
    assert "credential-shaped" not in str(batch)


def test_gateway_list_failure_does_not_poison_runtime_identity_or_memory() -> None:
    client = complete_client()
    client.operations["list_gateways"] = deque([PermissionError("private AWS response")])

    batch = connector(client).collect()
    states = coverage_by_plane(batch)

    assert states[GATEWAY_INVENTORY_PLANE] is CoverageState.FAILED
    assert states[TARGET_INVENTORY_PLANE] is CoverageState.FAILED
    assert states[GATEWAY_RELATIONSHIP_PLANE] is CoverageState.FAILED
    assert states[RUNTIME_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert states[IDENTITY_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert states[MEMORY_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert states[MEMORY_RELATIONSHIP_PLANE] is CoverageState.COMPLETE
    assert not any(item.asset.kind is AssetKind.MCP_SERVER for item in batch.assets)
    assert "private AWS response" not in str(batch)


def test_detail_failures_retain_summary_assets_and_block_only_affected_planes() -> None:
    client = complete_client()
    client.operations["get_agent_runtime"] = deque([RuntimeError("secret runtime detail")])
    client.operations["get_gateway"] = deque([RuntimeError("secret gateway detail")])
    client.operations["get_memory"] = deque([RuntimeError("secret memory detail")])

    batch = connector(client).collect()
    states = coverage_by_plane(batch)

    assert states[RUNTIME_INVENTORY_PLANE] is CoverageState.PARTIAL
    assert states[RUNTIME_RELATIONSHIP_PLANE] is CoverageState.PARTIAL
    assert states[ENDPOINT_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert states[GATEWAY_INVENTORY_PLANE] is CoverageState.PARTIAL
    assert states[TARGET_INVENTORY_PLANE] is CoverageState.COMPLETE
    assert states[MEMORY_INVENTORY_PLANE] is CoverageState.PARTIAL
    assert states[MEMORY_RELATIONSHIP_PLANE] is CoverageState.PARTIAL
    assert {item.asset.natural_key for item in batch.assets} >= {
        RUNTIME_ARN,
        GATEWAY_ARN,
        MEMORY_ARN,
    }
    assert "secret runtime detail" not in str(batch)


def test_out_of_scope_arns_do_not_create_cross_account_assets_or_edges() -> None:
    client = complete_client()
    foreign_account = "999999999999"
    runtime = client.operations["get_agent_runtime"][0]
    gateway = client.operations["get_gateway"][0]
    memory = client.operations["get_memory"][0]["memory"]
    assert isinstance(runtime, dict)
    assert isinstance(gateway, dict)
    runtime["roleArn"] = f"arn:aws:iam::{foreign_account}:role/foreign"
    runtime["workloadIdentityDetails"] = {
        "workloadIdentityArn": (
            f"arn:aws:bedrock-agentcore:{REGION}:{foreign_account}:workload-identity/foreign"
        )
    }
    gateway["roleArn"] = f"arn:aws:iam::{foreign_account}:role/foreign"
    memory["memoryExecutionRoleArn"] = f"arn:aws:iam::{foreign_account}:role/foreign"

    batch = connector(client).collect()

    assert not any(foreign_account in item.asset.natural_key for item in batch.assets)
    assert coverage_by_plane(batch)[RUNTIME_RELATIONSHIP_PLANE] is CoverageState.PARTIAL
    assert coverage_by_plane(batch)[GATEWAY_RELATIONSHIP_PLANE] is CoverageState.PARTIAL
    assert coverage_by_plane(batch)[MEMORY_RELATIONSHIP_PLANE] is CoverageState.PARTIAL


def test_repeated_pagination_token_fails_closed_for_only_that_family() -> None:
    client = complete_client()
    client.operations["list_workload_identities"] = deque(
        [
            {"workloadIdentities": [], "nextToken": "again"},
            {"workloadIdentities": [], "nextToken": "again"},
        ]
    )

    batch = connector(client).collect()

    assert coverage_by_plane(batch)[IDENTITY_INVENTORY_PLANE] is CoverageState.FAILED
    assert coverage_by_plane(batch)[RUNTIME_INVENTORY_PLANE] is CoverageState.COMPLETE
    identity_calls = [call for call in client.calls if call[0] == "list_workload_identities"]
    assert identity_calls[1] == ("list_workload_identities", {"nextToken": "again"})
