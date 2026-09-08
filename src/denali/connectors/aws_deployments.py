"""Bounded account/Region AWS deployment inventory for code-to-cloud correlation."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from denali.connections.aws import (
    AWS_COVERAGE_AUTOMATIC,
    AWS_SCOPE_AGENTCORE,
    AWS_SCOPE_BEDROCK_ACTIVITY,
    AWS_SCOPE_BEDROCK_AGENTS,
    AWS_SCOPE_BEDROCK_LOGGING,
    AWS_SCOPE_CODE_TO_CLOUD,
)
from denali.connectors.aws_agentcore import (
    ENDPOINT_INVENTORY_PLANE as AGENTCORE_ENDPOINT_PLANE,
)
from denali.connectors.aws_agentcore import (
    GATEWAY_INVENTORY_PLANE as AGENTCORE_GATEWAY_PLANE,
)
from denali.connectors.aws_agentcore import (
    GATEWAY_RELATIONSHIP_PLANE as AGENTCORE_GATEWAY_RELATIONSHIP_PLANE,
)
from denali.connectors.aws_agentcore import (
    IDENTITY_INVENTORY_PLANE as AGENTCORE_IDENTITY_PLANE,
)
from denali.connectors.aws_agentcore import (
    MEMORY_INVENTORY_PLANE as AGENTCORE_MEMORY_PLANE,
)
from denali.connectors.aws_agentcore import (
    MEMORY_RELATIONSHIP_PLANE as AGENTCORE_MEMORY_RELATIONSHIP_PLANE,
)
from denali.connectors.aws_agentcore import (
    RUNTIME_INVENTORY_PLANE as AGENTCORE_RUNTIME_PLANE,
)
from denali.connectors.aws_agentcore import (
    RUNTIME_RELATIONSHIP_PLANE as AGENTCORE_RUNTIME_RELATIONSHIP_PLANE,
)
from denali.connectors.aws_agentcore import (
    TARGET_INVENTORY_PLANE as AGENTCORE_TARGET_PLANE,
)
from denali.connectors.aws_agentcore import (
    AwsAgentCoreRegionConnector,
)
from denali.connectors.aws_bedrock import AwsBedrockRegionConnector
from denali.connectors.aws_bedrock_activity import AwsBedrockActivityConnector
from denali.domain import (
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    Evidence,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
)

CONNECTOR_ID = "denali.aws_deployments"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True)
MAX_PAGES = 100
MAX_RESOURCES = 10_000
PAGE_SIZE = 100
_MODEL_KEY_RE = re.compile(r"^[A-Z][A-Z0-9_]*(?:MODEL_ID|MODEL_NAME|ENDPOINT_NAME)$")

_SERVICES = {
    "lambda": ("aws_lambda_deployment_inventory", "aws_lambda_deployment_relationships"),
    "ecs": ("aws_ecs_deployment_inventory", "aws_ecs_deployment_relationships"),
    "eks": ("aws_eks_deployment_inventory", "aws_eks_deployment_relationships"),
    "sagemaker": (
        "aws_sagemaker_deployment_inventory",
        "aws_sagemaker_deployment_relationships",
    ),
}


class InventorySink(Protocol):
    def ingest(self, tenant_id: str, batch: InventoryBatch) -> dict[str, int]: ...

    def ingest_activity(self, tenant_id: str, batch: Any) -> dict[str, int]: ...


class AwsDeploymentDiscoveryError(RuntimeError):
    """A stable control-plane failure without credential or response material."""


class AwsConnectionDeploymentCollector:
    """Assume one connection role and collect its exact selected/enabled Regions."""

    def __init__(self, session_factory: Any | None = None):
        self._session_factory = session_factory or _boto3_session

    def collect(
        self,
        *,
        tenant_id: str,
        connection: dict[str, Any],
        repository: InventorySink,
    ) -> dict[str, Any]:
        if connection.get("provider") != "aws":
            raise ValueError("connection is not an AWS connection")
        if connection.get("lifecycle_state") != "active":
            raise ValueError("disabled AWS connections cannot collect")
        scopes = set(connection.get("declared_scopes", []))
        supported_scopes = {
            AWS_SCOPE_CODE_TO_CLOUD,
            AWS_SCOPE_BEDROCK_AGENTS,
            AWS_SCOPE_BEDROCK_ACTIVITY,
            AWS_SCOPE_AGENTCORE,
            AWS_SCOPE_BEDROCK_LOGGING,
        }
        if not scopes & supported_scopes:
            raise ValueError("AWS connection has no supported collection scope")
        configuration = connection.get("configuration", {})
        account_id = configuration.get("account_id")
        credential = connection.get("credential_reference", {})
        if not isinstance(account_id, str) or not re.fullmatch(r"[0-9]{12}", account_id):
            raise ValueError("AWS account boundary is incomplete")

        base_session = self._session_factory()
        assumed = base_session.client("sts").assume_role(
            RoleArn=credential["role_arn"],
            RoleSessionName=f"denali-deployments-{str(connection['id'])[:8]}",
            ExternalId=credential["external_id"],
            DurationSeconds=900,
        )
        temporary = assumed["Credentials"]
        session = self._session_factory(
            aws_access_key_id=temporary["AccessKeyId"],
            aws_secret_access_key=temporary["SecretAccessKey"],
            aws_session_token=temporary["SessionToken"],
        )
        observed_account = str(session.client("sts").get_caller_identity().get("Account", ""))
        if observed_account != account_id:
            raise ValueError("AWS assumed role account did not match the connection boundary")

        regions = _connection_regions(session, configuration)
        results: list[dict[str, Any]] = []
        failed = partial = 0
        for region in regions:
            inventory_batches: list[InventoryBatch] = []
            if AWS_SCOPE_CODE_TO_CLOUD in scopes:
                inventory_batches.append(
                    AwsDeploymentConnector(
                        account_id=account_id,
                        region=region,
                        partition=str(configuration.get("partition", "aws")),
                        session=session,
                    ).collect(connection_id=str(connection["id"]))
                )
            if AWS_SCOPE_BEDROCK_AGENTS in scopes:
                inventory_batches.append(
                    AwsBedrockRegionConnector(
                        account_id=account_id,
                        region=region,
                        partition=str(configuration.get("partition", "aws")),
                        agent_client=session.client("bedrock-agent", region_name=region),
                        bedrock_client=session.client("bedrock", region_name=region),
                    ).collect(connection_id=str(connection["id"]))
                )
            if AWS_SCOPE_AGENTCORE in scopes:
                inventory_batches.append(
                    _agentcore_batch(
                        session=session,
                        account_id=account_id,
                        region=region,
                        partition=str(configuration.get("partition", "aws")),
                        connection_id=str(connection["id"]),
                    )
                )
            if AWS_SCOPE_BEDROCK_LOGGING in scopes:
                inventory_batches.append(
                    _bedrock_logging_batch(
                        account_id=account_id,
                        region=region,
                        connection_id=str(connection["id"]),
                        client=session.client("bedrock", region_name=region),
                    )
                )
            for batch in inventory_batches:
                repository.ingest(tenant_id, batch)
            activity_count = 0
            activity_coverage: tuple[Coverage, ...] = ()
            if AWS_SCOPE_BEDROCK_ACTIVITY in scopes:
                end_time = datetime.now(UTC)
                activity_batch = AwsBedrockActivityConnector(
                    account_id=account_id,
                    region=region,
                    cloudtrail_client=session.client("cloudtrail", region_name=region),
                ).collect(
                    start_time=end_time - timedelta(hours=24),
                    end_time=end_time,
                    connection_id=str(connection["id"]),
                )
                repository.ingest_activity(tenant_id, activity_batch)
                activity_count = len(activity_batch.activities)
                activity_coverage = activity_batch.coverage
            all_coverage = [item for batch in inventory_batches for item in batch.coverage] + list(
                activity_coverage
            )
            states = {item.state for item in all_coverage}
            if CoverageState.FAILED in states:
                state = "failed"
                failed += 1
            elif CoverageState.PARTIAL in states:
                state = "partial"
                partial += 1
            else:
                state = "complete"
            results.append(
                {
                    "region": region,
                    "state": state,
                    "assets": sum(len(batch.assets) for batch in inventory_batches),
                    "ai_workloads": sum(
                        assertion.asset.kind is AssetKind.AI_WORKLOAD
                        for batch in inventory_batches
                        for assertion in batch.assets
                    ),
                    "activity_events": activity_count,
                }
            )
        completed_at = datetime.now(UTC).isoformat()
        state = (
            "failed" if failed == len(regions) else "partial" if failed or partial else "complete"
        )
        return {
            "connection_id": str(connection["id"]),
            "state": state,
            "completed_at": completed_at,
            "region_count": len(regions),
            "failed_count": failed,
            "partial_count": partial,
            "regions": results,
        }


class AwsDeploymentConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        *,
        account_id: str,
        region: str,
        session: Any,
        partition: str = "aws",
    ):
        if re.fullmatch(r"[0-9]{12}", account_id) is None:
            raise ValueError("AWS account ID must contain 12 digits")
        self.account_id = account_id
        self.region = region
        self.partition = partition
        self.session = session

    def collect(self, *, connection_id: str | None = None) -> InventoryBatch:
        observed_at = datetime.now(UTC)
        scope = f"aws:{self.account_id}:{self.region}"
        assets: dict[tuple[AssetRef, str], AssetAssertion] = {}
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, str], RelationshipAssertion
        ] = {}
        coverage: list[Coverage] = []
        for service, (inventory_plane, relationship_plane) in _SERVICES.items():
            warnings: list[str] = []
            try:
                resources = getattr(self, f"_collect_{service}")(warnings)
            except AwsDeploymentDiscoveryError as error:
                detail = str(error)
                coverage.extend(
                    (
                        Coverage(inventory_plane, CoverageState.FAILED, scope, detail),
                        Coverage(relationship_plane, CoverageState.FAILED, scope, detail),
                    )
                )
                continue
            ai_count = 0
            for parsed in resources:
                cloud, workload, identities = _assertions(parsed, observed_at, inventory_plane)
                assets[(cloud.asset, inventory_plane)] = cloud
                if workload is None:
                    continue
                ai_count += 1
                assets[(workload.asset, inventory_plane)] = workload
                _relationship(
                    relationships,
                    workload.asset,
                    cloud.asset,
                    RelationshipKind.HOSTED_ON,
                    relationship_plane,
                    workload.evidence,
                )
                for identity in identities:
                    assets[(identity.asset, inventory_plane)] = identity
                    _relationship(
                        relationships,
                        workload.asset,
                        identity.asset,
                        RelationshipKind.RUNS_AS,
                        relationship_plane,
                        workload.evidence,
                    )
            state = CoverageState.PARTIAL if warnings else CoverageState.COMPLETE
            detail = "; ".join(
                [
                    f"Observed {len(resources)} {service} resources; "
                    f"classified {ai_count} as AI workloads.",
                    *warnings[:10],
                ]
            )
            coverage.extend(
                (
                    Coverage(inventory_plane, state, scope, detail),
                    Coverage(relationship_plane, state, scope, detail),
                )
            )
        return InventoryBatch(
            connector_id=self.connector_id,
            connection_id=connection_id or f"aws:{self.account_id}",
            run_id=f"aws-deployments-{self.region}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=tuple(coverage),
            assets=tuple(assets.values()),
            relationships=tuple(relationships.values()),
        )

    def _collect_lambda(self, warnings: list[str]) -> list[dict[str, Any]]:
        client = self.session.client("lambda", region_name=self.region)
        functions = _pages(
            client.list_functions,
            "Functions",
            "Marker",
            response_token_key="NextMarker",
            MaxItems=PAGE_SIZE,
        )
        output: list[dict[str, Any]] = []
        for summary in functions:
            name = _text(summary.get("FunctionName"))
            if not name:
                warnings.append("lambda resource omitted because FunctionName was missing")
                continue
            try:
                config = client.get_function_configuration(FunctionName=name)
                arn = _text(config.get("FunctionArn"))
                tags = client.list_tags(Resource=arn).get("Tags", {}) if arn else {}
            except Exception as error:
                warnings.append(_failure("lambda:GetFunctionConfiguration/ListTags", error))
                continue
            environment = config.get("Environment", {}).get("Variables", {})
            model_keys = _model_keys(environment)
            logical_id = _tag_value(tags, "aws:cloudformation:logical-id")
            output.append(
                self._parsed(
                    service="lambda",
                    runtime_kind="serverless_function",
                    name=name,
                    arn=arn
                    or _arn(
                        self.partition,
                        "lambda",
                        self.region,
                        self.account_id,
                        f"function:{name}",
                    ),
                    identifier=("function_name", name),
                    correlation_identifiers={
                        "cloudformation_logical_id": [logical_id] if logical_id else [],
                    },
                    ai_classification=_tagged(tags) or bool(model_keys),
                    model_keys=model_keys,
                    role_arns=[_text(config.get("Role"))],
                    extra={
                        "runtime": _text(config.get("Runtime")),
                        "state": _text(config.get("State")),
                    },
                )
            )
        return output

    def _collect_ecs(self, warnings: list[str]) -> list[dict[str, Any]]:
        client = self.session.client("ecs", region_name=self.region)
        families = _pages(
            client.list_task_definition_families,
            "families",
            "nextToken",
            status="ACTIVE",
            maxResults=PAGE_SIZE,
        )
        output: list[dict[str, Any]] = []
        for family in families:
            if not isinstance(family, str) or not family:
                warnings.append("ECS task family omitted because its name was invalid")
                continue
            try:
                response = client.describe_task_definition(taskDefinition=family, include=["TAGS"])
            except Exception as error:
                warnings.append(_failure("ecs:DescribeTaskDefinition", error))
                continue
            task = response.get("taskDefinition") if isinstance(response, dict) else None
            if not isinstance(task, dict):
                warnings.append("ecs:DescribeTaskDefinition returned an invalid shape")
                continue
            model_keys: set[str] = set()
            containers: list[str] = []
            images: list[str] = []
            for container in task.get("containerDefinitions", []):
                if not isinstance(container, dict):
                    continue
                if _text(container.get("name")):
                    containers.append(str(container["name"]))
                if _text(container.get("image")):
                    images.append(str(container["image"]))
                model_keys.update(
                    _model_keys(
                        {
                            item.get("name"): True
                            for item in container.get("environment", [])
                            if isinstance(item, dict)
                        }
                    )
                )
            tags = response.get("tags", [])
            logical_id = _tag_value(tags, "aws:cloudformation:logical-id")
            arn = _text(task.get("taskDefinitionArn")) or _arn(
                self.partition,
                "ecs",
                self.region,
                self.account_id,
                f"task-definition/{family}",
            )
            output.append(
                self._parsed(
                    service="ecs",
                    runtime_kind="container_task",
                    name=family,
                    arn=arn,
                    identifier=("task_family", family),
                    correlation_identifiers={
                        "cloudformation_logical_id": [logical_id] if logical_id else [],
                        "container_name": sorted(set(containers)),
                    },
                    ai_classification=_tagged(tags) or bool(model_keys),
                    model_keys=sorted(model_keys),
                    role_arns=[_text(task.get("taskRoleArn"))],
                    extra={
                        "container_names": sorted(set(containers)),
                        "images": sorted(set(images)),
                        "revision": task.get("revision"),
                    },
                )
            )
        return output

    def _collect_eks(self, warnings: list[str]) -> list[dict[str, Any]]:
        client = self.session.client("eks", region_name=self.region)
        names = _pages(client.list_clusters, "clusters", "nextToken", maxResults=PAGE_SIZE)
        output: list[dict[str, Any]] = []
        for name in names:
            if not isinstance(name, str) or not name:
                warnings.append("EKS cluster omitted because its name was invalid")
                continue
            try:
                response = client.describe_cluster(name=name)
            except Exception as error:
                warnings.append(_failure("eks:DescribeCluster", error))
                continue
            cluster = response.get("cluster") if isinstance(response, dict) else None
            if not isinstance(cluster, dict):
                warnings.append("eks:DescribeCluster returned an invalid shape")
                continue
            arn = (
                _text(cluster.get("arn"))
                or f"arn:{self.partition}:eks:{self.region}:{self.account_id}:cluster/{name}"
            )
            output.append(
                self._parsed(
                    service="eks",
                    runtime_kind="kubernetes_cluster",
                    name=name,
                    arn=arn,
                    identifier=("cluster_name", name),
                    ai_classification=_tagged(cluster.get("tags", {})),
                    model_keys=[],
                    role_arns=[_text(cluster.get("roleArn"))],
                    extra={
                        "version": _text(cluster.get("version")),
                        "status": _text(cluster.get("status")),
                    },
                )
            )
        return output

    def _collect_sagemaker(self, warnings: list[str]) -> list[dict[str, Any]]:
        client = self.session.client("sagemaker", region_name=self.region)
        endpoints = _pages(client.list_endpoints, "Endpoints", "NextToken", MaxResults=PAGE_SIZE)
        output: list[dict[str, Any]] = []
        for summary in endpoints:
            name = _text(summary.get("EndpointName")) if isinstance(summary, dict) else None
            if not name:
                warnings.append("SageMaker endpoint omitted because EndpointName was missing")
                continue
            try:
                endpoint = client.describe_endpoint(EndpointName=name)
                config_name = _text(endpoint.get("EndpointConfigName"))
                config = client.describe_endpoint_config(EndpointConfigName=config_name)
                model_names = sorted(
                    {
                        str(item["ModelName"])
                        for item in config.get("ProductionVariants", [])
                        if isinstance(item, dict) and _text(item.get("ModelName"))
                    }
                )
                roles: list[str | None] = []
                for model_name in model_names:
                    roles.append(
                        _text(client.describe_model(ModelName=model_name).get("ExecutionRoleArn"))
                    )
            except Exception as error:
                warnings.append(_failure("sagemaker:DescribeEndpoint/Config/Model", error))
                continue
            arn = (
                _text(endpoint.get("EndpointArn"))
                or f"arn:{self.partition}:sagemaker:{self.region}:{self.account_id}:endpoint/{name}"
            )
            output.append(
                self._parsed(
                    service="sagemaker",
                    runtime_kind="model_endpoint",
                    name=name,
                    arn=arn,
                    identifier=("endpoint_name", name),
                    ai_classification=True,
                    model_keys=[],
                    role_arns=roles,
                    extra={
                        "endpoint_config_name": config_name,
                        "model_names": model_names,
                        "status": _text(endpoint.get("EndpointStatus")),
                    },
                )
            )
        return output

    def _parsed(self, **values: Any) -> dict[str, Any]:
        return {"provider": "aws", "account_id": self.account_id, "region": self.region, **values}


def _assertions(
    parsed: dict[str, Any], observed_at: datetime, plane: str
) -> tuple[AssetAssertion, AssetAssertion | None, tuple[AssetAssertion, ...]]:
    arn = parsed["arn"]
    cloud_ref = AssetRef(AssetKind.CLOUD_RESOURCE, arn)
    safe_payload = {
        "service": parsed["service"],
        "resource_arn": arn,
        "account_id": parsed["account_id"],
        "region": parsed["region"],
        "ai_classification": parsed["ai_classification"],
        "model_configuration_keys": parsed["model_keys"],
    }
    evidence = Evidence(
        source_type="aws_control_plane",
        locator=f"aws://{parsed['service']}/{parsed['region']}/{arn}",
        observed_at=observed_at,
        payload=safe_payload,
    )
    shared = {
        "provider": "aws",
        "service": parsed["service"],
        "runtime_kind": parsed["runtime_kind"],
        "account_id": parsed["account_id"],
        "region": parsed["region"],
        "resource_arn": arn,
        "ai_classification": parsed["ai_classification"],
        "model_configuration_keys": parsed["model_keys"],
        **parsed["extra"],
    }
    cloud = AssetAssertion(
        asset=cloud_ref,
        coverage_plane=plane,
        display_name=parsed["name"],
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=evidence,
        attributes=shared,
    )
    if not parsed["ai_classification"]:
        return cloud, None, ()
    identifier_name, identifier_value = parsed["identifier"]
    workload = AssetAssertion(
        asset=AssetRef(AssetKind.AI_WORKLOAD, arn),
        coverage_plane=plane,
        display_name=parsed["name"],
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=evidence,
        attributes={
            **shared,
            "deployment_identifiers": {
                "account_id": [parsed["account_id"]],
                "region": [parsed["region"]],
                identifier_name: [identifier_value],
                **{
                    name: values
                    for name, values in parsed.get("correlation_identifiers", {}).items()
                    if values
                },
            },
            "source_revision_status": "unattested",
        },
    )
    identities = tuple(
        AssetAssertion(
            asset=AssetRef(AssetKind.IDENTITY, role),
            coverage_plane=plane,
            display_name=role.rsplit("/", 1)[-1],
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=evidence,
            attributes={"provider": "aws", "account_id": parsed["account_id"], "role_arn": role},
        )
        for role in sorted({role for role in parsed["role_arns"] if isinstance(role, str) and role})
    )
    return cloud, workload, identities


def _relationship(
    relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind, str], RelationshipAssertion],
    source: AssetRef,
    target: AssetRef,
    kind: RelationshipKind,
    plane: str,
    evidence: Evidence,
) -> None:
    relationships[(source, target, kind, plane)] = RelationshipAssertion(
        source=source,
        target=target,
        coverage_plane=plane,
        kind=kind,
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=evidence,
    )


def _pages(
    call: Any,
    result_key: str,
    token_key: str,
    *,
    response_token_key: str | None = None,
    **kwargs: Any,
) -> list[Any]:
    output: list[Any] = []
    token: str | None = None
    for _ in range(MAX_PAGES):
        request = dict(kwargs)
        if token:
            request[token_key] = token
        try:
            response = call(**request)
        except Exception as error:
            raise AwsDeploymentDiscoveryError(_failure(call.__name__, error)) from None
        items = response.get(result_key) if isinstance(response, dict) else None
        if not isinstance(items, list):
            raise AwsDeploymentDiscoveryError(f"{call.__name__}:invalid_response_shape")
        output.extend(items)
        if len(output) > MAX_RESOURCES:
            raise AwsDeploymentDiscoveryError(f"{call.__name__}:record_limit_{MAX_RESOURCES}")
        next_token = response.get(response_token_key or token_key)
        if not next_token:
            return output
        if not isinstance(next_token, str):
            raise AwsDeploymentDiscoveryError(f"{call.__name__}:invalid_page_token")
        token = next_token
    raise AwsDeploymentDiscoveryError(f"{call.__name__}:page_limit_{MAX_PAGES}")


def _connection_regions(session: Any, configuration: dict[str, Any]) -> list[str]:
    if configuration.get("coverage_mode", AWS_COVERAGE_AUTOMATIC) != AWS_COVERAGE_AUTOMATIC:
        regions = list(dict.fromkeys(configuration.get("regions", [])))
        if not regions:
            raise ValueError("AWS selected-region boundary is empty")
        return regions
    deployment_region = configuration.get("deployment_region", "us-east-1")
    try:
        response = session.client("ec2", region_name=deployment_region).describe_regions(
            AllRegions=True
        )
    except Exception as error:
        raise AwsDeploymentDiscoveryError(_failure("ec2:DescribeRegions", error)) from None
    regions = sorted(
        str(item["RegionName"])
        for item in response.get("Regions", [])
        if isinstance(item, dict)
        and item.get("RegionName")
        and item.get("OptInStatus") in {"opt-in-not-required", "opted-in"}
    )
    if not regions:
        raise AwsDeploymentDiscoveryError("ec2:DescribeRegions:no_enabled_regions")
    return regions


_AGENTCORE_PLANES = (
    AGENTCORE_RUNTIME_PLANE,
    AGENTCORE_ENDPOINT_PLANE,
    AGENTCORE_RUNTIME_RELATIONSHIP_PLANE,
    AGENTCORE_GATEWAY_PLANE,
    AGENTCORE_TARGET_PLANE,
    AGENTCORE_GATEWAY_RELATIONSHIP_PLANE,
    AGENTCORE_IDENTITY_PLANE,
    AGENTCORE_MEMORY_PLANE,
    AGENTCORE_MEMORY_RELATIONSHIP_PLANE,
)


def _agentcore_batch(
    *, session: Any, account_id: str, region: str, partition: str, connection_id: str
) -> InventoryBatch:
    available_regions = session.get_available_regions(
        "bedrock-agentcore-control", partition_name=partition
    )
    if available_regions and region not in available_regions:
        observed_at = datetime.now(UTC)
        scope = f"account={account_id},region={region}"
        return InventoryBatch(
            connector_id="denali.aws_agentcore",
            connection_id=connection_id,
            run_id=f"aws-agentcore-{region}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=tuple(
                Coverage(
                    plane,
                    CoverageState.NOT_SUPPORTED,
                    scope,
                    "The AWS SDK does not expose AgentCore in this enabled Region.",
                )
                for plane in _AGENTCORE_PLANES
            ),
        )
    return AwsAgentCoreRegionConnector(
        account_id=account_id,
        region=region,
        partition=partition,
        client=session.client("bedrock-agentcore-control", region_name=region),
    ).collect(connection_id=connection_id)


def _bedrock_logging_batch(
    *, account_id: str, region: str, connection_id: str, client: Any
) -> InventoryBatch:
    observed_at = datetime.now(UTC)
    scope = f"aws:{account_id}:{region}:bedrock:invocation-logging"
    try:
        response = client.get_model_invocation_logging_configuration()
        if not isinstance(response, dict):
            raise ValueError("invalid response shape")
        configured = isinstance(response.get("loggingConfig"), dict)
        state = CoverageState.COMPLETE
        detail = (
            "Bedrock model invocation logging configuration is present."
            if configured
            else "Bedrock model invocation logging configuration is absent."
        )
    except Exception as error:
        state = CoverageState.FAILED
        detail = _failure("bedrock:GetModelInvocationLoggingConfiguration", error)
    return InventoryBatch(
        connector_id="denali.aws_bedrock_logging",
        connection_id=connection_id,
        run_id=f"aws-bedrock-logging-{region}-{observed_at.isoformat()}",
        scope_key=scope,
        collected_at=observed_at,
        coverage=(Coverage("aws_bedrock_invocation_logging", state, scope, detail),),
    )


def _model_keys(values: Any) -> list[str]:
    if not isinstance(values, dict):
        return []
    return sorted(
        str(key) for key in values if isinstance(key, str) and _MODEL_KEY_RE.fullmatch(key)
    )


def _tagged(tags: Any) -> bool:
    if isinstance(tags, dict):
        pairs = tags.items()
    elif isinstance(tags, list):
        pairs = (
            (item.get("key") or item.get("Key"), item.get("value") or item.get("Value"))
            for item in tags
            if isinstance(item, dict)
        )
    else:
        return False
    return any(
        str(key).lower() == "denali_ai_workload" and str(value).lower() == "true"
        for key, value in pairs
    )


def _tag_value(tags: Any, name: str) -> str | None:
    if isinstance(tags, dict):
        value = tags.get(name)
        return _text(value)
    if isinstance(tags, list):
        for item in tags:
            if not isinstance(item, dict):
                continue
            key = item.get("key") or item.get("Key")
            if key == name:
                return _text(item.get("value") or item.get("Value"))
    return None


def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _arn(partition: str, service: str, region: str, account_id: str, resource: str) -> str:
    return f"arn:{partition}:{service}:{region}:{account_id}:{resource}"


def _failure(operation: str, error: Exception) -> str:
    response = getattr(error, "response", None)
    if isinstance(response, dict) and isinstance(response.get("Error"), dict):
        code = response["Error"].get("Code")
        if code:
            return f"{operation}:{code}"
    return f"{operation}:{error.__class__.__name__}"


def _boto3_session(**kwargs: Any) -> Any:
    import boto3

    return boto3.Session(**kwargs)
