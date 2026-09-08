"""Bounded AWS connection onboarding and validation."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from threading import local
from typing import Any, Protocol

AWS_SCOPE_BEDROCK_AGENTS = "aws.bedrock_agents"
AWS_SCOPE_AGENTCORE = "aws.agentcore"
AWS_SCOPE_BEDROCK_ACTIVITY = "aws.bedrock_activity"
AWS_SCOPE_BEDROCK_LOGGING = "aws.bedrock_logging"
AWS_SCOPE_CODE_TO_CLOUD = "aws.code_to_cloud"
AWS_SCOPE_REGION_COVERAGE = "aws.region_coverage"
AWS_COVERAGE_AUTOMATIC = "automatic"
AWS_COVERAGE_SELECTED = "selected"
AWS_REGION_DISCOVERY_PLANE = "aws_region_discovery"
AWS_REGION_DISCOVERY_PERMISSION = "ec2:DescribeRegions"
_NOT_APPLICABLE_CODES = {
    "InvalidAction",
    "NotImplementedException",
    "UnknownOperationException",
    "UnsupportedOperation",
    "UnsupportedOperationException",
    "UnsupportedRegionException",
}

# AWS-published AgentCore feature availability, verified 2026-08-29. Probes still run in
# every enabled account Region: a successful live call always wins over this catalog, while
# a failed call outside the published set is bounded as not applicable rather than a
# permission or network conclusion.
# https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-regions.html
AGENTCORE_REGIONS = frozenset(
    {
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-south-1",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-5",
        "ap-southeast-7",
        "ca-central-1",
        "eu-central-1",
        "eu-north-1",
        "eu-south-1",
        "eu-south-2",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "sa-east-1",
        "us-east-1",
        "us-east-2",
        "us-gov-west-1",
        "us-west-2",
    }
)
AGENTCORE_MEMORY_REGIONS = AGENTCORE_REGIONS - {
    "ap-southeast-5",
    "ap-southeast-7",
    "eu-south-1",
    "eu-south-2",
}
_AGENTCORE_PLANE_REGIONS = {
    "agentcore_runtimes": AGENTCORE_REGIONS,
    "agentcore_gateways": AGENTCORE_REGIONS,
    "agentcore_workload_identities": AGENTCORE_REGIONS,
    "agentcore_memories": AGENTCORE_MEMORY_REGIONS,
}
AWS_SCOPES = (
    AWS_SCOPE_BEDROCK_AGENTS,
    AWS_SCOPE_AGENTCORE,
    AWS_SCOPE_BEDROCK_ACTIVITY,
    AWS_SCOPE_BEDROCK_LOGGING,
    AWS_SCOPE_CODE_TO_CLOUD,
)

_SCOPE_METADATA = {
    AWS_SCOPE_BEDROCK_AGENTS: {
        "planes": (
            {
                "label": "Bedrock Agents Classic inventory",
                "plane": "bedrock_agents",
                "permissions": ("bedrock:ListAgents", "bedrock:GetAgent"),
            },
            {
                "label": "Bedrock guardrail inventory",
                "plane": "bedrock_guardrails",
                "permissions": ("bedrock:ListGuardrails", "bedrock:GetGuardrail"),
            },
        ),
    },
    AWS_SCOPE_AGENTCORE: {
        "planes": (
            {
                "label": "AgentCore runtime inventory",
                "plane": "agentcore_runtimes",
                "permissions": (
                    "bedrock-agentcore:ListAgentRuntimes",
                    "bedrock-agentcore:GetAgentRuntime",
                    "bedrock-agentcore:ListAgentRuntimeEndpoints",
                ),
            },
            {
                "label": "AgentCore gateway inventory",
                "plane": "agentcore_gateways",
                "permissions": (
                    "bedrock-agentcore:ListGateways",
                    "bedrock-agentcore:GetGateway",
                    "bedrock-agentcore:ListGatewayTargets",
                    "bedrock-agentcore:GetGatewayTarget",
                ),
            },
            {
                "label": "AgentCore workload identity inventory",
                "plane": "agentcore_workload_identities",
                "permissions": ("bedrock-agentcore:ListWorkloadIdentities",),
            },
            {
                "label": "AgentCore memory inventory",
                "plane": "agentcore_memories",
                "permissions": (
                    "bedrock-agentcore:ListMemories",
                    "bedrock-agentcore:GetMemory",
                ),
            },
        ),
    },
    AWS_SCOPE_BEDROCK_ACTIVITY: {
        "planes": (
            {
                "label": "Bedrock management activity",
                "plane": "bedrock_management_activity",
                "permissions": ("cloudtrail:LookupEvents",),
            },
        ),
    },
    AWS_SCOPE_BEDROCK_LOGGING: {
        "planes": (
            {
                "label": "Bedrock invocation logging configuration",
                "plane": "bedrock_invocation_logging",
                "permissions": ("bedrock:GetModelInvocationLoggingConfiguration",),
            },
        ),
    },
    AWS_SCOPE_CODE_TO_CLOUD: {
        "planes": (
            {
                "label": "AWS Lambda deployment inventory",
                "plane": "aws_lambda_deployments",
                "permissions": (
                    "lambda:ListFunctions",
                    "lambda:GetFunctionConfiguration",
                    "lambda:ListTags",
                ),
            },
            {
                "label": "Amazon ECS task definition inventory",
                "plane": "aws_ecs_deployments",
                "permissions": (
                    "ecs:ListTaskDefinitionFamilies",
                    "ecs:DescribeTaskDefinition",
                    "ecs:ListTagsForResource",
                ),
            },
            {
                "label": "Amazon EKS cluster inventory",
                "plane": "aws_eks_deployments",
                "permissions": (
                    "eks:ListClusters",
                    "eks:DescribeCluster",
                    "eks:ListTagsForResource",
                ),
            },
            {
                "label": "Amazon SageMaker endpoint inventory",
                "plane": "aws_sagemaker_deployments",
                "permissions": (
                    "sagemaker:ListEndpoints",
                    "sagemaker:DescribeEndpoint",
                    "sagemaker:DescribeEndpointConfig",
                    "sagemaker:DescribeModel",
                    "sagemaker:ListTags",
                ),
            },
        ),
    },
}


class AwsClient(Protocol):
    def get_caller_identity(self) -> dict[str, Any]: ...

    def assume_role(self, **kwargs: Any) -> dict[str, Any]: ...


SessionFactory = Callable[..., Any]


def aws_coverage_plan(scopes: list[str], regions: list[str]) -> list[dict[str, Any]]:
    """Expand declared regional scopes into explicit validation planes."""

    plan: list[dict[str, Any]] = []
    for scope in scopes:
        for plane in _SCOPE_METADATA[scope]["planes"]:
            for region in regions:
                plan.append(
                    {
                        "scope": scope,
                        "plane": plane["plane"],
                        "label": plane["label"],
                        "region": region,
                        "permissions": list(plane["permissions"]),
                        "validation_state": "not_validated",
                    }
                )
    return plan


def aws_connection_coverage_plan(
    scopes: list[str],
    regions: list[str],
    *,
    deployment_region: str,
    coverage_mode: str,
) -> list[dict[str, Any]]:
    """Build the declared plan, including the region-discovery evidence boundary."""

    discovery = {
        "scope": AWS_SCOPE_REGION_COVERAGE,
        "plane": AWS_REGION_DISCOVERY_PLANE,
        "label": "AWS enabled-region discovery",
        "region": deployment_region,
        "permissions": [AWS_REGION_DISCOVERY_PERMISSION],
        "validation_state": "not_validated",
        "coverage_mode": coverage_mode,
    }
    return [discovery, *aws_coverage_plan(scopes, regions)]


def render_cloudformation(connection: dict[str, Any]) -> str:
    """Render the least-privilege onboarding role for one AWS connection."""

    configuration = connection["configuration"]
    credential = connection["credential_reference"]
    role_name = configuration["role_name"]
    external_id = credential["external_id"]
    actions = sorted(
        {
            permission
            for scope in connection["declared_scopes"]
            for plane in _SCOPE_METADATA[scope]["planes"]
            for permission in plane["permissions"]
        }
        | {
            AWS_REGION_DISCOVERY_PERMISSION,
            # Stack-scoped collectors are available to configure after this first
            # regional connection is healthy. Their coverage is not claimed here.
            "cloudformation:GetTemplate",
            "cloudformation:ListStackResources",
            "ecs:DescribeTaskDefinition",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
            "iam:GetRolePolicy",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "lambda:GetFunctionConfiguration",
            "logs:DescribeLogGroups",
        }
    )
    action_lines = "\n".join(f"                  - {action}" for action in actions)
    return f"""AWSTemplateFormatVersion: '2010-09-09'
Description: >-
  Denali evidence-first read-only AWS connection. Creates no access keys and grants
  no remediation or workload execution permissions.
Parameters:
  DenaliPrincipalArn:
    Type: String
    Description: ARN of the AWS principal that Denali uses to assume this role.
    AllowedPattern: '^arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{{12}}:(role|user)/.+$'
  DenaliExternalId:
    Type: String
    Default: '{external_id}'
    NoEcho: true
    Description: Keep this generated value unchanged so Denali can validate the role.
Resources:
  DenaliSecurityAuditRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: '{role_name}'
      Description: Read-only evidence collection for Denali AI Security
      MaxSessionDuration: 3600
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Ref DenaliPrincipalArn
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                sts:ExternalId: !Ref DenaliExternalId
      Policies:
        - PolicyName: DenaliEvidenceCollection
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Sid: DenaliReadOnlyEvidence
                Effect: Allow
                Action:
{action_lines}
                Resource: '*'
Outputs:
  RoleArn:
    Description: Role ARN Denali validates after stack deployment.
    Value: !GetAtt DenaliSecurityAuditRole.Arn
"""


class AwsConnectionValidator:
    """Validate identity and every declared plane without collecting product evidence."""

    def __init__(
        self,
        session_factory: SessionFactory | None = None,
        *,
        max_workers: int = 8,
    ):
        self._session_factory = session_factory or _boto3_session
        self._max_workers = max(1, max_workers)

    def validate(self, connection: dict[str, Any]) -> dict[str, Any]:
        started_at = datetime.now(UTC)
        configuration = connection["configuration"]
        credential = connection["credential_reference"]
        try:
            base_session = self._session_factory()
            sts = base_session.client("sts")
            assumed = sts.assume_role(
                RoleArn=credential["role_arn"],
                RoleSessionName=f"denali-validation-{str(connection['id'])[:8]}",
                ExternalId=credential["external_id"],
                DurationSeconds=900,
            )
            credentials = assumed["Credentials"]
            session = self._session_factory(
                aws_access_key_id=credentials["AccessKeyId"],
                aws_secret_access_key=credentials["SecretAccessKey"],
                aws_session_token=credentials["SessionToken"],
            )
            identity = session.client("sts").get_caller_identity()
            observed_account = str(identity.get("Account", ""))
            if observed_account != configuration["account_id"]:
                return _credential_failure(
                    connection,
                    started_at,
                    "account_mismatch",
                    observed_account=observed_account or None,
                )
        except Exception as error:  # AWS SDK exception types are optional at import time.
            return _credential_failure(connection, started_at, _aws_error_code(error))

        discovery = self._discover_regions(session, configuration)
        results: list[dict[str, Any]] = [discovery]
        coverage_mode = configuration.get("coverage_mode", AWS_COVERAGE_AUTOMATIC)
        configured_regions = list(dict.fromkeys(configuration.get("regions", [])))
        if discovery["state"] == "passed":
            scan_regions = (
                discovery["discovered_regions"]
                if coverage_mode == AWS_COVERAGE_AUTOMATIC
                else [
                    region
                    for region in configured_regions
                    if region in discovery["discovered_regions"]
                ]
            )
        elif coverage_mode == AWS_COVERAGE_SELECTED:
            # Preserve the explicitly declared scope, but do not claim that it is complete
            # relative to the account's enabled Regions.
            scan_regions = configured_regions
        else:
            scan_regions = []

        if not scan_regions:
            for planned in aws_coverage_plan(connection["declared_scopes"], ["all-enabled"]):
                results.append(
                    {
                        "scope": planned["scope"],
                        "plane": planned["plane"],
                        "label": planned["label"],
                        "region": planned["region"],
                        "state": "unknown",
                        "detail": (
                            "Not attempted because enabled-region coverage was not established."
                        ),
                    }
                )

        regional_plan = aws_coverage_plan(connection["declared_scopes"], scan_regions)
        if self._max_workers == 1 or len(regional_plan) < 2:
            regional_results = [
                self._validate_plane(session, planned, configuration)
                for planned in regional_plan
            ]
        else:
            worker_state = local()

            def validate_with_worker_session(planned: dict[str, Any]) -> dict[str, Any]:
                if not hasattr(worker_state, "session"):
                    worker_state.session = self._session_factory(
                        aws_access_key_id=credentials["AccessKeyId"],
                        aws_secret_access_key=credentials["SecretAccessKey"],
                        aws_session_token=credentials["SessionToken"],
                    )
                return self._validate_plane(worker_state.session, planned, configuration)

            with ThreadPoolExecutor(max_workers=self._max_workers) as executor:
                regional_results = list(executor.map(validate_with_worker_session, regional_plan))
        results.extend(regional_results)

        failed_count = sum(item["state"] in {"failed", "unknown"} for item in results)
        not_applicable_count = sum(item["state"] == "not_applicable" for item in results)
        health = "healthy" if failed_count == 0 else "partial"
        region_count = len(scan_regions)
        if health == "healthy":
            summary = (
                f"Credentials validated; all applicable planes passed across {region_count} "
                f"Region(s)."
            )
        else:
            summary = (
                f"Credentials validated; {failed_count} coverage check(s) failed or remain "
                f"unknown across {region_count} Region(s)."
            )
        if not_applicable_count:
            summary += f" {not_applicable_count} service/Region check(s) were not applicable."
        return {
            "started_at": started_at,
            "completed_at": datetime.now(UTC),
            "health_state": health,
            "credential_state": "passed",
            "account_id_observed": observed_account,
            "results": results,
            "summary": summary,
        }

    def _validate_plane(
        self,
        session: Any,
        planned: dict[str, Any],
        configuration: dict[str, Any],
    ) -> dict[str, Any]:
        result = {
            "scope": planned["scope"],
            "plane": planned["plane"],
            "label": planned["label"],
            "region": planned["region"],
        }
        if not self._service_available(
            session, planned["plane"], planned["region"], configuration
        ):
            result.update(
                state="not_applicable",
                detail="The AWS SDK has no endpoint for this service in the discovered Region.",
            )
            return result
        try:
            self._probe(session, planned["plane"], planned["region"])
            result.update(
                state="passed",
                detail=(
                    "The plane's read-only entrypoint succeeded. Resource-specific reads "
                    "are verified during collection when matching resources exist."
                ),
            )
        except Exception as error:  # Reduced to an operation-safe code below.
            error_code = _aws_error_code(error)
            documented_regions = _AGENTCORE_PLANE_REGIONS.get(planned["plane"])
            documented_unavailable = (
                documented_regions is not None and planned["region"] not in documented_regions
            )
            result.update(
                state=(
                    "not_applicable"
                    if documented_unavailable or error_code in _NOT_APPLICABLE_CODES
                    else "failed"
                ),
                detail=(
                    (
                        "AWS does not document this AgentCore feature as available in the "
                        f"Region; the bounded probe returned {error_code}."
                    )
                    if documented_unavailable
                    else f"The service does not expose this operation in the Region ({error_code})."
                    if error_code in _NOT_APPLICABLE_CODES
                    else f"Validation call failed ({error_code})."
                ),
            )
        return result

    @staticmethod
    def _discover_regions(session: Any, configuration: dict[str, Any]) -> dict[str, Any]:
        coverage_mode = configuration.get("coverage_mode", AWS_COVERAGE_AUTOMATIC)
        configured_regions = list(dict.fromkeys(configuration.get("regions", [])))
        deployment_region = configuration.get("deployment_region") or (
            configured_regions[0] if configured_regions else "us-east-1"
        )
        observed_at = datetime.now(UTC).isoformat()
        base = {
            "scope": AWS_SCOPE_REGION_COVERAGE,
            "plane": AWS_REGION_DISCOVERY_PLANE,
            "label": "AWS enabled-region discovery",
            "region": deployment_region,
            "coverage_mode": coverage_mode,
            "observed_at": observed_at,
            "discovered_regions": [],
            "not_enabled_regions": [],
            "excluded_enabled_regions": [],
        }
        try:
            response = _regional_client(session, "ec2", deployment_region).describe_regions(
                AllRegions=True
            )
        except Exception as error:
            return {
                **base,
                "state": "failed",
                "detail": f"Enabled-region discovery failed ({_aws_error_code(error)}).",
            }

        statuses = {
            str(item.get("RegionName")): str(item.get("OptInStatus", "unknown"))
            for item in response.get("Regions", [])
            if item.get("RegionName")
        }
        enabled = sorted(
            region
            for region, status in statuses.items()
            if status in {"opt-in-not-required", "opted-in"}
        )
        not_enabled = sorted(
            region for region, status in statuses.items() if status == "not-opted-in"
        )
        selected_not_enabled = (
            sorted(set(configured_regions) - set(enabled))
            if coverage_mode == AWS_COVERAGE_SELECTED
            else []
        )
        excluded_enabled = (
            sorted(set(enabled) - set(configured_regions))
            if coverage_mode == AWS_COVERAGE_SELECTED
            else []
        )
        state = "failed" if not enabled or selected_not_enabled else "passed"
        if not enabled:
            detail = "AWS returned no enabled Regions; regional coverage cannot be established."
        elif selected_not_enabled:
            detail = (
                "Selected Region(s) are not enabled or were not returned by AWS: "
                + ", ".join(selected_not_enabled)
                + "."
            )
        elif coverage_mode == AWS_COVERAGE_SELECTED:
            detail = (
                f"AWS reported {len(enabled)} enabled Region(s); {len(configured_regions)} "
                f"were explicitly selected and {len(excluded_enabled)} are outside scope."
            )
        else:
            detail = f"AWS reported {len(enabled)} enabled Region(s); all are in scope."
        return {
            **base,
            "state": state,
            "detail": detail,
            "discovered_regions": enabled,
            "not_enabled_regions": not_enabled,
            "excluded_enabled_regions": excluded_enabled,
        }

    @staticmethod
    def _service_available(
        session: Any,
        plane: str,
        region: str,
        configuration: dict[str, Any],
    ) -> bool:
        service_by_plane = {
            "bedrock_agents": "bedrock-agent",
            "bedrock_guardrails": "bedrock",
            "agentcore_runtimes": "bedrock-agentcore-control",
            "agentcore_gateways": "bedrock-agentcore-control",
            "agentcore_workload_identities": "bedrock-agentcore-control",
            "agentcore_memories": "bedrock-agentcore-control",
            "bedrock_management_activity": "cloudtrail",
            "bedrock_invocation_logging": "bedrock",
            "aws_lambda_deployments": "lambda",
            "aws_ecs_deployments": "ecs",
            "aws_eks_deployments": "eks",
            "aws_sagemaker_deployments": "sagemaker",
        }
        get_available_regions = getattr(session, "get_available_regions", None)
        if not callable(get_available_regions):
            return True
        try:
            available = get_available_regions(
                service_by_plane[plane], partition_name=configuration.get("partition", "aws")
            )
        except Exception:
            # SDK endpoint metadata is advisory. Failure to read it must not suppress a probe.
            return True
        return not available or region in available

    @staticmethod
    def _probe(session: Any, plane: str, region: str) -> None:
        if plane == "bedrock_agents":
            _regional_client(session, "bedrock-agent", region).list_agents(maxResults=1)
        elif plane == "bedrock_guardrails":
            _regional_client(session, "bedrock", region).list_guardrails(maxResults=1)
        elif plane == "agentcore_runtimes":
            _regional_client(
                session, "bedrock-agentcore-control", region
            ).list_agent_runtimes(maxResults=1)
        elif plane == "agentcore_gateways":
            _regional_client(
                session, "bedrock-agentcore-control", region
            ).list_gateways(maxResults=1)
        elif plane == "agentcore_workload_identities":
            client = _regional_client(session, "bedrock-agentcore-control", region)
            client.list_workload_identities(maxResults=1)
        elif plane == "agentcore_memories":
            _regional_client(
                session, "bedrock-agentcore-control", region
            ).list_memories(maxResults=1)
        elif plane == "bedrock_management_activity":
            _regional_client(session, "cloudtrail", region).lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "EventSource", "AttributeValue": "bedrock.amazonaws.com"}
                ],
                MaxResults=1,
            )
        elif plane == "bedrock_invocation_logging":
            client = _regional_client(session, "bedrock", region)
            client.get_model_invocation_logging_configuration()
        elif plane == "aws_lambda_deployments":
            _regional_client(session, "lambda", region).list_functions(MaxItems=1)
        elif plane == "aws_ecs_deployments":
            _regional_client(session, "ecs", region).list_task_definition_families(
                status="ACTIVE", maxResults=1
            )
        elif plane == "aws_eks_deployments":
            _regional_client(session, "eks", region).list_clusters(maxResults=1)
        elif plane == "aws_sagemaker_deployments":
            _regional_client(session, "sagemaker", region).list_endpoints(MaxResults=1)
        else:  # Creation validation should make this unreachable.
            raise ValueError("unsupported_scope")


def _credential_failure(
    connection: dict[str, Any],
    started_at: datetime,
    code: str,
    *,
    observed_account: str | None = None,
) -> dict[str, Any]:
    return {
        "started_at": started_at,
        "completed_at": datetime.now(UTC),
        "health_state": "unhealthy",
        "credential_state": "failed",
        "account_id_observed": observed_account,
        "results": [
            {
                "scope": AWS_SCOPE_REGION_COVERAGE,
                "plane": AWS_REGION_DISCOVERY_PLANE,
                "label": "AWS enabled-region discovery",
                "region": connection["configuration"].get("deployment_region", "us-east-1"),
                "state": "unknown",
                "detail": "Not attempted because credential validation failed.",
                "coverage_mode": connection["configuration"].get(
                    "coverage_mode", AWS_COVERAGE_AUTOMATIC
                ),
                "observed_at": datetime.now(UTC).isoformat(),
                "discovered_regions": [],
                "not_enabled_regions": [],
                "excluded_enabled_regions": [],
            },
            *[
            {
                "scope": item["scope"],
                "plane": item["plane"],
                "label": item["label"],
                "region": item["region"],
                "state": "unknown",
                "detail": "Not attempted because credential validation failed.",
            }
            for item in connection["coverage_plan"]
            if item["plane"] != AWS_REGION_DISCOVERY_PLANE
            ],
        ],
        "summary": f"Unable to validate the configured role ({code}).",
    }


def _aws_error_code(error: Exception) -> str:
    response = getattr(error, "response", None)
    if isinstance(response, dict):
        error_payload = response.get("Error")
        if isinstance(error_payload, dict) and error_payload.get("Code"):
            return str(error_payload["Code"])
    return error.__class__.__name__


def _boto3_session(**kwargs: Any) -> Any:
    import boto3

    return boto3.Session(**kwargs)


def _regional_client(session: Any, service: str, region: str) -> Any:
    from botocore.config import Config

    return session.client(
        service,
        region_name=region,
        config=Config(
            connect_timeout=3,
            read_timeout=10,
            retries={"total_max_attempts": 2, "mode": "standard"},
        ),
    )
