"""Exact, immutable Zip-Lambda read selection; never account discovery or execution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

AWS_COVERAGE_RESOURCE = "selected-resource"
SELECTED_LAMBDA_PLANE = "aws_selected_lambda_configuration"
SELECTED_IAM_PLANE = "aws_selected_execution_role_policies"
_FUNCTION = re.compile(
    r"arn:(aws|aws-us-gov|aws-cn):lambda:([a-z]{2}(?:-[a-z]+)+-[0-9]):"
    r"([0-9]{12}):function:([A-Za-z0-9_-]{1,64})"
)
_ROLE = re.compile(
    r"arn:(aws|aws-us-gov|aws-cn):iam::([0-9]{12}):role/"
    r"(?:[A-Za-z0-9_+=,.@-]+/)*([A-Za-z0-9_+=,.@-]{1,64})"
)
_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,297}(?::[0-9]+)?")


@dataclass(frozen=True)
class LambdaSelection:
    function_arn: str
    execution_role_arn: str
    expected_model_id: str
    partition: str
    account_id: str
    region: str
    function_name: str
    role_name: str


def parse_selection(value: Any) -> LambdaSelection:
    if (
        not isinstance(value, dict)
        or set(value) != {"kind", "function_arn", "execution_role_arn", "expected_model_id"}
        or value.get("kind") != "lambda_zip"
    ):
        raise ValueError("exact Zip Lambda selection is required")
    function = value.get("function_arn")
    role = value.get("execution_role_arn")
    model = value.get("expected_model_id")
    if not all(isinstance(item, str) and len(item) <= 300 for item in (function, role, model)):
        raise ValueError("exact selected resource identifiers are required")
    function_match, role_match = _FUNCTION.fullmatch(function), _ROLE.fullmatch(role)
    if function_match is None or role_match is None:
        raise ValueError("selected resource ARN format is unsupported")
    partition, region, account, name = function_match.groups()
    if role_match.group(1) != partition or role_match.group(2) != account:
        raise ValueError("selected Lambda and execution role boundaries differ")
    if (partition == "aws-cn") != region.startswith("cn-") or (
        (partition == "aws-us-gov") != region.startswith("us-gov-")
    ):
        raise ValueError("selected Lambda partition and Region differ")
    if model.startswith("arn:"):
        match = re.fullmatch(
            r"arn:(aws|aws-us-gov|aws-cn):bedrock:([a-z0-9-]+):([0-9]{12})?:"
            r"(foundation-model|inference-profile|application-inference-profile)/"
            r"([A-Za-z0-9][A-Za-z0-9._:-]{0,180})",
            model,
        )
        if (
            match is None
            or match.group(1) != partition
            or match.group(2) != region
            or (match.group(4) == "foundation-model" and match.group(3) is not None)
            or (match.group(4) != "foundation-model" and match.group(3) != account)
        ):
            raise ValueError("selected model ARN boundary is unsupported")
    elif _MODEL_ID.fullmatch(model) is None:
        raise ValueError("selected model identifier format is unsupported")
    return LambdaSelection(
        function, role, model, partition, account, region, name, role_match.group(3)
    )


def connection_selection(connection: dict[str, Any]) -> LambdaSelection | None:
    config = connection.get("configuration", {})
    if not isinstance(config, dict):
        raise ValueError("AWS connection configuration is invalid")
    selected = config.get("selected_resource")
    mode = config.get("coverage_mode")
    if mode != AWS_COVERAGE_RESOURCE and selected is None:
        return None
    selection = parse_selection(selected)
    if mode != AWS_COVERAGE_RESOURCE or connection.get("credential_type") != "aws_assume_role":
        raise ValueError("selected resource requires a native exact-resource AWS connection")
    if connection.get("provider") != "aws" or connection.get("declared_scopes") != [
        "aws.code_to_cloud"
    ]:
        raise ValueError("selected resource accepts only aws.code_to_cloud")
    if (
        config.get("account_id") != selection.account_id
        or config.get("partition") != selection.partition
    ):
        raise ValueError("selected resource does not match connection account or partition")
    if (
        config.get("regions") != [selection.region]
        or config.get("deployment_region") != selection.region
    ):
        raise ValueError("selected resource requires exactly its pinned Region")
    if config.get("stack_scopes"):
        raise ValueError("selected resource does not permit competing stack discovery")
    credential = connection.get("credential_reference", {})
    if not isinstance(credential, dict):
        raise ValueError("selected reader credential boundary is invalid")
    role_match = _ROLE.fullmatch(str(credential.get("role_arn", "")))
    if (
        role_match is None
        or role_match.group(1) != selection.partition
        or role_match.group(2) != selection.account_id
    ):
        raise ValueError("selected reader role account or partition differs")
    if role_match.group(3) != config.get("role_name") or role_match.group(3) == selection.role_name:
        raise ValueError("selected reader requires a separate configured role")
    return selection


def verify_identity(identity: Any, selection: LambdaSelection, reader_role: str) -> None:
    role = _ROLE.fullmatch(reader_role)
    expected = (
        (
            rf"arn:{re.escape(selection.partition)}:sts::{selection.account_id}:"
            rf"assumed-role/{re.escape(role.group(3))}/[A-Za-z0-9_+=,.@-]+"
        )
        if role
        else ""
    )
    if (
        not isinstance(identity, dict)
        or identity.get("Account") != selection.account_id
        or (
            not isinstance(identity.get("Arn"), str)
            or re.fullmatch(expected, identity["Arn"]) is None
        )
    ):
        raise ValueError("selected reader STS identity differs from its exact boundary")


def read_lambda(client: Any, selection: LambdaSelection) -> dict[str, Any]:
    """Retain only safe metadata after all returned identities and model pins match."""
    from denali.connectors.aws_stack import _model_entries

    config = client.get_function_configuration(FunctionName=selection.function_arn)
    if not isinstance(config, dict) or any(
        (
            config.get("FunctionArn") != selection.function_arn,
            config.get("FunctionName") != selection.function_name,
            config.get("PackageType") != "Zip",
            config.get("Role") != selection.execution_role_arn,
        )
    ):
        raise ValueError("selected Lambda identity, Zip packaging or execution role changed")
    environment = config.get("Environment")
    if (
        not isinstance(environment, dict)
        or environment.get("Error")
        or not isinstance(environment.get("Variables"), dict)
    ):
        raise ValueError("selected Lambda model metadata is unavailable")
    variables = environment["Variables"]
    keys = {
        key
        for key in variables
        if isinstance(key, str) and re.fullmatch(r"[A-Z][A-Z0-9_]*MODEL_ID", key)
    }
    models = _model_entries(variables)
    if not keys or set(models) != keys or set(models.values()) != {selection.expected_model_id}:
        raise ValueError("selected Lambda model metadata differs or is ambiguous")
    if not all(
        "BEDROCK" in key
        or value.startswith(
            (
                "global.",
                "us.",
                "eu.",
                "apac.",
                "anthropic.",
                "amazon.",
                "cohere.",
                "meta.",
                "mistral.",
                "arn:aws:bedrock:",
                "arn:aws-us-gov:bedrock:",
                "arn:aws-cn:bedrock:",
            )
        )
        for key, value in models.items()
    ):
        raise ValueError("selected Lambda model metadata does not establish Bedrock use")
    tags_response = client.list_tags(Resource=selection.function_arn)
    if not isinstance(tags_response, dict) or not isinstance(tags_response.get("Tags"), dict):
        raise ValueError("selected Lambda tag read is incomplete")
    logical_id = tags_response["Tags"].get("aws:cloudformation:logical-id")
    return {
        "models": models,
        "model_keys": sorted(models),
        "logical_id": logical_id
        if isinstance(logical_id, str) and re.fullmatch(r"[A-Za-z0-9]{1,255}", logical_id)
        else None,
        "runtime": config.get("Runtime")
        if isinstance(config.get("Runtime"), str)
        and re.fullmatch(r"[A-Za-z0-9._-]{1,40}", config["Runtime"])
        else None,
        "state": config.get("State")
        if config.get("State") in {"Pending", "Active", "Inactive", "Failed"}
        else None,
    }


class SelectedRoleIamReader:
    """Restrict the existing posture evaluator to exact-role inline policy reads."""

    def __init__(self, client: Any, selection: LambdaSelection):
        self.client, self.selection = client, selection
        self._policy_names: set[str] = set()
        self._markers: set[str] = set()

    def _check(self, values: dict[str, Any]) -> None:
        if values.get("RoleName") != self.selection.role_name:
            raise ValueError("selected execution role differs")

    def _read(self, method: str, values: dict[str, Any]) -> Any:
        # Never propagate provider exception text (which can contain request data).
        from denali.connectors.aws_stack import AwsStackDiscoveryError

        try:
            return getattr(self.client, method)(**values)
        except Exception:
            raise AwsStackDiscoveryError("selected-role:read-unavailable") from None

    def list_role_policies(self, **values: Any) -> dict[str, Any]:
        self._check(values)
        result = self._read("list_role_policies", values)
        names = result.get("PolicyNames") if isinstance(result, dict) else None
        if (
            not isinstance(names, list)
            or len(names) > 1000
            or any(
                not isinstance(name, str)
                or re.fullmatch(r"[A-Za-z0-9_+=,.@-]{1,128}", name) is None
                for name in names
            )
            or len(set(names)) != len(names)
            or not _pagination_proven(result)
        ):
            from denali.connectors.aws_stack import AwsStackDiscoveryError

            raise AwsStackDiscoveryError("selected-role:inline-policy-inventory-incomplete")
        if (
            len(self._policy_names) + len(names) > 1000
            or self._policy_names.intersection(names)
            or (result.get("IsTruncated") is True and result["Marker"] in self._markers)
        ):
            from denali.connectors.aws_stack import AwsStackDiscoveryError

            raise AwsStackDiscoveryError("selected-role:inline-policy-pagination-incomplete")
        self._policy_names.update(names)
        if result.get("IsTruncated") is True:
            self._markers.add(result["Marker"])
        return result

    def get_role_policy(self, **values: Any) -> dict[str, Any]:
        self._check(values)
        if values.get("PolicyName") not in self._policy_names:
            raise ValueError("selected inline policy was not observed on this role")
        result = self._read("get_role_policy", values)
        if (
            not isinstance(result, dict)
            or result.get("RoleName") != self.selection.role_name
            or (
                result.get("PolicyName") != values.get("PolicyName")
                or not _policy_document_proven(result.get("PolicyDocument"))
            )
        ):
            from denali.connectors.aws_stack import AwsStackDiscoveryError

            raise AwsStackDiscoveryError("selected-role:inline-policy-identity-incomplete")
        return result

    def list_attached_role_policies(self, **values: Any) -> dict[str, Any]:
        self._check(values)
        result = self._read("list_attached_role_policies", values)
        if (
            not isinstance(result, dict)
            or result.get("AttachedPolicies") != []
            or (result.get("IsTruncated") is not False)
            or not _pagination_proven(result)
        ):
            from denali.connectors.aws_stack import AwsStackDiscoveryError

            raise AwsStackDiscoveryError("selected-role:attached-policy-proof-incomplete")
        return result


def _pagination_proven(response: dict[str, Any]) -> bool:
    truncated = response.get("IsTruncated")
    if truncated is False:
        return "Marker" not in response
    marker = response.get("Marker")
    return truncated is True and isinstance(marker, str) and 1 <= len(marker) <= 320


def _policy_document_proven(document: Any) -> bool:
    """Unsupported policy grammar is partial, never a proof of no findings."""
    if not isinstance(document, dict):
        return False
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements or len(statements) > 1000:
        return False
    for statement in statements:
        if not isinstance(statement, dict) or statement.get("Effect") not in {"Allow", "Deny"}:
            return False
        if "NotAction" in statement or "NotResource" in statement:
            return False
        for field in ("Action", "Resource"):
            values = statement.get(field)
            if isinstance(values, str):
                values = [values]
            if (
                not isinstance(values, list)
                or not values
                or any(
                    not isinstance(value, str) or not value or len(value) > 2048 for value in values
                )
            ):
                return False
        if "Condition" in statement and not isinstance(statement["Condition"], dict):
            return False
    return True


def selected_coverage_plan(selection: LambdaSelection) -> list[dict[str, Any]]:
    return [
        {
            "scope": "aws.code_to_cloud",
            "plane": plane,
            "label": label,
            "region": selection.region,
            "permissions": permissions,
            "validation_state": "not_validated",
            "coverage_mode": AWS_COVERAGE_RESOURCE,
        }
        for plane, label, permissions in (
            (
                SELECTED_LAMBDA_PLANE,
                "Selected Zip Lambda configuration and tags",
                ["lambda:GetFunctionConfiguration", "lambda:ListTags"],
            ),
            (
                SELECTED_IAM_PLANE,
                "Selected execution-role inline IAM posture",
                ["iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:GetRolePolicy"],
            ),
        )
    ]


def selected_validation_passed(connection: dict[str, Any], validation: dict[str, Any]) -> bool:
    """A narrow read proof may finish onboarding, but never become global healthy."""
    try:
        selection = connection_selection(connection)
    except (ValueError, TypeError):
        return False
    if selection is None or validation.get("credential_state") != "passed":
        return False
    results = validation.get("results")
    if not isinstance(results, list) or len(results) != 2:
        return False
    return all(
        isinstance(result, dict)
        and result.get("scope") == "aws.code_to_cloud"
        and result.get("coverage_mode") == AWS_COVERAGE_RESOURCE
        and result.get("region") == selection.region
        and result.get("state") == "passed"
        for result in results
    ) and {result.get("plane") for result in results} == {
        SELECTED_LAMBDA_PLANE,
        SELECTED_IAM_PLANE,
    }


def render_selected_cloudformation(connection: dict[str, Any]) -> str:
    selection = connection_selection(connection)
    if selection is None:
        raise ValueError("selected resource is required")
    role = connection["configuration"]["role_name"]
    external_id = connection["credential_reference"]["external_id"]
    if (
        not isinstance(external_id, str)
        or re.fullmatch(r"[A-Za-z0-9-]{1,160}", external_id) is None
    ):
        raise ValueError("selected external ID is invalid")
    return f"""AWSTemplateFormatVersion: '2010-09-09'
Description: Denali exact Zip Lambda metadata and execution-role inline-policy read access.
Parameters:
  DenaliPrincipalArn:
    Type: String
    AllowedPattern: '^arn:{selection.partition}:iam::[0-9]{{12}}:(role|user)/.+$'
  DenaliExternalId:
    Type: String
    Default: '{external_id}'
    NoEcho: true
Resources:
  DenaliSecurityAuditRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: '{role}'
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
        - PolicyName: DenaliSelectedResourceRead
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action: [lambda:GetFunctionConfiguration, lambda:ListTags]
                Resource: '{selection.function_arn}'
              - Effect: Allow
                Action: [iam:ListRolePolicies, iam:ListAttachedRolePolicies, iam:GetRolePolicy]
                Resource: '{selection.execution_role_arn}'
Outputs:
  RoleArn:
    Value: !GetAtt DenaliSecurityAuditRole.Arn
"""
