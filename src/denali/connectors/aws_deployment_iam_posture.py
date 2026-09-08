"""IAM posture evidence for AWS AI workloads discovered by the hosted collector."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

from denali.connectors.aws_stack import AwsStackDiscoveryError
from denali.connectors.aws_stack_posture import _overbroad_bedrock_permissions
from denali.domain import (
    AffectedResource,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    EvaluationResult,
    Evidence,
    FindingAssertion,
    FindingBatch,
    FindingSeverity,
    FindingState,
    InventoryBatch,
    RelationshipKind,
)

CONNECTOR_ID = "denali.aws_deployment_iam_posture"
CAPABILITIES = ConnectorCapabilities(findings=True)
FINDINGS_PLANE = "aws_ai_workload_iam_posture"
MAX_ROLE_TARGETS = 500


class AwsDeploymentIamPostureConnector:
    """Evaluate only execution roles linked to observed Bedrock workloads."""

    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        *,
        account_id: str,
        region: str,
        iam_client: Any,
    ) -> None:
        self.account_id = account_id
        self.region = region
        self.iam_client = iam_client

    def collect(
        self,
        deployments: InventoryBatch,
        *,
        connection_id: str,
    ) -> FindingBatch:
        observed_at = datetime.now(UTC)
        scope = f"aws:{self.account_id}:{self.region}:ai-workload-iam"
        assets = {assertion.asset: assertion for assertion in deployments.assets}
        models_by_workload: dict[Any, set[str]] = defaultdict(set)
        roles_by_workload: dict[Any, set[Any]] = defaultdict(set)
        for relationship in deployments.relationships:
            if relationship.kind is RelationshipKind.USES:
                model = assets.get(relationship.target)
                if model is not None and model.asset.kind.value == "ai_model":
                    model_id = model.attributes.get("model_id")
                    if isinstance(model_id, str) and model_id:
                        models_by_workload[relationship.source].add(model_id)
            elif relationship.kind is RelationshipKind.RUNS_AS:
                roles_by_workload[relationship.source].add(relationship.target)

        role_context: dict[Any, dict[str, set[str]]] = defaultdict(
            lambda: {"models": set(), "workloads": set()}
        )
        for workload_ref, model_ids in models_by_workload.items():
            workload = assets.get(workload_ref)
            if workload is None:
                continue
            for role_ref in roles_by_workload.get(workload_ref, set()):
                role_context[role_ref]["models"].update(model_ids)
                role_context[role_ref]["workloads"].add(
                    workload.display_name or workload.asset.natural_key
                )

        warnings: list[str] = []
        role_refs = sorted(role_context, key=lambda item: item.natural_key)
        if len(role_refs) > MAX_ROLE_TARGETS:
            warnings.append(
                f"IAM evaluation limited to {MAX_ROLE_TARGETS} observed execution roles."
            )
            role_refs = role_refs[:MAX_ROLE_TARGETS]

        findings: list[FindingAssertion] = []
        for role_ref in role_refs:
            role_name = role_ref.natural_key.rsplit("/", 1)[-1]
            try:
                matches = _overbroad_bedrock_permissions(self.iam_client, role_name)
            except AwsStackDiscoveryError as error:
                warnings.append(str(error))
                continue
            if matches:
                context = role_context[role_ref]
                findings.append(
                    self._finding(
                        role_arn=role_ref.natural_key,
                        role_name=role_name,
                        model_ids=sorted(context["models"]),
                        workload_names=sorted(context["workloads"]),
                        matches=matches,
                        observed_at=observed_at,
                    )
                )

        state = CoverageState.PARTIAL if warnings else CoverageState.COMPLETE
        detail = "; ".join(dict.fromkeys(warnings))[:4_000] if warnings else None
        return FindingBatch(
            connector_id=self.connector_id,
            connection_id=connection_id,
            run_id=f"aws-deployment-iam-{self.region}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=(Coverage(FINDINGS_PLANE, state, scope, detail),),
            findings=tuple(findings),
            authoritative=True,
        )

    def _finding(
        self,
        *,
        role_arn: str,
        role_name: str,
        model_ids: list[str],
        workload_names: list[str],
        matches: list[dict[str, Any]],
        observed_at: datetime,
    ) -> FindingAssertion:
        workload_label = ", ".join(workload_names)
        return FindingAssertion(
            source_uid=f"{role_arn}:bedrock-model-family-wildcard",
            rule_uid="DENALI-AWS-AI-IAM-001",
            title=f"{workload_label} execution role permits a broader Bedrock model scope",
            description=(
                "AWS returned an Allow statement for Bedrock invocation against a wildcard "
                "model resource. The observed workload configuration names narrower model "
                "identifiers."
            ),
            risk=(
                "A compromised workload or unintended configuration change could select another "
                "model covered by the role, expanding model choice, cost, and data-processing "
                "behavior beyond the deployed configuration."
            ),
            remediation=(
                "Replace wildcard Bedrock model resources with the exact foundation-model and "
                "inference-profile ARNs required by the approved workload, then recollect AWS "
                "evidence."
            ),
            remediation_references=(),
            severity=FindingSeverity.MEDIUM,
            state=FindingState.OPEN,
            evaluation_result=EvaluationResult.FAIL,
            class_uid=2003,
            class_name="Compliance Finding",
            observed_at=observed_at,
            evidence=Evidence(
                source_type="aws_control_plane",
                locator=f"aws://{self.account_id}/iam/role/{role_name}",
                observed_at=observed_at,
                payload={
                    "configured_model_ids": model_ids,
                    "workload_names": workload_names,
                    "matching_policy_statements": matches,
                    "evaluation": "allow_bedrock_invoke_with_wildcard_model_identifier",
                },
            ),
            affected_resources=(
                AffectedResource(
                    uid=role_arn,
                    name=role_name,
                    resource_type="AWS IAM Role",
                    provider="AWS",
                    account_uid=self.account_id,
                    region=self.region,
                ),
            ),
            attributes={
                "category": "AI Configuration",
                "product": "Denali AWS Deployment IAM Posture",
                "denali_signal": "identity.bedrock_model_family_wildcard",
                "service": "iam",
                "role_arn": role_arn,
            },
        )
