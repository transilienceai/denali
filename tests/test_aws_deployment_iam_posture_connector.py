from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from denali.connectors.aws_deployment_iam_posture import (
    FINDINGS_PLANE,
    AwsDeploymentIamPostureConnector,
)
from denali.domain import (
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    Coverage,
    CoverageState,
    Evidence,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
)

OBSERVED_AT = datetime(2026, 9, 8, 20, 0, tzinfo=UTC)
WORKLOAD = AssetRef(
    AssetKind.AI_WORKLOAD,
    "arn:aws:lambda:ap-south-1:331145994818:function:ni-sales-agent",
)
ROLE = AssetRef(
    AssetKind.IDENTITY,
    "arn:aws:iam::331145994818:role/NiSalesAgentStack-AgentFnServiceRole372EE73B",
)
MODEL = AssetRef(
    AssetKind.AI_MODEL,
    "aws:bedrock:model:global.anthropic.claude-sonnet-4-5-20250929-v1:0",
)


class AwsError(Exception):
    def __init__(self, code: str, detail: str = "private-provider-detail"):
        super().__init__(detail)
        self.response = {"Error": {"Code": code, "Message": detail}}


class IamClient:
    def __init__(self, error: Exception | None = None):
        self.error = error

    def list_role_policies(self, **_kwargs: Any) -> dict[str, Any]:
        if self.error:
            raise self.error
        return {"PolicyNames": ["AgentPolicy"], "IsTruncated": False}

    def get_role_policy(self, **_kwargs: Any) -> dict[str, Any]:
        return {
            "PolicyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Action": ["bedrock:InvokeModel", "bedrock:Converse"],
                    "Resource": "arn:aws:bedrock:*::foundation-model/anthropic.*",
                }
            }
        }

    def list_attached_role_policies(self, **_kwargs: Any) -> dict[str, Any]:
        return {"AttachedPolicies": [], "IsTruncated": False}


def _batch(*, include_model: bool = True) -> InventoryBatch:
    evidence = Evidence("aws_control_plane", "aws://fixture", OBSERVED_AT)
    assets = [
        AssetAssertion(
            asset=WORKLOAD,
            coverage_plane="aws_lambda_deployment_inventory",
            display_name="ni-sales-agent",
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=evidence,
        ),
        AssetAssertion(
            asset=ROLE,
            coverage_plane="aws_lambda_deployment_inventory",
            display_name="AgentFnServiceRole372EE73B",
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=evidence,
        ),
    ]
    relationships = [
        RelationshipAssertion(
            source=WORKLOAD,
            target=ROLE,
            coverage_plane="aws_lambda_deployment_relationships",
            kind=RelationshipKind.RUNS_AS,
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=evidence,
        )
    ]
    if include_model:
        assets.append(
            AssetAssertion(
                asset=MODEL,
                coverage_plane="aws_lambda_deployment_inventory",
                display_name="Claude Sonnet 4.5",
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                evidence=evidence,
                attributes={
                    "model_id": "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
                },
            )
        )
        relationships.append(
            RelationshipAssertion(
                source=WORKLOAD,
                target=MODEL,
                coverage_plane="aws_lambda_deployment_relationships",
                kind=RelationshipKind.USES,
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                evidence=evidence,
            )
        )
    return InventoryBatch(
        connector_id="denali.aws_deployments",
        connection_id="connection",
        run_id="run",
        scope_key="aws:331145994818:ap-south-1",
        collected_at=OBSERVED_AT,
        coverage=(
            Coverage(
                "aws_lambda_deployment_inventory",
                CoverageState.COMPLETE,
                "aws:331145994818:ap-south-1",
            ),
            Coverage(
                "aws_lambda_deployment_relationships",
                CoverageState.COMPLETE,
                "aws:331145994818:ap-south-1",
            ),
        ),
        assets=tuple(assets),
        relationships=tuple(relationships),
    )


def test_evaluates_only_roles_linked_to_observed_bedrock_models() -> None:
    connector = AwsDeploymentIamPostureConnector(
        account_id="331145994818",
        region="ap-south-1",
        iam_client=IamClient(),
    )

    batch = connector.collect(_batch(), connection_id="connection")

    assert batch.coverage[0].state is CoverageState.COMPLETE
    assert batch.coverage[0].plane == FINDINGS_PLANE
    assert len(batch.findings) == 1
    finding = batch.findings[0]
    assert finding.attributes["denali_signal"] == "identity.bedrock_model_family_wildcard"
    assert finding.affected_resources[0].uid == ROLE.natural_key
    assert finding.evidence.payload["configured_model_ids"] == [
        "global.anthropic.claude-sonnet-4-5-20250929-v1:0"
    ]

    without_model = connector.collect(_batch(include_model=False), connection_id="connection")
    assert without_model.findings == ()


def test_iam_denial_is_partial_and_does_not_leak_provider_detail() -> None:
    batch = AwsDeploymentIamPostureConnector(
        account_id="331145994818",
        region="ap-south-1",
        iam_client=IamClient(AwsError("AccessDenied")),
    ).collect(_batch(), connection_id="connection")

    assert batch.coverage[0].state is CoverageState.PARTIAL
    assert "AccessDenied" in (batch.coverage[0].detail or "")
    assert "private-provider-detail" not in str(batch)
    assert batch.findings == ()
