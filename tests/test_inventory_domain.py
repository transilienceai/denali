from datetime import UTC, datetime

import pytest

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
    InventoryCategory,
    RelationshipAssertion,
    RelationshipCategory,
    RelationshipKind,
)
from denali.domain.inventory import ASSET_CATEGORY_KINDS


def evidence() -> Evidence:
    return Evidence(
        source_type="test_fixture",
        locator="fixture://inventory/agent-1",
        observed_at=datetime.now(UTC),
        payload={"id": "agent-1"},
    )


def agent() -> AssetAssertion:
    return AssetAssertion(
        asset=AssetRef(AssetKind.AI_AGENT, "aws:123:us-east-1:agent-1"),
        coverage_plane="agents",
        display_name="Agent One",
        assertion_type=AssertionType.EXTERNALLY_VERIFIED,
        confidence=1.0,
        evidence=evidence(),
    )


def batch(state: CoverageState) -> InventoryBatch:
    return InventoryBatch(
        connector_id="aws",
        connection_id="connection-1",
        run_id="run-1",
        scope_key="us-east-1",
        collected_at=datetime.now(UTC),
        coverage=(Coverage("agents", state, "account=123,region=us-east-1"),),
        assets=(agent(),),
    )


@pytest.mark.parametrize(
    "state",
    [
        CoverageState.PARTIAL,
        CoverageState.FAILED,
        CoverageState.UNKNOWN,
        CoverageState.NOT_SUPPORTED,
    ],
)
def test_only_complete_coverage_authorizes_withdrawal(state: CoverageState) -> None:
    assert batch(state).may_withdraw("agents") is False


def test_complete_coverage_authorizes_withdrawal() -> None:
    assert batch(CoverageState.COMPLETE).may_withdraw("agents") is True


def test_every_asset_kind_has_one_inventory_category() -> None:
    categorized = [
        kind
        for category in InventoryCategory
        for kind in ASSET_CATEGORY_KINDS[category]
    ]
    assert set(categorized) == set(AssetKind)
    assert len(categorized) == len(set(categorized))


def test_empty_success_is_explicit_and_can_reconcile() -> None:
    result = InventoryBatch.empty_complete(
        connector_id="aws",
        connection_id="connection-1",
        run_id="run-2",
        scope_key="us-east-1",
        plane="agents",
        scope="account=123,region=us-east-1",
    )
    assert result.assets == ()
    assert result.may_withdraw("agents") is True


def test_capability_and_influence_are_different_categories() -> None:
    agent_ref = AssetRef(AssetKind.AI_AGENT, "agent-1")
    tool_ref = AssetRef(AssetKind.AI_TOOL, "tool-1")
    capability = RelationshipAssertion(
        source=agent_ref,
        target=tool_ref,
        coverage_plane="capabilities",
        kind=RelationshipKind.CAN_INVOKE,
        assertion_type=AssertionType.DECLARED,
        confidence=0.9,
        evidence=evidence(),
        agent_ref=agent_ref,
    )
    influence = RelationshipAssertion(
        source=tool_ref,
        target=agent_ref,
        coverage_plane="capabilities",
        kind=RelationshipKind.INFLUENCES,
        assertion_type=AssertionType.INFERRED,
        confidence=0.7,
        evidence=evidence(),
        agent_ref=agent_ref,
    )
    assert capability.category is RelationshipCategory.CAPABILITY
    assert influence.category is RelationshipCategory.INFLUENCE


def test_principal_ref_cannot_be_an_agent() -> None:
    agent_ref = AssetRef(AssetKind.AI_AGENT, "agent-1")
    tool_ref = AssetRef(AssetKind.AI_TOOL, "tool-1")
    with pytest.raises(ValueError, match="principal_ref must reference an identity"):
        RelationshipAssertion(
            source=agent_ref,
            target=tool_ref,
            coverage_plane="capabilities",
            kind=RelationshipKind.CAN_INVOKE,
            assertion_type=AssertionType.DECLARED,
            confidence=1.0,
            evidence=evidence(),
            principal_ref=agent_ref,
        )


def test_connector_must_declare_real_capability() -> None:
    with pytest.raises(ValueError, match="at least one capability"):
        ConnectorCapabilities()


def test_conflicting_duplicate_assertions_are_rejected() -> None:
    first = agent()
    second = AssetAssertion(
        asset=first.asset,
        coverage_plane=first.coverage_plane,
        display_name="Contradictory Name",
        assertion_type=first.assertion_type,
        confidence=first.confidence,
        evidence=first.evidence,
    )
    with pytest.raises(ValueError, match="conflicting assertions"):
        InventoryBatch(
            connector_id="aws",
            connection_id="connection-1",
            run_id="run-1",
            scope_key="us-east-1",
            collected_at=datetime.now(UTC),
            coverage=(Coverage("agents", CoverageState.COMPLETE, "us-east-1"),),
            assets=(first, second),
        )


def test_assertion_plane_must_have_a_coverage_declaration() -> None:
    with pytest.raises(ValueError, match="did not declare: agents"):
        InventoryBatch(
            connector_id="aws",
            connection_id="connection-1",
            run_id="run-1",
            scope_key="us-east-1",
            collected_at=datetime.now(UTC),
            coverage=(Coverage("guardrails", CoverageState.COMPLETE, "us-east-1"),),
            assets=(agent(),),
        )
