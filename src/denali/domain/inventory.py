"""Provider-neutral inventory contracts.

These are deliberately not Prowler, AWS, Azure, GitHub, or MCP shapes. A connector
translates its source into these assertions; Denali retains the source record and
evidence so normalization never erases provenance.

An asset is a durable identity. An assertion is one source's claim about that asset.
Multiple sources may assert the same asset simultaneously and may disagree. Lifecycle
is derived from active assertions; one source cannot delete another source's knowledge.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any


class AssetKind(StrEnum):
    AI_APPLICATION = "ai_application"
    AI_AGENT = "ai_agent"
    AI_MODEL = "ai_model"
    MODEL_ARTIFACT = "model_artifact"
    MCP_SERVER = "mcp_server"
    AI_TOOL = "ai_tool"
    AI_GUARDRAIL = "ai_guardrail"
    AI_PIPELINE = "ai_pipeline"
    AI_DATASTORE = "ai_datastore"
    AI_WORKLOAD = "ai_workload"
    AI_FRAMEWORK = "ai_framework"
    CODE_REPOSITORY = "code_repository"
    CLOUD_RESOURCE = "cloud_resource"
    IDENTITY = "identity"
    APPLICATION_ENDPOINT = "application_endpoint"
    SOFTWARE_COMPONENT = "software_component"


class InventoryCategory(StrEnum):
    AI = "ai"
    SUPPORTING = "supporting"
    COMPONENTS = "components"


ASSET_CATEGORY_KINDS: Mapping[InventoryCategory, tuple[AssetKind, ...]] = MappingProxyType(
    {
        InventoryCategory.AI: (
            AssetKind.AI_APPLICATION,
            AssetKind.AI_AGENT,
            AssetKind.AI_MODEL,
            AssetKind.MODEL_ARTIFACT,
            AssetKind.MCP_SERVER,
            AssetKind.AI_TOOL,
            AssetKind.AI_GUARDRAIL,
            AssetKind.AI_PIPELINE,
            AssetKind.AI_DATASTORE,
            AssetKind.AI_WORKLOAD,
            AssetKind.AI_FRAMEWORK,
            AssetKind.APPLICATION_ENDPOINT,
        ),
        InventoryCategory.SUPPORTING: (
            AssetKind.CODE_REPOSITORY,
            AssetKind.CLOUD_RESOURCE,
            AssetKind.IDENTITY,
        ),
        InventoryCategory.COMPONENTS: (AssetKind.SOFTWARE_COMPONENT,),
    }
)


class AssertionType(StrEnum):
    DECLARED = "declared"
    INFERRED = "inferred"
    OBSERVED = "observed"
    EXTERNALLY_VERIFIED = "externally_verified"


class LifecycleState(StrEnum):
    ACTIVE = "active"
    WITHDRAWN = "withdrawn"
    UNKNOWN = "unknown"


class GovernanceStatus(StrEnum):
    APPROVED = "approved"
    UNREVIEWED = "unreviewed"
    UNWANTED = "unwanted"


class CoverageState(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_SUPPORTED = "not_supported"
    UNKNOWN = "unknown"


class RelationshipCategory(StrEnum):
    CAPABILITY = "capability"
    INFLUENCE = "influence"
    TOPOLOGY = "topology"


class RelationshipKind(StrEnum):
    # Permissions and authority. These may participate in a maximum blast-radius walk.
    CAN_INVOKE = "can_invoke"
    CAN_READ = "can_read"
    CAN_WRITE = "can_write"
    RUNS_AS = "runs_as"
    REACHES = "reaches"

    # Persuasion or steering. Never permission, never traversed as authority.
    INFLUENCES = "influences"

    # Structural and lineage relationships.
    USES = "uses"
    HOSTED_ON = "hosted_on"
    DEFINED_IN = "defined_in"
    DEPLOYED_BY = "deployed_by"
    PROTECTED_BY = "protected_by"
    TRAINS_ON = "trains_on"
    CONNECTS_TO = "connects_to"
    EXPOSES = "exposes"
    CONTAINS_COMPONENT = "contains_component"
    DEPENDS_ON = "depends_on"

    @property
    def category(self) -> RelationshipCategory:
        if self in {
            self.CAN_INVOKE,
            self.CAN_READ,
            self.CAN_WRITE,
            self.RUNS_AS,
            self.REACHES,
        }:
            return RelationshipCategory.CAPABILITY
        if self is self.INFLUENCES:
            return RelationshipCategory.INFLUENCE
        return RelationshipCategory.TOPOLOGY


@dataclass(frozen=True, slots=True)
class AssetRef:
    kind: AssetKind
    natural_key: str

    def __post_init__(self) -> None:
        if not self.natural_key or not self.natural_key.strip():
            raise ValueError("asset natural_key must be non-empty")
        if self.natural_key != self.natural_key.strip():
            raise ValueError("asset natural_key must not have surrounding whitespace")

    @property
    def canonical_key(self) -> str:
        return f"{self.kind.value}:{self.natural_key}"


@dataclass(frozen=True, slots=True)
class Evidence:
    """The source material supporting one assertion.

    ``payload`` contains the smallest useful source fragment, not an unbounded response.
    ``locator`` points back to the original record, file, API object, or event.
    """

    source_type: str
    locator: str
    observed_at: datetime
    payload: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source_type.strip():
            raise ValueError("evidence source_type must be non-empty")
        if not self.locator.strip():
            raise ValueError("evidence locator must be non-empty")
        if self.observed_at.tzinfo is None:
            raise ValueError("evidence observed_at must be timezone-aware")
        object.__setattr__(self, "payload", MappingProxyType(dict(self.payload)))


@dataclass(frozen=True, slots=True)
class AssetAssertion:
    asset: AssetRef
    coverage_plane: str
    display_name: str
    assertion_type: AssertionType
    confidence: float
    evidence: Evidence
    attributes: Mapping[str, Any] = field(default_factory=dict)
    lifecycle: LifecycleState = LifecycleState.ACTIVE

    def __post_init__(self) -> None:
        if not self.coverage_plane.strip():
            raise ValueError("asset coverage_plane must be non-empty")
        if not self.display_name.strip():
            raise ValueError("asset display_name must be non-empty")
        _validate_confidence(self.confidence)
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class RelationshipAssertion:
    source: AssetRef
    target: AssetRef
    coverage_plane: str
    kind: RelationshipKind
    assertion_type: AssertionType
    confidence: float
    evidence: Evidence
    attributes: Mapping[str, Any] = field(default_factory=dict)
    principal_ref: AssetRef | None = None
    agent_ref: AssetRef | None = None

    def __post_init__(self) -> None:
        if not self.coverage_plane.strip():
            raise ValueError("relationship coverage_plane must be non-empty")
        if self.source == self.target:
            raise ValueError("relationship source and target must differ")
        _validate_confidence(self.confidence)
        if self.principal_ref is not None and self.principal_ref.kind is not AssetKind.IDENTITY:
            raise ValueError("principal_ref must reference an identity")
        if self.agent_ref is not None and self.agent_ref.kind is not AssetKind.AI_AGENT:
            raise ValueError("agent_ref must reference an AI agent")
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))

    @property
    def category(self) -> RelationshipCategory:
        return self.kind.category


@dataclass(frozen=True, slots=True)
class ConnectorCapabilities:
    """What a connector can actually provide.

    The UI and issue engine consume this declaration. A findings-only source must never
    be presented as though Denali had inspected its inventory or relationship graph.
    """

    findings: bool = False
    inventory: bool = False
    relationships: bool = False
    activity: bool = False

    def __post_init__(self) -> None:
        if not any((self.findings, self.inventory, self.relationships, self.activity)):
            raise ValueError("a connector must provide at least one capability")


@dataclass(frozen=True, slots=True)
class Coverage:
    plane: str
    state: CoverageState
    scope: str
    detail: str | None = None

    def __post_init__(self) -> None:
        if not self.plane.strip():
            raise ValueError("coverage plane must be non-empty")
        if not self.scope.strip():
            raise ValueError("coverage scope must be non-empty")

    @property
    def authorizes_withdrawal(self) -> bool:
        """Only positive, complete coverage makes absence meaningful."""

        return self.state is CoverageState.COMPLETE


@dataclass(frozen=True, slots=True)
class InventoryBatch:
    """One connector run over one explicit reconciliation scope."""

    connector_id: str
    connection_id: str
    run_id: str
    scope_key: str
    collected_at: datetime
    coverage: tuple[Coverage, ...]
    assets: tuple[AssetAssertion, ...] = ()
    relationships: tuple[RelationshipAssertion, ...] = ()

    def __post_init__(self) -> None:
        for label, value in {
            "connector_id": self.connector_id,
            "connection_id": self.connection_id,
            "run_id": self.run_id,
            "scope_key": self.scope_key,
        }.items():
            if not value.strip():
                raise ValueError(f"{label} must be non-empty")
        if self.collected_at.tzinfo is None:
            raise ValueError("collected_at must be timezone-aware")
        if not self.coverage:
            raise ValueError("inventory batches must state coverage")
        declared_planes = {item.plane for item in self.coverage}
        assertion_planes = {
            *(item.coverage_plane for item in self.assets),
            *(item.coverage_plane for item in self.relationships),
        }
        undeclared = assertion_planes - declared_planes
        if undeclared:
            raise ValueError(
                "assertions use coverage planes the batch did not declare: "
                + ", ".join(sorted(undeclared))
            )
        _reject_conflicting_duplicates(self.assets)

    def may_withdraw(self, plane: str) -> bool:
        matches = [item for item in self.coverage if item.plane == plane]
        return bool(matches) and all(item.authorizes_withdrawal for item in matches)

    @classmethod
    def empty_complete(
        cls,
        *,
        connector_id: str,
        connection_id: str,
        run_id: str,
        scope_key: str,
        plane: str,
        scope: str,
    ) -> InventoryBatch:
        """An explicit successful empty result; different from failure or no execution."""

        return cls(
            connector_id=connector_id,
            connection_id=connection_id,
            run_id=run_id,
            scope_key=scope_key,
            collected_at=datetime.now(UTC),
            coverage=(Coverage(plane=plane, state=CoverageState.COMPLETE, scope=scope),),
        )


def _validate_confidence(value: float) -> None:
    if not 0.0 <= value <= 1.0:
        raise ValueError("confidence must be between 0.0 and 1.0")


def _reject_conflicting_duplicates(assertions: tuple[AssetAssertion, ...]) -> None:
    seen: dict[tuple[AssetRef, AssertionType], AssetAssertion] = {}
    for assertion in assertions:
        key = (assertion.asset, assertion.assertion_type)
        previous = seen.get(key)
        if previous is not None and previous != assertion:
            raise ValueError(
                "one batch cannot contain conflicting assertions for "
                f"{assertion.asset.canonical_key} at {assertion.assertion_type.value}"
            )
        seen[key] = assertion
