"""Deterministic issue-correlation contracts.

An issue is a derived security conclusion supported by existing findings, assets, and
relationship assertions. It never creates inventory or fills a missing graph edge.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from denali.domain.findings import FindingSeverity
from denali.domain.inventory import CoverageState


class IssueState(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class CorrelationAsset:
    id: str
    kind: str
    natural_key: str
    display_name: str
    assertion_type: str
    confidence: float
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class CorrelationRelationship:
    id: str
    source_id: str
    target_id: str
    kind: str
    category: str
    assertion_type: str
    confidence: float
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class CorrelationFinding:
    id: str
    source_uid: str
    rule_uid: str
    title: str
    severity: FindingSeverity
    state: str
    evaluation_result: str
    resource_uids: tuple[str, ...]
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class CorrelationSnapshot:
    assets: tuple[CorrelationAsset, ...]
    relationships: tuple[CorrelationRelationship, ...]
    findings: tuple[CorrelationFinding, ...]


@dataclass(frozen=True, slots=True)
class CorrelationRuntimeDetection:
    id: str
    rule_uid: str
    title: str
    severity: FindingSeverity
    state: str
    confidence: float
    first_seen_at: datetime
    last_seen_at: datetime
    activity_ids: tuple[str, ...]
    asset_ids: tuple[str, ...]
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.first_seen_at.tzinfo is None or self.last_seen_at.tzinfo is None:
            raise ValueError("correlated detection timestamps must be timezone-aware")
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class IssueFindingLink:
    finding_id: str
    role: str


@dataclass(frozen=True, slots=True)
class IssueDetectionLink:
    detection_id: str
    role: str


@dataclass(frozen=True, slots=True)
class IssueActivityLink:
    activity_id: str
    role: str


@dataclass(frozen=True, slots=True)
class IssuePathNode:
    asset_id: str
    position: int
    role: str


@dataclass(frozen=True, slots=True)
class IssuePathEdge:
    relationship_id: str
    position: int


@dataclass(frozen=True, slots=True)
class IssueCandidate:
    correlation_key: str
    rule_uid: str
    title: str
    description: str
    risk: str
    remediation: str
    severity: FindingSeverity
    confidence: float
    findings: tuple[IssueFindingLink, ...]
    path_nodes: tuple[IssuePathNode, ...]
    path_edges: tuple[IssuePathEdge, ...]
    detections: tuple[IssueDetectionLink, ...] = ()
    activities: tuple[IssueActivityLink, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.correlation_key or not self.rule_uid or not self.title:
            raise ValueError("issue identity and title must be non-empty")
        if not 0 <= self.confidence <= 1:
            raise ValueError("issue confidence must be between zero and one")
        if len({item.finding_id for item in self.findings}) != len(self.findings):
            raise ValueError("an issue cannot repeat a contributing finding")
        if len({item.detection_id for item in self.detections}) != len(self.detections):
            raise ValueError("an issue cannot repeat a contributing detection")
        if len({item.activity_id for item in self.activities}) != len(self.activities):
            raise ValueError("an issue cannot repeat a contributing activity")
        if len({item.position for item in self.path_nodes}) != len(self.path_nodes):
            raise ValueError("issue path node positions must be unique")
        if len({item.position for item in self.path_edges}) != len(self.path_edges):
            raise ValueError("issue path edge positions must be unique")
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class IssueEvaluation:
    rule_uid: str
    state: CoverageState
    evaluated_at: datetime
    candidates: tuple[IssueCandidate, ...]
    incomplete_candidates: int = 0
    ambiguous_resource_references: int = 0
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.evaluated_at.tzinfo is None:
            raise ValueError("issue evaluation time must be timezone-aware")
        if len({item.correlation_key for item in self.candidates}) != len(self.candidates):
            raise ValueError("an issue evaluation cannot repeat a correlation key")
