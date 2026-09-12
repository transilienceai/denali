"""Deterministic runtime-detection contracts.

Runtime detections are evaluated conclusions over immutable activity observations.
They retain links to the exact source events and inventory assets that supported the
conclusion; they never create either kind of evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from denali.domain.findings import FindingSeverity
from denali.domain.inventory import CoverageState


class RuntimeDetectionState(StrEnum):
    OPEN = "open"
    RESOLVED = "resolved"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class DetectionActivityEntity:
    role: str
    external_uid: str
    display_name: str | None = None
    asset_id: str | None = None


@dataclass(frozen=True, slots=True)
class DetectionActivity:
    id: str
    category: str
    outcome: str
    title: str
    occurred_at: datetime
    provider: str | None = None
    connection_id: str | None = None
    session_key: str | None = None
    session_uid: str | None = None
    trace_uid: str | None = None
    span_uid: str | None = None
    parent_span_uid: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    entities: tuple[DetectionActivityEntity, ...] = ()

    def __post_init__(self) -> None:
        if self.occurred_at.tzinfo is None:
            raise ValueError("detection activity timestamps must be timezone-aware")
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))
        object.__setattr__(self, "evidence", MappingProxyType(dict(self.evidence)))


@dataclass(frozen=True, slots=True)
class DetectionAsset:
    id: str
    kind: str
    natural_key: str
    display_name: str
    governance_status: str
    lifecycle_state: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class DetectionSnapshot:
    activities: tuple[DetectionActivity, ...]
    assets: tuple[DetectionAsset, ...]
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class DetectionActivityLink:
    activity_id: str
    role: str


@dataclass(frozen=True, slots=True)
class DetectionAssetLink:
    asset_id: str
    role: str


@dataclass(frozen=True, slots=True)
class RuntimeDetectionCandidate:
    correlation_key: str
    rule_uid: str
    title: str
    description: str
    risk: str
    investigation_guidance: str
    severity: FindingSeverity
    confidence: float
    first_seen_at: datetime
    last_seen_at: datetime
    activities: tuple[DetectionActivityLink, ...]
    assets: tuple[DetectionAssetLink, ...]
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.correlation_key or not self.rule_uid or not self.title:
            raise ValueError("runtime detection identity and title must be non-empty")
        if not 0 <= self.confidence <= 1:
            raise ValueError("runtime detection confidence must be between zero and one")
        if self.first_seen_at.tzinfo is None or self.last_seen_at.tzinfo is None:
            raise ValueError("runtime detection timestamps must be timezone-aware")
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("runtime detection last_seen_at cannot precede first_seen_at")
        if len({item.activity_id for item in self.activities}) != len(self.activities):
            raise ValueError("a runtime detection cannot repeat an activity")
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class RuntimeDetectionEvaluation:
    rule_uid: str
    state: CoverageState
    evaluated_at: datetime
    candidates: tuple[RuntimeDetectionCandidate, ...]
    incomplete_candidates: int = 0
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.evaluated_at.tzinfo is None:
            raise ValueError("runtime detection evaluation time must be timezone-aware")
        if len({item.correlation_key for item in self.candidates}) != len(self.candidates):
            raise ValueError("a runtime detection evaluation cannot repeat a correlation key")
