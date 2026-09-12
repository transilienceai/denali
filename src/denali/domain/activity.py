"""Provider-neutral, evidence-bearing runtime activity contracts.

Activity records describe observations, not detections or security issues.  An adapter
may correlate an entity to existing inventory, but it may never create inventory from
an event reference.  This keeps runtime telemetry useful without turning logs into
unearned topology claims.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from math import isfinite
from types import MappingProxyType
from typing import Any

from denali.domain.inventory import AssetRef, Coverage, Evidence


class ActivityCategory(StrEnum):
    MODEL_INVOCATION = "model_invocation"
    AGENT_INVOCATION = "agent_invocation"
    RETRIEVAL = "retrieval"
    TOOL_INVOCATION = "tool_invocation"
    AI_APP_SIGN_IN = "ai_app_sign_in"
    ADMIN_CHANGE = "admin_change"
    DATA_ACCESS = "data_access"
    OTHER = "other"


class ActivityOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class ActivityEntityRole(StrEnum):
    ACTOR = "actor"
    AGENT = "agent"
    MODEL = "model"
    TOOL = "tool"
    WORKLOAD = "workload"
    RESOURCE = "resource"
    APPLICATION = "application"


class ActivityCorrelation(StrEnum):
    EXACT_IDENTIFIER = "exact_identifier"
    EXPLICIT_CONTEXT = "explicit_context"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class ActivityEntity:
    role: ActivityEntityRole
    external_uid: str
    display_name: str | None = None
    asset: AssetRef | None = None
    correlation: ActivityCorrelation = ActivityCorrelation.UNRESOLVED
    confidence: float = 0.0
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.external_uid.strip() or self.external_uid != self.external_uid.strip():
            raise ValueError("activity entity external_uid must be non-empty and trimmed")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("activity entity confidence must be between 0 and 1")
        if self.asset is None:
            if self.correlation is not ActivityCorrelation.UNRESOLVED or self.confidence != 0.0:
                raise ValueError(
                    "an unlinked activity entity must be unresolved with zero confidence"
                )
        elif self.correlation is ActivityCorrelation.UNRESOLVED or self.confidence <= 0.0:
            raise ValueError(
                "a linked activity entity needs an explicit correlation and confidence"
            )
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class ActivityRecord:
    source_uid: str
    category: ActivityCategory
    activity_name: str
    title: str
    occurred_at: datetime
    observed_at: datetime
    outcome: ActivityOutcome
    provider: str
    evidence: Evidence
    account_uid: str | None = None
    region: str | None = None
    session_uid: str | None = None
    trace_uid: str | None = None
    span_uid: str | None = None
    parent_span_uid: str | None = None
    completed_at: datetime | None = None
    duration_ms: float | None = None
    telemetry_convention: str | None = None
    content_policy: str = "metadata_only"
    entities: tuple[ActivityEntity, ...] = ()
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for label, value in {
            "source_uid": self.source_uid,
            "activity_name": self.activity_name,
            "title": self.title,
            "provider": self.provider,
        }.items():
            if not value.strip() or value != value.strip():
                raise ValueError(f"activity {label} must be non-empty and trimmed")
        if self.occurred_at.tzinfo is None or self.observed_at.tzinfo is None:
            raise ValueError("activity timestamps must be timezone-aware")
        if self.completed_at is not None:
            if self.completed_at.tzinfo is None:
                raise ValueError("activity completion timestamp must be timezone-aware")
            if self.completed_at < self.occurred_at:
                raise ValueError("activity completion cannot precede its start")
        if self.duration_ms is not None and (
            not isfinite(self.duration_ms) or self.duration_ms < 0
        ):
            raise ValueError("activity duration must be finite and non-negative")
        if self.content_policy not in {"metadata_only", "redacted", "explicit_content"}:
            raise ValueError("activity content policy is invalid")
        if self.evidence.observed_at != self.observed_at:
            raise ValueError("activity and evidence observation times must match")
        identities = [(entity.role, entity.external_uid) for entity in self.entities]
        if len(set(identities)) != len(identities):
            raise ValueError("an activity cannot repeat an entity role and external_uid")
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True)
class ActivityBatch:
    connector_id: str
    connection_id: str
    run_id: str
    scope_key: str
    collected_at: datetime
    coverage: tuple[Coverage, ...]
    activities: tuple[ActivityRecord, ...] = ()

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
            raise ValueError("activity batches must state coverage")
        source_uids = [activity.source_uid for activity in self.activities]
        if len(set(source_uids)) != len(source_uids):
            raise ValueError("one activity batch cannot repeat a source_uid")
