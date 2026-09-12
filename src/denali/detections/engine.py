"""Pure runtime-detection rules over bounded activity and inventory snapshots."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from denali.domain import (
    CoverageState,
    DetectionActivity,
    DetectionActivityLink,
    DetectionAsset,
    DetectionAssetLink,
    DetectionSnapshot,
    FindingSeverity,
    RuntimeDetectionCandidate,
    RuntimeDetectionEvaluation,
)

ENTRA_FAILURE_RULE_UID = "DENALI-RUNTIME-ENTRA-FAILURES-001"
ENTRA_CONSENT_RULE_UID = "DENALI-RUNTIME-ENTRA-CONSENT-001"
UNREVIEWED_MODEL_RULE_UID = "DENALI-RUNTIME-UNREVIEWED-MODEL-001"
AWS_UNDECLARED_MODEL_RULE_UID = "DENALI-RUNTIME-AWS-UNDECLARED-MODEL-001"
AWS_UNAPPROVED_TOOL_RULE_UID = "DENALI-RUNTIME-AWS-UNAPPROVED-TOOL-001"
AWS_RISKY_SEQUENCE_RULE_UID = "DENALI-RUNTIME-AWS-RISKY-SEQUENCE-001"
FAILURE_THRESHOLD = 3
FAILURE_WINDOW = timedelta(hours=24)
CONSENT_OPERATIONS = (
    "consent to application",
    "add delegated permission grant",
    "add app role assignment grant",
)
HIGH_IMPACT_SCOPES = {
    "mail.readwrite",
    "mail.readwrite.shared",
    "files.readwrite.all",
    "sites.fullcontrol.all",
    "directory.readwrite.all",
    "rolemanagement.readwrite.directory",
}
AWS_SEQUENCE_WINDOW = timedelta(minutes=5)
MUTATING_TOOL_TOKENS = (
    "create",
    "delete",
    "execute",
    "invoke",
    "post",
    "publish",
    "put",
    "send",
    "update",
    "write",
)


def evaluate_repeated_failed_ai_signins(
    snapshot: DetectionSnapshot,
    *,
    coverage_state: CoverageState,
    evaluated_at: datetime | None = None,
) -> RuntimeDetectionEvaluation:
    """Detect repeated failures for the same exact actor and AI application."""

    now = evaluated_at or datetime.now(UTC)
    grouped: dict[tuple[str, str], list[tuple[DetectionActivity, DetectionAsset]]] = defaultdict(
        list
    )
    incomplete = 0
    assets = {asset.id: asset for asset in snapshot.assets}
    for activity in snapshot.activities:
        if activity.category != "ai_app_sign_in" or activity.outcome != "failure":
            continue
        actor = _one_entity(activity, "actor")
        application = _one_entity(activity, "application")
        app_asset = assets.get(application.asset_id) if application else None
        if (
            actor is None
            or application is None
            or app_asset is None
            or app_asset.kind != "ai_application"
        ):
            incomplete += 1
            continue
        grouped[(actor.external_uid.casefold(), app_asset.id)].append((activity, app_asset))

    candidates: list[RuntimeDetectionCandidate] = []
    for (actor_uid, asset_id), items in grouped.items():
        items.sort(key=lambda item: item[0].occurred_at)
        best: list[tuple[DetectionActivity, DetectionAsset]] = []
        left = 0
        for right, item in enumerate(items):
            while item[0].occurred_at - items[left][0].occurred_at > FAILURE_WINDOW:
                left += 1
            window = items[left : right + 1]
            if len(window) > len(best):
                best = window
        if len(best) < FAILURE_THRESHOLD:
            continue
        activities = tuple(item[0] for item in best)
        app = best[0][1]
        actor = _one_entity(activities[-1], "actor")
        actor_name = (actor.display_name if actor else None) or actor_uid
        correlation_key = _key(ENTRA_FAILURE_RULE_UID, actor_uid, asset_id)
        candidates.append(
            RuntimeDetectionCandidate(
                correlation_key=correlation_key,
                rule_uid=ENTRA_FAILURE_RULE_UID,
                title=f"Repeated failed access to {app.display_name}",
                description=(
                    f"{actor_name} had {len(activities)} failed sign-ins to "
                    f"{app.display_name} inside a 24-hour window."
                ),
                risk=(
                    "Repeated failures can indicate credential misuse, blocked automation, "
                    "or an access path that needs investigation. The failures alone do not "
                    "prove malicious activity."
                ),
                investigation_guidance=(
                    "Review the exact Entra sign-in records, authentication requirements, "
                    "IP and device context retained by Microsoft, and nearby successful "
                    "sign-ins for the same actor and application."
                ),
                severity=FindingSeverity.MEDIUM,
                confidence=1.0,
                first_seen_at=activities[0].occurred_at,
                last_seen_at=activities[-1].occurred_at,
                activities=tuple(
                    DetectionActivityLink(activity.id, "failed_sign_in") for activity in activities
                ),
                assets=(DetectionAssetLink(app.id, "ai_application"),),
                attributes={
                    "actor_uid": actor_uid,
                    "actor_display_name": actor_name,
                    "failure_count": len(activities),
                    "window_hours": 24,
                    "threshold": FAILURE_THRESHOLD,
                },
            )
        )
    return RuntimeDetectionEvaluation(
        rule_uid=ENTRA_FAILURE_RULE_UID,
        state=coverage_state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=(
            f"{incomplete} failed sign-in observations lacked an exact actor/application link"
            if incomplete
            else None
        ),
    )


def evaluate_unreviewed_ai_consent(
    snapshot: DetectionSnapshot,
    *,
    coverage_state: CoverageState,
    evaluated_at: datetime | None = None,
) -> RuntimeDetectionEvaluation:
    """Detect successful consent changes for exact, active, unreviewed AI apps."""

    now = evaluated_at or datetime.now(UTC)
    assets = {asset.id: asset for asset in snapshot.assets}
    grouped: dict[tuple[str, str, str], list[DetectionActivity]] = defaultdict(list)
    incomplete = 0
    for activity in snapshot.activities:
        if activity.category != "admin_change" or activity.outcome != "success":
            continue
        operation = _operation(activity).casefold()
        if not any(candidate in operation for candidate in CONSENT_OPERATIONS):
            continue
        actor = _one_entity(activity, "actor")
        application = _one_entity(activity, "application")
        app_asset = assets.get(application.asset_id) if application else None
        if actor is None or app_asset is None or app_asset.kind != "ai_application":
            incomplete += 1
            continue
        if app_asset.lifecycle_state != "active" or app_asset.governance_status != "unreviewed":
            continue
        trace = activity.trace_uid or activity.id
        grouped[(app_asset.id, actor.external_uid.casefold(), trace)].append(activity)

    candidates: list[RuntimeDetectionCandidate] = []
    for (asset_id, actor_uid, trace), activities in grouped.items():
        activities.sort(key=lambda item: item.occurred_at)
        app = assets[asset_id]
        actor = _one_entity(activities[-1], "actor")
        actor_name = (actor.display_name if actor else None) or actor_uid
        scopes = _scopes(app)
        high_impact = sorted(scope for scope in scopes if scope.casefold() in HIGH_IMPACT_SCOPES)
        severity = FindingSeverity.HIGH if high_impact else FindingSeverity.MEDIUM
        candidates.append(
            RuntimeDetectionCandidate(
                correlation_key=_key(ENTRA_CONSENT_RULE_UID, asset_id, actor_uid, trace),
                rule_uid=ENTRA_CONSENT_RULE_UID,
                title=f"Consent changed for unreviewed AI app {app.display_name}",
                description=(
                    f"{actor_name} performed {len(activities)} successful consent or permission "
                    f"change event(s) for unreviewed AI application {app.display_name}."
                ),
                risk=(
                    "A newly consented AI application may access tenant data under delegated "
                    "permissions before the organization has approved its use. This detection "
                    "does not claim that the application misused those permissions."
                ),
                investigation_guidance=(
                    "Confirm the business owner and approval status, inspect the exact Microsoft "
                    "audit events, review delegated scopes and verified publisher information, "
                    "and determine whether the grant should remain active."
                ),
                severity=severity,
                confidence=1.0,
                first_seen_at=activities[0].occurred_at,
                last_seen_at=activities[-1].occurred_at,
                activities=tuple(
                    DetectionActivityLink(activity.id, "consent_or_permission_change")
                    for activity in activities
                ),
                assets=(DetectionAssetLink(app.id, "unreviewed_ai_application"),),
                attributes={
                    "actor_uid": actor_uid,
                    "actor_display_name": actor_name,
                    "correlation_id": trace,
                    "event_count": len(activities),
                    "delegated_scopes": sorted(scopes),
                    "high_impact_scopes": high_impact,
                },
            )
        )
    return RuntimeDetectionEvaluation(
        rule_uid=ENTRA_CONSENT_RULE_UID,
        state=coverage_state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=(
            f"{incomplete} consent observations lacked an exact actor/application link"
            if incomplete
            else None
        ),
    )


def evaluate_unreviewed_model_invocation(
    snapshot: DetectionSnapshot,
    *,
    coverage_state: CoverageState,
    evaluated_at: datetime | None = None,
) -> RuntimeDetectionEvaluation:
    """Detect successful invocation of an exact model still awaiting governance review."""

    now = evaluated_at or datetime.now(UTC)
    assets = {asset.id: asset for asset in snapshot.assets}
    grouped: dict[str, list[DetectionActivity]] = defaultdict(list)
    incomplete = 0
    for activity in snapshot.activities:
        if activity.category != "model_invocation" or activity.outcome != "success":
            continue
        model_entity = _one_entity(activity, "model")
        model = assets.get(model_entity.asset_id) if model_entity else None
        if model is None or model.kind != "ai_model":
            incomplete += 1
            continue
        if model.lifecycle_state != "active" or model.governance_status != "unreviewed":
            continue
        grouped[model.id].append(activity)

    candidates: list[RuntimeDetectionCandidate] = []
    for model_id, activities in grouped.items():
        activities.sort(key=lambda item: (item.occurred_at, item.id))
        model = assets[model_id]
        actors = sorted(
            {
                entity.display_name or entity.external_uid
                for activity in activities
                for entity in activity.entities
                if entity.role == "actor"
            }
        )
        candidates.append(
            RuntimeDetectionCandidate(
                correlation_key=_key(UNREVIEWED_MODEL_RULE_UID, model.natural_key),
                rule_uid=UNREVIEWED_MODEL_RULE_UID,
                title=f"Unreviewed model {model.display_name} was invoked",
                description=(
                    f"Runtime telemetry recorded {len(activities)} successful invocation(s) "
                    f"of the exact model {model.display_name} while its governance status "
                    "remained unreviewed."
                ),
                risk=(
                    "An actively used model may process organizational data before model "
                    "ownership, allowed use, retention expectations, and provider terms have "
                    "been reviewed. This detection does not claim the invocation was harmful."
                ),
                investigation_guidance=(
                    "Confirm the workload owner and approved use case, review the linked runtime "
                    "event metadata and execution identity, then approve or reject the model "
                    "through the governance workflow."
                ),
                severity=FindingSeverity.MEDIUM,
                confidence=1.0,
                first_seen_at=activities[0].occurred_at,
                last_seen_at=activities[-1].occurred_at,
                activities=tuple(
                    DetectionActivityLink(activity.id, "successful_model_invocation")
                    for activity in activities
                ),
                assets=(DetectionAssetLink(model.id, "unreviewed_ai_model"),),
                attributes={
                    "model_natural_key": model.natural_key,
                    "invocation_count": len(activities),
                    "actors": actors,
                    "governance_status": model.governance_status,
                },
            )
        )
    return RuntimeDetectionEvaluation(
        rule_uid=UNREVIEWED_MODEL_RULE_UID,
        state=coverage_state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=(
            f"{incomplete} model invocation observations lacked one exact model asset link"
            if incomplete
            else None
        ),
    )


def evaluate_aws_undeclared_model_invocation(
    snapshot: DetectionSnapshot,
    *,
    coverage_state: CoverageState,
    evaluated_at: datetime | None = None,
) -> RuntimeDetectionEvaluation:
    """Detect an exact AWS model used by an agent without declared evidence."""

    now = evaluated_at or datetime.now(UTC)
    assets = {asset.id: asset for asset in snapshot.assets}
    agents_by_session = _aws_agents_by_session(snapshot, assets)
    grouped: dict[tuple[str, str], list[DetectionActivity]] = defaultdict(list)
    incomplete = 0
    for activity in snapshot.activities:
        if not _successful_aws(activity, "model_invocation"):
            continue
        model_entity = _one_entity(activity, "model")
        model = assets.get(model_entity.asset_id) if model_entity else None
        session = _session(activity)
        agents = agents_by_session.get(session, ()) if session else ()
        if model is None or model.kind != "ai_model" or len(agents) != 1:
            incomplete += 1
            continue
        if bool(model.attributes.get("_denali_declared")):
            continue
        grouped[(agents[0].id, model.id)].append(activity)

    candidates: list[RuntimeDetectionCandidate] = []
    for (agent_id, model_id), activities in grouped.items():
        activities.sort(key=lambda item: (item.occurred_at, item.id))
        agent, model = assets[agent_id], assets[model_id]
        candidates.append(
            RuntimeDetectionCandidate(
                correlation_key=_key(
                    AWS_UNDECLARED_MODEL_RULE_UID, agent.natural_key, model.natural_key
                ),
                rule_uid=AWS_UNDECLARED_MODEL_RULE_UID,
                title=f"{agent.display_name} invoked undeclared model {model.display_name}",
                description=(
                    f"AWS AgentCore telemetry recorded {len(activities)} successful invocation(s) "
                    f"of {model.display_name}, but Denali has no active declared assertion for "
                    "that exact model."
                ),
                risk=(
                    "Runtime model use that is absent from reviewed configuration can change data "
                    "handling, cost, residency, and model-risk assumptions. This is evidence of "
                    "configuration drift, not evidence of malicious use."
                ),
                investigation_guidance=(
                    "Review the ordered session evidence, confirm the intended model and agent "
                    "version, then update the reviewed declaration or remove the unexpected path."
                ),
                severity=FindingSeverity.HIGH,
                confidence=1.0,
                first_seen_at=activities[0].occurred_at,
                last_seen_at=activities[-1].occurred_at,
                activities=tuple(
                    DetectionActivityLink(activity.id, "undeclared_model_invocation")
                    for activity in activities
                ),
                assets=(
                    DetectionAssetLink(agent.id, "executing_agent"),
                    DetectionAssetLink(model.id, "undeclared_model"),
                ),
                attributes={
                    "agent_natural_key": agent.natural_key,
                    "model_natural_key": model.natural_key,
                    "invocation_count": len(activities),
                    "content_policy": "metadata_only",
                },
            )
        )
    return RuntimeDetectionEvaluation(
        rule_uid=AWS_UNDECLARED_MODEL_RULE_UID,
        state=coverage_state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=(
            f"{incomplete} AWS model observations lacked one exact agent/model correlation"
            if incomplete
            else None
        ),
    )


def evaluate_aws_unapproved_tool_invocation(
    snapshot: DetectionSnapshot,
    *,
    coverage_state: CoverageState,
    evaluated_at: datetime | None = None,
) -> RuntimeDetectionEvaluation:
    """Detect observed AWS tool execution that is not explicitly approved."""

    now = evaluated_at or datetime.now(UTC)
    assets = {asset.id: asset for asset in snapshot.assets}
    agents_by_session = _aws_agents_by_session(snapshot, assets)
    candidates: list[RuntimeDetectionCandidate] = []
    incomplete = 0
    for activity in snapshot.activities:
        if not _successful_aws(activity, "tool_invocation"):
            continue
        session = _session(activity)
        agents = agents_by_session.get(session, ()) if session else ()
        tool_entity = _one_entity(activity, "tool")
        tool = assets.get(tool_entity.asset_id) if tool_entity else None
        if len(agents) != 1:
            incomplete += 1
            continue
        agent = agents[0]
        if tool is not None and tool.kind != "ai_tool":
            incomplete += 1
            continue
        if tool is not None and tool.governance_status == "approved":
            continue
        if tool is None and coverage_state is not CoverageState.COMPLETE:
            incomplete += 1
            continue
        tool_uid = (
            tool.natural_key if tool else (tool_entity.external_uid if tool_entity else "unknown")
        )
        tool_name = (
            tool.display_name
            if tool
            else (
                (tool_entity.display_name or tool_entity.external_uid)
                if tool_entity
                else "unknown tool"
            )
        )
        links = [DetectionAssetLink(agent.id, "executing_agent")]
        if tool is not None:
            links.append(DetectionAssetLink(tool.id, "unapproved_tool"))
        candidates.append(
            RuntimeDetectionCandidate(
                correlation_key=_key(
                    AWS_UNAPPROVED_TOOL_RULE_UID,
                    agent.natural_key,
                    tool_uid,
                    activity.id,
                ),
                rule_uid=AWS_UNAPPROVED_TOOL_RULE_UID,
                title=f"{agent.display_name} invoked unapproved tool {tool_name}",
                description=(
                    "Provider-native AgentCore telemetry recorded a successful tool execution, "
                    "but the exact tool is not approved in Denali."
                ),
                risk=(
                    "An unapproved tool path can give an agent access to actions or data outside "
                    "its reviewed operating boundary. An unresolved tool identity means the "
                    "runtime name could not be joined to complete inventory, not that Denali "
                    "invented an asset."
                ),
                investigation_guidance=(
                    "Inspect the linked session, agent version, execution identity, tool target, "
                    "and adjacent calls. Approve the exact tool only after confirming intended use."
                ),
                severity=FindingSeverity.HIGH,
                confidence=1.0 if tool is not None else 0.8,
                first_seen_at=activity.occurred_at,
                last_seen_at=activity.occurred_at,
                activities=(DetectionActivityLink(activity.id, "unapproved_tool_invocation"),),
                assets=tuple(links),
                attributes={
                    "agent_natural_key": agent.natural_key,
                    "tool_natural_key": tool.natural_key if tool else None,
                    "observed_tool_uid": tool_uid,
                    "inventory_linked": tool is not None,
                    "content_policy": "metadata_only",
                },
            )
        )
    return RuntimeDetectionEvaluation(
        rule_uid=AWS_UNAPPROVED_TOOL_RULE_UID,
        state=coverage_state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=(
            f"{incomplete} AWS tool observations lacked complete correlation evidence"
            if incomplete
            else None
        ),
    )


def evaluate_aws_risky_action_sequence(
    snapshot: DetectionSnapshot,
    *,
    coverage_state: CoverageState,
    evaluated_at: datetime | None = None,
) -> RuntimeDetectionEvaluation:
    """Detect a retrieval followed by a mutation-like tool call in one AWS session."""

    now = evaluated_at or datetime.now(UTC)
    assets = {asset.id: asset for asset in snapshot.assets}
    agents_by_session = _aws_agents_by_session(snapshot, assets)
    sessions: dict[str, list[DetectionActivity]] = defaultdict(list)
    for activity in snapshot.activities:
        session = _session(activity)
        if session and activity.provider == "aws_agentcore":
            sessions[session].append(activity)

    candidates: list[RuntimeDetectionCandidate] = []
    incomplete = 0
    for session, activities in sessions.items():
        activities.sort(key=lambda item: (item.occurred_at, item.id))
        agents = agents_by_session.get(session, ())
        if len(agents) != 1:
            incomplete += 1
            continue
        agent = agents[0]
        retrievals: list[DetectionActivity] = []
        for activity in activities:
            if activity.category == "retrieval" and activity.outcome != "failure":
                retrievals.append(activity)
                continue
            if not _successful_aws(activity, "tool_invocation") or not _is_mutating_tool(activity):
                continue
            eligible = [
                item
                for item in retrievals
                if timedelta(0) <= activity.occurred_at - item.occurred_at <= AWS_SEQUENCE_WINDOW
            ]
            if not eligible:
                continue
            retrieval = eligible[-1]
            tool_entity = _one_entity(activity, "tool")
            tool = assets.get(tool_entity.asset_id) if tool_entity else None
            asset_links = [DetectionAssetLink(agent.id, "executing_agent")]
            if tool is not None:
                asset_links.append(DetectionAssetLink(tool.id, "mutation_tool"))
            candidates.append(
                RuntimeDetectionCandidate(
                    correlation_key=_key(
                        AWS_RISKY_SEQUENCE_RULE_UID, session, retrieval.id, activity.id
                    ),
                    rule_uid=AWS_RISKY_SEQUENCE_RULE_UID,
                    title=f"{agent.display_name} retrieved data then invoked a mutating tool",
                    description=(
                        "An ordered AgentCore session shows retrieval followed within five "
                        "minutes by a successful mutation-like tool call."
                    ),
                    risk=(
                        "This sequence can move retrieved or sensitive context into a "
                        "consequential "
                        "action. Metadata establishes ordering only; Denali intentionally does not "
                        "collect prompt, response, document, argument, or result content."
                    ),
                    investigation_guidance=(
                        "Review the exact span order, execution identity, tool target, agent "
                        "release, "
                        "and the provider-side content under your existing access controls."
                    ),
                    severity=FindingSeverity.HIGH,
                    confidence=0.9,
                    first_seen_at=retrieval.occurred_at,
                    last_seen_at=activity.occurred_at,
                    activities=(
                        DetectionActivityLink(retrieval.id, "preceding_retrieval"),
                        DetectionActivityLink(activity.id, "subsequent_mutating_tool"),
                    ),
                    assets=tuple(asset_links),
                    attributes={
                        "session_uid_hash": _key("aws-session", session),
                        "elapsed_ms": int(
                            (activity.occurred_at - retrieval.occurred_at).total_seconds() * 1000
                        ),
                        "tool_operation": _tool_operation(activity),
                        "content_policy": "metadata_only",
                    },
                )
            )
    return RuntimeDetectionEvaluation(
        rule_uid=AWS_RISKY_SEQUENCE_RULE_UID,
        state=coverage_state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=(
            f"{incomplete} AWS sessions lacked one exact agent correlation" if incomplete else None
        ),
    )


def _successful_aws(activity: DetectionActivity, category: str) -> bool:
    return (
        activity.provider == "aws_agentcore"
        and activity.category == category
        and activity.outcome == "success"
    )


def _session(activity: DetectionActivity) -> str | None:
    if activity.session_key:
        return activity.session_key
    runtime_uid = activity.session_uid or activity.trace_uid
    if runtime_uid and activity.connection_id:
        return f"{activity.connection_id}\x1f{runtime_uid}"
    return runtime_uid


def _aws_agents_by_session(
    snapshot: DetectionSnapshot, assets: dict[str, DetectionAsset]
) -> dict[str, tuple[DetectionAsset, ...]]:
    grouped: dict[str, dict[str, DetectionAsset]] = defaultdict(dict)
    for activity in snapshot.activities:
        if activity.provider != "aws_agentcore":
            continue
        session = _session(activity)
        if session is None:
            continue
        for entity in activity.entities:
            asset = assets.get(entity.asset_id) if entity.role == "agent" else None
            if asset is not None and asset.kind == "ai_agent":
                grouped[session][asset.id] = asset
    return {
        session: tuple(sorted(items.values(), key=lambda item: item.id))
        for session, items in grouped.items()
    }


def _tool_operation(activity: DetectionActivity) -> str:
    for key in ("gen_ai.tool.name", "tool.name", "aws.operation.name"):
        value = activity.attributes.get(key)
        if isinstance(value, str) and value:
            return value
    entity = _one_entity(activity, "tool")
    return (entity.display_name or entity.external_uid) if entity else ""


def _is_mutating_tool(activity: DetectionActivity) -> bool:
    operation = _tool_operation(activity).casefold().replace("_", "-")
    tokens = {token for token in re.split(r"[^a-z0-9]+", operation) if token}
    return bool(tokens.intersection(MUTATING_TOOL_TOKENS))


def _one_entity(activity: DetectionActivity, role: str):
    matches = [entity for entity in activity.entities if entity.role == role]
    return matches[0] if len(matches) == 1 else None


def _operation(activity: DetectionActivity) -> str:
    value = activity.attributes.get("activity_operation")
    if isinstance(value, str) and value:
        return value
    payload = activity.evidence.get("payload")
    if isinstance(payload, dict):
        value = payload.get("activityDisplayName")
        if isinstance(value, str):
            return value
    return ""


def _scopes(asset: DetectionAsset) -> set[str]:
    value = asset.attributes.get("delegated_scopes")
    if isinstance(value, str):
        return {scope.strip() for scope in value.split(",") if scope.strip()}
    if isinstance(value, list):
        return {str(scope).strip() for scope in value if str(scope).strip()}
    return set()


def _key(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()
