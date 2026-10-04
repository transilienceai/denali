"""Pure runtime-detection rules over bounded activity and inventory snapshots."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatchcase

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
OPENSHELL_BOUNDARY_RULE_UID = "DENALI-RUNTIME-OPENSHELL-BOUNDARY-001"
OPENSHELL_PROVER_AUTHORITY_RULE_UID = "DENALI-RUNTIME-OPENSHELL-PROVER-001"
OPENSHELL_CREDENTIAL_DESTINATION_RULE_UID = "DENALI-RUNTIME-OPENSHELL-CREDENTIAL-001"
RUNTIME_DENIAL_PATH_RULE_UID = "DENALI-RUNTIME-DENIAL-PATH-001"
RUNTIME_TELEMETRY_INTEGRITY_RULE_UID = "DENALI-RUNTIME-TELEMETRY-INTEGRITY-001"
RUNTIME_POLICY_MISMATCH_RULE_UID = "DENALI-RUNTIME-POLICY-MISMATCH-001"
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
DENIAL_PATH_WINDOW = timedelta(minutes=5)
DENIAL_PATH_THRESHOLD = 3
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


def evaluate_effective_policy_exceeds_boundary(
    snapshot: DetectionSnapshot,
    *,
    coverage_state: CoverageState,
    evaluated_at: datetime | None = None,
) -> RuntimeDetectionEvaluation:
    """Surface conclusive OpenShell boundary counterexamples without re-proving them."""

    now = evaluated_at or datetime.now(UTC)
    candidates: list[RuntimeDetectionCandidate] = []
    incomplete = 0
    for check in _openshell_checks(snapshot):
        result = check.attributes.get("result")
        if result != "exceeds_boundary":
            continue
        candidate_digest = check.attributes.get("candidate_policy_sha256")
        boundary_digest = check.attributes.get("boundary_policy_sha256")
        effective = _policy_by_digest(snapshot, "effective_policy", candidate_digest)
        boundary = _policy_by_digest(snapshot, "boundary_policy", boundary_digest)
        if effective is None or boundary is None:
            incomplete += 1
            continue
        counterexample = check.attributes.get("counterexample")
        counterexample = counterexample if isinstance(counterexample, dict) else {}
        domain = str(counterexample.get("domain") or "modeled policy domain")
        candidates.append(
            RuntimeDetectionCandidate(
                correlation_key=_key(OPENSHELL_BOUNDARY_RULE_UID, check.natural_key),
                rule_uid=OPENSHELL_BOUNDARY_RULE_UID,
                title=f"{effective.display_name} exceeds its approved boundary",
                description=(
                    "The OpenShell standalone prover returned exceeds_boundary for the exact "
                    "effective and boundary policy artifacts. The counterexample domain is "
                    f"{domain}."
                ),
                risk=(
                    "The sandbox can exercise authority outside the operator-approved maximum in "
                    "at least one modeled domain. This conclusion is limited to the prover's "
                    "reported coverage and counterexample."
                ),
                investigation_guidance=(
                    "Review the linked effective policy, boundary policy, artifact digests, and "
                    "counterexample. Narrow the effective policy or explicitly revise the approved "
                    "boundary, then run and ingest a fresh proof."
                ),
                severity=FindingSeverity.CRITICAL,
                confidence=1.0,
                first_seen_at=now,
                last_seen_at=now,
                activities=(),
                assets=(
                    DetectionAssetLink(effective.id, "effective_policy"),
                    DetectionAssetLink(boundary.id, "approved_boundary"),
                    DetectionAssetLink(check.id, "boundary_check"),
                ),
                attributes={
                    "result": result,
                    "counterexample": counterexample,
                    "coverage_domains": check.attributes.get("coverage_domains", []),
                    "candidate_policy_sha256": candidate_digest,
                    "boundary_policy_sha256": boundary_digest,
                },
            )
        )
    return RuntimeDetectionEvaluation(
        rule_uid=OPENSHELL_BOUNDARY_RULE_UID,
        state=coverage_state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=(
            f"{incomplete} boundary results lacked their exact policy artifacts"
            if incomplete
            else None
        ),
    )


def evaluate_prover_authority_gap(
    snapshot: DetectionSnapshot,
    *,
    coverage_state: CoverageState,
    evaluated_at: datetime | None = None,
) -> RuntimeDetectionEvaluation:
    """Detect unsupported, inconclusive, errored, or under-covered required proof domains."""

    now = evaluated_at or datetime.now(UTC)
    candidates: list[RuntimeDetectionCandidate] = []
    incomplete = 0
    for check in _openshell_checks(snapshot):
        result = check.attributes.get("result")
        observed = _string_set(check.attributes.get("coverage_domains"))
        required = _string_set(check.attributes.get("required_domains"))
        if not required:
            incomplete += 1
            continue
        missing = sorted(required - observed)
        if result not in {"unsupported", "inconclusive", "error"} and not missing:
            continue
        reason_code = check.attributes.get("reason_code")
        candidates.append(
            RuntimeDetectionCandidate(
                correlation_key=_key(
                    OPENSHELL_PROVER_AUTHORITY_RULE_UID,
                    check.natural_key,
                    str(result),
                    ",".join(missing),
                ),
                rule_uid=OPENSHELL_PROVER_AUTHORITY_RULE_UID,
                title="OpenShell proof is not authoritative for every required domain",
                description=(
                    f"The exact boundary check returned {result}. "
                    + (
                        "Required domains without modeled coverage: " + ", ".join(missing) + "."
                        if missing
                        else "All declared domains were listed, but the proof did not conclude."
                    )
                ),
                risk=(
                    "Unsupported or inconclusive proof authority cannot establish that the "
                    "effective policy stays inside the approved boundary. It is not evidence that "
                    "the policy exceeds the boundary."
                ),
                investigation_guidance=(
                    "Inspect the prover version and stable reason code, simplify unsupported "
                    "policy shapes or increase the bounded solve budget, and require a "
                    "within_boundary result covering every required domain before approval."
                ),
                severity=FindingSeverity.HIGH,
                confidence=1.0,
                first_seen_at=now,
                last_seen_at=now,
                activities=(),
                assets=(DetectionAssetLink(check.id, "incomplete_boundary_check"),),
                attributes={
                    "result": result,
                    "reason_code": reason_code,
                    "required_domains": sorted(required),
                    "observed_domains": sorted(observed),
                    "missing_domains": missing,
                    "prover_version": check.attributes.get("prover_version"),
                },
            )
        )
    return RuntimeDetectionEvaluation(
        rule_uid=OPENSHELL_PROVER_AUTHORITY_RULE_UID,
        state=coverage_state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=(
            f"{incomplete} prover observations did not declare required domains"
            if incomplete
            else None
        ),
    )


def evaluate_new_credentialed_destination(
    snapshot: DetectionSnapshot,
    *,
    coverage_state: CoverageState,
    evaluated_at: datetime | None = None,
) -> RuntimeDetectionEvaluation:
    """Detect credential-bearing destinations added by effective policy composition."""

    now = evaluated_at or datetime.now(UTC)
    candidates: list[RuntimeDetectionCandidate] = []
    incomplete = 0
    declared_by_scope = {
        _openshell_policy_scope(asset): asset
        for asset in snapshot.assets
        if asset.attributes.get("policy_role") == "declared_policy"
    }
    for effective in snapshot.assets:
        if effective.attributes.get("policy_role") != "effective_policy":
            continue
        scope = _openshell_policy_scope(effective)
        declared = declared_by_scope.get(scope)
        if scope is None or declared is None:
            incomplete += 1
            continue
        effective_destinations = _credentialed_destinations(effective)
        declared_destinations = _credentialed_destinations(declared)
        for destination in sorted(effective_destinations - declared_destinations):
            host, port, protocol = destination
            candidates.append(
                RuntimeDetectionCandidate(
                    correlation_key=_key(
                        OPENSHELL_CREDENTIAL_DESTINATION_RULE_UID,
                        effective.natural_key,
                        host,
                        port,
                        protocol,
                    ),
                    rule_uid=OPENSHELL_CREDENTIAL_DESTINATION_RULE_UID,
                    title=f"Effective policy added credentialed destination {host}:{port}",
                    description=(
                        "The fully composed OpenShell policy contains a credential-bearing "
                        f"{protocol} destination that is absent from the directly declared policy."
                    ),
                    risk=(
                        "Provider composition can expand where sandbox credentials are usable. "
                        "This is an authority change, not evidence that a credential was used."
                    ),
                    investigation_guidance=(
                        "Identify the provider profile or composed rule that introduced the "
                        "destination, verify endpoint binding and methods, and compare it with the "
                        "approved boundary and source declaration."
                    ),
                    severity=FindingSeverity.HIGH,
                    confidence=1.0,
                    first_seen_at=now,
                    last_seen_at=now,
                    activities=(),
                    assets=(
                        DetectionAssetLink(declared.id, "declared_policy"),
                        DetectionAssetLink(effective.id, "effective_policy"),
                    ),
                    attributes={
                        "destination_host": host,
                        "destination_port": int(port) if port.isdigit() else port,
                        "protocol": protocol,
                        "source": "effective_minus_declared_policy",
                    },
                )
            )
    return RuntimeDetectionEvaluation(
        rule_uid=OPENSHELL_CREDENTIAL_DESTINATION_RULE_UID,
        state=coverage_state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=(
            f"{incomplete} effective policies lacked an exact declared-policy peer"
            if incomplete
            else None
        ),
    )


def evaluate_denials_followed_by_alternate_path(
    snapshot: DetectionSnapshot,
    *,
    coverage_state: CoverageState,
    evaluated_at: datetime | None = None,
) -> RuntimeDetectionEvaluation:
    """Detect repeated OpenShell denials followed by a changed successful execution path."""

    now = evaluated_at or datetime.now(UTC)
    assets = {asset.id: asset for asset in snapshot.assets}
    by_workload: dict[str, list[DetectionActivity]] = defaultdict(list)
    incomplete = 0
    for activity in snapshot.activities:
        if activity.provider != "nvidia_openshell" or activity.category != "data_access":
            continue
        workload = _one_entity(activity, "workload")
        if workload is None or workload.asset_id is None:
            incomplete += 1
            continue
        by_workload[workload.asset_id].append(activity)

    candidates: list[RuntimeDetectionCandidate] = []
    for workload_id, activities in by_workload.items():
        activities.sort(key=lambda item: (item.occurred_at, item.id))
        denied: list[DetectionActivity] = []
        for activity in activities:
            if _is_denied(activity):
                denied.append(activity)
                continue
            if activity.outcome != "success":
                continue
            recent = [
                item
                for item in denied
                if timedelta(0) <= activity.occurred_at - item.occurred_at <= DENIAL_PATH_WINDOW
            ]
            if len(recent) < DENIAL_PATH_THRESHOLD:
                continue
            latest_path = _execution_path(activity)
            matching_denials = [item for item in recent if _execution_path(item) != latest_path]
            if len(matching_denials) < DENIAL_PATH_THRESHOLD:
                continue
            evidence = tuple(matching_denials[-DENIAL_PATH_THRESHOLD:] + [activity])
            workload = assets.get(workload_id)
            if workload is None:
                incomplete += 1
                continue
            candidates.append(
                RuntimeDetectionCandidate(
                    correlation_key=_key(
                        RUNTIME_DENIAL_PATH_RULE_UID,
                        workload.natural_key,
                        *(item.id for item in evidence),
                    ),
                    rule_uid=RUNTIME_DENIAL_PATH_RULE_UID,
                    title=f"{workload.display_name} changed execution path after repeated denials",
                    description=(
                        f"OpenShell recorded {DENIAL_PATH_THRESHOLD} denied access attempts "
                        "followed within five minutes by a successful request using a different "
                        "process or destination path."
                    ),
                    risk=(
                        "A rapid path change after repeated enforcement failures can indicate "
                        "policy probing or fallback behavior that bypasses the intended route. "
                        "Metadata alone does not establish intent."
                    ),
                    investigation_guidance=(
                        "Review the ordered events, exact process and destination metadata, policy "
                        "revision, and surrounding sandbox activity. Confirm whether the alternate "
                        "path was an approved fallback."
                    ),
                    severity=FindingSeverity.HIGH,
                    confidence=0.9,
                    first_seen_at=evidence[0].occurred_at,
                    last_seen_at=evidence[-1].occurred_at,
                    activities=tuple(
                        DetectionActivityLink(
                            item.id,
                            "alternate_path_success" if item is activity else "preceding_denial",
                        )
                        for item in evidence
                    ),
                    assets=(DetectionAssetLink(workload.id, "openshell_workload"),),
                    attributes={
                        "denial_count": DENIAL_PATH_THRESHOLD,
                        "window_seconds": int(DENIAL_PATH_WINDOW.total_seconds()),
                        "denied_paths": [list(_execution_path(item)) for item in evidence[:-1]],
                        "successful_path": list(latest_path),
                    },
                )
            )
    return RuntimeDetectionEvaluation(
        rule_uid=RUNTIME_DENIAL_PATH_RULE_UID,
        state=coverage_state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=(
            f"{incomplete} OpenShell access observations lacked exact workload identity"
            if incomplete
            else None
        ),
    )


def evaluate_telemetry_interruption_or_contradiction(
    snapshot: DetectionSnapshot,
    *,
    coverage_state: CoverageState,
    evaluated_at: datetime | None = None,
) -> RuntimeDetectionEvaluation:
    """Detect explicit capture loss attestations or contradictory enforcement fields."""

    now = evaluated_at or datetime.now(UTC)
    candidates: list[RuntimeDetectionCandidate] = []
    for workload in snapshot.assets:
        if (
            workload.kind != "ai_workload"
            or workload.attributes.get("provider") != "nvidia_openshell"
        ):
            continue
        complete = workload.attributes.get("capture_complete")
        loss_signals = sorted(_string_set(workload.attributes.get("loss_signals")))
        if complete is not False and not loss_signals:
            continue
        candidates.append(
            RuntimeDetectionCandidate(
                correlation_key=_key(
                    RUNTIME_TELEMETRY_INTEGRITY_RULE_UID,
                    workload.natural_key,
                    "interruption",
                    ",".join(loss_signals),
                ),
                rule_uid=RUNTIME_TELEMETRY_INTEGRITY_RULE_UID,
                title=f"OpenShell telemetry continuity is interrupted for {workload.display_name}",
                description=(
                    "The imported capture explicitly does not attest a complete interval or "
                    f"reported loss signals: {', '.join(loss_signals) or 'unspecified gap'}."
                ),
                risk=(
                    "A telemetry gap prevents reliable negative conclusions and can hide policy "
                    "violations or execution-path changes. It is not itself evidence of malicious "
                    "activity."
                ),
                investigation_guidance=(
                    "Recover retained sandbox-local JSONL segments when possible, inspect exporter "
                    "drop/error metrics, and ingest a new bounded interval with no unresolved loss "
                    "signal."
                ),
                severity=FindingSeverity.HIGH,
                confidence=1.0,
                first_seen_at=now,
                last_seen_at=now,
                activities=(),
                assets=(DetectionAssetLink(workload.id, "telemetry_source"),),
                attributes={
                    "kind": "interruption",
                    "capture_complete": complete,
                    "loss_signals": loss_signals,
                    "capture_started_at": workload.attributes.get("capture_started_at"),
                    "capture_ended_at": workload.attributes.get("capture_ended_at"),
                },
            )
        )
    for activity in snapshot.activities:
        if activity.provider != "nvidia_openshell":
            continue
        action = str(activity.attributes.get("action") or "").casefold()
        status = str(activity.attributes.get("status") or "").casefold()
        disposition = str(activity.attributes.get("disposition") or "").casefold()
        contradiction = (
            (action == "allowed" and status in {"failure", "error"})
            or (action == "denied" and status == "success")
            or (disposition == "blocked" and activity.outcome == "success")
            or (disposition == "allowed" and activity.outcome == "failure")
        )
        if not contradiction:
            continue
        workload_entity = _one_entity(activity, "workload")
        links = ()
        if workload_entity and workload_entity.asset_id:
            links = (DetectionAssetLink(workload_entity.asset_id, "telemetry_source"),)
        candidates.append(
            RuntimeDetectionCandidate(
                correlation_key=_key(
                    RUNTIME_TELEMETRY_INTEGRITY_RULE_UID, activity.id, "contradiction"
                ),
                rule_uid=RUNTIME_TELEMETRY_INTEGRITY_RULE_UID,
                title="OpenShell enforcement telemetry is internally contradictory",
                description=(
                    "One OCSF record contains action, disposition, status, or normalized outcome "
                    "fields that cannot all describe the same enforcement result."
                ),
                risk=(
                    "Contradictory security telemetry cannot safely support allow/deny conclusions "
                    "and may indicate producer, transformation, or schema errors."
                ),
                investigation_guidance=(
                    "Compare the source record digest with the original JSONL event and producer "
                    "version, then repair or upgrade the producer before relying on the interval."
                ),
                severity=FindingSeverity.HIGH,
                confidence=1.0,
                first_seen_at=activity.occurred_at,
                last_seen_at=activity.occurred_at,
                activities=(DetectionActivityLink(activity.id, "contradictory_event"),),
                assets=links,
                attributes={
                    "kind": "contradiction",
                    "action": action,
                    "disposition": disposition,
                    "status": status,
                    "outcome": activity.outcome,
                },
            )
        )
    return RuntimeDetectionEvaluation(
        rule_uid=RUNTIME_TELEMETRY_INTEGRITY_RULE_UID,
        state=coverage_state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
    )


def evaluate_runtime_policy_mismatch(
    snapshot: DetectionSnapshot,
    *,
    coverage_state: CoverageState,
    evaluated_at: datetime | None = None,
) -> RuntimeDetectionEvaluation:
    """Detect exact successful OpenShell access absent from its effective policy summary."""

    now = evaluated_at or datetime.now(UTC)
    assets = {asset.id: asset for asset in snapshot.assets}
    policies = {
        _openshell_policy_scope(asset): asset
        for asset in snapshot.assets
        if asset.attributes.get("policy_role") == "effective_policy"
    }
    candidates: list[RuntimeDetectionCandidate] = []
    incomplete = 0
    for activity in snapshot.activities:
        if (
            activity.provider != "nvidia_openshell"
            or activity.category != "data_access"
            or activity.outcome != "success"
        ):
            continue
        workload_entity = _one_entity(activity, "workload")
        workload = assets.get(workload_entity.asset_id) if workload_entity else None
        scope = _openshell_workload_scope(workload) if workload else None
        policy = policies.get(scope)
        host = activity.attributes.get("destination_domain") or activity.attributes.get(
            "destination_ip"
        )
        port = activity.attributes.get("destination_port")
        process = activity.attributes.get("process_name")
        method = activity.attributes.get("http_method")
        if (
            workload is None
            or policy is None
            or not isinstance(host, str)
            or not isinstance(port, int)
        ):
            incomplete += 1
            continue
        match = _effective_policy_allows(policy, host, port, process, method)
        if match is None:
            incomplete += 1
            continue
        if match:
            continue
        candidates.append(
            RuntimeDetectionCandidate(
                correlation_key=_key(
                    RUNTIME_POLICY_MISMATCH_RULE_UID,
                    workload.natural_key,
                    policy.natural_key,
                    activity.id,
                ),
                rule_uid=RUNTIME_POLICY_MISMATCH_RULE_UID,
                title=f"Runtime access by {workload.display_name} is absent from effective policy",
                description=(
                    f"OpenShell reported successful access to {host}:{port}, but no normalized "
                    "effective-policy endpoint and binary/method constraint admits the exact "
                    "metadata."
                ),
                risk=(
                    "Observed access outside the declared enforcement surface can indicate policy "
                    "drift, a bypass, stale evidence, or a producer defect. Denali does not infer "
                    "which cause applies."
                ),
                investigation_guidance=(
                    "Verify the policy revision active at the event time, inspect "
                    "provider-composed rules and runtime enforcement logs, and compare "
                    "source/IAM/tool declarations before changing policy or access."
                ),
                severity=FindingSeverity.CRITICAL,
                confidence=1.0,
                first_seen_at=activity.occurred_at,
                last_seen_at=activity.occurred_at,
                activities=(DetectionActivityLink(activity.id, "inconsistent_runtime_access"),),
                assets=(
                    DetectionAssetLink(workload.id, "executing_workload"),
                    DetectionAssetLink(policy.id, "effective_policy"),
                ),
                attributes={
                    "destination_host": host,
                    "destination_port": port,
                    "process_name": process,
                    "http_method": method,
                    "policy_sha256": policy.attributes.get("policy_sha256"),
                    "comparison": "exact_runtime_metadata_to_effective_policy",
                },
            )
        )
    return RuntimeDetectionEvaluation(
        rule_uid=RUNTIME_POLICY_MISMATCH_RULE_UID,
        state=coverage_state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=(
            f"{incomplete} successful accesses lacked exact workload, policy, or "
            "destination evidence"
            if incomplete
            else None
        ),
    )


def _openshell_checks(snapshot: DetectionSnapshot) -> tuple[DetectionAsset, ...]:
    return tuple(
        asset
        for asset in snapshot.assets
        if asset.kind == "ai_guardrail"
        and asset.attributes.get("provider") == "nvidia_openshell"
        and asset.attributes.get("check") == "boundary"
    )


def _policy_by_digest(
    snapshot: DetectionSnapshot, role: str, digest: object
) -> DetectionAsset | None:
    if not isinstance(digest, str) or not digest:
        return None
    matches = [
        asset
        for asset in snapshot.assets
        if asset.attributes.get("policy_role") == role
        and asset.attributes.get("policy_sha256") == digest
    ]
    return matches[0] if len(matches) == 1 else None


def _openshell_policy_scope(asset: DetectionAsset) -> str | None:
    role = asset.attributes.get("policy_role")
    if not isinstance(role, str):
        return None
    suffix = f":{role}"
    return asset.natural_key[: -len(suffix)] if asset.natural_key.endswith(suffix) else None


def _openshell_workload_scope(asset: DetectionAsset) -> str | None:
    if not asset.natural_key.startswith("openshell:") or ":sandbox:" not in asset.natural_key:
        return None
    return asset.natural_key


def _credentialed_destinations(asset: DetectionAsset) -> set[tuple[str, str, str]]:
    output: set[tuple[str, str, str]] = set()
    value = asset.attributes.get("network_destinations")
    if not isinstance(value, list):
        return output
    for destination in value:
        if not isinstance(destination, dict) or destination.get("credentialed") is not True:
            continue
        host = destination.get("host")
        protocol = destination.get("protocol")
        if not isinstance(host, str) or not host or not isinstance(protocol, str):
            continue
        ports: list[object] = []
        if destination.get("port") is not None:
            ports.append(destination["port"])
        value_ports = destination.get("ports")
        if isinstance(value_ports, list):
            ports.extend(value_ports)
        if not ports:
            ports.append("any")
        output.update((host.casefold(), str(port), protocol.casefold()) for port in ports)
    return output


def _is_denied(activity: DetectionActivity) -> bool:
    action = str(activity.attributes.get("action") or "").casefold()
    disposition = str(activity.attributes.get("disposition") or "").casefold()
    return (
        activity.outcome == "failure"
        and (action == "denied" or disposition in {"blocked", "denied"})
    )


def _execution_path(activity: DetectionActivity) -> tuple[str, str, str]:
    destination = str(
        activity.attributes.get("destination_domain")
        or activity.attributes.get("destination_ip")
        or "unknown"
    ).casefold()
    port = str(activity.attributes.get("destination_port") or "unknown")
    process = str(activity.attributes.get("process_name") or "unknown").casefold()
    return process, destination, port


def _effective_policy_allows(
    policy: DetectionAsset,
    host: str,
    port: int,
    process: object,
    method: object,
) -> bool | None:
    destinations = policy.attributes.get("network_destinations")
    binaries = policy.attributes.get("network_binaries")
    if not isinstance(destinations, list) or not isinstance(binaries, list):
        return None
    normalized_process = process if isinstance(process, str) and process else None
    if binaries:
        if normalized_process is None:
            return None
        if not any(
            isinstance(pattern, str) and fnmatchcase(normalized_process, pattern)
            for pattern in binaries
        ):
            return False
    normalized_method = method.upper() if isinstance(method, str) and method else None
    for destination in destinations:
        if not isinstance(destination, dict):
            continue
        pattern = destination.get("host")
        if not isinstance(pattern, str) or not _host_matches(host, pattern):
            continue
        declared_ports: set[int] = set()
        if isinstance(destination.get("port"), int):
            declared_ports.add(destination["port"])
        if isinstance(destination.get("ports"), list):
            declared_ports.update(
                item for item in destination["ports"] if isinstance(item, int)
            )
        if declared_ports and port not in declared_ports:
            continue
        enforcement = destination.get("enforcement")
        methods = destination.get("methods")
        access = destination.get("access")
        protocol = destination.get("protocol")
        if protocol == "rest" and enforcement == "enforce" and normalized_method:
            if isinstance(methods, list) and methods:
                if normalized_method not in {str(item).upper() for item in methods}:
                    continue
            elif access == "read-only" and normalized_method not in {"GET", "HEAD", "OPTIONS"}:
                continue
            elif access == "read-write" and normalized_method not in {
                "GET",
                "HEAD",
                "OPTIONS",
                "POST",
                "PUT",
                "PATCH",
            }:
                continue
        return True
    return False


def _host_matches(host: str, pattern: str) -> bool:
    host = host.casefold().rstrip(".")
    pattern = pattern.casefold().rstrip(".")
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix) and host != suffix[1:]
    return host == pattern


def _string_set(value: object) -> set[str]:
    if not isinstance(value, list | tuple | set):
        return set()
    return {item for item in value if isinstance(item, str) and item}


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
