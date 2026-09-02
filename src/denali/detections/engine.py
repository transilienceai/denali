"""Pure runtime-detection rules over bounded activity and inventory snapshots."""

from __future__ import annotations

import hashlib
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
                    DetectionActivityLink(activity.id, "failed_sign_in")
                    for activity in activities
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
