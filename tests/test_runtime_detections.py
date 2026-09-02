from datetime import UTC, datetime, timedelta

from denali.detections import (
    evaluate_repeated_failed_ai_signins,
    evaluate_unreviewed_ai_consent,
    evaluate_unreviewed_model_invocation,
)
from denali.domain import (
    CoverageState,
    DetectionActivity,
    DetectionActivityEntity,
    DetectionAsset,
    DetectionSnapshot,
    FindingSeverity,
)

NOW = datetime(2026, 8, 27, 20, 0, tzinfo=UTC)
APP = DetectionAsset(
    id="app-1",
    kind="ai_application",
    natural_key="entra:tenant:application:app-1",
    display_name="Claude for Office",
    governance_status="unreviewed",
    lifecycle_state="active",
    attributes={"delegated_scopes": ["User.Read", "Mail.ReadWrite"]},
)


def sign_in(number: int, *, outcome: str = "failure", hours: int = 0) -> DetectionActivity:
    return DetectionActivity(
        id=f"sign-in-{number}",
        category="ai_app_sign_in",
        outcome=outcome,
        title="Claude for Office sign-in failed",
        occurred_at=NOW + timedelta(hours=hours),
        entities=(
            DetectionActivityEntity("actor", "alice@example.com", "Alice"),
            DetectionActivityEntity("application", "app-1", "Claude for Office", "app-1"),
        ),
    )


def test_repeated_failure_requires_three_exact_events_inside_24_hours() -> None:
    snapshot = DetectionSnapshot(
        activities=(sign_in(1), sign_in(2, hours=2), sign_in(3, hours=23)),
        assets=(APP,),
    )

    evaluation = evaluate_repeated_failed_ai_signins(
        snapshot, coverage_state=CoverageState.COMPLETE, evaluated_at=NOW
    )

    assert evaluation.state is CoverageState.COMPLETE
    assert len(evaluation.candidates) == 1
    candidate = evaluation.candidates[0]
    assert candidate.severity is FindingSeverity.MEDIUM
    assert candidate.attributes["failure_count"] == 3
    assert {link.activity_id for link in candidate.activities} == {
        "sign-in-1",
        "sign-in-2",
        "sign-in-3",
    }


def test_repeated_failure_does_not_fire_for_single_failure_or_wide_window() -> None:
    snapshot = DetectionSnapshot(
        activities=(sign_in(1), sign_in(2, hours=25), sign_in(3, hours=50)),
        assets=(APP,),
    )

    evaluation = evaluate_repeated_failed_ai_signins(
        snapshot, coverage_state=CoverageState.COMPLETE, evaluated_at=NOW
    )

    assert evaluation.candidates == ()


def test_consent_groups_correlated_events_and_raises_severity_for_high_impact_scope() -> None:
    activities = tuple(
        DetectionActivity(
            id=f"audit-{number}",
            category="admin_change",
            outcome="success",
            title=f"{operation}: Claude for Office",
            occurred_at=NOW + timedelta(seconds=number),
            trace_uid="correlation-1",
            attributes={"activity_operation": operation},
            entities=(
                DetectionActivityEntity("actor", "admin@example.com", "Admin"),
                DetectionActivityEntity("application", "app-1", "Claude for Office", "app-1"),
            ),
        )
        for number, operation in enumerate(
            ("Consent to application", "Add delegated permission grant"), start=1
        )
    )
    evaluation = evaluate_unreviewed_ai_consent(
        DetectionSnapshot(activities, (APP,)),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert len(evaluation.candidates) == 1
    candidate = evaluation.candidates[0]
    assert candidate.severity is FindingSeverity.HIGH
    assert candidate.attributes["event_count"] == 2
    assert candidate.attributes["high_impact_scopes"] == ["Mail.ReadWrite"]


def test_consent_does_not_fire_for_approved_application() -> None:
    approved = DetectionAsset(
        id=APP.id,
        kind=APP.kind,
        natural_key=APP.natural_key,
        display_name=APP.display_name,
        governance_status="approved",
        lifecycle_state="active",
    )
    activity = DetectionActivity(
        id="audit-1",
        category="admin_change",
        outcome="success",
        title="Consent to application: Claude for Office",
        occurred_at=NOW,
        trace_uid="correlation-1",
        attributes={"activity_operation": "Consent to application"},
        entities=(
            DetectionActivityEntity("actor", "admin@example.com"),
            DetectionActivityEntity("application", "app-1", asset_id="app-1"),
        ),
    )

    evaluation = evaluate_unreviewed_ai_consent(
        DetectionSnapshot((activity,), (approved,)),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert evaluation.candidates == ()


def test_missing_exact_application_link_is_reported_not_inferred() -> None:
    activity = DetectionActivity(
        id="audit-1",
        category="admin_change",
        outcome="success",
        title="Consent to application: unknown",
        occurred_at=NOW,
        attributes={"activity_operation": "Consent to application"},
        entities=(
            DetectionActivityEntity("actor", "admin@example.com"),
            DetectionActivityEntity("application", "unknown"),
        ),
    )

    evaluation = evaluate_unreviewed_ai_consent(
        DetectionSnapshot((activity,), (APP,)),
        coverage_state=CoverageState.PARTIAL,
        evaluated_at=NOW,
    )

    assert evaluation.candidates == ()
    assert evaluation.incomplete_candidates == 1
    assert evaluation.state is CoverageState.PARTIAL


def test_successful_invocation_of_exact_unreviewed_model_creates_detection() -> None:
    model = DetectionAsset(
        id="model-1",
        kind="ai_model",
        natural_key="gcp:vertex:model:gemini-2.5-flash",
        display_name="gemini-2.5-flash",
        governance_status="unreviewed",
        lifecycle_state="active",
    )
    invocation = DetectionActivity(
        id="vertex-1",
        category="model_invocation",
        outcome="success",
        title="Generate content",
        occurred_at=NOW,
        entities=(
            DetectionActivityEntity(
                "actor", "summit@example.com", "Summit service account"
            ),
            DetectionActivityEntity(
                "model", model.natural_key, model.display_name, model.id
            ),
        ),
    )

    evaluation = evaluate_unreviewed_model_invocation(
        DetectionSnapshot((invocation,), (model,)),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert evaluation.state is CoverageState.COMPLETE
    assert len(evaluation.candidates) == 1
    candidate = evaluation.candidates[0]
    assert candidate.title == "Unreviewed model gemini-2.5-flash was invoked"
    assert candidate.assets[0].asset_id == model.id
    assert candidate.activities[0].activity_id == invocation.id


def test_unreviewed_model_rule_requires_exact_model_link() -> None:
    invocation = DetectionActivity(
        id="vertex-1",
        category="model_invocation",
        outcome="success",
        title="Generate content",
        occurred_at=NOW,
        entities=(DetectionActivityEntity("model", "gemini-2.5-flash"),),
    )

    evaluation = evaluate_unreviewed_model_invocation(
        DetectionSnapshot((invocation,), ()),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert evaluation.candidates == ()
    assert evaluation.incomplete_candidates == 1
