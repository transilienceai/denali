from datetime import UTC, datetime, timedelta

from denali.detections import (
    evaluate_aws_risky_action_sequence,
    evaluate_aws_unapproved_tool_invocation,
    evaluate_aws_undeclared_model_invocation,
    evaluate_denials_followed_by_alternate_path,
    evaluate_effective_policy_exceeds_boundary,
    evaluate_new_credentialed_destination,
    evaluate_prover_authority_gap,
    evaluate_repeated_failed_ai_signins,
    evaluate_runtime_policy_mismatch,
    evaluate_telemetry_interruption_or_contradiction,
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
            DetectionActivityEntity("actor", "summit@example.com", "Summit service account"),
            DetectionActivityEntity("model", model.natural_key, model.display_name, model.id),
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


def _aws_assets(*, declared_model: bool = False, approved_tool: bool = False):
    agent = DetectionAsset(
        id="agent-1",
        kind="ai_agent",
        natural_key="arn:aws:bedrock-agentcore:us-east-1:123456789012:runtime/sales",
        display_name="Sales agent",
        governance_status="approved",
        lifecycle_state="active",
    )
    model = DetectionAsset(
        id="model-aws-1",
        kind="ai_model",
        natural_key="aws:bedrock:model:global.anthropic.claude-sonnet-4-6",
        display_name="Claude Sonnet 4.6",
        governance_status="approved",
        lifecycle_state="active",
        attributes={"_denali_declared": declared_model},
    )
    tool = DetectionAsset(
        id="tool-1",
        kind="ai_tool",
        natural_key="arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw#target/slack",
        display_name="send_message",
        governance_status="approved" if approved_tool else "unreviewed",
        lifecycle_state="active",
    )
    return agent, model, tool


def _aws_activity(
    activity_id: str,
    category: str,
    *,
    offset_seconds: int,
    entities: tuple[DetectionActivityEntity, ...],
    outcome: str = "success",
    attributes: dict | None = None,
    connection_id: str = "connection-1",
    session_key: str = "session-key-1",
) -> DetectionActivity:
    return DetectionActivity(
        id=activity_id,
        category=category,
        outcome=outcome,
        title=activity_id,
        occurred_at=NOW + timedelta(seconds=offset_seconds),
        provider="aws_agentcore",
        connection_id=connection_id,
        session_key=session_key,
        session_uid="session-1",
        trace_uid="trace-1",
        attributes=attributes or {},
        entities=entities,
    )


def test_aws_exact_observed_model_without_declaration_is_drift() -> None:
    agent, model, _ = _aws_assets()
    invocation = _aws_activity(
        "model-span",
        "model_invocation",
        offset_seconds=1,
        entities=(DetectionActivityEntity("model", model.natural_key, asset_id=model.id),),
    )
    root = _aws_activity(
        "agent-span",
        "agent_invocation",
        offset_seconds=0,
        entities=(DetectionActivityEntity("agent", agent.natural_key, asset_id=agent.id),),
    )

    evaluation = evaluate_aws_undeclared_model_invocation(
        DetectionSnapshot((root, invocation), (agent, model)),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert len(evaluation.candidates) == 1
    assert {link.asset_id for link in evaluation.candidates[0].assets} == {
        agent.id,
        model.id,
    }


def test_aws_declared_model_is_not_reported_as_drift() -> None:
    agent, model, _ = _aws_assets(declared_model=True)
    root = _aws_activity(
        "agent-span",
        "agent_invocation",
        offset_seconds=0,
        entities=(DetectionActivityEntity("agent", agent.natural_key, asset_id=agent.id),),
    )
    invocation = _aws_activity(
        "model-span",
        "model_invocation",
        offset_seconds=1,
        entities=(DetectionActivityEntity("model", model.natural_key, asset_id=model.id),),
    )

    evaluation = evaluate_aws_undeclared_model_invocation(
        DetectionSnapshot((root, invocation), (agent, model)),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert evaluation.candidates == ()


def test_aws_unapproved_exact_tool_invocation_is_detected() -> None:
    agent, _, tool = _aws_assets()
    root = _aws_activity(
        "agent-span",
        "agent_invocation",
        offset_seconds=0,
        entities=(DetectionActivityEntity("agent", agent.natural_key, asset_id=agent.id),),
    )
    invocation = _aws_activity(
        "tool-span",
        "tool_invocation",
        offset_seconds=2,
        entities=(DetectionActivityEntity("tool", tool.natural_key, asset_id=tool.id),),
        attributes={"gen_ai.tool.name": "send_message"},
    )

    evaluation = evaluate_aws_unapproved_tool_invocation(
        DetectionSnapshot((root, invocation), (agent, tool)),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert len(evaluation.candidates) == 1
    assert evaluation.candidates[0].confidence == 1.0


def test_aws_sessions_are_scoped_by_connection_key_not_raw_session_id() -> None:
    agent, model, _ = _aws_assets()
    other_agent = DetectionAsset(
        id="agent-2",
        kind="ai_agent",
        natural_key="arn:aws:bedrock-agentcore:us-west-2:210987654321:runtime/support",
        display_name="Support agent",
        governance_status="approved",
        lifecycle_state="active",
    )
    first_root = _aws_activity(
        "agent-span-1",
        "agent_invocation",
        offset_seconds=0,
        entities=(DetectionActivityEntity("agent", agent.natural_key, asset_id=agent.id),),
    )
    first_model = _aws_activity(
        "model-span-1",
        "model_invocation",
        offset_seconds=1,
        entities=(DetectionActivityEntity("model", model.natural_key, asset_id=model.id),),
    )
    second_root = _aws_activity(
        "agent-span-2",
        "agent_invocation",
        offset_seconds=0,
        entities=(
            DetectionActivityEntity(
                "agent", other_agent.natural_key, asset_id=other_agent.id
            ),
        ),
        connection_id="connection-2",
        session_key="session-key-2",
    )

    evaluation = evaluate_aws_undeclared_model_invocation(
        DetectionSnapshot((first_root, first_model, second_root), (agent, other_agent, model)),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert len(evaluation.candidates) == 1
    assert {link.asset_id for link in evaluation.candidates[0].assets} == {
        agent.id,
        model.id,
    }


def test_aws_unresolved_tool_requires_complete_inventory_coverage() -> None:
    agent, _, _ = _aws_assets()
    root = _aws_activity(
        "agent-span",
        "agent_invocation",
        offset_seconds=0,
        entities=(DetectionActivityEntity("agent", agent.natural_key, asset_id=agent.id),),
    )
    invocation = _aws_activity(
        "tool-span",
        "tool_invocation",
        offset_seconds=2,
        entities=(DetectionActivityEntity("tool", "mystery", "mystery"),),
    )

    evaluation = evaluate_aws_unapproved_tool_invocation(
        DetectionSnapshot((root, invocation), (agent,)),
        coverage_state=CoverageState.PARTIAL,
        evaluated_at=NOW,
    )

    assert evaluation.candidates == ()
    assert evaluation.incomplete_candidates == 1


def test_aws_retrieval_then_mutating_tool_is_ordered_sequence() -> None:
    agent, _, tool = _aws_assets(approved_tool=True)
    root = _aws_activity(
        "agent-span",
        "agent_invocation",
        offset_seconds=0,
        entities=(DetectionActivityEntity("agent", agent.natural_key, asset_id=agent.id),),
    )
    retrieval = _aws_activity("retrieve-span", "retrieval", offset_seconds=5, entities=())
    invocation = _aws_activity(
        "tool-span",
        "tool_invocation",
        offset_seconds=15,
        entities=(DetectionActivityEntity("tool", tool.natural_key, asset_id=tool.id),),
        attributes={"gen_ai.tool.name": "send_message"},
    )

    evaluation = evaluate_aws_risky_action_sequence(
        DetectionSnapshot((root, invocation, retrieval), (agent, tool)),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert len(evaluation.candidates) == 1
    assert [link.activity_id for link in evaluation.candidates[0].activities] == [
        retrieval.id,
        invocation.id,
    ]
    assert evaluation.candidates[0].attributes["elapsed_ms"] == 10_000


def _openshell_assets(
    *,
    prover_result: str = "within_boundary",
    effective_destinations: list[dict] | None = None,
    declared_destinations: list[dict] | None = None,
    loss_signals: list[str] | None = None,
) -> tuple[DetectionAsset, DetectionAsset, DetectionAsset, DetectionAsset, DetectionAsset]:
    scope = "openshell:gateway-1:sandbox:sandbox-1"
    workload = DetectionAsset(
        id="openshell-workload",
        kind="ai_workload",
        natural_key=scope,
        display_name="Review agent",
        governance_status="approved",
        lifecycle_state="active",
        attributes={
            "provider": "nvidia_openshell",
            "capture_complete": not bool(loss_signals),
            "loss_signals": loss_signals or [],
            "capture_started_at": "2026-10-04T10:00:00Z",
            "capture_ended_at": "2026-10-04T11:00:00Z",
        },
    )
    declared = DetectionAsset(
        id="declared-policy",
        kind="ai_guardrail",
        natural_key=f"{scope}:declared_policy",
        display_name="Review agent declared policy",
        governance_status="approved",
        lifecycle_state="active",
        attributes={
            "provider": "nvidia_openshell",
            "policy_role": "declared_policy",
            "policy_sha256": "declared-digest",
            "network_destinations": declared_destinations or [],
            "network_binaries": ["/usr/bin/curl"],
        },
    )
    effective = DetectionAsset(
        id="effective-policy",
        kind="ai_guardrail",
        natural_key=f"{scope}:effective_policy",
        display_name="Review agent effective policy",
        governance_status="approved",
        lifecycle_state="active",
        attributes={
            "provider": "nvidia_openshell",
            "policy_role": "effective_policy",
            "policy_sha256": "effective-digest",
            "network_destinations": effective_destinations or [],
            "network_binaries": ["/usr/bin/curl"],
        },
    )
    boundary = DetectionAsset(
        id="boundary-policy",
        kind="ai_guardrail",
        natural_key=f"{scope}:boundary_policy",
        display_name="Review agent approved boundary",
        governance_status="approved",
        lifecycle_state="active",
        attributes={
            "provider": "nvidia_openshell",
            "policy_role": "boundary_policy",
            "policy_sha256": "boundary-digest",
        },
    )
    check = DetectionAsset(
        id="boundary-check",
        kind="ai_guardrail",
        natural_key=f"{scope}:boundary-check:effective:boundary",
        display_name="Review agent boundary check",
        governance_status="approved",
        lifecycle_state="active",
        attributes={
            "provider": "nvidia_openshell",
            "check": "boundary",
            "result": prover_result,
            "reason_code": "solver_timeout" if prover_result == "inconclusive" else None,
            "coverage_domains": [
                "filesystem",
                "network_l4",
                "network_rest",
                "process",
                "landlock",
            ],
            "required_domains": [
                "filesystem",
                "network_l4",
                "network_rest",
                "process",
                "landlock",
            ],
            "candidate_policy_sha256": "effective-digest",
            "boundary_policy_sha256": "boundary-digest",
            "counterexample": {"domain": "network", "host": "example.net", "port": 443},
            "prover_version": "0.1.2",
        },
    )
    return workload, declared, effective, boundary, check


def _openshell_access(
    activity_id: str,
    *,
    seconds: int,
    outcome: str,
    action: str,
    destination: str,
    process: str,
    status: str | None = None,
    disposition: str | None = None,
) -> DetectionActivity:
    return DetectionActivity(
        id=activity_id,
        category="data_access",
        outcome=outcome,
        title=activity_id,
        occurred_at=NOW + timedelta(seconds=seconds),
        provider="nvidia_openshell",
        connection_id="openshell:gateway-1",
        session_uid="sandbox-1",
        attributes={
            "action": action,
            "status": status or ("Success" if outcome == "success" else "Failure"),
            "disposition": disposition or ("Allowed" if outcome == "success" else "Blocked"),
            "destination_domain": destination,
            "destination_port": 443,
            "process_name": process,
            "http_method": "GET",
        },
        entities=(
            DetectionActivityEntity(
                "workload",
                "sandbox-1",
                "Review agent",
                "openshell-workload",
            ),
        ),
    )


def test_effective_policy_exceeds_boundary_requires_exact_proof_artifacts() -> None:
    assets = _openshell_assets(prover_result="exceeds_boundary")
    evaluation = evaluate_effective_policy_exceeds_boundary(
        DetectionSnapshot((), assets),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert len(evaluation.candidates) == 1
    candidate = evaluation.candidates[0]
    assert candidate.severity is FindingSeverity.CRITICAL
    assert {link.role for link in candidate.assets} == {
        "effective_policy",
        "approved_boundary",
        "boundary_check",
    }
    assert candidate.attributes["counterexample"]["domain"] == "network"


def test_prover_unsupported_or_missing_required_domain_is_detected() -> None:
    assets = list(_openshell_assets(prover_result="inconclusive"))
    check = assets[-1]
    assets[-1] = DetectionAsset(
        id=check.id,
        kind=check.kind,
        natural_key=check.natural_key,
        display_name=check.display_name,
        governance_status=check.governance_status,
        lifecycle_state=check.lifecycle_state,
        attributes={
            **dict(check.attributes),
            "coverage_domains": ["filesystem", "network_l4"],
        },
    )
    evaluation = evaluate_prover_authority_gap(
        DetectionSnapshot((), tuple(assets)),
        coverage_state=CoverageState.PARTIAL,
        evaluated_at=NOW,
    )

    assert len(evaluation.candidates) == 1
    assert evaluation.candidates[0].attributes["missing_domains"] == [
        "landlock",
        "network_rest",
        "process",
    ]
    assert evaluation.candidates[0].attributes["reason_code"] == "solver_timeout"


def test_effective_policy_credential_destination_absent_from_declaration_is_detected() -> None:
    github = {
        "host": "api.github.com",
        "port": 443,
        "protocol": "rest",
        "credentialed": True,
    }
    slack = {
        "host": "slack.com",
        "port": 443,
        "protocol": "rest",
        "credentialed": True,
    }
    assets = _openshell_assets(
        declared_destinations=[github], effective_destinations=[github, slack]
    )
    evaluation = evaluate_new_credentialed_destination(
        DetectionSnapshot((), assets),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert len(evaluation.candidates) == 1
    assert evaluation.candidates[0].attributes["destination_host"] == "slack.com"
    assert evaluation.candidates[0].attributes["source"] == (
        "effective_minus_declared_policy"
    )


def test_three_denials_then_changed_successful_path_is_detected() -> None:
    assets = _openshell_assets()
    activities = (
        _openshell_access(
            "deny-1",
            seconds=0,
            outcome="failure",
            action="Denied",
            destination="blocked.example",
            process="/usr/bin/curl",
        ),
        _openshell_access(
            "deny-2",
            seconds=10,
            outcome="failure",
            action="Denied",
            destination="blocked.example",
            process="/usr/bin/curl",
        ),
        _openshell_access(
            "deny-3",
            seconds=20,
            outcome="failure",
            action="Denied",
            destination="blocked.example",
            process="/usr/bin/curl",
        ),
        _openshell_access(
            "success-1",
            seconds=30,
            outcome="success",
            action="Allowed",
            destination="alternate.example",
            process="/usr/bin/python",
        ),
    )
    evaluation = evaluate_denials_followed_by_alternate_path(
        DetectionSnapshot(activities, assets),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert len(evaluation.candidates) == 1
    assert [link.role for link in evaluation.candidates[0].activities] == [
        "preceding_denial",
        "preceding_denial",
        "preceding_denial",
        "alternate_path_success",
    ]


def test_telemetry_loss_and_field_contradiction_are_distinct_candidates() -> None:
    assets = _openshell_assets(loss_signals=["watch_stream_skip"])
    contradiction = _openshell_access(
        "contradiction",
        seconds=0,
        outcome="failure",
        action="Allowed",
        status="Failure",
        disposition="Allowed",
        destination="api.github.com",
        process="/usr/bin/curl",
    )
    evaluation = evaluate_telemetry_interruption_or_contradiction(
        DetectionSnapshot((contradiction,), assets),
        coverage_state=CoverageState.PARTIAL,
        evaluated_at=NOW,
    )

    assert len(evaluation.candidates) == 2
    assert {candidate.attributes["kind"] for candidate in evaluation.candidates} == {
        "interruption",
        "contradiction",
    }


def test_successful_runtime_access_absent_from_effective_policy_is_detected() -> None:
    allowed = {
        "host": "api.github.com",
        "port": 443,
        "protocol": "rest",
        "enforcement": "enforce",
        "access": "read-only",
        "methods": [],
        "credentialed": False,
    }
    assets = _openshell_assets(effective_destinations=[allowed])
    unexpected = _openshell_access(
        "unexpected",
        seconds=0,
        outcome="success",
        action="Allowed",
        destination="uploads.example.net",
        process="/usr/bin/curl",
    )
    expected = _openshell_access(
        "expected",
        seconds=1,
        outcome="success",
        action="Allowed",
        destination="api.github.com",
        process="/usr/bin/curl",
    )
    evaluation = evaluate_runtime_policy_mismatch(
        DetectionSnapshot((unexpected, expected), assets),
        coverage_state=CoverageState.COMPLETE,
        evaluated_at=NOW,
    )

    assert len(evaluation.candidates) == 1
    assert evaluation.candidates[0].activities[0].activity_id == "unexpected"
    assert evaluation.candidates[0].attributes["destination_host"] == "uploads.example.net"
