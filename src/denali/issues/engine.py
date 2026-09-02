"""Pure issue-correlation rules over a bounded repository snapshot."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import UTC, datetime

from denali.domain import (
    CorrelationAsset,
    CorrelationFinding,
    CorrelationRelationship,
    CorrelationRuntimeDetection,
    CorrelationSnapshot,
    CoverageState,
    DetectionActivity,
    FindingSeverity,
    IssueActivityLink,
    IssueCandidate,
    IssueDetectionLink,
    IssueEvaluation,
    IssueFindingLink,
    IssuePathEdge,
    IssuePathNode,
)

RULE_UID = "DENALI-ISSUE-AGENT-WRITE-001"
CONSENT_THEN_USE_RULE_UID = "DENALI-ISSUE-SHADOW-AI-CONSENT-USE-001"
CONSENT_DETECTION_RULE_UID = "DENALI-RUNTIME-ENTRA-CONSENT-001"
IDENTITY_SIGNAL = "identity.overprivileged"
TOOL_SIGNAL = "tool.write_without_confirmation"
DEPLOYED_BEDROCK_RULE_UID = "DENALI-ISSUE-DEPLOYED-BEDROCK-GOVERNANCE-001"
REPOSITORY_GUARDRAIL_SIGNAL = (
    "repository.bedrock_managed_guardrail_not_requested"
)
BEDROCK_SCOPE_SIGNAL = "identity.bedrock_model_family_wildcard"
ELIGIBLE_ASSERTIONS = {"observed", "externally_verified"}
MIN_CONFIDENCE = 0.8


def aggregate_issue_evaluation_state(
    evaluations: tuple[IssueEvaluation, ...],
) -> CoverageState:
    """Summarize issue-rule coverage without hiding an incomplete correlation.

    A rule with no candidates and unknown upstream coverage is non-participating: its
    own rule evaluation remains unknown, but it must not downgrade a different rule
    that completed. Once an unknown rule has a candidate or incomplete/ambiguous
    evidence, however, that uncertainty is material and must remain visible in the
    aggregate result.
    """

    if not evaluations:
        return CoverageState.UNKNOWN

    states = {evaluation.state for evaluation in evaluations}
    if states == {CoverageState.FAILED}:
        return CoverageState.FAILED
    if CoverageState.FAILED in states or CoverageState.PARTIAL in states:
        return CoverageState.PARTIAL

    material_unknown = any(
        evaluation.state is CoverageState.UNKNOWN
        and (
            evaluation.candidates
            or evaluation.incomplete_candidates
            or evaluation.ambiguous_resource_references
        )
        for evaluation in evaluations
    )
    if material_unknown:
        return CoverageState.UNKNOWN

    if CoverageState.COMPLETE in states:
        return CoverageState.COMPLETE
    if states == {CoverageState.NOT_SUPPORTED}:
        return CoverageState.NOT_SUPPORTED
    return CoverageState.UNKNOWN


def evaluate_unreviewed_ai_consent_then_use(
    detections: tuple[CorrelationRuntimeDetection, ...],
    activities: tuple[DetectionActivity, ...],
    assets: tuple[CorrelationAsset, ...],
    *,
    coverage_state: CoverageState = CoverageState.COMPLETE,
    evaluated_at: datetime | None = None,
) -> IssueEvaluation:
    """Correlate high-impact consent with later exact use of the same AI app.

    The rule proves sequence and identity only. It does not claim the application
    exercised the granted permission or that either observed actor had malicious intent.
    """

    now = evaluated_at or datetime.now(UTC)
    assets_by_id = {asset.id: asset for asset in assets}
    successful_sign_ins: dict[str, list[DetectionActivity]] = defaultdict(list)
    for activity in activities:
        if activity.category != "ai_app_sign_in" or activity.outcome != "success":
            continue
        for entity in activity.entities:
            if entity.role == "application" and entity.asset_id:
                successful_sign_ins[entity.asset_id].append(activity)

    candidates: list[IssueCandidate] = []
    incomplete = 0
    for detection in detections:
        if detection.rule_uid != CONSENT_DETECTION_RULE_UID or detection.state != "open":
            continue
        high_impact_scopes = tuple(
            sorted(str(scope) for scope in detection.attributes.get("high_impact_scopes", ()))
        )
        if not high_impact_scopes:
            continue
        exact_assets = [
            assets_by_id[asset_id]
            for asset_id in detection.asset_ids
            if asset_id in assets_by_id
            and assets_by_id[asset_id].kind == "ai_application"
            and assets_by_id[asset_id].assertion_type in ELIGIBLE_ASSERTIONS
            and assets_by_id[asset_id].confidence >= MIN_CONFIDENCE
            and assets_by_id[asset_id].attributes.get("governance_status") == "unreviewed"
        ]
        if len(exact_assets) != 1:
            incomplete += 1
            continue
        application = exact_assets[0]
        later_use = tuple(
            activity
            for activity in successful_sign_ins.get(application.id, ())
            if activity.occurred_at > detection.last_seen_at
        )
        if not later_use:
            continue
        first_use = min(item.occurred_at for item in later_use)
        actors = sorted(
            {
                entity.display_name or entity.external_uid
                for activity in later_use
                for entity in activity.entities
                if entity.role == "actor"
            }
        )
        correlation_key = hashlib.sha256(
            f"{CONSENT_THEN_USE_RULE_UID}|{application.natural_key}".encode()
        ).hexdigest()
        scope_text = ", ".join(high_impact_scopes)
        candidates.append(
            IssueCandidate(
                correlation_key=correlation_key,
                rule_uid=CONSENT_THEN_USE_RULE_UID,
                title=(
                    f"Unreviewed AI app {application.display_name} received high-impact "
                    "consent and was subsequently used"
                ),
                description=(
                    f"Microsoft Entra recorded high-impact delegated consent ({scope_text}) "
                    f"for unreviewed AI application {application.display_name}, followed by "
                    f"{len(later_use)} successful sign-in event(s) to that exact application."
                ),
                risk=(
                    "The application can be used while holding access to sensitive tenant data "
                    "before the organization has approved its use. This chronology does not "
                    "prove that the granted scope was exercised or that either actor intended "
                    "misuse."
                ),
                remediation=(
                    "Confirm the business owner and need for the application, review the exact "
                    "delegated scopes and sign-in actors, then approve the app or revoke consent "
                    "through the organization's established remediation workflow."
                ),
                severity=FindingSeverity.HIGH,
                confidence=min(detection.confidence, application.confidence),
                findings=(),
                path_nodes=(IssuePathNode(application.id, 0, "unreviewed_ai_application"),),
                path_edges=(),
                detections=(IssueDetectionLink(detection.id, "high_impact_consent"),),
                activities=tuple(
                    IssueActivityLink(item.id, "subsequent_successful_sign_in")
                    for item in sorted(later_use, key=lambda item: (item.occurred_at, item.id))
                ),
                attributes={
                    "correlation": "deterministic_temporal",
                    "path_status": "exact_application_identity",
                    "high_impact_scopes": list(high_impact_scopes),
                    "consent_last_seen_at": detection.last_seen_at.isoformat(),
                    "first_subsequent_use_at": first_use.isoformat(),
                    "subsequent_use_count": len(later_use),
                    "actors": actors,
                },
            )
        )

    state = coverage_state
    detail = None
    if incomplete:
        state = CoverageState.UNKNOWN
        detail = f"{incomplete} consent detections lacked one exact active application asset"
    return IssueEvaluation(
        rule_uid=CONSENT_THEN_USE_RULE_UID,
        state=state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates, key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=detail,
    )


def evaluate_agent_sensitive_write(
    snapshot: CorrelationSnapshot,
    *,
    evaluated_at: datetime | None = None,
) -> IssueEvaluation:
    """Correlate independently supported agent-to-sensitive-data write paths.

    Finding resource references select already observed assets by kind and exact natural
    key. They never add nodes or edges. Only observed or externally verified capability
    relationships with sufficient confidence may participate in the path.
    """

    now = evaluated_at or datetime.now(UTC)
    trusted_assets = tuple(
        asset
        for asset in snapshot.assets
        if asset.assertion_type in ELIGIBLE_ASSERTIONS and asset.confidence >= MIN_CONFIDENCE
    )
    assets_by_id = {asset.id: asset for asset in trusted_assets}
    assets_by_kind_key: dict[tuple[str, str], list[CorrelationAsset]] = defaultdict(list)
    for asset in trusted_assets:
        assets_by_kind_key[(asset.kind, asset.natural_key)].append(asset)

    eligible = tuple(
        relationship
        for relationship in snapshot.relationships
        if relationship.category == "capability"
        and relationship.assertion_type in ELIGIBLE_ASSERTIONS
        and relationship.confidence >= MIN_CONFIDENCE
    )
    by_kind_target: dict[tuple[str, str], list[CorrelationRelationship]] = defaultdict(list)
    by_kind_source: dict[tuple[str, str], list[CorrelationRelationship]] = defaultdict(list)
    for relationship in eligible:
        by_kind_target[(relationship.kind, relationship.target_id)].append(relationship)
        by_kind_source[(relationship.kind, relationship.source_id)].append(relationship)

    identity_findings = _active_signal_findings(snapshot.findings, IDENTITY_SIGNAL)
    tool_findings = _active_signal_findings(snapshot.findings, TOOL_SIGNAL)
    candidates: dict[str, IssueCandidate] = {}
    incomplete = 0
    ambiguous = 0

    for identity_finding in identity_findings:
        identity_assets, identity_ambiguous = _referenced_assets(
            identity_finding, "identity", assets_by_kind_key
        )
        ambiguous += identity_ambiguous
        for tool_finding in tool_findings:
            tool_assets, tool_ambiguous = _referenced_assets(
                tool_finding, "ai_tool", assets_by_kind_key
            )
            ambiguous += tool_ambiguous
            pair_confirmed = False
            for identity in identity_assets:
                for tool in tool_assets:
                    for runs_as in by_kind_target[("runs_as", identity.id)]:
                        agent = assets_by_id.get(runs_as.source_id)
                        if agent is None or agent.kind != "ai_agent":
                            continue
                        invokes = next(
                            (
                                edge
                                for edge in by_kind_source[("can_invoke", agent.id)]
                                if edge.target_id == tool.id
                            ),
                            None,
                        )
                        if invokes is None:
                            continue
                        for writes in by_kind_source[("can_write", tool.id)]:
                            datastore = assets_by_id.get(writes.target_id)
                            if datastore is None or datastore.kind != "ai_datastore":
                                continue
                            if str(datastore.attributes.get("classification", "")).lower() not in {
                                "sensitive",
                                "confidential",
                                "restricted",
                            }:
                                continue
                            candidate = _candidate(
                                identity_finding,
                                tool_finding,
                                agent,
                                identity,
                                tool,
                                datastore,
                                runs_as,
                                invokes,
                                writes,
                            )
                            candidates[candidate.correlation_key] = candidate
                            pair_confirmed = True
            if not pair_confirmed:
                incomplete += 1

    state = CoverageState.COMPLETE
    detail = None
    if incomplete or ambiguous:
        state = CoverageState.UNKNOWN
        detail = (
            f"{incomplete} candidate pairs lacked a confirmed capability path; "
            f"{ambiguous} resource references were ambiguous"
        )
    return IssueEvaluation(
        rule_uid=RULE_UID,
        state=state,
        evaluated_at=now,
        candidates=tuple(sorted(candidates.values(), key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        ambiguous_resource_references=ambiguous,
        detail=detail,
    )


def evaluate_deployed_bedrock_governance_gap(
    snapshot: CorrelationSnapshot,
    *,
    evaluated_at: datetime | None = None,
) -> IssueEvaluation:
    """Correlate an included unguarded Bedrock call with broad runtime authority.

    The exact deployment join and reachable-source set prove only artifact inclusion.
    Observed workload configuration and role identity independently prove the runtime
    context; the rule does not claim that the source call was executed.
    """

    now = evaluated_at or datetime.now(UTC)
    assets_by_id = {asset.id: asset for asset in snapshot.assets}
    deployments = tuple(
        relationship
        for relationship in snapshot.relationships
        if relationship.kind == "deployed_by"
        and relationship.assertion_type == "inferred"
        and relationship.confidence == 1.0
        and relationship.attributes.get("correlation") == "deterministic"
    )
    observed_relationships = tuple(
        relationship
        for relationship in snapshot.relationships
        if relationship.assertion_type in ELIGIBLE_ASSERTIONS
        and relationship.confidence >= MIN_CONFIDENCE
    )
    runs_as_by_workload: dict[str, list[CorrelationRelationship]] = defaultdict(list)
    models_by_workload: dict[str, list[CorrelationRelationship]] = defaultdict(list)
    for relationship in observed_relationships:
        if relationship.kind == "runs_as":
            runs_as_by_workload[relationship.source_id].append(relationship)
        elif relationship.kind == "uses":
            models_by_workload[relationship.source_id].append(relationship)

    repository_findings = _active_signal_findings(
        snapshot.findings, REPOSITORY_GUARDRAIL_SIGNAL
    )
    identity_findings = _active_signal_findings(snapshot.findings, BEDROCK_SCOPE_SIGNAL)
    candidates: dict[str, IssueCandidate] = {}
    incomplete = 0

    for deployment in deployments:
        workload = assets_by_id.get(deployment.source_id)
        repository = assets_by_id.get(deployment.target_id)
        if (
            workload is None
            or workload.kind != "ai_workload"
            or repository is None
            or repository.kind != "code_repository"
        ):
            continue
        reachable_paths = {
            str(path) for path in deployment.attributes.get("reachable_source_paths", ())
        }
        included_findings = tuple(
            finding
            for finding in repository_findings
            if finding.attributes.get("repository") == repository.natural_key
            and finding.attributes.get("source_path") in reachable_paths
        )
        if not included_findings:
            continue
        for runs_as in runs_as_by_workload.get(workload.id, ()):
            identity = assets_by_id.get(runs_as.target_id)
            if identity is None or identity.kind != "identity":
                continue
            matching_identity_findings = tuple(
                finding
                for finding in identity_findings
                if identity.natural_key in finding.resource_uids
            )
            if not matching_identity_findings:
                continue
            model_edges = tuple(
                edge
                for edge in models_by_workload.get(workload.id, ())
                if (model := assets_by_id.get(edge.target_id)) is not None
                and model.kind == "ai_model"
                and model.natural_key.startswith("aws:bedrock:model:")
            )
            if not model_edges:
                incomplete += 1
                continue
            for model_edge in model_edges:
                model = assets_by_id[model_edge.target_id]
                for code_finding in included_findings:
                    for identity_finding in matching_identity_findings:
                        identity_material = "|".join(
                            (
                                DEPLOYED_BEDROCK_RULE_UID,
                                workload.natural_key,
                                identity.natural_key,
                                model.natural_key,
                                code_finding.source_uid,
                            )
                        )
                        correlation_key = hashlib.sha256(
                            identity_material.encode()
                        ).hexdigest()
                        candidate = IssueCandidate(
                            correlation_key=correlation_key,
                            rule_uid=DEPLOYED_BEDROCK_RULE_UID,
                            title=(
                                f"{workload.display_name} can invoke {model.display_name} "
                                "without a managed guardrail under broader family permission"
                            ),
                            description=(
                                f"The exact deployment correlation includes the Bedrock call "
                                f"at {code_finding.attributes.get('source_path')}:"
                                f"{code_finding.attributes.get('source_line')}. That call does "
                                f"not request an AWS managed guardrail. The observed workload "
                                f"runs as {identity.display_name}, whose effective policy permits "
                                "a broader Anthropic model family than the configured model "
                                f"{model.display_name}."
                            ),
                            risk=(
                                "A compromised workload or unintended configuration change can "
                                "select another permitted model while the included call site "
                                "does not itself request provider-managed filtering. Artifact "
                                "inclusion does not prove that the call executed."
                            ),
                            remediation=(
                                "Restrict the execution role to the exact approved Bedrock model "
                                "resources and pass an approved guardrail identifier and version "
                                "at the included call site. Recollect source and AWS evidence, "
                                "then rerun issue evaluation."
                            ),
                            severity=FindingSeverity.HIGH,
                            confidence=min(
                                deployment.confidence,
                                runs_as.confidence,
                                model_edge.confidence,
                                workload.confidence,
                                repository.confidence,
                                identity.confidence,
                                model.confidence,
                            ),
                            findings=(
                                IssueFindingLink(
                                    code_finding.id, "included_unguarded_bedrock_call"
                                ),
                                IssueFindingLink(
                                    identity_finding.id, "broad_model_family_permission"
                                ),
                            ),
                            path_nodes=(
                                IssuePathNode(repository.id, 0, "source_repository"),
                                IssuePathNode(workload.id, 1, "deployed_workload"),
                                IssuePathNode(identity.id, 2, "execution_identity"),
                                IssuePathNode(model.id, 3, "configured_model"),
                            ),
                            path_edges=(
                                IssuePathEdge(deployment.id, 0),
                                IssuePathEdge(runs_as.id, 1),
                                IssuePathEdge(model_edge.id, 2),
                            ),
                            attributes={
                                "correlation": "deterministic_code_to_cloud",
                                "path_status": "confirmed",
                                "source_path": code_finding.attributes.get("source_path"),
                                "source_line": code_finding.attributes.get("source_line"),
                                "artifact_identity_status": deployment.attributes.get(
                                    "artifact_identity_status"
                                ),
                                "source_execution_status": "not_observed",
                            },
                        )
                        candidates[correlation_key] = candidate

    return IssueEvaluation(
        rule_uid=DEPLOYED_BEDROCK_RULE_UID,
        state=CoverageState.UNKNOWN if incomplete else CoverageState.COMPLETE,
        evaluated_at=now,
        candidates=tuple(sorted(candidates.values(), key=lambda item: item.correlation_key)),
        incomplete_candidates=incomplete,
        detail=(
            f"{incomplete} deployed workload candidates lacked an observed Bedrock model"
            if incomplete
            else None
        ),
    )


def _active_signal_findings(
    findings: tuple[CorrelationFinding, ...], signal: str
) -> tuple[CorrelationFinding, ...]:
    return tuple(
        finding
        for finding in findings
        if finding.state == "open"
        and finding.evaluation_result == "fail"
        and finding.attributes.get("denali_signal") == signal
    )


def _referenced_assets(
    finding: CorrelationFinding,
    kind: str,
    index: dict[tuple[str, str], list[CorrelationAsset]],
) -> tuple[tuple[CorrelationAsset, ...], int]:
    output: dict[str, CorrelationAsset] = {}
    ambiguous = 0
    for uid in finding.resource_uids:
        matches = index.get((kind, uid), [])
        if len(matches) == 1:
            output[matches[0].id] = matches[0]
        elif len(matches) > 1:
            ambiguous += 1
    return tuple(output.values()), ambiguous


def _candidate(
    identity_finding: CorrelationFinding,
    tool_finding: CorrelationFinding,
    agent: CorrelationAsset,
    identity: CorrelationAsset,
    tool: CorrelationAsset,
    datastore: CorrelationAsset,
    runs_as: CorrelationRelationship,
    invokes: CorrelationRelationship,
    writes: CorrelationRelationship,
) -> IssueCandidate:
    identity_material = "|".join(
        (RULE_UID, agent.natural_key, identity.natural_key, tool.natural_key, datastore.natural_key)
    )
    correlation_key = hashlib.sha256(identity_material.encode()).hexdigest()
    confidence = min(
        agent.confidence,
        identity.confidence,
        tool.confidence,
        datastore.confidence,
        runs_as.confidence,
        invokes.confidence,
        writes.confidence,
    )
    return IssueCandidate(
        correlation_key=correlation_key,
        rule_uid=RULE_UID,
        title=(
            f"{agent.display_name} can change sensitive data through an unconfirmed tool"
        ),
        description=(
            f"{agent.display_name} runs as {identity.display_name}, can invoke "
            f"{tool.display_name}, and that tool can write to {datastore.display_name}. "
            "The execution identity is overprivileged and the write action lacks an "
            "independently enforced confirmation step."
        ),
        risk=(
            "A manipulated prompt or tool request can cross a confirmed authorization "
            "path and make persistent changes to sensitive data."
        ),
        remediation=(
            "Constrain the execution identity, require confirmation at the write-tool "
            "boundary, and restrict the tool to the exact datastore operations required."
        ),
        severity=FindingSeverity.CRITICAL,
        confidence=confidence,
        findings=(
            IssueFindingLink(identity_finding.id, "overprivileged_execution_identity"),
            IssueFindingLink(tool_finding.id, "unconfirmed_write_tool"),
        ),
        path_nodes=(
            IssuePathNode(agent.id, 0, "agent"),
            IssuePathNode(identity.id, 1, "execution_identity"),
            IssuePathNode(tool.id, 2, "write_tool"),
            IssuePathNode(datastore.id, 3, "sensitive_data"),
        ),
        path_edges=(
            IssuePathEdge(runs_as.id, 0),
            IssuePathEdge(invokes.id, 1),
            IssuePathEdge(writes.id, 2),
        ),
        attributes={
            "correlation": "deterministic",
            "path_status": "confirmed",
            "finding_count": 2,
            "capability_edge_count": 3,
        },
    )
