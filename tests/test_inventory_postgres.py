"""Postgres contract tests.

Set ``DENALI_TEST_DSN`` to run them. The local Compose DSN uses port 55450; a skip
is expected in the dependency-free unit target and is not accepted in the DB gate.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import psycopg
import pytest

from denali.connections import (
    AWS_SCOPE_BEDROCK_AGENTS,
    AZURE_SCOPES,
    GCP_SCOPES,
    GITHUB_SCOPES,
    aws_coverage_plan,
    azure_coverage_plan,
    gcp_coverage_plan,
    github_coverage_plan,
)
from denali.connectors.code_to_cloud import CodeToCloudConnector, DeploymentTarget
from denali.connectors.demo import demo_batch, demo_findings_batch
from denali.connectors.repository_posture import RepositoryPostureConnector
from denali.detections import (
    ENTRA_CONSENT_RULE_UID,
    ENTRA_FAILURE_RULE_UID,
    UNREVIEWED_MODEL_RULE_UID,
)
from denali.domain import (
    ActivityBatch,
    ActivityCategory,
    ActivityCorrelation,
    ActivityEntity,
    ActivityEntityRole,
    ActivityOutcome,
    ActivityRecord,
    AffectedResource,
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    ComponentIdentity,
    ComponentScope,
    Coverage,
    CoverageState,
    EvaluationResult,
    Evidence,
    ExploitState,
    FindingAssertion,
    FindingBatch,
    FindingSeverity,
    FindingState,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
    SoftwareComponentAssertion,
    VulnerabilityAssertion,
    VulnerabilityBatch,
    VulnerabilityFixState,
    VulnerabilityMatchMethod,
    VulnerabilityScanSubject,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

DSN = os.environ.get("DENALI_TEST_DSN")
pytestmark = pytest.mark.skipif(not DSN, reason="DENALI_TEST_DSN is not set")


def assertion(key: str, observed_at: datetime) -> AssetAssertion:
    return AssetAssertion(
        asset=AssetRef(AssetKind.AI_AGENT, key),
        coverage_plane="agents",
        display_name=key,
        assertion_type=AssertionType.EXTERNALLY_VERIFIED,
        confidence=1.0,
        evidence=Evidence("fixture", f"fixture://{key}", observed_at),
    )


def inventory_batch(
    *, run_id: str, state: CoverageState, assets: tuple[AssetAssertion, ...], at: datetime
) -> InventoryBatch:
    return InventoryBatch(
        connector_id="fixture",
        connection_id="fixture-connection",
        run_id=run_id,
        scope_key="fixture-scope",
        collected_at=at,
        coverage=(Coverage("agents", state, "fixture-scope"),),
        assets=assets,
    )


def finding_assertion(
    observed_at: datetime,
    *,
    state: FindingState = FindingState.OPEN,
    result: EvaluationResult = EvaluationResult.FAIL,
) -> FindingAssertion:
    return FindingAssertion(
        source_uid="prowler-finding-1",
        rule_uid="bedrock_guardrail_prompt_attack",
        title="Guardrail prompt attack filter is not enabled",
        description="The attached guardrail does not enable the expected filter.",
        risk="Prompt manipulation may change model behavior.",
        remediation="Enable the prompt attack filter.",
        remediation_references=("https://docs.aws.amazon.com/bedrock/",),
        severity=FindingSeverity.HIGH,
        state=state,
        evaluation_result=result,
        class_uid=2004,
        class_name="Detection Finding",
        observed_at=observed_at,
        evidence=Evidence("ocsf_finding", "file:///report#item=0", observed_at),
        affected_resources=(
            AffectedResource(
                uid="arn:aws:bedrock:us-east-1:123456789012:guardrail/gr-1",
                name="customer-safety",
                resource_type="AwsBedrockGuardrail",
                provider="aws",
                account_uid="123456789012",
                region="us-east-1",
            ),
        ),
        compliance={"OWASP-LLM": ("LLM01",)},
    )


def findings_batch(
    *,
    run_id: str,
    at: datetime,
    state: CoverageState,
    findings: tuple[FindingAssertion, ...],
    authoritative: bool = False,
) -> FindingBatch:
    return FindingBatch(
        connector_id="denali.ocsf_findings",
        connection_id="prowler-aws-test",
        run_id=run_id,
        scope_key="provider=aws,account=123456789012",
        collected_at=at,
        coverage=(
            Coverage(
                "ocsf_findings",
                state,
                "provider=aws,account=123456789012",
            ),
        ),
        findings=findings,
        authoritative=authoritative,
    )


def component_assertion(observed_at: datetime) -> SoftwareComponentAssertion:
    return SoftwareComponentAssertion(
        identity=ComponentIdentity(
            target=AssetRef(AssetKind.AI_WORKLOAD, "fixture-workload"),
            name="ray",
            version="2.3.1",
            ecosystem="python",
            package_type="python",
            purl="pkg:pypi/ray@2.3.1",
            location="/usr/local/lib/python3.11/site-packages/ray",
        ),
        coverage_plane="software_components",
        scope=ComponentScope.INSTALLED,
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=Evidence("syft", "file:///syft.json#artifact=ray", observed_at),
    )


def vulnerability_batch(
    *,
    connector_id: str,
    run_id: str,
    observed_at: datetime,
    vulnerabilities: tuple[VulnerabilityAssertion, ...],
    state: CoverageState = CoverageState.COMPLETE,
    authoritative: bool = False,
) -> VulnerabilityBatch:
    return VulnerabilityBatch(
        connector_id=connector_id,
        connection_id=f"{connector_id}-local",
        run_id=run_id,
        scope_key="fixture-workload",
        collected_at=observed_at,
        coverage=(Coverage("vulnerabilities", state, "fixture-workload"),),
        vulnerabilities=vulnerabilities,
        authoritative=authoritative,
    )


def vulnerability_assertion(
    observed_at: datetime, *, source_uid: str, source: str
) -> VulnerabilityAssertion:
    component = component_assertion(observed_at)
    return VulnerabilityAssertion(
        source_uid=source_uid,
        vulnerability_id="CVE-2023-6020",
        aliases=("GHSA-fixture",),
        component=component.identity.asset_ref,
        target=component.identity.target,
        title="Ray local file inclusion",
        description="A vulnerable Ray version is installed.",
        severity=FindingSeverity.CRITICAL,
        state=FindingState.OPEN,
        observed_at=observed_at,
        evidence=Evidence(source, f"file:///{source}.json#match=0", observed_at),
        match_method=VulnerabilityMatchMethod.EXACT_DIRECT,
        match_confidence=1.0,
        cvss_score=7.5,
        fix_state=VulnerabilityFixState.FIXED,
        fixed_versions=("2.8.1",),
        exploit_state=ExploitState.PUBLIC_EXPLOIT,
    )


def software_inventory_batch(observed_at: datetime, *, run_id: str) -> InventoryBatch:
    component = component_assertion(observed_at)
    target = AssetAssertion(
        asset=component.identity.target,
        coverage_plane="software_components",
        display_name="Fixture AI workload",
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=Evidence("syft", "fixture://workload", observed_at),
    )
    return InventoryBatch(
        connector_id="denali.syft",
        connection_id="syft-local",
        run_id=run_id,
        scope_key="fixture-workload",
        collected_at=observed_at,
        coverage=(Coverage("software_components", CoverageState.COMPLETE, "fixture-workload"),),
        assets=(target, component.asset_assertion()),
        relationships=(component.containment_assertion(),),
    )


@pytest.fixture
def repository():
    assert DSN
    migrate(DSN)
    tenant = str(uuid.uuid4())
    return tenant, PostgresInventoryRepository(DSN)


def test_clerk_organization_mapping_is_stable_and_isolated(repository) -> None:
    _, repo = repository

    first = repo.resolve_tenant("org_DenaliPilotA")
    assert repo.resolve_tenant("org_DenaliPilotA") == first
    assert repo.resolve_tenant("org_DenaliPilotB") != first


def test_clerk_tenants_cannot_cross_read_or_mutate_evidence_and_jobs(repository) -> None:
    _, repo = repository
    alpha = repo.resolve_tenant("org_IsolationAlpha")
    beta = repo.resolve_tenant("org_IsolationBeta")
    now = datetime.now(UTC)
    repo.ingest(alpha, demo_batch(now))
    repo.ingest_findings(alpha, demo_findings_batch(now))

    alpha_asset = repo.list_assets(alpha)[0]
    alpha_finding = repo.list_findings(alpha)[0]
    assert repo.list_assets(beta) == []
    assert repo.get_asset(beta, str(alpha_asset["id"])) is None
    assert repo.list_findings(beta) == []
    assert repo.get_finding(beta, str(alpha_finding["id"])) is None
    assert (
        repo.set_governance(
            beta,
            str(alpha_asset["id"]),
            status="approved",
        )
        is None
    )

    connection_id = str(uuid.uuid4())
    repo.create_connection(
        alpha,
        connection_id=connection_id,
        provider="aws",
        display_name="Tenant isolation connection",
        credential_type="aws_assume_role",
        credential_reference={
            "role_arn": "arn:aws:iam::123456789012:role/DenaliSecurityAuditRole",
            "external_id": "denali-tenant-isolation-fixture",
        },
        declared_scopes=[],
        coverage_plan=[],
        configuration={"account_id": "123456789012", "regions": []},
    )
    job, created = repo.create_connection_validation_job(
        alpha,
        connection_id,
        wait_for_credentials=False,
        wait_for_healthy=False,
    )
    assert created is True
    assert repo.list_connections(beta) == []
    assert repo.get_connection(beta, connection_id) is None
    assert repo.connection_validation_job_state(beta, connection_id) == "idle"
    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        repo.create_connection_validation_job(
            beta,
            connection_id,
            wait_for_credentials=False,
            wait_for_healthy=False,
        )
    repo.fail_connection_validation_job(str(job["id"]), "fixture cleanup")


def test_connection_validation_jobs_are_deduplicated_and_expire(repository) -> None:
    tenant, repo = repository
    connection_id = str(uuid.uuid4())
    repo.create_connection(
        tenant,
        connection_id=connection_id,
        provider="aws",
        display_name="Durable validation fixture",
        credential_type="aws_assume_role",
        credential_reference={
            "role_arn": "arn:aws:iam::123456789012:role/DenaliSecurityAuditRole",
            "external_id": "denali-durable-validation-fixture",
        },
        declared_scopes=[],
        coverage_plan=[],
        configuration={"account_id": "123456789012", "regions": []},
    )

    job, created = repo.create_connection_validation_job(
        tenant,
        connection_id,
        wait_for_credentials=False,
        wait_for_healthy=False,
    )
    duplicate, duplicate_created = repo.create_connection_validation_job(
        tenant,
        connection_id,
        wait_for_credentials=False,
        wait_for_healthy=False,
    )
    assert created is True
    assert duplicate_created is False
    assert duplicate["id"] == job["id"]
    assert repo.connection_validation_job_state(tenant, connection_id) == "running"

    claimed = repo.claim_connection_validation_job(str(job["id"]), lease_seconds=60)
    assert claimed is not None
    assert claimed["attempt_count"] == 1
    assert repo.claim_connection_validation_job(str(job["id"]), lease_seconds=60) is None
    repo.complete_connection_validation_job(str(job["id"]))
    assert repo.connection_validation_job_state(tenant, connection_id) == "idle"

    stale, stale_created = repo.create_connection_validation_job(
        tenant,
        connection_id,
        wait_for_credentials=False,
        wait_for_healthy=False,
    )
    assert stale_created is True
    assert DSN
    with psycopg.connect(DSN) as connection:
        connection.execute(
            """
            UPDATE connection_validation_job
            SET created_at = now() - interval '31 minutes'
            WHERE id = %s::uuid
            """,
            (str(stale["id"]),),
        )
    assert repo.connection_validation_job_state(tenant, connection_id) == "idle"
    with psycopg.connect(DSN) as connection:
        state, error_summary = connection.execute(
            "SELECT state, error_summary FROM connection_validation_job WHERE id = %s::uuid",
            (str(stale["id"]),),
        ).fetchone()
    assert state == "failed"
    assert error_summary == "Validation dispatch timed out."


def test_connection_lifecycle_retains_collected_evidence(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    connection_id = str(uuid.uuid4())
    role_arn = "arn:aws:iam::123456789012:role/DenaliSecurityAuditRole"
    plan = aws_coverage_plan([AWS_SCOPE_BEDROCK_AGENTS], ["us-east-1"])

    created = repo.create_connection(
        tenant,
        connection_id=connection_id,
        provider="aws",
        display_name="Fixture AWS",
        credential_type="aws_assume_role",
        credential_reference={"role_arn": role_arn, "external_id": "denali-private-fixture"},
        declared_scopes=[AWS_SCOPE_BEDROCK_AGENTS],
        coverage_plan=plan,
        configuration={
            "account_id": "123456789012",
            "partition": "aws",
            "regions": ["us-east-1"],
            "role_name": "DenaliSecurityAuditRole",
            "stack_scopes": [],
        },
    )

    assert created["health_state"] == "unknown"
    assert created["credential_reference"] == {
        "type": "aws_assume_role",
        "role_arn": role_arn,
    }
    assert "external_id" not in str(created)
    target = repo.get_connection_validation_target(tenant, connection_id)
    assert target is not None
    assert target["credential_reference"]["external_id"] == "denali-private-fixture"

    launched = repo.record_connection_launch(
        tenant,
        connection_id,
        {
            "method": "cloudformation_quick_create",
            "template_version": "denali-aws-readonly-role-v1",
            "template_sha256": "a" * 64,
            "principal_arn": "arn:aws:iam::999999999999:role/DenaliRuntime",
            "published_at": now.isoformat(),
            "url_expires_at": now.isoformat(),
        },
    )
    assert launched is not None
    assert launched["configuration"]["onboarding"]["template_sha256"] == "a" * 64
    assert "external_id" not in str(launched)

    validated = repo.record_connection_validation(
        tenant,
        connection_id,
        {
            "started_at": now,
            "completed_at": now,
            "health_state": "partial",
            "credential_state": "passed",
            "account_id_observed": "123456789012",
            "results": [
                {
                    "scope": AWS_SCOPE_BEDROCK_AGENTS,
                    "plane": "bedrock_agents",
                    "label": "Bedrock Agents Classic inventory",
                    "region": "us-east-1",
                    "state": "failed",
                    "detail": "Validation call failed (AccessDeniedException).",
                }
            ],
            "summary": "Credentials validated; 1 declared collection plane(s) failed.",
        },
    )
    assert validated is not None
    assert validated["health_state"] == "partial"
    assert validated["last_validation"]["results"][0]["state"] == "failed"

    observed = assertion("connection-evidence-agent", now)
    repo.ingest(
        tenant,
        InventoryBatch(
            connector_id="fixture",
            connection_id=connection_id,
            run_id="connection-evidence-run",
            scope_key="fixture-scope",
            collected_at=now,
            coverage=(Coverage("agents", CoverageState.COMPLETE, "fixture-scope"),),
            assets=(observed,),
        ),
    )

    assert repo.delete_connection(tenant, connection_id) == "active"
    disabled = repo.disable_connection(tenant, connection_id)
    assert disabled is not None
    assert disabled["health_state"] == "disabled"
    assert repo.delete_connection(tenant, connection_id) == "deleted"
    assert repo.get_connection(tenant, connection_id) is None
    assert repo.summary(tenant)["total"] == 1


def test_azure_setup_completion_consumes_token_and_binds_selected_subscriptions(
    repository,
) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    connection_id = str(uuid.uuid4())
    client_id = str(uuid.uuid4())
    service_principal_id = str(uuid.uuid4())
    setup_token_sha256 = "b" * 64
    subscriptions = [
        {"id": str(uuid.uuid4()), "name": "Production"},
        {"id": str(uuid.uuid4()), "name": "AI Lab"},
    ]
    created = repo.create_connection(
        tenant,
        connection_id=connection_id,
        provider="azure",
        display_name="Fixture Azure",
        credential_type="azure_multitenant_app",
        credential_reference={"client_id": client_id},
        declared_scopes=list(AZURE_SCOPES),
        coverage_plan=[],
        configuration={
            "tenant_id": str(uuid.uuid4()),
            "cloud": "AzureCloud",
            "coverage_mode": "selected-subscriptions",
            "subscriptions": [],
        },
    )
    assert created["credential_reference"] == {
        "type": "azure_multitenant_app",
        "client_id": client_id,
    }

    launched = repo.record_connection_setup_launch(
        tenant,
        connection_id,
        launch={
            "method": "azure_cloud_shell",
            "script_version": "denali-azure-subscription-reader-v1",
            "script_sha256": "c" * 64,
            "client_id": client_id,
            "published_at": now.isoformat(),
            "url_expires_at": (now + timedelta(hours=1)).isoformat(),
        },
        setup_token_sha256=setup_token_sha256,
    )
    assert launched is not None
    assert "setup_token" not in str(launched)
    target = repo.get_connection_validation_target(tenant, connection_id)
    assert target is not None
    assert target["credential_reference"]["setup_token_sha256"] == setup_token_sha256

    plan = azure_coverage_plan(list(AZURE_SCOPES), subscriptions)
    completed = repo.complete_azure_connection_setup(
        tenant,
        connection_id,
        expected_setup_token_sha256=setup_token_sha256,
        service_principal_id=service_principal_id,
        subscriptions=subscriptions,
        coverage_plan=plan,
        completed_at=now,
    )
    assert completed is not None
    assert completed["configuration"]["subscriptions"] == subscriptions
    assert completed["credential_reference"]["service_principal_id"] == service_principal_id
    assert len(completed["coverage_plan"]) == 16
    completed_target = repo.get_connection_validation_target(tenant, connection_id)
    assert completed_target is not None
    assert "setup_token_sha256" not in completed_target["credential_reference"]

    replay = repo.complete_azure_connection_setup(
        tenant,
        connection_id,
        expected_setup_token_sha256=setup_token_sha256,
        service_principal_id=service_principal_id,
        subscriptions=subscriptions,
        coverage_plan=plan,
        completed_at=now,
    )
    assert replay is None


def test_gcp_setup_completion_consumes_token_and_binds_selected_projects(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    connection_id = str(uuid.uuid4())
    principal_email = "denali-audit@denali-operator.iam.gserviceaccount.com"
    setup_token_sha256 = "d" * 64
    projects = [
        {"id": "production-ai-12345", "name": "Production", "number": "123456789012"},
        {"id": "ai-lab-67890", "name": "AI Lab", "number": "210987654321"},
    ]
    created = repo.create_connection(
        tenant,
        connection_id=connection_id,
        provider="gcp",
        display_name="Fixture GCP",
        credential_type="gcp_service_account",
        credential_reference={"principal_email": principal_email},
        declared_scopes=list(GCP_SCOPES),
        coverage_plan=[],
        configuration={"coverage_mode": "selected-projects", "projects": []},
    )
    assert created["credential_reference"] == {
        "type": "gcp_service_account",
        "principal_email": principal_email,
    }

    launched = repo.record_gcp_connection_setup_launch(
        tenant,
        connection_id,
        launch={
            "method": "gcp_cloud_shell",
            "script_version": "denali-gcp-project-reader-v1",
            "script_sha256": "e" * 64,
            "principal_email": principal_email,
            "published_at": now.isoformat(),
            "url_expires_at": (now + timedelta(hours=1)).isoformat(),
        },
        setup_token_sha256=setup_token_sha256,
    )
    assert launched is not None
    assert "setup_token" not in str(launched)
    target = repo.get_connection_validation_target(tenant, connection_id)
    assert target is not None
    assert target["credential_reference"]["setup_token_sha256"] == setup_token_sha256

    plan = gcp_coverage_plan(list(GCP_SCOPES), projects)
    completed = repo.complete_gcp_connection_setup(
        tenant,
        connection_id,
        expected_setup_token_sha256=setup_token_sha256,
        projects=projects,
        coverage_plan=plan,
        completed_at=now,
    )
    assert completed is not None
    assert completed["configuration"]["projects"] == projects
    assert len(completed["coverage_plan"]) == 12
    completed_target = repo.get_connection_validation_target(tenant, connection_id)
    assert completed_target is not None
    assert "setup_token_sha256" not in completed_target["credential_reference"]

    replay = repo.complete_gcp_connection_setup(
        tenant,
        connection_id,
        expected_setup_token_sha256=setup_token_sha256,
        projects=projects,
        coverage_plan=plan,
        completed_at=now,
    )
    assert replay is None


def test_github_setup_consumes_transient_state_and_binds_exact_repositories(
    repository,
) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    connection_id = str(uuid.uuid4())
    install_state_sha256 = "a" * 64
    oauth_state_sha256 = "b" * 64
    repositories = [
        {
            "id": 101,
            "node_id": "R_fixture_one",
            "name": "service-one",
            "full_name": "example/service-one",
            "owner_id": 44,
            "owner_login": "example",
            "private": True,
            "archived": False,
            "default_branch": "main",
        }
    ]
    created = repo.create_connection(
        tenant,
        connection_id=connection_id,
        provider="github",
        display_name="Fixture GitHub",
        credential_type="github_app_installation",
        credential_reference={"app_id": 12345, "app_slug": "denali-fixture"},
        declared_scopes=list(GITHUB_SCOPES),
        coverage_plan=[],
        configuration={
            "coverage_mode": "exact-installation-repositories",
            "repositories": [],
        },
    )
    assert created["credential_reference"] == {
        "type": "github_app_installation",
        "app_id": 12345,
        "app_slug": "denali-fixture",
    }

    launched = repo.record_github_install_launch(
        tenant,
        connection_id,
        launch={
            "method": "github_app_installation",
            "app_id": 12345,
            "app_slug": "denali-fixture",
            "created_at": now.isoformat(),
            "install_expires_at": (now + timedelta(minutes=30)).isoformat(),
        },
        state_sha256=install_state_sha256,
    )
    assert launched is not None
    assert "install_state" not in str(launched)

    returned = repo.record_github_install_return(
        tenant,
        connection_id,
        expected_install_state_sha256=install_state_sha256,
        installation_id=24680,
        oauth={
            "state_sha256": oauth_state_sha256,
            "pkce_verifier": "transient-pkce-verifier",
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(minutes=30)).isoformat(),
        },
    )
    assert returned is not None
    assert returned["credential_reference"]["installation_id"] == 24680
    assert "pkce" not in str(returned)

    plan = github_coverage_plan(list(GITHUB_SCOPES), repositories)
    completed = repo.complete_github_connection_setup(
        tenant,
        connection_id,
        expected_oauth_state_sha256=oauth_state_sha256,
        installation={
            "account_id": 44,
            "account_login": "example",
            "account_type": "Organization",
            "repository_selection": "selected",
        },
        installer={"id": 55, "login": "installer"},
        repositories=repositories,
        coverage_plan=plan,
        completed_at=now,
    )
    assert completed is not None
    assert completed["configuration"]["repositories"] == repositories
    assert completed["configuration"]["account_id"] == 44
    assert completed["configuration"]["onboarding"]["completed_at"] == now.isoformat()
    assert len(completed["coverage_plan"]) == len(GITHUB_SCOPES)
    target = repo.get_connection_validation_target(tenant, connection_id)
    assert target is not None
    assert "install_state_sha256" not in target["credential_reference"]
    assert "oauth_state_sha256" not in target["credential_reference"]
    assert "pkce_verifier" not in target["credential_reference"]

    replay = repo.complete_github_connection_setup(
        tenant,
        connection_id,
        expected_oauth_state_sha256=oauth_state_sha256,
        installation={
            "account_id": 44,
            "account_login": "example",
            "account_type": "Organization",
            "repository_selection": "selected",
        },
        installer={"id": 55, "login": "installer"},
        repositories=repositories,
        coverage_plan=plan,
        completed_at=now,
    )
    assert replay is None


def test_activity_can_be_filtered_by_correlated_asset(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    first = AssetRef(AssetKind.AI_APPLICATION, "entra:tenant:application:first")
    second = AssetRef(AssetKind.AI_APPLICATION, "entra:tenant:application:second")
    repo.ingest(
        tenant,
        InventoryBatch(
            connector_id="fixture",
            connection_id="fixture-connection",
            run_id="activity-assets",
            scope_key="fixture-scope",
            collected_at=now,
            coverage=(Coverage("applications", CoverageState.COMPLETE, "fixture-scope"),),
            assets=(
                AssetAssertion(
                    asset=first,
                    coverage_plane="applications",
                    display_name="First AI app",
                    assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                    confidence=1.0,
                    evidence=Evidence("fixture", "fixture://first", now),
                ),
                AssetAssertion(
                    asset=second,
                    coverage_plane="applications",
                    display_name="Second AI app",
                    assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                    confidence=1.0,
                    evidence=Evidence("fixture", "fixture://second", now),
                ),
            ),
        ),
    )
    activities = tuple(
        ActivityRecord(
            source_uid=f"sign-in-{index}",
            category=ActivityCategory.AI_APP_SIGN_IN,
            activity_name="entra.auditLogs.signIns",
            title=f"User signed in to {label}",
            occurred_at=now + timedelta(seconds=index),
            observed_at=now,
            outcome=ActivityOutcome.SUCCESS,
            provider="Microsoft Entra",
            evidence=Evidence("fixture", f"fixture://sign-in-{index}", now),
            entities=(
                ActivityEntity(
                    role=ActivityEntityRole.APPLICATION,
                    external_uid=asset.natural_key,
                    display_name=label,
                    asset=asset,
                    correlation=ActivityCorrelation.EXACT_IDENTIFIER,
                    confidence=1.0,
                ),
            ),
        )
        for index, (asset, label) in enumerate(((first, "First AI app"), (second, "Second AI app")))
    )
    repo.ingest_activity(
        tenant,
        ActivityBatch(
            connector_id="fixture.activity",
            connection_id="fixture-activity",
            run_id="activity-run",
            scope_key="fixture-scope",
            collected_at=now,
            coverage=(Coverage("activity", CoverageState.COMPLETE, "fixture-scope"),),
            activities=activities,
        ),
    )

    first_id = next(
        row["id"] for row in repo.list_assets(tenant) if row["natural_key"] == first.natural_key
    )
    rows = repo.list_activity(tenant, asset_id=str(first_id))

    assert [row["source_uid"] for row in rows] == ["sign-in-0"]

    fixture_activity = replace(
        activities[0],
        source_uid="transparent-fixture-sign-in",
        attributes={"fixture": True},
    )
    repo.ingest_activity(
        tenant,
        ActivityBatch(
            connector_id="denali.demo",
            connection_id="local-demo-runtime",
            run_id="transparent-fixture-run",
            scope_key="runtime-preview",
            collected_at=now,
            coverage=(Coverage("activity", CoverageState.COMPLETE, "runtime-preview"),),
            activities=(fixture_activity,),
        ),
    )

    assert {row["source_uid"] for row in repo.list_activity(tenant)} == {
        "sign-in-0",
        "sign-in-1",
    }
    assert {row["source_uid"] for row in repo.list_activity(tenant, include_fixtures=True)} == {
        "sign-in-0",
        "sign-in-1",
        "transparent-fixture-sign-in",
    }
    assert repo.activity_summary(tenant) == {
        "total": 2,
        "last_24h": 2,
        "providers": 1,
        "failures": 0,
        "fixture_total": 1,
        "by_category": {"ai_app_sign_in": 2},
    }
    assert repo.activity_summary(tenant, include_fixtures=True)["total"] == 3


def test_runtime_detections_are_evidence_linked_and_idempotent(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    application = AssetRef(
        AssetKind.AI_APPLICATION,
        "entra:tenant:application:fireflies",
    )
    repo.ingest(
        tenant,
        InventoryBatch(
            connector_id="denali.entra_ai",
            connection_id="entra:tenant",
            run_id="entra-inventory",
            scope_key="entra:tenant:enterprise-applications",
            collected_at=now,
            coverage=(
                Coverage(
                    "entra_ai_application_inventory",
                    CoverageState.COMPLETE,
                    "entra:tenant:enterprise-applications",
                ),
            ),
            assets=(
                AssetAssertion(
                    asset=application,
                    coverage_plane="entra_ai_application_inventory",
                    display_name="Fireflies.ai",
                    assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                    confidence=1.0,
                    evidence=Evidence("microsoft_graph", "graph://servicePrincipals/1", now),
                    attributes={"delegated_scopes": ["User.Read", "Mail.ReadWrite"]},
                ),
            ),
        ),
    )

    actor = ActivityEntity(
        role=ActivityEntityRole.ACTOR,
        external_uid="analyst@example.com",
        display_name="analyst@example.com",
    )
    app_entity = ActivityEntity(
        role=ActivityEntityRole.APPLICATION,
        external_uid=application.natural_key,
        display_name="Fireflies.ai",
        asset=application,
        correlation=ActivityCorrelation.EXACT_IDENTIFIER,
        confidence=1.0,
    )
    failures = tuple(
        ActivityRecord(
            source_uid=f"failed-sign-in-{index}",
            category=ActivityCategory.AI_APP_SIGN_IN,
            activity_name="entra.auditLogs.signIns",
            title="Fireflies.ai sign-in failed",
            occurred_at=now + timedelta(hours=index),
            observed_at=now,
            outcome=ActivityOutcome.FAILURE,
            provider="Microsoft Entra",
            evidence=Evidence("microsoft_graph_signin", f"graph://signIns/{index}", now),
            entities=(actor, app_entity),
        )
        for index in range(3)
    )
    consent = tuple(
        ActivityRecord(
            source_uid=f"consent-change-{index}",
            category=ActivityCategory.ADMIN_CHANGE,
            activity_name="entra.auditLogs.directoryAudits",
            title="Consent changed for Fireflies.ai",
            occurred_at=now + timedelta(hours=4, seconds=index),
            observed_at=now,
            outcome=ActivityOutcome.SUCCESS,
            provider="Microsoft Entra",
            evidence=Evidence(
                "microsoft_graph_directory_audit",
                f"graph://directoryAudits/{index}",
                now,
            ),
            trace_uid="consent-correlation-1",
            entities=(actor, app_entity),
            attributes={"activity_operation": "Add delegated permission grant"},
        )
        for index in range(2)
    )
    repo.ingest_activity(
        tenant,
        ActivityBatch(
            connector_id="denali.entra_ai",
            connection_id="entra:tenant",
            run_id="entra-activity",
            scope_key="entra:tenant:activity",
            collected_at=now,
            coverage=(
                Coverage("entra_ai_signins", CoverageState.COMPLETE, "entra:tenant:signins"),
                Coverage(
                    "entra_ai_directory_audits",
                    CoverageState.COMPLETE,
                    "entra:tenant:directory-audits",
                ),
            ),
            activities=failures + consent,
        ),
    )

    first = repo.evaluate_runtime_detections(tenant)
    rows = repo.list_runtime_detections(tenant)
    assert first["confirmed_detections"] == 2
    assert len(rows) == 2
    assert {row["severity"] for row in rows} == {"medium", "high"}
    assert {row["activity_count"] for row in rows} == {2, 3}
    assert {row["asset_count"] for row in rows} == {1}

    consent_row = next(row for row in rows if row["severity"] == "high")
    detail = repo.get_runtime_detection(tenant, str(consent_row["id"]))
    assert detail is not None
    assert len(detail["activities"]) == 2
    assert detail["attributes"]["high_impact_scopes"] == ["Mail.ReadWrite"]
    assert detail["assets"][0]["natural_key"] == application.natural_key

    second = repo.evaluate_runtime_detections(tenant)
    assert second["confirmed_detections"] == 2
    assert [row["id"] for row in repo.list_runtime_detections(tenant)] == [
        row["id"] for row in rows
    ]
    assert repo.runtime_detection_summary(tenant) == {
        "total": 2,
        "by_state": {"open": 2},
        "open_by_severity": {"high": 1, "medium": 1},
    }
    evaluations = repo.latest_runtime_detection_evaluations(tenant)
    evaluations_by_rule = {row["rule_uid"]: row for row in evaluations}
    assert {
        rule_uid: (row["state"], row["confirmed_detections"])
        for rule_uid, row in evaluations_by_rule.items()
    } == {
        ENTRA_FAILURE_RULE_UID: ("complete", 1),
        ENTRA_CONSENT_RULE_UID: ("complete", 1),
        UNREVIEWED_MODEL_RULE_UID: ("unknown", 0),
    }


def test_consent_then_use_issue_persists_exact_detection_and_activity_evidence(
    repository,
) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    application = AssetRef(
        AssetKind.AI_APPLICATION,
        "entra:tenant:application:claude-for-office",
    )
    repo.ingest(
        tenant,
        InventoryBatch(
            connector_id="denali.entra_ai",
            connection_id="entra:tenant",
            run_id="entra-issue-inventory",
            scope_key="entra:tenant:enterprise-applications",
            collected_at=now,
            coverage=(
                Coverage(
                    "entra_ai_application_inventory",
                    CoverageState.COMPLETE,
                    "entra:tenant:enterprise-applications",
                ),
            ),
            assets=(
                AssetAssertion(
                    asset=application,
                    coverage_plane="entra_ai_application_inventory",
                    display_name="Claude for Office",
                    assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                    confidence=1.0,
                    evidence=Evidence(
                        "microsoft_graph",
                        "graph://servicePrincipals/claude-for-office",
                        now,
                    ),
                    attributes={"delegated_scopes": ["Mail.ReadWrite"]},
                ),
            ),
        ),
    )

    application_entity = ActivityEntity(
        role=ActivityEntityRole.APPLICATION,
        external_uid=application.natural_key,
        display_name="Claude for Office",
        asset=application,
        correlation=ActivityCorrelation.EXACT_IDENTIFIER,
        confidence=1.0,
    )
    consent_actor = ActivityEntity(
        role=ActivityEntityRole.ACTOR,
        external_uid="admin@example.com",
        display_name="admin@example.com",
    )
    use_actor = ActivityEntity(
        role=ActivityEntityRole.ACTOR,
        external_uid="user@example.com",
        display_name="user@example.com",
    )
    consent = ActivityRecord(
        source_uid="claude-consent-change",
        category=ActivityCategory.ADMIN_CHANGE,
        activity_name="entra.auditLogs.directoryAudits",
        title="Consent changed for Claude for Office",
        occurred_at=now,
        observed_at=now,
        outcome=ActivityOutcome.SUCCESS,
        provider="Microsoft Entra",
        evidence=Evidence(
            "microsoft_graph_directory_audit",
            "graph://directoryAudits/claude-consent",
            now,
        ),
        trace_uid="claude-consent-correlation",
        entities=(consent_actor, application_entity),
        attributes={"activity_operation": "Add delegated permission grant"},
    )
    later_sign_in = ActivityRecord(
        source_uid="claude-sign-in-after-consent",
        category=ActivityCategory.AI_APP_SIGN_IN,
        activity_name="entra.auditLogs.signIns",
        title="Claude for Office sign-in succeeded",
        occurred_at=now + timedelta(hours=1),
        observed_at=now + timedelta(hours=1),
        outcome=ActivityOutcome.SUCCESS,
        provider="Microsoft Entra",
        evidence=Evidence(
            "microsoft_graph_signin",
            "graph://signIns/claude-after-consent",
            now + timedelta(hours=1),
        ),
        entities=(use_actor, application_entity),
    )
    repo.ingest_activity(
        tenant,
        ActivityBatch(
            connector_id="denali.entra_ai",
            connection_id="entra:tenant",
            run_id="entra-issue-activity",
            scope_key="entra:tenant:activity",
            collected_at=now + timedelta(hours=1),
            coverage=(
                Coverage("entra_ai_signins", CoverageState.COMPLETE, "entra:tenant:signins"),
                Coverage(
                    "entra_ai_directory_audits",
                    CoverageState.COMPLETE,
                    "entra:tenant:directory-audits",
                ),
            ),
            activities=(consent, later_sign_in),
        ),
    )

    assert repo.evaluate_runtime_detections(tenant)["confirmed_detections"] == 1
    result = repo.evaluate_issues(tenant)
    assert result["confirmed_issues"] == 1

    rows = repo.list_issues(tenant)
    assert len(rows) == 1
    assert rows[0]["rule_uid"] == "DENALI-ISSUE-SHADOW-AI-CONSENT-USE-001"
    assert rows[0]["detection_count"] == 1
    assert rows[0]["activity_count"] == 1
    assert rows[0]["asset_count"] == 1
    assert rows[0]["finding_count"] == 0

    detail = repo.get_issue(tenant, str(rows[0]["id"]))
    assert detail is not None
    assert detail["path_edges"] == []
    assert detail["detections"][0]["role"] == "high_impact_consent"
    assert detail["activities"][0]["role"] == "subsequent_successful_sign_in"
    assert detail["activities"][0]["actors"][0]["display_name"] == "user@example.com"
    assert detail["attributes"]["high_impact_scopes"] == ["Mail.ReadWrite"]


def test_deployment_targets_accept_provider_neutral_identity(repository, tmp_path: Path) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    workload = AssetRef(
        AssetKind.AI_WORKLOAD,
        "//run.googleapis.com/projects/denali-test/locations/us-central1/services/denali-ai",
    )
    evidence = Evidence(
        "gcp_control_plane",
        "gcp://run/denali-test/us-central1/denali-ai",
        now,
    )
    repo.ingest(
        tenant,
        InventoryBatch(
            connector_id="fixture.gcp_run",
            connection_id="gcp:denali-test",
            run_id="gcp-run",
            scope_key="gcp:denali-test:us-central1",
            collected_at=now,
            coverage=(
                Coverage(
                    "gcp_run_inventory",
                    CoverageState.COMPLETE,
                    "gcp:denali-test:us-central1",
                ),
            ),
            assets=(
                AssetAssertion(
                    asset=workload,
                    coverage_plane="gcp_run_inventory",
                    display_name="denali-ai",
                    assertion_type=AssertionType.OBSERVED,
                    confidence=1.0,
                    evidence=evidence,
                    attributes={
                        "provider": "gcp",
                        "service": "cloud_run",
                        "runtime_kind": "container_service",
                        "deployment_identifiers": {
                            "project": ["denali-test"],
                            "project_number": ["123456789012"],
                            "location": ["us-central1"],
                            "service_name": ["denali-ai"],
                        },
                    },
                ),
            ),
        ),
    )

    [target] = repo.deployment_targets(tenant)
    assert target["natural_key"] == workload.natural_key
    assert target["identity"] == {
        "provider": "gcp",
        "runtime_kind": "container_service",
        "identifiers": [
            {"name": "project", "value": "denali-test", "comparison": "exact"},
            {"name": "location", "value": "us-central1", "comparison": "exact"},
            {"name": "service_name", "value": "denali-ai", "comparison": "exact"},
            {
                "name": "project_number",
                "value": "123456789012",
                "comparison": "exact",
            },
        ],
    }

    (tmp_path / "service.yaml").write_text(
        """
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: denali-ai
  namespace: '123456789012'
  labels:
    cloud.googleapis.com/location: us-central1
"""
    )
    targets = tuple(
        DeploymentTarget.from_record(item) for item in repo.deployment_targets(tenant)
    )
    correlated = CodeToCloudConnector(
        tmp_path,
        targets=targets,
        repository_name="github.com/example/denali-gcp",
    ).collect()
    repo.ingest(tenant, correlated)

    [deployment] = repo.code_to_cloud_deployments(tenant)
    assert deployment["repository_natural_key"] == "github.com/example/denali-gcp"
    assert deployment["workload_natural_key"] == workload.natural_key
    assert deployment["workload_attributes"]["provider"] == "gcp"
    assert deployment["evidence"]["payload"]["match_basis"] == [
        "literal_gcp_project_number",
        "literal_gcp_location",
        "literal_cloud_run_service_name",
    ]


def test_code_to_cloud_query_preserves_proven_runtime_context(repository, tmp_path: Path) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    workload = AssetRef(
        AssetKind.AI_WORKLOAD,
        "arn:aws:lambda:ap-south-1:123456789012:function:anna-agent",
    )
    model = AssetRef(AssetKind.AI_MODEL, "aws:bedrock:model:claude")
    identity = AssetRef(
        AssetKind.IDENTITY,
        "arn:aws:iam::123456789012:role/anna-agent-role",
    )
    evidence = Evidence("aws_control_plane", "aws://fixture/anna-agent", now)
    observed = InventoryBatch(
        connector_id="denali.aws_stack",
        connection_id="aws:123456789012",
        run_id="aws-run",
        scope_key="aws:123456789012:stack:Anna",
        collected_at=now,
        coverage=(
            Coverage("aws_stack_inventory", CoverageState.COMPLETE, "stack:Anna"),
            Coverage("aws_stack_relationships", CoverageState.COMPLETE, "stack:Anna"),
        ),
        assets=(
            AssetAssertion(
                asset=workload,
                coverage_plane="aws_stack_inventory",
                display_name="anna-agent",
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                    evidence=evidence,
                    attributes={
                        "provider": "aws",
                        "service": "lambda",
                        "runtime_kind": "serverless_function",
                        "logical_id": "AgentFnC1FD126F",
                        "deployment_identifiers": {
                            "cloudformation_logical_id": ["AgentFnC1FD126F"],
                            "function_name": ["anna-agent"],
                        },
                    "account_id": "123456789012",
                    "region": "ap-south-1",
                    "deployment_artifact": {
                        "kind": "container_image",
                        "image": "registry.example/anna@sha256:fixture",
                    },
                },
            ),
            AssetAssertion(
                asset=model,
                coverage_plane="aws_stack_inventory",
                display_name="Claude",
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                evidence=evidence,
            ),
            AssetAssertion(
                asset=identity,
                coverage_plane="aws_stack_inventory",
                display_name="anna-agent-role",
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                evidence=evidence,
            ),
        ),
        relationships=(
            RelationshipAssertion(
                source=workload,
                target=model,
                coverage_plane="aws_stack_relationships",
                kind=RelationshipKind.USES,
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                evidence=evidence,
            ),
            RelationshipAssertion(
                source=workload,
                target=identity,
                coverage_plane="aws_stack_relationships",
                kind=RelationshipKind.RUNS_AS,
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                evidence=evidence,
            ),
        ),
    )
    repo.ingest(tenant, observed)
    targets = tuple(
        DeploymentTarget.from_record(item) for item in repo.deployment_targets(tenant)
    )
    assert [item.natural_key for item in targets] == [workload.natural_key]

    (tmp_path / "stack.ts").write_text(
        """
new nodejs.NodejsFunction(this, 'AgentFn', {
  functionName: 'anna-agent',
  entry: 'src/handler.ts',
});
"""
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "handler.ts").write_text(
        "import { ConverseCommand } from '@aws-sdk/client-bedrock-runtime';\n"
        "new ConverseCommand({ modelId: 'model' });\n"
    )
    (tmp_path / "src" / "other.ts").write_text(
        "import { InvokeModelCommand } from '@aws-sdk/client-bedrock-runtime';\n"
        "new InvokeModelCommand({ modelId: 'other' });\n"
    )
    posture = RepositoryPostureConnector(
        tmp_path,
        repository_name="github.com/example/anna",
    ).collect()
    repo.ingest_findings(tenant, posture)
    correlated = CodeToCloudConnector(
        tmp_path,
        targets=targets,
        repository_name="github.com/example/anna",
    ).collect()
    repo.ingest(tenant, correlated)

    observations = repo.code_to_cloud_observations(tenant)
    assert len(observations) == 1
    assert observations[0]["repository_natural_key"] == "github.com/example/anna"
    assert observations[0]["source_state"] is None
    assert observations[0]["analysis_state"] == "complete"
    assert observations[0]["correlation_summary"] == {
        "declarations": 1,
        "proven": 1,
        "ambiguous": 0,
        "unmatched": 0,
        "targets_evaluated": 1,
    }
    assert observations[0]["correlation_candidates"][0]["status"] == "proven"

    scan_time = now + timedelta(minutes=1)
    component = SoftwareComponentAssertion(
        identity=ComponentIdentity(
            target=workload,
            name="boto3",
            version="1.34.0",
            ecosystem="python",
            package_type="python",
            purl="pkg:pypi/boto3@1.34.0",
            location="/var/task/boto3",
        ),
        coverage_plane="software_components",
        scope=ComponentScope.INSTALLED,
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=Evidence("syft", "file:///anna.syft.json#artifact=0", scan_time),
    )
    scan_scope = workload.canonical_key
    repo.ingest(
        tenant,
        InventoryBatch(
            connector_id="denali.syft",
            connection_id=f"syft:{scan_scope}",
            run_id="syft-anna-1",
            scope_key=scan_scope,
            collected_at=scan_time,
            coverage=(Coverage("software_components", CoverageState.COMPLETE, scan_scope),),
            assets=(component.asset_assertion(),),
            relationships=(component.containment_assertion(),),
        ),
    )
    vulnerability = VulnerabilityAssertion(
        source_uid="grype:CVE-2026-0001:boto3",
        vulnerability_id="CVE-2026-0001",
        component=component.identity.asset_ref,
        target=workload,
        title="Fixture boto3 vulnerability",
        severity=FindingSeverity.HIGH,
        state=FindingState.OPEN,
        observed_at=scan_time,
        evidence=Evidence("grype", "file:///anna.grype.json#match=0", scan_time),
        match_method=VulnerabilityMatchMethod.EXACT_DIRECT,
        match_confidence=1.0,
        cvss_score=8.1,
        fix_state=VulnerabilityFixState.FIXED,
        fixed_versions=("1.34.1",),
    )
    repo.ingest_vulnerabilities(
        tenant,
        VulnerabilityBatch(
            connector_id="denali.grype",
            connection_id=f"grype:{scan_scope}",
            run_id="grype-anna-1",
            scope_key=scan_scope,
            collected_at=scan_time,
            coverage=(Coverage("vulnerabilities", CoverageState.COMPLETE, scan_scope),),
            vulnerabilities=(vulnerability,),
            scan_subject=VulnerabilityScanSubject(
                target=workload,
                artifact_kind="container_image",
                artifact_locator="registry.example/anna@sha256:fixture",
                evidence=Evidence(
                    "grype_scan_subject",
                    "file:///anna.grype.json#source",
                    scan_time,
                ),
            ),
            authoritative=True,
        ),
    )

    deployments = repo.code_to_cloud_deployments(tenant)

    assert len(deployments) == 1
    assert deployments[0]["repository_natural_key"] == "github.com/example/anna"
    assert deployments[0]["workload_natural_key"] == workload.natural_key
    assert deployments[0]["models"][0]["natural_key"] == model.natural_key
    assert deployments[0]["identity"]["natural_key"] == identity.natural_key
    assert [item["applicability"] for item in deployments[0]["code_findings"]] == [
        "artifact_included",
        "repository_only",
    ]
    included = deployments[0]["code_findings"][0]
    assert included["source_path"] == "src/handler.ts"
    assert included["import_chain"] == ["src/handler.ts"]
    assert deployments[0]["vulnerability_coverage"]["state"] == "complete"
    assert deployments[0]["vulnerability_coverage"]["artifact_identity_status"] == "matched"
    assert deployments[0]["vulnerability_coverage"]["artifact_identity_method"] == "exact_locator"
    assert deployments[0]["artifact_vulnerability_count"] == 1
    assert deployments[0]["artifact_vulnerability_id_count"] == 1
    assert len(deployments[0]["artifact_vulnerabilities"]) == 1
    artifact_vulnerability = deployments[0]["artifact_vulnerabilities"][0]
    assert artifact_vulnerability["vulnerability_id"] == "CVE-2026-0001"
    assert artifact_vulnerability["component_name"] == "boto3 1.34.0"
    assert artifact_vulnerability["component_purl"] == "pkg:pypi/boto3@1.34.0"
    assert artifact_vulnerability["source_count"] == 1

    mismatch_time = scan_time + timedelta(minutes=1)
    repo.ingest_vulnerabilities(
        tenant,
        VulnerabilityBatch(
            connector_id="denali.grype",
            connection_id=f"grype:{scan_scope}",
            run_id="grype-anna-mismatched",
            scope_key=scan_scope,
            collected_at=mismatch_time,
            coverage=(Coverage("vulnerabilities", CoverageState.PARTIAL, scan_scope),),
            vulnerabilities=(
                replace(
                    vulnerability,
                    observed_at=mismatch_time,
                    evidence=Evidence(
                        "grype",
                        "file:///other.grype.json#match=0",
                        mismatch_time,
                    ),
                ),
            ),
            scan_subject=VulnerabilityScanSubject(
                target=workload,
                artifact_kind="container_image",
                artifact_locator="registry.example/other@sha256:not-deployed",
                evidence=Evidence(
                    "grype_scan_subject",
                    "file:///other.grype.json#source",
                    mismatch_time,
                ),
            ),
        ),
    )

    mismatched = repo.code_to_cloud_deployments(tenant)[0]
    assert mismatched["vulnerability_coverage"]["state"] == "partial"
    assert mismatched["vulnerability_coverage"]["artifact_identity_status"] == "not_matched"
    assert mismatched["artifact_vulnerability_count"] == 0
    assert mismatched["artifact_vulnerability_id_count"] == 0
    assert mismatched["artifact_vulnerabilities"] == []


def test_complete_empty_snapshot_withdraws_but_partial_does_not(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    first = assertion("agent-one", now)
    repo.ingest(
        tenant,
        inventory_batch(run_id="run-1", state=CoverageState.COMPLETE, assets=(first,), at=now),
    )

    partial = repo.ingest(
        tenant,
        inventory_batch(
            run_id="run-2",
            state=CoverageState.PARTIAL,
            assets=(),
            at=now + timedelta(minutes=1),
        ),
    )
    assert partial["withdrawn_assets"] == 0
    assert repo.summary(tenant)["total"] == 1

    complete = repo.ingest(
        tenant,
        inventory_batch(
            run_id="run-3",
            state=CoverageState.COMPLETE,
            assets=(),
            at=now + timedelta(minutes=2),
        ),
    )
    assert complete["withdrawn_assets"] == 1
    assert repo.summary(tenant)["total"] == 0


def test_one_source_cannot_withdraw_another_sources_asset(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    shared = assertion("shared-agent", now)
    repo.ingest(
        tenant,
        inventory_batch(
            run_id="fixture-run", state=CoverageState.COMPLETE, assets=(shared,), at=now
        ),
    )
    second_source = InventoryBatch(
        connector_id="other-source",
        connection_id="other-connection",
        run_id="other-run",
        scope_key="fixture-scope",
        collected_at=now,
        coverage=(Coverage("agents", CoverageState.COMPLETE, "fixture-scope"),),
        assets=(shared,),
    )
    repo.ingest(tenant, second_source)

    repo.ingest(
        tenant,
        inventory_batch(
            run_id="fixture-empty",
            state=CoverageState.COMPLETE,
            assets=(),
            at=now + timedelta(minutes=1),
        ),
    )
    assert repo.summary(tenant)["total"] == 1
    detail = repo.get_asset(tenant, str(repo.list_assets(tenant)[0]["id"]))
    assert detail is not None
    active = [row for row in detail["assertions"] if row["withdrawn_at"] is None]
    assert {row["connector_id"] for row in active} == {"other-source"}


def test_findings_do_not_mint_assets_and_partial_absence_does_not_resolve(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    finding = finding_assertion(now)
    repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="finding-run-1",
            at=now,
            state=CoverageState.COMPLETE,
            findings=(finding,),
        ),
    )

    assert repo.summary(tenant)["total"] == 0
    rows = repo.list_findings(tenant)
    assert len(rows) == 1
    assert rows[0]["state"] == "open"
    detail = repo.get_finding(tenant, str(rows[0]["id"]))
    assert detail is not None
    assert detail["resources"][0]["uid"].endswith("guardrail/gr-1")
    assert detail["compliance"] == {"OWASP-LLM": ["LLM01"]}

    result = repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="finding-run-partial",
            at=now + timedelta(minutes=1),
            state=CoverageState.PARTIAL,
            findings=(),
            authoritative=True,
        ),
    )
    assert result["resolved_missing"] == 0
    assert repo.list_findings(tenant)[0]["state"] == "open"


def test_authoritative_absence_and_explicit_pass_resolve_findings(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="finding-run-open",
            at=now,
            state=CoverageState.COMPLETE,
            findings=(finding_assertion(now),),
        ),
    )

    absent = repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="finding-run-empty",
            at=now + timedelta(minutes=1),
            state=CoverageState.COMPLETE,
            findings=(),
            authoritative=True,
        ),
    )
    assert absent["resolved_missing"] == 1
    assert repo.list_findings(tenant)[0]["resolution_reason"] == (
        "absent_from_authoritative_snapshot"
    )

    repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="finding-run-reopen",
            at=now + timedelta(minutes=2),
            state=CoverageState.COMPLETE,
            findings=(finding_assertion(now + timedelta(minutes=2)),),
        ),
    )
    passed = finding_assertion(
        now + timedelta(minutes=3),
        state=FindingState.RESOLVED,
        result=EvaluationResult.PASS,
    )
    repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="finding-run-pass",
            at=now + timedelta(minutes=3),
            state=CoverageState.COMPLETE,
            findings=(passed,),
        ),
    )
    rows = repo.list_findings(tenant)
    assert rows[0]["state"] == "resolved"
    assert rows[0]["resolution_reason"] == "source_status"
    detail = repo.get_finding(tenant, str(rows[0]["id"]))
    assert detail is not None
    assert len(detail["observations"]) == 3


def test_pass_without_a_prior_failure_does_not_create_finding_noise(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    passed = finding_assertion(
        now,
        state=FindingState.RESOLVED,
        result=EvaluationResult.PASS,
    )

    result = repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="pass-only-run",
            at=now,
            state=CoverageState.COMPLETE,
            findings=(passed,),
        ),
    )

    assert result == {"findings": 0, "resolved_missing": 0}


def test_vulnerability_sources_deduplicate_and_resolve_independently(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    repo.ingest(tenant, software_inventory_batch(now, run_id="syft-run-1"))

    grype = vulnerability_assertion(now, source_uid="grype:CVE-2023-6020:ray", source="grype")
    repo.ingest_vulnerabilities(
        tenant,
        vulnerability_batch(
            connector_id="denali.grype",
            run_id="grype-run-1",
            observed_at=now,
            vulnerabilities=(grype,),
        ),
    )
    later = now + timedelta(minutes=1)
    trivy = replace(
        grype,
        source_uid="trivy:CVE-2023-6020:ray",
        observed_at=later,
        evidence=Evidence("trivy", "file:///trivy.json#match=0", later),
        match_method=VulnerabilityMatchMethod.ECOSYSTEM,
        match_confidence=0.95,
    )
    repo.ingest_vulnerabilities(
        tenant,
        vulnerability_batch(
            connector_id="denali.trivy",
            run_id="trivy-run-1",
            observed_at=later,
            vulnerabilities=(trivy,),
        ),
    )

    rows = repo.list_vulnerabilities(tenant)
    assert len(rows) == 1
    assert rows[0]["source_count"] == 2
    assert rows[0]["component_correlated"] is True
    assert rows[0]["target_correlated"] is True
    detail = repo.get_vulnerability(tenant, str(rows[0]["id"]))
    assert detail is not None
    assert {row["connector_id"] for row in detail["observations"]} == {
        "denali.grype",
        "denali.trivy",
    }

    grype_empty_at = later + timedelta(minutes=1)
    repo.ingest_vulnerabilities(
        tenant,
        vulnerability_batch(
            connector_id="denali.grype",
            run_id="grype-run-2",
            observed_at=grype_empty_at,
            vulnerabilities=(),
            authoritative=True,
        ),
    )
    assert repo.list_vulnerabilities(tenant)[0]["state"] == "open"
    assert repo.list_vulnerabilities(tenant)[0]["source_count"] == 1

    trivy_empty_at = grype_empty_at + timedelta(minutes=1)
    result = repo.ingest_vulnerabilities(
        tenant,
        vulnerability_batch(
            connector_id="denali.trivy",
            run_id="trivy-run-2",
            observed_at=trivy_empty_at,
            vulnerabilities=(),
            authoritative=True,
        ),
    )
    assert result["resolved_missing"] == 1
    assert repo.list_vulnerabilities(tenant)[0]["state"] == "resolved"


def test_vulnerability_references_correlate_when_inventory_arrives_later(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    item = vulnerability_assertion(now, source_uid="grype:CVE-2023-6020:ray", source="grype")
    repo.ingest_vulnerabilities(
        tenant,
        vulnerability_batch(
            connector_id="denali.grype",
            run_id="grype-first",
            observed_at=now,
            vulnerabilities=(item,),
        ),
    )
    before = repo.list_vulnerabilities(tenant)[0]
    assert before["component_correlated"] is False
    assert before["target_correlated"] is False

    repo.ingest(
        tenant,
        software_inventory_batch(now + timedelta(minutes=1), run_id="syft-later"),
    )
    after = repo.list_vulnerabilities(tenant)[0]
    assert after["component_correlated"] is True
    assert after["target_correlated"] is True
    assert repo.finding_summary(tenant)["total"] == 0


def test_vulnerability_component_correlates_across_bounded_purl_qualifier_drift(
    repository,
) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    target = AssetRef(AssetKind.AI_WORKLOAD, "fixture-debian-workload")
    syft_component = SoftwareComponentAssertion(
        identity=ComponentIdentity(
            target=target,
            name="perl-base",
            version="5.36.0-7+deb12u3",
            ecosystem="deb",
            package_type="deb",
            purl=(
                "pkg:deb/debian/perl-base@5.36.0-7%2Bdeb12u3"
                "?arch=amd64&distro=debian-12&upstream=perl"
            ),
            location="/var/lib/dpkg/status",
        ),
        coverage_plane="software_components",
        scope=ComponentScope.INSTALLED,
        assertion_type=AssertionType.OBSERVED,
        confidence=1.0,
        evidence=Evidence("syft", "file:///syft.json#artifact=perl-base", now),
        attributes={"syft": {"artifact_ids": ["artifact-perl-base"]}},
    )
    repo.ingest(
        tenant,
        InventoryBatch(
            connector_id="denali.syft",
            connection_id="syft-debian",
            run_id="syft-debian-1",
            scope_key=target.canonical_key,
            collected_at=now,
            coverage=(
                Coverage(
                    "software_components",
                    CoverageState.COMPLETE,
                    target.canonical_key,
                ),
            ),
            assets=(syft_component.asset_assertion(),),
            relationships=(syft_component.containment_assertion(),),
        ),
    )

    grype_identity = ComponentIdentity(
        target=target,
        name="perl-base",
        version="5.36.0-7+deb12u3",
        ecosystem="deb",
        package_type="deb",
        purl=(
            "pkg:deb/debian/perl-base@5.36.0-7%2Bdeb12u3"
            "?arch=amd64&distro=debian-12.15&upstream=perl"
        ),
        location="/var/lib/dpkg/status",
    )
    vulnerability = VulnerabilityAssertion(
        source_uid="grype:CVE-2026-12087:perl-base",
        vulnerability_id="CVE-2026-12087",
        component=grype_identity.asset_ref,
        target=target,
        title="Perl Socket out-of-bounds heap read",
        severity=FindingSeverity.CRITICAL,
        state=FindingState.OPEN,
        observed_at=now,
        evidence=Evidence(
            "grype_json",
            "file:///grype.json#match=0",
            now,
            payload={
                "artifact_id": "artifact-perl-base",
                "location": "/var/lib/dpkg/status",
            },
        ),
        match_method=VulnerabilityMatchMethod.EXACT_INDIRECT,
        match_confidence=0.95,
        attributes={
            "component": {
                "artifact_id": "artifact-perl-base",
                "name": "perl-base",
                "version": "5.36.0-7+deb12u3",
                "ecosystem": "deb",
                "package_type": "deb",
                "purl": grype_identity.purl,
                "location": "/var/lib/dpkg/status",
            }
        },
    )
    repo.ingest_vulnerabilities(
        tenant,
        vulnerability_batch(
            connector_id="denali.grype",
            run_id="grype-debian-1",
            observed_at=now,
            vulnerabilities=(vulnerability,),
        ),
    )

    row = repo.list_vulnerabilities(tenant)[0]
    assert row["component_correlated"] is True
    assert row["component_name"] == "perl-base 5.36.0-7+deb12u3"
    assert row["component_natural_key"] == grype_identity.natural_key
    detail = repo.get_vulnerability(tenant, str(row["id"]))
    assert detail is not None
    component_asset = next(
        item
        for item in repo.list_assets(tenant, kind="software_component")
        if item["natural_key"] == syft_component.identity.natural_key
    )
    assert detail["component"]["asset_id"] == component_asset["id"]


def test_reobservation_time_does_not_look_like_a_semantic_finding_change(repository) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="stable-run-1",
            at=now,
            state=CoverageState.COMPLETE,
            findings=(finding_assertion(now),),
        ),
    )
    first_changed_at = repo.list_findings(tenant)[0]["last_changed_at"]

    later = now + timedelta(minutes=5)
    repo.ingest_findings(
        tenant,
        findings_batch(
            run_id="stable-run-2",
            at=later,
            state=CoverageState.COMPLETE,
            findings=(finding_assertion(later),),
        ),
    )

    assert repo.list_findings(tenant)[0]["last_changed_at"] == first_changed_at


def test_issue_projection_requires_graph_evidence_and_tracks_finding_resolution(
    repository,
) -> None:
    tenant, repo = repository
    now = datetime.now(UTC)
    repo.ingest(tenant, demo_batch(now))
    original_findings = demo_findings_batch(now)
    repo.ingest_findings(tenant, original_findings)

    result = repo.evaluate_issues(tenant)
    assert result == {
        "confirmed_issues": 1,
        "evaluation_state": "complete",
        "incomplete_candidates": 0,
        "ambiguous_resource_references": 0,
    }
    rows = repo.list_issues(tenant)
    assert len(rows) == 1
    assert rows[0]["finding_count"] == 2
    assert rows[0]["asset_count"] == 4
    detail = repo.get_issue(tenant, str(rows[0]["id"]))
    assert detail is not None
    assert [edge["kind"] for edge in detail["path_edges"]] == [
        "runs_as",
        "can_invoke",
        "can_write",
    ]
    assert all(edge["category"] == "capability" for edge in detail["path_edges"])

    later = now + timedelta(minutes=1)
    resolved_identity = replace(
        original_findings.findings[0],
        state=FindingState.RESOLVED,
        evaluation_result=EvaluationResult.PASS,
        observed_at=later,
        evidence=replace(original_findings.findings[0].evidence, observed_at=later),
    )
    updated = replace(
        demo_findings_batch(later),
        findings=(resolved_identity, *demo_findings_batch(later).findings[1:]),
    )
    repo.ingest_findings(tenant, updated)
    repo.evaluate_issues(tenant)

    resolved = repo.list_issues(tenant)[0]
    assert resolved["state"] == "resolved"
    assert resolved["resolution_reason"] == "contributing_finding_inactive"
