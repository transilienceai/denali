"""Selected native AWS reads are an exact boundary, not discovery or remediation."""

from copy import deepcopy
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_connections import ConnectionRepositoryStub
from test_gateway_connection_lifecycle import GUARD, HEADERS, PATH, Repository, app
from test_validation_jobs import JobRepository

from denali.api.app import AwsConnectionCreate, create_app
from denali.api.connection_capabilities import setup_summary
from denali.api.validation import run_durable_validation_job
from denali.connections.aws import AwsConnectionValidator, render_cloudformation
from denali.connections.aws_selected_resource import (
    SelectedRoleIamReader,
    connection_selection,
    parse_selection,
    read_lambda,
    selected_validation_passed,
)
from denali.connectors.aws_deployments import AwsConnectionDeploymentCollector
from denali.connectors.aws_stack import AwsStackDiscoveryError
from denali.connectors.aws_stack_posture import _overbroad_bedrock_permissions
from denali.domain import AssetKind, CoverageState, RelationshipKind

ACCOUNT = "123456789012"
FUNCTION = f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:approved-agent"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/service-role/approved-execution"
READER = f"arn:aws:iam::{ACCOUNT}:role/ExactLambdaReader"
MODEL = "anthropic.claude-3-haiku-20240307-v1:0"
PRIVATE = "never-retain-provider-secrets"


def payload():
    return {
        "provider": "aws",
        "display_name": "Exact native Lambda",
        "account_id": ACCOUNT,
        "partition": "aws",
        "deployment_region": "us-east-1",
        "role_name": "ExactLambdaReader",
        "coverage_mode": "selected-resource",
        "regions": ["us-east-1"],
        "declared_scopes": ["aws.code_to_cloud"],
        "selected_resource": {
            "kind": "lambda_zip",
            "function_arn": FUNCTION,
            "execution_role_arn": ROLE,
            "expected_model_id": MODEL,
        },
    }


def target():
    body = payload()
    return {
        "id": "5e340aec-1157-48d3-9f18-3d6f750aa840",
        "provider": "aws",
        "lifecycle_state": "active",
        "credential_type": "aws_assume_role",
        "credential_reference": {"role_arn": READER, "external_id": "denali-tenant-plan"},
        "declared_scopes": body["declared_scopes"],
        "configuration": {
            key: body[key]
            for key in (
                "account_id",
                "partition",
                "deployment_region",
                "role_name",
                "coverage_mode",
                "regions",
                "selected_resource",
            )
        },
    }


class Session:
    """No fallback method exists: any accidental discovery/service call fails this test."""

    def __init__(self, *, wildcard=True):
        self.calls = []
        self.identity = {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/ExactLambdaReader/qa-session",
        }
        self.config = {
            "FunctionArn": FUNCTION,
            "FunctionName": "approved-agent",
            "PackageType": "Zip",
            "Role": ROLE,
            "Runtime": "python3.13",
            "State": "Active",
            "Environment": {"Variables": {"BEDROCK_MODEL_ID": MODEL, "API_TOKEN": PRIVATE}},
        }
        self.tags = {"Tags": {"aws:cloudformation:logical-id": "ApprovedAgent", "private": PRIVATE}}
        self.inline = {"PolicyNames": ["ModelInvoke"], "IsTruncated": False}
        self.policy = {
            "RoleName": "approved-execution",
            "PolicyName": "ModelInvoke",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "bedrock:InvokeModel",
                        "Resource": "arn:aws:bedrock:us-east-1::foundation-model/anthropic.*"
                        if wildcard
                        else f"arn:aws:bedrock:us-east-1::foundation-model/{MODEL}",
                    }
                ],
            },
        }
        self.attached = {"AttachedPolicies": [], "IsTruncated": False}

    def client(self, service, **kwargs):
        self.calls.append(("client", service, kwargs.get("region_name")))
        if service == "sts":
            return SimpleNamespace(get_caller_identity=lambda: deepcopy(self.identity))
        assert kwargs["region_name"] == "us-east-1"
        if service == "lambda":
            return SimpleNamespace(
                get_function_configuration=self.get_config,
                list_tags=self.list_tags,
            )
        if service == "iam":
            return SimpleNamespace(
                list_role_policies=self.list_role_policies,
                get_role_policy=self.get_role_policy,
                list_attached_role_policies=self.list_attached,
            )
        raise AssertionError(f"unexpected service: {service}")

    def get_config(self, **kwargs):
        assert kwargs == {"FunctionName": FUNCTION}
        self.calls.append(("lambda:GetFunctionConfiguration",))
        return deepcopy(self.config)

    def list_tags(self, **kwargs):
        assert kwargs == {"Resource": FUNCTION}
        self.calls.append(("lambda:ListTags",))
        return deepcopy(self.tags)

    def list_role_policies(self, **kwargs):
        assert kwargs == {"RoleName": "approved-execution"}
        self.calls.append(("iam:ListRolePolicies",))
        return deepcopy(self.inline)

    def get_role_policy(self, **kwargs):
        assert kwargs == {"RoleName": "approved-execution", "PolicyName": "ModelInvoke"}
        self.calls.append(("iam:GetRolePolicy",))
        return deepcopy(self.policy)

    def list_attached(self, **kwargs):
        assert kwargs == {"RoleName": "approved-execution"}
        self.calls.append(("iam:ListAttachedRolePolicies",))
        return deepcopy(self.attached)


class Sink:
    def __init__(self, connection):
        self.connection = connection
        self.inventory = []
        self.findings = []
        self.lookups = []

    def get_connection_validation_target(self, tenant, connection_id):
        self.lookups.append((tenant, connection_id))
        return self.connection if tenant == "tenant-alpha" else None

    def ingest(self, tenant, batch):
        assert tenant == "tenant-alpha"
        self.inventory.append(batch)

    def ingest_findings(self, tenant, batch):
        assert tenant == "tenant-alpha"
        self.findings.append(batch)


def session_factory(session):
    def assume(**kwargs):
        assert kwargs["RoleArn"] == READER
        assert kwargs["ExternalId"] == "denali-tenant-plan"
        assert kwargs["DurationSeconds"] == 900
        return {
            "Credentials": {
                "AccessKeyId": "memory-only",
                "SecretAccessKey": PRIVATE,
                "SessionToken": PRIVATE,
            }
        }

    base = SimpleNamespace(client=lambda service: SimpleNamespace(assume_role=assume))
    return lambda **kwargs: session if kwargs else base


def collector(session):
    return AwsConnectionDeploymentCollector(session_factory=session_factory(session))


def validator(session):
    return AwsConnectionValidator(
        session_factory=session_factory(session),
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("function_arn", FUNCTION + ":1"),
        ("function_arn", FUNCTION + ":alias"),
        ("function_arn", FUNCTION.replace("approved-agent", "*")),
        ("function_arn", "https://lambda.amazonaws.com/"),
        ("function_arn", FUNCTION.replace(ACCOUNT, "999999999999")),
        ("execution_role_arn", ROLE.replace(ACCOUNT, "999999999999")),
        ("execution_role_arn", ROLE.replace("aws:", "aws-cn:")),
        ("expected_model_id", MODEL + "?secret=value"),
        ("expected_model_id", "https://example.com/model"),
        ("expected_model_id", "anthropic.*"),
        ("expected_model_id", MODEL + "," + MODEL),
        ("expected_model_id", f"arn:aws:bedrock:us-west-2::foundation-model/{MODEL}"),
        ("expected_model_id", f"arn:aws:bedrock:us-east-1:999999999999:inference-profile/{MODEL}"),
    ],
)
def test_selection_rejects_broad_ambiguous_and_cross_boundary(field, value):
    body = payload()
    body["selected_resource"][field] = value
    with pytest.raises(ValidationError):
        AwsConnectionCreate.model_validate(body)


@pytest.mark.parametrize(
    "change",
    [
        {"regions": []},
        {"regions": ["us-east-1", "us-west-2"]},
        {"regions": ["us-east-1", "us-east-1"]},
        {"deployment_region": "us-west-2"},
        {"declared_scopes": ["aws.code_to_cloud", "aws.bedrock_agents"]},
        {"declared_scopes": ["aws.code_to_cloud", "aws.code_to_cloud"]},
        {"coverage_mode": "automatic"},
        {"coverage_mode": "selected"},
        {"selected_resource": None},
        {"account_id": "999999999999"},
        {
            "role_name": "approved-execution",
            "selected_resource": {
                **payload()["selected_resource"],
                "execution_role_arn": READER.replace("ExactLambdaReader", "approved-execution"),
            },
        },
    ],
)
def test_typed_create_rejects_competing_modes_regions_scopes_and_reader_reuse(change):
    with pytest.raises(ValidationError):
        AwsConnectionCreate.model_validate({**payload(), **change})


def test_legacy_omission_and_shared_broker_remain_unchanged():
    legacy = payload()
    legacy.pop("selected_resource")
    legacy["coverage_mode"] = "selected"
    assert AwsConnectionCreate.model_validate(legacy).selected_resource is None
    old = target()
    old["configuration"].pop("selected_resource")
    old["configuration"]["coverage_mode"] = "selected"
    assert connection_selection(old) is None
    shared = target()
    shared["credential_type"] = "platform_shared_aws"
    with pytest.raises(ValueError):
        connection_selection(shared)


def test_template_exact_resources_only_and_no_discovery_managed_policy_or_writes():
    template = render_cloudformation(target())
    assert f"Resource: '{FUNCTION}'" in template
    assert f"Resource: '{ROLE}'" in template
    for permission in (
        "lambda:GetFunctionConfiguration",
        "lambda:ListTags",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
        "iam:GetRolePolicy",
    ):
        assert permission in template
    for forbidden in (
        "Resource: '*'",
        "ManagedPolicyArns",
        "DescribeRegions",
        "ListFunctions",
        "GetFunction,",
        "ecs:",
        "eks:",
        "sagemaker:",
        "logs:",
        "InvokeFunction",
        "GetPolicyVersion",
        "iam:GetPolicy,",
    ):
        assert forbidden not in template
    assert "sts:ExternalId" in template


def test_api_and_product_mcp_create_share_typed_selected_plan_and_guards():
    repo = ConnectionRepositoryStub()
    with TestClient(create_app(repository=repo, migrate_on_start=False)) as client:
        response = client.post("/v1/connections", json=payload())
        assert response.status_code == 201
        created = response.json()
        assert created["configuration"]["selected_resource"] == payload()["selected_resource"]
        assert len(created["coverage_plan"]) == 2
        assert all(
            item["coverage_mode"] == "selected-resource" for item in created["coverage_plan"]
        )
        assert "DescribeRegions" not in str(created["coverage_plan"])
        invalid = {**payload(), "regions": ["us-west-2"]}
        assert client.post("/v1/connections", json=invalid).status_code == 422
        assert len(repo.rows) == 1
    gateway = Repository()
    with TestClient(app(gateway)) as client:
        body = {**GUARD, "action": "create", "connection": payload()}
        denied = client.post(PATH, headers=HEADERS, json={**body, "confirmed": False})
        assert denied.status_code == 422
        assert gateway.created == 0
        response = client.post(PATH, headers=HEADERS, json=body)
        assert response.status_code == 201
        row = next(iter(gateway.rows.values()))
        assert row["configuration"]["selected_resource"] == payload()["selected_resource"]
        assert next(iter(gateway.rows))[0] == "tenant-alpha"
        assert PRIVATE not in response.text


def test_validation_exact_reads_only_and_truthful_partial_account_coverage():
    session = Session()
    result = validator(session).validate(target())
    assert result["credential_state"] == "passed"
    assert result["health_state"] == "partial"
    assert [item["state"] for item in result["results"]] == ["passed", "passed"]
    assert "Account-wide inventory" in result["summary"]
    assert PRIVATE not in str(result)
    assert {call[1] for call in session.calls if call[0] == "client"} == {"sts", "lambda", "iam"}


@pytest.mark.parametrize(
    "change",
    [
        {"Account": "999999999999"},
        {"Arn": f"arn:aws-cn:sts::{ACCOUNT}:assumed-role/ExactLambdaReader/session"},
        {"Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/other/session"},
        {"Arn": None},
    ],
)
def test_sts_drift_denies_before_selected_provider_reads(change):
    session = Session()
    session.identity.update(change)
    result = validator(session).validate(target())
    assert result["credential_state"] == "failed"
    assert result["health_state"] == "unhealthy"
    assert session.calls == [("client", "sts", None)]


@pytest.mark.parametrize(
    "change",
    [
        {"FunctionArn": FUNCTION.replace("us-east-1", "us-west-2")},
        {"FunctionName": "other"},
        {"Role": ROLE.replace("approved-execution", "other")},
        {"PackageType": "Image"},
        {"Environment": None},
        {"Environment": {"Variables": {"BEDROCK_MODEL_ID": "other"}}},
        {"Environment": {"Variables": {"BEDROCK_MODEL_ID": MODEL, "OTHER_MODEL_ID": "other"}}},
        {"Environment": {"Variables": {"BEDROCK_MODEL_ID": MODEL}, "Error": {"Message": PRIVATE}}},
    ],
)
def test_metadata_drift_persists_no_assets_findings_and_skips_iam(change):
    session = Session()
    session.config.update(change)
    sink = Sink(target())
    result = collector(session).collect(
        tenant_id="tenant-alpha",
        connection=target(),
        repository=sink,
    )
    assert result["state"] == "failed"
    assert not sink.inventory[0].assets
    assert not sink.findings[0].findings
    assert sink.findings[0].coverage[0].state is CoverageState.UNKNOWN
    assert "iam" not in {call[1] for call in session.calls if call[0] == "client"}
    assert PRIVATE not in str(result) + str(sink.inventory) + str(sink.findings)


@pytest.mark.parametrize(
    "tenant,change",
    [
        ("tenant-beta", {}),
        ("tenant-alpha", {"lifecycle_state": "disabled"}),
        (
            "tenant-alpha",
            {"credential_reference": {"role_arn": READER, "external_id": "different"}},
        ),
    ],
)
def test_collector_reloads_server_tenant_before_any_provider_call(tenant, change):
    session = Session()
    stored = target()
    stored.update(change)
    sink = Sink(stored)
    with pytest.raises(ValueError):
        collector(session).collect(tenant_id=tenant, connection=target(), repository=sink)
    assert session.calls == []


def test_collection_reuses_real_observed_assertions_relationships_and_iam_evaluator():
    session = Session()
    sink = Sink(target())
    result = collector(session).collect(
        tenant_id="tenant-alpha",
        connection=target(),
        repository=sink,
    )
    assert result["state"] == "partial" and result["resource_coverage_state"] == "complete"
    assert result["account_coverage"] == "not_assessed" and result["partial_count"] == 1
    assert result["regions"][0]["state"] == "partial"
    batch = sink.inventory[0]
    assert batch.scope_key == FUNCTION
    assert {item.asset.kind for item in batch.assets} == {
        AssetKind.CLOUD_RESOURCE,
        AssetKind.AI_WORKLOAD,
        AssetKind.IDENTITY,
        AssetKind.AI_MODEL,
    }
    assert {item.kind for item in batch.relationships} == {
        RelationshipKind.HOSTED_ON,
        RelationshipKind.RUNS_AS,
        RelationshipKind.USES,
    }
    finding = sink.findings[0]
    assert finding.scope_key == ROLE and len(finding.findings) == 1
    assert finding.findings[0].rule_uid == "DENALI-AWS-AI-IAM-001"
    assert finding.findings[0].evidence.payload["configured_model_ids"] == [MODEL]
    assert PRIVATE not in str(batch) + str(finding) + str(result)
    assert sink.lookups == [("tenant-alpha", target()["id"])]


@pytest.mark.parametrize(
    "response",
    [
        {"PolicyNames": []},
        {"PolicyNames": [], "IsTruncated": 0},
        {"PolicyNames": [], "IsTruncated": "false"},
        {"PolicyNames": [], "IsTruncated": True},
        {"PolicyNames": [], "IsTruncated": True, "Marker": ""},
        {"PolicyNames": [], "IsTruncated": False, "Marker": "unexpected"},
        {"PolicyNames": [None], "IsTruncated": False},
        {"PolicyNames": ["same", "same"], "IsTruncated": False},
    ],
)
def test_inline_policy_pagination_incomplete_is_never_clean(response):
    session = Session()
    session.inline = response
    result = validator(session).validate(target())
    assert result["results"][1]["state"] == "failed"
    sink = Sink(target())
    result = collector(session).collect(
        tenant_id="tenant-alpha",
        connection=target(),
        repository=sink,
    )
    assert result["resource_coverage_state"] == "partial"
    assert not sink.findings[0].findings


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"AttachedPolicies": []},
        {"AttachedPolicies": [], "IsTruncated": True},
        {"AttachedPolicies": [], "IsTruncated": 0},
        {"AttachedPolicies": [], "IsTruncated": False, "Marker": "unexpected"},
        {
            "AttachedPolicies": [{"PolicyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}],
            "IsTruncated": False,
        },
    ],
)
def test_attached_policy_incomplete_or_nonempty_is_partial_without_expansion(response):
    session = Session()
    session.attached = response
    sink = Sink(target())
    result = collector(session).collect(
        tenant_id="tenant-alpha",
        connection=target(),
        repository=sink,
    )
    assert result["resource_coverage_state"] == "partial"
    assert not sink.findings[0].findings


@pytest.mark.parametrize(
    "change",
    [
        {"RoleName": "other"},
        {"PolicyName": "other"},
        {"PolicyDocument": None},
        {"PolicyDocument": {}},
        {"PolicyDocument": {"Statement": []}},
        {"PolicyDocument": {"Statement": [None]}},
        {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Resource": "*"}]}},
        {"PolicyDocument": {"Statement": [{"Effect": "Allow", "Action": "bedrock:*"}]}},
        {
            "PolicyDocument": {
                "Statement": [{"Effect": "Allow", "NotAction": "logs:*", "Resource": "*"}]
            }
        },
    ],
)
def test_inline_document_missing_malformed_or_unsupported_is_partial(change):
    session = Session()
    session.policy.update(change)
    sink = Sink(target())
    result = collector(session).collect(
        tenant_id="tenant-alpha",
        connection=target(),
        repository=sink,
    )
    assert result["resource_coverage_state"] == "partial"
    assert not sink.findings[0].findings


def test_exact_model_policy_is_no_finding_but_not_account_wide_safe():
    session = Session(wildcard=False)
    sink = Sink(target())
    result = collector(session).collect(
        tenant_id="tenant-alpha",
        connection=target(),
        repository=sink,
    )
    assert result["state"] == "partial" and result["resource_coverage_state"] == "complete"
    assert not sink.findings[0].findings


def test_reader_does_not_expand_policy_or_role_targets_and_sanitizes_sdk_failures():
    session = Session()
    selection = parse_selection(payload()["selected_resource"])
    reader = SelectedRoleIamReader(session.client("iam", region_name="us-east-1"), selection)
    with pytest.raises(ValueError):
        reader.list_role_policies(RoleName="other")
    with pytest.raises(ValueError):
        reader.get_role_policy(RoleName=selection.role_name, PolicyName="not-observed")
    assert not hasattr(reader, "get_policy") and not hasattr(reader, "get_policy_version")
    reader.client = SimpleNamespace(
        list_role_policies=lambda **_: (_ for _ in ()).throw(RuntimeError(PRIVATE))
    )
    with pytest.raises(AwsStackDiscoveryError) as error:
        _overbroad_bedrock_permissions(reader, selection.role_name)
    assert PRIVATE not in str(error.value)


def test_read_lambda_filters_nonmodel_environment_and_arbitrary_tag_values():
    session = Session()
    data = read_lambda(
        session.client("lambda", region_name="us-east-1"),
        parse_selection(payload()["selected_resource"]),
    )
    assert data["models"] == {"BEDROCK_MODEL_ID": MODEL}
    assert PRIVATE not in str(data)


def test_public_setup_projection_is_bounded_and_never_echoes_opaque_selection_fields():
    row = target()
    row["configuration"]["selected_resource"]["private_token"] = PRIVATE
    row["configuration"]["private_environment"] = PRIVATE
    projection = setup_summary(row)
    assert projection["setup"]["selected_resource"] == payload()["selected_resource"]
    assert PRIVATE not in str(projection)
    row["configuration"]["selected_resource"]["function_arn"] = "https://example.com/" + PRIVATE
    assert "selected_resource" not in setup_summary(row)["setup"]


def test_reader_name_cannot_reuse_execution_role_with_a_different_path():
    body = payload()
    body["role_name"] = "approved-execution"
    with pytest.raises(ValidationError):
        AwsConnectionCreate.model_validate(body)


def test_duplicate_model_keys_do_not_duplicate_observed_model_assets():
    session = Session()
    session.config["Environment"]["Variables"]["SECOND_BEDROCK_MODEL_ID"] = MODEL
    sink = Sink(target())
    collector(session).collect(tenant_id="tenant-alpha", connection=target(), repository=sink)
    assert sum(item.asset.kind is AssetKind.AI_MODEL for item in sink.inventory[0].assets) == 1


def test_repeated_iam_marker_fails_closed_before_another_page_or_policy_read():
    client = SimpleNamespace(
        list_role_policies=lambda **_: {
            "PolicyNames": [],
            "IsTruncated": True,
            "Marker": "repeat",
        }
    )
    reader = SelectedRoleIamReader(client, parse_selection(payload()["selected_resource"]))
    reader.list_role_policies(RoleName="approved-execution")
    with pytest.raises(AwsStackDiscoveryError):
        reader.list_role_policies(RoleName="approved-execution", Marker="repeat")


@pytest.mark.parametrize("proof_state", ["passed", "unknown", "failed"])
def test_durable_validation_wait_accepts_only_complete_selected_proof_without_auto_collection(
    proof_state,
    monkeypatch,
):
    import denali.api.validation as runner

    stored = target()
    proof = validator(Session()).validate(stored)
    proof["results"][1]["state"] = proof_state
    assert selected_validation_passed(stored, proof) is (proof_state == "passed")

    class SelectedRepository(JobRepository):
        def claim_connection_validation_job(self, job_id, *, lease_seconds):
            job = super().claim_connection_validation_job(job_id, lease_seconds=lease_seconds)
            return {**job, "wait_for_healthy": True}

        def get_connection_validation_target(self, tenant_id, connection_id):
            return stored

    attempts = []
    observer = SimpleNamespace(validate=lambda _: attempts.append(1) or deepcopy(proof))
    clock = iter(range(100))
    monkeypatch.setattr(runner, "monotonic", lambda: next(clock))
    monkeypatch.setattr(runner, "sleep", lambda _: None)
    repo = SelectedRepository()
    callbacks = []
    run_durable_validation_job(
        repo,
        {"aws": observer},
        "job",
        timeout_seconds=3,
        retry_seconds=0,
        on_healthy=lambda *values: callbacks.append(values),
    )
    assert len(attempts) == (1 if proof_state == "passed" else 2)
    assert repo.completed and repo.validation["health_state"] == "partial"
    assert callbacks == []


def test_generic_partial_or_incomplete_plane_set_cannot_finish_exact_onboarding():
    selected = target()
    proof = validator(Session()).validate(selected)
    legacy = deepcopy(selected)
    legacy["configuration"].pop("selected_resource")
    legacy["configuration"]["coverage_mode"] = "selected"
    assert not selected_validation_passed(legacy, proof)
    for results in (proof["results"][:1], [proof["results"][0]] * 2, [], None):
        assert not selected_validation_passed(selected, {**proof, "results": results})


@pytest.mark.parametrize("stage", ["assume", "identity"])
def test_selected_sts_sdk_exception_chain_is_not_visible_to_generic_worker_logger(stage):
    import traceback

    session = Session()
    ordinary_factory = session_factory(session)

    def unavailable(**kwargs):
        raise RuntimeError(PRIVATE)

    def factory(**kwargs):
        if stage == "assume" and not kwargs:
            return SimpleNamespace(client=lambda _: SimpleNamespace(assume_role=unavailable))
        if stage == "identity" and kwargs:
            return SimpleNamespace(
                client=lambda _: SimpleNamespace(get_caller_identity=unavailable)
            )
        return ordinary_factory(**kwargs)

    reader = AwsConnectionDeploymentCollector(session_factory=factory)
    with pytest.raises(ValueError) as error:
        reader.collect(tenant_id="tenant-alpha", connection=target(), repository=Sink(target()))
    assert error.value.__suppress_context__
    assert PRIVATE not in "".join(traceback.format_exception(error.value))
