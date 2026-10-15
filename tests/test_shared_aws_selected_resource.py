"""Shared exact Lambda plans never acquire broad account-discovery credentials."""

from copy import deepcopy
from importlib import import_module

import pytest
from test_aws_selected_resource import ACCOUNT, READER, Session, Sink, payload, target
from test_shared_github import Platform, Repository, _client

from denali.connections.aws import AwsConnectionValidator
from denali.connections.aws_selected_resource import selected_validation_passed
from denali.connectors.aws_deployments import AwsConnectionDeploymentCollector
from denali.integrations.shared_aws_session import leased_aws_session

ID = "5e340aec-1157-48d3-9f18-3d6f750aa840"
ADMIN = {"Authorization": "Bearer alpha-admin"}


def shared_target():
    connection = target()
    connection.update(credential_type="platform_shared_aws", clerk_organization_id="org_alpha")
    connection["credential_reference"] = {"platform_connection_id": ID, "role_arn": READER}
    return connection


class Broker(Platform):
    def __init__(self):
        super().__init__()
        self.change = None

    def request(self, method, path, *, clerk_org_id, payload=None, **_kwargs):
        self.calls.append((method, path, clerk_org_id, deepcopy(payload)))
        assert clerk_org_id == "org_alpha"
        plan = {
            "id": ID,
            "provider": "aws",
            "connection_kind": "shared_aws",
            "availability": "ready",
            "validated_scopes": ["aws.code_to_cloud"],
            "external_account_id": ACCOUNT,
            "partition": "aws",
            "coverage_mode": "selected-resource",
            "selected_resource": shared_target()["configuration"]["selected_resource"],
            "role_arn": READER,
            "role_name": "ExactLambdaReader",
        }
        if method == "GET":
            return {"items": [plan]}
        if path.endswith("/credentials"):
            assert payload == {
                "scopes": ["aws.code_to_cloud"],
                "region": "us-east-1",
                "selected_resource": plan["selected_resource"],
            }
            lease = {
                "access_key_id": "test-only",
                "secret_access_key": "test-only",
                "session_token": "test-only",
                "role_arn": READER,
                "selected_resource": plan["selected_resource"],
            }
            return self.change(lease) if self.change else lease
        if path == "/internal/v1/connections/aws":
            assert "role_name" not in payload  # Platform derives its isolated reader role.
            return {"id": ID}
        raise AssertionError(path)


def test_shared_exact_scope_is_dark_by_default_without_a_broad_lease(monkeypatch):
    monkeypatch.delenv("DENALI_PLATFORM_AWS_SELECTED_RESOURCE_ENABLED", raising=False)
    broker = Broker()
    with pytest.raises(ValueError, match="Region"):
        leased_aws_session(
            shared_target(),
            region="us-east-1",
            scopes=["aws.code_to_cloud"],
            session_factory=lambda **_: None,
            client=broker,
        )
    assert broker.calls == []


def test_shared_exact_validation_collection_preserve_native_truthful_coverage(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_AWS_SELECTED_RESOURCE_ENABLED", "true")
    broker, session = Broker(), Session()
    monkeypatch.setattr(
        import_module("denali.integrations.shared_connections_client").SharedConnectionsClient,
        "from_environment",
        lambda: broker,
    )
    connection = shared_target()
    def factory(**keys):
        assert keys, "native identity used"
        return session
    validation = AwsConnectionValidator(session_factory=factory).validate(connection)
    assert validation["health_state"] == "partial"
    assert selected_validation_passed(connection, validation)
    sink = Sink(connection)
    result = AwsConnectionDeploymentCollector(session_factory=factory).collect(
        tenant_id="tenant-alpha", connection=connection, repository=sink
    )
    assert result["state"] == "partial" and sink.inventory
    assert all(call[1] == f"/internal/v1/connections/aws/{ID}/credentials" for call in broker.calls)
    assert all(
        call[3]["selected_resource"] == connection["configuration"]["selected_resource"]
        for call in broker.calls
    )
    assert all(call[1] in {"sts", "lambda", "iam"} for call in session.calls if call[0] == "client")
    assert "never-retain-provider-secrets" not in repr(sink.inventory + sink.findings)


@pytest.mark.parametrize(
    "change",
    [
        lambda lease: {**lease, "role_arn": READER + "Changed"},
        lambda lease: {**lease, "selected_resource": {}},
    ],
)
def test_selected_lease_identity_or_pin_drift_denies_before_provider_reads(monkeypatch, change):
    monkeypatch.setenv("DENALI_PLATFORM_AWS_SELECTED_RESOURCE_ENABLED", "true")
    broker = Broker()
    broker.change = change
    with pytest.raises(ValueError, match="binding changed"):
        leased_aws_session(
            shared_target(),
            region="us-east-1",
            scopes=["aws.code_to_cloud"],
            session_factory=lambda **_: (_ for _ in ()).throw(AssertionError("must not use lease")),
            client=broker,
        )


def test_selected_shared_attachment_is_explicit_immutable_and_does_not_reenable(monkeypatch):
    monkeypatch.setattr(
        import_module("denali.api.app"), "_with_validation_state", lambda _r, _t, row: row
    )
    body = {
        key: payload()[key]
        for key in (
            "coverage_mode",
            "regions",
            "deployment_region",
            "declared_scopes",
            "selected_resource",
        )
    }
    broker, repository = Broker(), Repository()
    path = f"/v1/shared/connections/aws/{ID}/use-in-denali"
    monkeypatch.delenv("DENALI_PLATFORM_AWS_SELECTED_RESOURCE_ENABLED", raising=False)
    with _client(broker, repository) as web:
        assert web.post(path, json=body, headers=ADMIN).status_code == 404
        assert not broker.calls
        monkeypatch.setenv("DENALI_PLATFORM_AWS_SELECTED_RESOURCE_ENABLED", "true")
        assert (
            web.post(path, json=body, headers={"Authorization": "Bearer alpha-member"}).status_code
            == 403
        )
        created = web.post(path, json=body, headers=ADMIN)
        assert created.status_code == 201, created.text
        assert len(repository.created[0]["coverage_plan"]) == 2
        assert web.post(path, json=body, headers=ADMIN).status_code == 201
        changed = {
            **body,
            "selected_resource": {
                **body["selected_resource"],
                "expected_model_id": "amazon.titan-text-express-v1",
            },
        }
        assert web.post(path, json=changed, headers=ADMIN).status_code == 409
        assert (
            web.post(
                path,
                json={"region": "us-east-1", "declared_scopes": ["aws.code_to_cloud"]},
                headers=ADMIN,
            ).status_code
            == 409
        )
        repository.created[0]["lifecycle_state"] = "disabled"
        assert web.post(path, json=body, headers=ADMIN).status_code == 409
        setup = {**body, "account_id": ACCOUNT, "partition": "aws"}
        assert web.post("/v1/shared/connections/aws", json=setup, headers=ADMIN).status_code == 201
