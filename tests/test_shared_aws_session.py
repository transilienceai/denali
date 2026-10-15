from __future__ import annotations

import pytest

from denali.integrations.shared_aws_session import leased_aws_session, shared_aws_session

PLATFORM_ID = "11111111-1111-4111-8111-111111111111"


def _connection() -> dict:
    return {
        "id": PLATFORM_ID,
        "credential_type": "platform_shared_aws",
        "credential_reference": {"platform_connection_id": PLATFORM_ID},
        "clerk_organization_id": "org_alpha",
        "declared_scopes": ["aws.bedrock_agents"],
        "configuration": {"coverage_mode": "selected", "regions": ["us-east-1"]},
    }


class FakeBridge:
    def __init__(self, response: dict | None = None):
        self.response = response or {
            "access_key_id": "temporary-access",
            "secret_access_key": "temporary-secret",
            "session_token": "temporary-token",
        }
        self.calls: list[tuple] = []

    def request(self, method, path, *, clerk_org_id, payload):
        self.calls.append((method, path, clerk_org_id, payload))
        return self.response


def test_shared_aws_session_uses_server_bound_org_scope_and_region():
    bridge = FakeBridge()
    sessions = []

    def session_factory(**kwargs):
        sessions.append(kwargs)
        return object()

    result = leased_aws_session(
        _connection(),
        region="us-east-1",
        scopes=["aws.bedrock_agents"],
        session_factory=session_factory,
        client=bridge,  # type: ignore[arg-type]
    )
    assert result is not None
    assert bridge.calls == [
        (
            "POST",
            f"/internal/v1/connections/aws/{PLATFORM_ID}/credentials",
            "org_alpha",
            {"scopes": ["aws.bedrock_agents"], "region": "us-east-1"},
        )
    ]
    assert sessions == [
        {
            "aws_access_key_id": "temporary-access",
            "aws_secret_access_key": "temporary-secret",
            "aws_session_token": "temporary-token",
        }
    ]


@pytest.mark.parametrize(
    ("change", "region", "scopes"),
    [
        ({"clerk_organization_id": None}, "us-east-1", ["aws.bedrock_agents"]),
        ({"credential_reference": {}}, "us-east-1", ["aws.bedrock_agents"]),
        ({"id": "22222222-2222-4222-8222-222222222222"}, "us-east-1", ["aws.bedrock_agents"]),
        ({}, "us-west-2", ["aws.bedrock_agents"]),
        ({}, "us-east-1", ["aws.code_to_cloud"]),
        ({}, "us-east-1", ["aws.bedrock_agents", "aws.bedrock_agents"]),
    ],
)
def test_shared_aws_session_fails_closed_before_request(change, region, scopes):
    bridge = FakeBridge()
    connection = {**_connection(), **change}
    with pytest.raises(ValueError):
        leased_aws_session(
            connection,
            region=region,
            scopes=scopes,
            session_factory=lambda **_kwargs: object(),
            client=bridge,  # type: ignore[arg-type]
        )
    assert bridge.calls == []


def test_shared_aws_session_rejects_incomplete_credential_response():
    bridge = FakeBridge({"access_key_id": "temporary-access"})
    with pytest.raises(ValueError, match="lease is invalid"):
        leased_aws_session(
            _connection(),
            region="us-east-1",
            scopes=["aws.bedrock_agents"],
            session_factory=lambda **_kwargs: object(),
            client=bridge,  # type: ignore[arg-type]
        )


def test_multiregion_clients_lease_only_declared_service_scope_and_verify_each_account():
    connection = _connection()
    connection["declared_scopes"] = ["aws.bedrock_agents", "aws.code_to_cloud"]
    connection["configuration"].update(
        account_id="123456789012", deployment_region="us-east-1", regions=["us-east-1", "us-west-2"]
    )
    bridge = FakeBridge()
    clients = []

    class Session:
        def client(self, service, **kwargs):
            clients.append((service, kwargs))
            return self

        def get_caller_identity(self):
            return {"Account": "123456789012"}

    session = shared_aws_session(
        connection,
        scopes=connection["declared_scopes"],
        session_factory=lambda **_keys: Session(),
        client=bridge,
    )
    session.client("lambda", region_name="us-west-2")
    session.client("bedrock-agent", region_name="us-east-1")
    assert [call[3] for call in bridge.calls] == [
        {"scopes": ["aws.code_to_cloud"], "region": "us-west-2"},
        {"scopes": ["aws.bedrock_agents"], "region": "us-east-1"},
    ]
    assert sum(service == "sts" for service, _kwargs in clients) == 2
    for service, kwargs in (
        ("lambda", {"region_name": "eu-west-1"}),
        ("logs", {"region_name": "us-east-1"}),
        ("lambda", {"region_name": "us-east-1", "endpoint_url": "https://unexpected.example"}),
    ):
        with pytest.raises(ValueError):
            session.client(service, **kwargs)
    assert len(bridge.calls) == 2


def test_automatic_discovery_uses_one_narrow_scope_and_broker_revocation_fails_closed():
    connection = _connection()
    connection["configuration"].update(
        coverage_mode="automatic",
        regions=[],
        deployment_region="us-east-1",
        account_id="123456789012",
    )
    bridge = FakeBridge()

    class Session:
        def client(self, *_args, **_kwargs):
            return self

        def get_caller_identity(self):
            return {"Account": "123456789012"}

    session = shared_aws_session(
        connection,
        scopes=["aws.bedrock_agents"],
        session_factory=lambda **_keys: Session(),
        client=bridge,
    )
    session.client("ec2", region_name="us-east-1")
    session.client("bedrock-agent", region_name="ap-south-1")
    assert [call[3]["region"] for call in bridge.calls] == ["us-east-1", "ap-south-1"]
    assert all(call[3]["scopes"] == ["aws.bedrock_agents"] for call in bridge.calls)
    bridge.request = lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("revoked"))
    with pytest.raises(ValueError):
        session.client("bedrock-agent", region_name="ap-south-1")


def test_each_region_lease_account_must_match_the_saved_account():
    connection = _connection()
    connection["configuration"].update(account_id="123456789012")

    class Session:
        def client(self, *_args, **_kwargs):
            return self

        def get_caller_identity(self):
            return {"Account": "999999999999"}

    session = shared_aws_session(
        connection,
        scopes=["aws.bedrock_agents"],
        session_factory=lambda **_keys: Session(),
        client=FakeBridge(),
    )
    with pytest.raises(ValueError, match="account"):
        session.client("bedrock-agent", region_name="us-east-1")
