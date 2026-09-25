from __future__ import annotations

import pytest

from denali.integrations.shared_aws_session import leased_aws_session
from denali.integrations.shared_connections_client import SharedConnectionsError

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


def test_shared_aws_session_fails_closed_when_platform_revokes_access():
    class RevokedBridge:
        def request(self, *_args, **_kwargs):
            raise SharedConnectionsError(409)

    def unexpected_session(**_kwargs):
        raise AssertionError("revoked access must not create an AWS session")

    with pytest.raises(SharedConnectionsError) as error:
        leased_aws_session(
            _connection(),
            region="us-east-1",
            scopes=["aws.bedrock_agents"],
            session_factory=unexpected_session,
            client=RevokedBridge(),  # type: ignore[arg-type]
        )
    assert error.value.status_code == 409
