from __future__ import annotations

from denali.integrations import shared_aws_probe


def test_probe_uses_short_lived_credentials_for_one_bounded_read(monkeypatch):
    seen = {}

    class FakeAgentClient:
        def list_agents(self, **options):
            seen["list_options"] = options
            return {"agentSummaries": [{"agentId": "must-not-return"}]}

    class FakeSession:
        def __init__(self, **credentials):
            seen["credentials"] = credentials

        def client(self, service, **options):
            seen["service"] = service
            seen["client_options"] = options
            return FakeAgentClient()

    monkeypatch.setattr(shared_aws_probe, "_session", FakeSession)
    monkeypatch.setattr(shared_aws_probe, "_client_config", lambda: "bounded-config")
    result = shared_aws_probe.probe_shared_bedrock_agents(
        {
            "access_key_id": "temporary-test-key",
            "secret_access_key": "temporary-test-secret",
            "session_token": "temporary-test-token",
        },
        "us-east-1",
    )
    assert seen["service"] == "bedrock-agent"
    assert seen["client_options"]["region_name"] == "us-east-1"
    assert seen["list_options"] == {"maxResults": 1}
    assert seen["credentials"]["aws_session_token"] == "temporary-test-token"
    assert result == {
        "scope": "aws.bedrock_agents",
        "region": "us-east-1",
        "read_state": "passed",
        "sample_count": 1,
    }
    assert "must-not-return" not in str(result)
