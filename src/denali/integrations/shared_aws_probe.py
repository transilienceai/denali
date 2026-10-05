"""Bounded Denali read that proves a shared AWS credential lease is usable."""

from __future__ import annotations

from typing import Any


def _session(**kwargs: Any) -> Any:
    import boto3

    return boto3.Session(**kwargs)


def _client_config() -> Any:
    from botocore.config import Config

    return Config(connect_timeout=3, read_timeout=10, retries={"total_max_attempts": 2})


def probe_shared_bedrock_agents(credentials: dict[str, Any], region: str) -> dict[str, Any]:
    """Read one result without returning AWS resource data or temporary credentials."""

    session = _session(
        aws_access_key_id=credentials["access_key_id"],
        aws_secret_access_key=credentials["secret_access_key"],
        aws_session_token=credentials["session_token"],
    )
    response = session.client(
        "bedrock-agent", region_name=region, config=_client_config()
    ).list_agents(maxResults=1)
    return {
        "scope": "aws.bedrock_agents",
        "region": region,
        "read_state": "passed",
        "sample_count": min(len(response.get("agentSummaries", [])), 1),
    }
