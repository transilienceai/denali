"""One-off Denali dev probe: shared lease -> bounded Bedrock Agents read.

Run only after the pilot customer role is deployed and platform validation is
healthy. The function returns no Clerk token, STS credential, or AWS resource.
"""

from __future__ import annotations

import os
import sys
from urllib.parse import urlsplit
from uuid import UUID

import modal

PILOT_ORG_ID = "org_3Hb8Nbfbvw9OqO52pEEhoMjVuaV"
app = modal.App("denali-shared-aws-probe-dev")
image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("clerk-backend-api>=7,<8", "httpx>=0.28,<1", "boto3>=1.43.9,<2")
    .add_local_file(
        "src/denali/integrations/shared_connections_client.py",
        remote_path="/opt/shared_connections_client.py",
        copy=True,
    )
    .add_local_file(
        "src/denali/integrations/shared_aws_probe.py",
        remote_path="/opt/shared_aws_probe.py",
        copy=True,
    )
)


@app.function(
    image=image,
    secrets=[
        modal.Secret.from_name("denali-dev"),
        modal.Secret.from_dict({
            "DENALI_PLATFORM_CONNECTIONS_ORIGIN":
                "https://transilience-transilience-platform-dev--transilience-pla-73050c.modal.run"
        }),
    ],
    timeout=90,
)
def verify(connection_id: str, region: str) -> dict[str, object]:
    sys.path.insert(0, "/opt")
    from shared_aws_probe import probe_shared_bedrock_agents
    from shared_connections_client import SharedConnectionsClient, SharedConnectionsError

    if os.environ.get("MODAL_ENVIRONMENT") != "denali-dev":
        raise RuntimeError("shared AWS smoke is restricted to Denali development")
    UUID(connection_id)
    origin = os.environ.get("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.hostname.endswith(".modal.run")
        or "transilience-platform-dev" not in parsed.hostname
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("expected the isolated platform dev origin")
    client = SharedConnectionsClient.from_environment()
    if client is None:
        raise RuntimeError("Denali dev machine configuration is incomplete")
    try:
        leased = client.request(
            "POST",
            f"/internal/v1/connections/aws/{connection_id}/credentials",
            clerk_org_id=PILOT_ORG_ID,
            payload={"scopes": ["aws.bedrock_agents"], "region": region},
        )
    except SharedConnectionsError as error:
        return {"lease_status": error.status_code}
    if not isinstance(leased, dict):
        raise RuntimeError("shared AWS lease response was invalid")
    try:
        return probe_shared_bedrock_agents(leased, region)
    except Exception:  # noqa: BLE001 - never return provider details or temporary keys.
        return {"read_state": "failed"}


@app.local_entrypoint()
def main(connection_id: str, region: str = "us-east-1") -> None:
    print(verify.remote(connection_id, region))
