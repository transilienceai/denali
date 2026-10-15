"""Resolve an AWS session from a server-bound shared connection lease."""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from typing import Any
from uuid import UUID

from denali.connections.aws import AWS_SCOPES
from denali.connections.aws_selected_resource import connection_selection, verify_identity
from denali.integrations.shared_connections_client import SharedConnectionsClient

_SERVICE_SCOPES = {
    "bedrock-agent": {"aws.bedrock_agents"},
    "bedrock": {"aws.bedrock_agents", "aws.bedrock_logging"},
    "bedrock-agentcore-control": {"aws.agentcore"},
    "logs": {"aws.agent_runtime_activity"},
    "cloudtrail": {"aws.bedrock_activity"},
    **{
        service: {"aws.code_to_cloud"}
        for service in ("lambda", "ecs", "ecr", "eks", "sagemaker", "iam")
    },
}


def shared_aws_selected_resource_enabled() -> bool:
    return (
        os.environ.get("DENALI_PLATFORM_AWS_SELECTED_RESOURCE_ENABLED", "false").lower() == "true"
    )


def _region_allowed(connection: dict[str, Any], region: str) -> bool:
    configuration = connection.get("configuration") or {}
    partition = configuration.get("partition", "aws")
    if partition not in {"aws", "aws-us-gov", "aws-cn"}:
        return False
    if not isinstance(region, str) or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]+", region):
        return False
    if (partition == "aws-cn") != region.startswith("cn-") or (
        partition == "aws-us-gov"
    ) != region.startswith("us-gov-"):
        return False
    regions = configuration.get("regions") or []
    mode = configuration.get("coverage_mode")
    if mode == "selected-resource":
        if not shared_aws_selected_resource_enabled():
            return False
        selection = connection_selection(connection)
        return selection is not None and region == selection.region
    return (mode == "automatic" and regions == []) or (
        mode == "selected" and 1 <= len(regions) <= 40 and region in regions
    )


def leased_aws_session(
    connection: dict[str, Any],
    *,
    region: str,
    scopes: list[str],
    session_factory: Callable[..., Any],
    client: SharedConnectionsClient | None = None,
) -> Any:
    """Lease only declared scopes; never persist or return credentials to an API caller."""

    if connection.get("credential_type") != "platform_shared_aws":
        raise ValueError("connection is not a shared AWS connection")
    reference = connection.get("credential_reference") or {}
    try:
        platform_id = UUID(str(reference["platform_connection_id"]))
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("shared AWS connection reference is invalid") from error
    if str(platform_id) != str(connection.get("id")):
        raise ValueError("shared AWS connection identity is inconsistent")
    clerk_org_id = connection.get("clerk_organization_id")
    if not isinstance(clerk_org_id, str) or not re.fullmatch(r"org_[A-Za-z0-9]+", clerk_org_id):
        raise ValueError("shared AWS organization boundary is missing")
    declared = set(connection.get("declared_scopes") or [])
    if (
        not scopes
        or not set(scopes) <= declared
        or not set(scopes) <= set(AWS_SCOPES)
        or len(scopes) != len(set(scopes))
    ):
        raise ValueError("shared AWS scope boundary is invalid")
    if not _region_allowed(connection, region):
        raise ValueError("shared AWS Region is outside its declared coverage")
    bridge = client or SharedConnectionsClient.from_environment()
    if bridge is None:
        raise ValueError("shared connections are not configured")
    selection = connection_selection(connection)
    payload = {"scopes": scopes, "region": region}
    if selection is not None:
        payload["selected_resource"] = connection["configuration"]["selected_resource"]
    leased = bridge.request(
        "POST",
        f"/internal/v1/connections/aws/{platform_id}/credentials",
        clerk_org_id=clerk_org_id,
        payload=payload,
    )
    if not isinstance(leased, dict) or any(
        not isinstance(leased.get(key), str) or not leased[key]
        for key in ("access_key_id", "secret_access_key", "session_token")
    ):
        raise ValueError("shared AWS credential lease is invalid")
    if selection is not None and (
        leased.get("selected_resource") != connection["configuration"]["selected_resource"]
        or leased.get("role_arn") != reference.get("role_arn")
    ):
        raise ValueError("shared selected-resource lease binding changed")
    return session_factory(
        aws_access_key_id=leased["access_key_id"],
        aws_secret_access_key=leased["secret_access_key"],
        aws_session_token=leased["session_token"],
    )


class _SharedAwsSession:
    """Keep every client inside the saved Region/service boundary.

    Broker leases are fresh for each client and use only that service's pinned
    scopes. This avoids a combined six-scope STS policy exceeding AWS's limit,
    and never reuses a Region-admitted lease for an out-of-bound client.
    """

    def __init__(
        self,
        connection: dict[str, Any],
        *,
        scopes: list[str],
        session_factory: Callable[..., Any],
        client: SharedConnectionsClient | None,
    ):
        self._connection = connection
        self._scopes = set(scopes)
        self._factory = session_factory
        self._client = client
        account = connection.get("configuration", {}).get("account_id")
        if not isinstance(account, str) or not re.fullmatch(r"[0-9]{12}", account):
            raise ValueError("shared AWS account boundary is invalid")
        if (
            not scopes
            or not self._scopes <= set(connection.get("declared_scopes") or [])
            or not self._scopes <= set(AWS_SCOPES)
        ):
            raise ValueError("shared AWS scope boundary is invalid")
        self._account = account
        self._selection = connection_selection(connection)

    def client(self, service_name: str, *, region_name: str | None = None, **kwargs: Any) -> Any:
        if set(kwargs) - {"config"}:
            raise ValueError("unexpected shared AWS client configuration")
        configuration = self._connection["configuration"]
        region = (
            region_name
            or configuration.get("deployment_region")
            or (configuration.get("regions") or ["us-east-1"])[0]
        )
        if self._selection is not None and service_name not in {"sts", "lambda", "iam"}:
            raise ValueError("AWS service is outside the exact selected-resource boundary")
        if service_name in {"sts", "ec2"}:
            # Every Platform evidence scope explicitly includes DescribeRegions.
            scopes = [sorted(self._scopes)[0]]
        else:
            scopes = sorted(self._scopes & _SERVICE_SCOPES.get(service_name, set()))
        if not scopes:
            raise ValueError("AWS service is outside the declared evidence scopes")
        session = leased_aws_session(
            self._connection,
            region=region,
            scopes=scopes,
            session_factory=self._factory,
            client=self._client,
        )
        identity = session.client("sts", region_name=region)
        observed = identity.get_caller_identity()
        if str(observed.get("Account", "")) != self._account:
            raise ValueError("AWS account did not match the shared connection boundary")
        if self._selection is not None:
            verify_identity(
                observed, self._selection, self._connection["credential_reference"]["role_arn"]
            )
        return session.client(service_name, region_name=region, **kwargs)


def shared_aws_session(
    connection: dict[str, Any],
    *,
    scopes: list[str],
    session_factory: Callable[..., Any],
    client: SharedConnectionsClient | None = None,
) -> Any:
    return _SharedAwsSession(
        connection, scopes=scopes, session_factory=session_factory, client=client
    )
