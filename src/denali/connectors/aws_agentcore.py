"""Privacy-preserving, read-only Amazon Bedrock AgentCore inventory.

Every API family has its own coverage boundary. Summary objects survive detail failures,
while only complete coverage can authorize reconciliation withdrawals.
"""

from __future__ import annotations

import argparse
import os
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from denali.domain import (
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    Evidence,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.aws_agentcore"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True)

RUNTIME_INVENTORY_PLANE = "aws_agentcore_runtime_inventory"
ENDPOINT_INVENTORY_PLANE = "aws_agentcore_endpoint_inventory"
RUNTIME_RELATIONSHIP_PLANE = "aws_agentcore_runtime_relationships"
GATEWAY_INVENTORY_PLANE = "aws_agentcore_gateway_inventory"
TARGET_INVENTORY_PLANE = "aws_agentcore_gateway_target_inventory"
GATEWAY_RELATIONSHIP_PLANE = "aws_agentcore_gateway_relationships"
IDENTITY_INVENTORY_PLANE = "aws_agentcore_workload_identity_inventory"
MEMORY_INVENTORY_PLANE = "aws_agentcore_memory_inventory"
MEMORY_RELATIONSHIP_PLANE = "aws_agentcore_memory_relationships"

MAX_PAGES = 1_000
_ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
_REGION_RE = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")


class AwsAgentCoreDiscoveryError(RuntimeError):
    """A safe discovery failure containing no SDK response or credential text."""


class AwsAgentCoreRegionConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        *,
        account_id: str,
        region: str,
        client: Any,
        partition: str = "aws",
    ) -> None:
        if not _ACCOUNT_RE.fullmatch(account_id):
            raise ValueError("AWS account_id must be 12 digits")
        if not _REGION_RE.fullmatch(region):
            raise ValueError("AWS region has an invalid shape")
        if not partition or ":" in partition:
            raise ValueError("AWS partition has an invalid shape")
        self.account_id = account_id
        self.region = region
        self.partition = partition
        self.client = client

    def collect(
        self,
        *,
        connection_id: str | None = None,
        include_memories: bool = True,
    ) -> InventoryBatch:
        observed_at = datetime.now(UTC)
        connection = connection_id or f"aws:{self.account_id}"
        scope = f"account={self.account_id},region={self.region}"
        assets: dict[AssetRef, AssetAssertion] = {}
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion] = {}

        warnings: dict[str, list[str]] = {
            plane: []
            for plane in (
                RUNTIME_INVENTORY_PLANE,
                ENDPOINT_INVENTORY_PLANE,
                RUNTIME_RELATIONSHIP_PLANE,
                GATEWAY_INVENTORY_PLANE,
                TARGET_INVENTORY_PLANE,
                GATEWAY_RELATIONSHIP_PLANE,
                IDENTITY_INVENTORY_PLANE,
                MEMORY_INVENTORY_PLANE,
                MEMORY_RELATIONSHIP_PLANE,
            )
        }
        succeeded = {plane: False for plane in warnings}

        self._collect_workload_identities(
            observed_at, assets, warnings[IDENTITY_INVENTORY_PLANE], succeeded
        )
        self._collect_runtimes(observed_at, assets, relationships, warnings, succeeded)
        self._collect_gateways(observed_at, assets, relationships, warnings, succeeded)
        if include_memories:
            self._collect_memories(observed_at, assets, relationships, warnings, succeeded)

        coverage = tuple(
            Coverage(
                plane=plane,
                state=(
                    CoverageState.NOT_SUPPORTED
                    if not include_memories
                    and plane in {MEMORY_INVENTORY_PLANE, MEMORY_RELATIONSHIP_PLANE}
                    else _coverage_state(succeeded[plane], warnings[plane])
                ),
                scope=scope,
                detail=(
                    "AWS does not document AgentCore Memory as available in this Region."
                    if not include_memories
                    and plane in {MEMORY_INVENTORY_PLANE, MEMORY_RELATIONSHIP_PLANE}
                    else _coverage_detail(warnings[plane])
                ),
            )
            for plane in warnings
        )
        return InventoryBatch(
            connector_id=CONNECTOR_ID,
            connection_id=connection,
            run_id=f"aws-agentcore-{self.region}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=coverage,
            assets=tuple(assets.values()),
            relationships=tuple(relationships.values()),
        )

    def _collect_workload_identities(
        self,
        observed_at: datetime,
        assets: dict[AssetRef, AssetAssertion],
        warnings: list[str],
        succeeded: dict[str, bool],
    ) -> None:
        try:
            items = _paginate(self.client, "list_workload_identities", "workloadIdentities")
            succeeded[IDENTITY_INVENTORY_PLANE] = True
        except AwsAgentCoreDiscoveryError as error:
            warnings.append(str(error))
            return

        for position, raw in enumerate(items):
            if not isinstance(raw, dict):
                warnings.append(f"list_workload_identities item {position}: expected object")
                continue
            name = _string(raw.get("name"))
            arn = _string(raw.get("workloadIdentityArn"))
            if not name or not arn or not self._valid_agentcore_arn(arn):
                warnings.append(
                    f"list_workload_identities item {position}: missing or inconsistent identity"
                )
                continue
            ref = AssetRef(AssetKind.IDENTITY, arn)
            self._add_asset(
                assets,
                ref,
                display_name=name,
                plane=IDENTITY_INVENTORY_PLANE,
                evidence=self._evidence(
                    observed_at,
                    operation="ListWorkloadIdentities",
                    resource_id=name,
                ),
                attributes={
                    "provider": "aws",
                    "service": "bedrock-agentcore",
                    "account_id": self.account_id,
                    "region": self.region,
                    "principal_type": "agentcore_workload_identity",
                    "name": name,
                },
            )

    def _collect_runtimes(
        self,
        observed_at: datetime,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        warnings: dict[str, list[str]],
        succeeded: dict[str, bool],
    ) -> None:
        try:
            items = _paginate(self.client, "list_agent_runtimes", "agentRuntimes")
            succeeded[RUNTIME_INVENTORY_PLANE] = True
            succeeded[ENDPOINT_INVENTORY_PLANE] = True
            succeeded[RUNTIME_RELATIONSHIP_PLANE] = True
        except AwsAgentCoreDiscoveryError as error:
            for plane in (
                RUNTIME_INVENTORY_PLANE,
                ENDPOINT_INVENTORY_PLANE,
                RUNTIME_RELATIONSHIP_PLANE,
            ):
                warnings[plane].append(str(error))
            return

        for position, raw in enumerate(items):
            if not isinstance(raw, dict):
                message = f"list_agent_runtimes item {position}: expected object"
                warnings[RUNTIME_INVENTORY_PLANE].append(message)
                warnings[ENDPOINT_INVENTORY_PLANE].append(message)
                warnings[RUNTIME_RELATIONSHIP_PLANE].append(message)
                continue
            runtime_id = _string(raw.get("agentRuntimeId"))
            runtime_arn = _string(raw.get("agentRuntimeArn"))
            version = _string(raw.get("agentRuntimeVersion"))
            name = _string(raw.get("agentRuntimeName"))
            if (
                not runtime_id
                or not runtime_arn
                or not version
                or not name
                or not self._valid_agentcore_arn(
                    runtime_arn, resource_type="runtime", resource_id=runtime_id
                )
            ):
                message = f"list_agent_runtimes item {position}: missing or inconsistent identity"
                warnings[RUNTIME_INVENTORY_PLANE].append(message)
                warnings[ENDPOINT_INVENTORY_PLANE].append(message)
                warnings[RUNTIME_RELATIONSHIP_PLANE].append(message)
                continue

            runtime_ref = AssetRef(AssetKind.AI_AGENT, runtime_arn)
            evidence = self._evidence(
                observed_at, operation="ListAgentRuntimes", resource_id=runtime_id
            )
            attributes: dict[str, Any] = {
                "provider": "aws",
                "service": "bedrock-agentcore",
                "native_type": "agentcore_runtime",
                "account_id": self.account_id,
                "region": self.region,
                "runtime_id": runtime_id,
                "version": version,
                "status": _string(raw.get("status")) or "UNKNOWN",
                "description": (_string(raw.get("description")) or "")[:500],
                "configuration_observed": False,
            }
            detail: dict[str, Any] | None = None
            try:
                response = self.client.get_agent_runtime(
                    agentRuntimeId=runtime_id,
                    agentRuntimeVersion=version,
                )
                if not isinstance(response, dict):
                    raise AwsAgentCoreDiscoveryError("GetAgentRuntime: invalid response shape")
                if (
                    _string(response.get("agentRuntimeId")) != runtime_id
                    or _string(response.get("agentRuntimeArn")) != runtime_arn
                    or _string(response.get("agentRuntimeVersion")) != version
                ):
                    raise AwsAgentCoreDiscoveryError(
                        "GetAgentRuntime: identity did not match ListAgentRuntimes"
                    )
                detail = response
                attributes.update(_runtime_attributes(response))
                attributes["configuration_observed"] = True
                evidence = self._evidence(
                    observed_at, operation="GetAgentRuntime", resource_id=runtime_id
                )
            except Exception as error:
                message = _safe_failure("GetAgentRuntime", error, runtime_id)
                warnings[RUNTIME_INVENTORY_PLANE].append(message)
                warnings[RUNTIME_RELATIONSHIP_PLANE].append(message)

            self._add_asset(
                assets,
                runtime_ref,
                display_name=name,
                plane=RUNTIME_INVENTORY_PLANE,
                evidence=evidence,
                attributes=attributes,
            )
            if detail is not None:
                self._add_principal_relationships(
                    source=runtime_ref,
                    role_arn=_string(detail.get("roleArn")),
                    workload_identity_arn=_nested_string(
                        detail, "workloadIdentityDetails", "workloadIdentityArn"
                    ),
                    plane=RUNTIME_RELATIONSHIP_PLANE,
                    asset_plane=RUNTIME_INVENTORY_PLANE,
                    evidence=evidence,
                    assets=assets,
                    relationships=relationships,
                    warnings=warnings[RUNTIME_RELATIONSHIP_PLANE],
                    agent_ref=runtime_ref,
                )

            self._collect_runtime_endpoints(
                runtime_id,
                runtime_ref,
                observed_at,
                assets,
                relationships,
                warnings,
            )

    def _collect_runtime_endpoints(
        self,
        runtime_id: str,
        runtime_ref: AssetRef,
        observed_at: datetime,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        warnings: dict[str, list[str]],
    ) -> None:
        try:
            items = _paginate(
                self.client,
                "list_agent_runtime_endpoints",
                "runtimeEndpoints",
                agentRuntimeId=runtime_id,
            )
        except AwsAgentCoreDiscoveryError as error:
            warnings[ENDPOINT_INVENTORY_PLANE].append(str(error))
            warnings[RUNTIME_RELATIONSHIP_PLANE].append(str(error))
            return

        for position, raw in enumerate(items):
            if not isinstance(raw, dict):
                message = f"runtime {runtime_id} endpoint item {position}: expected object"
                warnings[ENDPOINT_INVENTORY_PLANE].append(message)
                warnings[RUNTIME_RELATIONSHIP_PLANE].append(message)
                continue
            arn = _string(raw.get("agentRuntimeEndpointArn"))
            parent_arn = _string(raw.get("agentRuntimeArn"))
            endpoint_id = _string(raw.get("id"))
            name = _string(raw.get("name"))
            if (
                not arn
                or not endpoint_id
                or not name
                or parent_arn != runtime_ref.natural_key
                or not self._valid_agentcore_arn(arn)
            ):
                message = f"runtime {runtime_id} endpoint item {position}: inconsistent identity"
                warnings[ENDPOINT_INVENTORY_PLANE].append(message)
                warnings[RUNTIME_RELATIONSHIP_PLANE].append(message)
                continue
            endpoint_ref = AssetRef(AssetKind.APPLICATION_ENDPOINT, arn)
            evidence = self._evidence(
                observed_at,
                operation="ListAgentRuntimeEndpoints",
                resource_id=endpoint_id,
            )
            self._add_asset(
                assets,
                endpoint_ref,
                display_name=name,
                plane=ENDPOINT_INVENTORY_PLANE,
                evidence=evidence,
                attributes={
                    "provider": "aws",
                    "service": "bedrock-agentcore",
                    "native_type": "agentcore_runtime_endpoint",
                    "account_id": self.account_id,
                    "region": self.region,
                    "endpoint_id": endpoint_id,
                    "status": _string(raw.get("status")) or "UNKNOWN",
                    "live_version": _string(raw.get("liveVersion")),
                    "target_version": _string(raw.get("targetVersion")),
                },
            )
            self._add_relationship(
                relationships,
                runtime_ref,
                endpoint_ref,
                RelationshipKind.EXPOSES,
                plane=RUNTIME_RELATIONSHIP_PLANE,
                evidence=evidence,
                agent_ref=runtime_ref,
            )

    def _collect_gateways(
        self,
        observed_at: datetime,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        warnings: dict[str, list[str]],
        succeeded: dict[str, bool],
    ) -> None:
        try:
            items = _paginate(self.client, "list_gateways", "items")
            succeeded[GATEWAY_INVENTORY_PLANE] = True
            succeeded[TARGET_INVENTORY_PLANE] = True
            succeeded[GATEWAY_RELATIONSHIP_PLANE] = True
        except AwsAgentCoreDiscoveryError as error:
            for plane in (
                GATEWAY_INVENTORY_PLANE,
                TARGET_INVENTORY_PLANE,
                GATEWAY_RELATIONSHIP_PLANE,
            ):
                warnings[plane].append(str(error))
            return

        for position, raw in enumerate(items):
            if not isinstance(raw, dict):
                message = f"list_gateways item {position}: expected object"
                warnings[GATEWAY_INVENTORY_PLANE].append(message)
                warnings[TARGET_INVENTORY_PLANE].append(message)
                warnings[GATEWAY_RELATIONSHIP_PLANE].append(message)
                continue
            gateway_id = _string(raw.get("gatewayId"))
            name = _string(raw.get("name"))
            if not gateway_id or not name:
                message = f"list_gateways item {position}: missing identity"
                warnings[GATEWAY_INVENTORY_PLANE].append(message)
                warnings[TARGET_INVENTORY_PLANE].append(message)
                warnings[GATEWAY_RELATIONSHIP_PLANE].append(message)
                continue
            gateway_arn = (
                f"arn:{self.partition}:bedrock-agentcore:{self.region}:{self.account_id}:"
                f"gateway/{gateway_id}"
            )
            gateway_ref = AssetRef(AssetKind.MCP_SERVER, gateway_arn)
            evidence = self._evidence(observed_at, operation="ListGateways", resource_id=gateway_id)
            attributes: dict[str, Any] = {
                "provider": "aws",
                "service": "bedrock-agentcore",
                "native_type": "agentcore_gateway",
                "account_id": self.account_id,
                "region": self.region,
                "gateway_id": gateway_id,
                "status": _string(raw.get("status")) or "UNKNOWN",
                "protocol": _string(raw.get("protocolType")) or "UNKNOWN",
                "authorizer_type": _string(raw.get("authorizerType")) or "UNKNOWN",
                "description": (_string(raw.get("description")) or "")[:500],
                "configuration_observed": False,
                "arn_source": "constructed_from_list_identity",
            }
            detail: dict[str, Any] | None = None
            try:
                response = self.client.get_gateway(gatewayIdentifier=gateway_id)
                if not isinstance(response, dict):
                    raise AwsAgentCoreDiscoveryError("GetGateway: invalid response shape")
                if (
                    _string(response.get("gatewayId")) != gateway_id
                    or _string(response.get("gatewayArn")) != gateway_arn
                ):
                    raise AwsAgentCoreDiscoveryError(
                        "GetGateway: identity did not match ListGateways"
                    )
                detail = response
                attributes.update(_gateway_attributes(response))
                attributes["configuration_observed"] = True
                attributes["arn_source"] = "get_gateway"
                evidence = self._evidence(
                    observed_at, operation="GetGateway", resource_id=gateway_id
                )
            except Exception as error:
                message = _safe_failure("GetGateway", error, gateway_id)
                warnings[GATEWAY_INVENTORY_PLANE].append(message)
                warnings[GATEWAY_RELATIONSHIP_PLANE].append(message)

            self._add_asset(
                assets,
                gateway_ref,
                display_name=name,
                plane=GATEWAY_INVENTORY_PLANE,
                evidence=evidence,
                attributes=attributes,
            )
            if detail is not None:
                self._add_principal_relationships(
                    source=gateway_ref,
                    role_arn=_string(detail.get("roleArn")),
                    workload_identity_arn=_nested_string(
                        detail, "workloadIdentityDetails", "workloadIdentityArn"
                    ),
                    plane=GATEWAY_RELATIONSHIP_PLANE,
                    asset_plane=GATEWAY_INVENTORY_PLANE,
                    evidence=evidence,
                    assets=assets,
                    relationships=relationships,
                    warnings=warnings[GATEWAY_RELATIONSHIP_PLANE],
                )
            self._collect_gateway_targets(
                gateway_id,
                gateway_ref,
                observed_at,
                assets,
                relationships,
                warnings,
            )

    def _collect_gateway_targets(
        self,
        gateway_id: str,
        gateway_ref: AssetRef,
        observed_at: datetime,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        warnings: dict[str, list[str]],
    ) -> None:
        try:
            items = _paginate(
                self.client,
                "list_gateway_targets",
                "items",
                gatewayIdentifier=gateway_id,
            )
        except AwsAgentCoreDiscoveryError as error:
            warnings[TARGET_INVENTORY_PLANE].append(str(error))
            warnings[GATEWAY_RELATIONSHIP_PLANE].append(str(error))
            return

        for position, raw in enumerate(items):
            if not isinstance(raw, dict):
                message = f"gateway {gateway_id} target item {position}: expected object"
                warnings[TARGET_INVENTORY_PLANE].append(message)
                warnings[GATEWAY_RELATIONSHIP_PLANE].append(message)
                continue
            target_id = _string(raw.get("targetId"))
            name = _string(raw.get("name"))
            if not target_id or not name:
                message = f"gateway {gateway_id} target item {position}: missing identity"
                warnings[TARGET_INVENTORY_PLANE].append(message)
                warnings[GATEWAY_RELATIONSHIP_PLANE].append(message)
                continue
            target_ref = AssetRef(
                AssetKind.AI_TOOL, f"{gateway_ref.natural_key}#target/{target_id}"
            )
            evidence = self._evidence(
                observed_at, operation="ListGatewayTargets", resource_id=target_id
            )
            attributes: dict[str, Any] = {
                "provider": "aws",
                "service": "bedrock-agentcore",
                "native_type": "agentcore_gateway_target",
                "granularity": "gateway_target",
                "account_id": self.account_id,
                "region": self.region,
                "gateway_id": gateway_id,
                "target_id": target_id,
                "status": _string(raw.get("status")) or "UNKNOWN",
                "description": (_string(raw.get("description")) or "")[:500],
                "configuration_observed": False,
            }
            try:
                detail = self.client.get_gateway_target(
                    gatewayIdentifier=gateway_id, targetId=target_id
                )
                if not isinstance(detail, dict):
                    raise AwsAgentCoreDiscoveryError("GetGatewayTarget: invalid response shape")
                if (
                    _string(detail.get("targetId")) != target_id
                    or _string(detail.get("gatewayArn")) != gateway_ref.natural_key
                ):
                    raise AwsAgentCoreDiscoveryError(
                        "GetGatewayTarget: identity did not match ListGatewayTargets"
                    )
                attributes.update(_target_attributes(detail))
                attributes["configuration_observed"] = True
                evidence = self._evidence(
                    observed_at, operation="GetGatewayTarget", resource_id=target_id
                )
            except Exception as error:
                message = _safe_failure("GetGatewayTarget", error, target_id)
                warnings[TARGET_INVENTORY_PLANE].append(message)
                warnings[GATEWAY_RELATIONSHIP_PLANE].append(message)

            self._add_asset(
                assets,
                target_ref,
                display_name=name,
                plane=TARGET_INVENTORY_PLANE,
                evidence=evidence,
                attributes=attributes,
            )
            self._add_relationship(
                relationships,
                gateway_ref,
                target_ref,
                RelationshipKind.EXPOSES,
                plane=GATEWAY_RELATIONSHIP_PLANE,
                evidence=evidence,
            )

    def _collect_memories(
        self,
        observed_at: datetime,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        warnings: dict[str, list[str]],
        succeeded: dict[str, bool],
    ) -> None:
        try:
            items = _paginate(self.client, "list_memories", "memories")
            succeeded[MEMORY_INVENTORY_PLANE] = True
            succeeded[MEMORY_RELATIONSHIP_PLANE] = True
        except AwsAgentCoreDiscoveryError as error:
            warnings[MEMORY_INVENTORY_PLANE].append(str(error))
            warnings[MEMORY_RELATIONSHIP_PLANE].append(str(error))
            return

        for position, raw in enumerate(items):
            if not isinstance(raw, dict):
                message = f"list_memories item {position}: expected object"
                warnings[MEMORY_INVENTORY_PLANE].append(message)
                warnings[MEMORY_RELATIONSHIP_PLANE].append(message)
                continue
            memory_id = _string(raw.get("id"))
            memory_arn = _string(raw.get("arn"))
            if (
                not memory_id
                or not memory_arn
                or not self._valid_agentcore_arn(memory_arn, resource_id=memory_id)
            ):
                message = f"list_memories item {position}: missing or inconsistent identity"
                warnings[MEMORY_INVENTORY_PLANE].append(message)
                warnings[MEMORY_RELATIONSHIP_PLANE].append(message)
                continue
            memory_ref = AssetRef(AssetKind.AI_DATASTORE, memory_arn)
            display_name = memory_id
            evidence = self._evidence(observed_at, operation="ListMemories", resource_id=memory_id)
            attributes: dict[str, Any] = {
                "provider": "aws",
                "service": "bedrock-agentcore",
                "native_type": "agentcore_memory",
                "account_id": self.account_id,
                "region": self.region,
                "memory_id": memory_id,
                "status": _string(raw.get("status")) or "UNKNOWN",
                "configuration_observed": False,
            }
            detail: dict[str, Any] | None = None
            try:
                response = self.client.get_memory(memoryId=memory_id, view="without_decryption")
                candidate = response.get("memory") if isinstance(response, dict) else None
                if not isinstance(candidate, dict):
                    raise AwsAgentCoreDiscoveryError("GetMemory: invalid response shape")
                if (
                    _string(candidate.get("id")) != memory_id
                    or _string(candidate.get("arn")) != memory_arn
                ):
                    raise AwsAgentCoreDiscoveryError(
                        "GetMemory: identity did not match ListMemories"
                    )
                detail = candidate
                attributes.update(_memory_attributes(candidate))
                attributes["configuration_observed"] = True
                display_name = _string(candidate.get("name")) or display_name
                evidence = self._evidence(observed_at, operation="GetMemory", resource_id=memory_id)
            except Exception as error:
                message = _safe_failure("GetMemory", error, memory_id)
                warnings[MEMORY_INVENTORY_PLANE].append(message)
                warnings[MEMORY_RELATIONSHIP_PLANE].append(message)

            self._add_asset(
                assets,
                memory_ref,
                display_name=display_name,
                plane=MEMORY_INVENTORY_PLANE,
                evidence=evidence,
                attributes=attributes,
            )
            if detail is not None:
                self._add_principal_relationships(
                    source=memory_ref,
                    role_arn=_string(detail.get("memoryExecutionRoleArn")),
                    workload_identity_arn=None,
                    plane=MEMORY_RELATIONSHIP_PLANE,
                    asset_plane=MEMORY_INVENTORY_PLANE,
                    evidence=evidence,
                    assets=assets,
                    relationships=relationships,
                    warnings=warnings[MEMORY_RELATIONSHIP_PLANE],
                )

    def _add_principal_relationships(
        self,
        *,
        source: AssetRef,
        role_arn: str | None,
        workload_identity_arn: str | None,
        plane: str,
        asset_plane: str,
        evidence: Evidence,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        warnings: list[str],
        agent_ref: AssetRef | None = None,
    ) -> None:
        principals: list[tuple[str, str]] = []
        if role_arn:
            if _valid_role_arn(role_arn, self.partition, self.account_id):
                principals.append((role_arn, "iam_role"))
            else:
                warnings.append("execution role ARN was outside the scanned account")
        if workload_identity_arn:
            if self._valid_agentcore_arn(workload_identity_arn):
                principals.append((workload_identity_arn, "agentcore_workload_identity"))
            else:
                warnings.append("workload identity ARN was outside the scanned scope")

        for principal_arn, principal_type in principals:
            principal_ref = AssetRef(AssetKind.IDENTITY, principal_arn)
            self._add_asset(
                assets,
                principal_ref,
                display_name=principal_arn.rsplit("/", 1)[-1],
                plane=asset_plane,
                evidence=evidence,
                attributes={
                    "provider": "aws",
                    "service": "iam" if principal_type == "iam_role" else "bedrock-agentcore",
                    "principal_type": principal_type,
                    "account_id": self.account_id,
                    "region": self.region,
                },
            )
            self._add_relationship(
                relationships,
                source,
                principal_ref,
                RelationshipKind.RUNS_AS,
                plane=plane,
                evidence=evidence,
                attributes={"principal_type": principal_type},
                principal_ref=principal_ref,
                agent_ref=agent_ref,
            )

    def _add_asset(
        self,
        assets: dict[AssetRef, AssetAssertion],
        ref: AssetRef,
        *,
        display_name: str,
        plane: str,
        evidence: Evidence,
        attributes: dict[str, Any],
    ) -> None:
        assets.setdefault(
            ref,
            AssetAssertion(
                asset=ref,
                coverage_plane=plane,
                display_name=display_name,
                assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                confidence=1.0,
                evidence=evidence,
                attributes=attributes,
            ),
        )

    def _add_relationship(
        self,
        relationships: dict[tuple[AssetRef, AssetRef, RelationshipKind], RelationshipAssertion],
        source: AssetRef,
        target: AssetRef,
        kind: RelationshipKind,
        *,
        plane: str,
        evidence: Evidence,
        attributes: dict[str, Any] | None = None,
        principal_ref: AssetRef | None = None,
        agent_ref: AssetRef | None = None,
    ) -> None:
        relationships.setdefault(
            (source, target, kind),
            RelationshipAssertion(
                source=source,
                target=target,
                coverage_plane=plane,
                kind=kind,
                assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                confidence=1.0,
                evidence=evidence,
                attributes=attributes or {},
                principal_ref=principal_ref,
                agent_ref=agent_ref,
            ),
        )

    def _valid_agentcore_arn(
        self,
        arn: str,
        *,
        resource_type: str | None = None,
        resource_id: str | None = None,
    ) -> bool:
        parts = arn.split(":", 5)
        if not (
            len(parts) == 6
            and parts[:3] == ["arn", self.partition, "bedrock-agentcore"]
            and parts[3] == self.region
            and parts[4] == self.account_id
            and parts[5]
        ):
            return False
        if resource_type and parts[5] != f"{resource_type}/{resource_id}":
            return False
        if resource_id and resource_id not in parts[5].split("/"):
            return False
        return True

    def _evidence(
        self,
        observed_at: datetime,
        *,
        operation: str,
        resource_id: str,
    ) -> Evidence:
        return Evidence(
            source_type="aws_control_plane",
            locator=(
                f"aws://{self.account_id}/{self.region}/bedrock-agentcore/{operation}/{resource_id}"
            ),
            observed_at=observed_at,
            payload={
                "account_id": self.account_id,
                "region": self.region,
                "service": "bedrock-agentcore-control",
                "operation": operation,
                "resource_id": resource_id,
            },
        )


def scan_main() -> None:
    parser = argparse.ArgumentParser(description="Discover AWS Bedrock AgentCore inventory")
    parser.add_argument(
        "--regions", help="comma-separated AWS regions; defaults to configured region"
    )
    parser.add_argument("--profile", help="AWS shared-config profile")
    parser.add_argument("--connection-id", help="source connection id")
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        raise SystemExit("--dsn or DENALI_DSN is required")

    try:
        import boto3
        from botocore.config import Config
    except ImportError as error:
        raise SystemExit("AWS discovery requires: pip install 'denali-ai-security[aws]'") from error

    session = boto3.Session(profile_name=args.profile)
    regions = [
        item.strip()
        for item in (args.regions or session.region_name or "").split(",")
        if item.strip()
    ]
    if not regions:
        raise SystemExit("--regions or an AWS configured region is required")
    config = Config(
        connect_timeout=10,
        read_timeout=30,
        retries={"max_attempts": 3, "mode": "standard"},
    )
    identity = session.client("sts", config=config).get_caller_identity()
    account_id = _string(identity.get("Account"))
    identity_arn = _string(identity.get("Arn"))
    if not account_id or not identity_arn:
        raise SystemExit("STS GetCallerIdentity returned no account identity")
    partition = identity_arn.split(":", 2)[1] if identity_arn.startswith("arn:") else "aws"

    migrate(args.dsn)
    repository = PostgresInventoryRepository(args.dsn)
    failed = False
    for region in regions:
        connector = AwsAgentCoreRegionConnector(
            account_id=account_id,
            region=region,
            partition=partition,
            client=session.client("bedrock-agentcore-control", region_name=region, config=config),
        )
        batch = connector.collect(connection_id=args.connection_id)
        result = repository.ingest(args.tenant_id, batch)
        states = ",".join(f"{item.plane}={item.state.value}" for item in batch.coverage)
        print(
            f"Scanned AgentCore {account_id}/{region}: {result['assets']} assets, "
            f"{result['relationships']} relationships; {states}"
        )
        failed = failed or any(item.state is not CoverageState.COMPLETE for item in batch.coverage)
    if failed:
        raise SystemExit(2)


def _paginate(client: Any, operation: str, result_key: str, **parameters: Any) -> list[Any]:
    output: list[Any] = []
    token: str | None = None
    seen_tokens: set[str] = set()
    for _ in range(MAX_PAGES):
        request = dict(parameters)
        if token:
            request["nextToken"] = token
        try:
            response = getattr(client, operation)(**request)
        except Exception as error:
            raise AwsAgentCoreDiscoveryError(_safe_failure(operation, error)) from error
        if not isinstance(response, dict) or not isinstance(response.get(result_key), list):
            raise AwsAgentCoreDiscoveryError(f"{operation}: invalid response shape")
        output.extend(response[result_key])
        next_token = response.get("nextToken")
        if next_token is None:
            return output
        if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
            raise AwsAgentCoreDiscoveryError(f"{operation}: invalid or repeated pagination token")
        seen_tokens.add(next_token)
        token = next_token
    raise AwsAgentCoreDiscoveryError(f"{operation}: exceeded {MAX_PAGES} page safety limit")


def _runtime_attributes(detail: dict[str, Any]) -> dict[str, Any]:
    network = detail.get("networkConfiguration")
    lifecycle = detail.get("lifecycleConfiguration")
    protocol = detail.get("protocolConfiguration")
    filesystem = detail.get("filesystemConfigurations")
    artifact = detail.get("agentRuntimeArtifact")
    environment = detail.get("environmentVariables")
    request_headers = detail.get("requestHeaderConfiguration")
    return {
        "status": _string(detail.get("status")) or "UNKNOWN",
        "description": (_string(detail.get("description")) or "")[:500],
        "network_mode": _nested_string(detail, "networkConfiguration", "networkMode"),
        "network_configuration_present": isinstance(network, dict),
        "server_protocol": _nested_string(detail, "protocolConfiguration", "serverProtocol"),
        "protocol_configuration_present": isinstance(protocol, dict),
        "authorizer_configured": isinstance(detail.get("authorizerConfiguration"), dict),
        "request_header_allowlist_count": len(request_headers.get("requestHeaderAllowlist", []))
        if isinstance(request_headers, dict)
        else 0,
        "environment_variable_count": len(environment) if isinstance(environment, dict) else 0,
        "artifact_type": _first_mapping_key(artifact),
        "filesystem_configuration_types": sorted(
            {
                key
                for item in filesystem or []
                if isinstance(item, dict)
                for key, value in item.items()
                if value is not None
            }
        )
        if isinstance(filesystem, list)
        else [],
        "idle_runtime_session_timeout": lifecycle.get("idleRuntimeSessionTimeout")
        if isinstance(lifecycle, dict)
        else None,
        "max_lifetime": lifecycle.get("maxLifetime") if isinstance(lifecycle, dict) else None,
        "mmds_v2_required": _nested_value(detail, "metadataConfiguration", "requireMMDSV2"),
    }


def _gateway_attributes(detail: dict[str, Any]) -> dict[str, Any]:
    url = _string(detail.get("gatewayUrl"))
    safe_url = _safe_url(url)
    parsed = urlsplit(safe_url) if safe_url else None
    interceptors = detail.get("interceptorConfigurations")
    return {
        "status": _string(detail.get("status")) or "UNKNOWN",
        "description": (_string(detail.get("description")) or "")[:500],
        "protocol": _string(detail.get("protocolType")) or "UNKNOWN",
        "authorizer_type": _string(detail.get("authorizerType")) or "UNKNOWN",
        "authorizer_configured": isinstance(detail.get("authorizerConfiguration"), dict),
        "gateway_url": safe_url,
        "gateway_url_scheme": parsed.scheme if parsed else None,
        "kms_key_configured": bool(detail.get("kmsKeyArn")),
        "policy_engine_configured": isinstance(detail.get("policyEngineConfiguration"), dict),
        "interceptor_count": len(interceptors) if isinstance(interceptors, list) else 0,
        "status_reason_count": len(detail.get("statusReasons", []))
        if isinstance(detail.get("statusReasons"), list)
        else 0,
    }


def _target_attributes(detail: dict[str, Any]) -> dict[str, Any]:
    target_configuration = detail.get("targetConfiguration")
    target_protocol = _first_mapping_key(target_configuration)
    target_value = (
        target_configuration.get(target_protocol)
        if isinstance(target_configuration, dict) and target_protocol
        else None
    )
    credential_configs = detail.get("credentialProviderConfigurations")
    metadata = detail.get("metadataConfiguration")
    return {
        "status": _string(detail.get("status")) or "UNKNOWN",
        "protocol": _string(detail.get("protocolType")) or target_protocol or "UNKNOWN",
        "target_protocol": target_protocol,
        "target_kind": _first_mapping_key(target_value),
        "credential_provider_types": sorted(
            {
                str(item["credentialProviderType"])
                for item in credential_configs or []
                if isinstance(item, dict) and item.get("credentialProviderType")
            }
        )
        if isinstance(credential_configs, list)
        else [],
        "authorization_configured": isinstance(detail.get("authorizationData"), dict),
        "private_endpoint_configured": isinstance(detail.get("privateEndpoint"), dict),
        "allowed_request_header_count": len(metadata.get("allowedRequestHeaders", []))
        if isinstance(metadata, dict)
        else 0,
        "allowed_query_parameter_count": len(metadata.get("allowedQueryParameters", []))
        if isinstance(metadata, dict)
        else 0,
        "allowed_response_header_count": len(metadata.get("allowedResponseHeaders", []))
        if isinstance(metadata, dict)
        else 0,
        "status_reason_count": len(detail.get("statusReasons", []))
        if isinstance(detail.get("statusReasons"), list)
        else 0,
    }


def _memory_attributes(detail: dict[str, Any]) -> dict[str, Any]:
    strategies = detail.get("strategies")
    indexed_keys = detail.get("indexedKeys")
    return {
        "status": _string(detail.get("status")) or "UNKNOWN",
        "encryption_configured": bool(detail.get("encryptionKeyArn")),
        "execution_role_configured": bool(detail.get("memoryExecutionRoleArn")),
        "event_expiry_duration": detail.get("eventExpiryDuration"),
        "strategy_count": len(strategies) if isinstance(strategies, list) else 0,
        "strategy_types": sorted(
            {
                str(item["type"])
                for item in strategies or []
                if isinstance(item, dict) and item.get("type")
            }
        )
        if isinstance(strategies, list)
        else [],
        "indexed_key_count": len(indexed_keys) if isinstance(indexed_keys, list) else 0,
        "indexed_key_types": sorted(
            {
                str(item["type"])
                for item in indexed_keys or []
                if isinstance(item, dict) and item.get("type")
            }
        )
        if isinstance(indexed_keys, list)
        else [],
        "managed_by_resource_configured": bool(detail.get("managedByResourceArn")),
        "failure_reason_present": bool(detail.get("failureReason")),
    }


def _coverage_state(succeeded: bool, warnings: list[str]) -> CoverageState:
    if not succeeded:
        return CoverageState.FAILED
    return CoverageState.PARTIAL if warnings else CoverageState.COMPLETE


def _coverage_detail(warnings: list[str]) -> str | None:
    return "; ".join(dict.fromkeys(warnings))[:2_000] if warnings else None


def _safe_failure(operation: str, error: Exception, resource_id: str | None = None) -> str:
    resource = f" for {resource_id}" if resource_id else ""
    return f"{operation}{resource}: {error.__class__.__name__}"


def _valid_role_arn(arn: str, partition: str, account_id: str) -> bool:
    parts = arn.split(":", 5)
    return (
        len(parts) == 6
        and parts[:3] == ["arn", partition, "iam"]
        and parts[3] == ""
        and parts[4] == account_id
        and parts[5].startswith("role/")
        and len(parts[5]) > len("role/")
    )


def _first_mapping_key(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    return next((str(key) for key, member in value.items() if member is not None), None)


def _safe_url(value: str | None) -> str | None:
    if not value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{host}{port}{parsed.path or ''}"


def _nested_string(value: dict[str, Any], object_key: str, member_key: str) -> str | None:
    return _string(_nested_value(value, object_key, member_key))


def _nested_value(value: dict[str, Any], object_key: str, member_key: str) -> Any:
    nested = value.get(object_key)
    return nested.get(member_key) if isinstance(nested, dict) else None


def _string(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


if __name__ == "__main__":
    scan_main()
