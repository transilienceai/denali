"""Explicit gateway read catalog; never proxy arbitrary Denali URLs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlencode
from uuid import UUID

from fastapi import HTTPException
from starlette.datastructures import QueryParams

# This product-owned v1 contract is pinned by the shared Platform adapter.
# Breaking an operation name, parameter, or result change requires a new
# contract version. Additive optional parameters remain v1-compatible when
# coordinated with the gateway/CLI/MCP rollout.
CAPABILITY_CONTRACT_VERSION = 1


@dataclass(frozen=True)
class ReadCapability:
    path: str
    filters: frozenset[str] = frozenset()
    identifier: str | None = None


READ_CAPABILITIES: dict[str, ReadCapability] = {
    "connections": ReadCapability("/v1/connection-summaries", frozenset({"limit", "offset"})),
    "connection-detail": ReadCapability("/v1/connection-summaries/{id}", identifier="uuid"),
    "connection-setup-status": ReadCapability(
        "/v1/connection-setup-summaries/{id}", identifier="uuid"
    ),
    "connection-aws-template": ReadCapability(
        "/v1/connection-setup-templates/aws/{id}", identifier="uuid"
    ),
    "shared-connections": ReadCapability(
        "/v1/shared/connection-summaries", frozenset({"limit", "offset"})
    ),
    "shared-aws-status": ReadCapability(
        "/v1/shared/connection-summaries/aws/{id}", identifier="uuid"
    ),
    "shared-aws-template": ReadCapability(
        "/v1/shared/connection-setup-templates/aws/{id}", identifier="uuid"
    ),
    "inventory-summary": ReadCapability("/v1/inventory/summary"),
    "assets": ReadCapability(
        "/v1/inventory/assets",
        frozenset({"kind", "category", "lifecycle", "governance", "q", "limit", "offset"}),
    ),
    "asset-detail": ReadCapability("/v1/inventory/assets/{id}", identifier="uuid"),
    "sources-coverage": ReadCapability("/v1/sources/coverage"),
    "findings-summary": ReadCapability("/v1/findings/summary"),
    "findings": ReadCapability("/v1/findings", frozenset({"state", "severity", "limit", "offset"})),
    "finding-detail": ReadCapability("/v1/findings/{id}", identifier="uuid"),
    "vulnerabilities-summary": ReadCapability("/v1/vulnerabilities/summary"),
    "vulnerabilities": ReadCapability(
        "/v1/vulnerabilities", frozenset({"state", "severity", "limit", "offset"})
    ),
    "vulnerability-detail": ReadCapability("/v1/vulnerabilities/{id}", identifier="uuid"),
    "vulnerability-import-status": ReadCapability(
        "/v1/vulnerabilities/imports/{id}", identifier="uuid"
    ),
    "issues-summary": ReadCapability("/v1/issues/summary"),
    "issues": ReadCapability("/v1/issues", frozenset({"state", "severity", "limit", "offset"})),
    "issue-detail": ReadCapability("/v1/issues/{id}", identifier="uuid"),
    "issue-evaluations": ReadCapability("/v1/issues/evaluations"),
    "code-to-cloud-deployments": ReadCapability(
        "/v1/code-to-cloud/deployments", frozenset({"limit", "offset"})
    ),
    "code-to-cloud-observations": ReadCapability(
        "/v1/code-to-cloud/observations", frozenset({"limit", "offset"})
    ),
    "activity-summary": ReadCapability("/v1/activity/summary", frozenset({"include_fixtures"})),
    "activity": ReadCapability(
        "/v1/activity",
        frozenset({"category", "outcome", "asset_id", "include_fixtures", "limit", "offset"}),
    ),
    "activity-detail": ReadCapability("/v1/activity/{id}", identifier="uuid"),
    "runtime-sessions": ReadCapability(
        "/v1/runtime/sessions", frozenset({"provider", "outcome", "limit", "offset"})
    ),
    "runtime-session-detail": ReadCapability("/v1/runtime/sessions/{id}", identifier="session_key"),
    "detections-summary": ReadCapability("/v1/detections/summary"),
    "detections": ReadCapability(
        "/v1/detections", frozenset({"state", "severity", "limit", "offset"})
    ),
    "detection-detail": ReadCapability("/v1/detections/{id}", identifier="uuid"),
    "detection-evaluations": ReadCapability("/v1/detections/evaluations"),
}


def read_route(operation: str, query: QueryParams) -> tuple[str, bytes]:
    """Resolve one named read and validate the complete query before dispatch."""

    capability = READ_CAPABILITIES.get(operation)
    if capability is None:
        raise HTTPException(status_code=404, detail="not found")
    pairs = list(query.multi_items())
    values = dict(pairs)
    if len(pairs) != len(values):
        raise HTTPException(status_code=422, detail="duplicate query parameter")
    allowed = capability.filters | ({"id"} if capability.identifier else set())
    if not values.keys() <= allowed:
        raise HTTPException(status_code=422, detail="unsupported query parameter")
    path = capability.path
    if capability.identifier:
        raw_id = values.pop("id", None)
        if raw_id is None:
            raise HTTPException(status_code=422, detail="id is required")
        if capability.identifier == "session_key":
            if re.fullmatch(r"[0-9a-f]{64}", raw_id) is None:
                raise HTTPException(status_code=422, detail="invalid session key")
            identifier = raw_id
        else:
            try:
                identifier = str(UUID(raw_id))
            except (ValueError, AttributeError) as error:
                raise HTTPException(status_code=422, detail="invalid id") from error
            if identifier != raw_id.lower():
                raise HTTPException(status_code=422, detail="invalid id")
        path = path.replace("{id}", identifier)
    if "asset_id" in values:
        try:
            asset_id = str(UUID(values["asset_id"]))
        except (ValueError, AttributeError) as error:
            raise HTTPException(status_code=422, detail="invalid asset_id") from error
        if asset_id != values["asset_id"].lower():
            raise HTTPException(status_code=422, detail="invalid asset_id")
        values["asset_id"] = asset_id
    for name, minimum, maximum in (("limit", 1, 100), ("offset", 0, 100000)):
        if name in values:
            try:
                number = int(values[name])
            except ValueError as error:
                raise HTTPException(status_code=422, detail=f"invalid {name}") from error
            if not minimum <= number <= maximum:
                raise HTTPException(status_code=422, detail=f"invalid {name}")
            values[name] = str(number)
    if "q" in values and len(values["q"]) > 200:
        raise HTTPException(status_code=422, detail="search query is too long")
    if "kind" in values and len(values["kind"]) > 100:
        raise HTTPException(status_code=422, detail="asset kind is too long")
    if "include_fixtures" in values and values["include_fixtures"] not in {"true", "false"}:
        raise HTTPException(status_code=422, detail="invalid include_fixtures")
    if operation in {"code-to-cloud-deployments", "code-to-cloud-observations"}:
        # Browser reads retain their legacy behavior, but gateway responses
        # must never return an unbounded collection by default.
        values.setdefault("limit", "100")
    return path, urlencode(values).encode()
