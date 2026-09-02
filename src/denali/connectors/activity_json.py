"""Bounded runtime activity importers for Bedrock, Vertex AI, Workspace and Entra.

These are import adapters, not background pollers.  They normalize provider evidence
into Denali's activity contract while keeping collection coverage explicit.  Pollers
can later reuse the same normalization without owning a second event model.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from denali.connectors.json_file import JsonImportError, load_json_file
from denali.domain import (
    ActivityBatch,
    ActivityCategory,
    ActivityCorrelation,
    ActivityEntity,
    ActivityEntityRole,
    ActivityOutcome,
    ActivityRecord,
    AssetKind,
    AssetRef,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    Evidence,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.activity_json"
ACTIVITY_PLANE = "runtime_activity"
CAPABILITIES = ConnectorCapabilities(activity=True)
MAX_RECORDS = 250_000
FORMATS = (
    "aws-bedrock-cloudtrail",
    "gcp-vertex-audit",
    "google-workspace-gemini",
    "entra-ai-signin",
)
_VERTEX_MODEL_RESOURCE_RE = re.compile(
    r"^projects/[^/]+/locations/[^/]+/publishers/google/models/(?P<model>[^/:]+)"
)


class ActivityImportError(ValueError):
    """A normalization error that never echoes arbitrary event content."""


class ActivityJsonConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def collect(
        self,
        document: Any,
        *,
        format_name: str,
        connection_id: str,
        run_id: str,
        scope_key: str,
        source_locator: str,
    ) -> ActivityBatch:
        if format_name not in FORMATS:
            raise ActivityImportError("unsupported activity format")
        collected_at = datetime.now(UTC)
        records = _records(document, format_name)
        if len(records) > MAX_RECORDS:
            raise ActivityImportError(f"input exceeds the {MAX_RECORDS} record safety limit")
        activities: dict[str, ActivityRecord] = {}
        warnings: list[str] = []
        for position, record in enumerate(records):
            try:
                normalized = _normalize(
                    record,
                    format_name=format_name,
                    position=position,
                    source_locator=source_locator,
                    observed_at=collected_at,
                )
            except ActivityImportError as error:
                warnings.append(f"item {position}: {error}")
                continue
            for activity in normalized:
                if activity.source_uid in activities:
                    warnings.append(f"item {position}: duplicate source event identifier")
                    continue
                activities[activity.source_uid] = activity
        state = (
            CoverageState.FAILED
            if records and not activities
            else CoverageState.PARTIAL
            if warnings
            else CoverageState.COMPLETE
        )
        detail = "; ".join(dict.fromkeys(warnings))[:4_000] if warnings else None
        return ActivityBatch(
            connector_id=f"{CONNECTOR_ID}.{format_name}",
            connection_id=connection_id,
            run_id=run_id,
            scope_key=scope_key,
            collected_at=collected_at,
            coverage=(Coverage(ACTIVITY_PLANE, state, scope_key, detail),),
            activities=tuple(activities.values()),
        )


def _records(document: Any, format_name: str) -> list[Any]:
    if isinstance(document, list):
        return document
    if not isinstance(document, dict):
        raise ActivityImportError("input root must be an object or array")
    keys = {
        "aws-bedrock-cloudtrail": "Records",
        "gcp-vertex-audit": "entries",
        "google-workspace-gemini": "items",
        "entra-ai-signin": "value",
    }
    value = document.get(keys[format_name])
    if not isinstance(value, list):
        raise ActivityImportError(f"input does not contain a {keys[format_name]} array")
    return value


def _normalize(
    record: Any,
    *,
    format_name: str,
    position: int,
    source_locator: str,
    observed_at: datetime,
) -> tuple[ActivityRecord, ...]:
    if not isinstance(record, dict):
        raise ActivityImportError("record must be an object")
    digest = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()
    locator = f"{source_locator}#record={position}"
    if format_name == "aws-bedrock-cloudtrail":
        return (_aws(record, digest, locator, observed_at),)
    if format_name == "gcp-vertex-audit":
        return (_vertex(record, digest, locator, observed_at),)
    if format_name == "google-workspace-gemini":
        return _workspace(record, digest, locator, observed_at)
    return (_entra(record, digest, locator, observed_at),)


def _aws(
    record: dict[str, Any], digest: str, locator: str, observed_at: datetime
) -> ActivityRecord:
    event = record
    encoded = record.get("CloudTrailEvent")
    if isinstance(encoded, str):
        try:
            parsed = json.loads(encoded)
        except json.JSONDecodeError as error:
            raise ActivityImportError("CloudTrailEvent is not valid JSON") from error
        if isinstance(parsed, dict):
            event = parsed
    name = _text(event.get("eventName") or record.get("EventName"), "eventName")
    if name not in {
        "InvokeModel",
        "InvokeModelWithResponseStream",
        "Converse",
        "ConverseStream",
        "InvokeAgent",
        "Retrieve",
        "RetrieveAndGenerate",
    }:
        raise ActivityImportError("record is not a supported Bedrock runtime event")
    occurred = _time(event.get("eventTime") or record.get("EventTime"))
    source_uid = str(event.get("eventID") or record.get("EventId") or digest)
    request = (
        event.get("requestParameters") if isinstance(event.get("requestParameters"), dict) else {}
    )
    identity = event.get("userIdentity") if isinstance(event.get("userIdentity"), dict) else {}
    session = (
        identity.get("sessionContext") if isinstance(identity.get("sessionContext"), dict) else {}
    )
    issuer = session.get("sessionIssuer") if isinstance(session.get("sessionIssuer"), dict) else {}
    observed_actor_uid = str(
        identity.get("arn") or issuer.get("arn") or identity.get("principalId") or "unknown"
    )
    issuer_arn = issuer.get("arn") if isinstance(issuer.get("arn"), str) else None
    actor_asset_key = issuer_arn or (
        observed_actor_uid if observed_actor_uid.startswith("arn:") else None
    )
    actor_asset = (
        AssetRef(AssetKind.IDENTITY, actor_asset_key) if actor_asset_key is not None else None
    )
    entities: list[ActivityEntity] = [
        ActivityEntity(
            role=ActivityEntityRole.ACTOR,
            external_uid=observed_actor_uid,
            display_name=str(record.get("Username") or observed_actor_uid),
            asset=actor_asset,
            correlation=(
                ActivityCorrelation.EXACT_IDENTIFIER
                if actor_asset is not None
                else ActivityCorrelation.UNRESOLVED
            ),
            confidence=1.0 if actor_asset is not None else 0.0,
            attributes={"session_issuer_arn": issuer_arn} if issuer_arn else {},
        )
    ]
    model_id = request.get("modelId") or request.get("modelIdentifier")
    if isinstance(model_id, str) and model_id:
        entities.append(
            _entity(
                ActivityEntityRole.MODEL,
                model_id,
                model_id,
                AssetKind.AI_MODEL,
                f"aws:bedrock:model:{model_id}",
            )
        )
    agent_id = request.get("agentId")
    account = event.get("recipientAccountId")
    region = event.get("awsRegion")
    if isinstance(agent_id, str) and agent_id:
        partition = str(event.get("awsPartition") or "aws")
        agent_arn = f"arn:{partition}:bedrock:{region}:{account}:agent/{agent_id}"
        entities.append(
            _entity(ActivityEntityRole.AGENT, agent_id, agent_id, AssetKind.AI_AGENT, agent_arn)
        )
    category = (
        ActivityCategory.AGENT_INVOCATION
        if name == "InvokeAgent"
        else ActivityCategory.RETRIEVAL
        if name in {"Retrieve", "RetrieveAndGenerate"}
        else ActivityCategory.MODEL_INVOCATION
    )
    error_code = event.get("errorCode")
    return ActivityRecord(
        source_uid=source_uid,
        category=category,
        activity_name=f"aws.bedrock.{name}",
        title=_title(name),
        occurred_at=occurred,
        observed_at=observed_at,
        outcome=ActivityOutcome.FAILURE if error_code else ActivityOutcome.SUCCESS,
        provider="aws_bedrock",
        account_uid=str(account) if account else None,
        region=str(region) if region else None,
        session_uid=str(request.get("sessionId")) if request.get("sessionId") else None,
        entities=tuple(entities),
        evidence=_aws_evidence(event, locator, observed_at, digest, name),
        attributes={"error_code": error_code} if error_code else {},
    )


def _vertex(
    record: dict[str, Any], digest: str, locator: str, observed_at: datetime
) -> ActivityRecord:
    payload = record.get("protoPayload") if isinstance(record.get("protoPayload"), dict) else {}
    name = _text(payload.get("methodName"), "protoPayload.methodName")
    principal = payload.get("authenticationInfo")
    principal = principal if isinstance(principal, dict) else {}
    actor = str(principal.get("principalEmail") or "unknown")
    resource = str(payload.get("resourceName") or record.get("resourceName") or "unknown")
    lowered = name.lower()
    category = (
        ActivityCategory.RETRIEVAL
        if any(item in lowered for item in ("search", "retrieve"))
        else ActivityCategory.MODEL_INVOCATION
        if any(item in lowered for item in ("predict", "generate"))
        else ActivityCategory.OTHER
    )
    status = payload.get("status") if isinstance(payload.get("status"), dict) else {}
    actor_entity = (
        _entity(
            ActivityEntityRole.ACTOR,
            actor,
            actor,
            AssetKind.IDENTITY,
            f"gcp:service-account:{actor}",
        )
        if actor.endswith(".iam.gserviceaccount.com")
        else _entity(ActivityEntityRole.ACTOR, actor, actor)
    )
    entities: list[ActivityEntity] = [
        actor_entity,
        _entity(ActivityEntityRole.RESOURCE, resource, resource),
    ]
    model_match = _VERTEX_MODEL_RESOURCE_RE.match(resource)
    if model_match:
        model_id = model_match.group("model")
        entities.append(
            _entity(
                ActivityEntityRole.MODEL,
                model_id,
                model_id,
                AssetKind.AI_MODEL,
                f"gcp:vertex:model:{model_id}",
            )
        )
    return ActivityRecord(
        source_uid=str(record.get("insertId") or digest),
        category=category,
        activity_name=name,
        title=_title(name.rsplit(".", 1)[-1]),
        occurred_at=_time(record.get("timestamp") or record.get("receiveTimestamp")),
        observed_at=observed_at,
        outcome=ActivityOutcome.FAILURE if status.get("code") else ActivityOutcome.SUCCESS,
        provider="gcp_vertex_ai",
        region=_label(record, "location"),
        entities=tuple(entities),
        evidence=_evidence("gcp_cloud_logging", locator, observed_at, digest, name),
        attributes={"status_code": status.get("code")} if status.get("code") else {},
    )


def _workspace(
    record: dict[str, Any], digest: str, locator: str, observed_at: datetime
) -> tuple[ActivityRecord, ...]:
    record_id = record.get("id") if isinstance(record.get("id"), dict) else {}
    events = record.get("events")
    if not isinstance(events, list) or not events:
        raise ActivityImportError("Workspace record has no events array")
    actor = record.get("actor") if isinstance(record.get("actor"), dict) else {}
    actor_uid = str(actor.get("email") or actor.get("profileId") or "unknown")
    occurred = _time(record_id.get("time"))
    qualifier = str(record_id.get("uniqueQualifier") or digest)
    results: list[ActivityRecord] = []
    for index, event in enumerate(events):
        if not isinstance(event, dict):
            raise ActivityImportError("Workspace events entries must be objects")
        name = _text(event.get("name"), "events.name")
        results.append(
            ActivityRecord(
                source_uid=f"{qualifier}:{index}:{name}",
                category=ActivityCategory.OTHER,
                activity_name=f"google.workspace.gemini.{name}",
                title=_title(name),
                occurred_at=occurred,
                observed_at=observed_at,
                outcome=ActivityOutcome.SUCCESS,
                provider="google_workspace_gemini",
                entities=(
                    _entity(ActivityEntityRole.ACTOR, actor_uid, actor_uid),
                    _entity(
                        ActivityEntityRole.APPLICATION,
                        "gemini_in_workspace_apps",
                        "Gemini in Workspace",
                    ),
                ),
                evidence=_evidence(
                    "google_workspace_reports",
                    f"{locator}&event={index}",
                    observed_at,
                    digest,
                    name,
                ),
                attributes={"event_type": event.get("type")},
            )
        )
    return tuple(results)


def _entra(
    record: dict[str, Any], digest: str, locator: str, observed_at: datetime
) -> ActivityRecord:
    app_uid = str(record.get("appId") or record.get("resourceId") or "unknown")
    app_name = str(record.get("appDisplayName") or app_uid)
    actor_uid = str(record.get("userPrincipalName") or record.get("userId") or "unknown")
    status = record.get("status") if isinstance(record.get("status"), dict) else {}
    error_code = status.get("errorCode")
    return ActivityRecord(
        source_uid=str(record.get("id") or digest),
        category=ActivityCategory.AI_APP_SIGN_IN,
        activity_name="microsoft.entra.ai_app_sign_in",
        title=f"Sign-in to {app_name}",
        occurred_at=_time(record.get("createdDateTime")),
        observed_at=observed_at,
        outcome=(
            ActivityOutcome.UNKNOWN
            if error_code is None
            else ActivityOutcome.SUCCESS
            if error_code in (0, "0")
            else ActivityOutcome.FAILURE
        ),
        provider="microsoft_entra",
        session_uid=str(record.get("correlationId")) if record.get("correlationId") else None,
        entities=(
            _entity(ActivityEntityRole.ACTOR, actor_uid, actor_uid),
            _entity(ActivityEntityRole.APPLICATION, app_uid, app_name),
        ),
        evidence=Evidence(
            "microsoft_graph_signins",
            locator,
            observed_at,
            {
                "record_sha256": digest,
                "id": record.get("id"),
                "createdDateTime": record.get("createdDateTime"),
                "userId": record.get("userId"),
                "userPrincipalName": record.get("userPrincipalName"),
                "appId": record.get("appId"),
                "appDisplayName": record.get("appDisplayName"),
                "resourceId": record.get("resourceId"),
                "status": status,
                "correlationId": record.get("correlationId"),
            },
        ),
        attributes={"error_code": error_code, "client_app": record.get("clientAppUsed")},
    )


def _entity(
    role: ActivityEntityRole,
    uid: str,
    name: str,
    kind: AssetKind | None = None,
    natural_key: str | None = None,
) -> ActivityEntity:
    asset = AssetRef(kind, natural_key) if kind is not None and natural_key else None
    return ActivityEntity(
        role=role,
        external_uid=uid,
        display_name=name,
        asset=asset,
        correlation=ActivityCorrelation.EXACT_IDENTIFIER
        if asset
        else ActivityCorrelation.UNRESOLVED,
        confidence=1.0 if asset else 0.0,
    )


def _evidence(
    source_type: str, locator: str, observed_at: datetime, digest: str, event_name: str
) -> Evidence:
    return Evidence(
        source_type, locator, observed_at, {"record_sha256": digest, "event_name": event_name}
    )


def _aws_evidence(
    event: dict[str, Any],
    locator: str,
    observed_at: datetime,
    digest: str,
    event_name: str,
) -> Evidence:
    """Retain the fields used for correlation without prompt or response content."""
    identity = event.get("userIdentity") if isinstance(event.get("userIdentity"), dict) else {}
    session = (
        identity.get("sessionContext") if isinstance(identity.get("sessionContext"), dict) else {}
    )
    issuer = session.get("sessionIssuer") if isinstance(session.get("sessionIssuer"), dict) else {}
    request = (
        event.get("requestParameters") if isinstance(event.get("requestParameters"), dict) else {}
    )
    safe_request = {
        key: request.get(key)
        for key in ("modelId", "modelIdentifier", "agentId", "sessionId", "knowledgeBaseId")
        if key in request
    }
    safe_identity: dict[str, Any] = {
        key: identity.get(key) for key in ("type", "principalId", "arn") if key in identity
    }
    if issuer:
        safe_identity["sessionIssuer"] = {
            key: issuer.get(key)
            for key in ("type", "principalId", "arn", "userName")
            if key in issuer
        }
    payload = {
        "record_sha256": digest,
        "eventID": event.get("eventID"),
        "eventTime": event.get("eventTime"),
        "eventName": event_name,
        "eventSource": event.get("eventSource"),
        "awsRegion": event.get("awsRegion"),
        "recipientAccountId": event.get("recipientAccountId"),
        "userIdentity": safe_identity,
        "requestIdentifiers": safe_request,
        "errorCode": event.get("errorCode"),
    }
    return Evidence("aws_cloudtrail", locator, observed_at, payload)


def _time(value: Any) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str) and value:
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise ActivityImportError("event timestamp is invalid") from error
    else:
        raise ActivityImportError("event timestamp is missing")
    if result.tzinfo is None:
        raise ActivityImportError("event timestamp must include a timezone")
    return result


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ActivityImportError(f"{field} is missing")
    return value.strip()


def _label(record: dict[str, Any], key: str) -> str | None:
    labels = record.get("resource") if isinstance(record.get("resource"), dict) else {}
    labels = labels.get("labels") if isinstance(labels.get("labels"), dict) else {}
    value = labels.get(key)
    return str(value) if value else None


def _title(value: str) -> str:
    output = value.replace("_", " ")
    for index in range(1, len(output)):
        if output[index].isupper() and output[index - 1].islower():
            output = output[:index] + " " + output[index:]
            break
    return output.strip().capitalize()


def import_main() -> None:
    parser = argparse.ArgumentParser(description="Import AI runtime activity JSON into Denali")
    parser.add_argument("path", type=Path)
    parser.add_argument("--format", required=True, choices=FORMATS)
    parser.add_argument("--connection-id", required=True)
    parser.add_argument("--scope-key", required=True)
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        parser.error("--dsn or DENALI_DSN is required")
    try:
        document, digest, locator = load_json_file(args.path)
        batch = ActivityJsonConnector().collect(
            document,
            format_name=args.format,
            connection_id=args.connection_id,
            run_id=f"activity-{datetime.now(UTC).isoformat()}",
            scope_key=args.scope_key,
            source_locator=locator,
        )
    except (JsonImportError, ActivityImportError) as error:
        parser.error(str(error))
    migrate(args.dsn)
    result = PostgresInventoryRepository(args.dsn).ingest_activity(args.tenant_id, batch)
    print(json.dumps({**result, "input_sha256": digest, "coverage": batch.coverage[0].state.value}))
