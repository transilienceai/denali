"""Fixed, bounded Workspace report reads; Google credentials stay in Platform."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from time import monotonic
from typing import Any
from uuid import UUID

from denali.connections.google_workspace import (
    GOOGLE_WORKSPACE_SCOPES,
    GoogleWorkspaceConnectionValidator,
    GoogleWorkspaceOperator,
)
from denali.connectors.google_workspace import (
    MAX_REPORT_RECORDS,
    GoogleWorkspaceConnectionCollector,
    GoogleWorkspaceRecordLimitReached,
)
from denali.integrations.shared_connections_client import SharedConnectionsClient

ROOT = "/internal/v1/connections/google-workspace"
CREDENTIAL_TYPE = "platform_shared_google_workspace"
_SHARED_REPORT_PAGE_SIZE = 100
OPERATIONS = {"gemini_in_workspace_apps": "gemini_activity", "token": "oauth_activity"}
PIN_FIELDS = (
    "target_id",
    "customer_id",
    "domain",
    "admin_email",
    "service_account",
    "oauth_client_id",
    "binding_revision",
)
PUBLIC_FIELDS = frozenset(
    {
        "id",
        "clerk_org_id",
        "provider",
        *PIN_FIELDS,
        "declared_scopes",
        "validated_scopes",
        "lifecycle_state",
        "setup_state",
        "health_state",
        "last_validated_at",
        "job_id",
        "job_state",
        "error_code",
        "connection_kind",
        "observed_customer_id",
        "validation_results",
    }
)
PARAMETERS = {
    "gemini_in_workspace_apps": frozenset(
        {
            "action",
            "event_category",
            "feature_source",
            "app_name",
            "application_name",
        }
    ),
    "token": frozenset(
        {
            "client_id",
            "client_id_value",
            "app_name",
            "application_name",
            "client_type",
            "scope",
            "scope_data",
        }
    ),
}


def shared_google_workspace_enabled() -> bool:
    return os.environ.get("DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED", "false") == "true"


def _time(value: Any) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError("Workspace timestamp is invalid")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("Workspace timestamp must be UTC")
    return parsed.astimezone(UTC)


def _text(value: Any, maximum: int = 320) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or any(ord(char) < 32 for char in value)
    ):
        raise ValueError("Workspace metadata text is invalid")
    return value


def workspace_projection(value: Any, *, org: str, connection: bool = True) -> dict[str, Any]:
    """Validate admission metadata before browser display or immutable local attachment."""
    if not isinstance(value, dict):
        raise ValueError("Workspace metadata is invalid")
    projected = {key: item for key, item in value.items() if key in PUBLIC_FIELDS}
    if projected.get("clerk_org_id") != org or projected.get("provider") != "google_workspace":
        raise ValueError("Workspace organization boundary is invalid")
    UUID(_text(projected["target_id"]))
    if connection:
        UUID(_text(projected["id"]))
    if not re.fullmatch(r"C[A-Za-z0-9]{2,30}", _text(projected["customer_id"])):
        raise ValueError("Workspace customer identity is invalid")
    domain = _text(projected["domain"], 253)
    if not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+",
        domain,
    ):
        raise ValueError("Workspace domain is invalid")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+", _text(projected["admin_email"])):
        raise ValueError("Workspace delegated subject is invalid")
    if not re.fullmatch(
        r"[a-z0-9-]+@[a-z0-9.-]+\.iam\.gserviceaccount\.com", _text(projected["service_account"])
    ) or not re.fullmatch(r"[1-9][0-9]{5,39}", _text(projected["oauth_client_id"])):
        raise ValueError("Workspace operator identity is invalid")
    if connection:
        if type(projected.get("binding_revision")) is not int or projected["binding_revision"] < 1:
            raise ValueError("Workspace binding revision is invalid")
        if not full_bundle(projected.get("declared_scopes")):
            raise ValueError("Workspace scope bundle is invalid")
        if projected.get("lifecycle_state") not in {"active", "disabled"}:
            raise ValueError("Workspace lifecycle is invalid")
        if projected.get("setup_state") not in {"pending_authorization", "ready"} or projected.get(
            "health_state"
        ) not in {"unknown", "healthy", "partial", "unhealthy", "disabled"}:
            raise ValueError("Workspace status is invalid")
        validated = projected.get("validated_scopes")
        if (
            not isinstance(validated, list)
            or any(not isinstance(scope, str) for scope in validated)
            or (
                len(validated) != len(set(validated))
                or not set(validated) <= set(GOOGLE_WORKSPACE_SCOPES)
            )
        ):
            raise ValueError("Workspace validated scopes are invalid")
        if projected.get("last_validated_at") is not None:
            _time(projected["last_validated_at"])
    if "validation_results" in projected:
        results = projected["validation_results"]
        if not isinstance(results, list) or len(results) > 2:
            raise ValueError("Workspace validation projection is invalid")
        projected["validation_results"] = []
        for result in results:
            if (
                not isinstance(result, dict)
                or result.get("scope") not in GOOGLE_WORKSPACE_SCOPES
                or (
                    result.get("application_name") not in OPERATIONS
                    or result.get("state") not in {"passed", "failed"}
                    or type(result.get("customer_identity_observed")) is not bool
                )
            ):
                raise ValueError("Workspace validation projection is invalid")
            projected["validation_results"].append(
                {
                    key: result[key]
                    for key in ("scope", "application_name", "state", "customer_identity_observed")
                }
            )
    if projected.get("observed_customer_id") not in {None, projected["customer_id"]}:
        raise ValueError("Workspace observed customer is invalid")
    for key in ("job_id", "job_state", "error_code", "connection_kind"):
        if projected.get(key) is not None:
            _text(projected[key], 128)
    return projected


def full_bundle(value: Any) -> bool:
    return (
        isinstance(value, list)
        and len(value) == len(GOOGLE_WORKSPACE_SCOPES)
        and all(isinstance(item, str) for item in value)
        and set(value) == set(GOOGLE_WORKSPACE_SCOPES)
    )


def require_ready(
    value: dict[str, Any], *, now: datetime | None = None, fresh: bool = True
) -> None:
    if (
        value.get("lifecycle_state") != "active"
        or value.get("setup_state") != "ready"
        or (
            value.get("health_state") != "healthy" or not full_bundle(value.get("validated_scopes"))
        )
    ):
        raise ValueError("Workspace broker validation is not ready")
    results = value.get("validation_results")
    if (
        not isinstance(results, list)
        or len(results) != 2
        or {
            (item.get("scope"), item.get("application_name"), item.get("state"))
            for item in results
            if isinstance(item, dict)
        }
        != {
            (GOOGLE_WORKSPACE_SCOPES[0], "gemini_in_workspace_apps", "passed"),
            (GOOGLE_WORKSPACE_SCOPES[1], "token", "passed"),
        }
    ):
        raise ValueError("Workspace broker plane proof is invalid")
    proof_time = _time(value.get("last_validated_at"))
    if not fresh:
        return
    current = now or datetime.now(UTC)
    if not -timedelta(minutes=1) <= current - proof_time <= timedelta(minutes=15):
        raise ValueError("Workspace broker validation must be fresh")


def _record(value: Any, *, customer: str, application: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not set(value) <= {"id", "actor", "events"}:
        raise ValueError("Workspace record projection is invalid")
    identity = value.get("id")
    if (
        not isinstance(identity, dict)
        or set(identity) != {"time", "uniqueQualifier", "applicationName", "customerId"}
        or identity.get("customerId") != customer
        or identity.get("applicationName") != application
    ):
        raise ValueError("Workspace record identity is invalid")
    _time(identity["time"])
    _text(identity["uniqueQualifier"], 256)
    actor = value.get("actor", {})
    if not isinstance(actor, dict) or not set(actor) <= {"profileId"}:
        raise ValueError("Workspace actor projection is invalid")
    if actor:
        _text(actor["profileId"], 256)
    events = value.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= 100:
        raise ValueError("Workspace event projection is invalid")
    for event in events:
        if not isinstance(event, dict) or not set(event) <= {"name", "type", "parameters"}:
            raise ValueError("Workspace event projection is invalid")
        _text(event.get("name"), 128)
        if "type" in event:
            _text(event["type"], 128)
        parameters = event.get("parameters", [])
        if not isinstance(parameters, list) or len(parameters) > 20:
            raise ValueError("Workspace parameters are invalid")
        seen: set[str] = set()
        for parameter in parameters:
            if (
                not isinstance(parameter, dict)
                or parameter.get("name") not in PARAMETERS[application]
            ):
                raise ValueError("Workspace parameter projection is invalid")
            name = parameter["name"]
            if name in seen:
                raise ValueError("Workspace parameter is duplicated")
            seen.add(name)
            keys = set(parameter) - {"name"}
            if len(keys) != 1 or not keys <= {
                "value",
                "multiValue",
                "intValue",
                "multiIntValue",
                "boolValue",
            }:
                raise ValueError("Workspace parameter value is invalid")
            item = parameter[next(iter(keys))]
            if keys & {"multiValue", "multiIntValue"}:
                if not isinstance(item, list) or len(item) > 100:
                    raise ValueError("Workspace multi-value is invalid")
                for text in item:
                    _text(text, 2048)
            elif "boolValue" in keys:
                if type(item) is not bool:
                    raise ValueError("Workspace boolean is invalid")
            else:
                _text(item, 2048)
            if keys & {"intValue", "multiIntValue"}:
                values = item if isinstance(item, list) else [item]
                if any(not re.fullmatch(r"-?[0-9]{1,20}", text) for text in values):
                    raise ValueError("Workspace integer is invalid")
    return value


class SharedWorkspaceReportsClient:
    """Adapt sanitized broker pages to Denali's existing Reports protocol."""

    def __init__(
        self,
        connection: dict[str, Any],
        *,
        client: SharedConnectionsClient | None = None,
        clock: Callable[[], float] = monotonic,
    ):
        if (
            not shared_google_workspace_enabled()
            or connection.get("credential_type") != CREDENTIAL_TYPE
        ):
            raise ValueError("shared Workspace is disabled or reference is invalid")
        self._id = str(UUID(str(connection["credential_reference"]["platform_connection_id"])))
        self._org = connection.get("clerk_organization_id")
        if (
            self._id != str(connection["id"])
            or not isinstance(self._org, str)
            or not re.fullmatch(r"org_[A-Za-z0-9]+", self._org)
            or connection.get("lifecycle_state") != "active"
            or not full_bundle(connection.get("declared_scopes"))
        ):
            raise ValueError("shared Workspace identity is invalid")
        self._pin = connection["configuration"].get("platform_binding")
        if not isinstance(self._pin, dict) or set(self._pin) != set(PIN_FIELDS):
            raise ValueError("shared Workspace binding is invalid")
        if any(
            connection["configuration"].get(key) != self._pin[key]
            for key in ("domain", "customer_id", "admin_email")
        ) or not connection["configuration"].get("onboarding", {}).get("completed_at"):
            raise ValueError("shared Workspace local binding is inconsistent")
        self._client = client or SharedConnectionsClient.from_environment()
        if self._client is None or not self._client.allows_org(self._org):
            raise ValueError("shared Workspace organization is not enabled")
        self._clock = clock
        self._deadline = clock() + 1500
        self._observed_customer = False
        self._check_binding()

    def _check_binding(self) -> None:
        status = self._client.request(
            "GET", f"{ROOT}/{self._id}/status", clerk_org_id=self._org, max_response_bytes=128_000
        )
        current = workspace_projection(status, org=self._org)
        if current["id"] != self._id or any(current[key] != self._pin[key] for key in PIN_FIELDS):
            raise ValueError("shared Workspace binding changed")
        require_ready(current, fresh=False)

    @property
    def observed_identity(self) -> str | None:
        return self._pin["customer_id"] if self._observed_customer else None

    def list(
        self,
        application_name: str,
        *,
        start_time: datetime,
        end_time: datetime,
        max_results: int = 1000,
        limit: int = MAX_REPORT_RECORDS,
        follow_pagination: bool = True,
    ) -> tuple[dict[str, Any], ...]:
        if (
            application_name not in OPERATIONS
            or type(max_results) is not int
            or not (
                1 <= max_results <= 1000 and type(limit) is int and 1 <= limit <= MAX_REPORT_RECORDS
            )
            or start_time.tzinfo is None
            or end_time.tzinfo is None
            or not (timedelta(0) < end_time - start_time <= timedelta(days=180))
            or end_time > datetime.now(UTC) + timedelta(minutes=1)
        ):
            raise ValueError("shared Workspace read selection is invalid")
        start = start_time.astimezone(UTC).isoformat()
        end = end_time.astimezone(UTC).isoformat()
        deadline = self._deadline
        records: list[dict[str, Any]] = []
        response_bytes = 0
        cursor = None
        seen: set[str] = set()
        operation = OPERATIONS[application_name]
        page_size = min(max_results, limit, _SHARED_REPORT_PAGE_SIZE)
        for _ in range(200):
            if self._clock() >= deadline:
                raise ValueError("shared Workspace collection deadline exceeded")
            arguments = {"start_time": start, "end_time": end, "limit": page_size}
            if cursor:
                arguments["cursor"] = cursor
            result = self._client.request(
                "POST",
                f"{ROOT}/{self._id}/read",
                clerk_org_id=self._org,
                payload={"operation": operation, "arguments": arguments},
                max_response_bytes=2_097_152,
            )
            response_bytes += len(json.dumps(result).encode("utf-8"))
            if response_bytes > 16 * 1024 * 1024 or self._clock() >= deadline:
                raise GoogleWorkspaceRecordLimitReached("shared Workspace response budget reached")
            if (
                not isinstance(result, dict)
                or result.get("version") != 1
                or any(
                    result.get(key) != expected
                    for key, expected in {
                        "connection_id": self._id,
                        "customer_id": self._pin["customer_id"],
                        "domain": self._pin["domain"],
                        "operation": operation,
                        "application_name": application_name,
                        "binding_revision": self._pin["binding_revision"],
                    }.items()
                )
                or _time(result.get("start_time")) != start_time
                or _time(result.get("end_time")) != end_time
                or not isinstance(result.get("items"), list)
                or len(result["items"]) > page_size
            ):
                raise ValueError("shared Workspace read response is invalid")
            page = [
                _record(item, customer=self._pin["customer_id"], application=application_name)
                for item in result["items"]
            ]
            if any(not start_time <= _time(item["id"]["time"]) <= end_time for item in page):
                raise ValueError("shared Workspace event falls outside requested interval")
            records.extend(page)
            self._observed_customer |= bool(page)
            cursor = result.get("next_cursor")
            if cursor is not None and (not isinstance(cursor, str) or not 1 <= len(cursor) <= 8192):
                raise ValueError("shared Workspace cursor is invalid")
            if len(records) > limit or cursor and len(records) >= limit:
                raise GoogleWorkspaceRecordLimitReached("shared Workspace record limit reached")
            if not follow_pagination or cursor is None:
                return tuple(records)
            if cursor in seen:
                raise ValueError("shared Workspace cursor repeated")
            seen.add(cursor)
        raise GoogleWorkspaceRecordLimitReached("shared Workspace page limit reached")


class WorkspaceValidatorRouter:
    def __init__(self, native: Any, platform: SharedConnectionsClient | None):
        self._native, self._platform = native, platform

    def validate(self, connection: dict[str, Any]) -> dict[str, Any]:
        if connection.get("credential_type") != CREDENTIAL_TYPE:
            if self._native is None:
                raise ValueError("native Workspace validator is unavailable")
            return self._native.validate(connection)
        # Reuse native plane checks against the mediated Reports protocol.
        reader = SharedWorkspaceReportsClient(connection, client=self._platform)
        operator = GoogleWorkspaceOperator(
            service_account=reader._pin["service_account"],
            oauth_client_id=reader._pin["oauth_client_id"],
            client_factory=lambda _: reader,
        )
        result = GoogleWorkspaceConnectionValidator(operator).validate(connection)
        result["account_id_observed"] = reader.observed_identity
        result["credential_state"] = (
            "passed" if any(item["state"] == "passed" for item in result["results"]) else "failed"
        )
        return result


class WorkspaceCollectorRouter:
    def __init__(self, native: Any, platform: SharedConnectionsClient | None):
        self._native, self._platform = native, platform

    def collect(
        self, *, tenant_id: str, connection: dict[str, Any], repository: Any
    ) -> dict[str, Any]:
        if connection.get("credential_type") != CREDENTIAL_TYPE:
            if self._native is None:
                raise ValueError("native Workspace collector is unavailable")
            return self._native.collect(
                tenant_id=tenant_id, connection=connection, repository=repository
            )
        reader = SharedWorkspaceReportsClient(connection, client=self._platform)
        operator = GoogleWorkspaceOperator(
            service_account=reader._pin["service_account"],
            oauth_client_id=reader._pin["oauth_client_id"],
            client_factory=lambda _: reader,
        )
        return GoogleWorkspaceConnectionCollector(operator).collect(
            tenant_id=tenant_id,
            connection=connection,
            repository=repository,
        )
