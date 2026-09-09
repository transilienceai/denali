"""Bounded Google Workspace AI application and activity collection."""

from __future__ import annotations

import json
import urllib.parse
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from denali.connections.google_workspace import (
    GOOGLE_WORKSPACE_GEMINI_PLANE,
    GOOGLE_WORKSPACE_OAUTH_PLANE,
    GoogleWorkspaceOperator,
)
from denali.connectors.entra_ai import AiSaasCatalog, CatalogMatch
from denali.domain import (
    ActivityBatch,
    ActivityCategory,
    ActivityCorrelation,
    ActivityEntity,
    ActivityEntityRole,
    ActivityOutcome,
    ActivityRecord,
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    Coverage,
    CoverageState,
    Evidence,
    InventoryBatch,
)

CONNECTOR_ID = "denali.google_workspace"
REPORTS_ROOT = "https://admin.googleapis.com"
MAX_REPORT_RECORDS = 20_000


class GoogleWorkspaceRecordLimitReached(RuntimeError):
    """Raised when a bounded report cannot safely claim complete coverage."""


class GoogleWorkspaceReportsClient:
    """Small, bounded Admin Reports client with trusted-host pagination."""

    def __init__(self, credentials: Any, *, timeout: float = 30.0) -> None:
        from google.auth.transport.requests import AuthorizedSession

        self._session = AuthorizedSession(credentials)
        self._timeout = timeout

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
        if not 1 <= max_results <= 1000:
            raise ValueError("Google Workspace max_results must be between 1 and 1000")
        if not 1 <= limit <= MAX_REPORT_RECORDS:
            raise ValueError("Google Workspace report limit is invalid")
        path = f"/admin/reports/v1/activity/users/all/applications/{application_name}"
        params = {
            "startTime": _report_time(start_time),
            "endTime": _report_time(end_time),
            "maxResults": str(max_results),
        }
        url: str | None = f"{REPORTS_ROOT}{path}?{urllib.parse.urlencode(params)}"
        seen: set[str] = set()
        records: list[dict[str, Any]] = []
        while url is not None:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme != "https" or parsed.netloc != "admin.googleapis.com":
                raise ValueError("Google Workspace pagination returned an untrusted URL")
            if url in seen:
                raise ValueError("Google Workspace pagination returned a repeated URL")
            seen.add(url)
            response = self._session.get(url, timeout=self._timeout)
            if response.status_code >= 400:
                raise RuntimeError(
                    f"Google Workspace Reports request failed with HTTP {response.status_code}"
                )
            try:
                payload = response.json()
            except (ValueError, json.JSONDecodeError):
                raise ValueError("Google Workspace Reports returned invalid JSON") from None
            if not isinstance(payload, dict):
                raise ValueError("Google Workspace Reports returned an invalid response")
            items = payload.get("items", [])
            if not isinstance(items, list):
                raise ValueError("Google Workspace Reports returned an invalid items collection")
            for item in items:
                if isinstance(item, dict):
                    records.append(item)
                    if len(records) >= limit:
                        raise GoogleWorkspaceRecordLimitReached(
                            f"Google Workspace collection exceeded the {limit}-record safety limit"
                        )
            if not follow_pagination:
                return tuple(records)
            token = payload.get("nextPageToken")
            if token is None:
                url = None
            elif not isinstance(token, str) or not token:
                raise ValueError("Google Workspace Reports returned an invalid page token")
            else:
                next_params = {**params, "pageToken": token}
                url = f"{REPORTS_ROOT}{path}?{urllib.parse.urlencode(next_params)}"
        return tuple(records)


class GoogleWorkspaceConnector:
    def __init__(
        self,
        *,
        domain: str,
        reports_client: GoogleWorkspaceReportsClient,
        catalog: AiSaasCatalog | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.domain = domain
        self.reports_client = reports_client
        self.catalog = catalog or AiSaasCatalog.default()
        self._now = now or (lambda: datetime.now(UTC))

    def collect(
        self,
        *,
        start_time: datetime,
        end_time: datetime,
        connection_id: str,
    ) -> tuple[InventoryBatch, ActivityBatch]:
        observed_at = self._now()
        activity_scope = (
            f"google-workspace:{self.domain}:{_report_time(start_time)}:{_report_time(end_time)}"
        )
        inventory_scope = f"google-workspace:{self.domain}:observed-ai-applications"
        reports: dict[str, tuple[dict[str, Any], ...]] = {}
        coverage: list[Coverage] = []
        for application_name, plane, label in (
            ("gemini_in_workspace_apps", GOOGLE_WORKSPACE_GEMINI_PLANE, "Gemini activity"),
            ("token", GOOGLE_WORKSPACE_OAUTH_PLANE, "OAuth application activity"),
        ):
            try:
                records = self.reports_client.list(
                    application_name,
                    start_time=start_time,
                    end_time=end_time,
                )
                reports[application_name] = records
                coverage.append(
                    Coverage(
                        plane,
                        CoverageState.COMPLETE,
                        activity_scope,
                        f"Collected {len(records)} {label.lower()} audit records in the "
                        "bounded window.",
                    )
                )
            except Exception as error:
                reports[application_name] = ()
                coverage.append(
                    Coverage(
                        plane,
                        CoverageState.FAILED,
                        activity_scope,
                        f"{label} collection failed ({type(error).__name__}).",
                    )
                )

        assets: dict[str, AssetAssertion] = {}
        activities: dict[str, ActivityRecord] = {}
        gemini_records = reports["gemini_in_workspace_apps"]
        if gemini_records:
            assertion = _gemini_assertion(self.domain, gemini_records[0], observed_at)
            assets[assertion.asset.canonical_key] = assertion
        for record in gemini_records:
            for activity in _gemini_activities(self.domain, record, observed_at):
                activities[activity.source_uid] = activity

        for record in reports["token"]:
            for position, event in enumerate(_events(record)):
                parameters = _parameters(event)
                client_id = _first(parameters, "client_id", "client_id_value")
                app_name = _first(parameters, "app_name", "application_name")
                match = self.catalog.match(app_id=client_id, display_name=app_name)
                if match is None or not client_id:
                    continue
                assertion = _oauth_assertion(
                    self.domain, client_id, app_name, match, record, event, observed_at
                )
                assets[assertion.asset.canonical_key] = assertion
                activity = _oauth_activity(
                    self.domain,
                    record,
                    event,
                    position,
                    client_id,
                    app_name,
                    match,
                    observed_at,
                )
                activities[activity.source_uid] = activity

        return (
            InventoryBatch(
                connector_id=CONNECTOR_ID,
                connection_id=connection_id,
                run_id=f"google-workspace-inventory-{observed_at.isoformat()}",
                scope_key=inventory_scope,
                collected_at=observed_at,
                coverage=tuple(
                    Coverage(item.plane, item.state, inventory_scope, item.detail)
                    for item in coverage
                ),
                assets=tuple(assets.values()),
            ),
            ActivityBatch(
                connector_id=CONNECTOR_ID,
                connection_id=connection_id,
                run_id=f"google-workspace-activity-{observed_at.isoformat()}",
                scope_key=activity_scope,
                collected_at=observed_at,
                coverage=tuple(coverage),
                activities=tuple(activities.values()),
            ),
        )


class GoogleWorkspaceConnectionCollector:
    """Collect one delegated Workspace domain without retaining access tokens."""

    def __init__(
        self,
        operator: GoogleWorkspaceOperator,
        *,
        lookback_hours: int = 24 * 180,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not 1 <= lookback_hours <= 24 * 180:
            raise ValueError("Google Workspace lookback must be between 1 and 4320 hours")
        self._operator = operator
        self._lookback_hours = lookback_hours
        self._now = now or (lambda: datetime.now(UTC))

    def collect(
        self, *, tenant_id: str, connection: dict[str, Any], repository: Any
    ) -> dict[str, Any]:
        end = self._now()
        configuration = connection["configuration"]
        client = self._operator.reports_client(str(configuration["admin_email"]))
        inventory, activity = GoogleWorkspaceConnector(
            domain=str(configuration["domain"]), reports_client=client, now=self._now
        ).collect(
            start_time=end - timedelta(hours=self._lookback_hours),
            end_time=end,
            connection_id=str(connection["id"]),
        )
        inventory_result = repository.ingest(tenant_id, inventory)
        activity_result = repository.ingest_activity(tenant_id, activity)
        complete = sum(item.state is CoverageState.COMPLETE for item in inventory.coverage)
        failed = sum(item.state is CoverageState.FAILED for item in inventory.coverage)
        state = (
            "complete"
            if complete == len(inventory.coverage)
            else "failed"
            if failed == len(inventory.coverage)
            else "partial"
        )
        return {
            "connection_id": str(connection["id"]),
            "state": state,
            "completed_at": self._now().isoformat(),
            "lookback_hours": self._lookback_hours,
            "matched_ai_applications": len(inventory.assets),
            "activity_events": len(activity.activities),
            "coverage_complete": complete,
            "coverage_partial": len(inventory.coverage) - complete - failed,
            "coverage_failed": failed,
            "inventory": inventory_result,
            "activity": activity_result,
        }


def _gemini_ref(domain: str) -> AssetRef:
    return AssetRef(AssetKind.AI_APPLICATION, f"google-workspace:{domain}:application:gemini")


def _oauth_ref(domain: str, client_id: str) -> AssetRef:
    return AssetRef(AssetKind.AI_APPLICATION, f"google-workspace:{domain}:oauth-client:{client_id}")


def _gemini_assertion(domain: str, record: dict[str, Any], observed_at: datetime) -> AssetAssertion:
    return AssetAssertion(
        asset=_gemini_ref(domain),
        coverage_plane=GOOGLE_WORKSPACE_GEMINI_PLANE,
        display_name="Gemini in Google Workspace",
        assertion_type=AssertionType.EXTERNALLY_VERIFIED,
        confidence=1.0,
        evidence=_evidence(record, None, observed_at, "google_workspace_gemini_audit"),
        attributes={
            "provider": "Google Workspace",
            "domain": domain,
            "catalog_name": "Google Gemini",
            "catalog_category": "assistant",
            "catalog_match_method": "native_audit_application",
            "application_name": "gemini_in_workspace_apps",
            "observation_boundary": "bounded_audit_window",
        },
    )


def _oauth_assertion(
    domain: str,
    client_id: str,
    app_name: str | None,
    match: CatalogMatch,
    record: dict[str, Any],
    event: dict[str, Any],
    observed_at: datetime,
) -> AssetAssertion:
    parameters = _parameters(event)
    return AssetAssertion(
        asset=_oauth_ref(domain, client_id),
        coverage_plane=GOOGLE_WORKSPACE_OAUTH_PLANE,
        display_name=app_name or match.entry.name,
        assertion_type=AssertionType.EXTERNALLY_VERIFIED,
        confidence=1.0,
        evidence=_evidence(record, event, observed_at, "google_workspace_oauth_audit"),
        attributes={
            "provider": "Google Workspace",
            "domain": domain,
            "catalog_name": match.entry.name,
            "catalog_category": match.entry.category,
            "catalog_match_method": match.method,
            "catalog_matched_value": match.matched_value,
            "oauth_client_id": client_id,
            "client_type": _first(parameters, "client_type"),
            "scopes": _many(parameters, "scope", "scope_data"),
            "observation_boundary": "bounded_audit_window",
        },
    )


def _gemini_activities(
    domain: str, record: dict[str, Any], observed_at: datetime
) -> tuple[ActivityRecord, ...]:
    activities: list[ActivityRecord] = []
    for position, event in enumerate(_events(record)):
        event_name = str(event.get("name") or "feature_utilization")
        parameters = _parameters(event)
        action = _first(parameters, "action")
        label = action or event_name.replace("_", " ")
        activities.append(
            ActivityRecord(
                source_uid=(
                    f"google-workspace-gemini:{domain}:{_record_uid(record)}:"
                    f"{position}:{event_name}"
                ),
                category=(
                    ActivityCategory.MODEL_INVOCATION
                    if action
                    and any(
                        term in action.casefold() for term in ("generate", "summarize", "write")
                    )
                    else ActivityCategory.OTHER
                ),
                activity_name=f"google.workspace.gemini.{event_name}",
                title=f"Gemini in Workspace: {label}",
                occurred_at=_record_time(record),
                observed_at=observed_at,
                outcome=ActivityOutcome.UNKNOWN,
                provider="Google Workspace",
                account_uid=domain,
                entities=(
                    _actor(record),
                    ActivityEntity(
                        role=ActivityEntityRole.APPLICATION,
                        external_uid="gemini_in_workspace_apps",
                        display_name="Gemini in Google Workspace",
                        asset=_gemini_ref(domain),
                        correlation=ActivityCorrelation.EXACT_IDENTIFIER,
                        confidence=1.0,
                    ),
                ),
                attributes={
                    "event_type": event.get("type"),
                    "action": action,
                    "event_category": _first(parameters, "event_category"),
                    "feature_source": _first(parameters, "feature_source"),
                    "workspace_app": _first(parameters, "app_name", "application_name"),
                },
                evidence=_evidence(record, event, observed_at, "google_workspace_gemini_audit"),
            )
        )
    return tuple(activities)


def _oauth_activity(
    domain: str,
    record: dict[str, Any],
    event: dict[str, Any],
    position: int,
    client_id: str,
    app_name: str | None,
    match: CatalogMatch,
    observed_at: datetime,
) -> ActivityRecord:
    event_name = str(event.get("name") or "activity")
    parameters = _parameters(event)
    return ActivityRecord(
        source_uid=(
            f"google-workspace-token:{domain}:{_record_uid(record)}:{position}:{event_name}"
        ),
        category=(
            ActivityCategory.ADMIN_CHANGE
            if event_name in {"authorize", "deny", "revoke", "request"}
            else ActivityCategory.DATA_ACCESS
        ),
        activity_name=f"google.workspace.oauth.{event_name}",
        title=f"{app_name or match.entry.name}: OAuth {event_name.replace('_', ' ')}",
        occurred_at=_record_time(record),
        observed_at=observed_at,
        outcome=ActivityOutcome.UNKNOWN,
        provider="Google Workspace",
        account_uid=domain,
        entities=(
            _actor(record),
            ActivityEntity(
                role=ActivityEntityRole.APPLICATION,
                external_uid=client_id,
                display_name=app_name or match.entry.name,
                asset=_oauth_ref(domain, client_id),
                correlation=ActivityCorrelation.EXACT_IDENTIFIER,
                confidence=1.0,
                attributes={"catalog_name": match.entry.name},
            ),
        ),
        attributes={
            "event_type": event.get("type"),
            "client_type": _first(parameters, "client_type"),
            "scopes": _many(parameters, "scope", "scope_data"),
        },
        evidence=_evidence(record, event, observed_at, "google_workspace_oauth_audit"),
    )


def _actor(record: dict[str, Any]) -> ActivityEntity:
    actor = record.get("actor") if isinstance(record.get("actor"), dict) else {}
    email = actor.get("email")
    profile_id = actor.get("profileId")
    uid = email if isinstance(email, str) and email else str(profile_id or "unknown")
    return ActivityEntity(
        role=ActivityEntityRole.ACTOR,
        external_uid=uid,
        display_name=email if isinstance(email, str) else None,
        attributes={"identity_source": "google_workspace_audit"},
    )


def _evidence(
    record: dict[str, Any],
    event: dict[str, Any] | None,
    observed_at: datetime,
    source_type: str,
) -> Evidence:
    record_id = record.get("id") if isinstance(record.get("id"), dict) else {}
    payload: dict[str, Any] = {
        "time": record_id.get("time"),
        "uniqueQualifier": record_id.get("uniqueQualifier"),
        "applicationName": record_id.get("applicationName"),
        "customerId": record_id.get("customerId"),
    }
    if event is not None:
        payload.update(
            event_name=event.get("name"),
            event_type=event.get("type"),
            parameters={
                key: value
                for key in (
                    "action",
                    "event_category",
                    "feature_source",
                    "app_name",
                    "application_name",
                    "client_id",
                    "client_type",
                    "scope",
                    "scope_data",
                )
                if (value := _parameter_value(_parameters(event).get(key))) is not None
            },
        )
    return Evidence(
        source_type=source_type,
        locator=(
            "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/"
            f"{record_id.get('applicationName') or 'unknown'}#{_record_uid(record)}"
        ),
        observed_at=observed_at,
        payload=payload,
    )


def _events(record: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    value = record.get("events")
    return (
        tuple(item for item in value if isinstance(item, dict)) if isinstance(value, list) else ()
    )


def _parameters(event: dict[str, Any]) -> dict[str, Any]:
    value = event.get("parameters")
    if not isinstance(value, list):
        return {}
    return {
        str(item["name"]): item
        for item in value
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }


def _parameter_value(parameter: Any) -> Any:
    if not isinstance(parameter, dict):
        return None
    for key in ("value", "intValue", "boolValue", "multiValue"):
        if key in parameter:
            return parameter[key]
    return None


def _first(parameters: dict[str, Any], *names: str) -> str | None:
    for name in names:
        value = _parameter_value(parameters.get(name))
        if isinstance(value, list):
            value = value[0] if value else None
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _many(parameters: dict[str, Any], *names: str) -> list[str]:
    for name in names:
        value = _parameter_value(parameters.get(name))
        if isinstance(value, list):
            return sorted({str(item).strip() for item in value if str(item).strip()})
        if isinstance(value, str):
            return sorted({item for item in value.replace(",", " ").split() if item})
    return []


def _record_uid(record: dict[str, Any]) -> str:
    record_id = record.get("id") if isinstance(record.get("id"), dict) else {}
    return str(record_id.get("uniqueQualifier") or record_id.get("time") or "unknown")


def _record_time(record: dict[str, Any]) -> datetime:
    record_id = record.get("id") if isinstance(record.get("id"), dict) else {}
    value = record_id.get("time")
    if not isinstance(value, str):
        raise ValueError("Google Workspace record has no event time")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Google Workspace event time must include a timezone")
    return parsed.astimezone(UTC)


def _report_time(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("Google Workspace report timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
