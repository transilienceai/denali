"""Microsoft Entra AI application discovery and runtime activity collection.

Catalog matches discover reviewable AI applications. They are not findings. OAuth
grants, application permissions, sign-ins, and directory changes remain independent,
evidence-bearing facts with explicit coverage.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from importlib.resources import files
from typing import Any, Protocol

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

CONNECTOR_ID = "denali.entra_ai"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True, activity=True)
APPLICATION_PLANE = "entra_ai_application_inventory"
SERVICE_PRINCIPAL_PLANE = "entra_service_principal_context"
DELEGATED_GRANT_PLANE = "entra_oauth_delegated_grants"
APPLICATION_PERMISSION_PLANE = "entra_application_permissions"
SIGN_IN_PLANE = "entra_ai_signins"
DIRECTORY_AUDIT_PLANE = "entra_ai_directory_audits"
GRAPH_ROOT = "https://graph.microsoft.com"
MAX_GRAPH_RECORDS = 20_000
MAX_ASSIGNMENTS_PER_APPLICATION = 2_000
GRAPH_FILTER_BATCH_SIZE = 10


class GraphRecordLimitReached(RuntimeError):
    """Raised when a bounded Graph collection cannot be represented as complete."""


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    name: str
    aliases: tuple[str, ...]
    app_ids: tuple[str, ...]
    category: str


@dataclass(frozen=True, slots=True)
class CatalogMatch:
    entry: CatalogEntry
    method: str
    matched_value: str


class AiSaasCatalog:
    def __init__(self, entries: tuple[CatalogEntry, ...]) -> None:
        if not entries:
            raise ValueError("AI SaaS catalog must not be empty")
        self.entries = entries

    @classmethod
    def default(cls) -> AiSaasCatalog:
        path = files("denali.connectors").joinpath("data/ai_saas_catalog.json")
        raw = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, list):
            raise ValueError("AI SaaS catalog root must be a list")
        entries: list[CatalogEntry] = []
        for item in raw:
            if not isinstance(item, dict):
                raise ValueError("AI SaaS catalog entries must be objects")
            name = _required("catalog name", item.get("name"))
            category = _required("catalog category", item.get("category"))
            aliases = _string_tuple(item.get("aliases"))
            app_ids = tuple(value.casefold() for value in _string_tuple(item.get("app_ids")))
            if not aliases and not app_ids:
                raise ValueError(f"catalog entry {name} has no identifiers")
            entries.append(CatalogEntry(name, aliases, app_ids, category))
        return cls(tuple(entries))

    def match(self, *, app_id: str | None, display_name: str | None) -> CatalogMatch | None:
        normalized_id = app_id.casefold() if isinstance(app_id, str) else None
        if normalized_id:
            for entry in self.entries:
                if normalized_id in entry.app_ids:
                    return CatalogMatch(entry, "exact_app_id", app_id or normalized_id)
        if not isinstance(display_name, str) or not display_name.strip():
            return None
        for entry in self.entries:
            for alias in entry.aliases:
                pattern = rf"(?<![\w]){re.escape(alias)}(?![\w])"
                if re.search(pattern, display_name, flags=re.IGNORECASE):
                    return CatalogMatch(entry, "display_name_alias", alias)
        return None


class GraphClient(Protocol):
    def list(
        self, path: str, *, params: dict[str, str] | None = None, limit: int = MAX_GRAPH_RECORDS
    ) -> tuple[dict[str, Any], ...]: ...


class MicrosoftGraphClient:
    """Small bounded Graph client whose errors never include response bodies or tokens."""

    def __init__(self, access_token: str, *, timeout: float = 30.0) -> None:
        self.access_token = _required("access_token", access_token)
        self.timeout = timeout

    def list(
        self, path: str, *, params: dict[str, str] | None = None, limit: int = MAX_GRAPH_RECORDS
    ) -> tuple[dict[str, Any], ...]:
        if not path.startswith("/"):
            raise ValueError("Graph path must begin with /")
        query = urllib.parse.urlencode(params or {}, safe=",:$()' ")
        url = f"{GRAPH_ROOT}{path}" + (f"?{query}" if query else "")
        records: list[dict[str, Any]] = []
        seen_urls: set[str] = set()
        while url:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme != "https" or parsed.netloc != "graph.microsoft.com":
                raise ValueError("Graph pagination returned an untrusted next link")
            if url in seen_urls:
                raise ValueError("Graph pagination returned a repeated next link")
            seen_urls.add(url)
            request = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {self.access_token}",
                    "Accept": "application/json",
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    payload = json.loads(response.read())
            except urllib.error.HTTPError as error:
                raise RuntimeError(
                    f"Microsoft Graph request failed with HTTP {error.code}"
                ) from None
            except urllib.error.URLError as error:
                raise RuntimeError(
                    f"Microsoft Graph request failed: {type(error.reason).__name__}"
                ) from None
            if not isinstance(payload, dict) or not isinstance(payload.get("value"), list):
                raise ValueError("Microsoft Graph returned an invalid collection response")
            for item in payload["value"]:
                if isinstance(item, dict):
                    records.append(item)
                    if len(records) >= limit:
                        raise GraphRecordLimitReached(
                            f"Microsoft Graph collection exceeded the {limit}-record safety limit"
                        )
            next_link = payload.get("@odata.nextLink")
            if next_link is None:
                break
            if not isinstance(next_link, str) or not next_link:
                raise ValueError("Microsoft Graph returned an invalid next link")
            url = next_link
        return tuple(records)


class EntraAiConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        *,
        entra_tenant_id: str,
        graph_client: GraphClient,
        catalog: AiSaasCatalog | None = None,
    ) -> None:
        self.entra_tenant_id = _required("entra_tenant_id", entra_tenant_id)
        self.graph_client = graph_client
        self.catalog = catalog or AiSaasCatalog.default()
        self._service_principals: dict[str, dict[str, Any]] | None = None
        self._matched: dict[str, tuple[dict[str, Any], CatalogMatch]] | None = None

    def collect_inventory(self, *, connection_id: str | None = None) -> InventoryBatch:
        observed_at = datetime.now(UTC)
        connection = connection_id or f"entra:{self.entra_tenant_id}"
        scope = f"entra:{self.entra_tenant_id}:enterprise-applications"
        run_id = f"entra-ai-inventory-{observed_at.isoformat()}"
        coverage: list[Coverage] = []
        assets: dict[AssetRef, AssetAssertion] = {}
        relationships: list[RelationshipAssertion] = []
        delegated_counts: dict[str, int] = {}
        application_permission_counts: dict[str, int] = {}
        delegated_scopes: dict[str, set[str]] = {}
        delegated_consent_types: dict[str, set[str]] = {}
        delegated_principal_ids: dict[str, set[str]] = {}

        try:
            service_principals, matched = self._discover()
        except Exception as error:
            detail = _safe_failure("servicePrincipals", error)
            return InventoryBatch(
                connector_id=self.connector_id,
                connection_id=connection,
                run_id=run_id,
                scope_key=scope,
                collected_at=observed_at,
                coverage=tuple(
                    Coverage(plane, CoverageState.FAILED, scope, detail)
                    for plane in (
                        APPLICATION_PLANE,
                        SERVICE_PRINCIPAL_PLANE,
                        DELEGATED_GRANT_PLANE,
                        APPLICATION_PERMISSION_PLANE,
                    )
                ),
            )

        coverage.extend(
            (
                Coverage(
                    APPLICATION_PLANE,
                    CoverageState.COMPLETE,
                    scope,
                    f"Matched {len(matched)} AI applications from "
                    f"{len(service_principals)} enterprise service principals.",
                ),
                Coverage(
                    SERVICE_PRINCIPAL_PLANE,
                    CoverageState.COMPLETE,
                    scope,
                    "Service-principal identities needed to explain matched applications "
                    "and their permission targets.",
                ),
            )
        )

        for app_id, (service_principal, match) in matched.items():
            app_ref = _application_ref(self.entra_tenant_id, app_id)
            identity_ref = _service_principal_ref(
                self.entra_tenant_id, _required("service principal id", service_principal.get("id"))
            )
            evidence = _sp_evidence(service_principal, observed_at)
            assets[app_ref] = AssetAssertion(
                asset=app_ref,
                coverage_plane=APPLICATION_PLANE,
                display_name=_display_name(service_principal, match.entry.name),
                assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                confidence=1.0,
                evidence=evidence,
                attributes={
                    "provider": "Microsoft Entra",
                    "tenant_id": self.entra_tenant_id,
                    "catalog_name": match.entry.name,
                    "catalog_category": match.entry.category,
                    "catalog_match_method": match.method,
                    "catalog_matched_value": match.matched_value,
                    "app_id": app_id,
                    "service_principal_id": service_principal["id"],
                    "account_enabled": service_principal.get("accountEnabled"),
                    "publisher_name": service_principal.get("publisherName"),
                    "verified_publisher": _verified_publisher(service_principal),
                    "sign_in_audience": service_principal.get("signInAudience"),
                },
            )
            assets[identity_ref] = _identity_assertion(
                self.entra_tenant_id,
                service_principal,
                observed_at,
                APPLICATION_PLANE,
                role="enterprise_application_service_principal",
            )
            relationships.append(
                RelationshipAssertion(
                    source=app_ref,
                    target=identity_ref,
                    coverage_plane=APPLICATION_PLANE,
                    kind=RelationshipKind.RUNS_AS,
                    assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                    confidence=1.0,
                    evidence=evidence,
                    attributes={"provider": "Microsoft Entra"},
                    principal_ref=identity_ref,
                )
            )

        grant_state = CoverageState.COMPLETE
        grant_detail = "Collected delegated OAuth grants for matched AI applications."
        try:
            grants = self.graph_client.list(
                "/v1.0/oauth2PermissionGrants",
                params={"$select": "id,clientId,consentType,principalId,resourceId,scope"},
            )
            matched_object_ids = {
                str(item[0].get("id")): app_id for app_id, item in matched.items()
            }
            for grant in grants:
                app_id = matched_object_ids.get(str(grant.get("clientId")))
                target = service_principals.get(str(grant.get("resourceId")))
                if not app_id or target is None:
                    continue
                delegated_counts[app_id] = delegated_counts.get(app_id, 0) + 1
                delegated_scopes.setdefault(app_id, set()).update(_scopes(grant.get("scope")))
                consent_type = grant.get("consentType")
                if isinstance(consent_type, str) and consent_type:
                    delegated_consent_types.setdefault(app_id, set()).add(consent_type)
                principal_id = grant.get("principalId")
                if isinstance(principal_id, str) and principal_id:
                    delegated_principal_ids.setdefault(app_id, set()).add(principal_id)
                target_ref = _ensure_context_identity(
                    assets, self.entra_tenant_id, target, observed_at
                )
                relationships.append(
                    RelationshipAssertion(
                        source=_application_ref(self.entra_tenant_id, app_id),
                        target=target_ref,
                        coverage_plane=DELEGATED_GRANT_PLANE,
                        kind=RelationshipKind.CONNECTS_TO,
                        assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                        confidence=1.0,
                        evidence=_grant_evidence(grant, observed_at, "delegated_oauth"),
                        attributes={
                            "authorization_type": "delegated_oauth",
                            "consent_type": grant.get("consentType"),
                            "scopes": _scopes(grant.get("scope")),
                            "user_context_required": True,
                        },
                    )
                )
        except Exception as error:
            grant_state = CoverageState.FAILED
            grant_detail = _safe_failure("oauth2PermissionGrants", error)
        coverage.append(Coverage(DELEGATED_GRANT_PLANE, grant_state, scope, grant_detail))

        assignment_failures: list[str] = []
        for app_id, (service_principal, _) in matched.items():
            object_id = str(service_principal["id"])
            try:
                assignments = self.graph_client.list(
                    f"/v1.0/servicePrincipals/{urllib.parse.quote(object_id)}/appRoleAssignments",
                    params={"$select": "id,appRoleId,principalId,resourceId,createdDateTime"},
                    limit=MAX_ASSIGNMENTS_PER_APPLICATION,
                )
            except Exception as error:
                assignment_failures.append(_safe_failure(object_id, error))
                continue
            source_ref = _application_ref(self.entra_tenant_id, app_id)
            principal_ref = _service_principal_ref(self.entra_tenant_id, object_id)
            for assignment in assignments:
                target = service_principals.get(str(assignment.get("resourceId")))
                if target is None:
                    continue
                application_permission_counts[app_id] = (
                    application_permission_counts.get(app_id, 0) + 1
                )
                target_ref = _ensure_context_identity(
                    assets, self.entra_tenant_id, target, observed_at
                )
                relationships.append(
                    RelationshipAssertion(
                        source=source_ref,
                        target=target_ref,
                        coverage_plane=APPLICATION_PERMISSION_PLANE,
                        kind=RelationshipKind.CAN_INVOKE,
                        assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                        confidence=1.0,
                        evidence=_grant_evidence(assignment, observed_at, "application_role"),
                        attributes={
                            "authorization_type": "application_permission",
                            "app_role_id": assignment.get("appRoleId"),
                            "user_context_required": False,
                        },
                        principal_ref=principal_ref,
                    )
                )
        assignment_state = CoverageState.COMPLETE
        assignment_detail = "Collected application-role assignments for matched AI applications."
        if assignment_failures:
            assignment_state = CoverageState.PARTIAL
            assignment_detail = (
                f"{len(assignment_failures)} matched applications could not be fully read. "
                + " ".join(assignment_failures)
            )[:4_000]
        coverage.append(
            Coverage(APPLICATION_PERMISSION_PLANE, assignment_state, scope, assignment_detail)
        )
        for app_id in matched:
            app_ref = _application_ref(self.entra_tenant_id, app_id)
            assertion = assets[app_ref]
            assets[app_ref] = replace(
                assertion,
                attributes={
                    **assertion.attributes,
                    "delegated_grant_count": delegated_counts.get(app_id, 0),
                    "application_permission_count": application_permission_counts.get(app_id, 0),
                    "delegated_scopes": sorted(delegated_scopes.get(app_id, set())),
                    "delegated_consent_types": sorted(delegated_consent_types.get(app_id, set())),
                    "delegated_principal_ids": sorted(delegated_principal_ids.get(app_id, set())),
                },
            )
        return InventoryBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=run_id,
            scope_key=scope,
            collected_at=observed_at,
            coverage=tuple(coverage),
            assets=tuple(assets.values()),
            relationships=tuple(relationships),
        )

    def collect_activity(
        self,
        *,
        start_time: datetime,
        end_time: datetime,
        connection_id: str | None = None,
    ) -> ActivityBatch:
        start = _aware("start_time", start_time)
        end = _aware("end_time", end_time)
        if start >= end:
            raise ValueError("start_time must be earlier than end_time")
        observed_at = datetime.now(UTC)
        connection = connection_id or f"entra:{self.entra_tenant_id}"
        scope = f"entra:{self.entra_tenant_id}:audit:{start.isoformat()}:{end.isoformat()}"
        run_id = f"entra-ai-activity-{observed_at.isoformat()}"
        try:
            _, matched = self._discover()
        except Exception as error:
            detail = _safe_failure("servicePrincipals", error)
            return ActivityBatch(
                connector_id=self.connector_id,
                connection_id=connection,
                run_id=run_id,
                scope_key=scope,
                collected_at=observed_at,
                coverage=(
                    Coverage(SIGN_IN_PLANE, CoverageState.FAILED, scope, detail),
                    Coverage(DIRECTORY_AUDIT_PLANE, CoverageState.FAILED, scope, detail),
                ),
            )

        activities: list[ActivityRecord] = []
        coverage: list[Coverage] = []
        app_by_id = matched
        object_to_app = {
            str(service_principal.get("id")): app_id
            for app_id, (service_principal, _) in matched.items()
        }
        time_filter = (
            f"createdDateTime ge {_odata_time(start)} and createdDateTime lt {_odata_time(end)}"
        )
        sign_ins_by_id: dict[str, dict[str, Any]] = {}
        sign_in_failures: list[str] = []
        for app_ids in _batches(tuple(app_by_id), GRAPH_FILTER_BATCH_SIZE):
            app_filter = " or ".join(f"appId eq {_odata_literal(app_id)}" for app_id in app_ids)
            try:
                sign_ins = self.graph_client.list(
                    "/v1.0/auditLogs/signIns",
                    params={
                        "$filter": f"{time_filter} and ({app_filter})",
                        "$select": (
                            "id,createdDateTime,userId,userPrincipalName,appId,appDisplayName,"
                            "resourceId,resourceDisplayName,clientAppUsed,"
                            "conditionalAccessStatus,status,correlationId,isInteractive"
                        ),
                        "$orderby": "createdDateTime desc",
                    },
                )
                for sign_in in sign_ins:
                    source_id = sign_in.get("id")
                    if isinstance(source_id, str) and source_id:
                        sign_ins_by_id[source_id] = sign_in
            except Exception as error:
                sign_in_failures.append(_safe_failure("auditLogs/signIns", error))
        sign_in_start = len(activities)
        for sign_in in sign_ins_by_id.values():
            app_id = str(sign_in.get("appId") or "")
            matched_app = app_by_id.get(app_id)
            if matched_app is not None:
                activities.append(
                    _sign_in_activity(self.entra_tenant_id, sign_in, matched_app[1], observed_at)
                )
        sign_in_count = len(activities) - sign_in_start
        sign_in_state = CoverageState.PARTIAL if sign_in_failures else CoverageState.COMPLETE
        sign_in_detail = (
            f"Collected {sign_in_count} catalog-matched AI application sign-ins. "
            "No IP address or authentication token is retained."
        )
        if sign_in_failures:
            sign_in_detail += (
                f" {len(sign_in_failures)} of "
                f"{len(tuple(_batches(tuple(app_by_id), GRAPH_FILTER_BATCH_SIZE)))} "
                "application batches could not be read."
            )
        coverage.append(Coverage(SIGN_IN_PLANE, sign_in_state, scope, sign_in_detail))

        audit_start = len(activities)
        audit_filter = (
            f"activityDateTime ge {_odata_time(start)} and activityDateTime lt {_odata_time(end)}"
        )
        audits_by_id: dict[str, dict[str, Any]] = {}
        audit_failure: str | None = None
        try:
            audits = self.graph_client.list(
                "/v1.0/auditLogs/directoryAudits",
                params={
                    "$filter": f"{audit_filter} and category eq 'ApplicationManagement'",
                    "$select": (
                        "id,activityDateTime,activityDisplayName,category,result,"
                        "resultReason,initiatedBy,targetResources,correlationId"
                    ),
                    "$orderby": "activityDateTime desc",
                },
            )
            for audit in audits:
                source_id = audit.get("id")
                if isinstance(source_id, str) and source_id:
                    audits_by_id[source_id] = audit
        except Exception as error:
            audit_failure = _safe_failure("auditLogs/directoryAudits", error)
        for audit in audits_by_id.values():
            app_id = _audit_app_id(audit, object_to_app)
            if app_id is not None:
                activities.append(
                    _directory_audit_activity(self.entra_tenant_id, audit, app_id, observed_at)
                )
        audit_count = len(activities) - audit_start
        audit_state = CoverageState.FAILED if audit_failure else CoverageState.COMPLETE
        audit_detail = (
            f"Collected {audit_count} directory changes targeting catalog-matched AI applications."
        )
        if audit_failure:
            audit_detail = audit_failure
        coverage.append(Coverage(DIRECTORY_AUDIT_PLANE, audit_state, scope, audit_detail))
        return ActivityBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=run_id,
            scope_key=scope,
            collected_at=observed_at,
            coverage=tuple(coverage),
            activities=tuple(activities),
        )

    def _discover(
        self,
    ) -> tuple[dict[str, dict[str, Any]], dict[str, tuple[dict[str, Any], CatalogMatch]]]:
        if self._service_principals is not None and self._matched is not None:
            return self._service_principals, self._matched
        records = self.graph_client.list(
            "/v1.0/servicePrincipals",
            params={
                "$select": (
                    "id,appId,displayName,accountEnabled,servicePrincipalType,publisherName,"
                    "verifiedPublisher,homepage,servicePrincipalNames,signInAudience,"
                    "appOwnerOrganizationId,tags"
                )
            },
        )
        by_object_id: dict[str, dict[str, Any]] = {}
        matched: dict[str, tuple[dict[str, Any], CatalogMatch]] = {}
        for record in records:
            object_id = record.get("id")
            app_id = record.get("appId")
            if not isinstance(object_id, str) or not object_id:
                continue
            by_object_id[object_id] = record
            if not isinstance(app_id, str) or not app_id:
                continue
            match = self.catalog.match(app_id=app_id, display_name=record.get("displayName"))
            if match is not None:
                matched[app_id] = (record, match)
        self._service_principals = by_object_id
        self._matched = matched
        return by_object_id, matched


def _application_ref(tenant_id: str, app_id: str) -> AssetRef:
    return AssetRef(AssetKind.AI_APPLICATION, f"entra:{tenant_id}:application:{app_id}")


def _service_principal_ref(tenant_id: str, object_id: str) -> AssetRef:
    return AssetRef(AssetKind.IDENTITY, f"entra:{tenant_id}:service-principal:{object_id}")


def _identity_assertion(
    tenant_id: str,
    record: dict[str, Any],
    observed_at: datetime,
    plane: str,
    *,
    role: str,
) -> AssetAssertion:
    return AssetAssertion(
        asset=_service_principal_ref(
            tenant_id, _required("service principal id", record.get("id"))
        ),
        coverage_plane=plane,
        display_name=_display_name(record, "Microsoft Entra service principal"),
        assertion_type=AssertionType.EXTERNALLY_VERIFIED,
        confidence=1.0,
        evidence=_sp_evidence(record, observed_at),
        attributes={
            "identity_type": "service_principal",
            "role": role,
            "app_id": record.get("appId"),
            "account_enabled": record.get("accountEnabled"),
            "service_principal_type": record.get("servicePrincipalType"),
            "publisher_name": record.get("publisherName"),
            "verified_publisher": _verified_publisher(record),
        },
    )


def _ensure_context_identity(
    assets: dict[AssetRef, AssetAssertion],
    tenant_id: str,
    record: dict[str, Any],
    observed_at: datetime,
) -> AssetRef:
    object_id = _required("service principal id", record.get("id"))
    ref = _service_principal_ref(tenant_id, object_id)
    if ref not in assets:
        assets[ref] = _identity_assertion(
            tenant_id,
            record,
            observed_at,
            SERVICE_PRINCIPAL_PLANE,
            role="permission_resource_service_principal",
        )
    return ref


def _sp_evidence(record: dict[str, Any], observed_at: datetime) -> Evidence:
    object_id = _required("service principal id", record.get("id"))
    return Evidence(
        source_type="microsoft_graph_service_principal",
        locator=f"https://graph.microsoft.com/v1.0/servicePrincipals/{object_id}",
        observed_at=observed_at,
        payload={
            key: record.get(key)
            for key in (
                "id",
                "appId",
                "displayName",
                "accountEnabled",
                "servicePrincipalType",
                "publisherName",
                "verifiedPublisher",
                "signInAudience",
                "appOwnerOrganizationId",
            )
        },
    )


def _grant_evidence(record: dict[str, Any], observed_at: datetime, source_type: str) -> Evidence:
    record_id = _required("grant id", record.get("id"))
    allowed = (
        "id",
        "clientId",
        "consentType",
        "principalId",
        "resourceId",
        "scope",
        "appRoleId",
        "createdDateTime",
    )
    return Evidence(
        source_type=f"microsoft_graph_{source_type}",
        locator=f"https://graph.microsoft.com/v1.0/directoryObjects/{record_id}",
        observed_at=observed_at,
        payload={key: record.get(key) for key in allowed if key in record},
    )


def _sign_in_activity(
    tenant_id: str,
    record: dict[str, Any],
    match: CatalogMatch,
    observed_at: datetime,
) -> ActivityRecord:
    source_uid = _required("sign-in id", record.get("id"))
    occurred_at = _parse_time(record.get("createdDateTime"))
    app_id = _required("sign-in appId", record.get("appId"))
    app_name = _display_name(record, match.entry.name, key="appDisplayName")
    status = record.get("status") if isinstance(record.get("status"), dict) else {}
    error_code = status.get("errorCode")
    outcome = (
        ActivityOutcome.UNKNOWN
        if error_code is None
        else ActivityOutcome.SUCCESS
        if error_code in (0, "0")
        else ActivityOutcome.FAILURE
    )
    entities: list[ActivityEntity] = [
        ActivityEntity(
            role=ActivityEntityRole.APPLICATION,
            external_uid=app_id,
            display_name=app_name,
            asset=_application_ref(tenant_id, app_id),
            correlation=ActivityCorrelation.EXACT_IDENTIFIER,
            confidence=1.0,
            attributes={"catalog_name": match.entry.name},
        )
    ]
    user_id = record.get("userId")
    user_name = record.get("userPrincipalName")
    actor_uid = user_id if isinstance(user_id, str) and user_id else user_name
    if isinstance(actor_uid, str) and actor_uid:
        entities.append(
            ActivityEntity(
                role=ActivityEntityRole.ACTOR,
                external_uid=actor_uid,
                display_name=user_name if isinstance(user_name, str) else None,
                attributes={"identity_source": "entra_sign_in"},
            )
        )
    return ActivityRecord(
        source_uid=f"entra-signin:{source_uid}",
        category=ActivityCategory.AI_APP_SIGN_IN,
        activity_name="entra.auditLogs.signIns",
        title=f"{app_name} sign-in {_outcome_verb(outcome)}",
        occurred_at=occurred_at,
        observed_at=observed_at,
        outcome=outcome,
        provider="Microsoft Entra",
        account_uid=tenant_id,
        trace_uid=_optional_string(record.get("correlationId")),
        entities=tuple(entities),
        attributes={
            "client_app_used": record.get("clientAppUsed"),
            "conditional_access_status": record.get("conditionalAccessStatus"),
            "interactive": record.get("isInteractive"),
            "error_code": error_code,
            "failure_reason": status.get("failureReason"),
        },
        evidence=Evidence(
            source_type="microsoft_graph_sign_in",
            locator=f"https://graph.microsoft.com/v1.0/auditLogs/signIns/{source_uid}",
            observed_at=observed_at,
            payload={
                "id": source_uid,
                "createdDateTime": record.get("createdDateTime"),
                "userId": user_id,
                "userPrincipalName": user_name,
                "appId": app_id,
                "appDisplayName": record.get("appDisplayName"),
                "resourceId": record.get("resourceId"),
                "resourceDisplayName": record.get("resourceDisplayName"),
                "clientAppUsed": record.get("clientAppUsed"),
                "conditionalAccessStatus": record.get("conditionalAccessStatus"),
                "status": status,
                "correlationId": record.get("correlationId"),
                "isInteractive": record.get("isInteractive"),
            },
        ),
    )


def _audit_app_id(
    audit: dict[str, Any],
    object_to_app: dict[str, str],
) -> str | None:
    """Return an app only when Graph supplies its exact service-principal object ID.

    Display names are not identities. A tenant may contain many service principals
    with the same Copilot or SaaS display name, and an Application audit target is
    not interchangeable with a ServicePrincipal target.
    """
    targets = audit.get("targetResources")
    if not isinstance(targets, list):
        return None
    for target in targets:
        if not isinstance(target, dict):
            continue
        target_id = target.get("id")
        if isinstance(target_id, str) and target_id in object_to_app:
            return object_to_app[target_id]
    return None


def _directory_audit_activity(
    tenant_id: str,
    record: dict[str, Any],
    app_id: str,
    observed_at: datetime,
) -> ActivityRecord:
    source_uid = _required("directory audit id", record.get("id"))
    occurred_at = _parse_time(record.get("activityDateTime"))
    activity_name = _required("directory audit activity", record.get("activityDisplayName"))
    targets = (
        record.get("targetResources") if isinstance(record.get("targetResources"), list) else []
    )
    app_name = next(
        (
            item.get("displayName")
            for item in targets
            if isinstance(item, dict) and isinstance(item.get("displayName"), str)
        ),
        app_id,
    )
    initiated = record.get("initiatedBy") if isinstance(record.get("initiatedBy"), dict) else {}
    actor = initiated.get("user") or initiated.get("app")
    entities: list[ActivityEntity] = [
        ActivityEntity(
            role=ActivityEntityRole.APPLICATION,
            external_uid=app_id,
            display_name=app_name,
            asset=_application_ref(tenant_id, app_id),
            correlation=ActivityCorrelation.EXACT_IDENTIFIER,
            confidence=1.0,
        )
    ]
    if isinstance(actor, dict):
        actor_uid = actor.get("id") or actor.get("userPrincipalName") or actor.get("displayName")
        if isinstance(actor_uid, str) and actor_uid:
            entities.append(
                ActivityEntity(
                    role=ActivityEntityRole.ACTOR,
                    external_uid=actor_uid,
                    display_name=_optional_string(
                        actor.get("userPrincipalName") or actor.get("displayName")
                    ),
                    attributes={"identity_source": "entra_directory_audit"},
                )
            )
    result = str(record.get("result") or "").casefold()
    outcome = (
        ActivityOutcome.SUCCESS
        if result == "success"
        else (ActivityOutcome.FAILURE if result == "failure" else ActivityOutcome.UNKNOWN)
    )
    safe_targets = [
        {key: target.get(key) for key in ("id", "displayName", "type")}
        for target in targets[:20]
        if isinstance(target, dict)
    ]
    safe_initiator = _safe_initiator(initiated)
    return ActivityRecord(
        source_uid=f"entra-audit:{source_uid}",
        category=ActivityCategory.ADMIN_CHANGE,
        activity_name="entra.auditLogs.directoryAudits",
        title=f"{activity_name}: {app_name}",
        occurred_at=occurred_at,
        observed_at=observed_at,
        outcome=outcome,
        provider="Microsoft Entra",
        account_uid=tenant_id,
        trace_uid=_optional_string(record.get("correlationId")),
        entities=tuple(entities),
        attributes={
            "activity_operation": activity_name,
            "correlation_id": record.get("correlationId"),
            "directory_category": record.get("category"),
            "result": record.get("result"),
            "result_reason": record.get("resultReason"),
        },
        evidence=Evidence(
            source_type="microsoft_graph_directory_audit",
            locator=f"https://graph.microsoft.com/v1.0/auditLogs/directoryAudits/{source_uid}",
            observed_at=observed_at,
            payload={
                "id": source_uid,
                "activityDateTime": record.get("activityDateTime"),
                "activityDisplayName": activity_name,
                "category": record.get("category"),
                "result": record.get("result"),
                "resultReason": record.get("resultReason"),
                "initiatedBy": safe_initiator,
                "targetResources": safe_targets,
                "correlationId": record.get("correlationId"),
            },
        ),
    )


def _safe_initiator(initiated: dict[str, Any]) -> dict[str, Any]:
    """Retain only the identity fields used to derive the displayed actor."""
    output: dict[str, Any] = {}
    for kind in ("user", "app"):
        value = initiated.get(kind)
        if isinstance(value, dict):
            output[kind] = {
                key: value.get(key)
                for key in ("id", "userPrincipalName", "displayName", "appId")
                if key in value
            }
    return output


def _outcome_verb(outcome: ActivityOutcome) -> str:
    if outcome is ActivityOutcome.SUCCESS:
        return "succeeded"
    if outcome is ActivityOutcome.FAILURE:
        return "failed"
    return "outcome unknown"


def acquire_graph_token(
    *, tenant_id: str, client_id: str, client_secret: str, timeout: float = 30.0
) -> str:
    url = f"https://login.microsoftonline.com/{urllib.parse.quote(tenant_id)}/oauth2/v2.0/token"
    body = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        }
    ).encode()
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as error:
        raise RuntimeError(
            f"Microsoft identity token request failed with HTTP {error.code}"
        ) from None
    except urllib.error.URLError as error:
        raise RuntimeError(
            f"Microsoft identity token request failed: {type(error.reason).__name__}"
        ) from None
    token = payload.get("access_token") if isinstance(payload, dict) else None
    return _required("Microsoft identity access token", token)


def scan_main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Collect Entra AI application inventory, permissions, and runtime observations"
        )
    )
    parser.add_argument(
        "--entra-tenant-id",
        default=os.environ.get("DENALI_ENTRA_TENANT_ID") or os.environ.get("ENTRA_TENANT_ID"),
    )
    parser.add_argument(
        "--client-id",
        default=os.environ.get("DENALI_ENTRA_CLIENT_ID") or os.environ.get("ENTRA_CLIENT_ID"),
    )
    parser.add_argument("--connection-id")
    parser.add_argument("--lookback-hours", type=int, default=24 * 7)
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
        help="Denali workspace tenant id",
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    secret = os.environ.get("DENALI_ENTRA_CLIENT_SECRET") or os.environ.get("ENTRA_CLIENT_SECRET")
    if not args.entra_tenant_id:
        parser.error("--entra-tenant-id or DENALI_ENTRA_TENANT_ID is required")
    if not args.client_id:
        parser.error("--client-id or DENALI_ENTRA_CLIENT_ID is required")
    if not secret:
        parser.error("DENALI_ENTRA_CLIENT_SECRET is required")
    if not args.dsn:
        parser.error("--dsn or DENALI_DSN is required")
    if not 1 <= args.lookback_hours <= 24 * 90:
        parser.error("--lookback-hours must be between 1 and 2160")
    token = acquire_graph_token(
        tenant_id=args.entra_tenant_id,
        client_id=args.client_id,
        client_secret=secret,
    )
    connector = EntraAiConnector(
        entra_tenant_id=args.entra_tenant_id,
        graph_client=MicrosoftGraphClient(token),
    )
    inventory = connector.collect_inventory(connection_id=args.connection_id)
    end_time = datetime.now(UTC)
    activity = connector.collect_activity(
        start_time=end_time - timedelta(hours=args.lookback_hours),
        end_time=end_time,
        connection_id=args.connection_id,
    )
    migrate(args.dsn)
    repository = PostgresInventoryRepository(args.dsn)
    inventory_result = repository.ingest(args.tenant_id, inventory)
    activity_result = repository.ingest_activity(args.tenant_id, activity)
    states = [item.state for item in (*inventory.coverage, *activity.coverage)]
    print(
        json.dumps(
            {
                "inventory": inventory_result,
                "activity": activity_result,
                "matched_ai_applications": sum(
                    1 for item in inventory.assets if item.asset.kind is AssetKind.AI_APPLICATION
                ),
                "coverage": [
                    {"plane": item.plane, "state": item.state.value, "detail": item.detail}
                    for item in (*inventory.coverage, *activity.coverage)
                ],
                "scope": inventory.scope_key,
            }
        )
    )
    if any(state is not CoverageState.COMPLETE for state in states):
        raise SystemExit(2)


def _verified_publisher(record: dict[str, Any]) -> str | None:
    publisher = record.get("verifiedPublisher")
    if not isinstance(publisher, dict):
        return None
    return _optional_string(publisher.get("displayName"))


def _display_name(record: dict[str, Any], fallback: str, *, key: str = "displayName") -> str:
    value = record.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def _scopes(value: Any) -> list[str]:
    return sorted(set(value.split())) if isinstance(value, str) else []


def _string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError("catalog string lists must contain only strings")
    return tuple(item.strip() for item in value if item.strip())


def _required(label: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be non-empty")
    return value.strip()


def _optional_string(value: Any) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _aware(label: str, value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _parse_time(value: Any) -> datetime:
    text = _required("timestamp", value)
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


def _odata_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _odata_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _batches(values: tuple[str, ...], size: int) -> tuple[tuple[str, ...], ...]:
    if size < 1:
        raise ValueError("batch size must be positive")
    return tuple(values[index : index + size] for index in range(0, len(values), size))


def _safe_failure(operation: str, error: Exception) -> str:
    message = str(error)
    safe = message if message.startswith("Microsoft Graph request failed") else type(error).__name__
    return (
        f"{operation} could not be collected ({safe}). Missing permission, licensing, or "
        "source failure is not an empty result."
    )
