from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from denali.connectors.entra_ai import (
    APPLICATION_PERMISSION_PLANE,
    DELEGATED_GRANT_PLANE,
    DIRECTORY_AUDIT_PLANE,
    SIGN_IN_PLANE,
    AiSaasCatalog,
    CatalogEntry,
    EntraAiConnector,
    MicrosoftGraphClient,
)
from denali.domain import (
    ActivityCategory,
    ActivityCorrelation,
    ActivityEntityRole,
    AssetKind,
    CoverageState,
    RelationshipKind,
)

TENANT = "5519d103-66f6-4b0d-979f-35c233b454ed"
START = datetime(2026, 8, 26, tzinfo=UTC)
END = datetime(2026, 8, 27, tzinfo=UTC)


class FakeGraph:
    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.calls: list[str] = []
        self.requests: list[tuple[str, dict[str, str]]] = []

    def list(
        self,
        path: str,
        *,
        params: dict[str, str] | None = None,
        limit: int = 20_000,
        follow_pagination: bool = True,
    ) -> tuple[dict[str, Any], ...]:
        del limit, follow_pagination
        self.calls.append(path)
        self.requests.append((path, dict(params or {})))
        response = self.responses.get(path, ())
        if isinstance(response, Exception):
            raise response
        return tuple(response)


def test_graph_validation_probe_does_not_follow_a_next_link(monkeypatch) -> None:
    requested_urls: list[str] = []

    class FakeResponse:
        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return (
                b'{"value":[{"id":"first"}],"@odata.nextLink":'
                b'"https://graph.microsoft.com/v1.0/servicePrincipals?$skiptoken=next"}'
            )

    def urlopen(request: Any, *, timeout: float) -> FakeResponse:
        del timeout
        requested_urls.append(request.full_url)
        return FakeResponse()

    monkeypatch.setattr("denali.connectors.entra_ai.urllib.request.urlopen", urlopen)
    graph = MicrosoftGraphClient("short-lived-fixture-token")

    records = graph.list(
        "/v1.0/servicePrincipals",
        params={"$top": "1", "$select": "id"},
        limit=2,
        follow_pagination=False,
    )

    assert records == ({"id": "first"},)
    assert len(requested_urls) == 1


def _catalog() -> AiSaasCatalog:
    return AiSaasCatalog(
        (
            CatalogEntry(
                name="OpenAI / ChatGPT",
                aliases=("OpenAI", "ChatGPT"),
                app_ids=("known-openai-app",),
                category="assistant",
            ),
            CatalogEntry(
                name="Notion AI",
                aliases=("Notion AI",),
                app_ids=(),
                category="productivity",
            ),
        )
    )


def _service_principals() -> list[dict[str, Any]]:
    return [
        {
            "id": "sp-ai",
            "appId": "known-openai-app",
            "displayName": "ChatGPT Enterprise",
            "accountEnabled": True,
            "servicePrincipalType": "Application",
            "publisherName": "OpenAI",
            "verifiedPublisher": {"displayName": "OpenAI"},
            "signInAudience": "AzureADMultipleOrgs",
        },
        {
            "id": "sp-graph",
            "appId": "00000003-0000-0000-c000-000000000000",
            "displayName": "Microsoft Graph",
            "accountEnabled": True,
            "servicePrincipalType": "Application",
            "publisherName": "Microsoft Services",
            "verifiedPublisher": {"displayName": "Microsoft Services"},
        },
        {
            "id": "sp-notion-generic",
            "appId": "notion-calendar-app",
            "displayName": "Notion Calendar Connector",
        },
    ]


def _responses() -> dict[str, Any]:
    return {
        "/v1.0/servicePrincipals": _service_principals(),
        "/v1.0/oauth2PermissionGrants": [
            {
                "id": "grant-1",
                "clientId": "sp-ai",
                "consentType": "AllPrincipals",
                "principalId": None,
                "resourceId": "sp-graph",
                "scope": "User.Read Mail.Read User.Read",
            }
        ],
        "/v1.0/servicePrincipals/sp-ai/appRoleAssignments": [
            {
                "id": "assignment-1",
                "appRoleId": "role-mail-read",
                "principalId": "sp-ai",
                "resourceId": "sp-graph",
                "createdDateTime": "2026-08-01T00:00:00Z",
            }
        ],
        "/v1.0/auditLogs/signIns": [
            {
                "id": "signin-1",
                "createdDateTime": "2026-08-26T12:30:00Z",
                "userId": "user-object-1",
                "userPrincipalName": "analyst@example.com",
                "appId": "known-openai-app",
                "appDisplayName": "ChatGPT Enterprise",
                "resourceId": "sp-ai",
                "resourceDisplayName": "ChatGPT Enterprise",
                "clientAppUsed": "Browser",
                "conditionalAccessStatus": "success",
                "status": {"errorCode": 0},
                "correlationId": "trace-1",
                "isInteractive": True,
                "signInEventTypes": ["interactiveUser"],
            },
            {
                "id": "signin-unrelated",
                "createdDateTime": "2026-08-26T12:00:00Z",
                "appId": "ordinary-app",
                "appDisplayName": "Ordinary CRM",
                "status": {"errorCode": 0},
            },
        ],
        "/v1.0/auditLogs/directoryAudits": [
            {
                "id": "audit-1",
                "activityDateTime": "2026-08-26T10:30:00Z",
                "activityDisplayName": "Add delegated permission grant",
                "category": "ApplicationManagement",
                "result": "success",
                "initiatedBy": {
                    "user": {
                        "id": "admin-1",
                        "userPrincipalName": "admin@example.com",
                    }
                },
                "targetResources": [
                    {"id": "sp-ai", "displayName": "ChatGPT Enterprise", "type": "ServicePrincipal"}
                ],
                "correlationId": "trace-audit-1",
            }
        ],
    }


def test_catalog_prefers_app_id_and_avoids_broad_product_name() -> None:
    catalog = _catalog()

    match = catalog.match(app_id="KNOWN-OPENAI-APP", display_name="Renamed internal app")

    assert match is not None
    assert match.method == "exact_app_id"
    assert catalog.match(app_id="other", display_name="Notion Calendar Connector") is None
    assert catalog.match(app_id="other", display_name="Corporate Notion AI") is not None


def test_inventory_separates_app_identity_and_permission_semantics() -> None:
    connector = EntraAiConnector(
        entra_tenant_id=TENANT, graph_client=FakeGraph(_responses()), catalog=_catalog()
    )

    batch = connector.collect_inventory()

    ai_apps = [item for item in batch.assets if item.asset.kind is AssetKind.AI_APPLICATION]
    identities = [item for item in batch.assets if item.asset.kind is AssetKind.IDENTITY]
    assert len(ai_apps) == 1
    assert ai_apps[0].asset.natural_key == f"entra:{TENANT}:application:known-openai-app"
    assert ai_apps[0].attributes["tenant_id"] == TENANT
    assert ai_apps[0].attributes["catalog_match_method"] == "exact_app_id"
    assert ai_apps[0].attributes["delegated_grant_count"] == 1
    assert ai_apps[0].attributes["application_permission_count"] == 1
    assert ai_apps[0].attributes["delegated_scopes"] == ["Mail.Read", "User.Read"]
    assert ai_apps[0].attributes["delegated_consent_types"] == ["AllPrincipals"]
    assert ai_apps[0].attributes["delegated_principal_ids"] == []
    assert {item.asset.natural_key for item in identities} == {
        f"entra:{TENANT}:service-principal:sp-ai",
        f"entra:{TENANT}:service-principal:sp-graph",
    }
    runs_as = [item for item in batch.relationships if item.kind is RelationshipKind.RUNS_AS]
    delegated = [item for item in batch.relationships if item.kind is RelationshipKind.CONNECTS_TO]
    application = [item for item in batch.relationships if item.kind is RelationshipKind.CAN_INVOKE]
    assert len(runs_as) == len(delegated) == len(application) == 1
    assert delegated[0].coverage_plane == DELEGATED_GRANT_PLANE
    assert delegated[0].attributes["scopes"] == ["Mail.Read", "User.Read"]
    assert delegated[0].attributes["user_context_required"] is True
    assert application[0].coverage_plane == APPLICATION_PERMISSION_PLANE
    assert application[0].principal_ref == runs_as[0].target
    assert application[0].attributes["user_context_required"] is False
    assert all(item.state is CoverageState.COMPLETE for item in batch.coverage)


def test_activity_links_only_catalog_matched_application_and_keeps_actor_reference_only() -> None:
    graph = FakeGraph(_responses())
    connector = EntraAiConnector(entra_tenant_id=TENANT, graph_client=graph, catalog=_catalog())

    batch = connector.collect_activity(start_time=START, end_time=END)

    assert {item.category for item in batch.activities} == {
        ActivityCategory.AI_APP_SIGN_IN,
        ActivityCategory.ADMIN_CHANGE,
    }
    sign_in = next(
        item for item in batch.activities if item.category is ActivityCategory.AI_APP_SIGN_IN
    )
    application = next(
        item for item in sign_in.entities if item.role is ActivityEntityRole.APPLICATION
    )
    actor = next(item for item in sign_in.entities if item.role is ActivityEntityRole.ACTOR)
    assert application.asset is not None
    assert application.asset.kind is AssetKind.AI_APPLICATION
    assert application.correlation is ActivityCorrelation.EXACT_IDENTIFIER
    assert actor.asset is None
    assert actor.correlation is ActivityCorrelation.UNRESOLVED
    assert "ipAddress" not in sign_in.evidence.payload
    assert sign_in.evidence.payload["userId"] == "user-object-1"
    assert sign_in.evidence.payload["userPrincipalName"] == "analyst@example.com"
    audit = next(
        item for item in batch.activities if item.category is ActivityCategory.ADMIN_CHANGE
    )
    assert audit.evidence.payload["initiatedBy"] == {
        "user": {"id": "admin-1", "userPrincipalName": "admin@example.com"}
    }
    assert {item.plane for item in batch.coverage} == {SIGN_IN_PLANE, DIRECTORY_AUDIT_PLANE}
    assert all(item.state is CoverageState.COMPLETE for item in batch.coverage)
    audit_params = next(
        params for path, params in graph.requests if path == "/v1.0/auditLogs/directoryAudits"
    )
    assert "category eq 'ApplicationManagement'" in audit_params["$filter"]
    assert "activityDateTime ge" in audit_params["$filter"]
    assert "targetResources/any" not in audit_params["$filter"]


def test_directory_audit_never_links_by_display_name_alias() -> None:
    responses = _responses()
    responses["/v1.0/auditLogs/directoryAudits"] = [
        {
            "id": "audit-alias-only",
            "activityDateTime": "2026-08-26T10:30:00Z",
            "activityDisplayName": "Update application",
            "category": "ApplicationManagement",
            "result": "success",
            "targetResources": [
                {
                    "id": "different-service-principal",
                    "displayName": "ChatGPT Enterprise",
                    "type": "ServicePrincipal",
                }
            ],
        }
    ]
    connector = EntraAiConnector(
        entra_tenant_id=TENANT, graph_client=FakeGraph(responses), catalog=_catalog()
    )

    batch = connector.collect_activity(start_time=START, end_time=END)

    assert all(item.category is not ActivityCategory.ADMIN_CHANGE for item in batch.activities)
    audit_coverage = next(item for item in batch.coverage if item.plane == DIRECTORY_AUDIT_PLANE)
    assert "Collected 0 directory changes" in (audit_coverage.detail or "")


def test_permission_failure_is_visible_and_does_not_echo_source_detail() -> None:
    responses = _responses()
    responses["/v1.0/oauth2PermissionGrants"] = RuntimeError(
        "token=super-secret and tenant response body"
    )
    connector = EntraAiConnector(
        entra_tenant_id=TENANT, graph_client=FakeGraph(responses), catalog=_catalog()
    )

    batch = connector.collect_inventory()

    coverage = next(item for item in batch.coverage if item.plane == DELEGATED_GRANT_PLANE)
    assert coverage.state is CoverageState.FAILED
    assert coverage.detail is not None
    assert "super-secret" not in coverage.detail
    assert "empty result" in coverage.detail


def test_service_principal_failure_marks_every_inventory_plane_failed() -> None:
    connector = EntraAiConnector(
        entra_tenant_id=TENANT,
        graph_client=FakeGraph({"/v1.0/servicePrincipals": RuntimeError("forbidden")}),
        catalog=_catalog(),
    )

    batch = connector.collect_inventory()

    assert not batch.assets
    assert len(batch.coverage) == 4
    assert all(item.state is CoverageState.FAILED for item in batch.coverage)
