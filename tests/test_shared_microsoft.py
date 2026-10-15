"""Shared Microsoft references use fixed metadata reads and never native credentials."""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from denali.connections import azure_coverage_plan, entra_coverage_plan
from denali.connections.entra import ENTRA_SCOPES
from denali.connectors.azure_deployments import AzureDeploymentDiscoveryError
from denali.integrations.shared_microsoft import (
    SHARED_AZURE_SCOPES,
    MicrosoftCollectorRouter,
    MicrosoftValidatorRouter,
    SharedAzureReader,
    SharedEntraReader,
    selected_subscriptions,
)

ID = "11111111-1111-4111-8111-111111111111"
TENANT = "22222222-2222-4222-8222-222222222222"
SUBSCRIPTION = "33333333-3333-4333-8333-333333333333"
APP = "44444444-4444-4444-8444-444444444444"
PRINCIPAL = "55555555-5555-4555-8555-555555555555"


def connection(provider="azure"):
    scopes = list(SHARED_AZURE_SCOPES if provider == "azure" else ENTRA_SCOPES)
    subscriptions = [{"id": SUBSCRIPTION, "name": "Selected"}]
    return {
        "id": ID,
        "provider": provider,
        "lifecycle_state": "active",
        "credential_type": f"platform_shared_{provider}",
        "credential_reference": {"platform_connection_id": ID},
        "clerk_organization_id": "org_alpha",
        "declared_scopes": scopes,
        "configuration": {
            "tenant_id": TENANT,
            "coverage_mode": "selected-subscriptions"
            if provider == "azure"
            else "tenant-wide-admin-consent",
            **({"subscriptions": subscriptions} if provider == "azure" else {}),
        },
        "coverage_plan": azure_coverage_plan(scopes, subscriptions)
        if provider == "azure"
        else entra_coverage_plan(scopes, TENANT),
    }


class Broker:
    def __init__(self, handler=None):
        self.calls = []
        self.handler = handler

    def allows_org(self, org):
        return org == "org_alpha"

    def request(self, method, path, *, clerk_org_id, payload):
        self.calls.append((method, path, clerk_org_id, deepcopy(payload)))
        items = []
        if payload["operation"] == "subscription_metadata":
            items = [{"tenantId": TENANT, "subscriptionId": SUBSCRIPTION}]
        elif payload["operation"] == "service_principals":
            items = [{"id": PRINCIPAL, "appId": APP, "displayName": "GitHub Copilot"}]
        result = {
            "tenant_id": TENANT,
            "operation": payload["operation"],
            "items": items,
            "next_page_token": "",
        }
        if "subscription_id" in payload:
            result["subscription_id"] = payload["subscription_id"]
        return self.handler(payload, result) if self.handler else result


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_AZURE_ENABLED", "true")
    monkeypatch.setenv("DENALI_PLATFORM_ENTRA_ENABLED", "true")


@pytest.mark.parametrize(
    "provider,reader", [("azure", SharedAzureReader), ("entra", SharedEntraReader)]
)
def test_shared_readers_are_default_off(provider, reader, monkeypatch):
    monkeypatch.delenv(f"DENALI_PLATFORM_{provider.upper()}_ENABLED")
    with pytest.raises(ValueError, match="disabled"):
        reader(connection(provider), client=Broker())


@pytest.mark.parametrize(
    "provider,reader", [("azure", SharedAzureReader), ("entra", SharedEntraReader)]
)
@pytest.mark.parametrize(
    "change",
    [
        {"id": TENANT},
        {"clerk_organization_id": "org_beta"},
        {"lifecycle_state": "disabled"},
        {"credential_reference": {"platform_connection_id": TENANT}},
        {"declared_scopes": ["provider.admin"]},
        {"configuration": {"tenant_id": TENANT}},
    ],
)
def test_invalid_reference_fails_before_network(provider, reader, change):
    broker = Broker()
    with pytest.raises(ValueError):
        reader({**connection(provider), **change}, client=broker)
    assert not broker.calls


def test_subscription_selection_is_exact_bounded_and_unique():
    assert selected_subscriptions([{"id": SUBSCRIPTION}]) == [
        {"id": SUBSCRIPTION, "name": SUBSCRIPTION}
    ]
    for value in [[], [{"id": "*"}], [{"id": SUBSCRIPTION}] * 2, [{"id": SUBSCRIPTION}] * 9]:
        with pytest.raises(ValueError):
            selected_subscriptions(value)


@pytest.mark.parametrize(
    "parameters",
    [
        {"subscription_id": TENANT, "resource_type": "microsoft.app/containerapps"},
        {"subscription_id": SUBSCRIPTION, "resource_type": "arbitrary/resource"},
        {
            "subscription_id": SUBSCRIPTION,
            "resource_type": "microsoft.app/containerapps",
            "page_size": 101,
        },
        {
            "subscription_id": SUBSCRIPTION,
            "resource_type": "microsoft.app/containerapps",
            "page_size": True,
        },
        {
            "subscription_id": SUBSCRIPTION,
            "resource_type": "microsoft.app/containerapps",
            "page_token": "x" * 2049,
        },
    ],
)
def test_azure_read_selection_is_fail_closed(parameters):
    broker = Broker()
    reader = SharedAzureReader(connection(), client=broker)
    with pytest.raises(ValueError):
        reader.read("resources", **parameters)
    assert not broker.calls


def test_response_binding_and_cursor_are_checked():
    for change in [
        {"tenant_id": APP},
        {"subscription_id": APP},
        {"operation": "activity"},
        {"items": "raw"},
        {"next_page_token": "x" * 2049},
    ]:
        broker = Broker(lambda payload, result, change=change: {**result, **change})
        with pytest.raises(AzureDeploymentDiscoveryError):
            SharedAzureReader(connection(), client=broker).list_resources(
                subscription_id=SUBSCRIPTION, resource_type="microsoft.app/containerapps"
            )
    broker = Broker(lambda payload, result: {**result, "next_page_token": "repeat"})
    with pytest.raises(AzureDeploymentDiscoveryError, match="unavailable"):
        SharedAzureReader(connection(), client=broker).list_resources(
            subscription_id=SUBSCRIPTION, resource_type="microsoft.app/containerapps"
        )
    assert len(broker.calls) == 2


def test_entra_pagination_preserves_signed_cursor_and_never_forwards_graph_queries():
    token = "x" * 4096

    def pages(payload, result):
        return {**result, "next_page_token": token if "page_token" not in payload else ""}

    broker = Broker(pages)
    reader = SharedEntraReader(connection("entra"), client=broker)
    assert len(reader.list("/v1.0/servicePrincipals", params={"$select": "id,appId"})) == 2
    assert broker.calls[1][3]["page_token"] == token
    assert all(set(call[3]) <= {"operation", "page_size", "page_token"} for call in broker.calls)
    with pytest.raises(ValueError):
        reader.list("https://graph.microsoft.com/v1.0/users")
    with pytest.raises(ValueError):
        reader.list("/v1.0/servicePrincipals", params={"$filter": "accountEnabled eq true"})
    with pytest.raises(ValueError):
        reader.read("service_principals", page_token="x" * 8193)


def audit_parameters():
    end = datetime.now(UTC)
    return {"window_start": end - timedelta(hours=24), "window_end": end}


def audit_items(count, *, offset=0):
    return [
        {
            "id": f"synthetic-audit-{index}",
            "activityDateTime": "2026-01-01T12:00:00Z",
            "activityDisplayName": "Update application",
            "category": "ApplicationManagement",
            "result": "success",
            "targetResources": [{"id": PRINCIPAL, "type": "ServicePrincipal"}],
        }
        for index in range(offset, offset + count)
    ]


@pytest.mark.parametrize("count", [103, 200])
def test_entra_directory_audit_100_item_hint_accepts_bounded_complete_page(count):
    items = audit_items(count)
    broker = Broker(lambda payload, result: {**result, "items": items})
    reader = SharedEntraReader(connection("entra"), client=broker)
    result = reader.read("directory_audits", page_size=100, **audit_parameters())
    assert result["items"] == items
    assert len(result["items"]) == count
    assert broker.calls[0][3]["page_size"] == 100


@pytest.mark.parametrize(
    "change",
    [
        {"items": audit_items(201)},
        {"items": [*audit_items(102), "not-a-dictionary"]},
        {"items": {"value": audit_items(103)}},
        {"items": audit_items(103), "tenant_id": APP},
        {"items": audit_items(103), "operation": "sign_ins"},
        {"items": audit_items(103), "next_page_token": "x" * 8193},
    ],
)
def test_entra_directory_audit_compatibility_still_rejects_invalid_response(change):
    broker = Broker(lambda payload, result: {**result, **change})
    with pytest.raises(ValueError, match="read response is invalid"):
        SharedEntraReader(connection("entra"), client=broker).read(
            "directory_audits", page_size=100, **audit_parameters()
        )


@pytest.mark.parametrize("page_size", [1, 50, 99])
def test_entra_directory_audit_smaller_request_keeps_its_strict_response_bound(page_size):
    broker = Broker(lambda payload, result: {**result, "items": audit_items(page_size + 1)})
    with pytest.raises(ValueError, match="read response is invalid"):
        SharedEntraReader(connection("entra"), client=broker).read(
            "directory_audits", page_size=page_size, **audit_parameters()
        )
    assert broker.calls[0][3]["page_size"] == page_size


@pytest.mark.parametrize(
    "operation,parameters",
    [
        ("service_principals", {}),
        ("oauth_grants", {}),
        ("app_role_assignments", {"service_principal_id": PRINCIPAL}),
        ("sign_ins", {"app_ids": [APP]}),
    ],
)
def test_non_audit_entra_reads_reject_101_items(operation, parameters):
    broker = Broker(lambda payload, result: {**result, "items": audit_items(101)})
    if operation == "sign_ins":
        parameters = {**parameters, **audit_parameters()}
    with pytest.raises(ValueError, match="read response is invalid"):
        SharedEntraReader(connection("entra"), client=broker).read(
            operation, page_size=100, **parameters
        )


def test_azure_read_keeps_100_item_response_bound():
    broker = Broker(lambda payload, result: {**result, "items": audit_items(101)})
    with pytest.raises(ValueError, match="read response is invalid"):
        SharedAzureReader(connection(), client=broker).read(
            "activity", subscription_id=SUBSCRIPTION, page_size=100, **audit_parameters()
        )


@pytest.mark.parametrize("page_size", [101, 200, True])
def test_directory_audit_compatibility_does_not_expand_request_page_size(page_size):
    broker = Broker()
    with pytest.raises(ValueError, match="page size is invalid"):
        SharedEntraReader(connection("entra"), client=broker).read(
            "directory_audits", page_size=page_size, **audit_parameters()
        )
    assert broker.calls == []


def test_entra_directory_audit_pagination_preserves_all_206_records_and_opaque_cursor():
    first, second = audit_items(103), audit_items(103, offset=103)
    cursor = "opaque-signed-audit-cursor"

    def pages(payload, result):
        if "page_token" not in payload:
            return {**result, "items": first, "next_page_token": cursor}
        assert payload["page_token"] == cursor
        return {**result, "items": second}

    broker = Broker(pages)
    reader = SharedEntraReader(connection("entra"), client=broker)
    records = reader._list("directory_audits", limit=206, **audit_parameters())
    assert records == tuple(first + second)
    assert len({item["id"] for item in records}) == 206
    assert [call[3]["page_size"] for call in broker.calls] == [100, 100]
    assert broker.calls[1][3]["page_token"] == cursor

    broker.calls.clear()
    with pytest.raises(ValueError, match="record limit reached"):
        reader._list("directory_audits", limit=205, **audit_parameters())
    assert len(broker.calls) == 2


def test_entra_directory_audit_repeated_cursor_and_page_limits_are_unchanged():
    broker = Broker(lambda payload, result: {**result, "next_page_token": "repeat"})
    reader = SharedEntraReader(connection("entra"), client=broker)
    with pytest.raises(ValueError, match="page token repeated"):
        reader._list("directory_audits", **audit_parameters())
    assert len(broker.calls) == 2

    def unique_pages(payload, result):
        return {**result, "next_page_token": f"opaque-{len(broker.calls)}"}

    broker = Broker(unique_pages)
    reader = SharedEntraReader(connection("entra"), client=broker)
    with pytest.raises(ValueError, match="page limit reached"):
        reader._list("directory_audits", **audit_parameters())
    assert len(broker.calls) == 200
    with pytest.raises(ValueError, match="record limit is invalid"):
        reader._list("directory_audits", limit=20_001, **audit_parameters())
    assert len(broker.calls) == 200


def test_entra_known_native_queries_translate_into_fixed_operations():
    broker = Broker()
    reader = SharedEntraReader(connection("entra"), client=broker)
    end = datetime.now(UTC)
    start = end - timedelta(hours=24)
    window = f"createdDateTime ge {start.isoformat()} and createdDateTime lt {end.isoformat()}"
    reader.list(
        "/v1.0/auditLogs/signIns",
        params={
            "$filter": f"{window} and (appId eq '{APP}')",
            "$select": "id",
            "$orderby": "createdDateTime desc",
        },
    )
    reader.list(f"/v1.0/servicePrincipals/{PRINCIPAL}/appRoleAssignments")
    reader.list("/v1.0/oauth2PermissionGrants")
    reader.list(
        "/v1.0/auditLogs/directoryAudits",
        params={
            "$filter": (
                f"activityDateTime ge {start.isoformat()} "
                f"and activityDateTime lt {end.isoformat()} "
                "and category eq 'ApplicationManagement'"
            )
        },
    )
    assert [call[3]["operation"] for call in broker.calls] == [
        "sign_ins",
        "app_role_assignments",
        "oauth_grants",
        "directory_audits",
    ]
    assert broker.calls[0][3]["app_ids"] == [APP]
    assert broker.calls[1][3]["service_principal_id"] == PRINCIPAL
    assert all("path" not in call[3] and "$filter" not in call[3] for call in broker.calls)
    with pytest.raises(ValueError):
        reader.read(
            "sign_ins", app_ids=[APP], window_start=end - timedelta(hours=25), window_end=end
        )
    with pytest.raises(ValueError):
        reader.read("sign_ins", app_ids=[APP] * 11, window_start=start, window_end=end)


class Native:
    def validate(self, connection):
        raise AssertionError("native provider credentials must not be consulted")

    def collect(self, **kwargs):
        raise AssertionError("native provider credentials must not be consulted")


@pytest.mark.parametrize("provider", ["azure", "entra"])
def test_validation_uses_each_declared_fixed_operation_and_sanitizes_failure(provider):
    broker = Broker()
    result = MicrosoftValidatorRouter(provider, Native(), broker).validate(connection(provider))
    assert result["health_state"] == "healthy"
    operations = {call[3]["operation"] for call in broker.calls}
    assert operations == (
        {"subscription_metadata", "resources", "activity"}
        if provider == "azure"
        else {
            "service_principals",
            "oauth_grants",
            "app_role_assignments",
            "sign_ins",
            "directory_audits",
        }
    )

    def fail(payload, result):
        raise RuntimeError("synthetic-secret-marker")

    failed = MicrosoftValidatorRouter(provider, Native(), Broker(fail)).validate(
        connection(provider)
    )
    assert failed["health_state"] == "unhealthy"
    assert "synthetic-secret-marker" not in str(failed)


class Sink:
    def __init__(self):
        self.inventory = []
        self.activity = []

    def ingest(self, tenant, batch):
        self.inventory.append((tenant, batch))
        return {"assets": len(batch.assets)}

    def ingest_activity(self, tenant, batch):
        self.activity.append((tenant, batch))
        return {"activities": len(batch.activities)}


@pytest.mark.parametrize("provider", ["azure", "entra"])
def test_shared_collection_reuses_native_evidence_sink_and_24_hour_activity(provider):
    broker = Broker()
    sink = Sink()
    result = MicrosoftCollectorRouter(provider, Native(), broker).collect(
        tenant_id="local-tenant", connection=connection(provider), repository=sink
    )
    assert result["state"] == "complete"
    assert sink.inventory and sink.activity
    assert all(tenant == "local-tenant" for tenant, _batch in sink.inventory + sink.activity)
    for call in broker.calls:
        payload = call[3]
        assert call[1] == f"/internal/v1/connections/{provider}/{ID}/read"
        if "window_start" in payload:
            assert datetime.fromisoformat(payload["window_end"]) - datetime.fromisoformat(
                payload["window_start"]
            ) <= timedelta(hours=24)
    if provider == "entra":
        assert result["lookback_hours"] == 24


def test_entra_collector_completes_six_planes_with_103_non_ai_directory_audits():
    def metadata(payload, result):
        if payload["operation"] == "service_principals":
            return {
                **result,
                "items": [{"id": PRINCIPAL, "appId": APP, "displayName": "Finance Portal"}],
            }
        if payload["operation"] == "directory_audits":
            return {**result, "items": audit_items(103)}
        return result

    broker, sink = Broker(metadata), Sink()
    result = MicrosoftCollectorRouter("entra", Native(), broker).collect(
        tenant_id="local-tenant", connection=connection("entra"), repository=sink
    )
    assert result["state"] == "complete"
    assert result["coverage_complete"] == 6
    assert result["coverage_partial"] == result["coverage_failed"] == 0
    assert result["lookback_hours"] == 24
    assert result["matched_ai_applications"] == result["activity_events"] == 0
    assert sink.inventory[0][1].assets == ()
    assert sink.activity[0][1].activities == ()
    assert all(tenant == "local-tenant" for tenant, _ in sink.inventory + sink.activity)
    audits = [call[3] for call in broker.calls if call[3]["operation"] == "directory_audits"]
    assert len(audits) == 1 and audits[0]["page_size"] == 100
    assert datetime.fromisoformat(audits[0]["window_end"]) - datetime.fromisoformat(
        audits[0]["window_start"]
    ) == timedelta(hours=24)


def test_no_native_fallback_when_shared_reader_is_disabled(monkeypatch):
    monkeypatch.delenv("DENALI_PLATFORM_AZURE_ENABLED")
    with pytest.raises(ValueError, match="disabled"):
        MicrosoftCollectorRouter("azure", Native(), Broker()).collect(
            tenant_id="local-tenant", connection=connection(), repository=Sink()
        )
    result = MicrosoftValidatorRouter("azure", Native(), Broker()).validate(connection())
    assert result["health_state"] == "unhealthy"


def test_mismatched_shared_provider_type_cannot_select_native_credentials():
    wrong = {**connection(), "credential_type": "platform_shared_entra"}
    with pytest.raises(ValueError, match="does not match"):
        MicrosoftValidatorRouter("azure", Native(), Broker()).validate(wrong)
    with pytest.raises(ValueError, match="does not match"):
        MicrosoftCollectorRouter("azure", Native(), Broker()).collect(
            tenant_id="local-tenant", connection=wrong, repository=Sink()
        )


def test_entra_can_validate_and_collect_without_azure_enablement(monkeypatch):
    monkeypatch.delenv("DENALI_PLATFORM_AZURE_ENABLED", raising=False)
    broker, target, sink = Broker(), connection("entra"), Sink()
    validated = MicrosoftValidatorRouter("entra", Native(), broker).validate(target)
    collected = MicrosoftCollectorRouter("entra", Native(), broker).collect(
        tenant_id="local-tenant", connection=target, repository=sink
    )
    assert validated["health_state"] == "healthy"
    assert collected["state"] == "complete" and collected["lookback_hours"] == 24
    assert all(call[1] == f"/internal/v1/connections/entra/{ID}/read" for call in broker.calls)
    assert all("subscription_id" not in call[3] for call in broker.calls)


def test_entra_only_rollout_preserves_native_azure_and_entra_routing(monkeypatch):
    monkeypatch.delenv("DENALI_PLATFORM_AZURE_ENABLED", raising=False)
    broker, calls = Broker(), []

    class ExistingNative:
        def validate(self, target):
            calls.append(("validate", target["provider"]))
            return {"health_state": "native-result"}

        def collect(self, **kwargs):
            calls.append(("collect", kwargs["connection"]["provider"]))
            return {"state": "native-result"}

    native = ExistingNative()
    for provider in ("azure", "entra"):
        target = {"provider": provider, "credential_type": f"native_{provider}"}
        assert MicrosoftValidatorRouter(provider, native, broker).validate(target) == {
            "health_state": "native-result"
        }
        assert MicrosoftCollectorRouter(provider, native, broker).collect(
            tenant_id="local-tenant", connection=target, repository=Sink()
        ) == {"state": "native-result"}
    assert calls == [
        ("validate", "azure"), ("collect", "azure"),
        ("validate", "entra"), ("collect", "entra"),
    ]
    assert broker.calls == []
