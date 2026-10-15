"""Mediated reports retain native semantics without Google credentials or fallback."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta

import pytest

from denali.connections.google_workspace import (
    GOOGLE_WORKSPACE_SCOPES,
    google_workspace_coverage_plan,
)
from denali.connectors.google_workspace import GoogleWorkspaceRecordLimitReached
from denali.integrations.shared_google_workspace import (
    CREDENTIAL_TYPE,
    PIN_FIELDS,
    ROOT,
    SharedWorkspaceReportsClient,
    WorkspaceCollectorRouter,
    WorkspaceValidatorRouter,
    require_ready,
    workspace_projection,
)

ID = "11111111-1111-4111-8111-111111111111"
TARGET = "22222222-2222-4222-8222-222222222222"


def metadata():
    return {
        "id": ID,
        "target_id": TARGET,
        "clerk_org_id": "org_alpha",
        "provider": "google_workspace",
        "customer_id": "C012345",
        "domain": "example.com",
        "admin_email": "admin@example.com",
        "service_account": "workspace@project.iam.gserviceaccount.com",
        "oauth_client_id": "123456789012345678",
        "binding_revision": 1,
        "declared_scopes": list(GOOGLE_WORKSPACE_SCOPES),
        "validated_scopes": list(GOOGLE_WORKSPACE_SCOPES),
        "lifecycle_state": "active",
        "setup_state": "ready",
        "health_state": "healthy",
        "last_validated_at": datetime.now(UTC).isoformat(),
        "observed_customer_id": None,
        "validation_results": [
            {
                "scope": GOOGLE_WORKSPACE_SCOPES[0],
                "application_name": "gemini_in_workspace_apps",
                "state": "passed",
                "customer_identity_observed": False,
            },
            {
                "scope": GOOGLE_WORKSPACE_SCOPES[1],
                "application_name": "token",
                "state": "passed",
                "customer_identity_observed": False,
            },
        ],
    }


def connection():
    shared = metadata()
    return {
        "id": ID,
        "provider": "google_workspace",
        "clerk_organization_id": "org_alpha",
        "credential_type": CREDENTIAL_TYPE,
        "credential_reference": {"platform_connection_id": ID},
        "lifecycle_state": "active",
        "declared_scopes": list(GOOGLE_WORKSPACE_SCOPES),
        "coverage_plan": google_workspace_coverage_plan(
            list(GOOGLE_WORKSPACE_SCOPES), domain="example.com", admin_email="admin@example.com"
        ),
        "configuration": {
            "domain": "example.com",
            "customer_id": "C012345",
            "admin_email": "admin@example.com",
            "coverage_mode": "domain-wide-delegation",
            "platform_binding": {key: shared[key] for key in PIN_FIELDS},
            "onboarding": {"completed_at": shared["last_validated_at"]},
        },
    }


class Broker:
    def __init__(self):
        self.calls = []
        self.status = metadata()
        self.records = False
        self.failed_operation = None
        self.transform = None
        self.cursor = None

    def allows_org(self, org):
        return org == "org_alpha"

    def request(self, method, path, *, clerk_org_id, payload=None, max_response_bytes=None):
        self.calls.append((method, path, clerk_org_id, deepcopy(payload), max_response_bytes))
        if path.endswith("/config"):
            return {
                "enabled": True,
                "items": [deepcopy(self.status)],
                "declared_scopes": list(GOOGLE_WORKSPACE_SCOPES),
                "authorization_scope": "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                "setup_method": "domain_wide_delegation",
            }
        if path == ROOT:
            return {"items": [deepcopy(self.status)]}
        if path.endswith(("/status", "/setup", "/validate")):
            return deepcopy(self.status)
        assert path == f"{ROOT}/{self.status['id']}/read"
        operation = payload["operation"]
        if self.failed_operation == operation:
            raise PermissionError("sensitive provider detail")
        app = "token" if operation == "oauth_activity" else "gemini_in_workspace_apps"
        args = payload["arguments"]
        value = {
            "version": 1,
            "connection_id": self.status["id"],
            "customer_id": "C012345",
            "domain": "example.com",
            "binding_revision": self.status["binding_revision"],
            "operation": operation,
            "application_name": app,
            "start_time": args["start_time"],
            "end_time": args["end_time"],
            "items": [],
            "next_cursor": self.cursor,
        }
        if self.records:
            event = {
                "name": "feature_utilization",
                "type": "ai_usage_event",
                "parameters": [{"name": "action", "value": "generate text"}],
            }
            if app == "token":
                event = {
                    "name": "authorize",
                    "type": "auth",
                    "parameters": [
                        {"name": "client_id", "value": "oauth-client-1"},
                        {"name": "app_name", "value": "ChatGPT Enterprise"},
                    ],
                }
            value["items"] = [
                {
                    "id": {
                        "time": args["end_time"],
                        "uniqueQualifier": f"event-{app}",
                        "applicationName": app,
                        "customerId": "C012345",
                    },
                    "actor": {"profileId": "42"},
                    "events": [event],
                }
            ]
        return self.transform(value) if self.transform else value


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED", "true")


def read(reader, **kwargs):
    end = datetime.now(UTC)
    return reader.list(
        "gemini_in_workspace_apps", start_time=end - timedelta(hours=1), end_time=end, **kwargs
    )


def test_default_off_is_literal_and_never_calls_broker(monkeypatch):
    for value in ("false", "TRUE", "1", ""):
        monkeypatch.setenv("DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED", value)
        broker = Broker()
        with pytest.raises(ValueError):
            SharedWorkspaceReportsClient(connection(), client=broker)
        assert broker.calls == []


@pytest.mark.parametrize(
    "change",
    [
        {"id": TARGET},
        {"clerk_organization_id": "org_beta"},
        {"lifecycle_state": "disabled"},
        {"declared_scopes": [GOOGLE_WORKSPACE_SCOPES[0]]},
        {"declared_scopes": [GOOGLE_WORKSPACE_SCOPES[0]] * 2},
        {"credential_type": "google_workspace_domain_wide_delegation"},
    ],
)
def test_invalid_local_boundary_rejected_before_network(change):
    broker = Broker()
    with pytest.raises(ValueError):
        SharedWorkspaceReportsClient({**connection(), **change}, client=broker)
    assert not broker.calls


@pytest.mark.parametrize(
    "key,value",
    [
        ("customer_id", "C999999"),
        ("domain", "other.example"),
        ("binding_revision", 2),
        ("service_account", "changed@project.iam.gserviceaccount.com"),
        ("oauth_client_id", "999999999"),
        ("clerk_org_id", "org_beta"),
        ("lifecycle_state", "disabled"),
        ("validated_scopes", []),
    ],
)
def test_changed_registry_binding_denies_before_report_read(key, value):
    broker = Broker()
    broker.status[key] = value
    with pytest.raises(ValueError):
        SharedWorkspaceReportsClient(connection(), client=broker)
    assert len(broker.calls) == 1


def test_successful_empty_planes_validate_with_no_observed_identity():
    broker = Broker()
    result = WorkspaceValidatorRouter(None, broker).validate(connection())
    assert result["health_state"] == "healthy"
    assert result["credential_state"] == "passed"
    assert result["account_id_observed"] is None
    reads = [call for call in broker.calls if call[0] == "POST"]
    assert [call[3]["operation"] for call in reads] == ["gemini_activity", "oauth_activity"]
    assert all(call[3]["arguments"]["limit"] == 1 for call in reads)


def test_forbidden_planes_never_claim_healthy_or_credential_success():
    broker = Broker()
    broker.failed_operation = "oauth_activity"
    result = WorkspaceValidatorRouter(None, broker).validate(connection())
    assert result["health_state"] == "partial"
    assert [item["state"] for item in result["results"]] == ["passed", "failed"]
    assert "sensitive provider detail" not in repr(result)
    broker.transform = lambda _: (_ for _ in ()).throw(PermissionError("secret"))
    result = WorkspaceValidatorRouter(None, broker).validate(connection())
    assert result["health_state"] == "unhealthy"
    assert result["credential_state"] == "failed"


def test_sanitized_reports_feed_existing_native_catalog_and_activity_semantics():
    broker = Broker()
    broker.records = True
    batches = []

    class Repository:
        def ingest(self, tenant, batch):
            assert tenant == "tenant_alpha"
            batches.append(batch)
            return {"assets": len(batch.assets)}

        def ingest_activity(self, tenant, batch):
            batches.append(batch)
            return {"events": len(batch.activities)}

    result = WorkspaceCollectorRouter(None, broker).collect(
        tenant_id="tenant_alpha", connection=connection(), repository=Repository()
    )
    assert result["state"] == "complete"
    assert result["matched_ai_applications"] == result["activity_events"] == 2
    assert {asset.display_name for asset in batches[0].assets} == {
        "Gemini in Google Workspace",
        "ChatGPT Enterprise",
    }
    assert "admin@example.com" not in repr(batches)
    assert all(event.entities[0].external_uid == "42" for event in batches[1].activities)
    assert all(event.entities[0].display_name is None for event in batches[1].activities)


@pytest.mark.parametrize(
    "corruption",
    [
        lambda value: value.update(customer_id="C99999"),
        lambda value: value.update(binding_revision=2),
        lambda value: value.update(operation="oauth_activity"),
        lambda value: value.update(items=[{"raw": "payload"}]),
        lambda value: value["items"][0]["actor"].update(email="private@example.com"),
        lambda value: value["items"][0].update(ipAddress="192.0.2.1"),
        lambda value: value["items"][0]["events"][0]["parameters"].append(
            {"name": "prompt", "value": "secret"}
        ),
        lambda value: value["items"][0]["id"].update(customerId="C999999"),
        lambda value: value["items"][0]["id"].update(time="2020-01-01T00:00:00Z"),
    ],
)
def test_malformed_or_sensitive_projection_rejected_before_ingestion(corruption):
    broker = Broker()
    broker.records = True

    def transform(value):
        corruption(value)
        return value

    broker.transform = transform
    with pytest.raises(ValueError):
        read(SharedWorkspaceReportsClient(connection(), client=broker))


def test_repeated_cursor_record_cap_and_probe_do_not_create_complete_zero():
    broker = Broker()
    broker.cursor = "opaque-cursor"
    reader = SharedWorkspaceReportsClient(connection(), client=broker)
    assert read(reader, follow_pagination=False, max_results=1, limit=2) == ()
    with pytest.raises(ValueError, match="repeated"):
        read(reader)
    broker.records = True
    with pytest.raises(GoogleWorkspaceRecordLimitReached):
        read(reader, limit=1)


def test_pagination_keeps_exact_window_and_observed_customer_from_actual_records():
    broker = Broker()
    broker.records = True
    page_count = 0

    def transform(value):
        nonlocal page_count
        page_count += 1
        value["next_cursor"] = "next" if page_count == 1 else None
        return value

    broker.transform = transform
    reader = SharedWorkspaceReportsClient(connection(), client=broker)
    assert len(read(reader)) == 2
    assert reader.observed_identity == "C012345"
    calls = [call[3]["arguments"] for call in broker.calls if call[0] == "POST"]
    assert calls[0]["start_time"] == calls[1]["start_time"]
    assert calls[0]["end_time"] == calls[1]["end_time"]
    assert calls[1]["cursor"] == "next"


def test_stale_attachment_proof_rejected_but_live_reads_can_revalidate():
    shared = metadata()
    shared["last_validated_at"] = (datetime.now(UTC) - timedelta(minutes=16)).isoformat()
    with pytest.raises(ValueError, match="fresh"):
        require_ready(shared)
    broker = Broker()
    broker.status = shared
    assert (
        WorkspaceValidatorRouter(None, broker).validate(connection())["health_state"] == "healthy"
    )


def test_metadata_projection_strips_raw_fields_and_nested_provider_errors():
    shared = metadata()
    shared["raw_provider_payload"] = "secret"
    shared["validation_results"] = [
        {
            "scope": GOOGLE_WORKSPACE_SCOPES[0],
            "application_name": "gemini_in_workspace_apps",
            "state": "failed",
            "customer_identity_observed": False,
            "raw_error": "secret",
        }
    ]
    projected = workspace_projection(shared, org="org_alpha")
    assert "secret" not in repr(projected)


def test_native_routes_preserve_exact_original_objects():
    native_calls = []

    class Native:
        def validate(self, target):
            native_calls.append(target)
            return {"native": True}

        def collect(self, **arguments):
            native_calls.append(arguments)
            return {"native": True}

    target = {"credential_type": "google_workspace_domain_wide_delegation"}
    assert WorkspaceValidatorRouter(Native(), None).validate(target) == {"native": True}
    assert WorkspaceCollectorRouter(Native(), None).collect(
        tenant_id="alpha", connection=target, repository=None
    ) == {"native": True}
    assert native_calls[0] is target and native_calls[1]["connection"] is target


def test_unknown_operation_and_unbounded_window_never_reach_report_read():
    broker = Broker()
    reader = SharedWorkspaceReportsClient(connection(), client=broker)
    end = datetime.now(UTC)
    with pytest.raises(ValueError):
        reader.list("drive", start_time=end - timedelta(hours=1), end_time=end)
    with pytest.raises(ValueError):
        reader.list("token", start_time=end - timedelta(days=181), end_time=end)
    assert len(broker.calls) == 1


def test_deadline_and_aggregate_byte_cap_fail_closed():
    broker = Broker()
    ticks = iter([0, 1501])
    reader = SharedWorkspaceReportsClient(connection(), client=broker, clock=lambda: next(ticks))
    with pytest.raises(ValueError, match="deadline"):
        read(reader)
    assert len(broker.calls) == 1
    page = 0

    def transform(value):
        nonlocal page
        page += 1
        value["padding"] = "x" * 1_000_000
        value["next_cursor"] = f"page-{page}"
        return value

    broker.transform = transform
    with pytest.raises(GoogleWorkspaceRecordLimitReached, match="budget"):
        read(SharedWorkspaceReportsClient(connection(), client=broker))
    assert page < 200


def test_healthy_badge_without_committed_plane_proof_is_rejected():
    shared = metadata()
    shared["validation_results"] = []
    with pytest.raises(ValueError, match="plane proof"):
        require_ready(shared)
