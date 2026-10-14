"""Real bounded RPCs paginate synthetic reports without raising the broker cap."""

import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from test_shared_google_workspace import (
    ID,
    Broker,
    connection,
    metadata,
    read,
)

import denali.integrations.shared_connections_client as transport_module
from denali.connectors.google_workspace import (
    GoogleWorkspaceRecordLimitReached,
    GoogleWorkspaceReportsClient,
)
from denali.integrations.shared_connections_client import (
    SharedConnectionsClient,
    SharedConnectionsError,
)
from denali.integrations.shared_google_workspace import (
    ROOT,
    SharedWorkspaceReportsClient,
    WorkspaceCollectorRouter,
)


def record(operation, ordinal, when):
    application = "token" if operation == "oauth_activity" else "gemini_in_workspace_apps"
    parameters = [{"name": "action", "value": "generate text"}]
    if operation == "oauth_activity":
        parameters = [
            {"name": "client_id", "value": "oauth-client-1"},
            {"name": "app_name", "value": "ChatGPT Enterprise"},
        ]
    return {
        "id": {
            "time": when,
            "uniqueQualifier": str(ordinal),
            "applicationName": application,
            "customerId": "C012345",
        },
        "actor": {"profileId": "42"},
        "events": [
            {
                "name": "authorize" if operation == "oauth_activity" else "feature_utilization",
                "type": "auth" if operation == "oauth_activity" else "ai_usage_event",
                "parameters": parameters,
            }
        ],
    }


def page(arguments, operation, records, cursor=None):
    return {
        "version": 1,
        "connection_id": ID,
        "customer_id": "C012345",
        "domain": "example.com",
        "binding_revision": 1,
        "operation": operation,
        "application_name": "token"
        if operation == "oauth_activity"
        else "gemini_in_workspace_apps",
        "start_time": arguments["start_time"],
        "end_time": arguments["end_time"],
        "items": records,
        "next_cursor": cursor,
    }


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED", "true")


def real_client(monkeypatch, handler):
    monkeypatch.setattr(
        transport_module,
        "Clerk",
        lambda **_: SimpleNamespace(
            m2m=SimpleNamespace(
                create_token=lambda **_: SimpleNamespace(token="synthetic-m2m-token")
            )
        ),
    )
    monkeypatch.setattr(
        transport_module.httpx, "HTTPTransport", lambda **_: httpx.MockTransport(handler)
    )
    return SharedConnectionsClient(
        "https://broker.example.test",
        "synthetic-machine-key",
        allowed_clerk_org_ids=frozenset({"org_alpha"}),
    )


def test_concrete_rpc_collects_all_pages_when_legacy_1000_report_exceeds_broker_cap(monkeypatch):
    # Model the broker's existing pre-projection 2 MB Google response guard.
    # This synthetic HTTP stand-in is not a live Google acceptance test.
    sizes = []
    requests = []
    rejected = []
    totals = {"gemini_activity": 539, "oauth_activity": 1250}

    def handle(outbound):
        if outbound.method == "GET":
            assert outbound.url.path == f"{ROOT}/{ID}/status"
            return httpx.Response(200, json=metadata())
        assert outbound.url.path == f"{ROOT}/{ID}/read"
        payload = json.loads(outbound.content)
        assert payload["clerk_org_id"] == "org_alpha"
        operation, arguments = payload["operation"], payload["arguments"]
        requests.append((operation, deepcopy(arguments)))
        offset = int(arguments.get("cursor", "0"))
        stop = min(offset + arguments["limit"], totals[operation])
        records = [record(operation, index, arguments["end_time"]) for index in range(offset, stop)]
        raw = deepcopy(records)
        for item in raw:
            item["events"][0]["parameters"].append(
                {"name": "unprojected_report_parameter", "value": "x" * 1800}
            )
        size = len(json.dumps({"items": raw}, separators=(",", ":")).encode())
        sizes.append((arguments["limit"], size))
        if size > 2_000_000:
            rejected.append(operation)
            return httpx.Response(502, json={"detail": "Workspace metadata read failed"})
        cursor = str(stop) if stop < totals[operation] else None
        return httpx.Response(200, json=page(arguments, operation, records, cursor))

    client = real_client(monkeypatch, handle)
    end = datetime.now(UTC)
    arguments = {
        "start_time": (end - timedelta(days=180)).isoformat(),
        "end_time": end.isoformat(),
        "limit": 1000,
    }
    with pytest.raises(SharedConnectionsError) as failure:
        client.request(
            "POST",
            f"{ROOT}/{ID}/read",
            clerk_org_id="org_alpha",
            payload={"operation": "oauth_activity", "arguments": arguments},
            max_response_bytes=2_097_152,
        )
    assert failure.value.status_code == 502
    assert rejected == ["oauth_activity"] and sizes[0][1] > 2_000_000
    batches = []

    class Repository:
        def ingest(self, tenant_id, batch):
            assert tenant_id == "tenant_alpha"
            batches.append(batch)
            return {"assets": len(batch.assets)}

        def ingest_activity(self, tenant_id, batch):
            assert tenant_id == "tenant_alpha"
            batches.append(batch)
            return {"events": len(batch.activities)}

    result = WorkspaceCollectorRouter(None, client).collect(
        tenant_id="tenant_alpha", connection=connection(), repository=Repository()
    )
    assert result["state"] == "complete"
    assert result["lookback_hours"] == 24 * 180
    assert result["coverage_complete"] == 2
    assert result["coverage_partial"] == result["coverage_failed"] == 0
    assert result["matched_ai_applications"] == 2
    assert result["activity_events"] == sum(totals.values())
    assert len({event.source_uid for event in batches[1].activities}) == sum(totals.values())
    assert all(
        coverage.state.value == "complete" for batch in batches for coverage in batch.coverage
    )
    successful = requests[1:]
    assert all(arguments["limit"] == 100 for _, arguments in successful)
    assert all(size < 2_000_000 for _, size in sizes[1:])
    for operation, total in totals.items():
        pages = [arguments for name, arguments in successful if name == operation]
        assert len(pages) == (total + 99) // 100
        assert len({(args["start_time"], args["end_time"]) for args in pages}) == 1
        assert datetime.fromisoformat(pages[0]["end_time"]) - datetime.fromisoformat(
            pages[0]["start_time"]
        ) == timedelta(days=180)
        assert [args.get("cursor") for args in pages] == [
            None,
            *(str(offset) for offset in range(100, total, 100)),
        ]


@pytest.mark.parametrize(
    "max_results,limit,expected", [(1000, 20000, 100), (50, 20000, 50), (1000, 7, 7), (1, 2, 1)]
)
def test_requested_page_size_is_clamped_without_enlarging_small_probes(
    max_results, limit, expected
):
    broker = Broker()
    assert (
        read(
            SharedWorkspaceReportsClient(connection(), client=broker),
            max_results=max_results,
            limit=limit,
        )
        == ()
    )
    assert broker.calls[-1][3]["arguments"]["limit"] == expected


def test_returned_page_is_checked_against_actual_request_not_original_1000(monkeypatch):
    def handle(outbound):
        if outbound.method == "GET":
            return httpx.Response(200, json=metadata())
        payload = json.loads(outbound.content)
        arguments = payload["arguments"]
        assert arguments["limit"] == 100
        records = [
            record(payload["operation"], index, arguments["end_time"]) for index in range(101)
        ]
        return httpx.Response(200, json=page(arguments, payload["operation"], records))

    reader = SharedWorkspaceReportsClient(connection(), client=real_client(monkeypatch, handle))
    with pytest.raises(ValueError, match="read response is invalid"):
        read(reader, max_results=1000)


@pytest.mark.parametrize("failure", ["broker_cap", "wire_cap"])
def test_oversized_100_record_page_still_fails_plane_without_retry_or_false_complete(
    monkeypatch, failure
):
    operations = []

    def handle(outbound):
        if outbound.method == "GET":
            return httpx.Response(200, json=metadata())
        payload = json.loads(outbound.content)
        operation, arguments = payload["operation"], payload["arguments"]
        assert arguments["limit"] == 100
        operations.append(operation)
        if operation == "oauth_activity":
            if failure == "broker_cap":
                return httpx.Response(502, json={"detail": "Workspace metadata read failed"})
            return httpx.Response(200, content=b"x" * 2_097_153)
        return httpx.Response(
            200, json=page(arguments, operation, [record(operation, 1, arguments["end_time"])])
        )

    batches = []

    class Repository:
        def ingest(self, tenant_id, batch):
            batches.append(batch)
            return {"assets": len(batch.assets)}

        def ingest_activity(self, tenant_id, batch):
            batches.append(batch)
            return {"events": len(batch.activities)}

    result = WorkspaceCollectorRouter(None, real_client(monkeypatch, handle)).collect(
        tenant_id="tenant_alpha", connection=connection(), repository=Repository()
    )
    assert operations == ["gemini_activity", "oauth_activity"]
    assert result["state"] == "partial"
    assert result["coverage_complete"] == result["coverage_failed"] == 1
    assert result["coverage_partial"] == 0
    assert [coverage.state.value for coverage in batches[1].coverage] == ["complete", "failed"]


@pytest.mark.parametrize("more", [False, True])
def test_exact_20000_record_boundary_requires_terminal_cursor(more):
    broker = Broker()
    count = 0

    def transform(value):
        nonlocal count
        count += 1
        value["items"] = [
            record(value["operation"], (count - 1) * 100 + index, value["end_time"])
            for index in range(100)
        ]
        value["next_cursor"] = str(count) if count < 200 or more else None
        return value

    broker.transform = transform
    reader = SharedWorkspaceReportsClient(connection(), client=broker)
    if more:
        with pytest.raises(GoogleWorkspaceRecordLimitReached, match="record limit"):
            read(reader)
    else:
        assert len(read(reader)) == 20000
    assert count == 200


def test_200_page_exhaustion_never_claims_empty_complete_report():
    broker = Broker()
    count = 0

    def transform(value):
        nonlocal count
        count += 1
        value["next_cursor"] = str(count)
        return value

    broker.transform = transform
    with pytest.raises(GoogleWorkspaceRecordLimitReached, match="page limit"):
        read(SharedWorkspaceReportsClient(connection(), client=broker))
    assert count == 200


def test_native_unshared_reports_still_request_1000_by_default():
    calls = []
    client = GoogleWorkspaceReportsClient.__new__(GoogleWorkspaceReportsClient)
    client._timeout = 30.0
    client._session = SimpleNamespace(
        get=lambda url, **kwargs: (
            calls.append((url, kwargs)),
            SimpleNamespace(status_code=200, json=lambda: {"items": []}),
        )[1]
    )
    end = datetime.now(UTC)
    assert client.list("token", start_time=end - timedelta(hours=1), end_time=end) == ()
    assert parse_qs(urlsplit(calls[0][0]).query)["maxResults"] == ["1000"]
