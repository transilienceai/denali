"""Shasta's public bridge receives only bounded, explicit Workspace facts."""

from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from denali.bridges import shasta_workspace_snapshot as bridge

NOW = datetime(2026, 9, 17, 14, 0, tzinfo=UTC)


class Response:
    def __init__(self, body, status_code=200):
        self.body = body
        self.status_code = status_code

    def json(self):
        return self.body


def _requests(*, deny_directory=False, repeat_page=False):
    calls = []

    def for_scope(scope):
        assert scope in bridge.SCOPES.values()

        def request(method, url, params=None):
            calls.append((method, url, params))
            if deny_directory and "/directory/" in url:
                return Response({"error": "forbidden"}, 403)
            if url.endswith("/users"):
                return Response({
                    "users": [{"primaryEmail": "Founder@iisecurity.in",
                               "name": {"fullName": "Founder"},
                               "isAdmin": True, "isEnrolledIn2Sv": True,
                               "sensitive_provider_field": "discard"}],
                    **({"nextPageToken": "again"} if repeat_page else {}),
                })
            if url.endswith("/groups"):
                return Response({"groups": [{"email": "security@iisecurity.in",
                                              "directMembersCount": "1"}]})
            return Response({"items": [{
                "id": {"time": "2026-09-17T13:00:00Z", "uniqueQualifier": "42"},
                "actor": {"email": "founder@iisecurity.in"},
                "events": [{"name": "event", "parameters": [{"name": "token"}]}],
            }]})

        return request

    return for_scope, calls


def test_complete_snapshot_contains_only_allowlisted_reviewable_facts():
    requests, calls = _requests()
    snapshot = bridge.collect_snapshot(requests, domain="iisecurity.in", collected_at=NOW)

    assert snapshot["collection_state"] == "complete"
    assert snapshot["pagination_complete"] is True
    assert snapshot["capabilities_observed"] == sorted(bridge.SCOPES)
    assert snapshot["missing_permissions"] == []
    assert snapshot["observed_identity"] == "iisecurity.in"
    assert {item["kind"] for item in snapshot["facts"]} == {
        "directory.user", "directory.group", "reports.login_event", "reports.admin_event"
    }
    user = next(item for item in snapshot["facts"] if item["kind"] == "directory.user")
    assert user["subject"] == "founder@iisecurity.in"
    assert user["data"]["mfa_enrolled"] is True
    assert "sensitive_provider_field" not in str(snapshot)
    assert "parameters" not in str(snapshot)
    assert len(calls) == 4


def test_permission_denial_and_incomplete_pagination_stay_limited():
    denied, _ = _requests(deny_directory=True)
    snapshot = bridge.collect_snapshot(denied, domain="iisecurity.in", collected_at=NOW)
    assert snapshot["collection_state"] == "partial"
    assert snapshot["missing_permissions"] == [
        "directory.groups.read", "directory.users.read"
    ]
    assert snapshot["pagination_complete"] is False

    repeated, calls = _requests(repeat_page=True)
    snapshot = bridge.collect_snapshot(repeated, domain="iisecurity.in", collected_at=NOW)
    assert snapshot["collection_state"] == "partial"
    assert "directory.users.read" in snapshot["missing_permissions"]
    assert len([item for item in calls if item[1].endswith("/users")]) == bridge.MAX_PAGES


def test_signed_publish_uses_exact_source_binding_and_no_provider_token():
    source_id = str(uuid4())
    requests, _ = _requests()
    snapshot = bridge.collect_snapshot(requests, domain="iisecurity.in", collected_at=NOW)

    def receive(request: httpx.Request):
        assert request.url == (
            f"https://shasta.transilience.cloud/pilot/api/bridge/sources/{source_id}/snapshots"
        )
        assert request.headers["X-Shasta-Signature"].startswith("sha256=")
        assert b"sensitive_provider_field" not in request.content
        assert b"parameters" not in request.content
        assert b"directory.user" in request.content
        return httpx.Response(201, json={"snapshot_id": str(uuid4()),
                                         "replayed": False, "body_sha256": "a" * 64})

    receipt = bridge.publish_snapshot(
        snapshot, source_id=source_id, bridge_secret=b"s" * 32,
        transport=httpx.MockTransport(receive),
    )
    assert receipt["source_id"] == source_id
    assert receipt["replayed"] is False


def test_unsupported_binding_cannot_read_denali_connection(monkeypatch):
    monkeypatch.setattr(
        bridge, "delegated_requests",
        lambda *_: pytest.fail("Unsupported binding must not mint Google credentials"),
    )
    with pytest.raises(ValueError, match="Unsupported"):
        bridge.collect_and_publish(
            provider="github", tenant_id=str(uuid4()), connection_id=str(uuid4()),
            source_id=str(uuid4()), shasta_url="https://shasta.transilience.cloud/pilot",
            bridge_secret=b"s" * 32,
        )


def test_active_connection_is_loaded_with_both_denali_ids(monkeypatch):
    from denali.store import repository

    tenant_id, connection_id, source_id = (str(uuid4()) for _ in range(3))
    selected = []

    class FakeRepository:
        def __init__(self, dsn):
            assert dsn == "postgresql://test/denali"

        def get_connection_validation_target(self, tenant, connection):
            selected.append((tenant, connection))
            return {
                "lifecycle_state": "active", "provider": "google_workspace",
                "configuration": {"domain": "iisecurity.in",
                                  "admin_email": "admin@iisecurity.in"},
            }

    monkeypatch.setenv("DENALI_DSN", "postgresql://test/denali")
    monkeypatch.setenv(
        "DENALI_GOOGLE_WORKSPACE_SERVICE_ACCOUNT", "worker@project.iam.gserviceaccount.com"
    )
    monkeypatch.setattr(repository, "PostgresInventoryRepository", FakeRepository)
    requests, _ = _requests()
    monkeypatch.setattr(bridge, "delegated_requests", lambda *_: requests)
    monkeypatch.setattr(
        bridge, "publish_snapshot",
        lambda snapshot, **kwargs: {
            "source_id": kwargs["source_id"], "state": snapshot["collection_state"]
        },
    )

    receipt = bridge.collect_and_publish(
        provider="google_workspace", tenant_id=tenant_id, connection_id=connection_id,
        source_id=source_id, shasta_url="https://shasta.transilience.cloud/pilot",
        bridge_secret=b"s" * 32,
    )
    assert selected == [(tenant_id, connection_id)]
    assert receipt == {"source_id": source_id, "state": "complete"}


def test_disabled_connection_does_not_mint_credentials(monkeypatch):
    from denali.store import repository

    class DisabledRepository:
        def __init__(self, _dsn):
            pass

        def get_connection_validation_target(self, _tenant, _connection):
            return {"lifecycle_state": "disabled", "provider": "google_workspace"}

    monkeypatch.setenv("DENALI_DSN", "postgresql://test/denali")
    monkeypatch.setenv(
        "DENALI_GOOGLE_WORKSPACE_SERVICE_ACCOUNT", "worker@project.iam.gserviceaccount.com"
    )
    monkeypatch.setattr(repository, "PostgresInventoryRepository", DisabledRepository)
    monkeypatch.setattr(
        bridge, "delegated_requests",
        lambda *_: pytest.fail("Disabled source must not mint credentials"),
    )
    with pytest.raises(RuntimeError, match="unavailable or disabled"):
        bridge.collect_and_publish(
            provider="google_workspace", tenant_id=str(uuid4()),
            connection_id=str(uuid4()), source_id=str(uuid4()),
            shasta_url="https://shasta.transilience.cloud/pilot",
            bridge_secret=b"s" * 32,
        )
