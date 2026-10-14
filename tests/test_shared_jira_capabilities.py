"""Offline proof of the bounded Denali -> Platform shared Jira read boundary."""

from __future__ import annotations

from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from denali.api.app import create_app
from denali.api.auth import AuthenticationError
from denali.api.gateway_auth import GatewayPrincipal
from denali.integrations.shared_connections_client import SharedConnectionsError

CONNECTION = "11111111-1111-4111-8111-111111111111"
HEADERS = {"Authorization": "Bearer member-read"}
ROOT = "/internal/v1/capabilities"
STATUS = {
    "id": CONNECTION,
    "provider": "jira",
    "connection_kind": "shared_jira",
    "site_url": "https://example.atlassian.net",
    "cloud_id": "private-cloud-id",
    "project_ids": [10001, 10002],
    "declared_scopes": ["jira.projects", "jira.issues"],
    "available_scopes": ["jira.projects", "jira.issues"],
    "lifecycle_state": "active",
    "health_state": "healthy",
    "availability": "ready",
    "verified_at": "2026-10-14T12:00:00+00:00",
    "refresh_token": "never-return-this",
}
PROJECT = {"id": "10001", "key": "DEMO", "name": "Demo", "access_token": "secret"}
ISSUE = {
    "id": "45678", "key": "DEMO-42", "project": PROJECT,
    "summary": "Bounded issue", "status": {"id": "3", "name": "Open"},
    "issue_type": {"id": "1", "name": "Task"}, "priority": None,
    "created": "2026-10-14T12:00:00+00:00", "updated": None,
    "description": "private content must not be returned",
}


class Repository:
    def __init__(self):
        self.lookup_calls = []

    def lookup_tenant(self, org):
        self.lookup_calls.append(org)
        return {"org_Alpha": "tenant-alpha"}.get(org)

    def resolve_tenant(self, org):
        raise AssertionError("gateway read must never create a tenant")


class Verifier:
    def verify(self, token, *, purpose):
        if purpose != "results:read":
            return None
        identities = {
            "member-read": ("org_Alpha", "user_Member"),
            "admin-read": ("org_Alpha", "user_Admin"),
            "removed-read": ("org_Alpha", "user_Removed"),
            "other-read": ("org_Beta", "user_Beta"),
        }
        if token not in identities:
            return None
        org, user = identities[token]
        return GatewayPrincipal("mch_Gateway", org, user, purpose)


class Memberships:
    def role(self, org, user):
        return {
            ("org_Alpha", "user_Member"): "member",
            ("org_Alpha", "user_Admin"): "admin",
            ("org_Beta", "user_Beta"): "member",
        }.get((org, user))


class Authenticator:
    def authenticate(self, request):
        raise AuthenticationError("browser session unavailable")


class Broker:
    def __init__(self):
        self.calls = []
        self.status = deepcopy(STATUS)
        self.read = None
        self.failure = None

    def allows_org(self, org):
        return org == "org_Alpha"

    def request(
        self, method, path, *, clerk_org_id, payload=None, expect_text=False,
        max_response_bytes=None,
    ):
        self.calls.append((method, path, clerk_org_id, deepcopy(payload), max_response_bytes))
        if self.failure is not None:
            raise SharedConnectionsError(self.failure)
        if path == "/internal/v1/connections/jira":
            return {"items": [deepcopy(self.status)], "credential": "not-returned"}
        if path.endswith("/status"):
            return deepcopy(self.status)
        if path.endswith("/read"):
            if self.read is not None:
                return deepcopy(self.read)
            if payload["operation"] == "projects":
                return {"projects": [deepcopy(PROJECT)], "next_cursor": None, "token": "secret"}
            if payload["operation"] == "issues":
                return {"issues": [deepcopy(ISSUE)], "next_cursor": "opaque_1", "token": "secret"}
            return {"issue": deepcopy(ISSUE), "token": "secret"}
        raise AssertionError(f"unexpected Platform path: {path}")


def app(repo=None, broker=None):
    return create_app(
        repository=repo or Repository(), auth_mode="clerk",
        authenticator=Authenticator(),
        results_gateway_verifier=Verifier(), gateway_membership_checker=Memberships(),
        shared_connections_client=broker or Broker(), migrate_on_start=False,
    )


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_ENABLE_SHARED_JIRA_READS", "true")


def call(test, operation, *, params=None, headers=None):
    return test.get(f"{ROOT}/{operation}", params=params, headers=headers or HEADERS)


def test_default_off_and_direct_internal_route_never_calls_broker(monkeypatch):
    broker = Broker()
    monkeypatch.delenv("DENALI_ENABLE_SHARED_JIRA_READS")
    with TestClient(app(broker=broker)) as test:
        assert call(test, "shared-jira-connections").status_code == 404
        assert call(test, "shared-jira-issues", params={"project_id": "bad"}).status_code == 404
        assert test.get("/internal/v1/shared/jira/connections", headers=HEADERS).status_code == 404
    assert broker.calls == []


@pytest.mark.parametrize("invalid", ["TRUE", "1", "yes", " false ", "invalid"])
def test_nonliteral_jira_flag_never_enables_gateway_reads(monkeypatch, invalid):
    broker = Broker()
    monkeypatch.setenv("DENALI_ENABLE_SHARED_JIRA_READS", invalid)
    with TestClient(app(broker=broker)) as test:
        response = call(test, "shared-jira-connections")
    assert response.status_code == 404
    assert broker.calls == []


def test_member_and_admin_reads_use_existing_org_bound_machine_and_safe_projections():
    broker, repo = Broker(), Repository()
    with TestClient(app(repo, broker)) as test:
        listing = call(test, "shared-jira-connections", params={"limit": 20, "offset": 0})
        status = call(test, "shared-jira-status", params={"id": CONNECTION},
                      headers={"Authorization": "Bearer admin-read"})
        projects = call(test, "shared-jira-projects", params={"id": CONNECTION})
        issues = call(test, "shared-jira-issues", params={
            "id": CONNECTION, "project_id": "10001", "limit": "5", "cursor": "opaque_1",
        })
        detail = call(test, "shared-jira-issue-detail", params={
            "id": CONNECTION, "project_id": "10001", "issue_id": "DEMO-42",
        })
    for response in (listing, status, projects, issues, detail):
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        assert "secret" not in response.text
        assert "private-cloud-id" not in response.text
        assert "private content" not in response.text
    assert listing.json() == {
        "items": [status.json()], "limit": 20, "offset": 0, "has_more": False,
    }
    assert projects.json() == {"projects": [{"id": "10001", "key": "DEMO", "name": "Demo"}],
                               "next_cursor": None}
    assert issues.json()["issues"][0]["summary"] == "Bounded issue"
    assert issues.json()["next_cursor"] == "opaque_1"
    assert detail.json()["issue"]["key"] == "DEMO-42"
    assert repo.lookup_calls == ["org_Alpha"] * 5
    assert all(row[2] == "org_Alpha" and row[4] == 1_100_000 for row in broker.calls)
    reads = [row for row in broker.calls if row[1].endswith("/read")]
    assert [row[3]["operation"] for row in reads] == ["projects", "issues", "issue_detail"]
    assert [row[3]["project_ids"] for row in reads] == [[10001, 10002], [10001], [10001]]
    assert reads[1][3]["arguments"] == {"project_id": 10001, "limit": 5}
    assert reads[1][3]["cursor"] == "opaque_1"
    assert reads[2][3]["arguments"] == {"issue_id": "DEMO-42"}
    assert all("clerk_org_id" not in row[3] for row in reads)


@pytest.mark.parametrize("params", [
    {"id": "bad"}, {"id": CONNECTION, "clerk_org_id": "org_Beta"},
    {"id": CONNECTION, "project_id": "0"},
    {"id": CONNECTION, "project_id": "01"},
    {"id": CONNECTION, "project_id": "9223372036854775808"},
    {"id": CONNECTION, "project_id": "10001", "cursor": "https://example.test"},
    {"id": CONNECTION, "project_id": "10001", "limit": "51"},
    [("id", CONNECTION), ("id", CONNECTION), ("project_id", "10001")],
])
def test_invalid_or_duplicate_selector_is_rejected_before_broker(params):
    broker = Broker()
    with TestClient(app(broker=broker)) as test:
        response = call(test, "shared-jira-issues", params=params)
    assert response.status_code == 422
    assert broker.calls == []


@pytest.mark.parametrize("issue_id", ["demo-1", "DEMO-0", "DEMO-1 OR 1=1", "https://x", ""])
def test_issue_detail_rejects_unbounded_or_jql_like_selector(issue_id):
    broker = Broker()
    with TestClient(app(broker=broker)) as test:
        response = call(test, "shared-jira-issue-detail", params={
            "id": CONNECTION, "project_id": "10001", "issue_id": issue_id,
        })
    assert response.status_code == 422
    assert broker.calls == []


def test_project_selection_and_current_auth_fail_closed():
    broker = Broker()
    with TestClient(app(broker=broker)) as test:
        assert call(test, "shared-jira-issues", params={
            "id": CONNECTION, "project_id": "99999",
        }).status_code == 403
        assert call(test, "shared-jira-connections", headers={
            "Authorization": "Bearer removed-read"
        }).status_code == 403
        assert call(test, "shared-jira-connections", headers={
            "Authorization": "Bearer other-read"
        }).status_code == 404
        assert call(test, "shared-jira-connections", headers={
            "Authorization": "Bearer wrong-machine"
        }).status_code == 401
        assert test.post(f"{ROOT}/shared-jira-connections", headers=HEADERS).status_code == 404
    assert [row[1] for row in broker.calls] == [
        f"/internal/v1/connections/jira/{CONNECTION}/status"
    ]


def test_missing_scope_or_unhealthy_connection_never_reads_provider():
    for change in ({"available_scopes": ["jira.projects"]}, {"availability": "unavailable"}):
        broker = Broker()
        broker.status.update(change)
        with TestClient(app(broker=broker)) as test:
            response = call(test, "shared-jira-issues", params={
                "id": CONNECTION, "project_id": "10001",
            })
        assert response.status_code == 403
        assert all(not row[1].endswith("/read") for row in broker.calls)


def test_malformed_broker_identity_and_issue_payload_fail_closed_without_leak():
    broker = Broker()
    broker.status["id"] = "22222222-2222-4222-8222-222222222222"
    with TestClient(app(broker=broker)) as test:
        response = call(test, "shared-jira-status", params={"id": CONNECTION})
    assert response.status_code == 502 and "secret" not in response.text
    broker = Broker()
    broker.read = {"issues": [{**ISSUE, "project": {**PROJECT, "id": "99999"}}],
                   "next_cursor": None, "access_token": "secret"}
    with TestClient(app(broker=broker)) as test:
        response = call(test, "shared-jira-issues", params={
            "id": CONNECTION, "project_id": "10001",
        })
    assert response.status_code == 502 and "secret" not in response.text


@pytest.mark.parametrize("field", ["lifecycle_state", "health_state", "availability"])
@pytest.mark.parametrize("invalid", [None, [], {}, True])
def test_malformed_broker_connection_enums_return_sanitized_502(field, invalid):
    broker = Broker()
    broker.status[field] = invalid
    with TestClient(app(broker=broker)) as test:
        response = call(test, "shared-jira-status", params={"id": CONNECTION})
    assert response.status_code == 502
    assert response.json() == {"detail": "shared Jira response invalid"}
    assert "secret" not in response.text


@pytest.mark.parametrize("invalid", [None, [], {}, True])
def test_malformed_broker_project_type_returns_sanitized_502(invalid):
    broker = Broker()
    broker.read = {
        "projects": [{**PROJECT, "project_type": invalid}],
        "next_cursor": None,
        "access_token": "secret",
    }
    with TestClient(app(broker=broker)) as test:
        response = call(test, "shared-jira-projects", params={"id": CONNECTION})
    assert response.status_code == 502
    assert response.json() == {"detail": "shared Jira response invalid"}
    assert "secret" not in response.text


@pytest.mark.parametrize("invalid", [None, [], {}, True])
def test_malformed_broker_issue_status_returns_sanitized_502(invalid):
    broker = Broker()
    broker.read = {
        "issues": [{**ISSUE, "status": invalid}],
        "next_cursor": None,
        "access_token": "secret",
    }
    with TestClient(app(broker=broker)) as test:
        response = call(test, "shared-jira-issues", params={
            "id": CONNECTION, "project_id": "10001",
        })
    assert response.status_code == 502
    assert response.json() == {"detail": "shared Jira response invalid"}
    assert "secret" not in response.text
