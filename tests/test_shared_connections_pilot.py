from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from denali.integrations import shared_connections


class FakeCursor:
    def __init__(self, value):
        self.value = value

    def fetchone(self):
        return self.value

    def fetchall(self):
        return self.value


class FakeConnection:
    def __init__(self, rows, has_tenant=True):
        self.rows = rows
        self.has_tenant = has_tenant
        self.queries = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def execute(self, statement, params):
        self.queries.append((statement, params))
        if "FROM denali_tenant" in statement:
            return FakeCursor(
                {"id": UUID("11111111-1111-1111-1111-111111111111")} if self.has_tenant else None
            )
        return FakeCursor(self.rows)


def test_snapshot_is_scoped_and_never_exports_denali_credentials(monkeypatch):
    validated_at = datetime.now(UTC)
    connection = FakeConnection(
        [
            {
                "id": UUID("22222222-2222-2222-2222-222222222222"),
                "account_id": "123456789012",
                "partition": "aws-us-gov",
                "lifecycle_state": "active",
                "health_state": "healthy",
                "declared_scopes": ["aws.bedrock_agents"],
                "last_validated_at": validated_at,
                "role_arn": "must-not-export",
                "external_id": "must-not-export",
            }
        ]
    )
    monkeypatch.setattr(shared_connections.psycopg, "connect", lambda *_args, **_kw: connection)
    snapshot = shared_connections.aws_snapshot("unused-dsn", "org_123")
    assert snapshot["clerk_org_id"] == "org_123"
    assert snapshot["items"][0]["partition"] == "aws-us-gov"
    assert snapshot["items"][0]["validated_scopes"] == ["aws.bedrock_agents"]
    assert "role_arn" not in str(snapshot)
    assert "external_id" not in str(snapshot)
    assert connection.queries[0][1] == ("org_123",)
    assert connection.queries[1][1][0] == UUID("11111111-1111-1111-1111-111111111111")


def test_empty_snapshot_is_valid_only_for_an_existing_tenant(monkeypatch):
    connection = FakeConnection([])
    monkeypatch.setattr(shared_connections.psycopg, "connect", lambda *_args, **_kw: connection)
    assert shared_connections.aws_snapshot("unused-dsn", "org_123")["items"] == []
    connection.has_tenant = False
    with pytest.raises(ValueError, match="no Denali tenant"):
        shared_connections.aws_snapshot("unused-dsn", "org_123")


def test_snapshot_aborts_instead_of_sending_a_truncated_set(monkeypatch):
    rows = [
        {
            "id": UUID(int=index + 1),
            "account_id": "123456789012",
            "partition": "aws",
            "lifecycle_state": "active",
            "health_state": "unknown",
            "declared_scopes": [],
            "last_validated_at": None,
        }
        for index in range(101)
    ]
    monkeypatch.setattr(
        shared_connections.psycopg, "connect", lambda *_args, **_kw: FakeConnection(rows)
    )
    with pytest.raises(ValueError, match="bounded pilot limit"):
        shared_connections.aws_snapshot("unused-dsn", "org_123")


def test_publisher_requires_https_and_a_distinct_machine_key(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "http://platform.example")
    monkeypatch.setenv("DENALI_PLATFORM_MACHINE_SECRET_KEY", "test-key")
    with pytest.raises(ValueError, match="HTTPS origin"):
        shared_connections.publish_aws_snapshot("org_123")
    monkeypatch.setenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "https://platform.example")
    monkeypatch.delenv("DENALI_PLATFORM_MACHINE_SECRET_KEY")
    with pytest.raises(ValueError, match="MACHINE_SECRET_KEY"):
        shared_connections.publish_aws_snapshot("org_123")


def test_publisher_sends_one_complete_snapshot_with_clerk_m2m(monkeypatch):
    sent = {}

    class FakeM2m:
        def create_token(self, **options):
            assert options["seconds_until_expiration"] == 60
            return type("Token", (), {"token": "short-lived-test-token"})()

    class FakeClerk:
        def __init__(self, bearer_auth):
            assert bearer_auth == "machine-test-key"
            self.m2m = FakeM2m()

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"imported": 1, "tombstoned": 0}

    class FakeClient:
        def __init__(self, **options):
            assert options["follow_redirects"] is False

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return None

        def put(self, url, **options):
            sent.update(url=url, **options)
            return FakeResponse()

    monkeypatch.setenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "https://platform.example")
    monkeypatch.setenv("DENALI_PLATFORM_MACHINE_SECRET_KEY", "machine-test-key")
    monkeypatch.setenv("DENALI_DSN", "unused-dsn")
    monkeypatch.setattr(shared_connections, "Clerk", FakeClerk)
    monkeypatch.setattr(shared_connections.httpx, "Client", FakeClient)
    monkeypatch.setattr(
        shared_connections,
        "aws_snapshot",
        lambda _dsn, _org: {"clerk_org_id": "org_123", "items": [{"source_connection_id": "id"}]},
    )
    assert shared_connections.publish_aws_snapshot("org_123") == {
        "imported": 1,
        "tombstoned": 0,
    }
    assert sent["url"] == "https://platform.example/internal/v1/connections/aws/legacy/snapshot"
    assert sent["headers"] == {"Authorization": "Bearer short-lived-test-token"}
    assert sent["json"]["clerk_org_id"] == "org_123"
