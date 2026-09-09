from datetime import UTC, datetime

from denali.connectors.google_workspace import (
    GoogleWorkspaceConnector,
    GoogleWorkspaceReportsClient,
)

NOW = datetime(2026, 9, 8, 12, tzinfo=UTC)


class FakeReports:
    def __init__(self, records):
        self.records = records
        self.calls = []

    def list(self, application_name, **kwargs):
        self.calls.append((application_name, kwargs))
        value = self.records[application_name]
        if isinstance(value, Exception):
            raise value
        return tuple(value)


def record(application, qualifier, events):
    return {
        "id": {
            "time": "2026-09-08T11:00:00Z",
            "uniqueQualifier": qualifier,
            "applicationName": application,
            "customerId": "C0123",
        },
        "actor": {"email": "person@example.com", "profileId": "42"},
        "events": events,
    }


def parameter(name, value):
    return {"name": name, "value": value}


def test_collects_gemini_and_catalog_matched_oauth_without_sensitive_payloads() -> None:
    reports = FakeReports(
        {
            "gemini_in_workspace_apps": [
                record(
                    "gemini_in_workspace_apps",
                    "gemini-1",
                    [
                        {
                            "type": "ai_usage_event",
                            "name": "feature_utilization",
                            "parameters": [
                                parameter("action", "generate text"),
                                parameter("feature_source", "GMAIL"),
                                parameter("prompt", "must-not-be-retained"),
                            ],
                        }
                    ],
                )
            ],
            "token": [
                record(
                    "token",
                    "token-1",
                    [
                        {
                            "type": "auth",
                            "name": "authorize",
                            "parameters": [
                                parameter("app_name", "ChatGPT Enterprise"),
                                parameter("client_id", "oauth-client-1"),
                                {"name": "scope", "multiValue": ["openid", "email"]},
                            ],
                        }
                    ],
                ),
                record(
                    "token",
                    "token-2",
                    [
                        {
                            "type": "auth",
                            "name": "authorize",
                            "parameters": [
                                parameter("app_name", "Ordinary Calendar Tool"),
                                parameter("client_id", "oauth-client-2"),
                            ],
                        }
                    ],
                ),
            ],
        }
    )
    inventory, activity = GoogleWorkspaceConnector(
        domain="example.com", reports_client=reports, now=lambda: NOW
    ).collect(
        start_time=datetime(2026, 9, 1, tzinfo=UTC),
        end_time=NOW,
        connection_id="connection-1",
    )

    assert {asset.display_name for asset in inventory.assets} == {
        "Gemini in Google Workspace",
        "ChatGPT Enterprise",
    }
    assert len(activity.activities) == 2
    assert {item.category.value for item in activity.activities} == {
        "model_invocation",
        "admin_change",
    }
    assert all(item.outcome.value == "unknown" for item in activity.activities)
    assert "must-not-be-retained" not in repr(activity)
    assert [item.state.value for item in inventory.coverage] == ["complete", "complete"]


def test_one_failed_report_plane_remains_explicitly_partial() -> None:
    reports = FakeReports(
        {
            "gemini_in_workspace_apps": PermissionError("forbidden payload"),
            "token": [],
        }
    )
    inventory, activity = GoogleWorkspaceConnector(
        domain="example.com", reports_client=reports, now=lambda: NOW
    ).collect(
        start_time=datetime(2026, 9, 1, tzinfo=UTC),
        end_time=NOW,
        connection_id="connection-1",
    )

    assert [item.state.value for item in inventory.coverage] == ["failed", "complete"]
    assert [item.state.value for item in activity.coverage] == ["failed", "complete"]
    assert "forbidden payload" not in repr(inventory.coverage)


def test_reports_validation_probe_ignores_next_page_token() -> None:
    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {
                "items": [{"id": {"uniqueQualifier": "first"}}],
                "nextPageToken": "more-records-exist",
            }

    class Session:
        def __init__(self):
            self.calls = []

        def get(self, url, *, timeout):
            self.calls.append((url, timeout))
            return Response()

    client = GoogleWorkspaceReportsClient.__new__(GoogleWorkspaceReportsClient)
    client._session = Session()
    client._timeout = 30.0

    records = client.list(
        "gemini_in_workspace_apps",
        start_time=datetime(2026, 9, 8, 11, tzinfo=UTC),
        end_time=NOW,
        max_results=1,
        limit=2,
        follow_pagination=False,
    )

    assert records == ({"id": {"uniqueQualifier": "first"}},)
    assert len(client._session.calls) == 1
