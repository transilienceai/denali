from datetime import UTC, datetime

from denali.connections.google_workspace import (
    GOOGLE_WORKSPACE_AUDIT_SCOPE,
    GOOGLE_WORKSPACE_SCOPES,
    GoogleWorkspaceConnectionValidator,
    GoogleWorkspaceOperator,
    google_workspace_coverage_plan,
)

NOW = datetime(2026, 9, 8, 12, tzinfo=UTC)


class FakeReports:
    def __init__(self, failed_application=None):
        self.failed_application = failed_application
        self.calls = []

    def list(self, application_name, **kwargs):
        self.calls.append((application_name, kwargs))
        if application_name == self.failed_application:
            raise PermissionError("sensitive provider message")
        return ()


def connection(*, completed=True):
    configuration = {
        "domain": "iisecurity.in",
        "admin_email": "kkmookhey@iisecurity.in",
        "onboarding": {},
    }
    if completed:
        configuration["onboarding"]["completed_at"] = NOW.isoformat()
    return {
        "id": "connection-1",
        "configuration": configuration,
        "coverage_plan": google_workspace_coverage_plan(
            list(GOOGLE_WORKSPACE_SCOPES),
            domain="iisecurity.in",
            admin_email="kkmookhey@iisecurity.in",
        ),
    }


def test_coverage_discloses_one_read_only_scope_for_both_planes() -> None:
    plan = connection()["coverage_plan"]
    assert len(plan) == 2
    assert {permission for item in plan for permission in item["permissions"]} == {
        GOOGLE_WORKSPACE_AUDIT_SCOPE
    }
    assert {item["application_name"] for item in plan} == {
        "gemini_in_workspace_apps",
        "token",
    }


def test_validator_checks_both_planes_with_short_lived_delegation() -> None:
    reports = FakeReports()
    subjects = []
    operator = GoogleWorkspaceOperator(
        service_account="workspace@project.iam.gserviceaccount.com",
        oauth_client_id="123456789",
        client_factory=lambda subject: subjects.append(subject) or reports,
    )
    validation = GoogleWorkspaceConnectionValidator(operator, now=lambda: NOW).validate(
        connection()
    )

    assert validation["health_state"] == "healthy"
    assert validation["credential_state"] == "passed"
    assert validation["account_id_observed"] == "iisecurity.in"
    assert subjects == ["kkmookhey@iisecurity.in"]
    assert [call[0] for call in reports.calls] == ["gemini_in_workspace_apps", "token"]


def test_validator_never_treats_a_forbidden_plane_as_zero() -> None:
    reports = FakeReports(failed_application="token")
    operator = GoogleWorkspaceOperator(
        service_account="workspace@project.iam.gserviceaccount.com",
        oauth_client_id="123456789",
        client_factory=lambda _subject: reports,
    )
    validation = GoogleWorkspaceConnectionValidator(operator, now=lambda: NOW).validate(
        connection()
    )

    assert validation["health_state"] == "partial"
    assert [item["state"] for item in validation["results"]] == ["passed", "failed"]
    assert "sensitive provider message" not in repr(validation)


def test_validator_refuses_unconfirmed_authorization() -> None:
    reports = FakeReports()
    operator = GoogleWorkspaceOperator(
        service_account="workspace@project.iam.gserviceaccount.com",
        oauth_client_id="123456789",
        client_factory=lambda _subject: reports,
    )
    validation = GoogleWorkspaceConnectionValidator(operator).validate(
        connection(completed=False)
    )

    assert validation["health_state"] == "unhealthy"
    assert validation["credential_state"] == "failed"
    assert reports.calls == []
