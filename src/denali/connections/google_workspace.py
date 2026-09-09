"""Google Workspace domain-wide delegation onboarding and validation."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

GOOGLE_WORKSPACE_AUDIT_SCOPE = "https://www.googleapis.com/auth/admin.reports.audit.readonly"
GOOGLE_WORKSPACE_SCOPE_GEMINI_ACTIVITY = "google_workspace.gemini_activity"
GOOGLE_WORKSPACE_SCOPE_OAUTH_ACTIVITY = "google_workspace.oauth_activity"
GOOGLE_WORKSPACE_SCOPES = (
    GOOGLE_WORKSPACE_SCOPE_GEMINI_ACTIVITY,
    GOOGLE_WORKSPACE_SCOPE_OAUTH_ACTIVITY,
)
GOOGLE_WORKSPACE_GEMINI_PLANE = "google_workspace_gemini_activity"
GOOGLE_WORKSPACE_OAUTH_PLANE = "google_workspace_oauth_activity"

_SCOPE_PLAN = {
    GOOGLE_WORKSPACE_SCOPE_GEMINI_ACTIVITY: (
        GOOGLE_WORKSPACE_GEMINI_PLANE,
        "Gemini in Google Workspace activity",
        "gemini_in_workspace_apps",
    ),
    GOOGLE_WORKSPACE_SCOPE_OAUTH_ACTIVITY: (
        GOOGLE_WORKSPACE_OAUTH_PLANE,
        "Google Workspace OAuth application activity",
        "token",
    ),
}


class WorkspaceReportsClient(Protocol):
    def list(
        self,
        application_name: str,
        *,
        start_time: datetime,
        end_time: datetime,
        max_results: int = 1000,
        limit: int = 20_000,
        follow_pagination: bool = True,
    ) -> tuple[dict[str, Any], ...]: ...


def google_workspace_coverage_plan(
    scopes: list[str], *, domain: str, admin_email: str
) -> list[dict[str, Any]]:
    """Expand the fixed read-only bundle into independently testable report planes."""

    return [
        {
            "scope": f"domains/{domain}",
            "declared_scope": scope,
            "plane": _SCOPE_PLAN[scope][0],
            "label": _SCOPE_PLAN[scope][1],
            "region": "global",
            "domain": domain,
            "admin_email": admin_email,
            "application_name": _SCOPE_PLAN[scope][2],
            "permissions": [GOOGLE_WORKSPACE_AUDIT_SCOPE],
            "validation_state": "not_validated",
            "coverage_mode": "domain-wide-delegation",
        }
        for scope in scopes
    ]


class GoogleWorkspaceOperator:
    """Mint short-lived delegated credentials without retaining a key or customer token."""

    def __init__(
        self,
        *,
        service_account: str,
        oauth_client_id: str,
        client_factory: Callable[[str], WorkspaceReportsClient] | None = None,
    ) -> None:
        if "@" not in service_account or not service_account.endswith(".iam.gserviceaccount.com"):
            raise ValueError("Google Workspace service account email is invalid")
        if not oauth_client_id.isdigit():
            raise ValueError("Google Workspace OAuth client ID must be numeric")
        self.service_account = service_account
        self.oauth_client_id = oauth_client_id
        self._client_factory = client_factory

    def reports_client(self, admin_email: str) -> WorkspaceReportsClient:
        if self._client_factory is not None:
            return self._client_factory(admin_email)
        from google.auth import default
        from google.auth.impersonated_credentials import Credentials

        from denali.connectors.google_workspace import GoogleWorkspaceReportsClient

        source_credentials, _ = default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        delegated = Credentials(
            source_credentials=source_credentials,
            target_principal=self.service_account,
            target_scopes=[GOOGLE_WORKSPACE_AUDIT_SCOPE],
            subject=admin_email,
            lifetime=3600,
        )
        return GoogleWorkspaceReportsClient(delegated)


class GoogleWorkspaceConnectionValidator:
    """Validate the fixed Workspace reports bundle plane by plane."""

    def __init__(
        self,
        operator: GoogleWorkspaceOperator,
        *,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self._operator = operator
        self._now = now or (lambda: datetime.now(UTC))

    def validate(self, connection: dict[str, Any]) -> dict[str, Any]:
        started_at = self._now()
        configuration = connection.get("configuration", {})
        domain = str(configuration.get("domain", ""))
        admin_email = str(configuration.get("admin_email", ""))
        if not configuration.get("onboarding", {}).get("completed_at"):
            return _credential_failure(connection, started_at, "authorization_not_confirmed")
        try:
            client = self._operator.reports_client(admin_email)
        except Exception:
            return _credential_failure(connection, started_at, "delegated_credentials_unavailable")

        end = self._now()
        start = end - timedelta(hours=1)
        results: list[dict[str, Any]] = []
        for planned in connection["coverage_plan"]:
            result = {
                "scope": planned["scope"],
                "plane": planned["plane"],
                "label": planned["label"],
                "region": "global",
                "domain": domain,
            }
            try:
                client.list(
                    str(planned["application_name"]),
                    start_time=start,
                    end_time=end,
                    max_results=1,
                    limit=2,
                    follow_pagination=False,
                )
                result.update(
                    state="passed",
                    detail="The delegated read-only Google Workspace report plane was callable.",
                )
            except Exception as error:
                result.update(
                    state="failed",
                    detail=f"Google Workspace validation failed ({type(error).__name__}).",
                )
            results.append(result)
        passed = sum(item["state"] == "passed" for item in results)
        health_state = "healthy" if passed == len(results) else "partial" if passed else "unhealthy"
        return {
            "started_at": started_at,
            "completed_at": self._now(),
            "health_state": health_state,
            "credential_state": "passed",
            "account_id_observed": domain,
            "results": results,
            "summary": (
                "All declared Google Workspace read planes validated."
                if health_state == "healthy"
                else (
                    f"Google Workspace validation passed {passed} of "
                    f"{len(results)} declared planes."
                )
            ),
        }


def _credential_failure(
    connection: dict[str, Any], started_at: datetime, code: str
) -> dict[str, Any]:
    return {
        "started_at": started_at,
        "completed_at": datetime.now(UTC),
        "health_state": "unhealthy",
        "credential_state": "failed",
        "account_id_observed": None,
        "results": [
            {
                "scope": item["scope"],
                "plane": item["plane"],
                "label": item["label"],
                "region": "global",
                "domain": item.get("domain"),
                "state": "unknown",
                "detail": "Not attempted because Workspace delegation was not available.",
            }
            for item in connection["coverage_plan"]
        ],
        "summary": f"Unable to validate the Google Workspace connection ({code}).",
    }
