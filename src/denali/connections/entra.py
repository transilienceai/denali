"""Microsoft Entra tenant-consent onboarding and read-plane validation."""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlencode, urlparse
from uuid import UUID

from denali.connectors.entra_ai import (
    APPLICATION_PERMISSION_PLANE,
    APPLICATION_PLANE,
    DELEGATED_GRANT_PLANE,
    DIRECTORY_AUDIT_PLANE,
    SERVICE_PRINCIPAL_PLANE,
    SIGN_IN_PLANE,
    GraphClient,
    MicrosoftGraphClient,
    acquire_graph_token,
)

ENTRA_SCOPE_APPLICATIONS = "entra.ai_applications"
ENTRA_SCOPE_PERMISSIONS = "entra.permissions"
ENTRA_SCOPE_SIGN_INS = "entra.sign_ins"
ENTRA_SCOPE_DIRECTORY_AUDITS = "entra.directory_audits"
ENTRA_SCOPES = (
    ENTRA_SCOPE_APPLICATIONS,
    ENTRA_SCOPE_PERMISSIONS,
    ENTRA_SCOPE_SIGN_INS,
    ENTRA_SCOPE_DIRECTORY_AUDITS,
)

_SCOPE_PLAN = {
    ENTRA_SCOPE_APPLICATIONS: (
        (
            APPLICATION_PLANE,
            "Microsoft Entra AI application inventory",
            "/v1.0/servicePrincipals",
            "id,appId",
        ),
        (
            SERVICE_PRINCIPAL_PLANE,
            "Microsoft Entra service-principal context",
            "/v1.0/servicePrincipals",
            "id,appId",
        ),
    ),
    ENTRA_SCOPE_PERMISSIONS: (
        (
            DELEGATED_GRANT_PLANE,
            "Microsoft Entra delegated grants",
            "/v1.0/oauth2PermissionGrants",
            "id",
        ),
        (
            APPLICATION_PERMISSION_PLANE,
            "Microsoft Entra application permissions",
            "/v1.0/servicePrincipals",
            "id,appId",
        ),
    ),
    ENTRA_SCOPE_SIGN_INS: (
        (
            SIGN_IN_PLANE,
            "Microsoft Entra AI application sign-ins",
            "/v1.0/auditLogs/signIns",
            "id",
        ),
    ),
    ENTRA_SCOPE_DIRECTORY_AUDITS: (
        (
            DIRECTORY_AUDIT_PLANE,
            "Microsoft Entra application directory audits",
            "/v1.0/auditLogs/directoryAudits",
            "id",
        ),
    ),
}


def entra_coverage_plan(scopes: list[str], tenant_id: str) -> list[dict[str, Any]]:
    """Expand declared Entra capabilities into independently validated Graph planes."""

    normalized_tenant = str(UUID(tenant_id))
    return [
        {
            "scope": f"tenants/{normalized_tenant}",
            "declared_scope": scope,
            "plane": plane,
            "label": label,
            "region": "global",
            "tenant_id": normalized_tenant,
            "permissions": [
                "Directory.Read.All",
                *(
                    ["AuditLog.Read.All"]
                    if scope
                    in {
                        ENTRA_SCOPE_SIGN_INS,
                        ENTRA_SCOPE_DIRECTORY_AUDITS,
                    }
                    else []
                ),
            ],
            "validation_state": "not_validated",
            "coverage_mode": "tenant-wide-admin-consent",
        }
        for scope in scopes
        for plane, label, _path, _select in _SCOPE_PLAN[scope]
    ]


class EntraAdminConsentClient:
    """Create bounded tenant-admin consent state and mint transient Graph clients."""

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        callback_url: str,
        web_url: str,
        token: Callable[[], str] | None = None,
        now: Callable[[], datetime] | None = None,
        setup_seconds: int = 1800,
        graph_client_factory: Callable[[str], GraphClient] | None = None,
    ):
        UUID(client_id)
        if not client_secret.strip():
            raise ValueError("Microsoft Entra client secret must not be blank")
        for url, label in ((callback_url, "callback"), (web_url, "web")):
            parsed = urlparse(url)
            is_https = parsed.scheme == "https" and bool(parsed.netloc)
            is_local_http = parsed.scheme == "http" and parsed.hostname in {
                "127.0.0.1",
                "localhost",
            }
            if not (is_https or is_local_http):
                raise ValueError(f"Microsoft Entra {label} URL is invalid")
        if not 300 <= setup_seconds <= 3600:
            raise ValueError("Microsoft Entra setup lifetime must be between 300 and 3600 seconds")
        self.client_id = client_id
        self.callback_url = callback_url.rstrip("/")
        self.web_url = web_url.rstrip("/")
        self._client_secret = client_secret
        self._token = token or (lambda: secrets.token_urlsafe(48))
        self._now = now or (lambda: datetime.now(UTC))
        self._setup_seconds = setup_seconds
        self._graph_client_factory = graph_client_factory

    def create_launch(
        self, *, denali_tenant_id: str, connection_id: str, entra_tenant_id: str
    ) -> dict[str, Any]:
        denali_tenant = str(UUID(denali_tenant_id))
        connection = str(UUID(connection_id))
        entra_tenant = str(UUID(entra_tenant_id))
        state = f"{denali_tenant}.{connection}.{self._token()}"
        created_at = self._now()
        query = urlencode(
            {
                "client_id": self.client_id,
                "scope": "https://graph.microsoft.com/.default",
                "redirect_uri": self.callback_url,
                "state": state,
            }
        )
        return {
            "consent_url": (
                f"https://login.microsoftonline.com/{entra_tenant}/v2.0/adminconsent?{query}"
            ),
            "state_sha256": hashlib.sha256(state.encode()).hexdigest(),
            "created_at": created_at,
            "expires_at": created_at + timedelta(seconds=self._setup_seconds),
        }

    def graph_client(self, entra_tenant_id: str) -> GraphClient:
        normalized_tenant = str(UUID(entra_tenant_id))
        if self._graph_client_factory is not None:
            return self._graph_client_factory(normalized_tenant)
        access_token = acquire_graph_token(
            tenant_id=normalized_tenant,
            client_id=self.client_id,
            client_secret=self._client_secret,
        )
        return MicrosoftGraphClient(access_token)


class EntraConnectionValidator:
    """Validate every declared Microsoft Graph plane independently."""

    def __init__(self, consent_client: EntraAdminConsentClient):
        self._consent_client = consent_client

    def validate(self, connection: dict[str, Any]) -> dict[str, Any]:
        started_at = datetime.now(UTC)
        tenant_id = str(connection.get("configuration", {}).get("tenant_id", ""))
        if not connection.get("configuration", {}).get("onboarding", {}).get("completed_at"):
            return _credential_failure(connection, started_at, "admin_consent_not_completed")
        try:
            graph = self._consent_client.graph_client(tenant_id)
        except Exception:
            return _credential_failure(connection, started_at, "graph_token_unavailable")

        results: list[dict[str, Any]] = []
        for planned in connection["coverage_plan"]:
            metadata = next(
                item
                for item in _SCOPE_PLAN[planned["declared_scope"]]
                if item[0] == planned["plane"]
            )
            result = {
                "scope": planned["scope"],
                "plane": planned["plane"],
                "label": planned["label"],
                "region": "global",
                "tenant_id": tenant_id,
            }
            try:
                graph.list(metadata[2], params={"$top": "1", "$select": metadata[3]}, limit=2)
                result.update(
                    state="passed",
                    detail="The declared read-only Microsoft Graph plane was callable.",
                )
            except Exception as error:
                result.update(
                    state="failed",
                    detail=f"Microsoft Graph validation failed ({type(error).__name__}).",
                )
            results.append(result)

        passed = sum(item["state"] == "passed" for item in results)
        health_state = "healthy" if passed == len(results) else "partial" if passed else "unhealthy"
        summary = (
            "All declared Microsoft Entra read planes validated."
            if health_state == "healthy"
            else f"Microsoft Entra validation passed {passed} of {len(results)} declared planes."
        )
        return {
            "started_at": started_at,
            "completed_at": datetime.now(UTC),
            "health_state": health_state,
            "credential_state": "passed",
            "account_id_observed": tenant_id,
            "results": results,
            "summary": summary,
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
                "tenant_id": item.get("tenant_id"),
                "state": "unknown",
                "detail": "Not attempted because Microsoft Entra consent or credentials failed.",
            }
            for item in connection["coverage_plan"]
        ],
        "summary": f"Unable to validate the Microsoft Entra connection ({code}).",
    }
