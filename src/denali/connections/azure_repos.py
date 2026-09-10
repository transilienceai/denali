"""Microsoft Entra OAuth onboarding and read-only Azure Repos validation."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import quote, urlencode, urlparse
from uuid import UUID

AZURE_REPOS_SCOPE_METADATA = "azure_repos.repository_metadata"
AZURE_REPOS_SCOPE_CONTENTS = "azure_repos.repository_contents"
AZURE_REPOS_SCOPES = (AZURE_REPOS_SCOPE_METADATA, AZURE_REPOS_SCOPE_CONTENTS)
AZURE_DEVOPS_RESOURCE_SCOPE = "https://app.vssps.visualstudio.com/.default"
AZURE_DEVOPS_API_VERSION = "7.1"
MAX_AZURE_REPOSITORIES = 500

_ORGANIZATION = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,48}[A-Za-z0-9])?$")
_SCOPE_PLAN = {
    AZURE_REPOS_SCOPE_METADATA: {
        "plane": "azure_repos_repository_metadata",
        "label": "Azure Repos repository metadata",
        "permission": "vso.code",
    },
    AZURE_REPOS_SCOPE_CONTENTS: {
        "plane": "azure_repos_repository_contents",
        "label": "Azure Repos source revision access",
        "permission": "vso.code",
    },
}


class AzureReposHttpResponse(Protocol):
    status_code: int
    headers: Any

    def raise_for_status(self) -> None: ...

    def json(self) -> Any: ...


AzureReposRequest = Callable[..., AzureReposHttpResponse]


def valid_azure_devops_organization(value: str) -> bool:
    return bool(_ORGANIZATION.fullmatch(value))


def azure_repos_coverage_plan(
    scopes: list[str], *, organization: str, repositories: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Expand declared Azure Repos scopes over immutable repository UUIDs."""

    if not valid_azure_devops_organization(organization):
        raise ValueError("Azure DevOps organization is invalid")
    return [
        {
            "scope": f"organizations/{organization}/repositories/{repository['id']}",
            "declared_scope": scope,
            "plane": _SCOPE_PLAN[scope]["plane"],
            "label": _SCOPE_PLAN[scope]["label"],
            "region": "dev.azure.com",
            "organization": organization,
            "repository_id": repository["id"],
            "repository_full_name": repository["full_name"],
            "project_id": repository["project_id"],
            "project_name": repository["project_name"],
            "permissions": [_SCOPE_PLAN[scope]["permission"]],
            "validation_state": "not_validated",
            "coverage_mode": "exact-azure-repositories",
        }
        for repository in repositories
        for scope in scopes
    ]


class AzureReposClient:
    """Use transient user OAuth for setup and app-only tokens for steady-state reads."""

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        callback_url: str,
        web_url: str,
        request: AzureReposRequest | None = None,
        now: Callable[[], datetime] | None = None,
        token: Callable[[], str] | None = None,
        setup_seconds: int = 1800,
    ):
        UUID(client_id)
        if not client_secret.strip():
            raise ValueError("Azure Repos client secret must not be blank")
        for url, label in ((callback_url, "callback"), (web_url, "web")):
            parsed = urlparse(url)
            valid = parsed.scheme == "https" and bool(parsed.netloc)
            local = parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"}
            if not (valid or local):
                raise ValueError(f"Azure Repos {label} URL is invalid")
        if not 300 <= setup_seconds <= 3600:
            raise ValueError("Azure Repos setup lifetime must be between 300 and 3600 seconds")
        self.client_id = client_id
        self.callback_url = callback_url.rstrip("/")
        self.web_url = web_url.rstrip("/")
        self._client_secret = client_secret
        self._request = request or _default_request
        self._now = now or (lambda: datetime.now(UTC))
        self._token = token or (lambda: secrets.token_urlsafe(48))
        self._setup_seconds = setup_seconds

    def create_oauth_launch(
        self, *, denali_tenant_id: str, connection_id: str, entra_tenant_id: str
    ) -> dict[str, Any]:
        denali_tenant = str(UUID(denali_tenant_id))
        connection = str(UUID(connection_id))
        entra_tenant = str(UUID(entra_tenant_id))
        state = f"{denali_tenant}.{connection}.{self._token()}"
        verifier = self._token()
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode()
        created_at = self._now()
        query = urlencode(
            {
                "client_id": self.client_id,
                "response_type": "code",
                "redirect_uri": self.callback_url,
                "response_mode": "query",
                "scope": AZURE_DEVOPS_RESOURCE_SCOPE,
                "state": state,
                "code_challenge": challenge.rstrip("="),
                "code_challenge_method": "S256",
                "prompt": "select_account",
            }
        )
        return {
            "authorize_url": (
                f"https://login.microsoftonline.com/{entra_tenant}/oauth2/v2.0/authorize?{query}"
            ),
            "state_sha256": hashlib.sha256(state.encode()).hexdigest(),
            "pkce_verifier": verifier,
            "created_at": created_at,
            "expires_at": created_at + timedelta(seconds=self._setup_seconds),
        }

    def exchange_user_code(self, *, tenant_id: str, code: str, pkce_verifier: str) -> str:
        return self._exchange_token(
            tenant_id,
            {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": self._client_secret,
                "code": code,
                "redirect_uri": self.callback_url,
                "code_verifier": pkce_verifier,
                "scope": AZURE_DEVOPS_RESOURCE_SCOPE,
            },
        )

    def application_token(self, tenant_id: str) -> str:
        return self._exchange_token(
            tenant_id,
            {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self._client_secret,
                "scope": AZURE_DEVOPS_RESOURCE_SCOPE,
            },
        )

    def list_repositories(self, *, organization: str, token: str) -> list[dict[str, Any]]:
        if not valid_azure_devops_organization(organization):
            raise ValueError("Azure DevOps organization is invalid")
        response = self.request(
            "GET", organization=organization, path="/_apis/git/repositories", token=token
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("value"), list):
            raise RuntimeError("Azure DevOps returned an invalid repository list")
        count = payload.get("count")
        values = payload["value"]
        if count != len(values) or not 1 <= len(values) <= MAX_AZURE_REPOSITORIES:
            raise RuntimeError("Azure DevOps repository selection is empty or exceeds 500")
        repositories = [_repository_boundary(item) for item in values]
        if len({item["id"] for item in repositories}) != len(repositories):
            raise RuntimeError("Azure DevOps returned duplicate repository identities")
        return sorted(repositories, key=lambda item: item["full_name"].casefold())

    def request(
        self,
        method: str,
        *,
        organization: str,
        path: str,
        token: str,
        **kwargs: Any,
    ) -> AzureReposHttpResponse:
        if not valid_azure_devops_organization(organization):
            raise ValueError("Azure DevOps organization is invalid")
        if not path.startswith("/") or ".." in path:
            raise ValueError("Azure DevOps API path is invalid")
        params = dict(kwargs.pop("params", {}))
        params.setdefault("api-version", AZURE_DEVOPS_API_VERSION)
        accept = str(kwargs.pop("accept", "application/json"))
        return self._request(
            method,
            f"https://dev.azure.com/{quote(organization, safe='')}{path}",
            headers={"Accept": accept, "Authorization": f"Bearer {token}"},
            params=params,
            timeout=kwargs.pop("timeout", 20.0),
            **kwargs,
        )

    def _exchange_token(self, tenant_id: str, data: dict[str, str]) -> str:
        normalized_tenant = str(UUID(tenant_id))
        response = self._request(
            "POST",
            f"https://login.microsoftonline.com/{normalized_tenant}/oauth2/v2.0/token",
            data=data,
            timeout=15.0,
        )
        response.raise_for_status()
        payload = response.json()
        token = str(payload.get("access_token", "")) if isinstance(payload, dict) else ""
        if len(token) < 32:
            raise RuntimeError("Microsoft did not return a valid Azure DevOps access token")
        return token


class AzureReposConnectionValidator:
    """Validate app identity and every selected repository read plane independently."""

    def __init__(self, client: AzureReposClient):
        self._client = client

    def validate(self, connection: dict[str, Any]) -> dict[str, Any]:
        started_at = datetime.now(UTC)
        configuration = connection.get("configuration", {})
        repositories = configuration.get("repositories", [])
        tenant_id = str(configuration.get("tenant_id", ""))
        organization = str(configuration.get("organization", ""))
        if not repositories or not configuration.get("onboarding", {}).get("completed_at"):
            return _credential_failure(connection, started_at, "repository_selection_not_completed")
        try:
            token = self._client.application_token(tenant_id)
            observed = self._client.list_repositories(organization=organization, token=token)
            observed_by_id = {item["id"]: item for item in observed}
        except Exception as error:
            return _credential_failure(connection, started_at, _error_code(error))

        results: list[dict[str, Any]] = []
        for repository in repositories:
            plans = azure_repos_coverage_plan(
                connection["declared_scopes"],
                organization=organization,
                repositories=[repository],
            )
            current = observed_by_id.get(repository["id"])
            if current is None or not _same_repository(repository, current):
                results.extend(
                    _result(plan, "unknown", "Immutable repository binding did not match.")
                    for plan in plans
                )
                continue
            for plan in plans:
                try:
                    detail = "Immutable repository and project UUIDs matched."
                    if plan["plane"] == "azure_repos_repository_contents":
                        default_branch = current.get("default_branch")
                        if default_branch:
                            response = self._client.request(
                                "GET",
                                organization=organization,
                                path=f"/_apis/git/repositories/{current['id']}/refs",
                                token=token,
                                params={"filter": default_branch.removeprefix("refs/")},
                            )
                            response.raise_for_status()
                            payload = response.json()
                            values = payload.get("value") if isinstance(payload, dict) else None
                            if not isinstance(values, list) or not any(
                                item.get("name") == default_branch
                                for item in values
                                if isinstance(item, dict)
                            ):
                                raise RuntimeError("default branch was not readable")
                            detail = "The default source revision was readable through vso.code."
                        else:
                            detail = "Repository read succeeded; no default branch exists yet."
                    results.append(_result(plan, "passed", detail))
                except Exception as error:
                    results.append(
                        _result(
                            plan,
                            "failed",
                            f"Validation call failed ({_error_code(error)}).",
                        )
                    )
        failed = sum(item["state"] in {"failed", "unknown"} for item in results)
        health = "healthy" if failed == 0 else "partial"
        summary = (
            "Azure DevOps app identity and every declared repository check passed for "
            f"{len(repositories)} exact repository(s)."
            if health == "healthy"
            else f"Azure DevOps identity validated; {failed} repository check(s) need attention."
        )
        return {
            "started_at": started_at,
            "completed_at": datetime.now(UTC),
            "health_state": health,
            "credential_state": "passed",
            "account_id_observed": organization,
            "results": results,
            "summary": summary,
        }


def _repository_boundary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("Azure DevOps returned an invalid repository")
    project = value.get("project")
    try:
        repository_id = str(UUID(str(value.get("id", ""))))
        project_id = str(UUID(str(project.get("id", "")))) if isinstance(project, dict) else ""
    except ValueError as error:
        raise RuntimeError("Azure DevOps returned an invalid repository identity") from error
    name = str(value.get("name", ""))
    project_name = str(project.get("name", "")) if isinstance(project, dict) else ""
    if not name or len(name) > 256 or not project_name or len(project_name) > 256:
        raise RuntimeError("Azure DevOps returned an invalid repository name")
    return {
        "id": repository_id,
        "name": name,
        "full_name": f"{project_name}/{name}",
        "project_id": project_id,
        "project_name": project_name,
        "default_branch": str(value.get("defaultBranch") or "")[:512] or None,
        "remote_url": str(value.get("remoteUrl") or "")[:2048] or None,
    }


def _same_repository(expected: dict[str, Any], observed: dict[str, Any]) -> bool:
    return (
        expected.get("id") == observed.get("id")
        and expected.get("project_id") == observed.get("project_id")
        and str(expected.get("name", "")).casefold() == str(observed.get("name", "")).casefold()
        and str(expected.get("project_name", "")).casefold()
        == str(observed.get("project_name", "")).casefold()
    )


def _result(plan: dict[str, Any], state: str, detail: str) -> dict[str, Any]:
    return {
        "scope": plan["scope"],
        "plane": plan["plane"],
        "label": plan["label"],
        "region": "dev.azure.com",
        "organization": plan["organization"],
        "repository_id": plan["repository_id"],
        "repository_full_name": plan["repository_full_name"],
        "project_id": plan["project_id"],
        "project_name": plan["project_name"],
        "state": state,
        "detail": detail,
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
            _result(item, "unknown", "Not attempted because app identity validation failed.")
            for item in connection.get("coverage_plan", [])
        ],
        "summary": f"Unable to validate Azure Repos read access ({code}).",
    }


def _error_code(error: Exception) -> str:
    response = getattr(error, "response", None)
    if response is not None and getattr(response, "status_code", None):
        return f"HTTP{response.status_code}"
    return error.__class__.__name__


def _default_request(method: str, url: str, **kwargs: Any) -> AzureReposHttpResponse:
    try:
        import httpx
    except ImportError as error:  # pragma: no cover
        raise RuntimeError("httpx is required for Azure Repos onboarding") from error
    return httpx.request(method, url, **kwargs)
