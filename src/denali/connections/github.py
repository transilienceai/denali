"""Keyless GitHub App onboarding and repository-bound validation."""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol
from urllib.parse import quote, urlencode

GITHUB_SCOPE_REPOSITORY_METADATA = "github.repository_metadata"
GITHUB_SCOPE_REPOSITORY_CONTENTS = "github.repository_contents"
GITHUB_SCOPE_ACTIONS_WORKFLOWS = "github.actions_workflows"
GITHUB_SCOPES = (
    GITHUB_SCOPE_REPOSITORY_METADATA,
    GITHUB_SCOPE_REPOSITORY_CONTENTS,
    GITHUB_SCOPE_ACTIONS_WORKFLOWS,
)
GITHUB_REQUIRED_PERMISSIONS = {
    "metadata": "read",
    "contents": "read",
    "actions": "read",
}
GITHUB_API_VERSION = "2026-03-10"
GITHUB_API_BASE = "https://api.github.com"

_GITHUB_LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_GITHUB_REPOSITORY = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?/[A-Za-z0-9_.-]{1,100}$"
)
_GITHUB_APP_SLUG = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,98}[a-z0-9])?$")

_SCOPE_PLAN = {
    GITHUB_SCOPE_REPOSITORY_METADATA: {
        "plane": "github_repository_metadata",
        "label": "GitHub repository metadata",
        "permission": "metadata:read",
    },
    GITHUB_SCOPE_REPOSITORY_CONTENTS: {
        "plane": "github_repository_contents",
        "label": "GitHub source revision access",
        "permission": "contents:read",
    },
    GITHUB_SCOPE_ACTIONS_WORKFLOWS: {
        "plane": "github_actions_workflows",
        "label": "GitHub Actions workflow inventory",
        "permission": "actions:read",
    },
}


class GitHubHttpResponse(Protocol):
    status_code: int

    def raise_for_status(self) -> None: ...

    def json(self) -> Any: ...


GitHubRequest = Callable[..., GitHubHttpResponse]


def github_coverage_plan(
    scopes: list[str], repositories: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Expand declared GitHub scopes over immutable selected repository IDs."""

    return [
        {
            "scope": f"repositories/{repository['id']}",
            "declared_scope": scope,
            "plane": _SCOPE_PLAN[scope]["plane"],
            "label": _SCOPE_PLAN[scope]["label"],
            "region": "github.com",
            "repository_id": repository["id"],
            "repository_node_id": repository["node_id"],
            "repository_full_name": repository["full_name"],
            "permissions": [_SCOPE_PLAN[scope]["permission"]],
            "validation_state": "not_validated",
            "coverage_mode": "exact-installation-repositories",
        }
        for repository in repositories
        for scope in scopes
    ]


class GitHubAppClient:
    """Operate Denali's GitHub App without persisting installation or user tokens."""

    def __init__(
        self,
        *,
        app_id: int,
        client_id: str,
        client_secret: str,
        private_key: str,
        app_slug: str,
        callback_url: str,
        web_url: str,
        request: GitHubRequest | None = None,
        now: Callable[[], datetime] | None = None,
        token: Callable[[], str] | None = None,
        setup_seconds: int = 3600,
    ):
        if app_id <= 0:
            raise ValueError("GitHub App ID must be positive")
        if not client_id.strip() or not client_secret.strip():
            raise ValueError("GitHub App OAuth credentials must not be blank")
        if "PRIVATE KEY" not in private_key:
            raise ValueError("GitHub App private key is invalid")
        if not _GITHUB_APP_SLUG.fullmatch(app_slug):
            raise ValueError("GitHub App slug is invalid")
        for url, label in ((callback_url, "callback"), (web_url, "web")):
            if not url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
                raise ValueError(f"GitHub App {label} URL is invalid")
        if not 300 <= setup_seconds <= 3600:
            raise ValueError("GitHub setup lifetime must be between 300 and 3600 seconds")
        self.app_id = app_id
        self.client_id = client_id
        self.app_slug = app_slug
        self.callback_url = callback_url.rstrip("/")
        self.web_url = web_url.rstrip("/")
        self._client_secret = client_secret
        self._private_key = private_key
        self._request = request or _default_request
        self._now = now or (lambda: datetime.now(UTC))
        self._token = token or (lambda: secrets.token_urlsafe(48))
        self._setup_seconds = setup_seconds

    def create_install_launch(self, *, tenant_id: str, connection_id: str) -> dict[str, Any]:
        state = f"{tenant_id}.{connection_id}.{self._token()}"
        created_at = self._now()
        return {
            "install_url": (
                f"https://github.com/apps/{self.app_slug}/installations/new?"
                f"{urlencode({'state': state})}"
            ),
            "state_sha256": _sha256(state),
            "created_at": created_at,
            "expires_at": created_at + timedelta(seconds=self._setup_seconds),
        }

    def create_oauth_launch(self, *, tenant_id: str, connection_id: str) -> dict[str, Any]:
        state = f"{tenant_id}.{connection_id}.{self._token()}"
        verifier = self._token()
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode()
        challenge = challenge.rstrip("=")
        created_at = self._now()
        query = urlencode(
            {
                "client_id": self.client_id,
                "redirect_uri": self.callback_url,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "allow_signup": "false",
            }
        )
        return {
            "authorize_url": f"https://github.com/login/oauth/authorize?{query}",
            "state_sha256": _sha256(state),
            "pkce_verifier": verifier,
            "created_at": created_at,
            "expires_at": created_at + timedelta(seconds=self._setup_seconds),
        }

    def exchange_user_code(self, *, code: str, pkce_verifier: str) -> str:
        response = self._request(
            "POST",
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json"},
            data={
                "client_id": self.client_id,
                "client_secret": self._client_secret,
                "code": code,
                "redirect_uri": self.callback_url,
                "code_verifier": pkce_verifier,
            },
            timeout=15.0,
        )
        response.raise_for_status()
        payload = response.json()
        access_token = str(payload.get("access_token", ""))
        if not access_token.startswith("ghu_"):
            raise RuntimeError("GitHub did not return a valid expiring user token")
        return access_token

    def verify_user_installation(
        self, *, installation_id: int, user_token: str
    ) -> dict[str, Any]:
        installation = self.get_installation(installation_id)
        user_response = self._user_request("GET", "/user", user_token=user_token)
        user_response.raise_for_status()
        user = user_response.json()
        user_id = user.get("id")
        user_login = str(user.get("login", ""))
        if not isinstance(user_id, int) or user_id <= 0 or not valid_github_login(user_login):
            raise RuntimeError("GitHub returned an invalid installer identity")

        repositories: list[dict[str, Any]] = []
        expected_total: int | None = None
        for page in range(1, 6):
            response = self._user_request(
                "GET",
                f"/user/installations/{installation_id}/repositories",
                user_token=user_token,
                params={"per_page": 100, "page": page},
            )
            response.raise_for_status()
            payload = response.json()
            page_repositories = payload.get("repositories")
            total_count = payload.get("total_count")
            if (
                not isinstance(page_repositories, list)
                or not isinstance(total_count, int)
                or total_count < 1
            ):
                raise RuntimeError("GitHub returned an invalid repository selection")
            if expected_total is None:
                expected_total = total_count
            elif expected_total != total_count:
                raise RuntimeError("GitHub repository selection changed during verification")
            if expected_total > 500:
                raise RuntimeError("Select no more than 500 GitHub repositories")
            repositories.extend(_repository_boundary(item) for item in page_repositories)
            if len(page_repositories) < 100:
                break
        if expected_total != len(repositories) or not 1 <= len(repositories) <= 500:
            raise RuntimeError("Select between 1 and 500 GitHub repositories")
        if len({item["id"] for item in repositories}) != len(repositories):
            raise RuntimeError("GitHub returned duplicate repository identities")
        return {
            "installation": installation,
            "installer": {"id": user_id, "login": user_login},
            "repositories": sorted(repositories, key=lambda item: item["full_name"].lower()),
        }

    def get_installation(self, installation_id: int) -> dict[str, Any]:
        response = self._app_request("GET", f"/app/installations/{installation_id}")
        response.raise_for_status()
        payload = response.json()
        if payload.get("id") != installation_id or payload.get("app_id") != self.app_id:
            raise RuntimeError("GitHub installation identity does not match Denali's App")
        account = payload.get("account")
        permissions = payload.get("permissions")
        if not isinstance(account, dict) or not isinstance(permissions, dict):
            raise RuntimeError("GitHub returned an invalid installation")
        account_id = account.get("id")
        account_login = str(account.get("login", ""))
        if (
            not isinstance(account_id, int)
            or account_id <= 0
            or not valid_github_login(account_login)
        ):
            raise RuntimeError("GitHub returned an invalid installation account")
        missing = [
            f"{name}:{level}"
            for name, level in GITHUB_REQUIRED_PERMISSIONS.items()
            if permissions.get(name) != level
        ]
        if missing:
            raise GitHubPermissionError(",".join(missing))
        if payload.get("suspended_at"):
            raise RuntimeError("GitHub App installation is suspended")
        selection = str(payload.get("repository_selection", ""))
        if selection not in {"all", "selected"}:
            raise RuntimeError("GitHub returned an invalid repository selection mode")
        return {
            "id": installation_id,
            "account_id": account_id,
            "account_login": account_login,
            "account_type": str(account.get("type", "Unknown")),
            "repository_selection": selection,
            "permissions": dict(permissions),
        }

    def create_installation_token(self, *, installation_id: int, repository_id: int) -> str:
        response = self._app_request(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            json={
                "repository_ids": [repository_id],
                "permissions": GITHUB_REQUIRED_PERMISSIONS,
            },
        )
        response.raise_for_status()
        token = str(response.json().get("token", ""))
        if not token.startswith("ghs_"):
            raise RuntimeError("GitHub did not return a valid installation token")
        return token

    def installation_request(
        self, method: str, path: str, *, token: str, **kwargs: Any
    ) -> GitHubHttpResponse:
        return self._request(
            method,
            f"{GITHUB_API_BASE}{path}",
            headers=_github_headers(token),
            timeout=kwargs.pop("timeout", 10.0),
            **kwargs,
        )

    def _app_request(self, method: str, path: str, **kwargs: Any) -> GitHubHttpResponse:
        return self._request(
            method,
            f"{GITHUB_API_BASE}{path}",
            headers=_github_headers(self._app_jwt()),
            timeout=kwargs.pop("timeout", 15.0),
            **kwargs,
        )

    def _user_request(
        self, method: str, path: str, *, user_token: str, **kwargs: Any
    ) -> GitHubHttpResponse:
        return self._request(
            method,
            f"{GITHUB_API_BASE}{path}",
            headers=_github_headers(user_token),
            timeout=kwargs.pop("timeout", 15.0),
            **kwargs,
        )

    def _app_jwt(self) -> str:
        try:
            import jwt
        except ImportError as error:  # pragma: no cover - installation contract
            raise RuntimeError("install Denali with the github extra") from error
        now = self._now()
        encoded = jwt.encode(
            {
                "iat": int((now - timedelta(seconds=60)).timestamp()),
                "exp": int((now + timedelta(minutes=9)).timestamp()),
                "iss": str(self.app_id),
            },
            self._private_key,
            algorithm="RS256",
        )
        return str(encoded)


class GitHubConnectionValidator:
    """Validate one installation and every exact repository/plane independently."""

    def __init__(self, app_client: GitHubAppClient):
        self._app = app_client

    def validate(self, connection: dict[str, Any]) -> dict[str, Any]:
        started_at = datetime.now(UTC)
        reference = connection["credential_reference"]
        installation_id = reference.get("installation_id")
        repositories = connection["configuration"].get("repositories", [])
        if not isinstance(installation_id, int) or not repositories:
            return _credential_failure(connection, started_at, "installation_not_completed")
        try:
            installation = self._app.get_installation(installation_id)
            if installation["account_id"] != connection["configuration"]["account_id"]:
                raise GitHubBindingError("account_id_mismatch")
            if installation["account_login"].lower() != str(
                connection["configuration"]["account_login"]
            ).lower():
                raise GitHubBindingError("account_login_mismatch")
        except Exception as error:
            return _credential_failure(connection, started_at, _github_error_code(error))

        results: list[dict[str, Any]] = []
        for repository in repositories:
            results.extend(
                self._validate_repository(
                    installation_id=installation_id,
                    repository=repository,
                    scopes=connection["declared_scopes"],
                )
            )
        failed_count = sum(item["state"] in {"failed", "unknown"} for item in results)
        health = "healthy" if failed_count == 0 else "partial"
        summary = (
            "GitHub App installation and every declared repository check passed for "
            f"{len(repositories)} exact repository(s)."
            if health == "healthy"
            else (
                f"GitHub App installation validated; {failed_count} repository coverage "
                "check(s) failed or remain unknown."
            )
        )
        return {
            "started_at": started_at,
            "completed_at": datetime.now(UTC),
            "health_state": health,
            "credential_state": "passed",
            "account_id_observed": str(installation["account_id"]),
            "results": results,
            "summary": summary,
        }

    def _validate_repository(
        self,
        *,
        installation_id: int,
        repository: dict[str, Any],
        scopes: list[str],
    ) -> list[dict[str, Any]]:
        plans = github_coverage_plan(scopes, [repository])
        try:
            token = self._app.create_installation_token(
                installation_id=installation_id,
                repository_id=repository["id"],
            )
            response = self._app.installation_request(
                "GET", f"/repos/{repository['full_name']}", token=token
            )
            response.raise_for_status()
            observed = response.json()
            if observed.get("id") != repository["id"]:
                raise GitHubBindingError("repository_id_mismatch")
            if str(observed.get("node_id", "")) != repository["node_id"]:
                raise GitHubBindingError("repository_node_id_mismatch")
            if str(observed.get("full_name", "")).lower() != repository["full_name"].lower():
                raise GitHubBindingError("repository_name_mismatch")
            observed_owner = observed.get("owner")
            if (
                not isinstance(observed_owner, dict)
                or observed_owner.get("id") != repository["owner_id"]
                or str(observed_owner.get("login", "")).lower()
                != repository["owner_login"].lower()
            ):
                raise GitHubBindingError("repository_owner_mismatch")
        except Exception as error:
            return [
                _result(
                    plan,
                    "unknown",
                    f"Repository binding failed ({_github_error_code(error)}).",
                )
                for plan in plans
            ]

        results: list[dict[str, Any]] = []
        for plan in plans:
            try:
                if plan["plane"] == "github_repository_metadata":
                    detail = "Immutable repository ID, node ID, and full name matched."
                elif plan["plane"] == "github_repository_contents":
                    branch = observed.get("default_branch")
                    if branch:
                        encoded = quote(f"heads/{branch}", safe="/")
                        check = self._app.installation_request(
                            "GET",
                            f"/repos/{repository['full_name']}/git/ref/{encoded}",
                            token=token,
                        )
                        check.raise_for_status()
                        check.json()
                        detail = "The default source revision was readable through Contents."
                    else:
                        detail = (
                            "Contents read is granted; this repository currently has no "
                            "default branch to validate."
                        )
                else:
                    check = self._app.installation_request(
                        "GET",
                        f"/repos/{repository['full_name']}/actions/workflows",
                        token=token,
                        params={"per_page": 1},
                    )
                    check.raise_for_status()
                    check.json()
                    detail = "The read-only Actions workflow entrypoint succeeded."
                results.append(_result(plan, "passed", detail))
            except Exception as error:
                if (
                    plan["plane"] == "github_repository_contents"
                    and _github_http_status(error) == 409
                ):
                    results.append(
                        _result(
                            plan,
                            "not_applicable",
                            "Contents read is granted; GitHub reports that this repository "
                            "does not currently have a readable source revision.",
                        )
                    )
                    continue
                results.append(
                    _result(
                        plan,
                        "failed",
                        f"Validation call failed ({_github_error_code(error)}).",
                    )
                )
        return results


class GitHubBindingError(RuntimeError):
    pass


class GitHubPermissionError(RuntimeError):
    pass


def valid_github_login(value: str) -> bool:
    return bool(_GITHUB_LOGIN.fullmatch(value))


def _repository_boundary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RuntimeError("GitHub returned an invalid repository")
    repository_id = value.get("id")
    node_id = str(value.get("node_id", ""))
    full_name = str(value.get("full_name", ""))
    name = str(value.get("name", ""))
    owner = value.get("owner")
    if (
        not isinstance(repository_id, int)
        or repository_id <= 0
        or not node_id
        or len(node_id) > 200
        or not _GITHUB_REPOSITORY.fullmatch(full_name)
        or not name
        or len(name) > 100
        or not isinstance(owner, dict)
    ):
        raise RuntimeError("GitHub returned an invalid repository")
    owner_id = owner.get("id")
    owner_login = str(owner.get("login", ""))
    full_owner, full_repository = full_name.split("/", 1)
    if (
        not isinstance(owner_id, int)
        or owner_id <= 0
        or not valid_github_login(owner_login)
        or full_owner.lower() != owner_login.lower()
        or full_repository.lower() != name.lower()
    ):
        raise RuntimeError("GitHub returned an invalid repository owner")
    return {
        "id": repository_id,
        "node_id": node_id,
        "name": name,
        "full_name": full_name,
        "owner_id": owner_id,
        "owner_login": owner_login,
        "private": bool(value.get("private")),
        "archived": bool(value.get("archived")),
        "default_branch": str(value.get("default_branch") or "")[:255] or None,
    }


def _result(plan: dict[str, Any], state: str, detail: str) -> dict[str, Any]:
    return {
        "scope": plan["scope"],
        "plane": plan["plane"],
        "label": plan["label"],
        "region": "github.com",
        "repository_id": plan["repository_id"],
        "repository_full_name": plan["repository_full_name"],
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
            _result(item, "unknown", "Not attempted because installation binding failed.")
            for item in connection["coverage_plan"]
        ],
        "summary": f"Unable to validate the GitHub App installation ({code}).",
    }


def _github_error_code(error: Exception) -> str:
    if isinstance(error, (GitHubBindingError, GitHubPermissionError)):
        return str(error)
    response = getattr(error, "response", None)
    if response is not None and getattr(response, "status_code", None):
        return f"HTTP{response.status_code}"
    return error.__class__.__name__


def _github_http_status(error: Exception) -> int | None:
    response = getattr(error, "response", None)
    status = getattr(response, "status_code", None)
    return status if isinstance(status, int) else None


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _default_request(method: str, url: str, **kwargs: Any) -> GitHubHttpResponse:
    try:
        import httpx
    except ImportError as error:  # pragma: no cover - installation contract
        raise RuntimeError("httpx is required for GitHub App onboarding") from error
    return httpx.request(method, url, **kwargs)
