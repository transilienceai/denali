"""Authentication boundary for GitHub Actions evidence submissions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_ACTIONS_JWKS_URL = f"{GITHUB_ACTIONS_ISSUER}/.well-known/jwks"

_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


class GitHubOidcAuthenticationError(ValueError):
    """Raised when a GitHub Actions identity token cannot be trusted."""


@dataclass(frozen=True)
class GitHubActionsIdentity:
    repository: str
    repository_id: int
    repository_owner_id: int
    run_id: int
    run_attempt: int
    ref: str
    workflow_ref: str
    workflow_sha: str
    event_name: str


class GitHubActionsTokenVerifier(Protocol):
    def verify(self, token: str, *, audience: str) -> GitHubActionsIdentity: ...


class GitHubOidcVerifier:
    """Verify GitHub's signed OIDC token and return only stable workflow identifiers."""

    def __init__(self, *, jwks_url: str = GITHUB_ACTIONS_JWKS_URL):
        try:
            import jwt
        except ImportError as error:  # pragma: no cover - production dependency guard
            raise RuntimeError("GitHub OIDC verification support is unavailable") from error
        self._jwt = jwt
        self._jwks_client = jwt.PyJWKClient(jwks_url)

    def verify(self, token: str, *, audience: str) -> GitHubActionsIdentity:
        if not token or len(token) > 16384:
            raise GitHubOidcAuthenticationError("GitHub Actions identity token is invalid")
        try:
            signing_key = self._jwks_client.get_signing_key_from_jwt(token)
            claims = self._jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=audience,
                issuer=GITHUB_ACTIONS_ISSUER,
                options={
                    "require": [
                        "iss",
                        "aud",
                        "sub",
                        "exp",
                        "iat",
                        "nbf",
                        "jti",
                        "repository",
                        "repository_id",
                        "repository_owner_id",
                        "run_id",
                        "run_attempt",
                        "ref",
                        "workflow_ref",
                        "workflow_sha",
                        "event_name",
                    ]
                },
            )
        except Exception as error:
            raise GitHubOidcAuthenticationError(
                "GitHub Actions identity token could not be verified"
            ) from error

        repository = _bounded_string(claims, "repository", maximum=201)
        workflow_sha = _bounded_string(claims, "workflow_sha", maximum=64)
        if not _REPOSITORY_RE.fullmatch(repository) or not _SHA_RE.fullmatch(workflow_sha):
            raise GitHubOidcAuthenticationError("GitHub Actions identity claims are invalid")
        return GitHubActionsIdentity(
            repository=repository,
            repository_id=_positive_integer(claims, "repository_id"),
            repository_owner_id=_positive_integer(claims, "repository_owner_id"),
            run_id=_positive_integer(claims, "run_id"),
            run_attempt=_positive_integer(claims, "run_attempt"),
            ref=_bounded_string(claims, "ref", maximum=512),
            workflow_ref=_bounded_string(claims, "workflow_ref", maximum=1024),
            workflow_sha=workflow_sha.lower(),
            event_name=_bounded_string(claims, "event_name", maximum=100),
        )


def _positive_integer(claims: dict[str, Any], name: str) -> int:
    try:
        value = int(claims[name])
    except (KeyError, TypeError, ValueError) as error:
        raise GitHubOidcAuthenticationError("GitHub Actions identity claims are invalid") from error
    if value <= 0:
        raise GitHubOidcAuthenticationError("GitHub Actions identity claims are invalid")
    return value


def _bounded_string(claims: dict[str, Any], name: str, *, maximum: int) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise GitHubOidcAuthenticationError("GitHub Actions identity claims are invalid")
    return value
