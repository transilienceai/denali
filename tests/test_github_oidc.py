from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from denali.api.github_oidc import (
    GITHUB_ACTIONS_ISSUER,
    GitHubOidcAuthenticationError,
    GitHubOidcVerifier,
)

AUDIENCE = "https://denali.example/api/v1/ci/github/connection-id"


def _claims(**overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    claims: dict[str, object] = {
        "iss": GITHUB_ACTIONS_ISSUER,
        "aud": AUDIENCE,
        "sub": "repo:example/anna:ref:refs/heads/main",
        "exp": now + timedelta(minutes=5),
        "iat": now - timedelta(seconds=1),
        "nbf": now - timedelta(seconds=1),
        "jti": "one-time-token-id",
        "repository": "example/anna",
        "repository_id": "12345",
        "repository_owner_id": "456",
        "run_id": "789",
        "run_attempt": "2",
        "ref": "refs/heads/main",
        "workflow_ref": "example/anna/.github/workflows/deploy.yml@refs/heads/main",
        "workflow_sha": "a" * 40,
        "event_name": "push",
    }
    claims.update(overrides)
    return claims


def _verifier_and_token(**overrides: object) -> tuple[GitHubOidcVerifier, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode(_claims(**overrides), private_key, algorithm="RS256", headers={"kid": "k1"})
    verifier = GitHubOidcVerifier()
    verifier._jwks_client = SimpleNamespace(  # type: ignore[attr-defined]
        get_signing_key_from_jwt=lambda _token: SimpleNamespace(key=private_key.public_key())
    )
    return verifier, token


def test_verifies_github_actions_identity_and_returns_stable_identifiers() -> None:
    verifier, token = _verifier_and_token()

    identity = verifier.verify(token, audience=AUDIENCE)

    assert identity.repository == "example/anna"
    assert identity.repository_id == 12345
    assert identity.repository_owner_id == 456
    assert identity.run_id == 789
    assert identity.run_attempt == 2
    assert identity.workflow_sha == "a" * 40


@pytest.mark.parametrize(
    ("overrides", "audience"),
    [
        ({"iss": "https://issuer.example"}, AUDIENCE),
        ({"aud": "https://other.example"}, AUDIENCE),
        ({"exp": datetime.now(UTC) - timedelta(minutes=1)}, AUDIENCE),
        ({"repository_id": "not-an-id"}, AUDIENCE),
        ({"repository": "not-a-repository"}, AUDIENCE),
    ],
)
def test_rejects_untrusted_or_malformed_claims(overrides: dict[str, object], audience: str) -> None:
    verifier, token = _verifier_and_token(**overrides)

    with pytest.raises(GitHubOidcAuthenticationError):
        verifier.verify(token, audience=audience)
