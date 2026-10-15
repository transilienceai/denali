"""Browser controls never accept credentials, tenant selectors or wider selections."""

from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
from importlib import import_module
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from uuid import uuid4

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from test_shared_connections_api import FakeAuthenticator
from test_shared_github import Repository as GitHubRepository

from denali.api.app import create_app
from denali.api.connection_workflows import state_digest
from denali.connections.azure_repos import AZURE_REPOS_SCOPE_METADATA, AZURE_REPOS_SCOPES
from denali.integrations.shared_azure_repos import ROOT
from denali.integrations.shared_connections_client import SharedConnectionsError

BASE = "/v1/shared/connections/azure-repos"
PLATFORM_ID = "11111111-1111-4111-8111-111111111111"
TARGET_ID = "22222222-2222-4222-8222-222222222222"
PROVIDER_TENANT = "33333333-3333-4333-8333-333333333333"
APPLICATION_ID = "44444444-4444-4444-8444-444444444444"
REPOSITORY_ID = "55555555-5555-4555-8555-555555555555"
PROJECT_ID = "66666666-6666-4666-8666-666666666666"
AUTH = {"Authorization": "Bearer alpha-admin"}
MEMBER = {"Authorization": "Bearer alpha-member"}
BETA = {"Authorization": "Bearer beta-admin"}
REPOSITORY = {
    "id": REPOSITORY_ID,
    "project_id": PROJECT_ID,
    "name": "agent",
    "project_name": "AI",
    "full_name": "AI/agent",
    "default_branch": "refs/heads/main",
}
SOURCE = {
    "id": PLATFORM_ID,
    "provider": "azure_repos",
    "connection_kind": "shared_azure_repos",
    "target_id": TARGET_ID,
    "tenant_id": PROVIDER_TENANT,
    "organization": "example",
    "application_client_id": APPLICATION_ID,
    "display_name": "Example source",
    "lifecycle_state": "active",
    "setup_state": "ready",
    "health_state": "healthy",
    "declared_scopes": list(AZURE_REPOS_SCOPES),
    "validated_scopes": list(AZURE_REPOS_SCOPES),
    "repository_count": 1,
    "last_validated_at": "2026-10-15T00:00:00Z",
    "availability": "ready",
    "authority_revision": 1,
    "job_id": None,
    "job_state": None,
    "error_code": None,
    "retry_available": True,
}


class Repository(GitHubRepository):
    def begin_connection_onboarding(
        self,
        tenant_id,
        *,
        request_id,
        return_state_sha256,
        connection_id=None,
        provider="github",
        platform_connection_id=None,
    ):
        key = (tenant_id, provider, request_id)
        previous = self.workflows.get(key)
        if previous and (
            previous["connection_id"] != connection_id
            or previous["platform_connection_id"] != platform_connection_id
        ):
            raise ValueError("different binding")
        now = datetime.now(UTC)
        row = {
            "id": previous["id"] if previous else str(uuid4()),
            "tenant_id": tenant_id,
            "request_id": request_id,
            "connection_id": connection_id,
            "platform_connection_id": platform_connection_id,
            "provider": provider,
            "management_source": "platform",
            "return_state_sha256": return_state_sha256,
            "consumed_at": None,
            "stage": "external_authorization",
            "status": "in_progress",
            "expires_at": now + timedelta(minutes=30),
            "created_at": now,
            "updated_at": now,
            "error_code": None,
        }
        self.workflows[key] = row
        return row


class Platform:
    origin = "https://connectors.example.test"

    def __init__(self):
        self.calls = []
        self.source = copy.deepcopy(SOURCE)
        self.repositories = [copy.deepcopy(REPOSITORY)]
        self.live_repositories = None
        self.launch_patch = None
        self.validation = {"job_id": str(uuid4()), "state": "queued"}
        self.fail_read = False

    def allows_org(self, org):
        return org == "org_alpha"

    def authorize(self):
        callback = self.origin + ROOT + "/setup/callback"
        query = {
            "client_id": APPLICATION_ID,
            "response_type": "code",
            "redirect_uri": callback,
            "response_mode": "query",
            "scope": "https://app.vssps.visualstudio.com/.default",
            "state": "s" * 64,
            "code_challenge": "c" * 43,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
        value = {
            "authorize_url": f"https://login.microsoftonline.com/{PROVIDER_TENANT}"
            "/oauth2/v2.0/authorize?" + urlencode(query),
            "callback_url": callback,
            "application_client_id": APPLICATION_ID,
        }
        return self.launch_patch(value) if self.launch_patch else value

    def request(self, method, path, *, clerk_org_id, payload=None, **kwargs):
        assert clerk_org_id == "org_alpha"
        self.calls.append((method, path, clerk_org_id, copy.deepcopy(payload)))
        if path == ROOT + "/config":
            return {"items": [{**self.source, "client_secret": "never-browser-secret"}]}
        if path == ROOT:
            return {"items": [{**self.source, "access_token": "never-browser-token"}]}
        if path == ROOT + "/setup":
            return {"id": PLATFORM_ID, "client_secret": "never-browser-secret"}
        if path.endswith("/status"):
            return {**self.source, "access_token": "never-browser-token"}
        if path.endswith("/repositories"):
            return {"items": self.repositories}
        if path.endswith("/setup"):
            return self.authorize()
        if path.endswith("/validate"):
            return self.validation
        if path.endswith("/read"):
            if self.fail_read:
                raise RuntimeError("never-browser-provider-error")
            return {
                "items": self.live_repositories
                or [row for row in self.repositories if row["id"] in payload["repository_ids"]]
            }
        if path.endswith("/disable"):
            self.source.update(lifecycle_state="disabled", availability="disabled")
            return {"status": "disabled"}
        if method == "DELETE":
            if payload != {"confirmation_name": self.source["display_name"]}:
                raise SharedConnectionsError(409)
            self.source.update(lifecycle_state="deleted", availability="disabled")
            return {"status": "deleted"}
        raise AssertionError((method, path))


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_AZURE_REPOS_ENABLED", "true")
    # Isolate browser orchestration from unrelated row-presentation queries.
    monkeypatch.setattr(
        import_module("denali.api.app"), "_with_validation_state", lambda _r, _t, row: row
    )


def client(platform, repository):
    return TestClient(
        create_app(
            repository=repository,
            auth_mode="clerk",
            authenticator=FakeAuthenticator(),
            shared_connections_client=platform,
            migrate_on_start=False,
        )
    )


def use_payload(ids=None, scopes=None):
    return {
        "repository_ids": ids or [REPOSITORY_ID],
        "declared_scopes": scopes or list(AZURE_REPOS_SCOPES),
    }


def launch_payload():
    return {"request_id": str(uuid4())}


@pytest.mark.parametrize(
    "suffix,method,payload",
    [
        ("/setup", "post", {"request_id": str(uuid4()), "target_id": TARGET_ID}),
        (f"/{PLATFORM_ID}/setup", "post", launch_payload()),
        (f"/{PLATFORM_ID}/validate", "post", None),
        (f"/{PLATFORM_ID}/use-in-denali", "post", use_payload()),
        (f"/{PLATFORM_ID}/disable", "post", None),
        (f"/{PLATFORM_ID}", "delete", {"confirmation_name": "Example source"}),
    ],
)
def test_mutations_require_admin_active_org_and_pilot(suffix, method, payload):
    platform, repo = Platform(), Repository()
    with client(platform, repo) as web:
        request = web.request
        assert request(method, BASE + suffix, json=payload).status_code == 401
        assert request(method, BASE + suffix, json=payload, headers=MEMBER).status_code == 403
        assert request(method, BASE + suffix, json=payload, headers=BETA).status_code == 404
    assert not platform.calls and not repo.created and not repo.workflows


@pytest.mark.parametrize(
    "suffix", ["", "/config", f"/{PLATFORM_ID}/status", f"/{PLATFORM_ID}/repositories"]
)
def test_member_reads_are_org_bound_bounded_and_project_credentials(suffix):
    platform, repo = Platform(), Repository()
    platform.repositories[0].update(
        access_token="never-browser-token", remote_url="https://not-a-link.test"
    )
    with client(platform, repo) as web:
        assert web.get(BASE + suffix).status_code == 401
        assert web.get(BASE + suffix, headers=BETA).status_code == 404
        response = web.get(BASE + suffix, headers=MEMBER)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert "never-browser" not in response.text and "remote_url" not in response.text
    assert all(call[2] == "org_alpha" for call in platform.calls)


def test_disabled_feature_never_calls_platform(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_AZURE_REPOS_ENABLED", "false")
    platform, repo = Platform(), Repository()
    with client(platform, repo) as web:
        assert web.get(BASE, headers=AUTH).status_code == 404
        assert (
            web.post(
                BASE + "/setup",
                headers=AUTH,
                json={"request_id": str(uuid4()), "target_id": TARGET_ID},
            ).status_code
            == 404
        )
    assert not platform.calls


@pytest.mark.parametrize(
    "path,payload",
    [
        (
            "/setup",
            {"request_id": str(uuid4()), "target_id": TARGET_ID, "clerk_org_id": "org_beta"},
        ),
        (
            "/setup",
            {
                "request_id": str(uuid4()),
                "target_id": TARGET_ID,
                "client_secret": "never-browser-secret",
            },
        ),
        (f"/{PLATFORM_ID}/setup", {"return_state": "never-browser-secret"}),
        (f"/{PLATFORM_ID}/use-in-denali", use_payload([REPOSITORY_ID, REPOSITORY_ID])),
        (f"/{PLATFORM_ID}/use-in-denali", use_payload(scopes=["azure_repos.repository_contents"])),
        (
            f"/{PLATFORM_ID}/use-in-denali",
            use_payload(scopes=[AZURE_REPOS_SCOPE_METADATA, "never-browser-secret"]),
        ),
        ("/never-browser-secret/status", None),
    ],
)
def test_rejected_browser_values_are_not_reflected(path, payload):
    platform, repo = Platform(), Repository()
    with client(platform, repo) as web:
        response = (
            web.get(BASE + path, headers=AUTH)
            if payload is None
            else web.post(BASE + path, headers=AUTH, json=payload)
        )
    assert response.status_code == 422
    assert response.json() == {"detail": "invalid shared connection request"}
    assert "never-browser-secret" not in response.text
    assert not platform.calls


def test_create_and_validate_receipts_project_only_durable_identifiers():
    platform, repo = Platform(), Repository()
    with client(platform, repo) as web:
        created = web.post(
            BASE + "/setup", headers=AUTH, json={"request_id": str(uuid4()), "target_id": TARGET_ID}
        )
        validated = web.post(BASE + f"/{PLATFORM_ID}/validate", headers=AUTH)
    assert created.status_code == 201 and created.json() == {"id": PLATFORM_ID}
    assert validated.status_code == 202 and validated.json() == platform.validation
    assert validated.headers["cache-control"] == "no-store"
    assert all("clerk_org_id" not in (call[3] or {}) for call in platform.calls)


@pytest.mark.parametrize(
    "patch",
    [
        {"connection_kind": "native"},
        {"setup_state": "invented"},
        {"availability": "invented"},
        {"repository_count": True},
        {"repository_count": 501},
        {"authority_revision": 0},
        {"authority_revision": True},
        {"display_name": "bad\nname"},
        {"last_validated_at": "2026-10-15T00:00:00"},
        {"job_id": "bad"},
        {"job_state": "invented"},
        {"retry_available": "true"},
        {"error_code": "never-browser-provider-error"},
        {"declared_scopes": ["azure_repos.repository_contents"]},
        {"declared_scopes": [AZURE_REPOS_SCOPE_METADATA]},
        {"id": TARGET_ID},
    ],
)
def test_malformed_upstream_status_fails_closed(patch):
    platform, repo = Platform(), Repository()
    platform.source.update(patch)
    with client(platform, repo) as web:
        response = web.get(BASE + f"/{PLATFORM_ID}/status", headers=MEMBER)
    assert response.status_code == 502
    assert "never-browser" not in response.text


def rewrite_query(value, **changes):
    parts = urlsplit(value["authorize_url"])
    query = parse_qs(parts.query)
    query.update({key: [replacement] for key, replacement in changes.items()})
    value["authorize_url"] = urlunsplit(parts._replace(query=urlencode(query, doseq=True)))
    return value


@pytest.mark.parametrize(
    "patch",
    [
        lambda value: {
            **value,
            "authorize_url": value["authorize_url"].replace(
                "login.microsoftonline.com", "attacker.test"
            ),
        },
        lambda value: {**value, "authorize_url": value["authorize_url"] + "#fragment"},
        lambda value: rewrite_query(value, redirect_uri="https://attacker.test/callback"),
        lambda value: rewrite_query(value, client_id=TARGET_ID),
        lambda value: rewrite_query(value, scope="offline_access"),
        lambda value: rewrite_query(value, code_challenge_method="plain"),
        lambda value: rewrite_query(value, code_challenge="!" * 43),
        lambda value: rewrite_query(value, state="s" * 129),
        lambda value: rewrite_query(value, state="/" * 64),
        lambda value: rewrite_query(value, response_mode="fragment"),
        lambda value: rewrite_query(value, prompt="none"),
        lambda value: rewrite_query(value, client_secret="never-browser-secret"),
        lambda value: {**value, "authorize_url": value["authorize_url"] + "&state=duplicate"},
        lambda value: {**value, "callback_url": "https://attacker.test/callback"},
        lambda value: {**value, "application_client_id": TARGET_ID},
    ],
)
def test_launch_rejects_untrusted_redirect_and_pkce_metadata(patch):
    platform, repo = Platform(), Repository()
    platform.launch_patch = patch
    with client(platform, repo) as web:
        response = web.post(BASE + f"/{PLATFORM_ID}/setup", headers=AUTH, json=launch_payload())
    assert response.status_code == 502
    assert response.json() == {"detail": "shared Azure Repos authorization unavailable"}
    assert next(iter(repo.workflows.values()))["status"] == "failed"


def test_launch_persists_hashed_original_org_context_and_replays_fail():
    platform, repo = Platform(), Repository()
    with client(platform, repo) as web:
        response = web.post(BASE + f"/{PLATFORM_ID}/setup", headers=AUTH, json=launch_payload())
        assert response.status_code == 201
        workflow = next(iter(repo.workflows.values()))
        state = platform.calls[-1][3]["return_state"]
        assert workflow["return_state_sha256"] == state_digest(state)
        assert (
            workflow["provider"] == "azure_repos"
            and workflow["platform_connection_id"] == PLATFORM_ID
        )
        path = "/v1/connections/onboarding/" + response.json()["workflow_id"]
        assert web.get(path, headers=BETA).status_code == 404
        returned = web.get(
            "/v1/connections/onboarding/callback",
            params={"state": state, "status": "succeeded"},
            follow_redirects=False,
        )
        assert returned.status_code == 303
        assert state not in returned.headers["location"]
        assert web.get(path, headers=MEMBER).json()["status"] == "returned"
        assert web.get(path, headers=BETA).status_code == 404
        replay = web.get(
            "/v1/connections/onboarding/callback",
            params={"state": state, "status": "succeeded"},
            follow_redirects=False,
        )
        assert replay.status_code == 400
        assert state not in replay.text


def test_attach_is_exact_subset_idempotent_and_never_auto_enables_or_widens():
    platform, repo = Platform(), Repository()
    second = {**REPOSITORY, "id": str(uuid4()), "name": "another", "full_name": "AI/another"}
    platform.repositories.append(second)
    with client(platform, repo) as web:
        path = BASE + f"/{PLATFORM_ID}/use-in-denali"
        created = web.post(path, headers=AUTH, json=use_payload())
        repeated = web.post(path, headers=AUTH, json=use_payload())
        assert created.status_code == repeated.status_code == 201
        assert created.json()["id"] == repeated.json()["id"]
        assert len(repo.created) == 1
        assert [row["id"] for row in repo.created[0]["configuration"]["repositories"]] == [
            REPOSITORY_ID
        ]
        # Default branch is collection state, not a new authorization boundary.
        platform.repositories[0]["default_branch"] = "refs/heads/release"
        assert web.post(path, headers=AUTH, json=use_payload()).status_code == 201
        widened = web.post(path, headers=AUTH, json=use_payload([REPOSITORY_ID, second["id"]]))
        assert widened.status_code == 201 and widened.json()["id"] != created.json()["id"]
        assert len(repo.created) == 2
        repo.created[0]["lifecycle_state"] = "disabled"
        assert web.post(path, headers=AUTH, json=use_payload()).status_code == 409
        assert repo.created[0]["lifecycle_state"] == "disabled"
    reads = [call[3] for call in platform.calls if call[1].endswith("/read")]
    assert reads == [
        {"operation": "repositories", "repository_ids": [REPOSITORY_ID]},
        {"operation": "repositories", "repository_ids": sorted([REPOSITORY_ID, second["id"]])},
    ]


@pytest.mark.parametrize(
    "change",
    [
        {"name": "renamed", "full_name": "AI/renamed"},
        {"project_id": str(uuid4())},
        {"project_name": "Transferred", "full_name": "Transferred/agent"},
    ],
)
def test_existing_attachment_rejects_repository_rename_or_transfer(change):
    platform, repo = Platform(), Repository()
    with client(platform, repo) as web:
        path = BASE + f"/{PLATFORM_ID}/use-in-denali"
        assert web.post(path, headers=AUTH, json=use_payload()).status_code == 201
        platform.repositories[0].update(change)
        assert web.post(path, headers=AUTH, json=use_payload()).status_code == 409
    assert len(repo.created) == 1


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("not-ready", 409),
        ("disabled", 409),
        ("setup-pending", 409),
        ("scope", 403),
        ("missing-repo", 409),
        ("live-drift", 502),
        ("outage", 502),
    ],
)
def test_attachment_requires_fresh_ready_scope_and_live_exact_identity(mode, expected):
    platform, repo = Platform(), Repository()
    if mode == "not-ready":
        platform.source["availability"] = "needs_validation"
    elif mode == "disabled":
        platform.source["lifecycle_state"] = "disabled"
    elif mode == "setup-pending":
        platform.source["setup_state"] = "pending"
    elif mode == "scope":
        platform.source["validated_scopes"] = [AZURE_REPOS_SCOPE_METADATA]
    elif mode == "missing-repo":
        platform.repositories = [{**REPOSITORY, "id": str(uuid4())}]
    elif mode == "live-drift":
        platform.live_repositories = [{**REPOSITORY, "project_id": str(uuid4())}]
    else:
        platform.fail_read = True
    with client(platform, repo) as web:
        response = web.post(
            BASE + f"/{PLATFORM_ID}/use-in-denali", headers=AUTH, json=use_payload()
        )
    assert response.status_code == expected
    assert not repo.created and "never-browser" not in response.text


def test_resume_source_requires_same_tenant_and_same_platform_binding():
    platform, repo = Platform(), Repository()
    with client(platform, repo) as web:
        created = web.post(
            BASE + f"/{PLATFORM_ID}/use-in-denali", headers=AUTH, json=use_payload()
        ).json()
        launch = {**launch_payload(), "connection_id": created["id"]}
        assert (
            web.post(BASE + f"/{PLATFORM_ID}/setup", headers=AUTH, json=launch).status_code == 201
        )
        repo.created[0]["tenant_id"] = repo.resolve_tenant("org_beta")
        before = len(repo.workflows)
        assert (
            web.post(
                BASE + f"/{PLATFORM_ID}/setup",
                headers=AUTH,
                json={**launch, "request_id": str(uuid4())},
            ).status_code
            == 404
        )
        assert len(repo.workflows) == before
        repo.created[0]["tenant_id"] = repo.resolve_tenant("org_alpha")
        repo.created[0]["credential_reference"]["platform_connection_id"] = TARGET_ID
        assert (
            web.post(BASE + f"/{PLATFORM_ID}/setup", headers=AUTH, json=launch).status_code == 404
        )


def test_global_disable_and_delete_do_not_mutate_denali_attachment_lifecycle():
    platform, repo = Platform(), Repository()
    with client(platform, repo) as web:
        path = BASE + f"/{PLATFORM_ID}"
        assert (
            web.post(path + "/use-in-denali", headers=AUTH, json=use_payload()).status_code == 201
        )
        local = copy.deepcopy(repo.created)
        assert web.post(path + "/disable", headers=AUTH).json() == {"status": "disabled"}
        assert repo.created == local
        assert (
            web.post(path + "/use-in-denali", headers=AUTH, json=use_payload()).status_code == 409
        )
        assert (
            web.request(
                "DELETE", path, headers=AUTH, json={"confirmation_name": "wrong"}
            ).status_code
            == 409
        )
        assert web.request(
            "DELETE", path, headers=AUTH, json={"confirmation_name": "Example source"}
        ).json() == {"status": "deleted"}
        assert repo.created == local


@pytest.mark.parametrize(
    "outcome", ["succeeded", "provider-error", "duplicate-code", "duplicate-state", "missing-code"]
)
def test_real_platform_oauth_route_and_denali_return_contract_without_provider_network(outcome):
    api = pytest.importorskip("transilience_platform.azure_repos_api")
    connector = pytest.importorskip("transilience_platform.azure_repos_connector")
    platform, repo = Platform(), Repository()

    class Registry:
        binding = None
        failure_recorded = False

        def azure_repos_status(self, app, org, identifier):
            assert app == "denali" and org == "org_alpha" and str(identifier) == PLATFORM_ID
            return copy.deepcopy(SOURCE)

        def create_azure_repos_setup_state(
            self, app, org, identifier, state, verifier, *, return_state
        ):
            self.state = state
            self.binding = {
                "operator_client_id": APPLICATION_ID,
                "tenant_id": PROVIDER_TENANT,
                "organization": "example",
                "pkce_verifier": verifier,
                "return_origin": "https://denali.example.test",
                "return_state": return_state,
            }
            return self.binding

        def consume_azure_repos_setup_state(self, state):
            if state != self.state:
                return None
            self.state = None
            return self.binding

        def complete_azure_repos_setup(self, binding, repositories):
            assert binding is self.binding and repositories == [REPOSITORY]
            return True

        def fail_azure_repos_setup(self, binding):
            assert binding is self.binding
            self.failure_recorded = True

        def azure_repos_return_context(self, binding):
            return binding

    class Broker(connector.AzureReposBroker):
        def exchange_code(self, tenant, code, verifier):
            assert outcome == "succeeded", "invalid callback must not contact the provider"
            assert tenant == PROVIDER_TENANT and code == "fixture-one-time-code"
            assert verifier == registry.binding["pkce_verifier"]
            return "fixture-transient-provider-handle"

        def repositories(self, organization, token):
            assert organization == "example" and token == "fixture-transient-provider-handle"
            return [REPOSITORY]

    registry = Registry()
    broker = Broker(
        connector.AzureReposConfig(
            APPLICATION_ID, platform.origin + ROOT + "/setup/callback", "fixture-operator-secret"
        )
    )
    upstream = FastAPI()

    def entitled(authorization, org):
        if authorization != "Bearer fixture-machine" or org != "org_alpha":
            raise HTTPException(403, "not entitled")
        return "denali"

    api.register_azure_repos_routes(upstream, registry, entitled, broker)
    with TestClient(upstream) as wire:

        def request(method, path, *, clerk_org_id, payload=None, **kwargs):
            headers = {"Authorization": "Bearer fixture-machine"}
            response = wire.request(
                method,
                path,
                headers=headers,
                params={"clerk_org_id": clerk_org_id} if method == "GET" else None,
                json={**payload, "clerk_org_id": clerk_org_id} if payload is not None else None,
            )
            if response.status_code >= 400:
                raise SharedConnectionsError(response.status_code)
            return response.json()

        platform.request = request
        with client(platform, repo) as web:
            launched = web.post(BASE + f"/{PLATFORM_ID}/setup", headers=AUTH, json=launch_payload())
            assert launched.status_code == 201
            authorize = parse_qs(urlsplit(launched.json()["authorize_url"]).query)
            callback_query = [("state", authorize["state"][0])]
            if outcome != "missing-code":
                callback_query.append(("code", "fixture-one-time-code"))
            if outcome == "provider-error":
                callback_query.append(("error", "fixture-sensitive-provider-error"))
            elif outcome == "duplicate-code":
                callback_query.append(("code", "fixture-second-sensitive-code"))
            elif outcome == "duplicate-state":
                callback_query.append(("state", "fixture-second-sensitive-state"))
            returned = wire.get(
                ROOT + "/setup/callback",
                params=callback_query,
                follow_redirects=False,
            )
            if outcome == "duplicate-state":
                # An unknown last state resolves no tenant and cannot consume the valid one.
                assert returned.status_code == 400
                assert "location" not in returned.headers
                assert registry.state == authorize["state"][0]
                assert next(iter(repo.workflows.values()))["status"] == "in_progress"
                return
            assert returned.status_code == 303
            assert "fixture-one-time-code" not in returned.headers["location"]
            assert "fixture-sensitive" not in str(returned.headers)
            assert "fixture-transient-provider-handle" not in str(repo.workflows)
            callback = urlsplit(returned.headers["location"])
            assert callback.netloc == "denali.example.test"
            assert callback.path == "/api/v1/connections/onboarding/callback"
            resumed = web.get(
                callback.path.removeprefix("/api"),
                params=parse_qs(callback.query),
                follow_redirects=False,
            )
            assert resumed.status_code == 303
            receipt = web.get(
                "/v1/connections/onboarding/" + launched.json()["workflow_id"], headers=MEMBER
            )
            assert receipt.json()["status"] == ("returned" if outcome == "succeeded" else "failed")
            assert registry.failure_recorded == (outcome != "succeeded")
            assert receipt.json()["platform_connection_id"] == PLATFORM_ID
            assert (
                web.get(
                    "/v1/connections/onboarding/" + launched.json()["workflow_id"], headers=BETA
                ).status_code
                == 404
            )
