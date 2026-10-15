"""Catalog, authorization-aware status and durable GitHub navigation contracts."""

from copy import deepcopy
from datetime import UTC, datetime, timedelta
from importlib import import_module
from uuid import uuid4

import pytest
from test_shared_github import CONNECTION_ID, REPOSITORY, Platform, Repository, _client

from denali.api.connection_catalog import connection_presentation, platform_statuses
from denali.api.connection_workflows import state_digest
from denali.connections import AWS_SCOPES

ADMIN = {"Authorization": "Bearer alpha-admin"}
MEMBER = {"Authorization": "Bearer alpha-member"}
BETA = {"Authorization": "Bearer beta-admin"}


@pytest.fixture(autouse=True)
def enabled(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_GITHUB_ENABLED", "true")


def test_catalog_uses_current_org_rollout_not_frontend_provider_switch():
    platform = Platform()
    with _client(platform, Repository()) as web:
        assert web.get("/v1/connections/catalog").status_code == 401
        admitted = web.get("/v1/connections/catalog", headers=MEMBER)
        other = web.get("/v1/connections/catalog", headers=BETA)
    catalog = admitted.json()
    github = next(item for item in catalog["items"] if item["provider"] == "github")
    assert github["onboarding_path"] == "shared"
    assert github["shared_enabled"]
    assert not catalog["platform_only"]
    assert "hosted_acceptance_required" in catalog["platform_only_blockers"]
    github_other = next(item for item in other.json()["items"] if item["provider"] == "github")
    assert not github_other["shared_enabled"]
    assert github_other["reason_code"] == "organization_not_admitted"
    assert not platform.calls  # Flags/admission do not claim broker/provider acceptance.
    assert admitted.headers["cache-control"] == "no-store"


def test_platform_availability_is_distinct_from_saved_health_and_safe_for_members():
    row = {
        "provider": "github",
        "lifecycle_state": "active",
        "health_state": "healthy",
        "credential_reference": {
            "type": "platform_shared_github",
            "platform_connection_id": CONNECTION_ID,
        },
    }
    platform = Platform()
    platform.ready = False
    statuses = platform_statuses([row], client=platform, org="org_alpha")
    projected = connection_presentation(row, can_write=True, platform=statuses[CONNECTION_ID])
    assert projected["health_state"] == "healthy"
    assert projected["platform_availability"] == "disabled"
    assert projected["platform_status_freshness"] == "current"
    assert not projected["actions"]["collect"]
    assert projected["actions"]["disconnect"]
    assert not any(connection_presentation(row, can_write=False)["actions"].values())
    native = {**row, "credential_reference": {"type": "github_app_installation"}}
    assert platform_statuses([native], client=platform, org="org_alpha") == {}
    assert connection_presentation(native, can_write=True)["actions"]["collect"]


def test_platform_outage_does_not_hide_or_rebind_connections():
    class Unavailable(Platform):
        def request(self, *_args, **_kwargs):
            raise RuntimeError("sensitive provider detail")

    row = {
        "credential_reference": {
            "type": "platform_shared_github",
            "platform_connection_id": CONNECTION_ID,
        }
    }
    statuses = platform_statuses([row], client=Unavailable(), org="org_alpha")
    assert statuses[CONNECTION_ID]["freshness"] == "unavailable"
    assert statuses[CONNECTION_ID]["reason_code"] == "platform_unavailable"
    assert "sensitive" not in str(statuses)


def test_github_return_receipt_survives_api_replacement_and_enforces_tenant():
    repository, platform = Repository(), Platform()
    request_id = str(uuid4())
    with _client(platform, repository) as web:
        denied = web.post(
            "/v1/shared/connections/github/setup", json={"request_id": request_id}, headers=MEMBER
        )
        assert denied.status_code == 403
        first = web.post(
            "/v1/shared/connections/github/setup", json={"request_id": request_id}, headers=ADMIN
        )
        workflow_id = first.json()["workflow_id"]
        return_state = platform.calls[-1][3]["return_state"]
        assert web.get(f"/v1/connections/onboarding/{workflow_id}", headers=BETA).status_code == 404
        assert web.get("/v1/connections/onboarding", headers=BETA).json() == {"items": []}
    # A new API container reads the same durable receipt; callback never trusts active org.
    with _client(platform, repository) as web:
        callback = web.get(
            "/v1/connections/onboarding/callback",
            params={"state": return_state, "status": "succeeded"},
            follow_redirects=False,
        )
        assert callback.status_code == 303
        assert callback.headers["location"] == f"/connections?onboarding={workflow_id}"
        assert return_state not in callback.headers["location"]
        assert callback.headers["referrer-policy"] == "no-referrer"
        assert (
            web.get(
                "/v1/connections/onboarding/callback",
                params={"state": return_state, "status": "succeeded"},
            ).status_code
            == 400
        )
        resumed = web.get(f"/v1/connections/onboarding/{workflow_id}", headers=ADMIN)
        assert resumed.json()["stage"] == "select_repositories"
        assert resumed.json()["status"] == "returned"
        assert "return_state" not in resumed.text
        assert "tenant_id" not in resumed.text
        assert web.get(f"/v1/connections/onboarding/{workflow_id}", headers=BETA).status_code == 404
    assert not repository.created  # Navigation receipt never authorizes a connection.
    assert return_state not in str(repository.workflows)


def test_relaunch_rotates_one_time_hash_and_expiry_failure_is_generic():
    repository, platform = Repository(), Platform()
    request_id = str(uuid4())
    with _client(platform, repository) as web:
        first = web.post(
            "/v1/shared/connections/github/setup", json={"request_id": request_id}, headers=ADMIN
        )
        old_state = platform.calls[-1][3]["return_state"]
        second = web.post(
            "/v1/shared/connections/github/setup", json={"request_id": request_id}, headers=ADMIN
        )
        state = platform.calls[-1][3]["return_state"]
        assert first.json()["workflow_id"] == second.json()["workflow_id"]
        assert len(repository.workflows) == 1
        assert (
            web.get(
                "/v1/connections/onboarding/callback",
                params={"state": old_state, "status": "succeeded"},
            ).status_code
            == 400
        )
        next(iter(repository.workflows.values()))["expires_at"] = datetime.now(UTC) - timedelta(
            seconds=1
        )
        assert (
            web.get(
                "/v1/connections/onboarding/callback",
                params={"state": state, "status": "succeeded"},
            ).status_code
            == 400
        )
        for params in (
            {"state": "https://secret.example", "status": "succeeded"},
            {"state": state, "status": "connected"},
            {"state": state, "status": "failed", "tenant_id": "other"},
        ):
            error = web.get("/v1/connections/onboarding/callback", params=params)
            assert error.status_code == 400
            assert "secret.example" not in error.text
        assert (
            state_digest(state) == next(iter(repository.workflows.values()))["return_state_sha256"]
        )


def test_github_repeated_subset_ignores_mutable_flags_but_never_rebinds(monkeypatch):
    monkeypatch.setattr(
        import_module("denali.api.app"), "_with_validation_state", lambda _r, _t, row: row
    )
    repository, platform = Repository(), Platform()
    path = f"/v1/shared/connections/github/{CONNECTION_ID}/use-in-denali"
    with _client(platform, repository) as web:
        first = web.post(path, headers=ADMIN, json={"repository_ids": [REPOSITORY["id"]]})
        saved = deepcopy(repository.created)
        platform.repository.update(private=False, archived=True, default_branch="new-default")
        repeated = web.post(path, headers=ADMIN, json={"repository_ids": [REPOSITORY["id"]]})
        assert repeated.status_code == 201
        assert repeated.json()["id"] == first.json()["id"]
        assert repository.created == saved
        platform.repository["full_name"] = "transilienceai/renamed"
        platform.repository["name"] = "renamed"
        assert (
            web.post(path, headers=ADMIN, json={"repository_ids": [REPOSITORY["id"]]}).status_code
            == 409
        )


@pytest.mark.parametrize(
    "mode,regions", [("selected", ["us-east-1", "us-west-2"]), ("automatic", [])]
)
def test_shared_aws_attachment_pins_multiregion_all_scopes_without_rebinding(
    monkeypatch, mode, regions
):
    monkeypatch.setattr(
        import_module("denali.api.app"), "_with_validation_state", lambda _r, _t, row: row
    )

    class AwsPlatform(Platform):
        def request(self, method, path, *, clerk_org_id, payload=None, **_kwargs):
            self.calls.append((method, path, clerk_org_id, payload))
            if path == "/v1/connections":
                return {
                    "items": [
                        {
                            "id": CONNECTION_ID,
                            "connection_kind": "shared_aws",
                            "availability": "ready",
                            "validated_scopes": list(AWS_SCOPES),
                            "partition": "aws",
                            "external_account_id": "123456789012",
                        }
                    ]
                    if clerk_org_id == "org_alpha"
                    else []
                }
            if path.endswith("/credentials"):
                assert payload["region"] in (regions or ["us-east-1"])
                assert payload["scopes"] == [AWS_SCOPES[0]]  # Never combine six STS policies.
                return {
                    "access_key_id": "test-only",
                    "secret_access_key": "test-only",
                    "session_token": "test-only",
                }
            raise AssertionError(path)

    repository, platform = Repository(), AwsPlatform()
    body = {
        "coverage_mode": mode,
        "regions": regions,
        "deployment_region": "us-east-1",
        "declared_scopes": list(AWS_SCOPES),
    }
    path = f"/v1/shared/connections/aws/{CONNECTION_ID}/use-in-denali"
    with _client(platform, repository) as web:
        assert web.post(path, json=body, headers=MEMBER).status_code == 403
        assert web.post(path, json=body, headers=BETA).status_code == 404
        created = web.post(path, json=body, headers=ADMIN)
        assert created.status_code == 201
        assert web.post(path, json=body, headers=ADMIN).status_code == 201
        assert len(repository.created) == 1
        config = repository.created[0]["configuration"]
        assert config["coverage_mode"] == mode and config["regions"] == regions
        assert config["deployment_region"] == "us-east-1"
        assert "secret_access_key" not in created.text
        changed = {**body, "declared_scopes": [AWS_SCOPES[0]]}
        assert web.post(path, json=changed, headers=ADMIN).status_code == 409
        repository.created[0]["lifecycle_state"] = "disabled"
        assert web.post(path, json=body, headers=ADMIN).status_code == 409
