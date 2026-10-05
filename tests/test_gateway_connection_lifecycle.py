from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from test_gateway_capabilities import Memberships, SessionAuthenticator, Verifier

from denali.api.app import create_app
from denali.api.connection_capabilities import setup_summary
from denali.api.gateway_auth import GatewayPrincipal

PATH = "/internal/v1/capabilities/connections/actions"
GUARD = {"expected_org_id": "org_Alpha1", "confirmed": True}
HEADERS = {"Authorization": "Bearer admin-write", "Idempotency-Key": "lifecycle_test_1"}
PRIVATE = "never-return-or-persist-this-value"


class LifecycleVerifier(Verifier):
    def verify(self, token, *, purpose):
        if token == "admin-destructive" and purpose == "denali:connections:destructive":
            return GatewayPrincipal("mch_Gateway1", "org_Alpha1", "user_Admin1", purpose)
        return super().verify(token, purpose=purpose)


class Repository:
    def __init__(self):
        self.rows = {}
        self.actions = {}
        self.created = 0
        self.launches = 0
        self.validation_state = "idle"
        self.collection_state = "idle"

    def lookup_tenant(self, org):
        return {"org_Alpha1": "tenant-alpha", "org_Beta2": "tenant-beta"}.get(org)

    def claim_gateway_connection_action(self, tenant, **fields):
        key = (tenant, fields["idempotency_key"])
        previous = self.actions.get(key)
        if previous:
            if any(
                previous[field] != fields[field]
                for field in ("request_hash", "actor", "action_kind")
            ):
                raise ValueError("idempotency key was already used for another action")
            return False, previous
        self.actions[key] = {**fields, "state": "claimed", "status_code": None}
        return True, self.actions[key]

    def finish_gateway_connection_action(self, tenant, **fields):
        row = self.actions[(tenant, fields["idempotency_key"])]
        assert row["request_hash"] == fields["request_hash"]
        row.update(
            state="completed" if fields["status_code"] < 400 else "failed",
            status_code=fields["status_code"],
            connection_id=fields["connection_id"],
        )

    def create_connection(self, tenant, **values):
        self.created += 1
        row = {
            **values,
            "id": values["connection_id"],
            "lifecycle_state": "active",
            "health_state": "unknown",
            "last_validation": {"private_marker": PRIVATE},
        }
        row["configuration"]["private_marker"] = PRIVATE
        row["credential_reference"]["private_marker"] = PRIVATE
        self.rows[(tenant, row["id"])] = row
        return row

    def get_connection(self, tenant, connection_id):
        return self.rows.get((tenant, connection_id))

    get_connection_validation_target = get_connection

    def connection_validation_job_state(self, tenant, connection_id):
        return self.validation_state

    def connection_collection_status(self, tenant, connection_id, **kwargs):
        return {"state": self.collection_state, "last_result": None}

    def record_github_install_launch(self, tenant, connection_id, **fields):
        self.launches += 1
        return self.get_connection(tenant, connection_id)

    def disable_connection(self, tenant, connection_id):
        row = self.get_connection(tenant, connection_id)
        row["lifecycle_state"] = "disabled"
        return row

    def delete_connection(self, tenant, connection_id):
        row = self.get_connection(tenant, connection_id)
        if row["lifecycle_state"] == "active":
            return "active"
        del self.rows[(tenant, connection_id)]
        return "deleted"


class SharedClient:
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.calls = []
        self.connection_id = str(uuid4())

    def allows_org(self, org):
        return self.allowed

    def request(self, method, path, *, clerk_org_id, payload=None, expect_text=False):
        assert clerk_org_id == "org_Alpha1"
        self.calls.append((method, path, payload))
        if path == "/v1/connections":
            return {
                "items": [
                    {
                        "id": self.connection_id,
                        "connection_kind": "shared_aws",
                        "provider": "aws",
                        "external_account_id": "123456789012",
                        "partition": "aws",
                        "availability": "ready",
                        "validated_scopes": ["aws.bedrock_agents"],
                        "private_marker": PRIVATE,
                    }
                ]
            }
        if path.endswith("/credentials"):
            return {
                "access_key_id": PRIVATE,
                "secret_access_key": PRIVATE,
                "session_token": PRIVATE,
            }
        if path.endswith("/validation"):
            return {"job_state": "succeeded", "validation_summary": PRIVATE}
        if expect_text:
            return "AWSTemplateFormatVersion: '2010-09-09'"
        if path.endswith("/validate"):
            return {"job_id": str(uuid4()), "state": "queued", "private_marker": PRIVATE}
        return {"id": self.connection_id, "status": "disabled", "private_marker": PRIVATE}


def app(repo, **kwargs):
    now = datetime.now(UTC)
    github = SimpleNamespace(
        app_id="1",
        app_slug="denali",
        create_install_launch=lambda **_: {
            "created_at": now,
            "expires_at": now + timedelta(hours=1),
            "state_sha256": "a" * 64,
            "install_url": "https://github.com/apps/denali/installations/new?state=transient-state",
        },
    )
    return create_app(
        repository=repo,
        auth_mode="clerk",
        authenticator=SessionAuthenticator(),
        results_gateway_verifier=LifecycleVerifier(),
        gateway_membership_checker=Memberships(),
        azure_setup_launcher=SimpleNamespace(client_id="azure-public-client"),
        entra_consent_client=SimpleNamespace(client_id="entra-public-client"),
        gcp_setup_launcher=SimpleNamespace(),
        gcp_principal_provisioner=SimpleNamespace(
            operator_project_id="operator-project",
            create_principal=lambda **_: {
                "principal_email": "connection@example.iam.gserviceaccount.com"
            },
        ),
        google_workspace_operator=SimpleNamespace(
            service_account="operator@example.iam.gserviceaccount.com", oauth_client_id="123456789"
        ),
        github_app_client=github,
        azure_repos_client=SimpleNamespace(client_id="repos-public-client"),
        migrate_on_start=False,
        **kwargs,
    )


@pytest.mark.parametrize(
    "provider,fields",
    [
        ("aws", {"account_id": "123456789012"}),
        ("azure", {"tenant_id": str(uuid4())}),
        ("entra", {"tenant_id": str(uuid4())}),
        ("gcp", {}),
        ("github", {}),
        ("azure_repos", {"tenant_id": str(uuid4()), "organization": "test-organization"}),
        ("google_workspace", {"admin_email": "admin@example.com"}),
    ],
)
def test_native_create_preserves_every_provider_and_reserves_before_mutation(provider, fields):
    repo = Repository()
    payload = {
        **GUARD,
        "action": "create",
        "connection": {"provider": provider, "display_name": "Test provider", **fields},
    }
    with TestClient(app(repo)) as client:
        result = client.post(PATH, headers=HEADERS, json=payload)
        replay = client.post(PATH, headers=HEADERS, json=payload)
        changed = client.post(
            PATH,
            headers=HEADERS,
            json={
                **payload,
                "connection": {**payload["connection"], "display_name": "Another name"},
            },
        )
    assert result.status_code == 201, result.text
    assert result.json()["connection"]["provider"] == provider
    assert replay.status_code == 200 and replay.json()["replayed"] is True
    assert result.json()["connection_id"] == replay.json()["connection_id"]
    assert changed.status_code == 409 and repo.created == 1
    assert PRIVATE not in result.text and PRIVATE not in str(repo.actions)
    assert "credential_reference" not in result.json()["connection"]


@pytest.mark.parametrize(
    "token,body,status",
    [
        ("admin-read", GUARD, 401),
        ("member-write", GUARD, 403),
        ("admin-write", {**GUARD, "expected_org_id": "org_Beta2"}, 409),
        ("admin-write", {**GUARD, "confirmed": False}, 422),
        ("admin-write", {**GUARD, "tenant_id": str(uuid4())}, 422),
    ],
)
def test_lifecycle_denies_wrong_purpose_role_org_and_extra_fields(token, body, status):
    repo = Repository()
    with TestClient(app(repo)) as client:
        result = client.post(
            PATH,
            headers={**HEADERS, "Authorization": f"Bearer {token}"},
            json={
                **body,
                "action": "create",
                "connection": {
                    "provider": "aws",
                    "display_name": "Test",
                    "account_id": "123456789012",
                },
            },
        )
    assert result.status_code == status and not repo.actions and not repo.created


def test_one_time_launch_is_returned_once_and_never_saved_in_action_audit():
    repo = Repository()
    with TestClient(app(repo)) as client:
        created = client.post(
            PATH,
            headers=HEADERS,
            json={
                **GUARD,
                "action": "create",
                "connection": {"provider": "github", "display_name": "Github"},
            },
        ).json()
        payload = {
            **GUARD,
            "action": "setup-launch",
            "provider": "github",
            "connection_id": created["connection_id"],
        }
        headers = {**HEADERS, "Idempotency-Key": "launch_once_1"}
        first = client.post(PATH, headers=headers, json=payload)
        replay = client.post(PATH, headers=headers, json=payload)
        wrong_provider = client.post(
            PATH,
            headers={**HEADERS, "Idempotency-Key": "wrong_provider_1"},
            json={**payload, "provider": "azure"},
        )
        cross_tenant = client.post(
            PATH,
            headers={
                **HEADERS,
                "Authorization": "Bearer other-write",
                "Idempotency-Key": "other_launch_1",
            },
            json={**payload, "expected_org_id": "org_Beta2"},
        )
    assert first.status_code == 201 and "transient-state" in first.text
    assert replay.status_code == 200 and "setup" not in replay.json()
    assert "transient-state" not in str(repo.actions) and repo.launches == 1
    assert wrong_provider.status_code == 404 and cross_tenant.status_code == 404


def test_completion_validation_never_echoes_one_time_material():
    with TestClient(app(Repository())) as client:
        result = client.post(
            PATH,
            headers=HEADERS,
            json={
                **GUARD,
                "action": "setup-complete",
                "provider": "google_workspace",
                "connection_id": str(uuid4()),
                "completion_code": PRIVATE,
            },
        )
    assert result.status_code == 422 and PRIVATE not in result.text


def test_destructive_scope_exact_name_disable_before_delete_and_busy_jobs():
    repo = Repository()
    with TestClient(app(repo)) as client:
        created = client.post(
            PATH,
            headers=HEADERS,
            json={
                **GUARD,
                "action": "create",
                "connection": {
                    "provider": "aws",
                    "display_name": "AWS test",
                    "account_id": "123456789012",
                },
            },
        ).json()
        payload = {
            **GUARD,
            "action": "disable",
            "connection_id": created["connection_id"],
            "confirmation_name": "AWS test",
        }
        assert client.post(PATH, headers=HEADERS, json=payload).status_code == 401

        def destructive(key, action):
            return client.post(
                PATH,
                headers={
                    **HEADERS,
                    "Authorization": "Bearer admin-destructive",
                    "Idempotency-Key": key,
                },
                json=action,
            )

        assert destructive("delete_active_1", {**payload, "action": "delete"}).status_code == 409
        assert (
            destructive("disable_wrong_1", {**payload, "confirmation_name": "wrong"}).status_code
            == 409
        )
        repo.validation_state = "running"
        assert destructive("disable_busy_1", payload).status_code == 409
        repo.validation_state = "idle"
        repo.collection_state = "running"
        assert destructive("disable_collecting_1", payload).status_code == 409
        repo.collection_state = "idle"
        assert destructive("disable_success_1", payload).status_code == 200
        deleted = destructive("delete_success_1", {**payload, "action": "delete"})
        assert deleted.status_code == 200
        assert destructive("delete_success_1", {**payload, "action": "delete"}).json()["replayed"]
    assert not repo.rows


def test_templates_and_native_setup_status_are_bounded_no_store(monkeypatch):
    monkeypatch.setenv("DENALI_AWS_PRINCIPAL_ARN", "arn:aws:iam::111122223333:role/Operator")
    repo, shared = Repository(), SharedClient()
    with TestClient(app(repo, shared_connections_client=shared)) as client:
        created = client.post(
            PATH,
            headers=HEADERS,
            json={
                **GUARD,
                "action": "create",
                "connection": {
                    "provider": "aws",
                    "display_name": "AWS test",
                    "account_id": "123456789012",
                },
            },
        ).json()
        for operation, identifier in (
            ("connection-aws-template", created["connection_id"]),
            ("connection-setup-status", created["connection_id"]),
            ("shared-aws-template", shared.connection_id),
        ):
            result = client.get(
                f"/internal/v1/capabilities/{operation}?id={identifier}",
                headers={"Authorization": "Bearer admin-read"},
            )
            assert result.status_code == 200, result.text
            assert result.headers["cache-control"] == "no-store" and PRIVATE not in result.text
        too_large = client.post(PATH, headers=HEADERS, content='{"padding":"' + "x" * 66000 + '"}')
        assert too_large.status_code == 413


def test_pending_reservation_never_reexecutes():
    repo = Repository()
    payload = {
        **GUARD,
        "action": "create",
        "connection": {"provider": "aws", "display_name": "Test", "account_id": "123456789012"},
    }
    with TestClient(app(repo)) as client:
        assert client.post(PATH, headers=HEADERS, json=payload).status_code == 201
        repo.actions[("tenant-alpha", HEADERS["Idempotency-Key"])]["state"] = "claimed"
        assert client.post(PATH, headers=HEADERS, json=payload).status_code == 409
    assert repo.created == 1


def test_setup_status_projection_removes_opaque_configuration_and_nested_provider_values():
    row = {
        "id": str(uuid4()),
        "provider": "azure_repos",
        "credential_reference": {"pkce_verifier": PRIVATE},
        "configuration": {
            "private_marker": PRIVATE,
            "repository_candidates": [
                {"id": str(uuid4()), "name": "test", "private_marker": PRIVATE}
            ],
            "onboarding": {"oauth_state_sha256": PRIVATE, "selection_expires_at": "safe-expiry"},
        },
    }
    result = setup_summary(row)
    assert PRIVATE not in str(result)
    assert result["setup"]["onboarding"]["selection_expires_at"] == "safe-expiry"
    gcp = setup_summary(
        {
            "id": str(uuid4()),
            "provider": "gcp",
            "configuration": {
                "projects": [{"id": "selected-project", "number": "123456789", "name": "Selected"}]
            },
        }
    )
    assert gcp["setup"]["projects"] == [
        {"id": "selected-project", "number": "123456789", "name": "Selected"}
    ]


def test_shared_reads_and_attach_preserve_existing_allowlist_and_never_return_leases():
    repo = Repository()
    shared = SharedClient()
    with TestClient(app(repo, shared_connections_client=shared)) as client:
        listing = client.get(
            "/internal/v1/capabilities/shared-connections?limit=1",
            headers={"Authorization": "Bearer admin-read"},
        )
        status = client.get(
            f"/internal/v1/capabilities/shared-aws-status?id={shared.connection_id}",
            headers={"Authorization": "Bearer admin-read"},
        )
        attached = client.post(
            PATH,
            headers=HEADERS,
            json={
                **GUARD,
                "action": "shared-attach",
                "connection_id": shared.connection_id,
                "region": "us-east-1",
                "declared_scopes": ["aws.bedrock_agents"],
            },
        )
    assert listing.status_code == status.status_code == 200
    assert attached.status_code == 201, attached.text
    assert all(PRIVATE not in response.text for response in (listing, status, attached))
    assert PRIVATE not in str(repo.actions)
    assert any(path.endswith("/credentials") for _, path, _ in shared.calls)
    denied = SharedClient(allowed=False)
    with TestClient(app(Repository(), shared_connections_client=denied)) as client:
        result = client.get(
            "/internal/v1/capabilities/shared-connections",
            headers={"Authorization": "Bearer admin-read"},
        )
    assert result.status_code == 404 and not denied.calls
