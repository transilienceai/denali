from __future__ import annotations

from types import SimpleNamespace

import clerk_backend_api
import pytest
from fastapi.testclient import TestClient

from denali.api.app import create_app
from denali.api.auth import AuthContext, AuthenticationError
from denali.api.capabilities import CAPABILITY_CONTRACT_VERSION, READ_CAPABILITIES
from denali.api.gateway_auth import ClerkGatewayVerifier, ClerkMembershipChecker, GatewayPrincipal


def test_product_owned_read_contract_is_versioned_and_allowlisted():
    assert CAPABILITY_CONTRACT_VERSION == 1
    assert {
        "connections",
        "connection-detail",
        "context",
        "runtime-session-export",
    } <= READ_CAPABILITIES.keys()
    assert all(spec.path.startswith("/v1/") for spec in READ_CAPABILITIES.values())


ASSET = "11111111-1111-4111-8111-111111111111"


class SessionAuthenticator:
    def authenticate(self, request):
        if request.headers.get("authorization") == "Bearer browser":
            return AuthContext("user_Browser1", "org_Alpha1", "admin")
        raise AuthenticationError("invalid session")


class Verifier:
    def verify(self, token, *, purpose):
        identities = {
            "admin-read": ("org_Alpha1", "user_Admin1", "results:read"),
            "admin-write": ("org_Alpha1", "user_Admin1", "denali:write"),
            "reviewer-write": ("org_Alpha1", "user_Reviewer1", "denali:write"),
            "member-write": ("org_Alpha1", "user_Member1", "denali:write"),
            "removed-read": ("org_Alpha1", "user_Removed1", "results:read"),
            "other-read": ("org_Beta2", "user_Admin2", "results:read"),
            "other-write": ("org_Beta2", "user_Admin2", "denali:write"),
            "unmapped-read": ("org_Unknown3", "user_Admin3", "results:read"),
        }
        identity = identities.get(token)
        if identity is None or identity[2] != purpose:
            return None
        return GatewayPrincipal("mch_Gateway1", *identity)


class Memberships:
    def role(self, organization_id, user_id):
        return {
            ("org_Alpha1", "user_Admin1"): "admin",
            ("org_Alpha1", "user_Reviewer1"): "admin",
            ("org_Alpha1", "user_Member1"): "member",
            ("org_Beta2", "user_Admin2"): "admin",
            ("org_Unknown3", "user_Admin3"): "admin",
        }.get((organization_id, user_id))


class Repository:
    def __init__(self):
        self.calls = []
        self.actions = {}
        self.proposals = {}
        self.response_actions = {}

    def lookup_tenant(self, org):
        return {"org_Alpha1": "tenant-alpha", "org_Beta2": "tenant-beta"}.get(org)

    def resolve_tenant(self, org):
        raise AssertionError("machine traffic must not create tenant")

    def list_connection_summaries(self, tenant, *, limit, offset):
        self.calls.append(
            ("list_connection_summaries", tenant, (), {"limit": limit, "offset": offset})
        )
        return (
            [{"id": ASSET, "provider": "aws", "health_state": "healthy", "tenant": tenant}],
            False,
        )

    def get_connection_summary(self, tenant, connection_id):
        self.calls.append(("get_connection_summary", tenant, (connection_id,), {}))
        if tenant == "tenant-beta":
            return None
        return {"id": connection_id, "provider": "aws", "health_state": "healthy", "tenant": tenant}

    def __getattr__(self, name):
        if name == "count_assets":

            def count(tenant, *args, **kwargs):
                self.calls.append((name, tenant, args, kwargs))
                return 1

            return count
        if name.startswith(("list_", "latest_", "code_to_cloud_")):

            def rows(tenant, *args, **kwargs):
                self.calls.append((name, tenant, args, kwargs))
                return [{"tenant": tenant}]

            return rows
        if name.startswith(
            (
                "get_",
                "summary",
                "activity_summary",
                "finding_summary",
                "issue_summary",
                "runtime_detection_summary",
                "vulnerability_summary",
                "vulnerability_import_status",
            )
        ):

            def item(tenant, *args, **kwargs):
                self.calls.append((name, tenant, args, kwargs))
                return {"tenant": tenant}

            return item
        raise AttributeError(name)

    def set_governance_idempotent(
        self, tenant, asset, *, status, owner, notes, actor, idempotency_key
    ):
        key = (tenant, idempotency_key)
        payload = (asset, status, owner, notes, actor)
        self.calls.append(("set_governance_idempotent", tenant, payload, {}))
        if key in self.actions:
            if self.actions[key] != payload:
                raise ValueError("idempotency key was already used for another action")
        elif asset != ASSET:
            return None
        else:
            self.actions[key] = payload
        return {"id": asset, "governance_status": status, "tenant": tenant}

    def create_runtime_response_request_idempotent(
        self,
        tenant,
        detection,
        *,
        action_type,
        target_asset_id,
        justification,
        requested_by,
        idempotency_key,
    ):
        key = (tenant, idempotency_key)
        payload = (detection, action_type, target_asset_id, justification, requested_by)
        if key in self.response_actions:
            if self.response_actions[key][0] != payload:
                raise ValueError("idempotency key was already used for another action")
            return self.response_actions[key][1]
        if tenant != "tenant-alpha" or detection != ASSET:
            return None
        result = {
            "id": "22222222-2222-4222-8222-222222222222",
            "tenant": tenant,
            "state": "awaiting_approval",
            "requested_by": requested_by,
        }
        self.proposals[result["id"]] = result
        self.response_actions[key] = (payload, result)
        return result

    def review_runtime_response_request_idempotent(
        self,
        tenant,
        detection,
        response,
        *,
        decision,
        review_note,
        reviewed_by,
        idempotency_key,
    ):
        key = (tenant, idempotency_key)
        payload = (detection, response, decision, review_note, reviewed_by)
        if key in self.response_actions:
            if self.response_actions[key][0] != payload:
                raise ValueError("idempotency key was already used for another action")
            return self.response_actions[key][1]
        proposal = self.proposals.get(response)
        if (
            tenant != "tenant-alpha"
            or proposal is None
            or proposal["requested_by"] == reviewed_by
            or proposal["state"] != "awaiting_approval"
        ):
            return None
        result = {**proposal, "state": decision, "reviewed_by": reviewed_by}
        self.proposals[response] = result
        self.response_actions[key] = (payload, result)
        return result


def app(repository):
    return create_app(
        repository=repository,
        auth_mode="clerk",
        authenticator=SessionAuthenticator(),
        results_gateway_verifier=Verifier(),
        gateway_membership_checker=Memberships(),
        migrate_on_start=False,
    )


def test_read_catalog_is_explicit_org_scoped_and_never_creates_tenant():
    repo = Repository()
    with TestClient(app(repo)) as client:
        alpha = client.get(
            "/internal/v1/capabilities/inventory-summary",
            headers={"Authorization": "Bearer admin-read"},
        )
        beta = client.get(
            "/internal/v1/capabilities/finding-detail",
            params={"id": ASSET},
            headers={"Authorization": "Bearer other-read"},
        )
        assert alpha.status_code == beta.status_code == 200
        assert alpha.json()["tenant"] == "tenant-alpha"
        assert beta.json()["tenant"] == "tenant-beta"
        assert alpha.headers["cache-control"] == "no-store"
        assert (
            client.get(
                "/internal/v1/capabilities/nonexistent-read",
                headers={"Authorization": "Bearer admin-read"},
            ).status_code
            == 404
        )
        assert (
            client.get(
                "/internal/v1/capabilities/assets",
                params={"limit": 101},
                headers={"Authorization": "Bearer admin-read"},
            ).status_code
            == 422
        )
        assert (
            client.get(
                "/internal/v1/capabilities/asset-detail",
                params={"id": "bad"},
                headers={"Authorization": "Bearer admin-read"},
            ).status_code
            == 422
        )
    assert len(READ_CAPABILITIES) >= 30
    assert all(call[1] in {"tenant-alpha", "tenant-beta"} for call in repo.calls)


@pytest.mark.parametrize("operation", sorted(READ_CAPABILITIES))
def test_every_named_read_resolves_to_an_existing_tenant_scoped_handler(operation):
    repo = Repository()
    identifier = "a" * 64 if READ_CAPABILITIES[operation].identifier == "session_key" else ASSET
    params = {"id": identifier} if READ_CAPABILITIES[operation].identifier else {}
    with TestClient(app(repo)) as client:
        response = client.get(
            f"/internal/v1/capabilities/{operation}",
            params=params,
            headers={"Authorization": "Bearer admin-read"},
        )
    assert response.status_code == 200, (operation, response.text)
    assert response.headers["cache-control"] == "no-store"
    if operation == "context":
        assert response.json()["tenant_id"] == "tenant-alpha"
        assert response.json()["organization_id"] == "org_Alpha1"
    else:
        assert repo.calls and all(call[1] == "tenant-alpha" for call in repo.calls)


@pytest.mark.parametrize(
    ("operation", "method"),
    [
        ("code-to-cloud-deployments", "code_to_cloud_deployments"),
        ("code-to-cloud-observations", "code_to_cloud_observations"),
    ],
)
def test_code_to_cloud_gateway_reads_are_bounded_and_pageable(operation, method):
    repo = Repository()
    url = f"/internal/v1/capabilities/{operation}"
    headers = {"Authorization": "Bearer admin-read"}
    with TestClient(app(repo)) as client:
        default = client.get(url, headers=headers)
        page = client.get(url, params={"limit": "25", "offset": "50"}, headers=headers)
        excessive = client.get(url, params={"limit": "101"}, headers=headers)
        invalid_offset = client.get(url, params={"offset": "-1"}, headers=headers)
        duplicate = client.get(url, params=[("limit", "1"), ("limit", "2")], headers=headers)
    assert default.status_code == page.status_code == 200
    assert repo.calls == [
        (method, "tenant-alpha", (), {"limit": 100, "offset": 0}),
        (method, "tenant-alpha", (), {"limit": 25, "offset": 50}),
    ]
    assert excessive.status_code == invalid_offset.status_code == duplicate.status_code == 422


def test_connection_capability_reads_are_bounded_tenant_scoped_and_non_mutating():
    repo = Repository()
    headers = {"Authorization": "Bearer admin-read"}
    url = "/internal/v1/capabilities/connections"
    detail_url = "/internal/v1/capabilities/connection-detail"
    with TestClient(app(repo)) as client:
        first = client.get(url, headers=headers)
        page = client.get(url, params={"limit": 25, "offset": 50}, headers=headers)
        detail = client.get(detail_url, params={"id": ASSET}, headers=headers)
        other = client.get(
            detail_url, params={"id": ASSET}, headers={"Authorization": "Bearer other-read"}
        )
        invalid = client.get(url, params={"limit": 101}, headers=headers)
        duplicate = client.get(url, params=[("limit", 1), ("limit", 2)], headers=headers)
        unsupported = client.get(url, params={"configuration": "all"}, headers=headers)
        missing = client.get(detail_url, headers=headers)
    assert first.status_code == page.status_code == detail.status_code == 200
    assert first.json()["limit"] == 20
    assert first.json()["offset"] == 0
    assert first.json()["has_more"] is False
    assert page.json()["limit"] == 25
    assert page.json()["offset"] == 50
    assert detail.json()["tenant"] == "tenant-alpha"
    assert other.status_code == 404
    assert all(
        response.status_code == 422 for response in (invalid, duplicate, unsupported, missing)
    )
    assert repo.calls == [
        ("list_connection_summaries", "tenant-alpha", (), {"limit": 20, "offset": 0}),
        ("list_connection_summaries", "tenant-alpha", (), {"limit": 25, "offset": 50}),
        ("get_connection_summary", "tenant-alpha", (ASSET,), {}),
        ("get_connection_summary", "tenant-beta", (ASSET,), {}),
    ]


def test_gateway_write_requires_distinct_purpose_current_admin_and_idempotency():
    repo = Repository()
    url = f"/internal/v1/capabilities/assets/{ASSET}/governance"
    body = {"status": "approved", "owner": "security"}
    key = "action-abc123"
    with TestClient(app(repo)) as client:
        assert (
            client.patch(
                url,
                json=body,
                headers={"Authorization": "Bearer admin-read", "Idempotency-Key": key},
            ).status_code
            == 401
        )
        assert (
            client.patch(
                url,
                json=body,
                headers={"Authorization": "Bearer member-write", "Idempotency-Key": key},
            ).status_code
            == 403
        )
        assert (
            client.patch(
                url, json=body, headers={"Authorization": "Bearer admin-write"}
            ).status_code
            == 422
        )
        result = client.patch(
            url, json=body, headers={"Authorization": "Bearer admin-write", "Idempotency-Key": key}
        )
        assert result.status_code == 200
        assert result.json()["tenant"] == "tenant-alpha"
        assert result.headers["cache-control"] == "no-store"
        assert (
            client.patch(
                url,
                json=body,
                headers={"Authorization": "Bearer admin-write", "Idempotency-Key": key},
            ).status_code
            == 200
        )
        assert (
            client.patch(
                url,
                json={"status": "unwanted"},
                headers={"Authorization": "Bearer admin-write", "Idempotency-Key": key},
            ).status_code
            == 409
        )
        assert (
            client.patch(
                url.replace(ASSET, "bad"),
                json=body,
                headers={"Authorization": "Bearer admin-write", "Idempotency-Key": "another-key"},
            ).status_code
            == 422
        )
        assert (
            client.patch(
                url,
                json={"status": "invalid"},
                headers={"Authorization": "Bearer admin-write", "Idempotency-Key": "another-key"},
            ).status_code
            == 422
        )
        beta = client.patch(
            url, json=body, headers={"Authorization": "Bearer other-write", "Idempotency-Key": key}
        )
        assert beta.status_code == 200
        assert beta.json()["tenant"] == "tenant-beta"


def test_gateway_rejects_removed_member_unmapped_org_and_unconfigured_auth():
    repo = Repository()
    url = "/internal/v1/capabilities/inventory-summary"
    with TestClient(app(repo)) as client:
        for token, expected in (("removed-read", 403), ("unmapped-read", 404), ("browser", 401)):
            assert (
                client.get(url, headers={"Authorization": f"Bearer {token}"}).status_code
                == expected
            )
    no_gateway = create_app(
        repository=repo,
        auth_mode="clerk",
        authenticator=SessionAuthenticator(),
        migrate_on_start=False,
    )
    with TestClient(no_gateway) as client:
        assert client.get(url, headers={"Authorization": "Bearer admin-read"}).status_code == 404


def test_manual_runtime_response_requires_independent_admin_and_is_idempotent():
    repo = Repository()
    create_url = f"/internal/v1/capabilities/detections/{ASSET}/responses"
    proposal = {
        "action_type": "preserve_and_investigate",
        "justification": "Investigate exact evidence",
    }
    writer = {"Authorization": "Bearer admin-write", "Idempotency-Key": "proposal-123"}
    reviewer = {"Authorization": "Bearer reviewer-write", "Idempotency-Key": "review-123"}
    with TestClient(app(repo)) as client:
        assert (
            client.post(
                create_url, json=proposal, headers={**writer, "Authorization": "Bearer admin-read"}
            ).status_code
            == 401
        )
        assert (
            client.post(
                create_url,
                json=proposal,
                headers={**writer, "Authorization": "Bearer member-write"},
            ).status_code
            == 403
        )
        assert (
            client.post(create_url.replace(ASSET, "bad"), json=proposal, headers=writer).status_code
            == 422
        )
        created = client.post(create_url, json=proposal, headers=writer)
        assert created.status_code == 201
        assert client.post(create_url, json=proposal, headers=writer).json() == created.json()
        assert (
            client.post(
                create_url, json={**proposal, "justification": "Different"}, headers=writer
            ).status_code
            == 409
        )
        response_id = created.json()["id"]
        review_url = f"{create_url}/{response_id}"
        decision = {"decision": "approved"}
        assert client.patch(review_url, json=decision, headers=writer).status_code == 409
        reviewed = client.patch(review_url, json=decision, headers=reviewer)
        assert reviewed.status_code == 200
        assert reviewed.json()["state"] == "approved"
        assert client.patch(review_url, json=decision, headers=reviewer).json() == reviewed.json()
        assert (
            client.patch(review_url, json={"decision": "rejected"}, headers=reviewer).status_code
            == 409
        )
        assert (
            client.patch(
                review_url.replace(response_id, "bad"), json=decision, headers=reviewer
            ).status_code
            == 422
        )


def test_clerk_machine_verifier_and_live_membership_are_bounded(monkeypatch):
    token = SimpleNamespace(
        revoked=False,
        expired=False,
        subject="mch_Gateway1",
        scopes=["mch_Denali1"],
        created_at=1_000_000,
        expiration=1_300_000,
        claims={"purpose": "denali:write", "org_id": "org_Alpha1", "user_id": "user_Admin1"},
    )
    membership = SimpleNamespace(
        role="org:admin", public_user_data=SimpleNamespace(user_id="user_Admin1")
    )
    client = SimpleNamespace(
        m2m=SimpleNamespace(verify_token=lambda **_: token),
        organization_memberships=SimpleNamespace(
            list=lambda **_: SimpleNamespace(data=[membership])
        ),
    )
    monkeypatch.setattr(clerk_backend_api, "Clerk", lambda **_: client)
    verifier = ClerkGatewayVerifier("ak_test", "mch_Gateway1", "mch_Denali1")
    assert verifier.verify("token", purpose="denali:write") == GatewayPrincipal(
        "mch_Gateway1", "org_Alpha1", "user_Admin1", "denali:write"
    )
    assert verifier.verify("token", purpose="results:read") is None
    assert ClerkMembershipChecker("sk_test").role("org_Alpha1", "user_Admin1") == "admin"
    token.subject = "mch_Other1"
    assert verifier.verify("token", purpose="denali:write") is None
    token.subject = "mch_Gateway1"
    token.scopes = ["mch_Other1"]
    assert verifier.verify("token", purpose="denali:write") is None
    token.scopes = ["mch_Denali1"]
    token.claims = {"purpose": "denali:write", "org_id": "org_Alpha1", "user_id": "bad"}
    assert verifier.verify("token", purpose="denali:write") is None
    token.claims = {"purpose": "denali:write", "org_id": "org_Alpha1", "user_id": "user_Admin1"}
    token.revoked = True
    assert verifier.verify("token", purpose="denali:write") is None
    token.revoked = False
    token.expiration = token.created_at + 16 * 60 * 1000
    assert verifier.verify("token", purpose="denali:write") is None
