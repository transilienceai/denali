from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from denali.resource_writes.service import RemediationService
from denali.resource_writes.templates import AWS_ACTION, RemediationError


def service(*, role="admin", enabled=True):
    leases = SimpleNamespace(
        lease=lambda **kw: (_ for _ in ()).throw(AssertionError("no lease expected"))
    )
    return RemediationService(
        store=SimpleNamespace(),
        inventory=SimpleNamespace(),
        memberships=SimpleNamespace(role=lambda org, user: role),
        leases=leases,
        enabled=frozenset({AWS_ACTION}) if enabled else frozenset(),
    )


@pytest.mark.parametrize("role", [None, "member"])
def test_live_admin_revocation_is_enforced_before_provider_lease(role):
    product = service(role=role)
    with pytest.raises(RemediationError, match="live_organization_admin_required"):
        product.preview(
            tenant_id="tenant",
            organization_id="org_Alpha",
            actor="user_Admin",
            finding_id="finding",
            grant_id="grant",
            action=AWS_ACTION,
            parameters={},
        )


def test_default_off_and_membership_outage_fail_before_lease():
    product = service(enabled=False)
    with pytest.raises(RemediationError, match="resource_action_disabled"):
        product._build_plan({"action": AWS_ACTION})
    product = service()
    product.memberships = None
    with pytest.raises(RemediationError, match="membership_unavailable"):
        product._admin("org_Alpha", "user_Admin")


def test_self_review_rejected_before_preview_rebuild_or_lease():
    product = service()
    product.store.get = lambda *args: {
        "clerk_org_id": "org_Alpha",
        "action": AWS_ACTION,
        "actor_user_id": "user_Admin",
    }
    with pytest.raises(RemediationError, match="self_approval_forbidden"):
        product.review(
            tenant_id="tenant",
            organization_id="org_Alpha",
            actor="user_Admin",
            request_id="request",
            decision="approved",
            note="Review",
        )


@pytest.mark.parametrize("drift", [False, True])
def test_durable_attempt_marker_precedes_provider_and_drift_never_writes(drift):
    events = []
    row = {
        "tenant_id": "tenant",
        "lease_nonce": "nonce",
        "expires_at": datetime.now(UTC) + timedelta(minutes=10),
        "action": AWS_ACTION,
        "plan": {"approved": True},
        "clerk_org_id": "org_Alpha",
        "actor_user_id": "user_Admin",
        "reviewer_user_id": "user_Reviewer",
    }
    product = service()
    product.store = SimpleNamespace(
        claim=lambda request: row,
        mark_provider_attempted=lambda *args: events.append("persist-attempt"),
        finish=lambda *args, **kw: events.append(kw),
    )
    provider = SimpleNamespace(
        execute_once=lambda *args: events.append("provider-single-attempt") or {"verified": True}
    )
    product._build_plan = lambda *args, **kw: (
        {"approved": not drift},
        "diff",
        provider,
        "proposed",
    )
    product.execute("durable-id-only")
    if drift:
        assert events == [{"error": "preview_drift_requires_new_request"}]
    else:
        assert events == [
            "persist-attempt",
            "provider-single-attempt",
            {"result": {"verified": True}},
        ]


def test_duplicate_worker_has_no_provider_call():
    product = service()
    product.store.claim = lambda request: None
    product.execute("same-durable-id")


@pytest.mark.parametrize("removed", ["user_Admin", "user_Reviewer"])
def test_actor_or_reviewer_revoked_after_snapshot_never_starts_provider_write(removed):
    events = []
    row = {
        "tenant_id": "tenant",
        "lease_nonce": "nonce",
        "expires_at": datetime.now(UTC) + timedelta(minutes=10),
        "action": AWS_ACTION,
        "plan": {"approved": True},
        "clerk_org_id": "org_Alpha",
        "actor_user_id": "user_Admin",
        "reviewer_user_id": "user_Reviewer",
    }
    product = service()
    product.store = SimpleNamespace(
        claim=lambda rid: row,
        mark_provider_attempted=lambda *args: events.append("attempt"),
        finish=lambda *args, **kw: events.append(kw),
    )

    def snapshot(*args, **kwargs):
        product.memberships = SimpleNamespace(
            role=lambda org, user: None if user == removed else "admin"
        )
        return (
            row["plan"],
            "diff",
            SimpleNamespace(execute_once=lambda *args: events.append("provider")),
            {},
        )

    product._build_plan = snapshot
    product.execute("request")
    assert events == [{"error": "live_organization_admin_required"}]


def test_lease_failure_never_marks_attempt_or_retries():
    events = []
    row = {
        "tenant_id": "tenant",
        "lease_nonce": "nonce",
        "expires_at": datetime.now(UTC) + timedelta(minutes=10),
        "action": AWS_ACTION,
    }
    product = service()
    product.store = SimpleNamespace(
        claim=lambda rid: row,
        mark_provider_attempted=lambda *args: events.append("attempt"),
        finish=lambda *args, **kw: events.append(kw),
    )

    def fail(*args, **kw):
        raise RemediationError("resource_lease_unavailable")

    product._build_plan = fail
    product.execute("request")
    assert events == [{"error": "resource_lease_unavailable"}]
