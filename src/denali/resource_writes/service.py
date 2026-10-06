"""One product-owned remediation service behind browser/API/gateway surfaces."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from denali.resource_writes.providers import (
    AwsInlineRemediator,
    GitHubRemediator,
    PlatformWriteLeases,
)
from denali.resource_writes.store import RemediationStore
from denali.resource_writes.templates import (
    AWS_ACTION,
    GITHUB_ACTION,
    TEMPLATE_VERSION,
    RemediationError,
    git_blob_sha,
    github_patch,
    open_finding,
    sha256,
    tighten_inline_policy,
)


def enabled_actions():
    return frozenset(
        action
        for flag, action in (
            ("DENALI_ENABLE_GITHUB_RESOURCE_WRITES", GITHUB_ACTION),
            ("DENALI_ENABLE_AWS_RESOURCE_WRITES", AWS_ACTION),
        )
        if os.environ.get(flag, "false").lower() == "true"
    )


class RemediationService:
    def __init__(
        self,
        *,
        store,
        inventory,
        memberships,
        leases,
        enabled: frozenset[str] = frozenset(),
        github_factory=GitHubRemediator,
        aws_factory=AwsInlineRemediator,
    ):
        self.store, self.inventory, self.memberships, self.leases = (
            store,
            inventory,
            memberships,
            leases,
        )
        self.enabled = enabled
        self._github, self._aws = github_factory, aws_factory

    @classmethod
    def from_environment(cls, inventory, memberships):
        actions = enabled_actions()
        if not actions:
            return None
        return cls(
            store=RemediationStore(os.environ.get("DENALI_DSN", "")),
            inventory=inventory,
            memberships=memberships,
            leases=PlatformWriteLeases.from_environment(),
            enabled=actions,
        )

    def _admin(self, organization_id, user_id):
        try:
            if self.memberships is None:
                raise RemediationError("membership_unavailable")
            if self.memberships.role(organization_id, user_id) != "admin":
                raise RemediationError("live_organization_admin_required")
        except RemediationError:
            raise
        except Exception:
            raise RemediationError("membership_unavailable") from None

    def _enabled(self, action):
        if action not in self.enabled:
            raise RemediationError("resource_action_disabled")

    def _build_plan(self, row, *, mode="preview"):
        self._enabled(row["action"])
        self._admin(row["clerk_org_id"], row["actor_user_id"])
        reviewer = row.get("reviewer_user_id")
        if mode == "execute":
            if not reviewer or reviewer == row["actor_user_id"]:
                raise RemediationError("independent_review_required")
            self._admin(row["clerk_org_id"], reviewer)
        finding = self.inventory.get_finding(str(row["tenant_id"]), str(row["finding_id"]))
        if not finding:
            raise RemediationError("finding_not_found")
        open_finding(finding, row["action"])
        lease = self.leases.lease(
            organization_id=row["clerk_org_id"],
            grant_id=str(row["grant_id"]),
            action=row["action"],
            mode=mode,
            request_id=str(row["id"]),
            request_sha256=row.get("preview_sha256") or sha256(row["parameters"]),
            actor=row["actor_user_id"],
            reviewer=reviewer,
        )
        resource = lease["resource"]
        common = {
            "template_version": TEMPLATE_VERSION,
            "finding_sha256": sha256(
                {
                    key: finding.get(key)
                    for key in (
                        "rule_uid",
                        "state",
                        "evaluation_result",
                        "attributes",
                        "evidence",
                        "resources",
                    )
                }
            ),
            "resource_sha256": sha256(resource),
            "action": row["action"],
        }
        if row["action"] == GITHUB_ACTION:
            attributes = finding.get("attributes") or {}
            if attributes.get("repository", "").removeprefix("github.com/").lower() != (
                resource["full_name"].lower()
            ):
                raise RemediationError("finding_repository_mismatch")
            provider = self._github(lease)
            snapshot = provider.snapshot(attributes.get("source_path", ""))
            if attributes.get("repository_revision") != snapshot["base_sha"]:
                raise RemediationError("source_evidence_revision_stale")
            content, diff = github_patch(finding, snapshot["content"], row["parameters"])
            plan = {
                **common,
                **{key: value for key, value in snapshot.items() if key != "content"},
                "source_path": attributes["source_path"],
                "proposed_file_sha": git_blob_sha(content),
                "patch_sha256": sha256(diff.encode()),
            }
            return plan, diff, provider, content
        provider = self._aws(lease)
        document = provider.snapshot()
        proposed, diff = tighten_inline_policy(finding, document, row["parameters"], resource)
        plan = {
            **common,
            "before_sha256": sha256(document),
            "proposed_sha256": sha256(proposed),
            "patch_sha256": sha256(diff.encode()),
            "target_role_arn": resource["target_role_arn"],
            "policy_name": resource["policy_name"],
            "external_writer_race_possible": True,
        }
        return plan, diff, provider, proposed

    def preview(
        self, *, tenant_id, organization_id, actor, finding_id, grant_id, action, parameters
    ):
        row = {
            "id": str(uuid4()),
            "tenant_id": tenant_id,
            "clerk_org_id": organization_id,
            "actor_user_id": actor,
            "finding_id": finding_id,
            "grant_id": grant_id,
            "action": action,
            "parameters": parameters,
        }
        plan, diff, _, _ = self._build_plan(row)
        row["plan"] = plan
        row["preview_sha256"] = sha256({"action": action, "plan": plan, "parameters": parameters})
        row["expires_at"] = datetime.now(UTC) + timedelta(minutes=15)
        self.store.preview(row)
        return {
            "preview_id": row["id"],
            "preview_sha256": row["preview_sha256"],
            "plan": plan,
            "diff": diff,
            "expires_at": row["expires_at"].isoformat(),
            "requires_independent_admin_approval": True,
            "provider_mutated": False,
        }

    def request(
        self, *, tenant_id, organization_id, actor, preview_id, preview_sha256, key, justification
    ):
        self._admin(organization_id, actor)
        preview = self.store.get_preview(tenant_id, preview_id)
        if (
            not preview
            or preview["clerk_org_id"] != organization_id
            or (preview["preview_sha256"] != preview_sha256 or preview["actor_user_id"] != actor)
        ):
            raise RemediationError("preview_not_found")
        self._enabled(preview["action"])
        row = self.store.request(tenant_id, preview_id, actor, key, justification)
        return self.status(tenant_id, str(row["id"]))

    def review(self, *, tenant_id, organization_id, actor, request_id, decision, note):
        self._admin(organization_id, actor)
        row = self.store.get(tenant_id, request_id)
        if not row or row["clerk_org_id"] != organization_id:
            raise RemediationError("request_not_found")
        self._enabled(row["action"])
        self._admin(organization_id, row["actor_user_id"])
        if actor == row["actor_user_id"]:
            raise RemediationError("self_approval_forbidden")
        if decision == "approved":
            # Approval is for the exact current plan, not a stale diff.
            plan, _, _, _ = self._build_plan(row)
            if plan != row["plan"]:
                raise RemediationError("preview_drift_requires_new_request")
        self.store.review(tenant_id, request_id, actor, decision, note)
        return self.status(tenant_id, request_id)

    def status(self, tenant_id, request_id):
        row = self.store.get(tenant_id, request_id)
        if row is None:
            raise RemediationError("request_not_found")
        return {
            key: str(row[key]) if key in {"id", "preview_id", "grant_id"} else row.get(key)
            for key in (
                "id",
                "preview_id",
                "grant_id",
                "action",
                "state",
                "phase",
                "actor_user_id",
                "reviewer_user_id",
                "result",
                "error_code",
            )
        }

    def execute(self, request_id):
        row = self.store.claim(request_id)
        if not row:
            return
        tenant, nonce = str(row["tenant_id"]), str(row["lease_nonce"])
        try:
            if row["expires_at"] <= datetime.now(UTC):
                raise RemediationError("preview_expired")
            plan, _, provider, proposed = self._build_plan(row, mode="execute")
            if plan != row["plan"]:
                raise RemediationError("preview_drift_requires_new_request")
            self._admin(row["clerk_org_id"], row["actor_user_id"])
            self._admin(row["clerk_org_id"], row["reviewer_user_id"])
            self.store.mark_provider_attempted(tenant, request_id, nonce)
            result = (
                provider.execute_once(request_id, plan, proposed)
                if row["action"] == GITHUB_ACTION
                else provider.execute_once(plan, proposed)
            )
            self.store.finish(tenant, request_id, nonce, result=result)
        except RemediationError as error:
            self.store.finish(tenant, request_id, nonce, error=str(error))
        except Exception:
            self.store.finish(tenant, request_id, nonce, error="remediation_execution_failed")

    def reconcile(self, *, tenant_id, organization_id, actor, request_id):
        """Observe an ambiguous provider outcome, never repeat a provider write."""
        self._admin(organization_id, actor)
        row = self.store.get(tenant_id, request_id)
        if not row or row["clerk_org_id"] != organization_id:
            raise RemediationError("request_not_found")
        self._enabled(row["action"])
        if row["phase"] != "provider_attempted" or not (
            row["state"] == "needs_manual_resolution"
            or row["state"] == "running"
            and row["lease_expires_at"] <= datetime.now(UTC)
        ):
            raise RemediationError("request_not_reconcilable")
        self._admin(organization_id, row["actor_user_id"])
        self._admin(organization_id, row["reviewer_user_id"])
        lease = self.leases.lease(
            organization_id=organization_id,
            grant_id=str(row["grant_id"]),
            action=row["action"],
            mode="preview",
            request_id=request_id,
            request_sha256=row["preview_sha256"],
            actor=row["actor_user_id"],
            reviewer=row["reviewer_user_id"],
        )
        if sha256(lease["resource"]) != row["plan"]["resource_sha256"]:
            raise RemediationError("resource_grant_changed")
        if row["action"] == GITHUB_ACTION:
            result = self._github(lease).reconcile(request_id, row["plan"])
        else:
            result = self._aws(lease).reconcile(row["plan"])
        self.store.reconcile_finish(tenant_id, request_id, actor, result)
        return self.status(tenant_id, request_id)
