"""Bounded provider operations. No arbitrary URL/method/patch enters these clients."""

from __future__ import annotations

import base64
import json
import os
import re
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from denali.resource_writes.templates import (
    RemediationError,
    eligible_source_path,
    git_blob_sha,
    sha256,
)


class PlatformWriteLeases:
    def __init__(self, origin: str, key: str, receiver: str):
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.username
            or parsed.password
            or (parsed.path or parsed.query or parsed.fragment or not key or not receiver)
        ):
            raise ValueError("resource write lease configuration incomplete")
        from clerk_backend_api import Clerk

        self._origin = origin
        self._receiver = receiver
        self._clerk = Clerk(bearer_auth=key, timeout_ms=5000, retry_config=None)

    @classmethod
    def from_environment(cls):
        return cls(
            os.environ.get("DENALI_PLATFORM_CONNECTIONS_ORIGIN", ""),
            os.environ.get("DENALI_PLATFORM_MACHINE_SECRET_KEY", ""),
            os.environ.get("DENALI_PLATFORM_RESOURCE_WRITE_RECEIVER_MACHINE_ID", ""),
        )

    def lease(
        self,
        *,
        organization_id: str,
        grant_id: str,
        action: str,
        mode: str,
        request_id: str,
        request_sha256: str,
        actor: str,
        reviewer: str | None = None,
    ):
        claims = {
            "purpose": "denali:resource-write-lease",
            "org_id": organization_id,
            "grant_id": grant_id,
            "action": action,
            "mode": mode,
            "request_id": request_id,
            "request_sha256": request_sha256,
            "actor_user_id": actor,
            "reviewer_user_id": reviewer,
        }
        try:
            token = self._clerk.m2m.create_token(
                seconds_until_expiration=60,
                scopes=[self._receiver],
                claims=claims,
            ).token
            with httpx.Client(timeout=15, follow_redirects=False) as client:
                response = client.post(
                    f"{self._origin}/internal/v1/resource-write-grants/{grant_id}/lease",
                    json={
                        "clerk_org_id": organization_id,
                        "action": action,
                        "mode": mode,
                        "request_id": request_id,
                        "request_sha256": request_sha256,
                    },
                    headers={"Authorization": f"Bearer {token}"},
                )
                response.raise_for_status()
                return response.json()
        except Exception:
            raise RemediationError("resource_lease_unavailable") from None


class GitHubRemediator:
    def __init__(self, lease: dict[str, Any], client=None):
        self.resource = lease["resource"]
        self._token = lease["token"]
        self._client = client or httpx.Client(timeout=10, follow_redirects=False)
        self._repo = "/repos/" + self.resource["full_name"]

    def _api(self, method, path, *, missing=False, **kwargs):
        try:
            response = self._client.request(
                method,
                "https://api.github.com" + self._repo + path,
                headers={
                    "Authorization": "Bearer " + self._token,
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2026-03-10",
                },
                **kwargs,
            )
            if missing and response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError):
            raise RemediationError("github_provider_unavailable") from None

    def snapshot(self, path: str):
        eligible_source_path(path)
        repo = self._api("GET", "")
        if (
            repo.get("id") != self.resource["repository_id"]
            or repo.get("archived")
            or (repo.get("full_name", "").lower() != self.resource["full_name"].lower())
        ):
            raise RemediationError("github_repository_identity_changed")
        branch = repo.get("default_branch")
        if not isinstance(branch, str) or not branch or len(branch) > 200:
            raise RemediationError("github_base_branch_invalid")
        branch_state = self._api("GET", "/branches/" + quote(branch, safe=""))
        base_sha = (branch_state.get("commit") or {}).get("sha")
        if not isinstance(base_sha, str) or re.fullmatch(r"[0-9a-f]{40}", base_sha) is None:
            raise RemediationError("github_base_branch_invalid")
        rules = self._api(
            "GET", "/rules/branches/" + quote(branch, safe=""), params={"per_page": 100}
        )
        if not branch_state.get("protected") or not isinstance(rules, list) or len(rules) >= 100:
            raise RemediationError("github_review_rule_not_verified")
        eligible = [
            rule
            for rule in rules
            if rule.get("type") == "pull_request"
            and ((rule.get("parameters") or {}).get("required_approving_review_count", 0) >= 1)
        ]
        # Inspect only repository-level active rulesets in v1. Organization-level
        # policy needs its own reviewed metadata adapter, not an inferred bypass.
        eligible = [rule for rule in eligible if rule.get("ruleset_source_type") == "Repository"]
        verified_rule_ids = []
        for rule in eligible:
            details = self._api("GET", f"/rulesets/{int(rule['ruleset_id'])}")
            bypass = details.get("bypass_actors")
            if details.get("enforcement") != "active" or not isinstance(bypass, list):
                continue
            if bypass:
                continue
            verified_rule_ids.append(rule["ruleset_id"])
        if not verified_rule_ids:
            # Classic branch protection is also valid, but must require review,
            # enforce admins, and contain no bypass for this write App.
            protection = self._api("GET", "/branches/" + quote(branch, safe="") + "/protection")
            review = protection.get("required_pull_request_reviews") or {}
            bypass = review.get("bypass_pull_request_allowances") or {}
            apps = bypass.get("apps")
            if review.get("required_approving_review_count", 0) < 1 or (
                (protection.get("enforce_admins") or {}).get("enabled") is not True
                or not isinstance(apps, list)
                or apps
                or bypass.get("users")
                or bypass.get("teams")
            ):
                raise RemediationError("github_review_rule_not_verified")
            verified_rule_ids = ["classic:" + sha256(protection)]
        file = self._api("GET", "/contents/" + quote(path, safe="/"), params={"ref": base_sha})
        if (
            file.get("type") != "file"
            or file.get("encoding") != "base64"
            or (file.get("size", 100_001) > 100_000)
        ):
            raise RemediationError("github_file_not_eligible")
        try:
            content = base64.b64decode(file["content"].replace("\n", ""), validate=True)
        except (ValueError, KeyError, TypeError):
            raise RemediationError("github_file_not_eligible") from None
        if git_blob_sha(content) != file.get("sha"):
            raise RemediationError("github_blob_identity_changed")
        return {
            "base_branch": branch,
            "base_sha": base_sha,
            "file_sha": file["sha"],
            "rules_sha256": sha256({"rules": rules, "verified_rule_ids": verified_rule_ids}),
            "content": content,
        }

    def execute_once(self, request_id: str, plan: dict[str, Any], content: bytes):
        """Never retry this method automatically after an ambiguous outcome."""
        branch = "transilience/remediation/" + request_id
        marker = "<!-- transilience-remediation:" + request_id + ":" + plan["patch_sha256"] + " -->"
        if self._api("GET", "/git/ref/heads/" + branch, missing=True) is not None:
            raise RemediationError("github_branch_already_exists_reconcile_required")
        self._api(
            "POST", "/git/refs", json={"ref": "refs/heads/" + branch, "sha": plan["base_sha"]}
        )
        committed = self._api(
            "PUT",
            "/contents/" + quote(plan["source_path"], safe="/"),
            json={
                "message": "Denali: request managed Bedrock guardrail (" + request_id + ")",
                "content": base64.b64encode(content).decode(),
                "sha": plan["file_sha"],
                "branch": branch,
            },
        )
        if (committed.get("content") or {}).get("sha") != git_blob_sha(content):
            raise RemediationError("github_patch_readback_mismatch")
        pull = self._api(
            "POST",
            "/pulls",
            json={
                "title": "Denali: request an approved managed Bedrock guardrail",
                "body": (
                    marker
                    + "\n\nReview and test this deterministic guardrail configuration before "
                    "merging. Denali never merges or enables auto-merge. Existing CI may run."
                ),
                "head": branch,
                "base": plan["base_branch"],
                "draft": True,
            },
        )
        return self._verified_pull(pull, request_id, plan)

    def reconcile(self, request_id: str, plan: dict[str, Any]):
        pulls = self._api(
            "GET",
            "/pulls",
            params={
                "state": "all",
                "per_page": 100,
                "head": self.resource["full_name"].split("/")[0]
                + ":transilience/remediation/"
                + request_id,
            },
        )
        if not isinstance(pulls, list) or len(pulls) != 1:
            raise RemediationError("github_partial_outcome_manual_resolution")
        return self._verified_pull(pulls[0], request_id, plan)

    def _verified_pull(self, pull, request_id, plan):
        marker = "<!-- transilience-remediation:" + request_id + ":" + plan["patch_sha256"] + " -->"
        head, base = pull.get("head") or {}, pull.get("base") or {}
        if (
            not pull.get("draft")
            or pull.get("merged_at")
            or pull.get("state") != "open"
            or (
                head.get("ref") != "transilience/remediation/" + request_id
                or (head.get("repo") or {}).get("id") != self.resource["repository_id"]
                or base.get("ref") != plan["base_branch"]
                or marker not in str(pull.get("body", ""))
            )
        ):
            raise RemediationError("github_pull_identity_changed")
        file = self._api(
            "GET", "/contents/" + quote(plan["source_path"], safe="/"), params={"ref": head["sha"]}
        )
        if file.get("sha") != plan["proposed_file_sha"]:
            raise RemediationError("github_draft_patch_changed")
        files = self._api("GET", f"/pulls/{int(pull['number'])}/files", params={"per_page": 100})
        if (
            not isinstance(files, list)
            or len(files) != 1
            or files[0].get("filename") != (plan["source_path"])
            or files[0].get("sha") != plan["proposed_file_sha"]
        ):
            raise RemediationError("github_draft_has_unreviewed_changes")
        commits = self._api(
            "GET", f"/pulls/{int(pull['number'])}/commits", params={"per_page": 100}
        )
        if (
            not isinstance(commits, list)
            or len(commits) != 1
            or (
                (commits[0].get("parents") or [{}])[0].get("sha") != plan["base_sha"]
                or (commits[0].get("commit") or {}).get("message")
                != ("Denali: request managed Bedrock guardrail (" + request_id + ")")
            )
        ):
            raise RemediationError("github_commit_identity_changed")
        return {
            "pull_number": pull["number"],
            "pull_url": pull["html_url"],
            "commit_sha": head["sha"],
            "draft": True,
            "base_branch": base["ref"],
        }


class AwsInlineRemediator:
    def __init__(self, lease: dict[str, Any], client=None):
        self.resource = lease["resource"]
        if client is None:
            import boto3
            from botocore.config import Config

            client = boto3.client(
                "iam",
                aws_access_key_id=lease["access_key_id"],
                aws_secret_access_key=lease["secret_access_key"],
                aws_session_token=lease["session_token"],
                config=Config(
                    connect_timeout=3, read_timeout=10, retries={"total_max_attempts": 1}
                ),
            )
        self._client = client

    def snapshot(self):
        try:
            payload = self._client.get_role_policy(
                RoleName=self.resource["target_role_arn"].rsplit("/", 1)[-1],
                PolicyName=self.resource["policy_name"],
            )
            document = payload["PolicyDocument"]
            if not isinstance(document, dict):
                raise ValueError
            return document
        except Exception:
            raise RemediationError("aws_policy_read_unavailable") from None

    def execute_once(self, plan: dict[str, Any], proposed: dict[str, Any]):
        # IAM PutRolePolicy has no CAS. This last-moment check narrows, but
        # cannot eliminate, races with an external IAM writer. Never retry.
        if sha256(self.snapshot()) != plan["before_sha256"]:
            raise RemediationError("aws_policy_drift")
        try:
            self._client.put_role_policy(
                RoleName=self.resource["target_role_arn"].rsplit("/", 1)[-1],
                PolicyName=self.resource["policy_name"],
                PolicyDocument=json.dumps(proposed),
            )
        except Exception:
            raise RemediationError("aws_write_outcome_unknown") from None
        return self.reconcile(plan)

    def reconcile(self, plan: dict[str, Any]):
        if sha256(self.snapshot()) != plan["proposed_sha256"]:
            raise RemediationError("aws_write_outcome_manual_resolution")
        return {
            "target_role_arn": self.resource["target_role_arn"],
            "policy_name": self.resource["policy_name"],
            "policy_sha256": plan["proposed_sha256"],
            "external_writer_race_possible": True,
        }
