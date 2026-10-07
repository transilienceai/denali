from __future__ import annotations

import base64
import copy
from uuid import uuid4

import httpx
import pytest

from denali.resource_writes.providers import GitHubRemediator
from denali.resource_writes.templates import RemediationError, git_blob_sha, sha256

CONTENT = b'const call = new InvokeModelCommand({modelId: "approved"});\n'
RESOURCE = {
    "repository_id": 101,
    "full_name": "transilienceai/pilot",
    "app_id": 202,
    "installation_id": 303,
}


class GitHub:
    def __init__(self, *, drift=None, unknown=False):
        self.drift, self.unknown = drift, unknown
        self.calls, self.branch, self.pull = [], None, None
        self.committed = CONTENT

    def respond(self, request):
        import json

        method, path = request.method, request.url.path.removeprefix("/repos/transilienceai/pilot")
        self.calls.append((method, path))
        if method == "POST" and path == "/git/refs":
            self.branch = json.loads(request.content)
            payload = self.branch
        elif method == "PUT":
            body = json.loads(request.content)
            assert body["branch"].startswith("transilience/remediation/")
            self.committed = base64.b64decode(body["content"])
            payload = {"content": {"sha": git_blob_sha(self.committed)}}
        elif method == "POST" and path == "/pulls":
            body = json.loads(request.content)
            assert body["draft"] is True
            self.pull = {
                **body,
                "state": "open",
                "merged_at": None,
                "number": 1,
                "html_url": "https://github.com/transilienceai/pilot/pull/1",
                "head": {"ref": body["head"], "sha": "b" * 40, "repo": {"id": 101}},
                "base": {"ref": body["base"]},
            }
            if self.unknown:
                raise httpx.ReadTimeout("never-echo-private-token")
            payload = self.pull
        elif path.startswith("/git/ref/"):
            if self.branch is None:
                return httpx.Response(404)
            payload = self.branch
        elif path == "":
            payload = {"id": 101, "full_name": RESOURCE["full_name"], "default_branch": "main"}
            if self.drift == "repository":
                payload["id"] = 999
        elif path == "/branches/main":
            payload = {"protected": True, "commit": {"sha": "a" * 40}}
        elif path == "/rules/branches/main":
            payload = []
        elif path == "/branches/main/protection":
            payload = {
                "enforce_admins": {"enabled": True},
                "required_pull_request_reviews": {
                    "required_approving_review_count": 1,
                    "bypass_pull_request_allowances": {"apps": [], "teams": [], "users": []},
                },
            }
            if self.drift == "bypass":
                payload["required_pull_request_reviews"]["bypass_pull_request_allowances"][
                    "apps"
                ] = [{"id": 202}]
            elif self.drift == "no_reviews":
                payload["required_pull_request_reviews"]["required_approving_review_count"] = 0
            elif self.drift == "no_admin_enforcement":
                payload["enforce_admins"]["enabled"] = False
        elif path == "/contents/src/model.ts":
            content = CONTENT if request.url.params.get("ref") == "a" * 40 else self.committed
            payload = {
                "type": "file",
                "encoding": "base64",
                "size": len(content),
                "content": base64.b64encode(content).decode(),
                "sha": git_blob_sha(content),
            }
        elif path == "/pulls/1/files":
            payload = [{"filename": "src/model.ts", "sha": git_blob_sha(self.committed)}]
            if self.drift == "extra_file":
                payload.append({"filename": ".github/workflows/unsafe.yml", "sha": "bad"})
        elif path == "/pulls/1/commits":
            rid = self.pull["head"]["ref"].rsplit("/", 1)[-1]
            payload = [
                {
                    "parents": [{"sha": "a" * 40}],
                    "commit": {
                        "message": "Denali: request managed Bedrock guardrail (" + rid + ")"
                    },
                }
            ]
            if self.drift == "extra_commit":
                payload.append(copy.deepcopy(payload[0]))
        elif path == "/pulls":
            payload = [self.pull] if self.pull else []
        else:
            raise AssertionError((method, path))
        return httpx.Response(200, json=payload)


def provider(fake):
    return GitHubRemediator(
        {"resource": RESOURCE, "token": "opaque-test-token"},
        httpx.Client(transport=httpx.MockTransport(fake.respond)),
    )


def plan(client):
    return {
        **{
            key: value for key, value in client.snapshot("src/model.ts").items() if key != "content"
        },
        "source_path": "src/model.ts",
        "patch_sha256": "c" * 64,
        "proposed_file_sha": git_blob_sha(CONTENT + b"// approved guardrail\n"),
    }


@pytest.mark.parametrize("drift", ["repository", "bypass", "no_reviews", "no_admin_enforcement"])
def test_unprovable_repository_policy_never_writes(drift):
    fake = GitHub(drift=drift)
    with pytest.raises(RemediationError):
        provider(fake).snapshot("src/model.ts")
    assert all(method == "GET" for method, _ in fake.calls)


_ABSENT_BYPASS = object()


def classic_protection_provider(bypass):
    fake = GitHub()
    observed_protection = []

    def respond(request):
        response = fake.respond(request)
        if request.url.path.endswith("/branches/main/protection"):
            protection = response.json()
            review = protection["required_pull_request_reviews"]
            if bypass is _ABSENT_BYPASS:
                del review["bypass_pull_request_allowances"]
            else:
                review["bypass_pull_request_allowances"] = copy.deepcopy(bypass)
            observed_protection.append(copy.deepcopy(protection))
            return httpx.Response(200, json=protection)
        return response

    client = GitHubRemediator(
        {"resource": RESOURCE, "token": "opaque-test-token"},
        httpx.Client(transport=httpx.MockTransport(respond)),
    )
    return client, fake, observed_protection


@pytest.mark.parametrize("bypass", [
    _ABSENT_BYPASS, {"apps": [], "users": [], "teams": []},
])
def test_classic_no_bypass_shapes_allow_read_only_snapshot_and_hash_original(bypass):
    client, fake, protection = classic_protection_provider(bypass)
    snapshot = client.snapshot("src/model.ts")
    assert snapshot["content"] == CONTENT
    assert all(method == "GET" for method, _ in fake.calls)
    assert snapshot["rules_sha256"] == sha256({
        "rules": [], "verified_rule_ids": ["classic:" + sha256(protection[0])],
    })
    if bypass is _ABSENT_BYPASS:
        review = protection[0]["required_pull_request_reviews"]
        assert "bypass_pull_request_allowances" not in review


@pytest.mark.parametrize("bypass", [
    None, False, 0, "", [], {},
    {"apps": [], "users": []},
    {"apps": [], "teams": []},
    {"users": [], "teams": []},
    *[
        {**{"apps": [], "users": [], "teams": []}, actor_type: malformed}
        for actor_type in ("apps", "users", "teams")
        for malformed in (None, False, 0, "", {}, [{"id": 202}])
    ],
])
def test_present_malformed_or_nonempty_classic_bypass_never_reads_source_or_writes(bypass):
    client, fake, _ = classic_protection_provider(bypass)
    with pytest.raises(RemediationError, match="github_review_rule_not_verified"):
        client.snapshot("src/model.ts")
    assert all(method == "GET" for method, _ in fake.calls)
    assert not any(path.startswith("/contents/") for _, path in fake.calls)


def test_absent_and_explicit_empty_classic_protection_keep_distinct_original_hashes():
    absent, _, _ = classic_protection_provider(_ABSENT_BYPASS)
    explicit, _, _ = classic_protection_provider({"apps": [], "users": [], "teams": []})
    assert absent.snapshot("src/model.ts")["rules_sha256"] != (
        explicit.snapshot("src/model.ts")["rules_sha256"]
    )


def test_invalid_or_secret_path_is_denied_before_provider_read():
    fake = GitHub()
    with pytest.raises(RemediationError, match="source_path_not_eligible"):
        provider(fake).snapshot(".env")
    assert fake.calls == []


def test_deterministic_draft_only_no_default_push_merge_or_workflow():
    fake, rid = GitHub(), str(uuid4())
    client = provider(fake)
    approved = plan(client)
    result = client.execute_once(rid, approved, CONTENT + b"// approved guardrail\n")
    assert result["draft"] is True
    assert fake.branch == {"ref": "refs/heads/transilience/remediation/" + rid, "sha": "a" * 40}
    assert [item for item in fake.calls if item[0] != "GET"] == [
        ("POST", "/git/refs"),
        ("PUT", "/contents/src/model.ts"),
        ("POST", "/pulls"),
    ]


def test_ambiguous_creation_reconciles_read_only_never_creates_second_pull():
    fake, rid = GitHub(unknown=True), str(uuid4())
    client, content = provider(fake), CONTENT + b"// approved guardrail\n"
    approved = plan(client)
    with pytest.raises(RemediationError, match="github_provider_unavailable") as caught:
        client.execute_once(rid, approved, content)
    assert "private-token" not in str(caught.value)
    mutation_count = len([item for item in fake.calls if item[0] != "GET"])
    assert client.reconcile(rid, approved)["pull_number"] == 1
    assert len([item for item in fake.calls if item[0] != "GET"]) == mutation_count
    with pytest.raises(RemediationError, match="already_exists"):
        client.execute_once(rid, approved, content)
    assert len([item for item in fake.calls if item[0] != "GET"]) == mutation_count


@pytest.mark.parametrize("drift", ["extra_file", "extra_commit"])
def test_unreviewed_result_is_not_declared_success(drift):
    fake, rid = GitHub(drift=drift), str(uuid4())
    client = provider(fake)
    approved = plan(client)
    with pytest.raises(RemediationError):
        client.execute_once(rid, approved, CONTENT + b"// approved guardrail\n")
