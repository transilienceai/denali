"""Whole-repository continuations keep immutable proof, never credentials/source."""

from __future__ import annotations

import base64
from copy import deepcopy

import pytest
from test_github_repository_connector import (
    BLOB,
    COMMIT,
    HANDLER,
    HANDLER_BLOB,
    SOURCE,
    AppClient,
    Response,
    Sink,
    connection,
    routes,
)

from denali.connectors.github_repository import (
    GitHubCheckpointRejected,
    GitHubRepositoryCollector,
    GitHubSourceError,
)
from denali.domain import CoverageState


def target():
    value = connection()
    value["declared_scopes"] = [
        "github.repository_metadata",
        "github.repository_contents",
        "github.actions_workflows",
    ]
    return value


def run(collector, checkpoint, *, saved=None, selected=None, sink=None, callback=None):
    def save(value):
        checkpoint.clear()
        checkpoint.update(deepcopy(value))
        if saved is not None:
            saved.append(deepcopy(value))
        return True

    return collector.collect_resumable(
        tenant_id="tenant",
        connection=selected or target(),
        repository=sink or Sink(),
        checkpoint=deepcopy(checkpoint),
        save_checkpoint=callback or save,
    )


def test_113_repositories_finish_across_fresh_slices_without_connection_budget_sampling(
    monkeypatch,
):
    selected = target()
    selected["configuration"]["repositories"] = []
    provider_routes = {}
    content = b"synthetic-source-not-persisted = 1\n"
    for number in range(113):
        full_name = f"acme/repository-{number}"
        selected["configuration"]["repositories"].append(
            {
                "id": 1000 + number,
                "node_id": f"R_{number}",
                "full_name": full_name,
                "owner_id": 7,
                "owner_login": "acme",
            }
        )
        prefix = f"/repos/{full_name}"
        provider_routes[prefix] = {
            "id": 1000 + number,
            "node_id": f"R_{number}",
            "full_name": full_name,
            "owner": {"id": 7, "login": "acme"},
            "default_branch": "main",
        }
        provider_routes[f"{prefix}/git/ref/heads/main"] = {"object": {"sha": COMMIT}}
        entries = []
        for position in range(40):
            sha = f"{position + 100:040x}"
            entries.append(
                {
                    "path": f"src/file-{position}.py",
                    "mode": "100644",
                    "type": "blob",
                    "sha": sha,
                    "size": len(content),
                }
            )
            provider_routes[f"{prefix}/git/blobs/{sha}"] = {
                "sha": sha,
                "encoding": "base64",
                "content": base64.b64encode(content).decode(),
            }
        provider_routes[f"{prefix}/git/trees/{COMMIT}"] = {"truncated": False, "tree": entries}
    analyzed = []

    def analyze(_self, *, snapshot, before_ingest, **_kwargs):
        before_ingest()
        analyzed.append(snapshot.repository_id)
        assert len(snapshot.files) == 40
        return {
            "repository_id": snapshot.repository_id,
            "repository": snapshot.repository_name.removeprefix("github.com/"),
            "state": "complete",
            "revision": snapshot.commit,
            "files": len(snapshot.files),
            "bytes": snapshot.total_bytes,
            "source_assets": 1,
            "inventory_assets": 0,
            "inventory_relationships": 0,
            "posture_findings": 0,
            "deployment_relationships": 0,
            "coverage": {
                plane: "complete" for plane in ("source", "inventory", "posture", "correlation")
            },
            "correlation": {
                key: 0
                for key in ("declarations", "proven", "ambiguous", "unmatched", "targets_evaluated")
            },
        }

    monkeypatch.setattr(GitHubRepositoryCollector, "_analyze_snapshot", analyze)
    checkpoint = {}
    requests = slices = 0
    while True:
        app = AppClient(provider_routes)
        result = run(GitHubRepositoryCollector(app, max_requests=50), checkpoint, selected=selected)
        slices += 1
        requests += result["github_requests"]
        assert len(app.tokens) <= 5
        assert result["repository_count"] == 113
        assert result["completed_repository_count"] == min(slices * 5, 113)
        assert result["partial_count"] == result["failed_count"] == 0
        assert "synthetic-source-not-persisted" not in repr(checkpoint)
        assert "ghs_ephemeral" not in repr(checkpoint)
        assert set(checkpoint) == {"boundary_hash", "repositories", "repository_count"}
        if not result["resume_pending"]:
            break
        assert result["state"] == "running"
        assert result["retry_after_seconds"] == 0
        assert slices < 24
    assert slices == 23
    assert requests > 4000
    assert len(analyzed) == len(set(analyzed)) == 113
    assert result["state"] == "complete"
    assert all(
        set(value) == {"revision", "default_branch", "result"}
        for value in checkpoint["repositories"].values()
    )


def test_budget_pause_saves_commit_before_blobs_and_resumes_the_pinned_revision():
    checkpoint, saved, sink = {}, [], Sink()
    first = AppClient(routes())
    paused = run(
        GitHubRepositoryCollector(first, max_requests=5), checkpoint, saved=saved, sink=sink
    )
    assert paused["resume_pending"] is True
    assert paused["completed_repository_count"] == 0
    assert paused["repositories"] == []
    assert sink.batches == []
    assert checkpoint["repositories"]["42"] == {
        "revision": COMMIT,
        "default_branch": "main",
        "interruption_count": 1,
    }
    assert any(item["repositories"].get("42", {}).get("revision") == COMMIT for item in saved)
    changed = routes()
    changed["/repos/acme/agent"]["default_branch"] = "renamed-main"
    changed["/repos/acme/agent/git/ref/heads/main"] = {"object": {"sha": "f" * 40}}
    second = AppClient(changed)
    finished = run(GitHubRepositoryCollector(second), checkpoint, sink=sink)
    assert finished["state"] == "complete"
    assert finished["repositories"][0]["revision"] == COMMIT
    assert not any("/git/ref/" in path for path in second.requests)
    assert len(sink.batches) == 4
    assert SOURCE not in repr(checkpoint)
    assert "ghs_ephemeral-do-not-store" not in repr(checkpoint)


def test_mid_blob_rate_pause_never_ingests_or_completes_a_partial_snapshot(monkeypatch):
    monkeypatch.setattr("denali.connectors.github_repository.MAX_BLOB_FETCH_WORKERS", 1)
    limited = routes()
    limited[f"/repos/acme/agent/git/blobs/{BLOB}"] = Response(
        {}, status_code=429, headers={"Retry-After": "180"}
    )
    checkpoint, sink = {}, Sink()
    for _attempt in range(4):
        result = run(GitHubRepositoryCollector(AppClient(limited)), checkpoint, sink=sink)
        assert result["resume_pending"] is True
        assert result["state"] == "running"
        assert result["retry_after_seconds"] == 180
        assert result["completed_repository_count"] == 0
        assert "interruption_count" not in checkpoint["repositories"]["42"]
        assert "result" not in checkpoint["repositories"]["42"]
        assert sink.batches == []
    final = run(GitHubRepositoryCollector(AppClient(routes())), checkpoint, sink=sink)
    assert final["state"] == "complete"
    assert final["repositories"][0]["files"] == 2


def test_observed_rate_limit_reset_is_bounded_and_not_a_terminal_result():
    limited = routes()
    limited["/repos/acme/agent"] = Response(
        {},
        status_code=403,
        headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "9999999999"},
    )
    checkpoint, sink = {}, Sink()
    result = run(GitHubRepositoryCollector(AppClient(limited)), checkpoint, sink=sink)
    assert result["retry_after_seconds"] == 3660
    assert result["resume_pending"] is True
    assert result["repositories"] == []
    assert checkpoint["repositories"] == {}
    assert sink.batches == []


def test_non_rate_no_progress_restarts_have_a_durable_bound():
    checkpoint, sink = {}, Sink()
    for number in range(3):
        result = run(
            GitHubRepositoryCollector(AppClient(routes()), max_requests=5), checkpoint, sink=sink
        )
        assert checkpoint["repositories"]["42"]["interruption_count"] == number + 1
        assert result["resume_pending"] is (number < 2)
    assert result["state"] == "partial"
    assert result["completed_repository_count"] == 1
    assert result["repositories"][0]["detail"] == "github_collection_retry_limit_reached"
    assert len(sink.batches) == 1
    assert sink.batches[0].coverage[0].state is CoverageState.PARTIAL


@pytest.mark.parametrize("reject_at", [1, 3, 5, 6])
def test_checkpoint_rejection_stops_before_further_provider_or_ingest_work(reject_at):
    app, sink = AppClient(routes()), Sink()
    calls = []

    def save(value):
        calls.append(deepcopy(value))
        return len(calls) != reject_at

    with pytest.raises(GitHubCheckpointRejected):
        run(GitHubRepositoryCollector(app), {}, sink=sink, callback=save)
    assert len(calls) == reject_at
    assert len(sink.batches) == (1 if reject_at == 6 else 0)
    if reject_at == 1:
        assert app.requests == app.tokens == []
    if reject_at == 3:
        assert not any("/git/trees/" in path or "/git/blobs/" in path for path in app.requests)
    assert all("result" not in progress for progress in calls[-1]["repositories"].values())


def test_sink_failure_remains_retryable_and_never_checkpoints_repository_completion():
    checkpoint = {}

    class BrokenSink(Sink):
        def ingest(self, *_args):
            raise RuntimeError("synthetic database failure with private body")

    with pytest.raises(RuntimeError):
        run(GitHubRepositoryCollector(AppClient(routes())), checkpoint, sink=BrokenSink())
    assert checkpoint["repositories"]["42"]["revision"] == COMMIT
    assert "result" not in checkpoint["repositories"]["42"]
    assert "private body" not in repr(checkpoint)


def test_exhausted_transient_provider_retries_do_not_become_permanent_repository_failures():
    failing = routes()
    failing["/repos/acme/agent"] = Response({}, status_code=503)
    checkpoint, sink = {}, Sink()
    with pytest.raises(GitHubSourceError, match="github_upstream_unavailable"):
        run(GitHubRepositoryCollector(AppClient(failing)), checkpoint, sink=sink)
    assert checkpoint["repositories"] == {}
    assert sink.batches == []


@pytest.mark.parametrize("change", ["installation", "account", "scope", "node", "name", "tenant"])
def test_checkpoint_rejects_boundary_changes_before_provider_calls(change):
    checkpoint = {}
    run(GitHubRepositoryCollector(AppClient(routes()), max_requests=5), checkpoint)
    changed = target()
    if change == "installation":
        changed["credential_reference"]["installation_id"] = 10
    elif change == "account":
        changed["configuration"]["account_login"] = "different"
    elif change == "scope":
        changed["declared_scopes"] = ["github.repository_contents"]
    elif change == "node":
        changed["configuration"]["repositories"][0]["node_id"] = "R_changed"
    elif change == "name":
        changed["configuration"]["repositories"][0]["full_name"] = "acme/renamed"
    app = AppClient(routes())
    with pytest.raises(GitHubSourceError):
        GitHubRepositoryCollector(app).collect_resumable(
            tenant_id="other-tenant" if change == "tenant" else "tenant",
            connection=changed,
            repository=Sink(),
            checkpoint=checkpoint,
            save_checkpoint=lambda _value: pytest.fail("changed boundary was persisted"),
        )
    assert app.requests == app.tokens == []


@pytest.mark.parametrize(
    "scope", [[], ["github.repository_metadata"], ["github.actions_workflows"]]
)
def test_resumable_collection_requires_declared_contents_before_any_provider_call(scope):
    selected, app = target(), AppClient(routes())
    selected["declared_scopes"] = scope
    with pytest.raises(GitHubSourceError):
        run(GitHubRepositoryCollector(app), {}, selected=selected)
    assert app.requests == app.tokens == []


class WalkingApp(AppClient):
    ROOT = "d" * 40
    CHILD = "e" * 40

    def __init__(self, *, oversized=False, bad_child=None, truncated_child=False):
        super().__init__(routes())
        self.oversized, self.bad_child, self.truncated_child = oversized, bad_child, truncated_child
        self.tree_parameters = []

    def installation_request(self, method, path, *, token, **kwargs):
        if "/git/trees/" not in path:
            return super().installation_request(method, path, token=token, **kwargs)
        self.requests.append(path)
        self.tree_parameters.append(kwargs.get("params"))
        if kwargs.get("params") == {"recursive": "1"} and path.endswith(COMMIT):
            return Response(
                {
                    "truncated": not self.oversized,
                    "tree": (
                        [
                            {"path": f"manual-{index}.pdf", "type": "blob", "mode": "100644"}
                            for index in range(20_001)
                        ]
                        + [
                            {
                                "path": "stack.ts",
                                "type": "blob",
                                "mode": "100644",
                                "sha": BLOB,
                                "size": len(SOURCE.encode()),
                            },
                            {
                                "path": "src/handler.ts",
                                "type": "blob",
                                "mode": "100644",
                                "sha": HANDLER_BLOB,
                                "size": len(HANDLER.encode()),
                            },
                        ]
                        if self.oversized
                        else []
                    ),
                }
            )
        if path.endswith(COMMIT):
            assert "params" not in kwargs, "Non-recursive reads must omit recursive"
            return Response(
                {
                    "sha": self.ROOT,
                    "truncated": False,
                    "tree": [
                        {"path": "node_modules", "type": "tree", "mode": "040000", "sha": "1" * 40},
                        {"path": ".hidden", "type": "tree", "mode": "040000", "sha": "2" * 40},
                        {"path": "tests", "type": "tree", "mode": "040000", "sha": "3" * 40},
                        {
                            "path": "stack.ts",
                            "type": "blob",
                            "mode": "100644",
                            "sha": BLOB,
                            "size": len(SOURCE.encode()),
                        },
                        {"path": "src", "type": "tree", "mode": "040000", "sha": self.CHILD},
                        {"path": "linked.ts", "type": "blob", "mode": "120000", "sha": "4" * 40},
                        {"path": "submodule", "type": "commit", "mode": "160000", "sha": "5" * 40},
                    ],
                }
            )
        assert path.endswith(self.CHILD)
        return Response(
            {
                "sha": self.CHILD,
                "truncated": self.truncated_child,
                "tree": [
                    self.bad_child
                    or {
                        "path": "handler.ts",
                        "type": "blob",
                        "mode": "100644",
                        "sha": HANDLER_BLOB,
                        "size": len(HANDLER.encode()),
                    }
                ],
            }
        )


@pytest.mark.parametrize("oversized", [False, True])
def test_large_or_truncated_recursive_tree_uses_bounded_pruned_immutable_walk(oversized):
    app, checkpoint = WalkingApp(oversized=oversized), {}
    result = run(GitHubRepositoryCollector(app), checkpoint)
    assert result["state"] == "complete"
    assert result["repositories"][0]["files"] == 2
    assert app.tree_parameters == (
        [{"recursive": "1"}] if oversized else [{"recursive": "1"}, None, {"recursive": "1"}]
    )
    assert not any(
        path.endswith(sha * 40) for sha in ("1", "2", "3", "4", "5") for path in app.requests
    )
    assert checkpoint["repositories"]["42"]["revision"] == COMMIT


@pytest.mark.parametrize("path", ["../escape.py", "/escape.py", "a/b.py", ".", "bad\\name.py"])
def test_tree_walk_rejects_unsafe_child_paths_without_fetching_source(path):
    class NonrecursiveChildApp(WalkingApp):
        def installation_request(self, method, path, *, token, **kwargs):
            if path.endswith(self.CHILD) and "params" in kwargs:
                return Response({"sha": self.CHILD, "truncated": True, "tree": []})
            return super().installation_request(method, path, token=token, **kwargs)

    app = NonrecursiveChildApp(
        bad_child={
            "path": path,
            "type": "blob",
            "mode": "100644",
            "sha": HANDLER_BLOB,
            "size": len(HANDLER.encode()),
        }
    )
    result = run(GitHubRepositoryCollector(app), {})
    assert result["failed_count"] == 1
    assert result["repositories"][0]["detail"] == "invalid_tree_path"
    assert not any("/git/blobs/" in path for path in app.requests)


def test_nonrecursive_tree_truncation_and_traversal_limits_never_claim_complete(monkeypatch):
    truncated = run(GitHubRepositoryCollector(WalkingApp(truncated_child=True)), {})
    assert truncated["failed_count"] == 1
    assert truncated["repositories"][0]["detail"] == "repository_tree_incomplete"
    monkeypatch.setattr("denali.connectors.github_repository.MAX_TREE_REQUESTS", 1)
    limited = run(GitHubRepositoryCollector(WalkingApp()), {})
    assert limited["failed_count"] == 1
    assert limited["repositories"][0]["detail"] == "repository_tree_request_limit_exceeded"


def test_repository_file_safety_limit_is_honest_terminal_partial_not_a_resume_loop(monkeypatch):
    monkeypatch.setattr("denali.connectors.github_repository.MAX_SELECTED_FILES", 1)
    checkpoint = {}
    result = run(GitHubRepositoryCollector(AppClient(routes())), checkpoint)
    assert result["resume_pending"] is False
    assert result["partial_count"] == 1
    assert checkpoint["repositories"]["42"]["result"]["files"] == 1


def test_saved_final_interruption_after_container_loss_terminalizes_without_provider_work():
    checkpoint, sink = {}, Sink()
    run(GitHubRepositoryCollector(AppClient(routes()), max_requests=5), checkpoint)
    checkpoint["repositories"]["42"]["interruption_count"] = 3
    app = AppClient(routes())
    result = run(GitHubRepositoryCollector(app), checkpoint, sink=sink)
    assert result["resume_pending"] is False
    assert result["repositories"][0]["detail"] == "github_collection_retry_limit_reached"
    assert app.requests == app.tokens == []
    assert len(sink.batches) == 1
    # The terminal projection remains valid on another container/repeated dispatch.
    assert run(GitHubRepositoryCollector(app), checkpoint)["state"] == "partial"
    assert app.requests == app.tokens == []


def test_repeated_mid_repository_deadlines_are_bounded_without_partial_analysis(monkeypatch):
    monkeypatch.setattr("denali.connectors.github_repository.MAX_BLOB_FETCH_WORKERS", 1)
    checkpoint, sink = {}, Sink()

    class SlowTreeApp(AppClient):
        def __init__(self):
            super().__init__(routes())
            self.clock = 0.0

        def installation_request(self, method, path, *, token, **kwargs):
            response = super().installation_request(method, path, token=token, **kwargs)
            if "/git/trees/" in path:
                self.clock = 2.0
            return response

    for attempt in range(1, 4):
        app = SlowTreeApp()
        result = run(
            GitHubRepositoryCollector(app, monotonic=lambda app=app: app.clock, deadline_seconds=1),
            checkpoint,
            sink=sink,
        )
        assert not any("/git/blobs/" in path for path in app.requests)
        assert result["retry_after_seconds"] == 0
        assert result["resume_pending"] is (attempt < 3)
        assert len(sink.batches) == (0 if attempt < 3 else 1)
    assert result["repositories"][0]["detail"] == "github_collection_retry_limit_reached"


@pytest.mark.parametrize("damage", ["sha", "mode", "duplicate"])
def test_tree_walk_rejects_mismatched_identity_modes_and_duplicate_paths(damage):
    class InvalidTreeApp(WalkingApp):
        def installation_request(self, method, path, *, token, **kwargs):
            response = super().installation_request(method, path, token=token, **kwargs)
            if path.endswith(self.CHILD):
                if damage == "sha":
                    response.payload["sha"] = "f" * 40
                elif damage == "mode":
                    response.payload["tree"][0]["mode"] = "040000"
                else:
                    response.payload["tree"].append(deepcopy(response.payload["tree"][0]))
            return response

    app = InvalidTreeApp()
    result = run(GitHubRepositoryCollector(app), {})
    assert result["failed_count"] == 1
    assert not any("/git/blobs/" in path for path in app.requests)


@pytest.mark.parametrize("poison", ["token", "source", "result"])
def test_checkpoint_rejects_non_allowlisted_material_before_any_provider_call(poison):
    checkpoint = {}
    run(GitHubRepositoryCollector(AppClient(routes()), max_requests=5), checkpoint)
    if poison == "token":
        checkpoint["token"] = "ghs_never-store"
    elif poison == "source":
        checkpoint["repositories"]["42"]["files"] = {"source.py": "private source"}
    else:
        checkpoint["repositories"]["42"]["result"] = {
            "repository_id": 42,
            "repository": "acme/agent",
            "state": "failed",
            "detail": "ghs_never_store",
        }
    app = AppClient(routes())
    with pytest.raises(GitHubSourceError):
        run(GitHubRepositoryCollector(app), checkpoint)
    assert app.requests == app.tokens == []


@pytest.mark.parametrize(
    "damage",
    ["bare_complete", "missing_revision", "missing_coverage", "partial_coverage", "missing_branch"],
)
def test_checkpoint_cannot_skip_repository_without_complete_bound_analysis_proof(damage):
    checkpoint = {}
    run(GitHubRepositoryCollector(AppClient(routes())), checkpoint)
    progress = checkpoint["repositories"]["42"]
    completed = progress["result"]
    if damage == "bare_complete":
        progress["result"] = {
            key: completed[key] for key in ("repository_id", "repository", "state")
        }
    elif damage == "missing_revision":
        del completed["revision"]
    elif damage == "missing_coverage":
        del completed["coverage"]["posture"]
    elif damage == "partial_coverage":
        completed["coverage"]["source"] = "partial"
    else:
        del progress["default_branch"]
        progress["revision"] = completed["revision"] = "empty"
    app = AppClient(routes())
    with pytest.raises(GitHubSourceError, match="invalid_collection_checkpoint"):
        run(GitHubRepositoryCollector(app), checkpoint)
    assert app.requests == app.tokens == []
