"""Acquisition breadth follows bounded parser inputs, not unrelated repository data."""

from __future__ import annotations

import base64
import json
from copy import deepcopy

import pytest
from test_github_repository_connector import (
    BLOB,
    COMMIT,
    HANDLER,
    SOURCE,
    AppClient,
    Response,
    Sink,
    routes,
)
from test_github_resumable_collector import run, target

from denali.connectors.github_repository import (
    MAX_BLOB_BYTES,
    MAX_JSON_INSPECTION_BYTES,
    MAX_TOTAL_BYTES,
    GitHubRepositoryCollector,
    GitHubSourceError,
    _json_analysis_relevance,
    github_collection_boundary_hash,
)


def with_blobs(blobs):
    values = routes()
    tree = values[f"/repos/acme/agent/git/trees/{COMMIT}"]["tree"]
    for index, (path, content) in enumerate(blobs, start=100):
        sha = f"{index:040x}"
        tree.append(
            {"path": path, "type": "blob", "mode": "100644", "sha": sha, "size": len(content)}
        )
        values[f"/repos/acme/agent/git/blobs/{sha}"] = {
            "sha": sha,
            "encoding": "base64",
            "content": base64.b64encode(content).decode(),
        }
    return values


class MonorepoApp(AppClient):
    SUBTREE = "d" * 40

    def __init__(self, *, split=False):
        super().__init__(routes())
        self.split = split
        self.tree_calls = []

    def installation_request(self, method, path, *, token, **kwargs):
        if "/git/trees/" not in path:
            return super().installation_request(method, path, token=token, **kwargs)
        self.requests.append(path)
        recursive = "params" in kwargs
        self.tree_calls.append((path, recursive))
        if path.endswith(COMMIT):
            if recursive:
                return Response({"truncated": True, "tree": []})
            return Response(
                {
                    "sha": "e" * 40,
                    "truncated": False,
                    "tree": [
                        {"path": "src", "type": "tree", "mode": "040000", "sha": self.SUBTREE},
                        {"path": "node_modules", "type": "tree", "mode": "040000", "sha": "f" * 40},
                    ],
                }
            )
        if self.split and path.endswith(self.SUBTREE):
            if recursive:
                # An incomplete page is not used or merged with the later page.
                return Response(
                    {
                        "sha": self.SUBTREE,
                        "truncated": True,
                        "tree": [{"path": "unverified.py", "type": "blob", "mode": "100644"}],
                    }
                )
            return Response(
                {
                    "sha": self.SUBTREE,
                    "truncated": False,
                    "tree": [{"path": "lib", "type": "tree", "mode": "040000", "sha": "1" * 40}],
                }
            )
        assert recursive
        assert path.endswith("1" * 40 if self.split else self.SUBTREE)
        entries = []
        for number in range(300):
            entries.extend(
                [
                    {
                        "path": f"package-{number}",
                        "type": "tree",
                        "mode": "040000",
                        "sha": "2" * 40,
                    },
                    {
                        "path": f"package-{number}/app.py",
                        "type": "blob",
                        "mode": "100644",
                        "sha": BLOB,
                        "size": 0,
                    },
                ]
            )
        return Response(
            {"sha": "1" * 40 if self.split else self.SUBTREE, "truncated": False, "tree": entries}
        )


@pytest.mark.parametrize("split", [False, True])
def test_monorepo_batches_hundreds_of_nested_folders_inside_tree_request_bound(split):
    app = MonorepoApp(split=split)
    app.routes[f"/repos/acme/agent/git/blobs/{BLOB}"] = {
        "sha": BLOB,
        "encoding": "base64",
        "content": "",
    }
    checkpoint = {}
    result = run(GitHubRepositoryCollector(app), checkpoint)
    assert result["state"] == "complete"
    assert result["repositories"][0]["files"] == 300
    assert len(app.tree_calls) == (5 if split else 3)
    assert not any(path.endswith("f" * 40) for path in app.requests)
    assert "unverified.py" not in repr(checkpoint)
    assert all(
        path.endswith(COMMIT) or path.endswith(app.SUBTREE) or path.endswith("1" * 40)
        for path, _recursive in app.tree_calls
    )


def test_initial_truncated_page_still_has_a_raw_entry_safety_bound(monkeypatch):
    monkeypatch.setattr("denali.connectors.github_repository.MAX_TREE_INSPECTED_ENTRIES", 2)
    values = routes()
    values[f"/repos/acme/agent/git/trees/{COMMIT}"] = {
        "truncated": True,
        "tree": [{}, {}, {}],
    }
    app = AppClient(values)
    result = run(GitHubRepositoryCollector(app), {})
    assert result["repositories"][0]["detail"] == "repository_tree_inspection_limit_exceeded"
    assert not any("/git/blobs/" in path for path in app.requests)


def test_data_only_json_can_be_inspected_above_materialization_cap_and_is_not_persisted():
    private_data = json.dumps(
        {"records": ["synthetic-private-record"], "padding": "x" * MAX_BLOB_BYTES}
    ).encode()
    checkpoint, sink = {}, Sink()
    app = AppClient(with_blobs([("data/question-bank.json", private_data)]))
    result = run(GitHubRepositoryCollector(app), checkpoint, sink=sink)
    assert result["state"] == "complete"
    assert result["repositories"][0]["files"] == 2
    assert result["repositories"][0]["ignored_inputs"] == {"non_analysis_json": 1}
    assert "synthetic-private-record" not in repr(checkpoint)
    assert "synthetic-private-record" not in repr(sink.batches)
    assert run(GitHubRepositoryCollector(AppClient({})), checkpoint)["state"] == "complete"


def test_non_analysis_json_does_not_use_the_25mb_relevant_input_budget():
    data = json.dumps({"records": ["x" * 1_800_000]}).encode()
    app = AppClient(with_blobs([(f"data/records-{number}.json", data) for number in range(15)]))
    result = run(GitHubRepositoryCollector(app), {})
    assert len(data) * 15 > MAX_TOTAL_BYTES
    assert result["state"] == "complete"
    assert result["repositories"][0]["ignored_inputs"] == {"non_analysis_json": 15}
    assert result["repositories"][0]["files"] == 2


@pytest.mark.parametrize(
    "content",
    [
        {"Resources": {}},
        {"resources": []},
        {"id": "/subscriptions/example"},
        {"nested": {"mcpServers": {}}},
        {"nested": {"model_id": "example"}},
        [{"provider": "example"}],
        {"providers": {}},
    ],
)
def test_arbitrary_json_paths_keep_iac_mcp_and_provider_configuration(content):
    assert _json_analysis_relevance(json.dumps(content).encode()) is True


@pytest.mark.parametrize(
    "path", ["docs/site/artifacts/runtime.json", "examples/runtime.json", "configuration.json"]
)
def test_relevant_large_json_is_not_projected_or_relabelled_complete(path):
    content = json.dumps({"Resources": {}, "padding": "x" * MAX_BLOB_BYTES}).encode()
    result = run(GitHubRepositoryCollector(AppClient(with_blobs([(path, content)]))), {})
    assert result["state"] == "partial"
    assert result["repositories"][0]["files"] == 2
    assert "ignored_inputs" not in result["repositories"][0]


@pytest.mark.parametrize("content", [b'{"data":1,"data":2}', b'{"data":NaN}', b"{broken", b"\xff"])
def test_malformed_ambiguous_or_non_utf8_json_remains_unknown_and_partial(content):
    assert _json_analysis_relevance(content) is None
    result = run(GitHubRepositoryCollector(AppClient(with_blobs([("data.json", content)]))), {})
    assert result["state"] == "partial"
    assert result["repositories"][0]["files"] == 2
    assert "ignored_inputs" not in result["repositories"][0]


@pytest.mark.parametrize(
    "content", [[{"id": "CVE-example", "severity": "high"}], {"records": [1, 2]}, [1, 2], "data"]
)
def test_json_data_without_supported_configuration_is_not_an_analysis_input(content):
    assert _json_analysis_relevance(json.dumps(content).encode()) is False


@pytest.mark.parametrize("shape", ["dense", "deep"])
def test_json_allocation_is_bounded_before_decoder_runs(monkeypatch, shape):
    content = (
        b"[" + b"0," * (MAX_JSON_INSPECTION_BYTES // 2 - 2) + b"0]"
        if shape == "dense"
        else b"[" * 65 + b"0" + b"]" * 65
    )
    assert len(content) <= MAX_JSON_INSPECTION_BYTES

    def forbidden_decode(*_args, **_kwargs):
        pytest.fail("Unbounded JSON structure reached the allocating decoder")

    monkeypatch.setattr("denali.connectors.github_repository.json.loads", forbidden_decode)
    assert _json_analysis_relevance(content) is None


def test_json_structure_preflight_does_not_count_escaped_data_string_contents_as_nodes():
    content = json.dumps({"data": '[]{},:\\"' * 100_000}).encode()
    assert _json_analysis_relevance(content) is False


@pytest.mark.parametrize("path", ["data.json", "package.json", "mcp.json", "deploy.assets.json"])
def test_unsafe_json_never_reaches_an_unbounded_downstream_decoder(path):
    # Below the 2MB materialization cap, but far above the permitted AST shape.
    content = b"[" + b"0," * 100_000 + b"0]"
    result = run(GitHubRepositoryCollector(AppClient(with_blobs([(path, content)]))), {})
    assert result["state"] == "partial"
    assert result["repositories"][0]["files"] == 2
    assert "ignored_inputs" not in result["repositories"][0]


@pytest.mark.parametrize(
    "path", ["package.json", "mcp.json", "claude_desktop_config.json", "deploy.assets.json"]
)
def test_named_consumers_are_not_filtered_even_when_their_shape_is_unrecognized(path):
    result = run(GitHubRepositoryCollector(AppClient(with_blobs([(path, b"{}")]))), {})
    assert result["repositories"][0]["files"] == 3
    assert "ignored_inputs" not in result["repositories"][0]


def test_json_above_inspection_bound_stays_partial_without_downloading():
    values = with_blobs([("large.json", b"{}")])
    values[f"/repos/acme/agent/git/trees/{COMMIT}"]["tree"][-1]["size"] = (
        MAX_JSON_INSPECTION_BYTES + 1
    )
    app = AppClient(values)
    result = run(GitHubRepositoryCollector(app), {})
    assert result["state"] == "partial"
    assert not any(path.endswith(f"{100:040x}") for path in app.requests)


def test_json_inspection_has_separate_bounded_total_and_never_exceeds_analysis_bytes(monkeypatch):
    monkeypatch.setattr("denali.connectors.github_repository.MAX_JSON_INSPECTION_TOTAL_BYTES", 10)
    app = AppClient(with_blobs([("data.json", b'{"records": [1,2,3]}')]))
    result = run(GitHubRepositoryCollector(app), {})
    assert result["state"] == "partial"
    assert result["repositories"][0]["bytes"] < MAX_TOTAL_BYTES
    assert not any(path.endswith(f"{100:040x}") for path in app.requests)


def test_actual_relevant_source_still_has_honest_file_and_byte_limits(monkeypatch):
    monkeypatch.setattr(
        "denali.connectors.github_repository.MAX_TOTAL_BYTES", len(SOURCE) + len(HANDLER) - 1
    )
    result = run(GitHubRepositoryCollector(AppClient(routes())), {})
    assert result["state"] == "partial"
    assert result["repositories"][0]["files"] == 1
    assert result["repositories"][0]["coverage"]["source"] == "partial"


def test_large_blob_inspection_never_bypasses_live_repository_identity():
    values = with_blobs([("data.json", json.dumps({"records": "x" * MAX_BLOB_BYTES}).encode())])
    values["/repos/acme/agent"]["owner"]["id"] = 8
    app = AppClient(values)
    result = run(GitHubRepositoryCollector(app), {})
    assert result["repositories"][0]["detail"] == "repository_identity_mismatch"
    assert app.tokens == [(9, 42)]
    assert not any("/git/" in path for path in app.requests)


def test_retry_retains_90_complete_results_and_only_reads_the_other_23_repositories():
    previous = {}
    run(GitHubRepositoryCollector(AppClient(routes())), previous)
    proof = previous["repositories"]["42"]
    selected = target()
    selected["configuration"]["repositories"] = []
    provider_routes = {}
    retained = {}
    for number in range(113):
        identity = {
            "id": 1000 + number,
            "node_id": f"R_{number}",
            "full_name": f"acme/repository-{number}",
            "owner_id": 7,
            "owner_login": "acme",
        }
        selected["configuration"]["repositories"].append(identity)
        if number < 90:
            retained[str(identity["id"])] = {
                **deepcopy(proof),
                "result": {
                    **proof["result"],
                    "repository_id": identity["id"],
                    "repository": identity["full_name"],
                },
            }
        else:
            provider_routes[f"/repos/{identity['full_name']}"] = {
                "id": identity["id"],
                "node_id": identity["node_id"],
                "full_name": identity["full_name"],
                "owner": {"id": 7, "login": "acme"},
                "default_branch": None,
            }
    checkpoint = {
        "boundary_hash": github_collection_boundary_hash("tenant", selected),
        "repository_count": 113,
        "retained_repository_ids": list(range(1000, 1090)),
        "repositories": retained,
    }
    accessed = []
    for slice_number in range(1, 6):
        app = AppClient(provider_routes)
        result = run(GitHubRepositoryCollector(app), checkpoint, selected=selected)
        accessed.extend(repository_id for _installation, repository_id in app.tokens)
        assert len(app.tokens) <= 5
        assert result["retained_repository_count"] == 90
        assert result["retry_repository_count"] == 23
        assert result["refreshed_repository_count"] == min(5 * slice_number, 23)
        assert result["completed_repository_count"] == 90 + min(5 * slice_number, 23)
        assert result["repository_count"] == 113
    assert accessed == list(range(1090, 1113))
    assert result["resume_pending"] is False
    assert result["state"] == "complete"


def test_retained_complete_repositories_are_skipped_and_counted_separately():
    checkpoint = {}
    run(GitHubRepositoryCollector(AppClient(routes())), checkpoint)
    checkpoint["retained_repository_ids"] = [42]
    app = AppClient({})
    result = run(GitHubRepositoryCollector(app), checkpoint)
    assert result["retained_repository_count"] == 1
    assert result["retry_repository_count"] == result["refreshed_repository_count"] == 0
    assert result["completed_repository_count"] == result["repository_count"] == 1
    assert app.requests == app.tokens == []


@pytest.mark.parametrize("damage", ["duplicate", "unknown", "boolean", "missing", "partial"])
def test_retained_repository_metadata_cannot_admit_unproven_or_unselected_results(damage):
    checkpoint = {}
    run(GitHubRepositoryCollector(AppClient(routes())), checkpoint)
    checkpoint["retained_repository_ids"] = [42]
    if damage == "duplicate":
        checkpoint["retained_repository_ids"] = [42, 42]
    elif damage == "unknown":
        checkpoint["retained_repository_ids"] = [999]
    elif damage == "boolean":
        checkpoint["retained_repository_ids"] = [True]
    elif damage == "missing":
        del checkpoint["repositories"]["42"]["result"]
    else:
        result = checkpoint["repositories"]["42"]["result"]
        result["state"] = result["coverage"]["source"] = "partial"
    app = AppClient({})
    with pytest.raises(GitHubSourceError):
        run(GitHubRepositoryCollector(app), deepcopy(checkpoint))
    assert app.requests == app.tokens == []
