"""A local acquisition cap yields honest analysis, not identical download retries."""

from __future__ import annotations

import base64
from threading import Event, Lock

import pytest
from test_github_repository_connector import COMMIT, AppClient, Response, Sink, routes
from test_github_resumable_collector import run

from denali.connectors.github_repository import (
    MAX_SELECTED_FILES,
    GitHubRepositoryCollector,
    GitHubSourceError,
    _GitHubRequestBudget,
    _GitHubRequestBudgetReached,
)
from denali.domain import CoverageState


def provider_routes(*, source_count=20, json_count=0):
    values = routes()
    tree = []
    for number in range(source_count + json_count):
        source = number < source_count
        path = f"app/file_{number:05d}.py" if source else f"data/records_{number:05d}.json"
        content = b"" if source else b'{"records":[1,2,3]}'
        sha = f"{number + 100:040x}"
        tree.append(
            {"path": path, "type": "blob", "mode": "100644", "sha": sha, "size": len(content)}
        )
        values[f"/repos/acme/agent/git/blobs/{sha}"] = {
            "sha": sha,
            "encoding": "base64",
            "content": base64.b64encode(content).decode(),
        }
    values[f"/repos/acme/agent/git/trees/{COMMIT}"] = {"truncated": False, "tree": tree}
    return values


def assert_all_six_planes_partial(sink):
    assert len(sink.batches) == 4
    assert sum(len(batch.coverage) for batch in sink.batches) == 6
    assert {coverage.state for batch in sink.batches for coverage in batch.coverage} == {
        CoverageState.PARTIAL
    }


def test_full_file_capacity_stops_json_inspection_before_default_request_cap():
    values = provider_routes(source_count=MAX_SELECTED_FILES + 2, json_count=2846)
    app, sink, checkpoint = AppClient(values), Sink(), {}
    result = run(GitHubRepositoryCollector(app), checkpoint, sink=sink)
    assert result["resume_pending"] is False
    assert result["state"] == "partial"
    assert result["completed_repository_count"] == 1
    assert result["repositories"][0]["files"] == MAX_SELECTED_FILES
    assert result["repositories"][0]["revision"] == COMMIT
    assert result["github_requests"] <= MAX_SELECTED_FILES + 10
    assert result["request_budget_reached"] is False
    assert len([path for path in app.requests if "/git/blobs/" in path]) == MAX_SELECTED_FILES
    json_shas = {
        item["sha"]
        for item in values[f"/repos/acme/agent/git/trees/{COMMIT}"]["tree"]
        if item["path"].endswith(".json")
    }
    assert not any(path.rsplit("/", 1)[-1] in json_shas for path in app.requests)
    assert "interruption_count" not in checkpoint["repositories"]["42"]
    detail = sink.batches[0].coverage[0].detail
    assert "analysis file limit reached" in detail
    assert "remaining candidates were not inspected" in detail
    assert "github_collection_retry_limit_reached" not in detail
    assert_all_six_planes_partial(sink)
    # Already processed means no further provider read or re-ingestion on replay.
    replay = AppClient({})
    assert run(GitHubRepositoryCollector(replay), checkpoint)["state"] == "partial"
    assert replay.requests == replay.tokens == []


def test_file_capacity_reached_mid_batch_allows_only_bounded_speculative_json_reads(monkeypatch):
    monkeypatch.setattr("denali.connectors.github_repository.MAX_SELECTED_FILES", 3)
    app, sink = AppClient(provider_routes(source_count=3, json_count=30)), Sink()
    result = run(GitHubRepositoryCollector(app), {}, sink=sink)
    assert result["state"] == "partial"
    assert result["repositories"][0]["files"] == 3
    assert len([path for path in app.requests if "/git/blobs/" in path]) <= 3 + 7
    assert "remaining candidates were not inspected" in sink.batches[0].coverage[0].detail
    assert_all_six_planes_partial(sink)


@pytest.mark.parametrize("max_requests,verified_files", [(6, 1), (13, 8)])
def test_local_request_cap_keeps_verified_files_even_when_next_batch_is_all_stops(
    max_requests, verified_files
):
    app, sink, checkpoint = AppClient(provider_routes()), Sink(), {}
    result = run(GitHubRepositoryCollector(app, max_requests=max_requests), checkpoint, sink=sink)
    assert result["resume_pending"] is False
    assert result["state"] == "partial"
    assert result["request_budget_reached"] is True
    assert result["github_requests"] == max_requests
    assert result["repositories"][0]["files"] == verified_files
    assert result["repositories"][0]["revision"] == COMMIT
    assert "interruption_count" not in checkpoint["repositories"]["42"]
    assert "github_request_budget_reached" in sink.batches[0].coverage[0].detail
    assert "remaining candidates were not inspected" in sink.batches[0].coverage[0].detail
    assert_all_six_planes_partial(sink)


def test_local_cap_after_verified_non_analysis_json_also_avoids_identical_restarts():
    sink, checkpoint = Sink(), {}
    result = run(
        GitHubRepositoryCollector(
            AppClient(provider_routes(source_count=0, json_count=20)), max_requests=6
        ),
        checkpoint,
        sink=sink,
    )
    assert result["resume_pending"] is False
    assert result["repositories"][0]["files"] == 0
    assert result["repositories"][0]["ignored_inputs"] == {"non_analysis_json": 1}
    assert "interruption_count" not in checkpoint["repositories"]["42"]
    assert_all_six_planes_partial(sink)


def test_prior_two_interruptions_can_recover_into_analyzed_partial_without_third_restart():
    checkpoint = {}
    run(GitHubRepositoryCollector(AppClient(provider_routes()), max_requests=5), checkpoint)
    checkpoint["repositories"]["42"]["interruption_count"] = 2
    sink = Sink()
    result = run(
        GitHubRepositoryCollector(AppClient(provider_routes()), max_requests=6),
        checkpoint,
        sink=sink,
    )
    assert result["resume_pending"] is False
    assert result["repositories"][0]["files"] == 2  # Resumed immutable pin skips branch resolution.
    assert result["repositories"][0]["revision"] == COMMIT
    assert checkpoint["repositories"]["42"]["interruption_count"] == 2
    assert "github_collection_retry_limit_reached" not in repr(result)
    assert_all_six_planes_partial(sink)


@pytest.mark.parametrize("limit", ["file", "request"])
def test_critical_budget_gap_survives_snapshot_and_downstream_detail_trimming(monkeypatch, limit):
    source_count = 24
    if limit == "file":
        monkeypatch.setattr("denali.connectors.github_repository.MAX_SELECTED_FILES", source_count)
    values = provider_routes(source_count=source_count, json_count=60)
    tree = values[f"/repos/acme/agent/git/trees/{COMMIT}"]["tree"]
    for entry in tree:
        if entry["path"].endswith(".py"):
            # Each parser's own >4KB warning detail must retain a bounded share
            # alongside the source gap, not hide it or be hidden by it.
            entry["path"] = "app/" + "p" * 180 + entry["path"].rsplit("/", 1)[-1]
            entry["size"] = len(b"def broken(\n")
            values[f"/repos/acme/agent/git/blobs/{entry['sha']}"]["content"] = base64.b64encode(
                b"def broken(\n"
            ).decode()
        else:
            entry["path"] = "data/" + "x" * 180 + entry["path"].rsplit("/", 1)[-1]
            entry["size"] = 1
            values[f"/repos/acme/agent/git/blobs/{entry['sha']}"]["content"] = base64.b64encode(
                b"{"
            ).decode()
    for index in range(30):
        # These warnings are produced before blob acquisition; none is fetched.
        tree.append(
            {
                "path": f"oversized/{index:02d}" + "y" * 180 + ".py",
                "sha": f"{10_000 + index:040x}",
                "type": "blob",
                "mode": "100644",
                "size": 2_000_001,
            }
        )
    sink = Sink()
    result = run(
        GitHubRepositoryCollector(AppClient(values), max_requests=4000 if limit == "file" else 70),
        {},
        sink=sink,
    )
    assert result["state"] == "partial"
    code = "analysis file limit reached" if limit == "file" else "github_request_budget_reached"
    assert_all_six_planes_partial(sink)
    for batch in sink.batches:
        for coverage in batch.coverage:
            assert code in coverage.detail
            assert len(coverage.detail) <= 4000
    assert "invalid Python syntax" in sink.batches[1].coverage[0].detail


@pytest.mark.parametrize("external_stop", ["quota", "deadline"])
def test_late_successful_blob_response_overrides_already_returned_local_stops(
    monkeypatch, external_stop
):
    local_stops, lock = Event(), Lock()
    stopped = 0
    original_acquire = _GitHubRequestBudget.acquire

    def acquire(budget):
        nonlocal stopped
        try:
            original_acquire(budget)
        except _GitHubRequestBudgetReached as error:
            if error.code == "github_request_budget_reached":
                with lock:
                    stopped += 1
                    if stopped == 7:
                        local_stops.set()
            raise

    monkeypatch.setattr(_GitHubRequestBudget, "acquire", acquire)

    class LateResponseClient(AppClient):
        clock = 0.0

        def installation_request(self, method, path, **kwargs):
            response = super().installation_request(method, path, **kwargs)
            if "/git/blobs/" in path:
                # The admitted sixth request waits until the other seven workers
                # returned local-cap errors, then observes the external stop.
                assert local_stops.wait(timeout=3)
                if external_stop == "quota":
                    response.headers = {"X-RateLimit-Remaining": "0"}
                else:
                    self.clock = 2.0
            return response

    app, sink, checkpoint = LateResponseClient(provider_routes()), Sink(), {}
    result = run(
        GitHubRepositoryCollector(
            app, max_requests=6, deadline_seconds=1, monotonic=lambda: app.clock
        ),
        checkpoint,
        sink=sink,
    )
    assert stopped == 7
    assert result["resume_pending"] is True
    assert result["retry_after_seconds"] == (3660 if external_stop == "quota" else 0)
    assert result["repositories"] == []
    assert sink.batches == []
    progress = checkpoint["repositories"]["42"]
    assert progress["revision"] == COMMIT
    assert progress.get("interruption_count", 0) == int(external_stop == "deadline")
    assert "result" not in progress


def test_exact_last_request_may_complete_when_no_input_is_blocked():
    values = provider_routes(source_count=1)
    path = f"/repos/acme/agent/git/blobs/{100:040x}"
    values[path] = Response(values[path], headers={"X-RateLimit-Remaining": "0"})
    sink, checkpoint = Sink(), {}
    result = run(
        GitHubRepositoryCollector(AppClient(values), max_requests=6), checkpoint, sink=sink
    )
    assert result["resume_pending"] is False
    assert result["state"] == "complete"
    assert result["repositories"][0]["files"] == 1
    assert "interruption_count" not in checkpoint["repositories"]["42"]
    assert len(sink.batches) == 4


@pytest.mark.parametrize(
    "codes,expected_delay,interrupted",
    [
        (["github_request_budget_reached", "github_collection_deadline_reached"], 0, True),
        (["github_collection_deadline_reached", "github_request_budget_reached"], 0, True),
        (["github_request_budget_reached", "github_rate_limited"], 3660, False),
        (["github_rate_limit_reserve_reached", "github_request_budget_reached"], 3660, False),
        (
            [
                "github_request_budget_reached",
                "github_collection_deadline_reached",
                "github_rate_limited",
            ],
            3660,
            False,
        ),
        (
            [
                "github_rate_limited",
                "github_collection_deadline_reached",
                "github_request_budget_reached",
            ],
            3660,
            False,
        ),
    ],
)
def test_quota_and_deadline_stops_dominate_local_cap_without_ingestion(
    monkeypatch, codes, expected_delay, interrupted
):
    collector, sink, checkpoint = (
        GitHubRepositoryCollector(AppClient(provider_routes())),
        Sink(),
        {},
    )
    original = collector._json
    forced = {f"{100 + index:040x}": code for index, code in enumerate(codes)}

    def request(method, path, **kwargs):
        if "/git/blobs/" in path and path.rsplit("/", 1)[-1] in forced:
            raise _GitHubRequestBudgetReached(forced[path.rsplit("/", 1)[-1]])
        return original(method, path, **kwargs)

    monkeypatch.setattr(collector, "_json", request)
    result = run(collector, checkpoint, sink=sink)
    assert result["resume_pending"] is True
    assert result["retry_after_seconds"] == expected_delay
    assert result["repositories"] == []
    assert sink.batches == []
    progress = checkpoint["repositories"]["42"]
    assert progress["revision"] == COMMIT
    assert progress.get("interruption_count", 0) == int(interrupted)
    assert "result" not in progress


@pytest.mark.parametrize("failure", ["invalid_blob", "permission", "upstream"])
def test_bad_identity_or_provider_failures_never_become_bounded_partial_success(failure):
    values = provider_routes()
    path = f"/repos/acme/agent/git/blobs/{100:040x}"
    if failure == "invalid_blob":
        values[path]["sha"] = "f" * 40
    else:
        values[path] = Response({}, status_code=403 if failure == "permission" else 503)
    sink, checkpoint = Sink(), {}
    if failure == "upstream":
        with pytest.raises(GitHubSourceError, match="github_upstream_unavailable"):
            run(GitHubRepositoryCollector(AppClient(values)), checkpoint, sink=sink)
        assert sink.batches == []
        assert "result" not in checkpoint["repositories"]["42"]
    else:
        result = run(GitHubRepositoryCollector(AppClient(values)), checkpoint, sink=sink)
        assert result["failed_count"] == 1
        assert result["partial_count"] == 0
        assert len(sink.batches) == 1
        assert sink.batches[0].coverage[0].state is CoverageState.FAILED
