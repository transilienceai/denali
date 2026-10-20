"""A GitHub job survives bounded slices, dispatch loss and worker replacement."""

from copy import deepcopy

import pytest

from denali.api.collection import (
    queue_due_github_collection_jobs,
    run_durable_collection_job,
)


class Repository:
    def __init__(self):
        self.job = {
            "tenant_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "connection_id": "11111111-1111-4111-8111-111111111111",
            "collection_kind": "github_source",
            "state": "queued",
            "attempt_count": 0,
            "retry_count": 0,
            "checkpoint": {},
            "result": None,
        }
        self.active = True
        self.delay = 0
        self.errors = []
        self.fenced = []

    def claim_connection_collection_job(self, _job_id, *, lease_seconds):
        assert lease_seconds >= 2700
        if self.job["state"] != "queued" or self.delay:
            return None
        self.job["state"] = "running"
        self.job["attempt_count"] += 1
        return deepcopy(self.job)

    def get_connection_validation_target(self, tenant_id, connection_id):
        assert tenant_id == self.job["tenant_id"]
        return {"id": connection_id, "provider": "github", "lifecycle_state": "active"}

    def collection_job_is_current(self, _job_id, generation):
        return (
            self.active
            and self.job["state"] == "running"
            and generation == self.job["attempt_count"]
        )

    def for_collection_claim(self, job_id, generation):
        self.fenced.append((job_id, generation))
        return self

    def save_collection_checkpoint(self, job_id, generation, checkpoint):
        if not self.collection_job_is_current(job_id, generation):
            return False
        self.job["checkpoint"] = deepcopy(checkpoint)
        return True

    def defer_connection_collection_job(
        self, job_id, generation, checkpoint, result, *, delay_seconds
    ):
        if not self.save_collection_checkpoint(job_id, generation, checkpoint):
            return False
        self.job.update(state="queued", result=deepcopy(result), retry_count=0)
        self.delay = delay_seconds
        return True

    def complete_resumable_collection_job(self, job_id, generation, result):
        if not self.collection_job_is_current(job_id, generation):
            return False
        self.job.update(state="succeeded", result=result)
        return True

    def retry_resumable_collection_job(
        self, job_id, generation, summary, *, max_attempts, delay_seconds
    ):
        if not self.collection_job_is_current(job_id, generation):
            return False
        self.errors.append(summary)
        self.job["retry_count"] += 1
        retry = self.job["retry_count"] < max_attempts
        self.job["state"] = "queued" if retry else "failed"
        self.delay = delay_seconds if retry else 0
        return retry

    def list_due_github_collection_jobs(self, *, limit):
        assert limit == 100
        return ["job"] if self.job["state"] == "queued" and not self.delay else []


class Collector:
    def __init__(self, *, delay=0, failure=None):
        self.calls = []
        self.delay = delay
        self.failure = failure

    def collect_resumable(self, *, tenant_id, connection, repository, checkpoint, save_checkpoint):
        self.calls.append(deepcopy(checkpoint))
        count = checkpoint.get("done", 0)
        if self.failure:
            raise self.failure
        assert save_checkpoint({"done": count + 1})
        return {
            "state": "running" if count < 2 else "complete",
            "repository_count": 3,
            "completed_repository_count": count + 1,
            "resume_pending": count < 2,
            "retry_after_seconds": self.delay,
        }


def test_repository_checkpoints_resume_after_api_and_worker_replacement():
    repository = Repository()
    hooks = []
    dispatches = []
    for _slice in range(3):
        # New objects/container each time; PostgreSQL is the only shared state.
        collector = Collector()
        run_durable_collection_job(
            repository,
            {"github_source": collector},
            "job",
            dispatch_continuation=dispatches.append,
            on_succeeded=lambda *args: hooks.append(args),
        )
        assert len(collector.calls) == 1
    assert repository.job["state"] == "succeeded"
    assert repository.job["checkpoint"] == {"done": 3}
    assert dispatches == ["job", "job"]
    assert len(hooks) == 1
    assert repository.fenced == [("job", 1), ("job", 2), ("job", 3)]
    run_durable_collection_job(repository, {"github_source": Collector()}, "job")
    assert len(hooks) == 1


def test_lost_spawn_does_not_destroy_checkpoint_and_reconciler_recovers():
    repository = Repository()

    def broken_dispatch(_job_id):
        raise TimeoutError("secret-provider-payload")

    run_durable_collection_job(
        repository,
        {"github_source": Collector()},
        "job",
        dispatch_continuation=broken_dispatch,
    )
    assert repository.job["state"] == "queued"
    assert repository.job["checkpoint"] == {"done": 1}
    assert repository.errors == []
    delivered = []
    assert queue_due_github_collection_jobs(repository, delivered.append) == {
        "eligible": 1, "queued": 1, "failed": 0,
    }
    assert delivered == ["job"]


def test_provider_cooldown_does_not_spawn_or_consume_retry_attempts():
    repository = Repository()
    dispatches = []
    run_durable_collection_job(
        repository,
        {"github_source": Collector(delay=3600)},
        "job",
        dispatch_continuation=dispatches.append,
    )
    assert repository.delay == 3600
    assert repository.job["retry_count"] == 0
    assert dispatches == []
    assert queue_due_github_collection_jobs(repository, dispatches.append)["eligible"] == 0


@pytest.mark.parametrize("failure", [TimeoutError("private"), RuntimeError("private")])
def test_slice_failures_retry_durably_and_stop_after_bounded_failures(failure):
    repository = Repository()
    collector = Collector(failure=failure)
    for _ in range(3):
        repository.delay = 0
        run_durable_collection_job(repository, {"github_source": collector}, "job")
    assert repository.job["state"] == "failed"
    assert len(repository.errors) == 3
    assert all("private" not in summary for summary in repository.errors)


def test_stale_worker_cannot_defer_or_complete_new_claim():
    repository = Repository()

    class Superseded:
        def collect_resumable(self, **kwargs):
            repository.job["attempt_count"] += 1
            assert kwargs["save_checkpoint"]({"done": 9}) is False
            raise RuntimeError("lost claim")

    run_durable_collection_job(repository, {"github_source": Superseded()}, "job")
    assert repository.job["state"] == "running"
    assert repository.job["checkpoint"] == {}
    assert repository.errors == []


def test_storage_outage_never_falls_back_to_unfenced_legacy_failure():
    class UnavailableRepository(Repository):
        def collection_job_is_current(self, *_args):
            raise OSError("private storage outage")

        def record_connection_collection_failure(self, *_args, **_kwargs):
            pytest.fail("resumable work must never use the legacy unfenced failure path")

    repository = UnavailableRepository()
    run_durable_collection_job(
        repository, {"github_source": Collector(failure=TimeoutError("private"))}, "job"
    )
    assert repository.job["state"] == "running"
    assert repository.errors == []


@pytest.mark.parametrize("superseded", [False, True])
def test_target_lookup_failure_uses_retry_counter_and_generation_fence(superseded):
    class TargetFailure(Repository):
        def get_connection_validation_target(self, *_args):
            if superseded:
                self.job["attempt_count"] += 1
            raise TimeoutError("private provider detail")

        def record_connection_collection_failure(self, *_args, **_kwargs):
            pytest.fail("GitHub target lookup must not use unfenced failure")

    repository = TargetFailure()
    repository.job["attempt_count"] = 50  # Many successful continuations are not failures.
    run_durable_collection_job(repository, {"github_source": Collector()}, "job")
    assert repository.job["state"] == ("running" if superseded else "queued")
    assert repository.job["retry_count"] == (0 if superseded else 1)


def test_local_compose_mode_preserves_bounded_collection_without_modal_scheduler():
    repository = Repository()

    class LocalCollector:
        def collect(self, **_kwargs):
            return {"state": "partial"}

        def collect_resumable(self, **_kwargs):
            pytest.fail("local mode has no hosted continuation scheduler")

    repository.complete_connection_collection_job = lambda _id, result: repository.job.update(
        state="succeeded", result=result
    )
    run_durable_collection_job(
        repository, {"github_source": LocalCollector()}, "job", resumable_github=False
    )
    assert repository.job["state"] == "succeeded"


def test_post_processing_failure_retries_without_recollecting_finished_repositories():
    repository = Repository()
    repository.job["checkpoint"] = {"done": 2}
    collector = Collector()

    def failed_post_processing(*_args):
        raise TimeoutError("private")

    run_durable_collection_job(
        repository,
        {"github_source": collector},
        "job",
        on_succeeded=failed_post_processing,
    )
    assert repository.job["state"] == "queued"
    assert repository.job["checkpoint"] == {"done": 3}
    repository.delay = 0
    run_durable_collection_job(repository, {"github_source": collector}, "job")
    assert collector.calls[-1] == {"done": 3}
    assert repository.job["state"] == "succeeded"
