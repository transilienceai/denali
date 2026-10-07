"""Fresh-process logging proof only; no network, identity, provider or database calls."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest

ROOT = Path(__file__).resolve().parents[1]
PRIVATE = "SIMULATED_PRIVATE_TOKEN_SOURCE_EMAIL_URL_EXCEPTION"


def fresh_process(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", dedent(code)],
        cwd=ROOT,
        env={"PATH": os.defpath, "PYTHONPATH": str(ROOT / "src")},
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )


def events(result):
    assert PRIVATE not in result.stdout + result.stderr
    rows = [json.loads(line) for line in result.stderr.splitlines()]
    for row in rows:
        assert set(row) in (
            {"event", "phase", "category", "elapsed_ms"},
            {"event", "phase", "category", "elapsed_ms", "status"},
        )
        assert row["event"] == "resource_preview"
        assert type(row["elapsed_ms"]) is int and row["elapsed_ms"] >= 0
        if "status" in row:
            assert type(row["status"]) is int and 100 <= row["status"] <= 599
    return rows


@pytest.mark.parametrize("uvicorn_defaults", [False, True])
def test_fresh_default_process_delivers_fixed_json_only_to_stderr(uvicorn_defaults):
    result = fresh_process(
        f"""
        import logging
        import logging.config
        if {uvicorn_defaults!r}:
            from uvicorn.config import LOGGING_CONFIG
            logging.config.dictConfig(LOGGING_CONFIG)
        root = logging.getLogger()
        before = (root.level, tuple(root.handlers), root.disabled, tuple(root.filters))
        from denali.resource_writes import observability as observation
        result = observation.observe_preview(
            lambda: observation.observe_dependency("membership", lambda: True)
        )
        assert result is True
        assert before == (root.level, tuple(root.handlers), root.disabled, tuple(root.filters))
        assert observation._logger.propagate is False
        print("ok")
        """
    )
    assert result.stdout == "ok\n"
    rows = events(result)
    assert [(row["phase"], row["category"]) for row in rows] == [
        ("membership", "returned"),
        ("preview", "returned"),
    ]
    assert rows[-1]["status"] == 200


def test_fresh_process_never_formats_result_arguments_or_exception_material():
    result = fresh_process(
        f"""
        import httpx
        from denali.resource_writes import observability as observation
        private = {PRIVATE!r}
        value = {{"source": private, "claims": {{"token": private}}}}
        result = observation.observe_preview(
            lambda: observation.observe_dependency("lease_post", lambda **kw: value,
                                                    token=private, source=private)
        )
        assert result is value
        error = httpx.ReadTimeout(private, request=httpx.Request(
            "GET", "https://invalid.example/" + private,
            headers={{"Authorization": "Bearer " + private}},
        ))
        def failure():
            raise error
        try:
            observation.observe_preview(
                lambda: observation.observe_dependency("github_read", failure)
            )
        except httpx.ReadTimeout as caught:
            assert caught is error
        else:
            raise AssertionError("exception changed")
        assert observation._preview_active.get() is False
        print("ok")
        """
    )
    assert result.stdout == "ok\n"
    assert [(row["phase"], row["category"]) for row in events(result)] == [
        ("lease_post", "returned"),
        ("preview", "returned"),
        ("github_read", "timeout"),
        ("preview", "other"),
    ]


@pytest.mark.parametrize("failed_operation", ["write", "flush"])
def test_sink_failure_cannot_emit_fallback_traceback_or_change_outcome(failed_operation):
    result = fresh_process(
        f"""
        import json
        import logging
        import sys
        private = {PRIVATE!r}
        class FailedSink:
            def __init__(self):
                self.writes = []
                self.flushes = 0
            def write(self, message):
                self.writes.append(message)
                if {failed_operation!r} == "write":
                    raise OSError(private)
            def flush(self):
                self.flushes += 1
                if {failed_operation!r} == "flush":
                    raise OSError(private)
        original = sys.stderr
        sink = FailedSink()
        sys.stderr = sink
        logging.raiseExceptions = True
        from denali.resource_writes import observability as observation
        value = {{"source": private}}
        assert observation.observe_preview(lambda: value) is value
        error = RuntimeError(private)
        def failure():
            raise error
        try:
            observation.observe_preview(failure)
        except RuntimeError as caught:
            assert caught is error
        else:
            raise AssertionError("exception changed")
        assert observation._preview_active.get() is False
        assert len(sink.writes) == 2
        assert all(private not in message for message in sink.writes)
        assert all(json.loads(message)["event"] == "resource_preview"
                   for message in sink.writes)
        assert sink.flushes == (0 if {failed_operation!r} == "write" else 2)
        sys.stderr = original
        print("ok")
        """
    )
    assert result.stdout == "ok\n" and result.stderr == ""


@pytest.mark.parametrize("failure_type", ["RuntimeError", "ValueError", "OSError"])
def test_real_process_shutdown_flush_failure_never_prints_private_atexit_error(failure_type):
    result = fresh_process(
        f"""
        import json
        import logging
        import sys
        private = {PRIVATE!r}
        class ShutdownFailureSink:
            def __init__(self):
                self.writes = []
            def write(self, message):
                self.writes.append(message)
            def flush(self):
                raise {failure_type}(private)
        original = sys.stderr
        sink = ShutdownFailureSink()
        sys.stderr = sink
        logging.raiseExceptions = True
        from denali.resource_writes import observability as observation
        value = {{"source": private}}
        assert observation.observe_preview(lambda: value) is value
        assert observation._preview_active.get() is False
        assert len(sink.writes) == 1
        assert private not in sink.writes[0]
        assert json.loads(sink.writes[0])["event"] == "resource_preview"
        # Automatic logging.shutdown will still flush the handler's failed stream.
        # Restore the real stderr so an atexit fallback traceback would be captured.
        sys.stderr = original
        print("ok")
        """
    )
    assert result.stdout == "ok\n" and result.stderr == ""


def test_repeated_import_and_reload_install_exactly_one_owned_sink():
    result = fresh_process(
        """
        import importlib
        import logging
        import sys
        from denali.resource_writes import observability as observation
        sink = next(h for h in observation._logger.handlers
                    if h.get_name() == "denali.resource_preview.stderr")
        for _ in range(4):
            observation = importlib.import_module("denali.resource_writes.observability")
            observation = importlib.reload(observation)
        owned = [h for h in observation._logger.handlers
                 if h.get_name() == "denali.resource_preview.stderr"]
        assert owned == [sink]
        assert isinstance(sink, logging.StreamHandler)
        assert sink.stream is sys.stderr and sink.level == logging.INFO
        assert sink.formatter._fmt == "%(message)s"
        assert observation.observe_preview(
            lambda: observation.observe_dependency("membership", lambda: True)
        ) is True
        print("ok")
        """
    )
    assert result.stdout == "ok\n" and len(events(result)) == 2


def test_existing_root_and_unrelated_logger_handlers_and_levels_are_unchanged():
    result = fresh_process(
        """
        import io
        import logging
        root = logging.getLogger()
        unrelated = logging.getLogger("denali.regular_route")
        capture = io.StringIO()
        handler = logging.StreamHandler(capture)
        formatter = logging.Formatter("regular:%(message)s")
        handler.setFormatter(formatter)
        root.addHandler(handler)
        root.setLevel(logging.WARNING)
        unrelated.setLevel(logging.WARNING)
        unrelated.propagate = True
        def snapshot(logger):
            return (logger.level, tuple(logger.handlers), tuple(logger.filters),
                    logger.propagate, logger.disabled)
        before = (snapshot(root), snapshot(unrelated))
        from denali.resource_writes import observability as observation
        assert (snapshot(root), snapshot(unrelated)) == before
        assert handler.formatter is formatter
        assert observation.observe_preview(lambda: True) is True
        assert capture.getvalue() == ""
        unrelated.warning("unchanged regular event")
        assert capture.getvalue() == "regular:unchanged regular event\\n"
        assert (snapshot(root), snapshot(unrelated)) == before
        print("ok")
        """
    )
    assert result.stdout == "ok\n" and len(events(result)) == 1


@pytest.mark.parametrize("uvicorn_defaults", [False, True])
def test_import_and_non_preview_dependencies_emit_nothing(uvicorn_defaults):
    result = fresh_process(
        f"""
        import logging.config
        if {uvicorn_defaults!r}:
            from uvicorn.config import LOGGING_CONFIG
            logging.config.dictConfig(LOGGING_CONFIG)
        from denali.resource_writes import observability as observation
        for phase in ("membership", "lease_mint", "lease_post", "github_read"):
            assert observation.observe_dependency(phase, lambda: True) is True
        assert observation._preview_active.get() is False
        print("ok")
        """
    )
    assert result.stdout == "ok\n" and result.stderr == ""
