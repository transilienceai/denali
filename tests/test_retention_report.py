"""Read-only operator report contracts; no database is needed for these tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import psycopg
import pytest

from denali.store import retention


class Result:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class Connection:
    def __init__(self):
        self.statements = []
        self.rolled_back = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, query, params=None):
        self.statements.append((query, params))
        if query.startswith("SELECT now()"):
            now = datetime(2026, 10, 30, tzinfo=UTC)
            return Result(
                {
                    "snapshot_at": now,
                    "cutoff": now - timedelta(days=params[0]),
                    "read_only": "on",
                    "isolation": "repeatable read",
                }
            )
        if query == retention._SUMMARY_QUERY:
            keys = (
                "jobs_total jobs_old jobs_candidates jobs_active jobs_expired_running "
                "jobs_latest_terminal_protected jobs_cursor_protected jobs_audit_protected "
                "runs_total runs_old runs_candidates runs_latest_coverage_protected "
                "runs_evidence_protected runs_job_protected coverage_total coverage_old "
                "coverage_candidates"
            )
            return Result(dict.fromkeys(keys.split(), 0))
        return Result(None)

    def rollback(self):
        self.rolled_back = True


def test_report_sets_read_only_snapshot_before_any_reads_and_rolls_back(monkeypatch):
    connection = Connection()
    calls = []

    def connect(*args, **kwargs):
        calls.append((args, kwargs))
        return connection

    monkeypatch.setattr(retention.psycopg, "connect", connect)
    tenant = str(uuid4())
    report = retention.retention_report("synthetic-dsn", tenant_id=tenant, keep_days=90)
    assert calls[0][1]["connect_timeout"] == 10
    assert connection.statements[:3] == [
        ("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY", None),
        ("SET LOCAL statement_timeout = '20s'", None),
        ("SET LOCAL lock_timeout = '2s'", None),
    ]
    assert connection.statements[-1] == (
        retention._SUMMARY_QUERY,
        {"tenant_id": tenant, "keep_days": 90},
    )
    assert connection.rolled_back
    assert report["deletion_supported"] is False
    assert report["retention_policy_approved"] is False
    assert report["reclaimable_bytes"] is None
    assert report["transaction_read_only"] is True
    assert report["mode"] == "read_only_review"
    assert "synthetic-dsn" not in json.dumps(report)


@pytest.mark.parametrize("keep_days", [0, -1, 3651, True, 30.0])
def test_bad_policy_input_never_opens_a_connection(monkeypatch, keep_days):
    monkeypatch.setattr(retention.psycopg, "connect", lambda *_a, **_k: pytest.fail("connected"))
    with pytest.raises(ValueError):
        retention.retention_report("synthetic-dsn", tenant_id=str(uuid4()), keep_days=keep_days)


def test_invalid_tenant_never_opens_a_connection(monkeypatch):
    monkeypatch.setattr(retention.psycopg, "connect", lambda *_a, **_k: pytest.fail("connected"))
    with pytest.raises(ValueError):
        retention.retention_report("synthetic-dsn", tenant_id="not-a-uuid", keep_days=30)


def test_no_apply_flag_is_accepted(monkeypatch, capsys):
    monkeypatch.setattr(retention.psycopg, "connect", lambda *_a, **_k: pytest.fail("connected"))
    with pytest.raises(SystemExit) as error:
        retention.main(["--tenant-id", str(uuid4()), "--keep-days", "30", "--apply"])
    assert error.value.code == 2
    assert "unrecognized arguments" in capsys.readouterr().err


def test_cli_sanitizes_driver_failures(monkeypatch, capsys):
    def failed(*_args, **_kwargs):
        raise psycopg.OperationalError("password=do-not-print fixture-provider-payload")

    monkeypatch.setattr(retention.psycopg, "connect", failed)
    monkeypatch.setenv("DENALI_DSN", "synthetic-private-dsn")
    assert retention.main(["--tenant-id", str(uuid4()), "--keep-days", "180"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert "do-not-print" not in output.err
    assert "synthetic-private-dsn" not in output.err
    assert "fixture-provider-payload" not in output.err
    assert "Retention review failed" in output.err


@pytest.mark.parametrize("keep_days", [30, 90, 180])
def test_cli_outputs_json_and_requires_explicit_sensitivity_input(monkeypatch, capsys, keep_days):
    monkeypatch.setattr(retention.psycopg, "connect", lambda *_a, **_k: Connection())
    monkeypatch.setenv("DENALI_DSN", "synthetic-private-dsn")
    assert retention.main(["--tenant-id", str(uuid4()), "--keep-days", str(keep_days)]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["keep_days"] == keep_days
    assert report["deletion_supported"] is False
