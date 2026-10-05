from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "deploy_modal_dev.sh"
SHA = "a" * 40


def _executable(path: Path, contents: str) -> None:
    path.write_text(contents, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def _environment(tmp_path: Path, **overrides: str) -> dict[str, str]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    call_log = tmp_path / "calls.log"
    _executable(
        bin_dir / "git",
        """#!/usr/bin/env bash
set -euo pipefail
case "$*" in
  "status --porcelain") printf '%s' "${FAKE_GIT_STATUS:-}" ;;
  "rev-parse HEAD") printf '%s\n' "${FAKE_HEAD_SHA}" ;;
  "fetch --quiet origin dev") ;;
  "rev-parse origin/dev") printf '%s\n' "${FAKE_ORIGIN_DEV_SHA}" ;;
  *) printf 'unexpected git call: %s\n' "$*" >&2; exit 90 ;;
esac
""",
    )
    _executable(
        bin_dir / "modal",
        """#!/usr/bin/env bash
set -euo pipefail
printf 'modal %s\n' "$*" >>"${FAKE_CALL_LOG}"
""",
    )
    _executable(
        bin_dir / "curl",
        """#!/usr/bin/env bash
set -euo pipefail
printf 'curl %s\n' "$*" >>"${FAKE_CALL_LOG}"
if [[ "$*" == *"--write-out"* ]]; then
  printf '401'
elif [[ "$*" == *"/openapi.json"* ]]; then
  printf '%s' "${FAKE_OPENAPI}"
fi
""",
    )
    environment = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_CALL_LOG": str(call_log),
        "FAKE_GIT_STATUS": "",
        "FAKE_HEAD_SHA": SHA,
        "FAKE_ORIGIN_DEV_SHA": SHA,
        "FAKE_OPENAPI": '{"paths":{"/v1/shared/connections":{}}}',
    }
    environment.pop("GITHUB_ACTIONS", None)
    environment.pop("GITHUB_REF", None)
    environment.pop("GITHUB_SHA", None)
    environment.update(overrides)
    return environment


def _run(tmp_path: Path, **overrides: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=SCRIPT.parents[1],
        env=_environment(tmp_path, **overrides),
        capture_output=True,
        text=True,
        check=False,
    )


def test_development_deploy_rejects_dirty_worktree(tmp_path: Path) -> None:
    result = _run(tmp_path, FAKE_GIT_STATUS="modified")

    assert result.returncode == 2
    assert "dirty worktree" in result.stderr
    assert not (tmp_path / "calls.log").exists()


def test_development_deploy_rejects_stale_revision(tmp_path: Path) -> None:
    result = _run(tmp_path, FAKE_ORIGIN_DEV_SHA="b" * 40)

    assert result.returncode == 2
    assert "does not match origin/dev" in result.stderr
    assert not (tmp_path / "calls.log").exists()


def test_development_deploy_rejects_wrong_actions_ref(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        GITHUB_ACTIONS="true",
        GITHUB_REF="refs/heads/main",
        GITHUB_SHA=SHA,
    )

    assert result.returncode == 2
    assert "workflow source" in result.stderr
    assert not (tmp_path / "calls.log").exists()


def test_development_deploy_runs_checks_migration_deploy_and_smoke_tests(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        GITHUB_ACTIONS="true",
        GITHUB_REF="refs/heads/dev",
        GITHUB_SHA=SHA,
    )

    assert result.returncode == 0, result.stderr
    assert f"Development smoke checks passed for commit {SHA}." in result.stdout
    calls = (tmp_path / "calls.log").read_text(encoding="utf-8")
    assert "modal run --env denali-dev modal_app.py::configuration_status" in calls
    assert "modal run --env denali-dev modal_app.py::migrate_database" in calls
    assert "modal run --env denali-dev modal_app.py::database_status" in calls
    assert "modal deploy --env denali-dev modal_app.py" in calls
    assert "https://transilience-denali-dev--denali-dev-api.modal.run/healthz" in calls
    assert "https://transilience-denali-dev--denali-dev-api.modal.run/openapi.json" in calls
    assert "https://denali-dev.transilience.cloud/api/healthz" in calls
    assert "https://transilience-denali-dev--denali-dev-api.modal.run/v1/context" in calls


def test_development_deploy_rejects_stale_backend_without_shared_route(tmp_path: Path) -> None:
    result = _run(tmp_path, FAKE_OPENAPI='{"paths":{}}')

    assert result.returncode == 1
    assert "shared-connections route is absent" in result.stderr
