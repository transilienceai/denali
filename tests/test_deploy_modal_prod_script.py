from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "deploy_modal_prod.sh"
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
  "branch --show-current") printf '%s\n' "${FAKE_BRANCH:-main}" ;;
  "fetch --quiet origin main") ;;
  "rev-parse origin/main") printf '%s\n' "${FAKE_ORIGIN_MAIN_SHA}" ;;
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
fi
""",
    )
    environment = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_CALL_LOG": str(call_log),
        "FAKE_GIT_STATUS": "",
        "FAKE_HEAD_SHA": SHA,
        "FAKE_ORIGIN_MAIN_SHA": SHA,
        "FAKE_BRANCH": "main",
    }
    environment.pop("GITHUB_ACTIONS", None)
    environment.pop("GITHUB_REF", None)
    environment.pop("GITHUB_SHA", None)
    environment.update(overrides)
    return environment


def _run(
    tmp_path: Path,
    *arguments: str,
    **overrides: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), *arguments],
        cwd=SCRIPT.parents[1],
        env=_environment(tmp_path, **overrides),
        capture_output=True,
        text=True,
        check=False,
    )


def test_production_deploy_requires_explicit_confirmation(tmp_path: Path) -> None:
    result = _run(tmp_path)

    assert result.returncode == 2
    assert "--confirm-production" in result.stderr
    assert not (tmp_path / "calls.log").exists()


def test_production_deploy_rejects_dirty_worktree(tmp_path: Path) -> None:
    result = _run(tmp_path, "--confirm-production", FAKE_GIT_STATUS="modified")

    assert result.returncode == 2
    assert "dirty worktree" in result.stderr
    assert not (tmp_path / "calls.log").exists()


def test_production_deploy_rejects_non_main_local_branch(tmp_path: Path) -> None:
    result = _run(tmp_path, "--confirm-production", FAKE_BRANCH="feature")

    assert result.returncode == 2
    assert "branch other than main" in result.stderr
    assert not (tmp_path / "calls.log").exists()


def test_production_deploy_rejects_stale_actions_revision(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        "--confirm-production",
        GITHUB_ACTIONS="true",
        GITHUB_REF="refs/heads/main",
        GITHUB_SHA=SHA,
        FAKE_ORIGIN_MAIN_SHA="b" * 40,
    )

    assert result.returncode == 2
    assert "does not match origin/main" in result.stderr
    assert not (tmp_path / "calls.log").exists()


def test_production_deploy_rejects_wrong_actions_ref(tmp_path: Path) -> None:
    result = _run(
        tmp_path,
        "--confirm-production",
        GITHUB_ACTIONS="true",
        GITHUB_REF="refs/heads/dev",
        GITHUB_SHA=SHA,
    )

    assert result.returncode == 2
    assert "workflow source" in result.stderr
    assert not (tmp_path / "calls.log").exists()


def test_production_deploy_runs_p0_check_migration_deploy_and_smoke_tests(
    tmp_path: Path,
) -> None:
    result = _run(
        tmp_path,
        "--confirm-production",
        GITHUB_ACTIONS="true",
        GITHUB_REF="refs/heads/main",
        GITHUB_SHA=SHA,
    )

    assert result.returncode == 0, result.stderr
    assert f"Production smoke checks passed for commit {SHA}." in result.stdout
    calls = (tmp_path / "calls.log").read_text(encoding="utf-8")
    assert (
        "modal run --env denali-prod modal_app.py::configuration_status "
        "--required-groups core,aws,azure,entra,gcp,google_workspace,github,azure_repos"
    ) in calls
    assert "modal run --env denali-prod modal_app.py::migrate_database" in calls
    assert "modal run --env denali-prod modal_app.py::database_status" in calls
    assert "modal deploy --env denali-prod modal_app.py" in calls
    assert "https://transilience-denali-prod--denali-production-api.modal.run/healthz" in calls
    assert "https://denali.transilience.cloud/api/healthz" in calls
    assert "https://transilience-denali-prod--denali-production-api.modal.run/v1/context" in calls
