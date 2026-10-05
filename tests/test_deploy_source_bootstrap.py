"""Deploy imports must work without an editable Denali install or site packages."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from test_deploy_modal_dev_script import _environment as development_environment
from test_deploy_modal_prod_script import _environment as production_environment
from test_deploy_modal_prod_script import _executable

ROOT = Path(__file__).resolve().parents[1]
IMPORT_PROBE = """
import os
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

# Only Modal is mocked; Denali uses actual subprocess import resolution with
# site packages disabled, so an installed editable package cannot hide failure.
class Image:
    def __getattr__(self, name):
        return lambda *args, **kwargs: self

class App:
    def function(self, **kwargs):
        return lambda function: function

sys.modules['modal'] = SimpleNamespace(
    Image=SimpleNamespace(debian_slim=lambda **kwargs: Image()),
    Secret=SimpleNamespace(from_name=lambda *args: object(), from_dict=lambda *args: object()),
    App=lambda *args: App(), Period=lambda **kwargs: object(),
    asgi_app=lambda **kwargs: lambda function: function,
)
module = runpy.run_path('modal_app.py')
from denali import worker_limits
expected = Path(os.environ['FAKE_REPOSITORY_ROOT']) / 'src/denali/worker_limits.py'
assert Path(worker_limits.__file__).resolve() == expected.resolve()
assert module['VALIDATION_WORKER_TIMEOUT_SECONDS'] == 2400
assert module['COLLECTION_WORKER_TIMEOUT_SECONDS'] == 2400
assert module['VULNERABILITY_IMPORT_WORKER_TIMEOUT_SECONDS'] == 1200
"""


def test_deploy_interpreter_reproduces_missing_denali_without_source_bootstrap():
    environment = {**os.environ, "FAKE_REPOSITORY_ROOT": str(ROOT)}
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, "-S", "-c", IMPORT_PROBE],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "ModuleNotFoundError: No module named 'denali'" in result.stderr


@pytest.mark.parametrize("deployment", ["production", "development"])
@pytest.mark.parametrize("inherited_source", [False, True])
def test_guarded_helpers_import_actual_modal_module_with_clean_interpreter(
    tmp_path, deployment, inherited_source
):
    builder = production_environment if deployment == "production" else development_environment
    environment = builder(tmp_path)
    # Prove caller-supplied source does not override the guarded checkout.
    foreign = tmp_path / "foreign" / "denali"
    foreign.mkdir(parents=True)
    (foreign / "__init__.py").write_text("raise AssertionError('untrusted source imported')\n")
    environment.update(
        {
            "FAKE_CLEAN_PYTHON": sys.executable,
            "FAKE_IMPORT_PROBE": IMPORT_PROBE,
        }
    )
    if inherited_source:
        environment["PYTHONPATH"] = str(foreign.parent)
    else:
        environment.pop("PYTHONPATH", None)
    _executable(
        tmp_path / "bin" / "modal",
        """#!/usr/bin/env bash
set -euo pipefail
"${FAKE_CLEAN_PYTHON}" -S -c "${FAKE_IMPORT_PROBE}"
printf 'modal %s\n' "$*" >>"${FAKE_CALL_LOG}"
""",
    )
    arguments = ["--confirm-production"] if deployment == "production" else []
    script = ROOT / "scripts" / f"deploy_modal_{'prod' if deployment == 'production' else 'dev'}.sh"
    result = subprocess.run(
        ["bash", str(script), *arguments],
        cwd=ROOT / "scripts",
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    calls = (tmp_path / "calls.log").read_text()
    assert sum(line.startswith("modal ") for line in calls.splitlines()) == 4
