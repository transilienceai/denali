from __future__ import annotations

import runpy
from pathlib import Path

import modal
import pytest
import yaml

ROOT = Path(__file__).parents[1]


def test_native_publisher_default_off_with_same_existing_secret_graph(monkeypatch):
    monkeypatch.delenv("DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED", raising=False)
    monkeypatch.setenv("DENALI_MODAL_SECRET_NAME", "test-core")
    monkeypatch.setenv("DENALI_MODAL_PROVIDER_SECRET_NAME", "test-provider")
    module = runpy.run_path(str(ROOT / "modal_app.py"))
    assert module["native_settings_publish_flag"] == "false"
    assert "native_connection_settings_tick" not in module
    assert len(module["runtime_secrets"]) == 3
    assert [secret.name for secret in module["runtime_secrets"][:2]] == [
        "test-core", "test-provider",
    ]
    for name in (
        "native_connection_settings_manifest", "preflight_native_connection_settings",
        "publish_native_connection_settings", "verify_native_connection_settings_lookup",
    ):
        assert name in module


def test_native_publication_requires_literal_flag_and_preserves_empty_core_pins(monkeypatch):
    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED", "true")
    monkeypatch.setenv("DENALI_MODAL_APP_NAME", "denali-dev")
    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE", "database")
    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS", "")
    module = runpy.run_path(str(ROOT / "modal_app.py"))
    assert "native_connection_settings_tick" in module
    values = module["shared_connections_config"]
    assert values["DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED"] == "true"
    assert values["DENALI_NATIVE_CONNECTION_SETTINGS_ENVIRONMENT"] == "development"
    assert values["DENALI_NATIVE_CONNECTION_SETTINGS_SOURCE"] == "database"
    assert "DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS" not in values
    assert len(module["runtime_secrets"]) == 3


@pytest.mark.parametrize("flag", ["TRUE", "1", "yes", " false "])
def test_native_publisher_invalid_flag_fails_before_modal_resources(monkeypatch, flag):
    monkeypatch.setenv("DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED", flag)
    monkeypatch.setattr(modal.Image, "debian_slim", lambda **_kwargs: pytest.fail("image created"))
    with pytest.raises(ValueError, match="PUBLISH_ENABLED must be true or false"):
        runpy.run_path(str(ROOT / "modal_app.py"))


@pytest.mark.parametrize("workflow", [
    "deploy-modal-production.yml", "deploy-modal-development.yml",
])
def test_protected_workflows_keep_native_schedule_default_off(workflow):
    source = (ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
    document = yaml.safe_load(source)
    deploy = document["jobs"]["deploy"]
    assert deploy["env"]["DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED"] == (
        "${{ vars.DENALI_NATIVE_CONNECTION_SETTINGS_PUBLISH_ENABLED || 'false' }}"
    )
    assert "secrets.CLERK_SECRET_KEY" not in source
    assert "secrets.DENALI_NATIVE_CONNECTION_SETTINGS" not in source
