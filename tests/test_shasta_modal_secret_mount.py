from __future__ import annotations

import runpy
from pathlib import Path

import modal
import pytest

MODAL_APP = Path(__file__).parents[1] / "modal_app.py"


def test_production_bridge_retains_provider_identity_and_adds_dedicated_secret(monkeypatch):
    monkeypatch.setenv("DENALI_MODAL_SECRET_NAME", "test-core")
    monkeypatch.setenv("DENALI_MODAL_PROVIDER_SECRET_NAME", "test-provider")

    module = runpy.run_path(str(MODAL_APP))

    assert [secret.name for secret in module["runtime_secrets"][:2]] == [
        "test-core",
        "test-provider",
    ]
    assert len(module["runtime_secrets"]) == 3
    assert [secret.name for secret in module["shasta_bridge_secrets"][:2]] == [
        "test-core",
        "test-provider",
    ]
    assert module["shasta_bridge_secrets"][3].name == "shasta-denali-bridge"


def test_development_bridge_keeps_the_same_dependency_graph(monkeypatch):
    monkeypatch.setenv("DENALI_MODAL_SECRET_NAME", "test-core")
    monkeypatch.setenv("DENALI_MODAL_PROVIDER_SECRET_NAME", "test-provider")

    module = runpy.run_path(str(MODAL_APP))

    assert [secret.name for secret in module["shasta_bridge_secrets"][:2]] == [
        "test-core",
        "test-provider",
    ]
    assert len(module["shasta_bridge_secrets"]) == 4
    assert module["shasta_bridge_secrets"][3].name == "shasta-denali-bridge"


def test_shared_connections_origin_has_stable_dependency_graph(monkeypatch):
    monkeypatch.setenv("DENALI_MODAL_SECRET_NAME", "test-core")
    monkeypatch.setenv("DENALI_MODAL_PROVIDER_SECRET_NAME", "test-provider")
    monkeypatch.setenv("DENALI_MODAL_SHARED_CONNECTIONS_ORIGIN", "https://platform.example")
    monkeypatch.setenv("DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS", "org_pilot")
    monkeypatch.setenv("DENALI_ENABLE_SHARED_JIRA_READS", "true")
    monkeypatch.setenv("DENALI_MODAL_APP_NAME", "denali-dev")

    module = runpy.run_path(str(MODAL_APP))

    assert module["shared_connections_origin"] == "https://platform.example"
    assert module["shared_connections_allowed_org_ids"] == "org_pilot"
    assert module["shared_jira_reads_flag"] == "true"
    assert module["shared_connections_config"]["DENALI_ENABLE_SHARED_JIRA_READS"] == "true"
    assert [secret.name for secret in module["runtime_secrets"][:2]] == [
        "test-core",
        "test-provider",
    ]
    assert len(module["runtime_secrets"]) == 3
    assert len(module["shared_connections_secrets"]) == 3
    assert "DENALI_PLATFORM_CONNECTIONS_ORIGIN" in repr(module["shared_connections_secrets"][2])

    assert "DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS" in repr(module["shared_connections_secrets"][2])
    assert [secret.name for secret in module["shasta_bridge_secrets"][:2]] == [
        "test-core",
        "test-provider",
    ]
    assert module["shasta_bridge_secrets"][3].name == "shasta-denali-bridge"

    # The container import has no deploy-shell variables; its dependencies
    # must still match the deployment-side graph exactly.
    monkeypatch.delenv("DENALI_MODAL_SHARED_CONNECTIONS_ORIGIN")
    monkeypatch.delenv("DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS")
    monkeypatch.delenv("DENALI_MODAL_APP_NAME")
    module = runpy.run_path(str(MODAL_APP))
    assert module["shared_jira_reads_flag"] == "true"
    assert module["shared_connections_config"]["DENALI_ENABLE_SHARED_JIRA_READS"] == "true"
    assert len(module["runtime_secrets"]) == 3
    assert len(module["shared_connections_secrets"]) == 3
    assert len(module["shasta_bridge_secrets"]) == 4

    # An environment with no selector remains dark without changing any mount.
    monkeypatch.delenv("DENALI_ENABLE_SHARED_JIRA_READS")
    module = runpy.run_path(str(MODAL_APP))
    assert module["shared_connections_origin"] is None
    assert module["shared_connections_allowed_org_ids"] is None
    assert module["shared_jira_reads_flag"] == "false"
    assert module["shared_connections_config"]["DENALI_ENABLE_SHARED_JIRA_READS"] == "false"
    assert "DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS" not in module[
        "shared_connections_config"
    ]
    assert len(module["shared_connections_secrets"]) == 3
    assert "DENALI_PLATFORM_CONNECTIONS_ORIGIN" in repr(module["shared_connections_secrets"][2])


def test_workspace_flag_reaches_every_worker_without_extra_secret(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED", "true")
    monkeypatch.setenv("DENALI_ENABLE_SHARED_JIRA_READS", "true")
    module = runpy.run_path(str(MODAL_APP))
    config = module["shared_connections_config"]
    assert config["DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED"] == "true"
    assert config["DENALI_ENABLE_SHARED_JIRA_READS"] == "true"
    assert len(module["runtime_secrets"]) == 3
    assert len(module["shasta_bridge_secrets"]) == 4
    monkeypatch.delenv("DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED")
    module = runpy.run_path(str(MODAL_APP))
    assert (
        module["shared_connections_config"]["DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED"] == "false"
    )
    assert module["shared_connections_config"]["DENALI_ENABLE_SHARED_JIRA_READS"] == "true"


@pytest.mark.parametrize("invalid", ["TRUE", "1", "yes", " false ", "invalid"])
def test_shared_jira_selector_rejects_invalid_value_before_modal_graph(monkeypatch, invalid):
    monkeypatch.setenv("DENALI_ENABLE_SHARED_JIRA_READS", invalid)
    monkeypatch.setattr(
        modal.Image, "debian_slim", lambda **kwargs: pytest.fail("Modal image created"),
    )
    with pytest.raises(ValueError, match="DENALI_ENABLE_SHARED_JIRA_READS must be true or false"):
        runpy.run_path(str(MODAL_APP))


@pytest.mark.parametrize("workflow", [
    "deploy-modal-development.yml", "deploy-modal-production.yml",
])
def test_deployment_workflows_carry_public_jira_selector_with_false_default(workflow):
    source = (
        MODAL_APP.parent / ".github" / "workflows" / workflow
    ).read_text(encoding="utf-8")
    deploy = source.split("\n  deploy:\n", 1)[1]
    assert (
        "DENALI_ENABLE_SHARED_JIRA_READS: "
        "${{ vars.DENALI_ENABLE_SHARED_JIRA_READS || 'false' }}"
    ) in deploy
    assert "secrets.DENALI_ENABLE_SHARED_JIRA_READS" not in source


def test_workspace_flag_rejects_nonliteral_values(monkeypatch):
    monkeypatch.setenv("DENALI_PLATFORM_GOOGLE_WORKSPACE_ENABLED", "TRUE")
    with pytest.raises(ValueError, match="true or false"):
        runpy.run_path(str(MODAL_APP))
