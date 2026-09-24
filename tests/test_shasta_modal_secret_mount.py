from __future__ import annotations

import runpy
from pathlib import Path

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
    monkeypatch.setenv("DENALI_MODAL_APP_NAME", "denali-dev")

    module = runpy.run_path(str(MODAL_APP))

    assert module["shared_connections_origin"] == "https://platform.example"
    assert [secret.name for secret in module["runtime_secrets"][:2]] == [
        "test-core",
        "test-provider",
    ]
    assert len(module["runtime_secrets"]) == 3
    assert len(module["shared_connections_secrets"]) == 3
    assert "DENALI_PLATFORM_CONNECTIONS_ORIGIN" in repr(
        module["shared_connections_secrets"][2]
    )
    assert [secret.name for secret in module["shasta_bridge_secrets"][:2]] == [
        "test-core",
        "test-provider",
    ]
    assert module["shasta_bridge_secrets"][3].name == "shasta-denali-bridge"

    # The container import has no deploy-shell variables; its dependencies
    # must still match the deployment-side graph exactly.
    monkeypatch.delenv("DENALI_MODAL_SHARED_CONNECTIONS_ORIGIN")
    monkeypatch.delenv("DENALI_MODAL_APP_NAME")
    module = runpy.run_path(str(MODAL_APP))
    assert module["shared_connections_origin"] is None
    assert len(module["shared_connections_secrets"]) == 3
    assert "DENALI_PLATFORM_CONNECTIONS_ORIGIN" in repr(
        module["shared_connections_secrets"][2]
    )
