from __future__ import annotations

import runpy
from pathlib import Path

MODAL_APP = Path(__file__).parents[1] / "modal_app.py"
ORIGIN = "https://transilience-transilience-platform-dev--transilience-pla-73050c.modal.run"


def test_shared_connections_origin_has_stable_dependency_graph(monkeypatch):
    monkeypatch.setenv("DENALI_MODAL_SECRET_NAME", "test-core")
    monkeypatch.setenv("DENALI_MODAL_PROVIDER_SECRET_NAME", "test-provider")
    monkeypatch.setenv("DENALI_MODAL_SHARED_CONNECTIONS_ORIGIN", ORIGIN)
    monkeypatch.setenv("DENALI_MODAL_APP_NAME", "denali-dev")

    deployment = runpy.run_path(str(MODAL_APP))

    assert deployment["shared_connections_origin"] == ORIGIN
    assert [secret.name for secret in deployment["runtime_secrets"][:2]] == [
        "test-core",
        "test-provider",
    ]
    assert len(deployment["runtime_secrets"]) == 4
    assert deployment["runtime_secrets"][-1].name == "denali-platform-modal-proxy"
    assert deployment["shared_connections_secrets"] is deployment["runtime_secrets"]
    assert "DENALI_PLATFORM_CONNECTIONS_ORIGIN" in repr(deployment["runtime_secrets"][2])

    # Containers re-import without deploy-shell settings.
    monkeypatch.delenv("DENALI_MODAL_SHARED_CONNECTIONS_ORIGIN")
    monkeypatch.delenv("DENALI_MODAL_APP_NAME")
    monkeypatch.setenv("MODAL_IS_REMOTE", "1")
    monkeypatch.setenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", ORIGIN)
    container = runpy.run_path(str(MODAL_APP))
    assert container["shared_connections_origin"] == ORIGIN
    assert len(container["runtime_secrets"]) == len(deployment["runtime_secrets"])
    assert "DENALI_PLATFORM_CONNECTIONS_ORIGIN" in repr(container["runtime_secrets"][2])


def test_dark_deploy_masks_a_stale_core_origin_and_needs_no_proxy_secret(monkeypatch):
    monkeypatch.delenv("DENALI_MODAL_SHARED_CONNECTIONS_ORIGIN", raising=False)
    monkeypatch.delenv("MODAL_IS_REMOTE", raising=False)
    monkeypatch.setenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "https://stale.example")
    module = runpy.run_path(str(MODAL_APP))
    assert module["shared_connections_origin"] is None
    assert len(module["runtime_secrets"]) == 3
    # The explicit empty deployment value wins over a core Secret remotely.
    monkeypatch.setenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", "")
    monkeypatch.setenv("MODAL_IS_REMOTE", "1")
    remote = runpy.run_path(str(MODAL_APP))
    assert remote["shared_connections_origin"] == ""
    assert len(remote["runtime_secrets"]) == 3
