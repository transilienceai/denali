from __future__ import annotations

import runpy
from pathlib import Path

MODAL_APP = Path(__file__).parents[1] / "modal_app.py"


def test_shared_connections_origin_has_stable_dependency_graph(monkeypatch):
    monkeypatch.setenv("DENALI_MODAL_SECRET_NAME", "test-core")
    monkeypatch.setenv("DENALI_MODAL_PROVIDER_SECRET_NAME", "test-provider")
    monkeypatch.setenv("DENALI_MODAL_SHARED_CONNECTIONS_ORIGIN", "https://platform.example")
    monkeypatch.setenv("DENALI_MODAL_APP_NAME", "denali-dev")

    deployment = runpy.run_path(str(MODAL_APP))

    assert deployment["shared_connections_origin"] == "https://platform.example"
    assert [secret.name for secret in deployment["runtime_secrets"][:2]] == [
        "test-core",
        "test-provider",
    ]
    assert len(deployment["runtime_secrets"]) == 3
    assert deployment["shared_connections_secrets"] is deployment["runtime_secrets"]
    assert "DENALI_PLATFORM_CONNECTIONS_ORIGIN" in repr(deployment["runtime_secrets"][2])

    # Containers re-import without deploy-shell settings.
    monkeypatch.delenv("DENALI_MODAL_SHARED_CONNECTIONS_ORIGIN")
    monkeypatch.delenv("DENALI_MODAL_APP_NAME")
    container = runpy.run_path(str(MODAL_APP))
    assert container["shared_connections_origin"] is None
    assert len(container["runtime_secrets"]) == len(deployment["runtime_secrets"])
    assert "DENALI_PLATFORM_CONNECTIONS_ORIGIN" in repr(container["runtime_secrets"][2])
