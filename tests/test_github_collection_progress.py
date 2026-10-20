"""Private browser progress is distinct from terminal history/public summaries."""

from importlib import import_module
from types import SimpleNamespace

from denali.api.connection_capabilities import connection_summary


def test_browser_progress_preserves_terminal_history_without_exposing_checkpoint(monkeypatch):
    module = import_module("denali.api.app")
    monkeypatch.setattr(module, "_connection_validation_state", lambda *_args: "idle")
    monkeypatch.setattr(module, "_connection_setup_capabilities", lambda *_args: {})
    previous = {"state": "partial", "repository_count": 113, "partial_count": 72}
    progress = {
        "state": "running", "repository_count": 113,
        "completed_repository_count": 5, "retry_after_seconds": 120,
    }

    class Repository:
        def connection_collection_status(self, tenant, connection_id, *, collection_kind):
            assert (tenant, connection_id, collection_kind) == (
                "tenant", "connection", "github_source"
            )
            return {"state": "running", "last_result": previous, "progress": progress}

    request = SimpleNamespace(
        state=SimpleNamespace(denali_auth=SimpleNamespace(can_write=True)),
        app=SimpleNamespace(state=SimpleNamespace(repository=Repository())),
    )
    row = {
        "id": "connection", "provider": "github", "lifecycle_state": "active",
        "health_state": "healthy", "credential_reference": {"type": "github_app_installation"},
        "configuration": {}, "declared_scopes": [],
    }
    result = module._with_validation_state(request, "tenant", row)
    assert result["source_collection_state"] == "running"
    assert result["source_collection_progress"] == progress
    assert result["last_source_collection"] == previous
    public = connection_summary(result)
    assert "source_collection_progress" not in public
    assert "last_source_collection" not in public
    assert "checkpoint" not in result
