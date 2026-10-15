"""Focused dev port preserves legacy bridge and unconfigured native behavior."""

from __future__ import annotations

import ast
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_shared_microsoft import APP, ID, connection
from test_shared_microsoft_api import AUTH, Broker, Repository, client

from denali.api.app import create_app
from denali.integrations import shared_connections_client
from denali.integrations.shared_connections_client import SharedConnectionsClient


def test_microsoft_admission_is_empty_by_default_but_legacy_transport_still_runs(monkeypatch):
    monkeypatch.delenv("DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS", raising=False)
    bridge = SharedConnectionsClient("https://platform.example", "synthetic-machine")
    bridge._clerk = SimpleNamespace(
        m2m=SimpleNamespace(create_token=lambda **kwargs: SimpleNamespace(token="synthetic"))
    )
    calls = []

    class Http:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def request(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
            return SimpleNamespace(status_code=200, json=lambda: {"items": []})

    monkeypatch.setattr(shared_connections_client.httpx, "Client", Http)
    assert bridge.allows_org("org_existingdev") is False
    assert bridge.request("GET", "/v1/connections", clerk_org_id="org_existingdev") == {"items": []}
    assert calls[0][2]["params"] == {"clerk_org_id": "org_existingdev"}
    monkeypatch.setenv("DENALI_PLATFORM_ALLOWED_CLERK_ORG_IDS", "org_devapproved")
    assert bridge.allows_org("org_devapproved") is True
    assert bridge.allows_org("org_production") is False


def test_existing_development_origin_secret_pairing_is_preserved(monkeypatch):
    monkeypatch.delenv("DENALI_PLATFORM_CONNECTIONS_ORIGIN", raising=False)
    monkeypatch.setenv("DENALI_PLATFORM_MACHINE_SECRET_KEY", "synthetic-existing-sender")
    with pytest.raises(ValueError, match="configured together"):
        SharedConnectionsClient.from_environment()


@pytest.mark.parametrize("action", ["validate", "entra/collect"])
def test_unconfigured_native_entra_still_returns_503_before_any_job(action, monkeypatch):
    for name in (
        "DENALI_ENTRA_CLIENT_ID",
        "DENALI_ENTRA_CLIENT_SECRET",
        "DENALI_ENTRA_CALLBACK_URL",
    ):
        monkeypatch.delenv(name, raising=False)
    repo = Repository()
    row = connection("entra")
    row["credential_reference"] = {"type": "entra_multitenant_app", "client_id": APP}
    row["configuration"]["onboarding"] = {"completed_at": "2026-10-13T00:00:00+00:00"}
    repo.rows[(repo.resolve_tenant("org_alpha"), ID)] = row
    with client(Broker("entra"), repo) as test:
        response = test.post(f"/v1/connections/{ID}/{action}", headers=AUTH)
    assert response.status_code == 503


def test_dev_microsoft_contract_classifies_only_added_browser_routes():
    root = Path(__file__).resolve().parents[1]
    contract = json.loads((root / "docs/development/shared-microsoft-contract.v1.json").read_text())
    actual = set()
    for node in ast.walk(ast.parse((root / "src/denali/api/app.py").read_text())):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == "app"
                and decorator.func.attr in {"get", "post", "delete"}
                and decorator.args
                and isinstance(decorator.args[0], ast.Constant)
                and str(decorator.args[0].value).startswith("/v1/shared/connections/")
                and (
                    "{provider}" in str(decorator.args[0].value)
                    or "azure/" in str(decorator.args[0].value)
                )
            ):
                actual.add((decorator.func.attr.upper(), decorator.args[0].value))
    assert actual == {(row["method"], row["path"]) for row in contract["browser_operations"]}
    assert contract["new_tool_names"] == contract["new_login_scopes"] == []
    assert contract["activation_scope"] == "entra_only"
    assert contract["azure_activation"] == "deferred"
    assert all(
        row["role"] == "admin"
        for row in contract["browser_operations"]
        if row["method"] in {"POST", "DELETE"} or row["path"].endswith("/setup")
    )


def test_entra_only_rollout_does_not_replace_native_workspace_dependencies(monkeypatch):
    from fastapi.testclient import TestClient
    from test_shared_microsoft_api import Authenticator

    monkeypatch.setenv("DENALI_PLATFORM_ENTRA_ENABLED", "true")
    monkeypatch.delenv("DENALI_PLATFORM_AZURE_ENABLED", raising=False)
    validator, collector = object(), object()
    application = create_app(
        repository=Repository(),
        auth_mode="clerk",
        authenticator=Authenticator(),
        shared_connections_client=Broker("entra"),
        google_workspace_connection_validator=validator,
        google_workspace_connection_collector=collector,
        migrate_on_start=False,
    )
    with TestClient(application) as browser:
        assert browser.get("/v1/shared/connections/entra", headers=AUTH).status_code == 200
        assert application.state.google_workspace_connection_validator is validator
        assert application.state.google_workspace_connection_collector is collector
