"""Product parity additions preserve the product authorization and durable worker boundary."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from test_gateway_capabilities import ASSET, Memberships, Repository, SessionAuthenticator, Verifier
from test_vulnerability_import_jobs import _grype_report, _syft_report

from denali.api.app import MAX_GATEWAY_EXPORT_BYTES, MAX_GATEWAY_IMPORT_BYTES, create_app

IMPORT = "/internal/v1/capabilities/vulnerabilities/imports"
SESSION = "a" * 64
HEADERS = {"Authorization": "Bearer admin-write", "Idempotency-Key": "import-action-1"}


def body(**changes):
    return {
        "target_asset_id": ASSET,
        "syft_report": _syft_report(),
        "grype_report": _grype_report(),
        "authoritative": True,
        "expected_org_id": "org_Alpha1",
        "confirmed": True,
        **changes,
    }


class ImportRepository(Repository):
    def __init__(self):
        super().__init__()
        self.import_actions = {}
        self.jobs = {}

    def resolve_tenant(self, org):
        return self.lookup_tenant(org)

    def get_asset(self, tenant, asset):
        return (
            {"kind": "ai_workload", "lifecycle_state": "active"}
            if tenant == "tenant-alpha" and asset == ASSET
            else None
        )

    def get_runtime_session(self, tenant, session_key, **kwargs):
        self.calls.append(("get_runtime_session", tenant, session_key, kwargs))
        if tenant != "tenant-alpha":
            return None
        return {"provider": "aws_agentcore", "activities": [], "truncated": False}

    def gateway_vulnerability_import_action(self, tenant, *, idempotency_key, request_hash):
        stored = self.import_actions.get((tenant, idempotency_key))
        if stored is None:
            return None
        if stored[0] != request_hash:
            raise ValueError("idempotency key was already used for another action")
        return dict(self.jobs[stored[1]])

    def create_vulnerability_import_job_idempotent(self, tenant, **kwargs):
        previous = self.gateway_vulnerability_import_action(
            tenant, idempotency_key=kwargs["idempotency_key"], request_hash=kwargs["request_hash"]
        )
        if previous:
            return previous, False
        job = {"id": kwargs["job_id"], "state": "queued", "modal_call_id": None}
        self.jobs[job["id"]] = job
        self.import_actions[(tenant, kwargs["idempotency_key"])] = (
            kwargs["request_hash"],
            job["id"],
        )
        self.calls.append(("create_import", tenant, kwargs))
        return dict(job), True

    def set_vulnerability_import_call_id(self, job_id, call_id):
        self.jobs[job_id]["modal_call_id"] = call_id


class Store:
    def __init__(self):
        self.staged = []
        self.deleted = []

    def put_documents(self, *, tenant_id, job_id, documents):
        self.staged.append((tenant_id, job_id, documents))
        return {name: f"{tenant_id}/{job_id}/{name}.json" for name in documents}

    def delete_documents(self, keys):
        self.deleted.append(keys)


def app(repo, store=None, dispatcher=None):
    return create_app(
        repository=repo,
        auth_mode="clerk",
        authenticator=SessionAuthenticator(),
        results_gateway_verifier=Verifier(),
        gateway_membership_checker=Memberships(),
        evidence_report_store=store,
        vulnerability_import_dispatcher=dispatcher,
        migrate_on_start=False,
    )


def test_context_and_bounded_metadata_export_reuse_tenant_scoped_handlers():
    repo = ImportRepository()
    with TestClient(app(repo)) as client:
        context = client.get(
            "/internal/v1/capabilities/context", headers={"Authorization": "Bearer admin-read"}
        )
        assert context.json() == {
            "tenant_id": "tenant-alpha",
            "organization_id": "org_Alpha1",
            "role": "admin",
            "can_write": True,
        }
        exported = client.get(
            "/internal/v1/capabilities/runtime-session-export",
            params={"id": SESSION},
            headers={"Authorization": "Bearer admin-read"},
        )
        assert exported.status_code == 200
        assert exported.json()["schema_version"] == "denali.aws_agent_session.v1"
        assert exported.json()["content_policy"] == "metadata_only"
        assert exported.headers["cache-control"] == "no-store"
        assert exported.headers["content-disposition"].endswith('.json"')
        assert repo.calls[-1] == (
            "get_runtime_session",
            "tenant-alpha",
            SESSION,
            {"activity_limit": 100},
        )
        other = client.get(
            "/internal/v1/capabilities/runtime-session-export",
            params={"id": SESSION},
            headers={"Authorization": "Bearer other-read"},
        )
        assert other.status_code == 404
        assert (
            client.get(
                "/v1/runtime/sessions/" + SESSION + "/export",
                headers={"Authorization": "Bearer browser"},
            ).status_code
            == 200
        )
        assert repo.calls[-1][-1] == {}
        assert (
            client.get(
                "/internal/v1/capabilities/runtime-session-export",
                params={"id": "bad"},
                headers={"Authorization": "Bearer admin-read"},
            ).status_code
            == 422
        )


def test_gateway_export_byte_limit_and_browser_export_default_are_independent():
    repo = ImportRepository()
    repo.get_runtime_session = lambda *args, **kwargs: {
        "provider": "azure_foundry",
        "large": "x" * MAX_GATEWAY_EXPORT_BYTES,
    }
    with TestClient(app(repo)) as client:
        assert (
            client.get(
                "/internal/v1/capabilities/runtime-session-export",
                params={"id": SESSION},
                headers={"Authorization": "Bearer admin-read"},
            ).status_code
            == 413
        )
        assert (
            client.get(
                "/v1/runtime/sessions/" + SESSION + "/export",
                headers={"Authorization": "Bearer browser"},
            ).status_code
            == 200
        )


@pytest.mark.parametrize(
    "token,status",
    [
        ("admin-read", 401),
        ("member-write", 403),
        ("removed-read", 401),
        ("other-write", 404),
        ("browser", 401),
        ("", 401),
    ],
)
def test_import_authorization_and_cross_tenant_target(token, status):
    repo, store, spawned = ImportRepository(), Store(), []
    with TestClient(app(repo, store, lambda job: spawned.append(job) or "call-1")) as client:
        response = client.post(
            IMPORT,
            json=body(expected_org_id="org_Beta2" if token == "other-write" else "org_Alpha1"),
            headers={**HEADERS, "Authorization": "Bearer " + token},
        )
        assert response.status_code == status
    assert repo.import_actions == {} and store.staged == [] and spawned == []


@pytest.mark.parametrize(
    "changes,status",
    [
        ({"confirmed": False}, 422),
        ({"confirmed": 1}, 422),
        ({"confirmed": None}, 422),
        ({"authoritative": 1}, 422),
        ({"authoritative": "false"}, 422),
        ({"expected_org_id": "org_Beta2"}, 409),
        ({"tenant_id": "tenant-beta"}, 422),
        ({"target_asset_id": str(uuid4())}, 404),
        ({"syft_report": {}}, 422),
    ],
)
def test_import_guard_and_native_evidence_validation_before_staging(changes, status):
    repo, store = ImportRepository(), Store()
    with TestClient(app(repo, store, lambda job: "call-1")) as client:
        assert client.post(IMPORT, json=body(**changes), headers=HEADERS).status_code == status
        assert (
            client.post(
                IMPORT, json=body(), headers={"Authorization": "Bearer admin-write"}
            ).status_code
            == 422
        )
        assert (
            client.post(IMPORT + "?tenant_id=other", json=body(), headers=HEADERS).status_code
            == 422
        )
    assert repo.import_actions == {} and store.staged == []


@pytest.mark.parametrize(
    "field",
    [
        "syft_report",
        "grype_report",
        "target_asset_id",
        "expected_org_id",
        "confirmed",
        "authoritative",
        "unrecognized_credential",
    ],
)
def test_import_schema_errors_never_echo_rejected_input(field):
    private = "private-report-or-credential-marker"
    repo, store, spawned = ImportRepository(), Store(), []
    rejected = [{"source": private}] if field in {"syft_report", "grype_report"} else private
    with TestClient(app(repo, store, lambda job: spawned.append(job) or "call-1")) as client:
        result = client.post(IMPORT, json=body(**{field: rejected}), headers=HEADERS)
    assert result.status_code == 422
    assert result.json() == {"detail": "invalid evidence import"}
    assert private not in result.text
    assert repo.import_actions == {} and store.staged == [] and spawned == []


@pytest.mark.parametrize("malformed", [False, True])
def test_import_non_object_and_malformed_json_never_echo_reports(malformed):
    private = "private-nested-report-marker"
    repo, store, spawned = ImportRepository(), Store(), []
    payload = json.dumps([{"syft_report": {"source": private}}])
    if malformed:
        payload = '{"syft_report":{"source":"' + private + '"},"grype_report":'
    with TestClient(app(repo, store, lambda job: spawned.append(job) or "call-1")) as client:
        result = client.post(
            IMPORT,
            content=payload,
            headers={**HEADERS, "Content-Type": "application/json"},
        )
    assert result.status_code == 422
    assert result.json() == {"detail": "invalid evidence import"}
    assert private not in result.text
    assert repo.import_actions == {} and store.staged == [] and spawned == []


def test_import_replay_conflict_and_api_container_replacement():
    repo, store, spawned = ImportRepository(), Store(), []
    def dispatcher(job):
        return spawned.append(job) or "call-1"
    with TestClient(app(repo, store, dispatcher)) as client:
        first = client.post(IMPORT, json=body(), headers=HEADERS)
        assert first.status_code == 202
        assert first.headers["cache-control"] == "no-store"
        job_id = first.json()["id"]
        assert (
            client.post(IMPORT, json=body(authoritative=False), headers=HEADERS).status_code == 409
        )
        assert (
            client.post(
                IMPORT, json=body(), headers={**HEADERS, "Authorization": "Bearer reviewer-write"}
            ).status_code
            == 409
        )
    with TestClient(app(repo, store, dispatcher)) as replacement:
        replay = replacement.post(IMPORT, json=body(), headers=HEADERS)
        assert replay.json() == first.json()
    assert spawned == [job_id] and len(store.staged) == 1 and len(repo.import_actions) == 1


def test_import_dispatch_failure_retains_reports_and_retry_repairs_dispatch():
    repo, store, spawned = ImportRepository(), Store(), []

    def unavailable(job):
        raise RuntimeError("dispatcher unavailable")

    with TestClient(app(repo, store, unavailable)) as client:
        assert client.post(IMPORT, json=body(), headers=HEADERS).status_code == 503
    assert len(repo.jobs) == 1 and store.deleted == []
    with TestClient(app(repo, store, lambda job: spawned.append(job) or "call-1")) as replacement:
        repaired = replacement.post(IMPORT, json=body(), headers=HEADERS)
        assert repaired.status_code == 202
        assert spawned == [repaired.json()["id"]]
    assert len(store.staged) == 1


def test_import_streaming_body_limit_before_parsing_or_staging():
    repo, store = ImportRepository(), Store()
    with TestClient(app(repo, store, lambda job: "call-1")) as client:
        response = client.post(
            IMPORT,
            content=(b"x" * MAX_GATEWAY_IMPORT_BYTES, b"y"),
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        assert response.status_code == 413
    assert store.staged == [] and repo.import_actions == {}


def test_import_uncertain_commit_acknowledgement_retains_reports_for_replay():
    repo, store = ImportRepository(), Store()
    commit = repo.create_vulnerability_import_job_idempotent

    def lost_ack(tenant, **kwargs):
        commit(tenant, **kwargs)
        raise RuntimeError("commit acknowledgement lost")

    repo.create_vulnerability_import_job_idempotent = lost_ack
    with TestClient(app(repo, store, lambda job: "call-1")) as client:
        assert client.post(IMPORT, json=body(), headers=HEADERS).status_code == 503
    assert len(repo.jobs) == 1 and store.deleted == []
    repo.create_vulnerability_import_job_idempotent = commit
    with TestClient(app(repo, store, lambda job: "call-1")) as replacement:
        assert replacement.post(IMPORT, json=body(), headers=HEADERS).status_code == 202
    assert len(store.staged) == 1 and store.deleted == []


def test_concurrent_losing_retry_cleans_only_its_distinct_staged_objects():
    repo, store = ImportRepository(), Store()
    with TestClient(app(repo, store, lambda job: "call-1")) as client:
        first = client.post(IMPORT, json=body(), headers=HEADERS)
        assert first.status_code == 202
        lookup = repo.gateway_vulnerability_import_action
        calls = []

        def before_winner_commit(tenant, **kwargs):
            calls.append(True)
            return None if len(calls) == 1 else lookup(tenant, **kwargs)

        repo.gateway_vulnerability_import_action = before_winner_commit
        replay = client.post(IMPORT, json=body(), headers=HEADERS)
        assert replay.json() == first.json()
    assert len(repo.jobs) == 1 and len(store.staged) == 2
    losing_job_id = store.staged[-1][1]
    assert losing_job_id != first.json()["id"]
    assert len(store.deleted) == 1
    assert all(losing_job_id in key for key in store.deleted[0])


def test_staging_failure_does_not_record_or_dispatch_job():
    repo, store, spawned = ImportRepository(), Store(), []

    def unavailable(**kwargs):
        raise RuntimeError("evidence staging unavailable")

    store.put_documents = unavailable
    with TestClient(app(repo, store, lambda job: spawned.append(job) or "call-1")) as client:
        assert client.post(IMPORT, json=body(), headers=HEADERS).status_code == 502
    assert repo.jobs == {} and repo.import_actions == {} and spawned == []


def test_exhaustive_public_surface_map_covers_every_explicit_route_and_browser_method():
    root = Path(__file__).resolve().parents[1]
    mapped = json.loads((root / "docs/development/capability-surface.json").read_text())
    actual = set()
    for node in ast.walk(ast.parse((root / "src/denali/api/app.py").read_text())):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for decorator in node.decorator_list:
            if (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Attribute)
                and isinstance(decorator.func.value, ast.Name)
                and decorator.func.value.id == "app"
                and decorator.func.attr in {"get", "post", "patch", "delete", "put"}
                and decorator.args
            ):
                route = ast.literal_eval(decorator.args[0])
                if not route.startswith("/internal/"):
                    actual.add((decorator.func.attr.upper(), route, node.name))
    rows = mapped["operations"]
    assert actual == {
        (row["method"], row["path"], row["handler"])
        for row in rows
        if row["handler"] != "FastAPI-generated"
    }
    assert len(actual) == mapped["explicit_public_operation_count"]
    assert len(rows) == mapped["public_operation_count"]
    assert all(row["disposition"] != "unclassified" for row in rows)
    assert all("browser_methods" in row for row in rows)
    browser = (root / "web/src/api.ts").read_text().split("export const api = {", 1)[1]
    methods = set(re.findall(r"^  (\w+):", browser, re.M))
    assert methods == {method for row in rows for method in row["browser_methods"]}
    assert len(methods) == mapped["browser_operation_count"]
