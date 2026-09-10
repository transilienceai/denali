from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from denali.api.app import DEFAULT_LOCAL_TENANT, create_app
from denali.api.github_oidc import GitHubActionsIdentity

ASSET_ID = "11111111-1111-4111-8111-111111111111"
FINDING_ID = "22222222-2222-4222-8222-222222222222"
ISSUE_ID = "33333333-3333-4333-8333-333333333333"
VULNERABILITY_ID = "55555555-5555-4555-8555-555555555555"
ACTIVITY_ID = "66666666-6666-4666-8666-666666666666"
DETECTION_ID = "77777777-7777-4777-8777-777777777777"
GITHUB_CONNECTION_ID = "88888888-8888-4888-8888-888888888888"
IMAGE_DIGEST = f"sha256:{'a' * 64}"


class RepositoryStub:
    def __init__(self):
        self.governance = "unreviewed"
        self.asset_filters: dict[str, Any] = {}

    def list_assets(
        self,
        tenant_id: str,
        *,
        kind: str | None = None,
        kinds: tuple[str, ...] | None = None,
        lifecycle: str = "active",
        governance: str | None = None,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        assert tenant_id == DEFAULT_LOCAL_TENANT
        self.asset_filters = {
            "kind": kind,
            "kinds": kinds,
            "lifecycle": lifecycle,
            "governance": governance,
            "search": search,
            "limit": limit,
            "offset": offset,
        }
        return [
            {
                "id": ASSET_ID,
                "kind": kind or (kinds or ("ai_agent",))[0],
                "lifecycle_state": lifecycle,
            }
        ]

    def count_assets(
        self,
        tenant_id: str,
        *,
        kind: str | None = None,
        kinds: tuple[str, ...] | None = None,
        lifecycle: str = "active",
        governance: str | None = None,
        search: str | None = None,
    ) -> int:
        assert tenant_id == DEFAULT_LOCAL_TENANT
        return 1

    def get_asset(self, tenant_id: str, asset_id: str) -> dict[str, Any] | None:
        if asset_id != ASSET_ID:
            return None
        return {"id": ASSET_ID, "kind": "ai_agent", "assertions": [], "relationships": []}

    def summary(self, tenant_id: str) -> dict[str, Any]:
        return {"total": 1, "by_kind": {"ai_agent": 1}, "by_governance": {self.governance: 1}}

    def latest_coverage(self, tenant_id: str) -> list[dict[str, Any]]:
        return [{"connector_id": "fixture", "plane": "agents", "state": "complete"}]

    def list_findings(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return [
            {
                "id": FINDING_ID,
                "state": state or "open",
                "severity": severity or "critical",
            }
        ]

    def get_finding(self, tenant_id: str, finding_id: str) -> dict[str, Any] | None:
        if finding_id != FINDING_ID:
            return None
        return {"id": FINDING_ID, "state": "open", "resources": [], "observations": []}

    def finding_summary(self, tenant_id: str) -> dict[str, Any]:
        return {
            "total": 1,
            "by_state": {"open": 1},
            "open_by_severity": {"critical": 1},
        }

    def list_vulnerabilities(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return [
            {
                "id": VULNERABILITY_ID,
                "state": state or "open",
                "severity": severity or "critical",
            }
        ]

    def get_vulnerability(self, tenant_id: str, vulnerability_id: str) -> dict[str, Any] | None:
        if vulnerability_id != VULNERABILITY_ID:
            return None
        return {
            "id": VULNERABILITY_ID,
            "state": "open",
            "component": {},
            "target": {},
            "observations": [],
        }

    def vulnerability_summary(self, tenant_id: str) -> dict[str, Any]:
        return {
            "total": 1,
            "by_state": {"open": 1},
            "open_by_severity": {"critical": 1},
            "open_by_exploit_state": {"known_exploited": 1},
        }

    def list_issues(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return [
            {
                "id": ISSUE_ID,
                "state": state or "open",
                "severity": severity or "critical",
            }
        ]

    def get_issue(self, tenant_id: str, issue_id: str) -> dict[str, Any] | None:
        if issue_id != ISSUE_ID:
            return None
        return {"id": ISSUE_ID, "state": "open", "findings": [], "path_nodes": []}

    def issue_summary(self, tenant_id: str) -> dict[str, Any]:
        return {
            "total": 1,
            "by_state": {"open": 1},
            "open_by_severity": {"critical": 1},
        }

    def latest_issue_evaluations(self, tenant_id: str) -> list[dict[str, Any]]:
        return [{"rule_uid": "rule-1", "state": "complete", "confirmed_issues": 1}]

    def code_to_cloud_deployments(self, tenant_id: str) -> list[dict[str, Any]]:
        return [{"id": "deployment-1", "repository_name": "anna", "workload_name": "api"}]

    def code_to_cloud_observations(self, tenant_id: str) -> list[dict[str, Any]]:
        return [
            {
                "connection_id": "github-fixture",
                "repository_natural_key": "github.com/acme/agent",
                "source_state": "complete",
                "analysis_state": "complete",
                "correlation_summary": {
                    "declarations": 1,
                    "proven": 0,
                    "ambiguous": 0,
                    "unmatched": 1,
                    "targets_evaluated": 0,
                },
                "correlation_candidates": [],
            }
        ]

    def list_activity(
        self,
        tenant_id: str,
        *,
        category: str | None = None,
        outcome: str | None = None,
        asset_id: str | None = None,
        include_fixtures: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        return [
            {
                "id": ACTIVITY_ID,
                "category": category or "model_invocation",
                "outcome": outcome or "success",
            }
        ]

    def get_activity(self, tenant_id: str, activity_id: str) -> dict[str, Any] | None:
        if activity_id != ACTIVITY_ID:
            return None
        return {"id": ACTIVITY_ID, "category": "model_invocation", "entities": []}

    def activity_summary(self, tenant_id: str, *, include_fixtures: bool = False) -> dict[str, Any]:
        return {
            "total": 1,
            "last_24h": 1,
            "providers": 1,
            "failures": 0,
            "fixture_total": 0,
            "by_category": {"model_invocation": 1},
        }

    def list_runtime_detections(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        assert tenant_id == DEFAULT_LOCAL_TENANT
        return [
            {
                "id": DETECTION_ID,
                "state": state or "open",
                "severity": severity or "high",
            }
        ]

    def get_runtime_detection(self, tenant_id: str, detection_id: str) -> dict[str, Any] | None:
        if detection_id != DETECTION_ID:
            return None
        return {
            "id": DETECTION_ID,
            "state": "open",
            "severity": "high",
            "activities": [],
            "assets": [],
        }

    def runtime_detection_summary(self, tenant_id: str) -> dict[str, Any]:
        return {
            "total": 1,
            "by_state": {"open": 1},
            "open_by_severity": {"high": 1},
        }

    def latest_runtime_detection_evaluations(self, tenant_id: str) -> list[dict[str, Any]]:
        return [
            {
                "rule_uid": "DENALI-RUNTIME-ENTRA-CONSENT-001",
                "state": "complete",
                "confirmed_detections": 1,
            }
        ]

    def set_governance(
        self,
        tenant_id: str,
        asset_id: str,
        *,
        status: str,
        owner: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None:
        if asset_id != ASSET_ID:
            return None
        self.governance = status
        return {"id": asset_id, "governance_status": status, "owner": owner, "notes": notes}


def client() -> TestClient:
    return TestClient(create_app(repository=RepositoryStub(), migrate_on_start=False))


def test_inventory_surface() -> None:
    with client() as test_client:
        assert test_client.get("/", follow_redirects=False).headers["location"] == (
            "http://127.0.0.1:3080"
        )
        assert test_client.get("/healthz").json()["status"] == "ready"
        assert test_client.get("/v1/inventory/summary").json()["total"] == 1
        rows = test_client.get("/v1/inventory/assets?kind=ai_agent").json()["items"]
        assert rows[0]["kind"] == "ai_agent"
        assert test_client.get(f"/v1/inventory/assets/{ASSET_ID}").status_code == 200
        assert test_client.get("/v1/sources/coverage").json()["items"][0]["state"] == "complete"


def test_inventory_categories_and_server_side_filters() -> None:
    repository = RepositoryStub()
    with TestClient(create_app(repository=repository, migrate_on_start=False)) as test_client:
        response = test_client.get(
            "/v1/inventory/assets",
            params={
                "category": "components",
                "governance": "unreviewed",
                "q": "  boto3  ",
                "limit": 50,
                "offset": 100,
            },
        )
        assert response.status_code == 200
        assert response.json() == {
            "items": [
                {
                    "id": ASSET_ID,
                    "kind": "software_component",
                    "lifecycle_state": "active",
                }
            ],
            "total": 1,
            "limit": 50,
            "offset": 100,
            "category": "components",
        }
        assert repository.asset_filters == {
            "kind": None,
            "kinds": ("software_component",),
            "lifecycle": "active",
            "governance": "unreviewed",
            "search": "boto3",
            "limit": 50,
            "offset": 100,
        }


def test_inventory_rejects_invalid_category_and_governance() -> None:
    with client() as test_client:
        assert test_client.get("/v1/inventory/assets?category=packages").status_code == 422
        assert test_client.get("/v1/inventory/assets?governance=maybe").status_code == 422


def test_missing_asset_is_404() -> None:
    with client() as test_client:
        response = test_client.get("/v1/inventory/assets/does-not-exist")
        assert response.status_code == 404


def test_findings_surface_and_filters() -> None:
    with client() as test_client:
        assert test_client.get("/v1/findings/summary").json()["total"] == 1
        response = test_client.get("/v1/findings?state=open&severity=critical")
        assert response.status_code == 200
        assert response.json()["items"][0]["id"] == FINDING_ID
        assert test_client.get(f"/v1/findings/{FINDING_ID}").status_code == 200
        assert test_client.get("/v1/findings/not-found").status_code == 404
        assert test_client.get("/v1/findings?state=probably-open").status_code == 422


def test_activity_surface_and_filters() -> None:
    with client() as test_client:
        assert test_client.get("/v1/activity/summary").json()["last_24h"] == 1
        response = test_client.get("/v1/activity?category=model_invocation&outcome=success")
        assert response.status_code == 200
        assert response.json()["items"][0]["id"] == ACTIVITY_ID
        assert test_client.get(f"/v1/activity?asset_id={ASSET_ID}").status_code == 200
        assert test_client.get("/v1/activity?asset_id=not-a-uuid").status_code == 422
        assert test_client.get(f"/v1/activity/{ACTIVITY_ID}").status_code == 200
        assert test_client.get("/v1/activity/not-a-uuid").status_code == 422
        assert test_client.get("/v1/activity?category=threat").status_code == 422
        assert test_client.get("/v1/activity?include_fixtures=true").status_code == 200
        assert test_client.get("/v1/activity/summary?include_fixtures=true").status_code == 200


def test_runtime_detections_surface_and_filters() -> None:
    with client() as test_client:
        assert test_client.get("/v1/detections/summary").json()["total"] == 1
        response = test_client.get("/v1/detections?state=open&severity=high")
        assert response.status_code == 200
        assert response.json()["items"][0]["id"] == DETECTION_ID
        evaluations = test_client.get("/v1/detections/evaluations").json()["items"]
        assert evaluations[0]["state"] == "complete"
        assert test_client.get(f"/v1/detections/{DETECTION_ID}").status_code == 200
        assert (
            test_client.get("/v1/detections/44444444-4444-4444-8444-444444444444").status_code
            == 404
        )
        assert test_client.get("/v1/detections/not-a-uuid").status_code == 422
        assert test_client.get("/v1/detections?state=probably-open").status_code == 422
        assert test_client.get("/v1/detections?severity=catastrophic").status_code == 422


def test_issues_surface_and_evaluation_coverage() -> None:
    with client() as test_client:
        assert test_client.get("/v1/issues/summary").json()["total"] == 1
        response = test_client.get("/v1/issues?state=open&severity=critical")
        assert response.status_code == 200
        assert response.json()["items"][0]["id"] == ISSUE_ID
        assert test_client.get("/v1/issues/evaluations").json()["items"][0]["state"] == "complete"
        assert test_client.get(f"/v1/issues/{ISSUE_ID}").status_code == 200
        assert test_client.get("/v1/issues/44444444-4444-4444-8444-444444444444").status_code == 404
        assert test_client.get("/v1/issues/not-a-uuid").status_code == 422
        assert test_client.get("/v1/issues?state=probably-open").status_code == 422


def test_code_to_cloud_surface() -> None:
    with client() as test_client:
        response = test_client.get("/v1/code-to-cloud/deployments")
        assert response.status_code == 200
        assert response.json()["items"][0]["repository_name"] == "anna"
        observations = test_client.get("/v1/code-to-cloud/observations")
        assert observations.status_code == 200
        assert observations.json()["items"][0]["correlation_summary"]["unmatched"] == 1


def test_vulnerability_surface_and_filters() -> None:
    with client() as test_client:
        summary = test_client.get("/v1/vulnerabilities/summary").json()
        assert summary["open_by_exploit_state"] == {"known_exploited": 1}
        response = test_client.get("/v1/vulnerabilities?state=open&severity=critical")
        assert response.status_code == 200
        assert response.json()["items"][0]["id"] == VULNERABILITY_ID
        assert test_client.get(f"/v1/vulnerabilities/{VULNERABILITY_ID}").status_code == 200
        assert (
            test_client.get("/v1/vulnerabilities/44444444-4444-4444-8444-444444444444").status_code
            == 404
        )
        assert test_client.get("/v1/vulnerabilities/not-a-uuid").status_code == 422
        assert test_client.get("/v1/vulnerabilities?severity=catastrophic").status_code == 422


class VulnerabilityImportRepositoryStub(RepositoryStub):
    def __init__(self):
        super().__init__()
        self.job: dict[str, Any] | None = None

    def get_asset(self, tenant_id: str, asset_id: str) -> dict[str, Any] | None:
        if asset_id != ASSET_ID:
            return None
        return {
            "id": ASSET_ID,
            "kind": "ai_workload",
            "natural_key": "arn:aws:lambda:us-east-1:123:function:demo",
            "display_name": "Demo workload",
            "lifecycle_state": "active",
        }

    def create_vulnerability_import_job(self, tenant_id: str, **values: Any) -> dict[str, Any]:
        self.job = {"id": values["job_id"], "state": "queued", **values}
        return self.job

    def set_vulnerability_import_call_id(self, job_id: str, call_id: str) -> None:
        assert self.job is not None
        self.job["modal_call_id"] = call_id

    def fail_vulnerability_import_job(self, job_id: str, summary: str) -> None:
        assert self.job is not None
        self.job.update(state="failed", error_summary=summary)

    def vulnerability_import_status(self, tenant_id: str, job_id: str) -> dict[str, Any] | None:
        if self.job is None or self.job["id"] != job_id:
            return None
        return {
            "id": job_id,
            "target_asset_id": self.job["target_asset_id"],
            "state": self.job["state"],
            "attempt_count": 0,
            "result": None,
            "error_summary": None,
        }

    def github_ci_repository_context(
        self, connection_id: str, *, repository_id: int, repository_full_name: str
    ) -> dict[str, Any] | None:
        if (
            connection_id != GITHUB_CONNECTION_ID
            or repository_id != 12345
            or repository_full_name.casefold() != "example/anna"
        ):
            return None
        return {
            "tenant_id": DEFAULT_LOCAL_TENANT,
            "connection_id": connection_id,
            "repository_id": repository_id,
            "repository_full_name": repository_full_name,
            "repository_owner_id": 456,
            "default_branch": "main",
        }

    def resolve_workload_by_image_digest(self, tenant_id: str, image_digest: str) -> dict[str, Any]:
        assert tenant_id == DEFAULT_LOCAL_TENANT
        if image_digest != IMAGE_DIGEST:
            raise ValueError("No active cloud-observed workload has this exact image digest.")
        return {"id": ASSET_ID, "display_name": "Demo workload"}

    def create_github_vulnerability_import_upload(
        self, tenant_id: str, **values: Any
    ) -> tuple[dict[str, Any], bool]:
        self.job = {"id": values["job_id"], "state": "staging", **values}
        return self.job, False

    def github_vulnerability_import_upload(
        self, tenant_id: str, **values: Any
    ) -> dict[str, Any] | None:
        if self.job is None or self.job["id"] != values["job_id"]:
            return None
        return self.job

    def queue_github_vulnerability_import_job(
        self, tenant_id: str, **values: Any
    ) -> tuple[dict[str, Any], bool]:
        assert self.job is not None
        self.job["state"] = "queued"
        return self.job, True


class EvidenceStoreStub:
    def __init__(self):
        self.documents: dict[str, bytes] = {}
        self.deleted: list[tuple[str, ...]] = []

    def put_documents(
        self, *, tenant_id: str, job_id: str, documents: dict[str, bytes]
    ) -> dict[str, str]:
        self.documents = dict(documents)
        return {"syft": "private/syft.json", "grype": "private/grype.json"}

    def get_document(self, object_key: str) -> Any:
        raise AssertionError("API containers must not process staged reports")

    def delete_documents(self, object_keys: tuple[str, ...]) -> None:
        self.deleted.append(object_keys)

    def staged_object_keys(self, *, tenant_id: str, job_id: str) -> dict[str, str]:
        return {
            "syft": f"private/{tenant_id}/{job_id}/syft.json",
            "grype": f"private/{tenant_id}/{job_id}/grype.json",
        }

    def create_upload(
        self, *, object_key: str, sha256_hex: str, expires_in_seconds: int
    ) -> dict[str, Any]:
        assert 60 <= expires_in_seconds <= 600
        return {
            "url": f"https://uploads.example/{object_key}",
            "headers": {"x-amz-checksum-sha256": sha256_hex},
        }

    def verify_upload(self, *, object_key: str, size_bytes: int, sha256_hex: str) -> None:
        assert object_key.startswith("private/")
        assert size_bytes == 100
        assert len(sha256_hex) == 64


class GitHubTokenVerifierStub:
    def __init__(self, *, ref: str = "refs/heads/main"):
        self.ref = ref

    def verify(self, token: str, *, audience: str) -> GitHubActionsIdentity:
        assert token == "signed-github-token"
        assert audience.endswith(f"/api/v1/ci/github/{GITHUB_CONNECTION_ID}")
        return GitHubActionsIdentity(
            repository="example/anna",
            repository_id=12345,
            repository_owner_id=456,
            run_id=789,
            run_attempt=1,
            ref=self.ref,
            workflow_ref=f"example/anna/.github/workflows/deploy.yml@{self.ref}",
            workflow_sha="b" * 40,
            event_name="push",
        )


class MissingDigestRepositoryStub(VulnerabilityImportRepositoryStub):
    def __init__(self):
        super().__init__()
        self.collection_job: dict[str, Any] | None = None

    def resolve_workload_by_image_digest(self, tenant_id: str, image_digest: str) -> dict[str, Any]:
        raise ValueError(
            "No active cloud-observed workload has this exact image digest. "
            "Run provider collection after deployment and retry."
        )

    def list_healthy_connection_ids(
        self, tenant_id: str, *, provider: str, limit: int = 50
    ) -> list[str]:
        return ["99999999-9999-4999-8999-999999999999"] if provider == "aws" else []

    def get_connection_validation_target(
        self, tenant_id: str, connection_id: str
    ) -> dict[str, Any] | None:
        return {"id": connection_id, "provider": "aws", "lifecycle_state": "active"}

    def create_connection_collection_job(
        self, tenant_id: str, connection_id: str, *, collection_kind: str
    ) -> tuple[dict[str, Any], bool]:
        self.collection_job = {
            "id": "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
            "connection_id": connection_id,
            "collection_kind": collection_kind,
        }
        return self.collection_job, True

    def set_connection_collection_call_id(self, job_id: str, call_id: str) -> None:
        assert self.collection_job is not None
        self.collection_job["modal_call_id"] = call_id


def test_vulnerability_import_is_staged_and_durably_dispatched() -> None:
    repository = VulnerabilityImportRepositoryStub()
    store = EvidenceStoreStub()
    dispatched: list[str] = []
    app = create_app(
        repository=repository,
        evidence_report_store=store,
        vulnerability_import_dispatcher=lambda job_id: dispatched.append(job_id) or "call-1",
        migrate_on_start=False,
    )
    payload = {
        "target_asset_id": ASSET_ID,
        "syft_report": {
            "artifacts": [],
            "descriptor": {"name": "syft"},
            "source": {"type": "image", "name": "registry.example/demo:sha"},
        },
        "grype_report": {
            "matches": [],
            "ignoredMatches": [],
            "descriptor": {"name": "grype"},
            "source": {"type": "image", "target": "registry.example/demo:sha"},
        },
        "authoritative": True,
    }

    with TestClient(app) as test_client:
        response = test_client.post("/v1/vulnerabilities/imports", json=payload)
        assert response.status_code == 202
        job_id = response.json()["id"]
        assert dispatched == [job_id]
        assert repository.job is not None
        assert repository.job["target_asset_id"] == ASSET_ID
        assert repository.job["modal_call_id"] == "call-1"
        assert set(store.documents) == {"syft", "grype"}
        status = test_client.get(f"/v1/vulnerabilities/imports/{job_id}")
        assert status.status_code == 200
        assert status.json()["state"] == "queued"


def test_vulnerability_import_rejects_non_workload_target_before_staging() -> None:
    repository = VulnerabilityImportRepositoryStub()
    store = EvidenceStoreStub()
    app = create_app(
        repository=repository,
        evidence_report_store=store,
        vulnerability_import_dispatcher=lambda job_id: job_id,
        migrate_on_start=False,
    )

    with TestClient(app) as test_client:
        response = test_client.post(
            "/v1/vulnerabilities/imports",
            json={
                "target_asset_id": "99999999-9999-4999-8999-999999999999",
                "syft_report": {},
                "grype_report": {},
            },
        )
    assert response.status_code == 404
    assert store.documents == {}


def test_github_workflow_upload_is_oidc_bound_digest_resolved_and_durably_dispatched() -> None:
    repository = VulnerabilityImportRepositoryStub()
    store = EvidenceStoreStub()
    dispatched: list[str] = []
    app = create_app(
        repository=repository,
        evidence_report_store=store,
        github_actions_token_verifier=GitHubTokenVerifierStub(),
        vulnerability_import_dispatcher=lambda job_id: dispatched.append(job_id) or "call-ci",
        migrate_on_start=False,
    )
    headers = {"Authorization": "Bearer signed-github-token"}
    payload = {
        "image_digest": IMAGE_DIGEST,
        "syft": {"size_bytes": 100, "sha256": "c" * 64},
        "grype": {"size_bytes": 100, "sha256": "d" * 64},
        "authoritative": True,
    }

    with TestClient(app) as test_client:
        created = test_client.post(
            f"/v1/ci/github/{GITHUB_CONNECTION_ID}/vulnerability-imports",
            headers=headers,
            json=payload,
        )
        assert created.status_code == 201
        assert created.headers["cache-control"] == "no-store"
        assert created.json()["state"] == "staging"
        assert set(created.json()["uploads"]) == {"syft", "grype"}
        job_id = created.json()["id"]
        completed = test_client.post(
            f"/v1/ci/github/{GITHUB_CONNECTION_ID}/vulnerability-imports/{job_id}/complete",
            headers=headers,
        )
        status = test_client.get(
            f"/v1/ci/github/{GITHUB_CONNECTION_ID}/vulnerability-imports/{job_id}",
            headers=headers,
        )

    assert completed.status_code == 202
    assert completed.json()["state"] == "queued"
    assert status.status_code == 200
    assert status.json()["state"] == "queued"
    assert dispatched == [job_id]
    assert repository.job is not None
    assert repository.job["target_asset_id"] == ASSET_ID
    assert repository.job["source_repository_id"] == 12345
    assert repository.job["source_image_digest"] == IMAGE_DIGEST
    assert repository.job["modal_call_id"] == "call-ci"


def test_github_workflow_upload_rejects_missing_token_and_non_default_branch() -> None:
    repository = VulnerabilityImportRepositoryStub()
    payload = {
        "image_digest": IMAGE_DIGEST,
        "syft": {"size_bytes": 100, "sha256": "c" * 64},
        "grype": {"size_bytes": 100, "sha256": "d" * 64},
    }
    app = create_app(
        repository=repository,
        evidence_report_store=EvidenceStoreStub(),
        github_actions_token_verifier=GitHubTokenVerifierStub(ref="refs/heads/feature"),
        vulnerability_import_dispatcher=lambda job_id: job_id,
        migrate_on_start=False,
    )

    with TestClient(app) as test_client:
        missing = test_client.post(
            f"/v1/ci/github/{GITHUB_CONNECTION_ID}/vulnerability-imports",
            json=payload,
        )
        wrong_branch = test_client.post(
            f"/v1/ci/github/{GITHUB_CONNECTION_ID}/vulnerability-imports",
            headers={"Authorization": "Bearer signed-github-token"},
            json=payload,
        )

    assert missing.status_code == 401
    assert wrong_branch.status_code == 403
    assert repository.job is None


def test_github_workflow_upload_never_accepts_a_client_tenant_or_workload() -> None:
    repository = VulnerabilityImportRepositoryStub()
    app = create_app(
        repository=repository,
        evidence_report_store=EvidenceStoreStub(),
        github_actions_token_verifier=GitHubTokenVerifierStub(),
        vulnerability_import_dispatcher=lambda job_id: job_id,
        migrate_on_start=False,
    )
    payload = {
        "tenant_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        "target_asset_id": ASSET_ID,
        "image_digest": IMAGE_DIGEST,
        "syft": {"size_bytes": 100, "sha256": "c" * 64},
        "grype": {"size_bytes": 100, "sha256": "d" * 64},
    }

    with TestClient(app) as test_client:
        response = test_client.post(
            f"/v1/ci/github/{GITHUB_CONNECTION_ID}/vulnerability-imports",
            headers={"Authorization": "Bearer signed-github-token"},
            json=payload,
        )

    assert response.status_code == 422
    assert repository.job is None


def test_github_workflow_missing_digest_starts_durable_cloud_refresh() -> None:
    repository = MissingDigestRepositoryStub()
    dispatched: list[str] = []
    app = create_app(
        repository=repository,
        evidence_report_store=EvidenceStoreStub(),
        github_actions_token_verifier=GitHubTokenVerifierStub(),
        collection_dispatcher=lambda job_id: dispatched.append(job_id) or "collect-call",
        vulnerability_import_dispatcher=lambda job_id: job_id,
        migrate_on_start=False,
    )
    payload = {
        "image_digest": IMAGE_DIGEST,
        "syft": {"size_bytes": 100, "sha256": "c" * 64},
        "grype": {"size_bytes": 100, "sha256": "d" * 64},
    }

    with TestClient(app) as test_client:
        response = test_client.post(
            f"/v1/ci/github/{GITHUB_CONNECTION_ID}/vulnerability-imports",
            headers={"Authorization": "Bearer signed-github-token"},
            json=payload,
        )

    assert response.status_code == 409
    assert response.headers["retry-after"] == "20"
    assert "started a fresh cloud collection" in response.json()["detail"]
    assert dispatched == ["aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"]
    assert repository.collection_job is not None
    assert repository.collection_job["collection_kind"] == "aws_deployments"
    assert repository.collection_job["modal_call_id"] == "collect-call"


def test_governance_update_is_validated_and_persisted() -> None:
    with client() as test_client:
        response = test_client.patch(
            f"/v1/inventory/assets/{ASSET_ID}/governance",
            json={"status": "approved", "owner": "platform-security"},
        )
        assert response.status_code == 200
        assert response.json()["governance_status"] == "approved"
        invalid = test_client.patch(
            f"/v1/inventory/assets/{ASSET_ID}/governance",
            json={"status": "probably-safe"},
        )
        assert invalid.status_code == 422


def test_unconfigured_storage_fails_explicitly() -> None:
    app = create_app(repository=None, migrate_on_start=False)
    with TestClient(app) as test_client:
        assert test_client.get("/healthz").json()["status"] == "storage_unconfigured"
        assert test_client.get("/v1/inventory/summary").status_code == 503
