from typing import Any

from denali.connectors.gcp_deployments import (
    CLOUD_FUNCTION_ASSET_TYPE,
    CLOUD_FUNCTION_INVENTORY_PLANE,
    CLOUD_RUN_ASSET_TYPE,
    CLOUD_RUN_INVENTORY_PLANE,
    GKE_CLUSTER_ASSET_TYPE,
    GcpCloudAssetRestClient,
    GcpConnectionDeploymentCollector,
    GcpDeploymentConnector,
    GcpDeploymentDiscoveryError,
)
from denali.domain import AssetKind, CoverageState, RelationshipKind

PROJECT = "denali-test"


def run_asset(*, name: str, ai: bool) -> dict[str, Any]:
    environment = (
        [
            {"name": "VERTEX_MODEL_ID", "value": "gemini-2.5-flash"},
            {"name": "API_TOKEN", "value": "secret-model-value"},
        ]
        if ai
        else [{"name": "LOG_LEVEL", "value": "debug"}]
    )
    return {
        "name": f"//run.googleapis.com/projects/{PROJECT}/locations/us-central1/services/{name}",
        "assetType": CLOUD_RUN_ASSET_TYPE,
        "ancestors": ["projects/123456789012"],
        "resource": {
            "data": {
                "name": f"projects/{PROJECT}/locations/us-central1/services/{name}",
                "uid": f"uid-{name}",
                "updateTime": "2026-08-31T12:00:00Z",
                "latestReadyRevision": f"{name}-00001-abc",
                "uri": f"https://{name}.example.test",
                "terminalCondition": {"state": "CONDITION_SUCCEEDED"},
                "template": {
                    "serviceAccount": f"{name}@{PROJECT}.iam.gserviceaccount.com",
                    "containers": [
                        {
                            "image": f"us-central1-docker.pkg.dev/{PROJECT}/apps/{name}@sha256:abc",
                            "env": environment,
                        }
                    ],
                },
            }
        },
    }


def function_asset() -> dict[str, Any]:
    name = "denali-function"
    return {
        "name": (
            f"//cloudfunctions.googleapis.com/projects/{PROJECT}/locations/"
            f"us-central1/functions/{name}"
        ),
        "assetType": CLOUD_FUNCTION_ASSET_TYPE,
        "ancestors": ["projects/123456789012"],
        "resource": {
            "data": {
                "name": f"projects/{PROJECT}/locations/us-central1/functions/{name}",
                "environment": "GEN_2",
                "labels": {"denali_ai_workload": "true"},
                "state": "ACTIVE",
                "updateTime": "2026-08-31T12:00:00Z",
                "serviceConfig": {
                    "serviceAccountEmail": (
                        f"{name}@{PROJECT}.iam.gserviceaccount.com"
                    ),
                    "revision": f"{name}-00001-xyz",
                    "uri": f"https://{name}.example.test",
                    "environmentVariables": {"API_TOKEN": "do-not-persist"},
                },
            }
        },
    }


def run_asset_v1() -> dict[str, Any]:
    name = "denali-v1"
    return {
        "name": f"//run.googleapis.com/projects/{PROJECT}/locations/us-central1/services/{name}",
        "assetType": CLOUD_RUN_ASSET_TYPE,
        "resource": {
            "data": {
                "apiVersion": "serving.knative.dev/v1",
                "kind": "Service",
                "metadata": {
                    "name": name,
                    "namespace": "123456789012",
                    "uid": "uid-v1",
                    "labels": {"denali_ai_workload": "true"},
                    "creationTimestamp": "2026-08-31T12:00:00Z",
                },
                "spec": {
                    "template": {
                        "spec": {
                            "serviceAccountName": (
                                f"{name}@{PROJECT}.iam.gserviceaccount.com"
                            ),
                            "containers": [
                                {
                                    "image": f"gcr.io/{PROJECT}/{name}@sha256:def",
                                    "env": [{"name": "API_TOKEN", "value": "private"}],
                                }
                            ],
                        }
                    }
                },
                "status": {
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "latestReadyRevisionName": f"{name}-00001-def",
                    "url": f"https://{name}.example.test",
                },
            }
        },
    }


def gke_cluster() -> dict[str, Any]:
    name = "model-cluster"
    return {
        "name": (
            f"//container.googleapis.com/projects/{PROJECT}/locations/"
            f"us-central1/clusters/{name}"
        ),
        "assetType": GKE_CLUSTER_ASSET_TYPE,
        "ancestors": ["projects/123456789012"],
        "resource": {
            "data": {
                "name": f"projects/{PROJECT}/locations/us-central1/clusters/{name}",
                "id": "cluster-uid-1",
                "status": "RUNNING",
                "currentMasterVersion": "1.34.1-gke.1",
                "createTime": "2026-08-31T12:00:00Z",
                "endpoint": "10.0.0.1",
            }
        },
    }


class FakeAssetClient:
    def __init__(self, records: dict[str, tuple[dict[str, Any], ...]]):
        self.records = records
        self.calls: list[tuple[str, str]] = []

    def list_assets(self, *, project_id: str, asset_type: str) -> tuple[dict[str, Any], ...]:
        self.calls.append((project_id, asset_type))
        return self.records.get(asset_type, ())


def test_collects_bounded_gcp_deployments_without_environment_values() -> None:
    client = FakeAssetClient(
        {
            CLOUD_RUN_ASSET_TYPE: (
                run_asset(name="denali-ai", ai=True),
                run_asset(name="ordinary-service", ai=False),
            ),
            CLOUD_FUNCTION_ASSET_TYPE: (function_asset(),),
            GKE_CLUSTER_ASSET_TYPE: (gke_cluster(),),
        }
    )

    batch = GcpDeploymentConnector(project_id=PROJECT, asset_client=client).collect()

    assert {item.state for item in batch.coverage} == {CoverageState.COMPLETE}
    assert client.calls == [
        (PROJECT, CLOUD_RUN_ASSET_TYPE),
        (PROJECT, CLOUD_FUNCTION_ASSET_TYPE),
        (PROJECT, GKE_CLUSTER_ASSET_TYPE),
    ]
    workloads = [item for item in batch.assets if item.asset.kind is AssetKind.AI_WORKLOAD]
    cloud_resources = [
        item for item in batch.assets if item.asset.kind is AssetKind.CLOUD_RESOURCE
    ]
    assert {item.display_name for item in workloads} == {
        "denali-ai",
        "denali-function",
    }
    assert {item.display_name for item in cloud_resources} == {
        "denali-ai",
        "ordinary-service",
        "denali-function",
        "model-cluster",
    }
    run_workload = next(item for item in workloads if item.display_name == "denali-ai")
    assert run_workload.attributes["deployment_identifiers"] == {
        "project": [PROJECT],
        "project_number": ["123456789012"],
        "location": ["us-central1"],
        "service_name": ["denali-ai"],
    }
    assert run_workload.attributes["deployment_artifact"]["image"].endswith(
        "@sha256:abc"
    )
    assert run_workload.attributes["model_configuration_keys"] == ["VERTEX_MODEL_ID"]
    assert run_workload.attributes["model_configuration"] == {
        "VERTEX_MODEL_ID": "gemini-2.5-flash"
    }
    serialized = repr(batch)
    assert "secret-model-value" not in serialized
    assert "do-not-persist" not in serialized
    assert {item.kind for item in batch.relationships} == {
        RelationshipKind.HOSTED_ON,
        RelationshipKind.RUNS_AS,
        RelationshipKind.USES,
    }
    model = next(item for item in batch.assets if item.asset.kind is AssetKind.AI_MODEL)
    assert model.asset.natural_key == "gcp:vertex:model:gemini-2.5-flash"
    assert model.attributes == {
        "provider": "gcp_vertex_ai",
        "model_id": "gemini-2.5-flash",
    }


def test_asset_type_failures_are_isolated_by_coverage_plane() -> None:
    class PartiallyBrokenClient(FakeAssetClient):
        def list_assets(
            self, *, project_id: str, asset_type: str
        ) -> tuple[dict[str, Any], ...]:
            if asset_type == CLOUD_RUN_ASSET_TYPE:
                raise GcpDeploymentDiscoveryError("cloudasset:ListAssets:403")
            return (function_asset(),)

    batch = GcpDeploymentConnector(
        project_id=PROJECT,
        asset_client=PartiallyBrokenClient({}),
    ).collect()
    by_plane = {item.plane: item for item in batch.coverage}

    assert by_plane[CLOUD_RUN_INVENTORY_PLANE].state is CoverageState.FAILED
    assert by_plane[CLOUD_FUNCTION_INVENTORY_PLANE].state is CoverageState.COMPLETE
    assert "403" in (by_plane[CLOUD_RUN_INVENTORY_PLANE].detail or "")
    assert all("secret" not in (item.detail or "") for item in batch.coverage)


def test_exact_resource_name_boundary_excludes_other_project_services() -> None:
    selected = run_asset(name="summit", ai=True)
    client = FakeAssetClient(
        {
            CLOUD_RUN_ASSET_TYPE: (
                selected,
                run_asset(name="older-fixture", ai=True),
            )
        }
    )

    batch = GcpDeploymentConnector(
        project_id=PROJECT,
        asset_client=client,
        included_resource_names=(selected["name"],),
        resource_display_names={selected["name"]: "Summit"},
    ).collect()

    assert {item.display_name for item in batch.assets} == {
        "Summit",
        "gemini-2.5-flash",
        f"summit@{PROJECT}.iam.gserviceaccount.com",
    }
    run_coverage = next(
        item for item in batch.coverage if item.plane == CLOUD_RUN_INVENTORY_PLANE
    )
    assert "selected 1 by exact resource name" in (run_coverage.detail or "")


def test_cloud_asset_knative_v1_service_shape_is_normalized() -> None:
    client = FakeAssetClient({CLOUD_RUN_ASSET_TYPE: (run_asset_v1(),)})

    batch = GcpDeploymentConnector(project_id=PROJECT, asset_client=client).collect()

    workload = next(item for item in batch.assets if item.asset.kind is AssetKind.AI_WORKLOAD)
    assert workload.display_name == "denali-v1"
    assert workload.attributes["project_number"] == "123456789012"
    assert workload.attributes["revision"] == "denali-v1-00001-def"
    assert workload.attributes["state"] == "True"
    assert workload.attributes["deployment_artifact"]["image"].endswith("@sha256:def")
    assert "private" not in repr(batch)


def test_mismatched_resource_identity_is_partial_and_not_ingested() -> None:
    escaped = run_asset(name="denali-ai", ai=True)
    escaped["name"] = escaped["name"].replace(PROJECT, "other-project")
    client = FakeAssetClient({CLOUD_RUN_ASSET_TYPE: (escaped,)})

    batch = GcpDeploymentConnector(project_id=PROJECT, asset_client=client).collect()
    by_plane = {item.plane: item for item in batch.coverage}

    assert by_plane[CLOUD_RUN_INVENTORY_PLANE].state is CoverageState.PARTIAL
    assert "escaped the selected project" in (
        by_plane[CLOUD_RUN_INVENTORY_PLANE].detail or ""
    )
    assert batch.assets == ()


def test_rest_client_paginates_with_resource_content_and_exact_asset_type() -> None:
    calls: list[dict[str, Any]] = []

    class Response:
        def __init__(self, payload: dict[str, Any]):
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return self.payload

    pages = [
        Response({"assets": [run_asset(name="one", ai=False)], "nextPageToken": "next"}),
        Response({"assets": [run_asset(name="two", ai=False)]}),
    ]

    def request(method: str, url: str, **kwargs: Any) -> Response:
        calls.append({"method": method, "url": url, **kwargs})
        return pages.pop(0)

    records = GcpCloudAssetRestClient(request).list_assets(
        project_id=PROJECT,
        asset_type=CLOUD_RUN_ASSET_TYPE,
    )

    assert len(records) == 2
    assert calls[0]["url"].endswith(f"/projects/{PROJECT}/assets")
    assert ("assetTypes", CLOUD_RUN_ASSET_TYPE) in calls[0]["params"]
    assert ("contentType", "RESOURCE") in calls[0]["params"]
    assert ("pageToken", "next") in calls[1]["params"]


def test_connection_collector_uses_selected_project_number_and_persists_batch() -> None:
    client = FakeAssetClient({CLOUD_RUN_ASSET_TYPE: (run_asset(name="denali-ai", ai=True),)})
    principals: list[str] = []

    class Sink:
        def __init__(self):
            self.batches = []

        def ingest(self, tenant_id: str, batch: Any) -> dict[str, int]:
            assert tenant_id == "tenant"
            self.batches.append(batch)
            return {"assets": len(batch.assets)}

    sink = Sink()
    collector = GcpConnectionDeploymentCollector(
        asset_client_factory=lambda principal: (principals.append(principal) or client)
    )
    result = collector.collect(
        tenant_id="tenant",
        connection={
            "id": "connection",
            "provider": "gcp",
            "lifecycle_state": "active",
            "declared_scopes": ["gcp.code_to_cloud"],
            "credential_reference": {
                "principal_email": "denali@operator.iam.gserviceaccount.com"
            },
            "configuration": {
                "projects": [
                    {"id": PROJECT, "number": "123456789012", "name": "Denali Test"}
                ],
                "resource_names": [
                    f"//run.googleapis.com/projects/{PROJECT}/locations/us-central1/services/denali-ai"
                ],
                "resource_display_names": {
                    (
                        f"//run.googleapis.com/projects/{PROJECT}/locations/"
                        "us-central1/services/denali-ai"
                    ): "Summit"
                },
            },
        },
        repository=sink,
    )

    assert principals == ["denali@operator.iam.gserviceaccount.com"]
    assert len(sink.batches) == 1
    assert {item.display_name for item in sink.batches[0].assets} == {
        "Summit",
        "gemini-2.5-flash",
        f"denali-ai@{PROJECT}.iam.gserviceaccount.com",
    }
    assert result["state"] == "complete"
    assert result["projects"][0]["ai_workloads"] == 1
