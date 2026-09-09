"""Modal deployment for Denali's API, migrations, and durable provider workers."""

from __future__ import annotations

import os
from pathlib import Path

import modal

APP_NAME = os.environ.get("DENALI_MODAL_APP_NAME", "denali-production")
SECRET_NAME = os.environ.get("DENALI_MODAL_SECRET_NAME", "denali-production")
PROVIDER_SECRET_NAME = os.environ.get(
    "DENALI_MODAL_PROVIDER_SECRET_NAME", "denali-github-provider"
)

image = (
    modal.Image.debian_slim(python_version="3.12")
    .add_local_file("pyproject.toml", remote_path="/opt/denali/pyproject.toml", copy=True)
    .add_local_file("README.md", remote_path="/opt/denali/README.md", copy=True)
    .add_local_dir("src", remote_path="/opt/denali/src", copy=True)
    .run_commands("pip install '/opt/denali[api,aws,azure,gcp,github,hosted]'")
)
runtime_secrets = [
    modal.Secret.from_name(SECRET_NAME),
    modal.Secret.from_name(PROVIDER_SECRET_NAME),
]
app = modal.App(APP_NAME)


def _region_options() -> dict[str, str]:
    region = os.environ.get("DENALI_MODAL_REGION", "").strip()
    return {"region": region} if region else {}


def _configure_aws_oidc() -> None:
    """Expose Modal's short-lived identity token through boto's standard provider chain."""

    role_arn = os.environ.get("DENALI_MODAL_AWS_ROLE_ARN")
    identity_token = os.environ.get("MODAL_IDENTITY_TOKEN")
    if not role_arn or not identity_token:
        return
    token_path = Path("/tmp/denali-modal-identity-token")
    token_path.write_text(identity_token, encoding="utf-8")
    os.environ["AWS_ROLE_ARN"] = role_arn
    os.environ["AWS_WEB_IDENTITY_TOKEN_FILE"] = str(token_path)
    os.environ.setdefault("AWS_ROLE_SESSION_NAME", "denali-modal")


def _configure_gcp_oidc() -> None:
    """Expose Modal's short-lived identity token through Google ADC."""

    from denali.hosted import configure_gcp_external_account

    configure_gcp_external_account()


def _validators():
    from denali.api.app import (
        _azure_repos_client_from_environment,
        _entra_consent_client_from_environment,
        _github_app_from_environment,
        _google_workspace_operator_from_environment,
    )
    from denali.connections import (
        AwsConnectionValidator,
        AzureConnectionValidator,
        AzureReposConnectionValidator,
        EntraConnectionValidator,
        GcpConnectionValidator,
        GitHubConnectionValidator,
        GoogleWorkspaceConnectionValidator,
    )

    github_app = _github_app_from_environment()
    azure_repos_client = _azure_repos_client_from_environment()
    entra_client = _entra_consent_client_from_environment()
    workspace_operator = _google_workspace_operator_from_environment()
    return {
        "aws": AwsConnectionValidator(),
        "azure": AzureConnectionValidator(),
        "entra": EntraConnectionValidator(entra_client) if entra_client else None,
        "gcp": GcpConnectionValidator(),
        "github": GitHubConnectionValidator(github_app) if github_app else None,
        "azure_repos": (
            AzureReposConnectionValidator(azure_repos_client) if azure_repos_client else None
        ),
        "google_workspace": (
            GoogleWorkspaceConnectionValidator(workspace_operator) if workspace_operator else None
        ),
    }


@app.function(
    image=image,
    secrets=runtime_secrets,
    timeout=2400,
    retries=0,
    **_region_options(),
)
def validation_worker(job_id: str) -> None:
    from denali.api.validation import run_durable_validation_job
    from denali.store.repository import PostgresInventoryRepository

    _configure_aws_oidc()
    _configure_gcp_oidc()
    dsn = os.environ["DENALI_DSN"]
    run_durable_validation_job(
        PostgresInventoryRepository(dsn),
        _validators(),
        job_id,
        timeout_seconds=int(os.environ.get("DENALI_AWS_ONBOARDING_VALIDATION_SECONDS", "900")),
        retry_seconds=int(os.environ.get("DENALI_AWS_ONBOARDING_RETRY_SECONDS", "10")),
        on_healthy=_queue_primary_collection,
    )


def _dispatch_validation(job_id: str) -> str:
    call = validation_worker.spawn(job_id)
    return call.object_id


_PRIMARY_COLLECTION_KINDS = {
    "aws": "aws_deployments",
    "azure": "azure_deployments",
    "entra": "entra_ai",
    "gcp": "gcp_deployments",
    "github": "github_source",
    "azure_repos": "azure_repos_source",
    "google_workspace": "google_workspace_ai",
}


def _queue_collection(repository, tenant_id: str, connection_id: str, kind: str) -> None:
    job, created = repository.create_connection_collection_job(
        tenant_id, connection_id, collection_kind=kind
    )
    if not created:
        return
    job_id = str(job["id"])
    try:
        call = collection_worker.spawn(job_id)
        repository.set_connection_collection_call_id(job_id, call.object_id)
    except Exception:
        repository.fail_connection_collection_job(
            job_id, "Unable to dispatch automatic collection worker."
        )
        raise


def _queue_primary_collection(tenant_id: str, connection_id: str, provider: str) -> None:
    from denali.store.repository import PostgresInventoryRepository

    kind = _PRIMARY_COLLECTION_KINDS.get(provider)
    if kind is None:
        raise RuntimeError("validated provider has no collection workflow")
    _queue_collection(
        PostgresInventoryRepository(os.environ["DENALI_DSN"]),
        tenant_id,
        connection_id,
        kind,
    )


@app.function(
    image=image,
    secrets=runtime_secrets,
    timeout=2400,
    retries=0,
    **_region_options(),
)
def collection_worker(job_id: str) -> None:
    from denali.api.app import (
        _azure_repos_client_from_environment,
        _entra_consent_client_from_environment,
        _github_app_from_environment,
        _google_workspace_operator_from_environment,
    )
    from denali.api.collection import run_durable_collection_job
    from denali.connectors.aws_deployments import AwsConnectionDeploymentCollector
    from denali.connectors.azure_deployments import AzureConnectionDeploymentCollector
    from denali.connectors.azure_repos_repository import AzureReposRepositoryCollector
    from denali.connectors.entra_connection import EntraConnectionCollector
    from denali.connectors.gcp_deployments import GcpConnectionDeploymentCollector
    from denali.connectors.github_repository import GitHubRepositoryCollector
    from denali.connectors.google_workspace import GoogleWorkspaceConnectionCollector
    from denali.store.repository import PostgresInventoryRepository

    _configure_aws_oidc()
    _configure_gcp_oidc()
    entra_client = _entra_consent_client_from_environment()
    github_app = _github_app_from_environment()
    azure_repos_client = _azure_repos_client_from_environment()
    workspace_operator = _google_workspace_operator_from_environment()
    run_durable_collection_job(
        PostgresInventoryRepository(os.environ["DENALI_DSN"]),
        {
            "aws_deployments": AwsConnectionDeploymentCollector(),
            "azure_deployments": AzureConnectionDeploymentCollector(),
            "entra_ai": EntraConnectionCollector(entra_client) if entra_client else None,
            "gcp_deployments": GcpConnectionDeploymentCollector(),
            "github_source": GitHubRepositoryCollector(github_app) if github_app else None,
            "azure_repos_source": (
                AzureReposRepositoryCollector(azure_repos_client) if azure_repos_client else None
            ),
            "google_workspace_ai": (
                GoogleWorkspaceConnectionCollector(workspace_operator)
                if workspace_operator
                else None
            ),
        },
        job_id,
        on_succeeded=_after_collection_succeeded,
    )


def _after_collection_succeeded(
    tenant_id: str,
    _connection_id: str,
    collection_kind: str,
    _result: dict[str, object],
) -> None:
    """Refresh dependent source correlation and tenant-wide derived conclusions."""

    from denali.store.repository import PostgresInventoryRepository

    repository = PostgresInventoryRepository(os.environ["DENALI_DSN"])
    if collection_kind in {"aws_deployments", "azure_deployments", "gcp_deployments"}:
        for provider, collection_kind in (
            ("github", "github_source"),
            ("azure_repos", "azure_repos_source"),
        ):
            for source_connection_id in repository.list_healthy_connection_ids(
                tenant_id, provider=provider
            ):
                _queue_collection(repository, tenant_id, source_connection_id, collection_kind)
    repository.evaluate_runtime_detections(tenant_id)
    repository.evaluate_issues(tenant_id)


def _dispatch_collection(job_id: str) -> str:
    call = collection_worker.spawn(job_id)
    return call.object_id


@app.function(
    image=image,
    secrets=runtime_secrets,
    timeout=1200,
    retries=0,
    **_region_options(),
)
def vulnerability_import_worker(job_id: str) -> None:
    from denali.api.evidence_import import (
        S3EvidenceReportStore,
        run_durable_vulnerability_import_job,
    )
    from denali.store.repository import PostgresInventoryRepository

    _configure_aws_oidc()
    run_durable_vulnerability_import_job(
        PostgresInventoryRepository(os.environ["DENALI_DSN"]),
        S3EvidenceReportStore(
            os.environ.get("DENALI_EVIDENCE_BUCKET")
            or os.environ["DENALI_AWS_ONBOARDING_BUCKET"]
        ),
        job_id,
    )


def _dispatch_vulnerability_import(job_id: str) -> str:
    call = vulnerability_import_worker.spawn(job_id)
    return call.object_id


@app.function(
    image=image,
    secrets=runtime_secrets,
    min_containers=1,
    scaledown_window=600,
    timeout=300,
    **_region_options(),
)
@modal.asgi_app()
def api():
    from denali.api.app import create_app

    _configure_aws_oidc()
    _configure_gcp_oidc()
    return create_app(
        auth_mode="clerk",
        validation_dispatcher=_dispatch_validation,
        collection_dispatcher=_dispatch_collection,
        vulnerability_import_dispatcher=_dispatch_vulnerability_import,
        migrate_on_start=False,
    )


@app.function(
    image=image,
    secrets=runtime_secrets,
    timeout=300,
    **_region_options(),
)
def refresh_active_connections(limit: int = 100) -> dict[str, int]:
    """Durably refresh every bounded active connection after an operator-approved release."""

    from denali.api.maintenance import dispatch_active_connection_refresh
    from denali.store.repository import PostgresInventoryRepository

    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    repository = PostgresInventoryRepository(os.environ["DENALI_DSN"])
    summary = dispatch_active_connection_refresh(
        repository,
        lambda job_id: validation_worker.spawn(job_id).object_id,
        limit=limit,
    )
    print(" ".join(f"{key}={value}" for key, value in summary.items()))
    if summary["failed"]:
        raise RuntimeError("one or more validation workers could not be dispatched")
    return summary


@app.function(
    image=image,
    secrets=runtime_secrets,
    timeout=120,
    **_region_options(),
)
def active_connection_status(limit: int = 100) -> list[dict[str, str]]:
    """Print identifier-only validation and collection state for release acceptance."""

    from denali.store.repository import PostgresInventoryRepository

    if not 1 <= limit <= 500:
        raise ValueError("limit must be between 1 and 500")
    repository = PostgresInventoryRepository(os.environ["DENALI_DSN"])
    rows = repository.list_active_connection_refs(limit=limit)
    statuses: list[dict[str, str]] = []
    for row in rows:
        tenant_id = str(row["tenant_id"])
        connection_id = str(row["connection_id"])
        provider = str(row["provider"])
        validation = repository.connection_validation_status(tenant_id, connection_id)
        collection_kind = _PRIMARY_COLLECTION_KINDS[provider]
        collection = repository.connection_collection_status(
            tenant_id, connection_id, collection_kind=collection_kind
        )
        last_result = collection["last_result"] or {}
        status = {
            "tenant_id": tenant_id,
            "connection_id": connection_id,
            "provider": provider,
            "health": str(row["health_state"]),
            "validation": str(validation["state"]),
            "last_validation": str(
                (validation["last_result"] or {}).get("state", "none")
            ),
            "collection": str(collection["state"]),
            "last_collection": str(last_result.get("state", "none")),
        }
        statuses.append(status)
        print(
            " ".join(
                f"{key}={value}" for key, value in status.items()
            )
        )
    return statuses


@app.function(
    image=image,
    secrets=runtime_secrets,
    timeout=600,
    **_region_options(),
)
def migrate_database() -> None:
    from denali.store.db import migrate

    dsn = os.environ.get("DENALI_MIGRATION_DSN") or os.environ["DENALI_DSN"]
    migrate(dsn)


@app.function(
    image=image,
    secrets=runtime_secrets,
    timeout=60,
    **_region_options(),
)
def database_status() -> None:
    """Print non-sensitive migration state for deployment verification."""

    import psycopg

    dsn = os.environ.get("DENALI_MIGRATION_DSN") or os.environ["DENALI_DSN"]
    with psycopg.connect(dsn) as connection:
        database_name = connection.execute("SELECT current_database()").fetchone()[0]
        rows = connection.execute(
            "SELECT version FROM schema_migration ORDER BY version"
        ).fetchall()
    latest = rows[-1][0] if rows else "none"
    print(f"database={database_name} migrations={len(rows)} latest={latest}")


@app.function(
    image=image,
    secrets=runtime_secrets,
    timeout=60,
    **_region_options(),
)
def configuration_status() -> None:
    """Print presence-only production configuration without revealing values."""

    requirement_groups = {
        "core": (
            "DENALI_DSN",
            "DENALI_MIGRATION_DSN",
            "DENALI_WEB_URL",
            "DENALI_CORS_ORIGINS",
            "CLERK_SECRET_KEY",
            "CLERK_JWT_KEY",
            "CLERK_AUTHORIZED_PARTIES",
        ),
        "aws": (
            "DENALI_MODAL_AWS_ROLE_ARN",
            "DENALI_AWS_ONBOARDING_BUCKET",
            "DENALI_AWS_PRINCIPAL_ARN",
        ),
        "evidence": ("DENALI_AWS_ONBOARDING_BUCKET",),
        "azure": (
            "DENALI_AZURE_ONBOARDING_BUCKET",
            "DENALI_AZURE_CLIENT_ID",
            "DENALI_AZURE_CLIENT_SECRET",
        ),
        "entra": (
            "DENALI_ENTRA_CLIENT_ID",
            "DENALI_ENTRA_CLIENT_SECRET",
            "DENALI_ENTRA_CALLBACK_URL",
        ),
        "gcp": (
            "DENALI_GCP_ONBOARDING_BUCKET",
            "DENALI_GCP_OPERATOR_PROJECT_ID",
            "DENALI_GCP_WORKLOAD_IDENTITY_PROVIDER",
            "DENALI_GCP_RUNTIME_SERVICE_ACCOUNT",
        ),
        "google_workspace": (
            "DENALI_GOOGLE_WORKSPACE_SERVICE_ACCOUNT",
            "DENALI_GOOGLE_WORKSPACE_CLIENT_ID",
        ),
        "github": (
            "DENALI_GITHUB_APP_ID",
            "DENALI_GITHUB_CLIENT_ID",
            "DENALI_GITHUB_CLIENT_SECRET",
            "DENALI_GITHUB_APP_SLUG",
            "DENALI_GITHUB_PRIVATE_KEY",
            "DENALI_GITHUB_CALLBACK_URL",
        ),
    }
    for group, requirements in requirement_groups.items():
        missing = [name for name in requirements if not os.environ.get(name, "").strip()]
        state = "ready" if not missing else "incomplete"
        missing_text = ",".join(missing) if missing else "none"
        print(f"group={group} state={state} missing={missing_text}")
