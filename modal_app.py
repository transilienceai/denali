"""Modal deployment for Denali's API, migrations, and durable validation worker."""

from __future__ import annotations

import os
from pathlib import Path

import modal

APP_NAME = os.environ.get("DENALI_MODAL_APP_NAME", "denali-production")
SECRET_NAME = os.environ.get("DENALI_MODAL_SECRET_NAME", "denali-production")

image = (
    modal.Image.debian_slim(python_version="3.12")
    .add_local_file("pyproject.toml", remote_path="/opt/denali/pyproject.toml", copy=True)
    .add_local_file("README.md", remote_path="/opt/denali/README.md", copy=True)
    .add_local_dir("src", remote_path="/opt/denali/src", copy=True)
    .run_commands("pip install '/opt/denali[api,aws,azure,gcp,github,hosted]'")
)
secret = modal.Secret.from_name(SECRET_NAME)
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


def _validators():
    from denali.api.app import _github_app_from_environment
    from denali.connections import (
        AwsConnectionValidator,
        AzureConnectionValidator,
        GcpConnectionValidator,
        GitHubConnectionValidator,
    )

    github_app = _github_app_from_environment()
    return {
        "aws": AwsConnectionValidator(),
        "azure": AzureConnectionValidator(),
        "gcp": GcpConnectionValidator(),
        "github": GitHubConnectionValidator(github_app) if github_app else None,
    }


@app.function(
    image=image,
    secrets=[secret],
    timeout=2400,
    retries=0,
    **_region_options(),
)
def validation_worker(job_id: str) -> None:
    from denali.api.validation import run_durable_validation_job
    from denali.store.repository import PostgresInventoryRepository

    _configure_aws_oidc()
    dsn = os.environ["DENALI_DSN"]
    run_durable_validation_job(
        PostgresInventoryRepository(dsn),
        _validators(),
        job_id,
        timeout_seconds=int(os.environ.get("DENALI_AWS_ONBOARDING_VALIDATION_SECONDS", "900")),
        retry_seconds=int(os.environ.get("DENALI_AWS_ONBOARDING_RETRY_SECONDS", "10")),
    )


def _dispatch_validation(job_id: str) -> str:
    call = validation_worker.spawn(job_id)
    return call.object_id


@app.function(
    image=image,
    secrets=[secret],
    min_containers=1,
    scaledown_window=600,
    timeout=300,
    **_region_options(),
)
@modal.asgi_app()
def api():
    from denali.api.app import create_app

    _configure_aws_oidc()
    return create_app(
        auth_mode="clerk",
        validation_dispatcher=_dispatch_validation,
        migrate_on_start=False,
    )


@app.function(
    image=image,
    secrets=[secret],
    timeout=600,
    **_region_options(),
)
def migrate_database() -> None:
    from denali.store.db import migrate

    dsn = os.environ.get("DENALI_MIGRATION_DSN") or os.environ["DENALI_DSN"]
    migrate(dsn)


@app.function(
    image=image,
    secrets=[secret],
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
    secrets=[secret],
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
        "azure": (
            "DENALI_AZURE_ONBOARDING_BUCKET",
            "DENALI_AZURE_CLIENT_ID",
            "DENALI_AZURE_CLIENT_SECRET",
            "DENALI_AZURE_CONSENT_REDIRECT_URI",
        ),
        "gcp": (
            "DENALI_GCP_ONBOARDING_BUCKET",
            "DENALI_GCP_OPERATOR_PROJECT_ID",
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
