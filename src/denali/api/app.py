"""Inventory-first Denali API."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from time import monotonic, sleep
from typing import Annotated, Any, Literal, Protocol
from urllib.parse import urlencode
from uuid import UUID, uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from denali.api.auth import (
    AuthContext,
    AuthenticationError,
    AuthorizationError,
    ClerkAuthenticator,
    RequestAuthenticator,
)
from denali.api.clerk_admin import (
    ClerkAdminError,
    ClerkBackendOrganizationAdmin,
    ClerkOrganizationAdmin,
)
from denali.api.validation import run_durable_validation_job
from denali.connections import (
    AWS_COVERAGE_AUTOMATIC,
    AWS_COVERAGE_SELECTED,
    AWS_SCOPE_CODE_TO_CLOUD,
    AWS_SCOPES,
    AZURE_CLOUD_PUBLIC,
    AZURE_SCOPE_CODE_TO_CLOUD,
    AZURE_SCOPES,
    GCP_SCOPES,
    GITHUB_SCOPES,
    AwsCloudFormationLauncher,
    AwsConnectionValidator,
    AzureConnectionValidator,
    AzureSetupScriptLauncher,
    GcpConnectionPrincipalProvisioner,
    GcpConnectionValidator,
    GcpSetupScriptLauncher,
    GitHubAppClient,
    GitHubConnectionValidator,
    aws_connection_coverage_plan,
    azure_coverage_plan,
    gcp_coverage_plan,
    github_coverage_plan,
)
from denali.connections.aws import render_cloudformation
from denali.connections.gcp import valid_gcp_project_id
from denali.connectors.aws_deployments import AwsConnectionDeploymentCollector
from denali.connectors.azure_deployments import AzureConnectionDeploymentCollector
from denali.connectors.gcp_deployments import GcpConnectionDeploymentCollector
from denali.connectors.github_repository import GitHubRepositoryCollector
from denali.domain import FindingBatch, InventoryBatch
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

logger = logging.getLogger(__name__)

DEFAULT_LOCAL_TENANT = "00000000-0000-4000-8000-000000000001"


class InventoryReader(Protocol):
    def ingest(self, tenant_id: str, batch: InventoryBatch) -> dict[str, int]: ...

    def ingest_findings(self, tenant_id: str, batch: FindingBatch) -> dict[str, int]: ...

    def resolve_tenant(self, clerk_organization_id: str) -> str: ...

    def create_connection(
        self,
        tenant_id: str,
        *,
        connection_id: str,
        provider: str,
        display_name: str,
        credential_type: str,
        credential_reference: dict[str, Any],
        declared_scopes: list[str],
        coverage_plan: list[dict[str, Any]],
        configuration: dict[str, Any],
    ) -> dict[str, Any]: ...

    def list_connections(self, tenant_id: str) -> list[dict[str, Any]]: ...

    def get_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None: ...

    def get_connection_validation_target(
        self, tenant_id: str, connection_id: str
    ) -> dict[str, Any] | None: ...

    def record_connection_validation(
        self, tenant_id: str, connection_id: str, validation: dict[str, Any]
    ) -> dict[str, Any] | None: ...

    def create_connection_validation_job(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        wait_for_credentials: bool,
        wait_for_healthy: bool,
    ) -> tuple[dict[str, Any], bool]: ...

    def connection_validation_job_state(self, tenant_id: str, connection_id: str) -> str: ...

    def record_connection_launch(
        self, tenant_id: str, connection_id: str, launch: dict[str, Any]
    ) -> dict[str, Any] | None: ...

    def record_connection_setup_launch(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        launch: dict[str, Any],
        setup_token_sha256: str,
    ) -> dict[str, Any] | None: ...

    def record_gcp_connection_setup_launch(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        launch: dict[str, Any],
        setup_token_sha256: str,
    ) -> dict[str, Any] | None: ...

    def complete_azure_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_setup_token_sha256: str,
        service_principal_id: str,
        subscriptions: list[dict[str, str]],
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ) -> dict[str, Any] | None: ...

    def complete_gcp_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_setup_token_sha256: str,
        projects: list[dict[str, str]],
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ) -> dict[str, Any] | None: ...

    def record_github_install_launch(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        launch: dict[str, Any],
        state_sha256: str,
    ) -> dict[str, Any] | None: ...

    def record_github_install_return(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_install_state_sha256: str,
        installation_id: int,
        oauth: dict[str, Any],
    ) -> dict[str, Any] | None: ...

    def complete_github_connection_setup(
        self,
        tenant_id: str,
        connection_id: str,
        *,
        expected_oauth_state_sha256: str,
        installation: dict[str, Any],
        installer: dict[str, Any],
        repositories: list[dict[str, Any]],
        coverage_plan: list[dict[str, Any]],
        completed_at: datetime,
    ) -> dict[str, Any] | None: ...

    def disable_connection(self, tenant_id: str, connection_id: str) -> dict[str, Any] | None: ...

    def delete_connection(self, tenant_id: str, connection_id: str) -> str: ...

    def list_assets(
        self,
        tenant_id: str,
        *,
        kind: str | None = None,
        lifecycle: str = "active",
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    def get_asset(self, tenant_id: str, asset_id: str) -> dict[str, Any] | None: ...

    def summary(self, tenant_id: str) -> dict[str, Any]: ...

    def latest_coverage(self, tenant_id: str) -> list[dict[str, Any]]: ...

    def list_findings(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    def get_finding(self, tenant_id: str, finding_id: str) -> dict[str, Any] | None: ...

    def finding_summary(self, tenant_id: str) -> dict[str, Any]: ...

    def list_vulnerabilities(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    def get_vulnerability(self, tenant_id: str, vulnerability_id: str) -> dict[str, Any] | None: ...

    def vulnerability_summary(self, tenant_id: str) -> dict[str, Any]: ...

    def list_issues(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    def get_issue(self, tenant_id: str, issue_id: str) -> dict[str, Any] | None: ...

    def issue_summary(self, tenant_id: str) -> dict[str, Any]: ...

    def latest_issue_evaluations(self, tenant_id: str) -> list[dict[str, Any]]: ...

    def code_to_cloud_deployments(self, tenant_id: str) -> list[dict[str, Any]]: ...

    def code_to_cloud_observations(self, tenant_id: str) -> list[dict[str, Any]]: ...

    def deployment_targets(self, tenant_id: str) -> list[dict[str, Any]]: ...

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
    ) -> list[dict[str, Any]]: ...

    def get_activity(self, tenant_id: str, activity_id: str) -> dict[str, Any] | None: ...

    def activity_summary(
        self, tenant_id: str, *, include_fixtures: bool = False
    ) -> dict[str, Any]: ...

    def list_runtime_detections(
        self,
        tenant_id: str,
        *,
        state: str | None = None,
        severity: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]: ...

    def get_runtime_detection(
        self, tenant_id: str, detection_id: str
    ) -> dict[str, Any] | None: ...

    def runtime_detection_summary(self, tenant_id: str) -> dict[str, Any]: ...

    def latest_runtime_detection_evaluations(
        self, tenant_id: str
    ) -> list[dict[str, Any]]: ...

    def set_governance(
        self,
        tenant_id: str,
        asset_id: str,
        *,
        status: str,
        owner: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any] | None: ...


class GovernanceUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(pattern="^(approved|unreviewed|unwanted)$")
    owner: str | None = Field(default=None, max_length=256)
    notes: str | None = Field(default=None, max_length=4000)


class AwsConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["aws"] = "aws"
    display_name: str = Field(min_length=1, max_length=120)
    account_id: str = Field(pattern=r"^[0-9]{12}$")
    partition: Literal["aws", "aws-us-gov", "aws-cn"] = "aws"
    deployment_region: str = "us-east-1"
    coverage_mode: Literal["automatic", "selected"] = AWS_COVERAGE_AUTOMATIC
    regions: list[str] = Field(default_factory=list, max_length=40)
    declared_scopes: list[str] = Field(
        default_factory=lambda: list(AWS_SCOPES), min_length=1, max_length=len(AWS_SCOPES)
    )
    role_name: str = Field(
        default="DenaliSecurityAuditRole",
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9+=,.@_-]+$",
    )


class AzureConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["azure"] = "azure"
    display_name: str = Field(min_length=1, max_length=120)
    tenant_id: UUID
    cloud: Literal["AzureCloud"] = AZURE_CLOUD_PUBLIC
    declared_scopes: list[str] = Field(
        default_factory=lambda: list(AZURE_SCOPES), min_length=1, max_length=len(AZURE_SCOPES)
    )


class AzureSetupCompletion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    completion_code: str = Field(min_length=16, max_length=32768)


class GcpConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["gcp"] = "gcp"
    display_name: str = Field(min_length=1, max_length=120)
    declared_scopes: list[str] = Field(
        default_factory=lambda: list(GCP_SCOPES), min_length=1, max_length=len(GCP_SCOPES)
    )


class GcpSetupCompletion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    completion_code: str = Field(min_length=16, max_length=32768)


class GitHubConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: Literal["github"] = "github"
    display_name: str = Field(min_length=1, max_length=120)
    declared_scopes: list[str] = Field(
        default_factory=lambda: list(GITHUB_SCOPES),
        min_length=1,
        max_length=len(GITHUB_SCOPES),
    )


OrganizationRole = Literal["org:member", "org:admin"]


class BulkOrganizationInvite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    emails: list[str] = Field(min_length=1, max_length=50)
    role: OrganizationRole = "org:member"


class OrganizationUserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=320)
    password: str
    first_name: str | None = Field(default=None, max_length=100)
    last_name: str | None = Field(default=None, max_length=100)
    role: OrganizationRole = "org:member"


ConnectionCreate = Annotated[
    AwsConnectionCreate | AzureConnectionCreate | GcpConnectionCreate | GitHubConnectionCreate,
    Field(discriminator="provider"),
]


def create_app(
    *,
    repository: InventoryReader | None = None,
    connection_validator: AwsConnectionValidator | None = None,
    azure_connection_validator: AzureConnectionValidator | None = None,
    gcp_connection_validator: GcpConnectionValidator | None = None,
    cloudformation_launcher: AwsCloudFormationLauncher | None = None,
    azure_setup_launcher: AzureSetupScriptLauncher | None = None,
    gcp_principal_provisioner: GcpConnectionPrincipalProvisioner | None = None,
    gcp_setup_launcher: GcpSetupScriptLauncher | None = None,
    azure_deployment_collector: AzureConnectionDeploymentCollector | None = None,
    aws_deployment_collector: AwsConnectionDeploymentCollector | None = None,
    gcp_deployment_collector: GcpConnectionDeploymentCollector | None = None,
    github_app_client: GitHubAppClient | None = None,
    github_connection_validator: GitHubConnectionValidator | None = None,
    github_repository_collector: GitHubRepositoryCollector | None = None,
    onboarding_validation_timeout_seconds: int | None = None,
    onboarding_validation_retry_seconds: int | None = None,
    tenant_id: str | None = None,
    auth_mode: Literal["local", "clerk"] | None = None,
    authenticator: RequestAuthenticator | None = None,
    clerk_organization_admin: ClerkOrganizationAdmin | None = None,
    validation_dispatcher: Callable[[str], str | None] | None = None,
    migrate_on_start: bool = True,
) -> FastAPI:
    configured_dsn = os.environ.get("DENALI_DSN")
    configured_tenant = tenant_id or os.environ.get("DENALI_TENANT_ID", DEFAULT_LOCAL_TENANT)
    configured_auth_mode = auth_mode or os.environ.get("DENALI_AUTH_MODE", "local")
    if configured_auth_mode not in {"local", "clerk"}:
        raise ValueError("DENALI_AUTH_MODE must be 'local' or 'clerk'")
    configured_authenticator = authenticator or (
        ClerkAuthenticator.from_environment() if configured_auth_mode == "clerk" else None
    )
    configured_clerk_organization_admin = clerk_organization_admin
    if (
        configured_clerk_organization_admin is None
        and configured_auth_mode == "clerk"
        and os.environ.get("CLERK_SECRET_KEY")
    ):
        configured_clerk_organization_admin = ClerkBackendOrganizationAdmin.from_environment()
    configured_launcher = cloudformation_launcher or _cloudformation_launcher_from_environment()
    configured_azure_launcher = azure_setup_launcher or _azure_setup_launcher_from_environment()
    configured_gcp_provisioner = (
        gcp_principal_provisioner or _gcp_principal_provisioner_from_environment()
    )
    configured_gcp_launcher = gcp_setup_launcher or _gcp_setup_launcher_from_environment()
    configured_github_app = github_app_client or _github_app_from_environment()
    onboarding_validation_timeout = (
        onboarding_validation_timeout_seconds
        if onboarding_validation_timeout_seconds is not None
        else _bounded_environment_integer(
            "DENALI_AWS_ONBOARDING_VALIDATION_SECONDS",
            default=900,
            minimum=60,
            maximum=1800,
        )
    )
    onboarding_validation_retry = (
        onboarding_validation_retry_seconds
        if onboarding_validation_retry_seconds is not None
        else _bounded_environment_integer(
            "DENALI_AWS_ONBOARDING_RETRY_SECONDS", default=10, minimum=2, maximum=60
        )
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if repository is not None:
            app.state.repository = repository
        elif configured_dsn:
            if migrate_on_start:
                migrate(configured_dsn)
            app.state.repository = PostgresInventoryRepository(configured_dsn)
        else:
            app.state.repository = None
        app.state.tenant_id = configured_tenant
        app.state.auth_mode = configured_auth_mode
        app.state.authenticator = configured_authenticator
        app.state.clerk_organization_admin = configured_clerk_organization_admin
        app.state.validation_dispatcher = validation_dispatcher
        app.state.connection_validator = connection_validator or AwsConnectionValidator()
        app.state.azure_connection_validator = (
            azure_connection_validator or AzureConnectionValidator()
        )
        app.state.gcp_connection_validator = gcp_connection_validator or GcpConnectionValidator()
        app.state.cloudformation_launcher = configured_launcher
        app.state.azure_setup_launcher = configured_azure_launcher
        app.state.gcp_principal_provisioner = configured_gcp_provisioner
        app.state.gcp_setup_launcher = configured_gcp_launcher
        app.state.azure_deployment_collector = (
            azure_deployment_collector or AzureConnectionDeploymentCollector()
        )
        app.state.aws_deployment_collector = (
            aws_deployment_collector or AwsConnectionDeploymentCollector()
        )
        app.state.gcp_deployment_collector = (
            gcp_deployment_collector or GcpConnectionDeploymentCollector()
        )
        app.state.github_app_client = configured_github_app
        app.state.github_connection_validator = github_connection_validator or (
            GitHubConnectionValidator(configured_github_app)
            if configured_github_app is not None
            else None
        )
        app.state.github_repository_collector = github_repository_collector or (
            GitHubRepositoryCollector(configured_github_app)
            if configured_github_app is not None
            else None
        )
        app.state.onboarding_validation_timeout = onboarding_validation_timeout
        app.state.onboarding_validation_retry = onboarding_validation_retry
        app.state.active_connection_validations = set()
        app.state.connection_validation_lock = Lock()
        app.state.active_github_collections = set()
        app.state.github_collection_results = {}
        app.state.github_collection_lock = Lock()
        app.state.active_gcp_deployment_collections = set()
        app.state.gcp_deployment_collection_results = {}
        app.state.gcp_deployment_collection_lock = Lock()
        app.state.active_azure_deployment_collections = set()
        app.state.azure_deployment_collection_results = {}
        app.state.azure_deployment_collection_lock = Lock()
        app.state.active_aws_deployment_collections = set()
        app.state.aws_deployment_collection_results = {}
        app.state.aws_deployment_collection_lock = Lock()
        yield

    app = FastAPI(
        title="Denali API",
        description="Open-source AI security inventory and evidence API",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.middleware("http")
    async def authenticate_request_context(request: Request, call_next: Callable[..., Any]):
        if request.app.state.auth_mode == "local" or _is_public_request(request):
            return await call_next(request)
        authenticator = request.app.state.authenticator
        if authenticator is None:
            return JSONResponse(status_code=503, content={"detail": "authentication unavailable"})
        try:
            identity = await run_in_threadpool(authenticator.authenticate, request)
        except AuthenticationError as error:
            return JSONResponse(
                status_code=401,
                content={"detail": str(error)},
                headers={"WWW-Authenticate": "Bearer"},
            )
        except AuthorizationError as error:
            return JSONResponse(status_code=403, content={"detail": str(error)})

        repo = request.app.state.repository
        if repo is None:
            return JSONResponse(
                status_code=503, content={"detail": "Denali storage is not configured"}
            )
        resolve_tenant = getattr(repo, "resolve_tenant", None)
        if resolve_tenant is None:
            return JSONResponse(
                status_code=503, content={"detail": "tenant mapping is not configured"}
            )
        tenant_id = await run_in_threadpool(resolve_tenant, identity.organization_id)
        request.state.denali_auth = identity
        request.state.denali_tenant_id = tenant_id
        if _requires_admin(request) and not identity.can_write:
            return JSONResponse(
                status_code=403,
                content={"detail": "organization admin role is required"},
            )
        response = await call_next(request)
        logger.info(
            "authenticated API request",
            extra={
                "tenant_id": tenant_id,
                "connection_id": request.path_params.get("connection_id"),
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
            },
        )
        return response

    def queue_validation(
        request: Request,
        background_tasks: BackgroundTasks,
        repo: InventoryReader,
        current_tenant: str,
        target: dict[str, Any],
        *,
        wait_for_credentials: bool,
        wait_for_healthy: bool = False,
    ) -> dict[str, str]:
        connection_id = str(target["id"])
        validators = {
            "aws": request.app.state.connection_validator,
            "azure": request.app.state.azure_connection_validator,
            "gcp": request.app.state.gcp_connection_validator,
            "github": request.app.state.github_connection_validator,
        }
        validator = validators[target["provider"]]
        if validator is None:
            raise HTTPException(status_code=503, detail="connection validator is not configured")
        retry_seconds = request.app.state.onboarding_validation_retry
        timeout_seconds = request.app.state.onboarding_validation_timeout

        create_job = getattr(repo, "create_connection_validation_job", None)
        if create_job is not None:
            job, created = create_job(
                current_tenant,
                connection_id,
                wait_for_credentials=wait_for_credentials,
                wait_for_healthy=wait_for_healthy,
            )
            if not created:
                return {"status": "already_running", "connection_id": connection_id}
            job_id = str(job["id"])
            dispatcher = request.app.state.validation_dispatcher
            if dispatcher is not None:
                try:
                    call_id = dispatcher(job_id)
                    if call_id:
                        repo.set_connection_validation_call_id(job_id, call_id)  # type: ignore[attr-defined]
                except Exception as error:
                    repo.fail_connection_validation_job(  # type: ignore[attr-defined]
                        job_id, "Unable to dispatch validation worker."
                    )
                    raise HTTPException(
                        status_code=503, detail="Unable to dispatch connection validation"
                    ) from error
            else:
                background_tasks.add_task(
                    run_durable_validation_job,
                    repo,
                    validators,
                    job_id,
                    timeout_seconds=timeout_seconds,
                    retry_seconds=retry_seconds,
                )
            return {"status": "started", "connection_id": connection_id}

        # Injected in-memory repositories used by local contract tests retain the
        # legacy runner; production Postgres always takes the durable path above.
        connection_key = (current_tenant, connection_id)
        validation_lock = request.app.state.connection_validation_lock
        active_validations = request.app.state.active_connection_validations
        with validation_lock:
            if connection_key in active_validations:
                return {"status": "already_running", "connection_id": connection_id}
            active_validations.add(connection_key)

        def run_validation() -> None:
            deadline = monotonic() + timeout_seconds
            try:
                while True:
                    validation = validator.validate(target)
                    credentials_pending = (
                        wait_for_credentials
                        and validation["credential_state"] != "passed"
                    )
                    coverage_pending = (
                        wait_for_healthy and validation["health_state"] != "healthy"
                    )
                    if not (credentials_pending or coverage_pending) or monotonic() >= deadline:
                        repo.record_connection_validation(
                            current_tenant, connection_id, validation
                        )
                        return
                    sleep(min(retry_seconds, max(0, deadline - monotonic())))
            finally:
                with validation_lock:
                    active_validations.discard(connection_key)

        background_tasks.add_task(run_validation)
        return {"status": "started", "connection_id": connection_id}

    def queue_github_collection(
        request: Request,
        background_tasks: BackgroundTasks,
        repo: InventoryReader,
        current_tenant: str,
        target: dict[str, Any],
    ) -> dict[str, str]:
        connection_id = str(target["id"])
        connection_key = (current_tenant, connection_id)
        collector = request.app.state.github_repository_collector
        if collector is None:
            raise HTTPException(
                status_code=503, detail="GitHub source collection is not configured"
            )
        collection_lock = request.app.state.github_collection_lock
        active_collections = request.app.state.active_github_collections
        with collection_lock:
            if connection_key in active_collections:
                return {"status": "already_running", "connection_id": connection_id}
            active_collections.add(connection_key)

        def run_collection() -> None:
            try:
                result = collector.collect(
                    tenant_id=current_tenant,
                    connection=target,
                    repository=repo,
                )
            except Exception:
                result = {
                    "connection_id": connection_id,
                    "state": "failed",
                    "completed_at": datetime.now(UTC).isoformat(),
                    "repositories": [],
                    "repository_count": 0,
                    "failed_count": 0,
                    "partial_count": 0,
                    "detail": "source_collection_failed",
                }
            finally:
                with collection_lock:
                    request.app.state.github_collection_results[connection_key] = result
                    active_collections.discard(connection_key)

        background_tasks.add_task(run_collection)
        return {"status": "started", "connection_id": connection_id}

    def queue_gcp_deployment_collection(
        request: Request,
        background_tasks: BackgroundTasks,
        repo: InventoryReader,
        current_tenant: str,
        target: dict[str, Any],
    ) -> dict[str, str]:
        connection_id = str(target["id"])
        connection_key = (current_tenant, connection_id)
        collector = request.app.state.gcp_deployment_collector
        collection_lock = request.app.state.gcp_deployment_collection_lock
        active_collections = request.app.state.active_gcp_deployment_collections
        with collection_lock:
            if connection_key in active_collections:
                return {"status": "already_running", "connection_id": connection_id}
            active_collections.add(connection_key)

        def run_collection() -> None:
            try:
                result = collector.collect(
                    tenant_id=current_tenant,
                    connection=target,
                    repository=repo,
                )
            except Exception:
                result = {
                    "connection_id": connection_id,
                    "state": "failed",
                    "completed_at": datetime.now(UTC).isoformat(),
                    "project_count": 0,
                    "failed_count": 0,
                    "partial_count": 0,
                    "projects": [],
                    "detail": "gcp_deployment_collection_failed",
                }
            finally:
                with collection_lock:
                    request.app.state.gcp_deployment_collection_results[
                        connection_key
                    ] = result
                    active_collections.discard(connection_key)

        background_tasks.add_task(run_collection)
        return {"status": "started", "connection_id": connection_id}

    def queue_aws_deployment_collection(
        request: Request,
        background_tasks: BackgroundTasks,
        repo: InventoryReader,
        current_tenant: str,
        target: dict[str, Any],
    ) -> dict[str, str]:
        connection_id = str(target["id"])
        connection_key = (current_tenant, connection_id)
        collector = request.app.state.aws_deployment_collector
        collection_lock = request.app.state.aws_deployment_collection_lock
        active_collections = request.app.state.active_aws_deployment_collections
        with collection_lock:
            if connection_key in active_collections:
                return {"status": "already_running", "connection_id": connection_id}
            active_collections.add(connection_key)

        def run_collection() -> None:
            try:
                result = collector.collect(
                    tenant_id=current_tenant,
                    connection=target,
                    repository=repo,
                )
            except Exception:
                result = {
                    "connection_id": connection_id,
                    "state": "failed",
                    "completed_at": datetime.now(UTC).isoformat(),
                    "region_count": 0,
                    "failed_count": 0,
                    "partial_count": 0,
                    "regions": [],
                    "detail": "aws_deployment_collection_failed",
                }
            finally:
                with collection_lock:
                    request.app.state.aws_deployment_collection_results[
                        connection_key
                    ] = result
                    active_collections.discard(connection_key)

        background_tasks.add_task(run_collection)
        return {"status": "started", "connection_id": connection_id}

    def queue_azure_deployment_collection(
        request: Request,
        background_tasks: BackgroundTasks,
        repo: InventoryReader,
        current_tenant: str,
        target: dict[str, Any],
    ) -> dict[str, str]:
        connection_id = str(target["id"])
        connection_key = (current_tenant, connection_id)
        collector = request.app.state.azure_deployment_collector
        collection_lock = request.app.state.azure_deployment_collection_lock
        active_collections = request.app.state.active_azure_deployment_collections
        with collection_lock:
            if connection_key in active_collections:
                return {"status": "already_running", "connection_id": connection_id}
            active_collections.add(connection_key)

        def run_collection() -> None:
            try:
                result = collector.collect(
                    tenant_id=current_tenant,
                    connection=target,
                    repository=repo,
                )
            except Exception:
                result = {
                    "connection_id": connection_id,
                    "state": "failed",
                    "completed_at": datetime.now(UTC).isoformat(),
                    "subscription_count": 0,
                    "failed_count": 0,
                    "partial_count": 0,
                    "subscriptions": [],
                    "detail": "azure_deployment_collection_failed",
                }
            finally:
                with collection_lock:
                    request.app.state.azure_deployment_collection_results[
                        connection_key
                    ] = result
                    active_collections.discard(connection_key)

        background_tasks.add_task(run_collection)
        return {"status": "started", "connection_id": connection_id}

    @app.get("/", include_in_schema=False)
    def web_application() -> RedirectResponse:
        return RedirectResponse(os.environ.get("DENALI_WEB_URL", "http://127.0.0.1:3080"))

    @app.get("/healthz")
    def health(request: Request) -> dict[str, str]:
        state = "ready" if request.app.state.repository is not None else "storage_unconfigured"
        return {"status": state, "version": app.version}

    @app.get("/v1/context")
    def request_context(request: Request) -> dict[str, Any]:
        _, tenant_id = _context(request)
        if request.app.state.auth_mode == "local":
            return {
                "tenant_id": tenant_id,
                "organization_id": None,
                "role": "admin",
                "can_write": True,
            }
        identity: AuthContext = request.state.denali_auth
        return {
            "tenant_id": tenant_id,
            "organization_id": identity.organization_id,
            "role": identity.role,
            "can_write": identity.can_write,
        }

    @app.post("/v1/profile/organization/invitations/bulk")
    def invite_organization_members(
        request: Request, invitation: BulkOrganizationInvite
    ) -> dict[str, Any]:
        _context(request)
        identity, clerk_admin = _clerk_admin_context(request)
        emails = _normalized_emails(invitation.emails)
        results: list[dict[str, Any]] = []
        for email in emails:
            try:
                invitation_id = clerk_admin.invite_member(
                    organization_id=identity.organization_id,
                    inviter_user_id=identity.user_id,
                    email=email,
                    role=invitation.role,
                )
                results.append(
                    {"email": email, "status": "sent", "invitation_id": invitation_id}
                )
            except ClerkAdminError:
                results.append(
                    {
                        "email": email,
                        "status": "failed",
                        "error": "Clerk rejected this invitation",
                    }
                )
        sent = sum(result["status"] == "sent" for result in results)
        return {"sent": sent, "failed": len(results) - sent, "results": results}

    @app.post("/v1/profile/organization/users", status_code=201)
    def create_organization_user(
        request: Request, account: OrganizationUserCreate
    ) -> dict[str, str]:
        _context(request)
        identity, clerk_admin = _clerk_admin_context(request)
        email = _normalized_emails([account.email])[0]
        if not 8 <= len(account.password) <= 128:
            raise HTTPException(
                status_code=422, detail="password must contain between 8 and 128 characters"
            )
        first_name = _optional_clean_text(account.first_name)
        last_name = _optional_clean_text(account.last_name)
        try:
            user_id = clerk_admin.create_user_and_membership(
                organization_id=identity.organization_id,
                email=email,
                password=account.password,
                first_name=first_name,
                last_name=last_name,
                role=account.role,
            )
        except ClerkAdminError as error:
            details = {
                "user_rejected": (
                    "Clerk could not create the user; check whether the account already exists "
                    "and whether the password meets the Clerk instance policy"
                ),
                "membership_rejected": "Clerk could not add the new user to this organization",
            }
            raise HTTPException(
                status_code=502,
                detail=details.get(str(error), "Clerk user provisioning failed"),
            ) from error
        return {"user_id": user_id, "email": email, "role": account.role}

    @app.get("/v1/connections")
    def list_connections(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        rows = repo.list_connections(current_tenant)
        return {
            "items": [_with_validation_state(request, current_tenant, row) for row in rows]
        }

    @app.post("/v1/connections", status_code=201)
    def create_connection(request: Request, connection: ConnectionCreate) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        display_name = connection.display_name.strip()
        if not display_name:
            raise HTTPException(status_code=422, detail="display_name must not be blank")
        if isinstance(connection, AzureConnectionCreate):
            launcher = request.app.state.azure_setup_launcher
            if launcher is None:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Azure onboarding is not configured; set DENALI_AZURE_CLIENT_ID, "
                        "DENALI_AZURE_ONBOARDING_BUCKET, and the consent redirect URI"
                    ),
                )
            scopes = list(dict.fromkeys(connection.declared_scopes))
            unsupported_scopes = [scope for scope in scopes if scope not in AZURE_SCOPES]
            if unsupported_scopes:
                raise HTTPException(
                    status_code=422,
                    detail=f"unsupported Azure scope: {', '.join(unsupported_scopes)}",
                )
            connection_id = str(uuid4())
            try:
                created = repo.create_connection(
                    current_tenant,
                    connection_id=connection_id,
                    provider="azure",
                    display_name=display_name,
                    credential_type="azure_multitenant_app",
                    credential_reference={"client_id": launcher.client_id},
                    declared_scopes=scopes,
                    coverage_plan=[],
                    configuration={
                        "tenant_id": str(connection.tenant_id),
                        "cloud": connection.cloud,
                        "coverage_mode": "selected-subscriptions",
                        "subscriptions": [],
                    },
                )
                return _with_validation_state(request, current_tenant, created)
            except ValueError as error:
                raise HTTPException(status_code=409, detail=str(error)) from error

        if isinstance(connection, GcpConnectionCreate):
            launcher = request.app.state.gcp_setup_launcher
            provisioner = request.app.state.gcp_principal_provisioner
            if launcher is None or provisioner is None:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Google Cloud onboarding is not configured; set "
                        "DENALI_GCP_OPERATOR_PROJECT_ID and "
                        "DENALI_GCP_ONBOARDING_BUCKET"
                    ),
                )
            scopes = list(dict.fromkeys(connection.declared_scopes))
            unsupported_scopes = [scope for scope in scopes if scope not in GCP_SCOPES]
            if unsupported_scopes:
                raise HTTPException(
                    status_code=422,
                    detail=f"unsupported Google Cloud scope: {', '.join(unsupported_scopes)}",
                )
            connection_id = str(uuid4())
            try:
                principal = provisioner.create_principal(
                    connection_id=connection_id,
                    display_name=display_name,
                )
            except Exception as error:
                raise HTTPException(
                    status_code=502,
                    detail="Unable to create the keyless Google Cloud connection principal",
                ) from error
            try:
                created = repo.create_connection(
                    current_tenant,
                    connection_id=connection_id,
                    provider="gcp",
                    display_name=display_name,
                    credential_type="gcp_service_account",
                    credential_reference={
                        **principal,
                        "operator_project_id": provisioner.operator_project_id,
                    },
                    declared_scopes=scopes,
                    coverage_plan=[],
                    configuration={
                        "coverage_mode": "selected-projects",
                        "projects": [],
                    },
                )
                return _with_validation_state(request, current_tenant, created)
            except ValueError as error:
                raise HTTPException(status_code=409, detail=str(error)) from error

        if isinstance(connection, GitHubConnectionCreate):
            github_app = request.app.state.github_app_client
            if github_app is None:
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "GitHub onboarding is not configured; set the GitHub App ID, "
                        "client credentials, slug, callback URL, and private-key file"
                    ),
                )
            scopes = list(dict.fromkeys(connection.declared_scopes))
            unsupported_scopes = [scope for scope in scopes if scope not in GITHUB_SCOPES]
            if unsupported_scopes:
                raise HTTPException(
                    status_code=422,
                    detail=f"unsupported GitHub scope: {', '.join(unsupported_scopes)}",
                )
            connection_id = str(uuid4())
            try:
                created = repo.create_connection(
                    current_tenant,
                    connection_id=connection_id,
                    provider="github",
                    display_name=display_name,
                    credential_type="github_app_installation",
                    credential_reference={
                        "app_id": github_app.app_id,
                        "app_slug": github_app.app_slug,
                    },
                    declared_scopes=scopes,
                    coverage_plan=[],
                    configuration={
                        "coverage_mode": "exact-installation-repositories",
                        "repositories": [],
                    },
                )
                return _with_validation_state(request, current_tenant, created)
            except ValueError as error:
                raise HTTPException(status_code=409, detail=str(error)) from error

        if not _valid_aws_region(connection.deployment_region, partition=connection.partition):
            raise HTTPException(
                status_code=422,
                detail=f"unsupported AWS deployment region format: {connection.deployment_region}",
            )
        regions = list(dict.fromkeys(connection.regions))
        invalid_regions = [
            region
            for region in regions
            if not _valid_aws_region(region, partition=connection.partition)
        ]
        if invalid_regions:
            raise HTTPException(
                status_code=422,
                detail=f"unsupported AWS region format: {', '.join(invalid_regions)}",
            )
        if connection.coverage_mode == AWS_COVERAGE_SELECTED and not regions:
            raise HTTPException(
                status_code=422,
                detail="selected region coverage requires at least one region",
            )
        scopes = list(dict.fromkeys(connection.declared_scopes))
        unsupported_scopes = [scope for scope in scopes if scope not in AWS_SCOPES]
        if unsupported_scopes:
            raise HTTPException(
                status_code=422,
                detail=f"unsupported AWS scope: {', '.join(unsupported_scopes)}",
            )
        connection_id = str(uuid4())
        external_id = f"denali-{current_tenant}-{connection_id}"
        role_arn = (
            f"arn:{connection.partition}:iam::{connection.account_id}:role/{connection.role_name}"
        )
        try:
            created = repo.create_connection(
                current_tenant,
                connection_id=connection_id,
                provider="aws",
                display_name=display_name,
                credential_type="aws_assume_role",
                credential_reference={"role_arn": role_arn, "external_id": external_id},
                declared_scopes=scopes,
                coverage_plan=aws_connection_coverage_plan(
                    scopes,
                    (
                        regions
                        if connection.coverage_mode == AWS_COVERAGE_SELECTED
                        else ["all-enabled"]
                    ),
                    deployment_region=connection.deployment_region,
                    coverage_mode=connection.coverage_mode,
                ),
                configuration={
                    "account_id": connection.account_id,
                    "partition": connection.partition,
                    "deployment_region": connection.deployment_region,
                    "coverage_mode": connection.coverage_mode,
                    "regions": regions if connection.coverage_mode == AWS_COVERAGE_SELECTED else [],
                    "role_name": connection.role_name,
                    "stack_scopes": [],
                },
            )
            return _with_validation_state(request, current_tenant, created)
        except ValueError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error

    @app.get("/v1/connections/{connection_id}")
    def connection_detail(request: Request, connection_id: UUID) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_connection(current_tenant, str(connection_id))
        if row is None:
            raise HTTPException(status_code=404, detail="connection not found")
        return _with_validation_state(request, current_tenant, row)

    @app.get("/v1/connections/{connection_id}/aws/cloudformation.yaml")
    def aws_connection_cloudformation(
        request: Request, connection_id: UUID
    ) -> PlainTextResponse:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "aws":
            raise HTTPException(status_code=404, detail="AWS connection not found")
        template = render_cloudformation(target)
        filename = f"denali-aws-{connection_id}.yaml"
        return PlainTextResponse(
            template,
            media_type="application/yaml",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.post("/v1/connections/{connection_id}/aws/cloudformation/launch", status_code=201)
    def launch_aws_cloudformation(
        request: Request,
        response: Response,
        background_tasks: BackgroundTasks,
        connection_id: UUID,
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "aws":
            raise HTTPException(status_code=404, detail="AWS connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot be launched")
        launcher = request.app.state.cloudformation_launcher
        if launcher is None:
            raise HTTPException(
                status_code=503,
                detail=(
                    "AWS console launch is not configured; use Download template or configure "
                    "DENALI_AWS_ONBOARDING_BUCKET and DENALI_AWS_PRINCIPAL_ARN"
                ),
            )
        try:
            launch = launcher.create_launch(
                tenant_id=current_tenant,
                connection_id=str(connection_id),
                connection=target,
            )
        except Exception as error:
            raise HTTPException(
                status_code=502, detail="Unable to prepare the AWS CloudFormation launch"
            ) from error

        recorded = repo.record_connection_launch(
            current_tenant,
            str(connection_id),
            {
                "method": "cloudformation_quick_create",
                "template_version": launch["template_version"],
                "template_sha256": launch["template_sha256"],
                "principal_arn": launch["principal_arn"],
                "published_at": launch["published_at"].isoformat(),
                "url_expires_at": launch["expires_at"].isoformat(),
            },
        )
        if recorded is None:
            raise HTTPException(status_code=409, detail="connection changed during launch")
        validation = queue_validation(
            request,
            background_tasks,
            repo,
            current_tenant,
            target,
            wait_for_credentials=True,
        )
        response.headers["Cache-Control"] = "no-store"
        return {
            "launch_url": launch["launch_url"],
            "stack_name": launch["stack_name"],
            "stack_region": launch["stack_region"],
            "template_version": launch["template_version"],
            "template_sha256": launch["template_sha256"],
            "expires_at": launch["expires_at"],
            "validation_status": validation["status"],
        }

    @app.post("/v1/connections/{connection_id}/azure/setup/launch", status_code=201)
    def launch_azure_setup(
        request: Request,
        response: Response,
        connection_id: UUID,
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "azure":
            raise HTTPException(status_code=404, detail="Azure connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot be launched")
        launcher = request.app.state.azure_setup_launcher
        if launcher is None:
            raise HTTPException(
                status_code=503,
                detail="Azure Cloud Shell onboarding is not configured",
            )
        try:
            launch = launcher.create_launch(
                tenant_id=current_tenant,
                connection_id=str(connection_id),
                connection=target,
            )
        except Exception as error:
            raise HTTPException(
                status_code=502, detail="Unable to prepare the Azure setup script"
            ) from error

        recorded = repo.record_connection_setup_launch(
            current_tenant,
            str(connection_id),
            launch={
                "method": "azure_cloud_shell",
                "script_version": launch["script_version"],
                "script_sha256": launch["script_sha256"],
                "client_id": launch["client_id"],
                "published_at": launch["published_at"].isoformat(),
                "url_expires_at": launch["expires_at"].isoformat(),
            },
            setup_token_sha256=launch["callback_token_sha256"],
        )
        if recorded is None:
            raise HTTPException(status_code=409, detail="connection changed during launch")
        response.headers["Cache-Control"] = "no-store"
        return {
            "consent_url": launch["consent_url"],
            "cloud_shell_url": launch["cloud_shell_url"],
            "script_url": launch["script_url"],
            "setup_command": launch["setup_command"],
            "script_version": launch["script_version"],
            "script_sha256": launch["script_sha256"],
            "expires_at": launch["expires_at"],
        }

    @app.post("/v1/connections/{connection_id}/azure/setup/complete", status_code=202)
    def complete_azure_setup(
        request: Request,
        background_tasks: BackgroundTasks,
        connection_id: UUID,
        completion: AzureSetupCompletion,
    ) -> dict[str, str]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "azure":
            raise HTTPException(status_code=404, detail="Azure connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot be completed")
        payload = _decode_azure_completion_code(completion.completion_code)
        expected_token_hash = target["credential_reference"].get("setup_token_sha256")
        presented_token = payload.get("token")
        token_matches = (
            bool(expected_token_hash)
            and isinstance(presented_token, str)
            and hmac.compare_digest(
                expected_token_hash, hashlib.sha256(presented_token.encode()).hexdigest()
            )
        )
        if not token_matches:
            raise HTTPException(status_code=409, detail="Azure setup completion code is invalid")
        onboarding = target["configuration"].get("onboarding", {})
        try:
            expires_at = datetime.fromisoformat(onboarding["url_expires_at"])
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(
                status_code=409, detail="Azure setup launch is not current"
            ) from error
        if datetime.now(UTC) > expires_at:
            raise HTTPException(status_code=409, detail="Azure setup completion code has expired")
        if str(payload.get("tenant_id", "")).lower() != target["configuration"][
            "tenant_id"
        ].lower():
            raise HTTPException(status_code=409, detail="Azure tenant does not match the plan")
        service_principal_id = str(payload.get("service_principal_id", ""))
        if not _valid_uuid_text(service_principal_id):
            raise HTTPException(status_code=422, detail="Azure service principal ID is invalid")
        subscriptions = _azure_subscriptions_from_completion(payload)
        completed_at = datetime.now(UTC)
        updated = repo.complete_azure_connection_setup(
            current_tenant,
            str(connection_id),
            expected_setup_token_sha256=expected_token_hash,
            service_principal_id=service_principal_id,
            subscriptions=subscriptions,
            coverage_plan=azure_coverage_plan(target["declared_scopes"], subscriptions),
            completed_at=completed_at,
        )
        if updated is None:
            raise HTTPException(status_code=409, detail="connection changed during setup")
        validation_target = repo.get_connection_validation_target(
            current_tenant, str(connection_id)
        )
        if validation_target is None:
            raise HTTPException(status_code=409, detail="connection changed during setup")
        return queue_validation(
            request,
            background_tasks,
            repo,
            current_tenant,
            validation_target,
            wait_for_credentials=True,
            wait_for_healthy=True,
        )

    @app.post("/v1/connections/{connection_id}/gcp/setup/launch", status_code=201)
    def launch_gcp_setup(
        request: Request,
        response: Response,
        connection_id: UUID,
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "gcp":
            raise HTTPException(status_code=404, detail="Google Cloud connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot be launched")
        launcher = request.app.state.gcp_setup_launcher
        if launcher is None:
            raise HTTPException(
                status_code=503,
                detail="Google Cloud Shell onboarding is not configured",
            )
        try:
            launch = launcher.create_launch(
                tenant_id=current_tenant,
                connection_id=str(connection_id),
                connection=target,
            )
        except Exception as error:
            raise HTTPException(
                status_code=502, detail="Unable to prepare the Google Cloud setup script"
            ) from error

        recorded = repo.record_gcp_connection_setup_launch(
            current_tenant,
            str(connection_id),
            launch={
                "method": "gcp_cloud_shell",
                "script_version": launch["script_version"],
                "script_sha256": launch["script_sha256"],
                "principal_email": launch["principal_email"],
                "published_at": launch["published_at"].isoformat(),
                "url_expires_at": launch["expires_at"].isoformat(),
            },
            setup_token_sha256=launch["completion_token_sha256"],
        )
        if recorded is None:
            raise HTTPException(status_code=409, detail="connection changed during launch")
        response.headers["Cache-Control"] = "no-store"
        return {
            "cloud_shell_url": launch["cloud_shell_url"],
            "script_url": launch["script_url"],
            "setup_command": launch["setup_command"],
            "script_version": launch["script_version"],
            "script_sha256": launch["script_sha256"],
            "principal_email": launch["principal_email"],
            "expires_at": launch["expires_at"],
        }

    @app.post("/v1/connections/{connection_id}/gcp/setup/complete", status_code=202)
    def complete_gcp_setup(
        request: Request,
        background_tasks: BackgroundTasks,
        connection_id: UUID,
        completion: GcpSetupCompletion,
    ) -> dict[str, str]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "gcp":
            raise HTTPException(status_code=404, detail="Google Cloud connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot be completed")
        payload = _decode_gcp_completion_code(completion.completion_code)
        expected_token_hash = target["credential_reference"].get("setup_token_sha256")
        presented_token = payload.get("token")
        token_matches = (
            bool(expected_token_hash)
            and isinstance(presented_token, str)
            and hmac.compare_digest(
                expected_token_hash, hashlib.sha256(presented_token.encode()).hexdigest()
            )
        )
        if not token_matches:
            raise HTTPException(
                status_code=409, detail="Google Cloud setup completion code is invalid"
            )
        onboarding = target["configuration"].get("onboarding", {})
        try:
            expires_at = datetime.fromisoformat(onboarding["url_expires_at"])
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(
                status_code=409, detail="Google Cloud setup launch is not current"
            ) from error
        if datetime.now(UTC) > expires_at:
            raise HTTPException(
                status_code=409, detail="Google Cloud setup completion code has expired"
            )
        if payload.get("principal_email") != target["credential_reference"]["principal_email"]:
            raise HTTPException(
                status_code=409, detail="Google Cloud principal does not match the plan"
            )
        projects = _gcp_projects_from_completion(payload)
        completed_at = datetime.now(UTC)
        updated = repo.complete_gcp_connection_setup(
            current_tenant,
            str(connection_id),
            expected_setup_token_sha256=expected_token_hash,
            projects=projects,
            coverage_plan=gcp_coverage_plan(target["declared_scopes"], projects),
            completed_at=completed_at,
        )
        if updated is None:
            raise HTTPException(status_code=409, detail="connection changed during setup")
        validation_target = repo.get_connection_validation_target(
            current_tenant, str(connection_id)
        )
        if validation_target is None:
            raise HTTPException(status_code=409, detail="connection changed during setup")
        return queue_validation(
            request,
            background_tasks,
            repo,
            current_tenant,
            validation_target,
            wait_for_credentials=True,
            wait_for_healthy=True,
        )

    @app.post("/v1/connections/{connection_id}/github/setup/launch", status_code=201)
    def launch_github_setup(
        request: Request,
        response: Response,
        connection_id: UUID,
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "github":
            raise HTTPException(status_code=404, detail="GitHub connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot be launched")
        github_app = request.app.state.github_app_client
        if github_app is None:
            raise HTTPException(status_code=503, detail="GitHub App onboarding is not configured")
        launch = github_app.create_install_launch(
            tenant_id=current_tenant,
            connection_id=str(connection_id),
        )
        recorded = repo.record_github_install_launch(
            current_tenant,
            str(connection_id),
            launch={
                "method": "github_app_installation",
                "app_id": github_app.app_id,
                "app_slug": github_app.app_slug,
                "created_at": launch["created_at"].isoformat(),
                "install_expires_at": launch["expires_at"].isoformat(),
            },
            state_sha256=launch["state_sha256"],
        )
        if recorded is None:
            raise HTTPException(status_code=409, detail="connection changed during launch")
        response.headers["Cache-Control"] = "no-store"
        return {
            "install_url": launch["install_url"],
            "app_slug": github_app.app_slug,
            "expires_at": launch["expires_at"],
        }

    @app.get("/v1/connections/github/setup/callback", include_in_schema=False)
    def github_install_callback(
        request: Request,
        state: str = Query(min_length=32, max_length=1024),
        installation_id: int = Query(gt=0),
    ) -> RedirectResponse:
        state_tenant, connection_id = _github_state_context(state)
        repo, current_tenant = _context_for_tenant(request, state_tenant)
        target = repo.get_connection_validation_target(current_tenant, connection_id)
        if target is None or target["provider"] != "github":
            raise HTTPException(status_code=404, detail="GitHub connection not found")
        expected_hash = target["credential_reference"].get("install_state_sha256")
        if not expected_hash or not hmac.compare_digest(expected_hash, _sha256_text(state)):
            raise HTTPException(status_code=409, detail="GitHub setup state is invalid")
        _require_current_setup_expiry(
            target,
            key="install_expires_at",
            detail="GitHub installation launch has expired",
        )
        github_app = request.app.state.github_app_client
        if github_app is None:
            raise HTTPException(status_code=503, detail="GitHub App onboarding is not configured")
        oauth = github_app.create_oauth_launch(
            tenant_id=current_tenant,
            connection_id=connection_id,
        )
        recorded = repo.record_github_install_return(
            current_tenant,
            connection_id,
            expected_install_state_sha256=expected_hash,
            installation_id=installation_id,
            oauth={
                "state_sha256": oauth["state_sha256"],
                "pkce_verifier": oauth["pkce_verifier"],
                "created_at": oauth["created_at"].isoformat(),
                "expires_at": oauth["expires_at"].isoformat(),
            },
        )
        if recorded is None:
            raise HTTPException(status_code=409, detail="GitHub connection changed during setup")
        return RedirectResponse(oauth["authorize_url"], status_code=303)

    @app.get("/v1/connections/github/oauth/callback", include_in_schema=False)
    def github_oauth_callback(
        request: Request,
        background_tasks: BackgroundTasks,
        state: str = Query(min_length=32, max_length=1024),
        code: str = Query(min_length=8, max_length=1024),
    ) -> RedirectResponse:
        state_tenant, connection_id = _github_state_context(state)
        repo, current_tenant = _context_for_tenant(request, state_tenant)
        target = repo.get_connection_validation_target(current_tenant, connection_id)
        if target is None or target["provider"] != "github":
            raise HTTPException(status_code=404, detail="GitHub connection not found")
        expected_hash = target["credential_reference"].get("oauth_state_sha256")
        if not expected_hash or not hmac.compare_digest(expected_hash, _sha256_text(state)):
            raise HTTPException(status_code=409, detail="GitHub OAuth state is invalid")
        _require_current_setup_expiry(
            target,
            key="oauth_expires_at",
            detail="GitHub installer verification has expired",
        )
        github_app = request.app.state.github_app_client
        if github_app is None:
            raise HTTPException(status_code=503, detail="GitHub App onboarding is not configured")
        try:
            user_token = github_app.exchange_user_code(
                code=code,
                pkce_verifier=target["credential_reference"]["pkce_verifier"],
            )
            verified = github_app.verify_user_installation(
                installation_id=target["credential_reference"]["installation_id"],
                user_token=user_token,
            )
        except Exception:
            failure_query = urlencode(
                {
                    "github_setup": "failed",
                    "connection_id": connection_id,
                    "detail": "GitHub could not verify the installer and App installation",
                }
            )
            return RedirectResponse(
                f"{github_app.web_url}/?{failure_query}",
                status_code=303,
            )
        installation = verified["installation"]
        repositories = verified["repositories"]
        completed_at = datetime.now(UTC)
        updated = repo.complete_github_connection_setup(
            current_tenant,
            connection_id,
            expected_oauth_state_sha256=expected_hash,
            installation=installation,
            installer=verified["installer"],
            repositories=repositories,
            coverage_plan=github_coverage_plan(target["declared_scopes"], repositories),
            completed_at=completed_at,
        )
        if updated is None:
            raise HTTPException(status_code=409, detail="GitHub connection changed during setup")
        validation_target = repo.get_connection_validation_target(current_tenant, connection_id)
        if validation_target is None:
            raise HTTPException(status_code=409, detail="GitHub connection changed during setup")
        queue_validation(
            request,
            background_tasks,
            repo,
            current_tenant,
            validation_target,
            wait_for_credentials=False,
        )
        return RedirectResponse(
            f"{github_app.web_url}/?"
            f"{urlencode({'github_setup': 'succeeded', 'connection_id': connection_id})}",
            status_code=303,
        )

    @app.post("/v1/connections/{connection_id}/validate", status_code=202)
    def validate_connection(
        request: Request,
        background_tasks: BackgroundTasks,
        connection_id: UUID,
    ) -> dict[str, str]:
        repo, current_tenant = _context(request)
        connection_key = (current_tenant, str(connection_id))
        target = repo.get_connection_validation_target(current_tenant, connection_key[1])
        if target is None:
            raise HTTPException(status_code=404, detail="connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot be validated")
        if target["provider"] not in {"aws", "azure", "gcp", "github"}:
            raise HTTPException(status_code=422, detail="connection provider is not supported")
        if target["provider"] == "azure" and not target["configuration"].get("subscriptions"):
            raise HTTPException(
                status_code=409,
                detail="complete Azure subscription selection before validation",
            )
        if target["provider"] == "gcp" and not target["configuration"].get("projects"):
            raise HTTPException(
                status_code=409,
                detail="complete Google Cloud project selection before validation",
            )
        if target["provider"] == "github" and not target["configuration"].get("repositories"):
            raise HTTPException(
                status_code=409,
                detail="complete GitHub App installation before validation",
            )
        return queue_validation(
            request,
            background_tasks,
            repo,
            current_tenant,
            target,
            wait_for_credentials=False,
        )

    @app.post("/v1/connections/{connection_id}/github/collect", status_code=202)
    def collect_github_repository_source(
        request: Request,
        background_tasks: BackgroundTasks,
        connection_id: UUID,
    ) -> dict[str, str]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "github":
            raise HTTPException(status_code=404, detail="GitHub connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot collect")
        if not target["configuration"].get("repositories"):
            raise HTTPException(
                status_code=409,
                detail="complete GitHub App installation before collecting source",
            )
        return queue_github_collection(
            request, background_tasks, repo, current_tenant, target
        )

    @app.post(
        "/v1/connections/{connection_id}/aws/collect-deployments",
        status_code=202,
    )
    def collect_aws_deployments(
        request: Request,
        background_tasks: BackgroundTasks,
        connection_id: UUID,
    ) -> dict[str, str]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "aws":
            raise HTTPException(status_code=404, detail="AWS connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot collect")
        if AWS_SCOPE_CODE_TO_CLOUD not in target["declared_scopes"]:
            raise HTTPException(
                status_code=409,
                detail="AWS code-to-cloud scope is not declared",
            )
        return queue_aws_deployment_collection(
            request, background_tasks, repo, current_tenant, target
        )

    @app.post(
        "/v1/connections/{connection_id}/azure/collect-deployments",
        status_code=202,
    )
    def collect_azure_deployments(
        request: Request,
        background_tasks: BackgroundTasks,
        connection_id: UUID,
    ) -> dict[str, str]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "azure":
            raise HTTPException(status_code=404, detail="Azure connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot collect")
        if AZURE_SCOPE_CODE_TO_CLOUD not in target["declared_scopes"]:
            raise HTTPException(
                status_code=409,
                detail="Azure code-to-cloud scope is not declared",
            )
        if not target["configuration"].get("subscriptions"):
            raise HTTPException(
                status_code=409,
                detail="complete Azure subscription selection before collecting deployments",
            )
        return queue_azure_deployment_collection(
            request, background_tasks, repo, current_tenant, target
        )

    @app.post(
        "/v1/connections/{connection_id}/gcp/collect-deployments",
        status_code=202,
    )
    def collect_gcp_deployments(
        request: Request,
        background_tasks: BackgroundTasks,
        connection_id: UUID,
    ) -> dict[str, str]:
        repo, current_tenant = _context(request)
        target = repo.get_connection_validation_target(current_tenant, str(connection_id))
        if target is None or target["provider"] != "gcp":
            raise HTTPException(status_code=404, detail="Google Cloud connection not found")
        if target["lifecycle_state"] != "active":
            raise HTTPException(status_code=409, detail="disabled connections cannot collect")
        if not target["configuration"].get("projects"):
            raise HTTPException(
                status_code=409,
                detail="complete Google Cloud project selection before collecting deployments",
            )
        return queue_gcp_deployment_collection(
            request, background_tasks, repo, current_tenant, target
        )

    @app.post("/v1/connections/{connection_id}/disable")
    def disable_connection(request: Request, connection_id: UUID) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        connection_key = (current_tenant, str(connection_id))
        if _connection_validation_state(request, *connection_key) == "running":
            raise HTTPException(
                status_code=409,
                detail="wait for the active validation to finish before disabling",
            )
        with request.app.state.github_collection_lock:
            if connection_key in request.app.state.active_github_collections:
                raise HTTPException(
                    status_code=409,
                    detail="wait for the active source collection to finish before disabling",
                )
        with request.app.state.gcp_deployment_collection_lock:
            if connection_key in request.app.state.active_gcp_deployment_collections:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "wait for the active GCP deployment collection to finish "
                        "before disabling"
                    ),
                )
        with request.app.state.azure_deployment_collection_lock:
            if connection_key in request.app.state.active_azure_deployment_collections:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "wait for the active Azure deployment collection to finish "
                        "before disabling"
                    ),
                )
        with request.app.state.aws_deployment_collection_lock:
            if connection_key in request.app.state.active_aws_deployment_collections:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "wait for the active AWS deployment collection to finish "
                        "before disabling"
                    ),
                )
        row = repo.disable_connection(current_tenant, str(connection_id))
        if row is None:
            raise HTTPException(status_code=404, detail="connection not found")
        return _with_validation_state(request, current_tenant, row)

    @app.delete("/v1/connections/{connection_id}", status_code=204)
    def delete_connection(
        request: Request,
        connection_id: UUID,
        confirm: str = Query(min_length=1, max_length=120),
    ) -> Response:
        repo, current_tenant = _context(request)
        row = repo.get_connection(current_tenant, str(connection_id))
        if row is None:
            raise HTTPException(status_code=404, detail="connection not found")
        if confirm != row["display_name"]:
            raise HTTPException(status_code=409, detail="confirmation name does not match")
        result = repo.delete_connection(current_tenant, str(connection_id))
        if result == "active":
            raise HTTPException(status_code=409, detail="disable the connection before deleting it")
        if result == "not_found":
            raise HTTPException(status_code=404, detail="connection not found")
        return Response(status_code=204)

    @app.get("/v1/inventory/summary")
    def inventory_summary(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return repo.summary(current_tenant)

    @app.get("/v1/inventory/assets")
    def list_assets(
        request: Request,
        kind: str | None = None,
        lifecycle: str = Query(default="active", pattern="^(active|withdrawn|unknown|all)$"),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        rows = repo.list_assets(
            current_tenant,
            kind=kind,
            lifecycle="" if lifecycle == "all" else lifecycle,
            limit=limit,
            offset=offset,
        )
        return {"items": rows, "limit": limit, "offset": offset}

    @app.get("/v1/inventory/assets/{asset_id}")
    def asset_detail(request: Request, asset_id: str) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_asset(current_tenant, asset_id)
        if row is None:
            raise HTTPException(status_code=404, detail="asset not found")
        return row

    @app.patch("/v1/inventory/assets/{asset_id}/governance")
    def update_governance(
        request: Request, asset_id: str, update: GovernanceUpdate
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.set_governance(
            current_tenant,
            asset_id,
            status=update.status,
            owner=update.owner,
            notes=update.notes,
        )
        if row is None:
            raise HTTPException(status_code=404, detail="asset not found")
        return row

    @app.get("/v1/sources/coverage")
    def source_coverage(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {"items": repo.latest_coverage(current_tenant)}

    @app.get("/v1/findings/summary")
    def finding_summary(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return repo.finding_summary(current_tenant)

    @app.get("/v1/findings")
    def list_findings(
        request: Request,
        state: str | None = Query(
            default=None,
            pattern="^(open|resolved|suppressed|unknown)$",
        ),
        severity: str | None = Query(
            default=None,
            pattern="^(unknown|informational|low|medium|high|critical)$",
        ),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        rows = repo.list_findings(
            current_tenant,
            state=state,
            severity=severity,
            limit=limit,
            offset=offset,
        )
        return {"items": rows, "limit": limit, "offset": offset}

    @app.get("/v1/findings/{finding_id}")
    def finding_detail(request: Request, finding_id: str) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_finding(current_tenant, finding_id)
        if row is None:
            raise HTTPException(status_code=404, detail="finding not found")
        return row

    @app.get("/v1/vulnerabilities/summary")
    def vulnerability_summary(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return repo.vulnerability_summary(current_tenant)

    @app.get("/v1/vulnerabilities")
    def list_vulnerabilities(
        request: Request,
        state: str | None = Query(
            default=None,
            pattern="^(open|resolved|suppressed|unknown)$",
        ),
        severity: str | None = Query(
            default=None,
            pattern="^(unknown|informational|low|medium|high|critical)$",
        ),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        rows = repo.list_vulnerabilities(
            current_tenant,
            state=state,
            severity=severity,
            limit=limit,
            offset=offset,
        )
        return {"items": rows, "limit": limit, "offset": offset}

    @app.get("/v1/vulnerabilities/{vulnerability_id}")
    def vulnerability_detail(request: Request, vulnerability_id: UUID) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_vulnerability(current_tenant, str(vulnerability_id))
        if row is None:
            raise HTTPException(status_code=404, detail="vulnerability not found")
        return row

    @app.get("/v1/issues/summary")
    def issue_summary(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return repo.issue_summary(current_tenant)

    @app.get("/v1/issues")
    def list_issues(
        request: Request,
        state: str | None = Query(default=None, pattern="^(open|resolved|unknown)$"),
        severity: str | None = Query(
            default=None,
            pattern="^(unknown|informational|low|medium|high|critical)$",
        ),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        rows = repo.list_issues(
            current_tenant,
            state=state,
            severity=severity,
            limit=limit,
            offset=offset,
        )
        return {"items": rows, "limit": limit, "offset": offset}

    @app.get("/v1/issues/evaluations")
    def issue_evaluations(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {"items": repo.latest_issue_evaluations(current_tenant)}

    @app.get("/v1/issues/{issue_id}")
    def issue_detail(request: Request, issue_id: UUID) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_issue(current_tenant, str(issue_id))
        if row is None:
            raise HTTPException(status_code=404, detail="issue not found")
        return row

    @app.get("/v1/code-to-cloud/deployments")
    def code_to_cloud_deployments(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {"items": repo.code_to_cloud_deployments(current_tenant)}

    @app.get("/v1/code-to-cloud/observations")
    def code_to_cloud_observations(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {"items": repo.code_to_cloud_observations(current_tenant)}

    @app.get("/v1/activity/summary")
    def activity_summary(
        request: Request,
        include_fixtures: bool = Query(default=False),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return repo.activity_summary(current_tenant, include_fixtures=include_fixtures)

    @app.get("/v1/activity")
    def list_activity(
        request: Request,
        category: str | None = Query(
            default=None,
            pattern="^(model_invocation|agent_invocation|retrieval|tool_invocation|ai_app_sign_in|admin_change|data_access|other)$",
        ),
        outcome: str | None = Query(default=None, pattern="^(success|failure|unknown)$"),
        asset_id: Annotated[UUID | None, Query()] = None,
        include_fixtures: bool = Query(default=False),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {
            "items": repo.list_activity(
                current_tenant,
                category=category,
                outcome=outcome,
                asset_id=str(asset_id) if asset_id is not None else None,
                include_fixtures=include_fixtures,
                limit=limit,
                offset=offset,
            ),
            "limit": limit,
            "offset": offset,
        }

    @app.get("/v1/activity/{activity_id}")
    def activity_detail(request: Request, activity_id: UUID) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_activity(current_tenant, str(activity_id))
        if row is None:
            raise HTTPException(status_code=404, detail="activity not found")
        return row

    @app.get("/v1/detections/summary")
    def runtime_detection_summary(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return repo.runtime_detection_summary(current_tenant)

    @app.get("/v1/detections")
    def list_runtime_detections(
        request: Request,
        state: str | None = Query(default=None, pattern="^(open|resolved|unknown)$"),
        severity: str | None = Query(
            default=None,
            pattern="^(unknown|informational|low|medium|high|critical)$",
        ),
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
    ) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {
            "items": repo.list_runtime_detections(
                current_tenant,
                state=state,
                severity=severity,
                limit=limit,
                offset=offset,
            ),
            "limit": limit,
            "offset": offset,
        }

    @app.get("/v1/detections/evaluations")
    def runtime_detection_evaluations(request: Request) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        return {"items": repo.latest_runtime_detection_evaluations(current_tenant)}

    @app.get("/v1/detections/{detection_id}")
    def runtime_detection_detail(request: Request, detection_id: UUID) -> dict[str, Any]:
        repo, current_tenant = _context(request)
        row = repo.get_runtime_detection(current_tenant, str(detection_id))
        if row is None:
            raise HTTPException(status_code=404, detail="runtime detection not found")
        return row

    return app


def _context(request: Request) -> tuple[InventoryReader, str]:
    repository = request.app.state.repository
    if repository is None:
        raise HTTPException(status_code=503, detail="Denali storage is not configured")
    if request.app.state.auth_mode == "clerk":
        tenant_id = getattr(request.state, "denali_tenant_id", None)
        if tenant_id is None:
            raise HTTPException(status_code=401, detail="authentication required")
        return repository, str(tenant_id)
    return repository, request.app.state.tenant_id


def _clerk_admin_context(
    request: Request,
) -> tuple[AuthContext, ClerkOrganizationAdmin]:
    if request.app.state.auth_mode != "clerk":
        raise HTTPException(
            status_code=503, detail="Clerk organization administration is unavailable"
        )
    identity: AuthContext = request.state.denali_auth
    clerk_admin = request.app.state.clerk_organization_admin
    if clerk_admin is None:
        raise HTTPException(
            status_code=503, detail="Clerk organization administration is unavailable"
        )
    return identity, clerk_admin


def _normalized_emails(values: list[str]) -> list[str]:
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in values:
        email = raw.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 320:
            raise HTTPException(status_code=422, detail="every email must be a valid address")
        if email not in seen:
            normalized.append(email)
            seen.add(email)
    return normalized


def _optional_clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    return cleaned or None


def _context_for_tenant(request: Request, tenant_id: str) -> tuple[InventoryReader, str]:
    repository = request.app.state.repository
    if repository is None:
        raise HTTPException(status_code=503, detail="Denali storage is not configured")
    try:
        normalized = str(UUID(tenant_id))
    except ValueError as error:
        raise HTTPException(status_code=409, detail="provider setup state is invalid") from error
    return repository, normalized


def _with_validation_state(
    request: Request, tenant_id: str, row: dict[str, Any]
) -> dict[str, Any]:
    result = dict(row)
    connection_key = (tenant_id, str(result["id"]))
    result["validation_state"] = _connection_validation_state(
        request, tenant_id, str(result["id"])
    )
    with request.app.state.github_collection_lock:
        collecting = connection_key in request.app.state.active_github_collections
        collection_result = request.app.state.github_collection_results.get(connection_key)
    result["source_collection_state"] = "running" if collecting else "idle"
    result["last_source_collection"] = collection_result
    with request.app.state.gcp_deployment_collection_lock:
        gcp_collecting = (
            connection_key in request.app.state.active_gcp_deployment_collections
        )
        gcp_collection_result = request.app.state.gcp_deployment_collection_results.get(
            connection_key
        )
    result["deployment_collection_state"] = "running" if gcp_collecting else "idle"
    result["last_deployment_collection"] = gcp_collection_result
    with request.app.state.azure_deployment_collection_lock:
        azure_collecting = (
            connection_key in request.app.state.active_azure_deployment_collections
        )
        azure_collection_result = request.app.state.azure_deployment_collection_results.get(
            connection_key
        )
    if result["provider"] == "azure":
        result["deployment_collection_state"] = (
            "running" if azure_collecting else "idle"
        )
        result["last_deployment_collection"] = azure_collection_result
    with request.app.state.aws_deployment_collection_lock:
        aws_collecting = connection_key in request.app.state.active_aws_deployment_collections
        aws_collection_result = request.app.state.aws_deployment_collection_results.get(
            connection_key
        )
    if result["provider"] == "aws":
        result["deployment_collection_state"] = (
            "running" if aws_collecting else "idle"
        )
        result["last_deployment_collection"] = aws_collection_result
    result["setup_capabilities"] = {
        "cloudformation_quick_create": (
            result["provider"] == "aws"
            and request.app.state.cloudformation_launcher is not None
        ),
        "azure_cloud_shell": (
            result["provider"] == "azure"
            and request.app.state.azure_setup_launcher is not None
        ),
        "gcp_cloud_shell": (
            result["provider"] == "gcp"
            and request.app.state.gcp_setup_launcher is not None
        ),
        "github_app": (
            result["provider"] == "github"
            and request.app.state.github_app_client is not None
        ),
    }
    return result


def _connection_validation_state(
    request: Request, tenant_id: str, connection_id: str
) -> str:
    repository = request.app.state.repository
    durable_state = getattr(repository, "connection_validation_job_state", None)
    if durable_state is not None:
        return str(durable_state(tenant_id, connection_id))
    connection_key = (tenant_id, connection_id)
    with request.app.state.connection_validation_lock:
        running = connection_key in request.app.state.active_connection_validations
    return "running" if running else "idle"


def _is_public_request(request: Request) -> bool:
    if request.method == "OPTIONS":
        return True
    if request.url.path in {
        "/",
        "/healthz",
        "/openapi.json",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
        "/v1/connections/github/setup/callback",
        "/v1/connections/github/oauth/callback",
    }:
        return True
    return False


def _requires_admin(request: Request) -> bool:
    return request.url.path.startswith("/v1/") and request.method in {
        "POST",
        "PATCH",
        "PUT",
        "DELETE",
    }


def _cloudformation_launcher_from_environment() -> AwsCloudFormationLauncher | None:
    bucket_name = os.environ.get("DENALI_AWS_ONBOARDING_BUCKET")
    principal_arn = os.environ.get("DENALI_AWS_PRINCIPAL_ARN")
    if not bucket_name or not principal_arn:
        return None
    expires_in_seconds = _bounded_environment_integer(
        "DENALI_AWS_ONBOARDING_URL_SECONDS", default=3600, minimum=300, maximum=3600
    )
    return AwsCloudFormationLauncher(
        bucket_name=bucket_name,
        principal_arn=principal_arn,
        expires_in_seconds=expires_in_seconds,
    )


def _azure_setup_launcher_from_environment() -> AzureSetupScriptLauncher | None:
    bucket_name = os.environ.get("DENALI_AZURE_ONBOARDING_BUCKET")
    client_id = os.environ.get("DENALI_AZURE_CLIENT_ID")
    redirect_uri = os.environ.get("DENALI_AZURE_CONSENT_REDIRECT_URI") or os.environ.get(
        "DENALI_WEB_URL", "http://127.0.0.1:3080"
    )
    if not bucket_name or not client_id:
        return None
    expires_in_seconds = _bounded_environment_integer(
        "DENALI_AZURE_ONBOARDING_URL_SECONDS",
        default=3600,
        minimum=300,
        maximum=3600,
    )
    return AzureSetupScriptLauncher(
        bucket_name=bucket_name,
        client_id=client_id,
        redirect_uri=redirect_uri,
        expires_in_seconds=expires_in_seconds,
    )


def _gcp_setup_launcher_from_environment() -> GcpSetupScriptLauncher | None:
    bucket_name = os.environ.get("DENALI_GCP_ONBOARDING_BUCKET")
    if not bucket_name:
        return None
    expires_in_seconds = _bounded_environment_integer(
        "DENALI_GCP_ONBOARDING_URL_SECONDS",
        default=3600,
        minimum=300,
        maximum=3600,
    )
    return GcpSetupScriptLauncher(
        bucket_name=bucket_name,
        expires_in_seconds=expires_in_seconds,
    )


def _gcp_principal_provisioner_from_environment(
) -> GcpConnectionPrincipalProvisioner | None:
    operator_project_id = os.environ.get("DENALI_GCP_OPERATOR_PROJECT_ID")
    if not operator_project_id:
        return None
    return GcpConnectionPrincipalProvisioner(operator_project_id=operator_project_id)


def _github_app_from_environment() -> GitHubAppClient | None:
    app_id = os.environ.get("DENALI_GITHUB_APP_ID")
    client_id = os.environ.get("DENALI_GITHUB_CLIENT_ID")
    client_secret = os.environ.get("DENALI_GITHUB_CLIENT_SECRET")
    app_slug = os.environ.get("DENALI_GITHUB_APP_SLUG")
    private_key_value = os.environ.get("DENALI_GITHUB_PRIVATE_KEY")
    private_key_file = os.environ.get("DENALI_GITHUB_PRIVATE_KEY_FILE")
    callback_url = os.environ.get(
        "DENALI_GITHUB_CALLBACK_URL",
        "http://127.0.0.1:8088/v1/connections/github/oauth/callback",
    )
    web_url = os.environ.get("DENALI_WEB_URL", "http://127.0.0.1:3080")
    if not all((app_id, client_id, client_secret, app_slug)) or not (
        private_key_value or private_key_file
    ):
        return None
    if not str(app_id).isdigit():
        raise ValueError("DENALI_GITHUB_APP_ID must be a positive integer")
    private_key = (
        str(private_key_value).replace("\\n", "\n")
        if private_key_value
        else Path(str(private_key_file)).read_text(encoding="utf-8")
    )
    return GitHubAppClient(
        app_id=int(str(app_id)),
        client_id=str(client_id),
        client_secret=str(client_secret),
        private_key=private_key,
        app_slug=str(app_slug),
        callback_url=callback_url,
        web_url=web_url,
    )


def _decode_azure_completion_code(value: str) -> dict[str, Any]:
    encoded = value.strip()
    if encoded.startswith("DENALI_SETUP_COMPLETE="):
        encoded = encoded.split("=", 1)[1].strip()
    try:
        padding = "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded + padding))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=422, detail="Azure setup completion code is malformed"
        ) from error
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Azure setup completion code is malformed")
    return payload


def _decode_gcp_completion_code(value: str) -> dict[str, Any]:
    encoded = value.strip()
    if encoded.startswith("DENALI_GCP_SETUP_COMPLETE="):
        encoded = encoded.split("=", 1)[1].strip()
    try:
        padding = "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded + padding))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=422, detail="Google Cloud setup completion code is malformed"
        ) from error
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=422, detail="Google Cloud setup completion code is malformed"
        )
    return payload


def _azure_subscriptions_from_completion(payload: dict[str, Any]) -> list[dict[str, str]]:
    raw_subscriptions = payload.get("subscriptions")
    if not isinstance(raw_subscriptions, list) or not 1 <= len(raw_subscriptions) <= 200:
        raise HTTPException(status_code=422, detail="select between 1 and 200 subscriptions")
    subscriptions: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw_subscriptions:
        if not isinstance(item, dict):
            raise HTTPException(status_code=422, detail="Azure subscription selection is invalid")
        subscription_id = str(item.get("id", ""))
        name = str(item.get("name", "")).strip()
        normalized_id = subscription_id.lower()
        if not _valid_uuid_text(subscription_id) or not name or len(name) > 256:
            raise HTTPException(status_code=422, detail="Azure subscription selection is invalid")
        if normalized_id not in seen:
            seen.add(normalized_id)
            subscriptions.append({"id": subscription_id, "name": name})
    return subscriptions


def _gcp_projects_from_completion(payload: dict[str, Any]) -> list[dict[str, str]]:
    raw_projects = payload.get("projects")
    if not isinstance(raw_projects, list) or not 1 <= len(raw_projects) <= 200:
        raise HTTPException(status_code=422, detail="select between 1 and 200 projects")
    projects: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in raw_projects:
        if not isinstance(item, dict):
            raise HTTPException(
                status_code=422, detail="Google Cloud project selection is invalid"
            )
        project_id = str(item.get("id", ""))
        name = str(item.get("name", "")).strip()
        project_number = str(item.get("number", ""))
        if (
            not valid_gcp_project_id(project_id)
            or not name
            or len(name) > 256
            or not project_number.isdigit()
            or not 6 <= len(project_number) <= 30
        ):
            raise HTTPException(
                status_code=422, detail="Google Cloud project selection is invalid"
            )
        if project_id not in seen:
            seen.add(project_id)
            projects.append({"id": project_id, "name": name, "number": project_number})
    return projects


def _valid_uuid_text(value: str) -> bool:
    try:
        UUID(value)
    except ValueError:
        return False
    return True


def _github_state_context(value: str) -> tuple[str, str]:
    try:
        tenant_id, connection_id, token = value.split(".", 2)
        UUID(tenant_id)
        UUID(connection_id)
    except (ValueError, AttributeError) as error:
        raise HTTPException(status_code=409, detail="GitHub setup state is invalid") from error
    if len(token) < 32:
        raise HTTPException(status_code=409, detail="GitHub setup state is invalid")
    return tenant_id, connection_id


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _require_current_setup_expiry(
    target: dict[str, Any], *, key: str, detail: str
) -> None:
    try:
        expires_at = datetime.fromisoformat(target["configuration"]["onboarding"][key])
    except (KeyError, TypeError, ValueError) as error:
        raise HTTPException(status_code=409, detail="GitHub setup launch is not current") from error
    if datetime.now(UTC) > expires_at:
        raise HTTPException(status_code=409, detail=detail)


def _bounded_environment_integer(
    name: str, *, default: int, minimum: int, maximum: int
) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return min(maximum, max(minimum, value))


def _cors_origins() -> list[str]:
    raw = os.environ.get("DENALI_CORS_ORIGINS", "http://localhost:5173")
    return [item.strip() for item in raw.split(",") if item.strip()]


def _valid_aws_region(region: str, *, partition: str) -> bool:
    patterns = {
        "aws": (
            r"^(af|ap|ca|eu|il|me|mx|sa|us)-"
            r"(central|east|northeast|north|northwest|south|southeast|southwest|west)-[0-9]+$"
        ),
        "aws-us-gov": r"^us-gov-(east|west)-[0-9]+$",
        "aws-cn": r"^cn-(north|northwest)-[0-9]+$",
    }
    return bool(re.fullmatch(patterns[partition], region))


app = create_app()
