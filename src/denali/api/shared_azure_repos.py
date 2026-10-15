"""Organization-admin handoff and immutable local Azure Repos attachments."""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, urlsplit
from uuid import UUID, uuid4

from fastapi import APIRouter, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator

from denali.api.connection_workflows import new_return_state
from denali.connections.azure_repos import (
    AZURE_REPOS_SCOPE_METADATA,
    AZURE_REPOS_SCOPES,
    _same_repository,
    azure_repos_coverage_plan,
    valid_azure_devops_organization,
)
from denali.integrations.shared_azure_repos import (
    CREDENTIAL_TYPE,
    ROOT,
    SharedAzureReposClient,
    normalize_repositories,
    shared_azure_repos_binding_id,
    shared_azure_repos_enabled,
)

_ERROR_CODES = {
    "validation_failed",
    "dispatch_failed",
    "connector_disabled",
    "authorization_changed",
    "lease_expired",
}


def _valid_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 100
        and bool(value.strip())
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


class _Scopes(BaseModel):
    model_config = ConfigDict(extra="forbid")
    declared_scopes: list[str] = Field(
        default_factory=lambda: list(AZURE_REPOS_SCOPES), min_length=1, max_length=2
    )

    @model_validator(mode="after")
    def valid_scopes(self):
        if (
            len(set(self.declared_scopes)) != len(self.declared_scopes)
            or not set(self.declared_scopes) <= set(AZURE_REPOS_SCOPES)
            or AZURE_REPOS_SCOPE_METADATA not in self.declared_scopes
        ):
            raise ValueError("invalid Azure Repos scopes")
        return self


class SetupInput(_Scopes):
    request_id: UUID
    target_id: UUID


class LaunchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_id: UUID = Field(default_factory=uuid4)
    connection_id: UUID | None = None


class UseInput(_Scopes):
    repository_ids: list[UUID] = Field(min_length=1, max_length=500)

    @model_validator(mode="after")
    def unique_ids(self):
        if len(set(self.repository_ids)) != len(self.repository_ids):
            raise ValueError("repository selection is duplicated")
        return self


class DeleteInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmation_name: str = Field(min_length=1, max_length=100)


def _projection(value: Any, *, expected_id: str | None = None) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("provider") != "azure_repos":
        raise ValueError("invalid shared Azure Repos metadata")
    result = {
        key: value.get(key)
        for key in (
            "id",
            "provider",
            "connection_kind",
            "target_id",
            "tenant_id",
            "organization",
            "application_client_id",
            "display_name",
            "lifecycle_state",
            "setup_state",
            "health_state",
            "declared_scopes",
            "validated_scopes",
            "repository_count",
            "last_validated_at",
            "availability",
            "authority_revision",
            "job_id",
            "job_state",
            "error_code",
            "retry_available",
        )
        if key in value
    }
    for field in ("id", "target_id", "tenant_id", "application_client_id"):
        if str(UUID(str(result.get(field)))) != result.get(field):
            raise ValueError("invalid shared Azure Repos identity")
    if expected_id is not None and result["id"] != expected_id:
        raise ValueError("shared Azure Repos response identifies another connection")
    if not isinstance(result.get("organization"), str) or not valid_azure_devops_organization(
        result["organization"]
    ):
        raise ValueError("invalid Azure DevOps organization")
    if (
        result.get("connection_kind") != "shared_azure_repos"
        or result.get("lifecycle_state") not in {"active", "disabled", "deleted"}
        or result.get("health_state")
        not in {"unknown", "healthy", "partial", "unhealthy", "disabled"}
        or result.get("setup_state") not in {"pending", "ready", "failed"}
        or result.get("availability")
        not in {"disabled", "needs_setup", "needs_validation", "ready", "needs_scope_grant"}
    ):
        raise ValueError("invalid shared Azure Repos state")
    for field in ("declared_scopes", "validated_scopes"):
        scopes = result.get(field)
        if (
            not isinstance(scopes, list)
            or len(set(scopes)) != len(scopes)
            or not set(scopes) <= set(AZURE_REPOS_SCOPES)
        ):
            raise ValueError("invalid shared Azure Repos scopes")
    if AZURE_REPOS_SCOPE_METADATA not in result["declared_scopes"] or not set(
        result["validated_scopes"]
    ) <= set(result["declared_scopes"]):
        raise ValueError("invalid shared Azure Repos scope evidence")
    if not _valid_name(result.get("display_name")):
        raise ValueError("invalid shared Azure Repos name")
    if (
        type(result.get("repository_count")) is not int
        or not 0 <= result["repository_count"] <= 500
        or type(result.get("authority_revision")) is not int
        or not 1 <= result["authority_revision"] <= 2**63 - 1
    ):
        raise ValueError("invalid shared Azure Repos inventory evidence")
    validated_at = result.get("last_validated_at")
    if validated_at is not None:
        if not isinstance(validated_at, str) or len(validated_at) > 64:
            raise ValueError("invalid shared Azure Repos validation timestamp")
        if datetime.fromisoformat(validated_at).tzinfo is None:
            raise ValueError("invalid shared Azure Repos validation timestamp")
    if result.get("job_id") is not None and str(UUID(result["job_id"])) != result["job_id"]:
        raise ValueError("invalid shared Azure Repos job identity")
    if result.get("job_state") not in {None, "queued", "running", "succeeded", "failed"}:
        raise ValueError("invalid shared Azure Repos job state")
    if result.get("error_code") is not None and result["error_code"] not in _ERROR_CODES:
        raise ValueError("invalid shared Azure Repos error code")
    if "retry_available" in result and type(result["retry_available"]) is not bool:
        raise ValueError("invalid shared Azure Repos retry evidence")
    return result


def register_shared_azure_repos_routes(
    app: FastAPI,
    *,
    context: Callable,
    shared_context: Callable,
    shared_request: Callable,
    present: Callable,
) -> None:
    router = APIRouter(prefix="/v1/shared/connections/azure-repos")

    def require(request: Request):
        if not shared_azure_repos_enabled():
            raise HTTPException(status_code=404, detail="shared Azure Repos is not enabled")
        return shared_context(request)

    def upstream(request, method, path, *, payload=None):
        require(request)
        return shared_request(request, method, path, payload=payload, max_response_bytes=1_100_000)

    def status(request, identifier):
        value = upstream(request, "GET", f"{ROOT}/{identifier}/status")
        try:
            return _projection(value, expected_id=str(identifier))
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(
                status_code=502, detail="invalid shared Azure Repos metadata"
            ) from None

    @router.get("/config")
    def configuration(request: Request, response: Response):
        value = upstream(request, "GET", f"{ROOT}/config")
        try:
            if (
                not isinstance(value, dict)
                or not isinstance(value.get("items"), list)
                or len(value["items"]) > 100
            ):
                raise ValueError("invalid target inventory")
            targets = []
            for item in value["items"]:
                target = {
                    key: item[key]
                    for key in (
                        "target_id",
                        "tenant_id",
                        "organization",
                        "application_client_id",
                        "display_name",
                    )
                }
                for field in ("target_id", "tenant_id", "application_client_id"):
                    if str(UUID(target[field])) != target[field]:
                        raise ValueError("invalid target identity")
                if not valid_azure_devops_organization(target["organization"]) or not _valid_name(
                    target["display_name"]
                ):
                    raise ValueError("invalid target organization")
                targets.append(target)
        except (ValueError, TypeError, KeyError, AttributeError):
            raise HTTPException(
                status_code=502, detail="invalid shared Azure Repos targets"
            ) from None
        response.headers["Cache-Control"] = "no-store"
        return {"items": targets}

    @router.get("")
    def listing(request: Request, response: Response):
        value = upstream(request, "GET", ROOT)
        try:
            if (
                not isinstance(value, dict)
                or not isinstance(value.get("items"), list)
                or len(value["items"]) > 100
            ):
                raise ValueError("invalid connection inventory")
            items = [_projection(item) for item in value["items"]]
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(
                status_code=502, detail="invalid shared Azure Repos inventory"
            ) from None
        response.headers["Cache-Control"] = "no-store"
        return {"items": items}

    @router.post("/setup", status_code=201)
    def create(request: Request, response: Response, payload: SetupInput):
        value = upstream(request, "POST", f"{ROOT}/setup", payload=payload.model_dump(mode="json"))
        try:
            identifier = str(UUID(value["id"]))
        except (ValueError, KeyError, TypeError, AttributeError):
            raise HTTPException(
                status_code=502, detail="invalid shared Azure Repos setup"
            ) from None
        response.headers["Cache-Control"] = "no-store"
        return {"id": identifier}

    @router.get("/{connection_id}/status")
    def connection_status(request: Request, response: Response, connection_id: UUID):
        response.headers["Cache-Control"] = "no-store"
        return status(request, connection_id)

    @router.get("/{connection_id}/repositories")
    def repositories(request: Request, response: Response, connection_id: UUID):
        status(request, connection_id)
        try:
            values = normalize_repositories(
                upstream(request, "GET", f"{ROOT}/{connection_id}/repositories")
            )
        except (ValueError, TypeError, AttributeError):
            raise HTTPException(
                status_code=502, detail="invalid shared Azure Repos repository selection"
            ) from None
        response.headers["Cache-Control"] = "no-store"
        return {"items": values}

    @router.post("/{connection_id}/setup", status_code=201)
    def launch(request: Request, response: Response, connection_id: UUID, payload: LaunchInput):
        source = status(request, connection_id)
        platform, _ = require(request)
        repo, tenant = context(request)
        if payload.connection_id:
            row = repo.get_connection(tenant, str(payload.connection_id))
            if (
                row is None
                or row.get("provider") != "azure_repos"
                or row.get("credential_reference", {}).get("type") != CREDENTIAL_TYPE
                or row["credential_reference"].get("platform_connection_id") != str(connection_id)
            ):
                raise HTTPException(status_code=404, detail="Denali attachment not found")
        state, digest = new_return_state()
        try:
            workflow = repo.begin_connection_onboarding(
                tenant,
                provider="azure_repos",
                request_id=str(payload.request_id),
                return_state_sha256=digest,
                connection_id=str(payload.connection_id) if payload.connection_id else None,
                platform_connection_id=str(connection_id),
            )
        except ValueError:
            raise HTTPException(
                status_code=409, detail="onboarding request settings differ"
            ) from None
        try:
            value = upstream(
                request, "POST", f"{ROOT}/{connection_id}/setup", payload={"return_state": state}
            )
            url = value.get("authorize_url") if isinstance(value, dict) else None
            parsed = urlsplit(url) if isinstance(url, str) and len(url) <= 4096 else None
            if (
                parsed is None
                or parsed.scheme != "https"
                or parsed.netloc != "login.microsoftonline.com"
                or parsed.path != f"/{source['tenant_id']}/oauth2/v2.0/authorize"
                or parsed.fragment
            ):
                raise ValueError("invalid authorization link")
            params = parse_qs(
                parsed.query, strict_parsing=True, keep_blank_values=True, max_num_fields=16
            )
            expected_callback = f"{platform.origin}{ROOT}/setup/callback"
            if (
                any(len(values) != 1 for values in params.values())
                or set(params)
                - {
                    "client_id",
                    "code_challenge_method",
                    "code_challenge",
                    "response_type",
                    "redirect_uri",
                    "scope",
                    "state",
                    "response_mode",
                    "prompt",
                }
                or params.get("client_id") != [source["application_client_id"]]
                or params.get("code_challenge_method") != ["S256"]
                or params.get("response_type") != ["code"]
                or params.get("redirect_uri") != [expected_callback]
                or value.get("callback_url") != expected_callback
                or params.get("scope") != ["https://app.vssps.visualstudio.com/.default"]
                or not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", params.get("state", [""])[0])
                or not re.fullmatch(r"[A-Za-z0-9_-]{43}", params.get("code_challenge", [""])[0])
                or params.get("response_mode", ["query"]) != ["query"]
                or params.get("prompt", ["select_account"]) != ["select_account"]
                or value.get("application_client_id", source["application_client_id"])
                != source["application_client_id"]
            ):
                raise ValueError("invalid authorization link binding")
        except (HTTPException, ValueError, TypeError):
            repo.fail_connection_onboarding(tenant, str(workflow["id"]), return_state_sha256=digest)
            raise HTTPException(
                status_code=502, detail="shared Azure Repos authorization unavailable"
            ) from None
        response.headers["Cache-Control"] = "no-store"
        return {"authorize_url": url, "workflow_id": str(workflow["id"])}

    @router.post("/{connection_id}/validate", status_code=202)
    def validate(request: Request, response: Response, connection_id: UUID):
        value = upstream(request, "POST", f"{ROOT}/{connection_id}/validate", payload={})
        try:
            job_id = str(UUID(value["job_id"]))
            state = value["state"]
            if state not in {"queued", "running"}:
                raise ValueError("invalid job state")
        except (ValueError, KeyError, TypeError, AttributeError):
            raise HTTPException(
                status_code=502, detail="invalid shared Azure Repos validation job"
            ) from None
        response.headers["Cache-Control"] = "no-store"
        return {"job_id": job_id, "state": state}

    @router.post("/{connection_id}/use-in-denali", status_code=201)
    def attach(request: Request, connection_id: UUID, payload: UseInput):
        platform, org = require(request)
        repo, tenant = context(request)
        source = status(request, connection_id)
        if (
            source.get("availability") != "ready"
            or source["health_state"] != "healthy"
            or source["lifecycle_state"] != "active"
            or source["setup_state"] != "ready"
        ):
            raise HTTPException(status_code=409, detail="verify shared Azure Repos access first")
        if not set(payload.declared_scopes) <= set(source["validated_scopes"]):
            raise HTTPException(status_code=403, detail="Azure Repos scopes are not entitled")
        available = repositories(request, Response(), connection_id)["items"]
        ids = {str(value) for value in payload.repository_ids}
        if not ids <= {row["id"] for row in available}:
            raise HTTPException(status_code=409, detail="selected repositories are unavailable")
        selected = [row for row in available if row["id"] in ids]
        local_id = shared_azure_repos_binding_id(
            org, str(connection_id), list(ids), payload.declared_scopes
        )
        reference = {"platform_connection_id": str(connection_id)}
        config = {
            "coverage_mode": "exact-azure-repositories",
            "tenant_id": source["tenant_id"],
            "organization": source["organization"],
            "repositories": selected,
            "onboarding": {
                "method": CREDENTIAL_TYPE,
                "completed_at": datetime.now(UTC).isoformat(),
            },
        }

        def matches(row):
            stored = row.get("configuration") or {}
            try:
                originals = {
                    item["id"]: item
                    for item in normalize_repositories({"items": stored.get("repositories")})
                }
            except (ValueError, TypeError, AttributeError):
                return False
            return (
                row.get("lifecycle_state") == "active"
                and row.get("provider") == "azure_repos"
                and row.get("credential_reference", {}).get("type") == CREDENTIAL_TYPE
                and row["credential_reference"].get("platform_connection_id") == str(connection_id)
                and set(row.get("declared_scopes") or []) == set(payload.declared_scopes)
                and stored.get("tenant_id") == config["tenant_id"]
                and stored.get("organization") == config["organization"]
                and stored.get("coverage_mode") == "exact-azure-repositories"
                and set(originals) == ids
                and all(_same_repository(originals[item["id"]], item) for item in selected)
            )

        existing = repo.get_connection(tenant, local_id)
        if existing is not None:
            if not matches(existing):
                raise HTTPException(status_code=409, detail="existing Denali attachment differs")
            return present(request, tenant, existing)
        target = {
            "id": local_id,
            "provider": "azure_repos",
            "lifecycle_state": "active",
            "credential_type": CREDENTIAL_TYPE,
            "credential_reference": reference,
            "configuration": config,
            "declared_scopes": payload.declared_scopes,
            "clerk_organization_id": org,
        }
        try:
            verifier = SharedAzureReposClient(platform, target)
            verifier.list_repositories(
                organization=source["organization"],
                token=verifier.application_token(source["tenant_id"]),
            )
        except Exception:
            raise HTTPException(
                status_code=502, detail="live Azure Repos identity verification failed"
            ) from None
        try:
            row = repo.create_connection(
                tenant,
                connection_id=local_id,
                provider="azure_repos",
                display_name=f"Azure Repos {source['organization']} {local_id[:8]}",
                credential_type=CREDENTIAL_TYPE,
                credential_reference=reference,
                declared_scopes=payload.declared_scopes,
                configuration=config,
                coverage_plan=azure_repos_coverage_plan(
                    payload.declared_scopes,
                    organization=source["organization"],
                    repositories=selected,
                ),
            )
        except ValueError:
            row = repo.get_connection(tenant, local_id)
            if row is None or not matches(row):
                raise HTTPException(
                    status_code=409, detail="Azure Repos attachment conflicted"
                ) from None
        response = present(request, tenant, row)
        return response

    @router.post("/{connection_id}/disable")
    def disable(request: Request, connection_id: UUID):
        value = upstream(request, "POST", f"{ROOT}/{connection_id}/disable", payload={})
        if not isinstance(value, dict) or value.get("status") != "disabled":
            raise HTTPException(status_code=502, detail="shared disable did not complete")
        return {"status": "disabled"}

    @router.delete("/{connection_id}")
    def delete(request: Request, connection_id: UUID, payload: DeleteInput):
        value = upstream(request, "DELETE", f"{ROOT}/{connection_id}", payload=payload.model_dump())
        if not isinstance(value, dict) or value.get("status") != "deleted":
            raise HTTPException(status_code=502, detail="shared delete did not complete")
        return {"status": "deleted"}

    app.include_router(router)
