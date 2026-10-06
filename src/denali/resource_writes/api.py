"""Typed remediation routes; browser and MCP call this same product service."""

from __future__ import annotations

from typing import Any, Literal
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator

from denali.resource_writes.contract import RESOURCE_WRITE_RECEIVER
from denali.resource_writes.templates import GITHUB_ACTION, PURPOSES, RemediationError

INTERNAL_PATH = RESOURCE_WRITE_RECEIVER


class PreviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_id: UUID
    grant_id: UUID
    resource_action: Literal["github.guardrail_draft_pr", "aws.tighten_bedrock_inline_policy"]
    parameters: dict[str, Any]
    expected_organization_id: str = Field(pattern=r"^org_[A-Za-z0-9]+$")

    @model_validator(mode="after")
    def bounded_parameters(self):
        if self.resource_action == GITHUB_ACTION:
            if set(self.parameters) != {"guardrail_id", "guardrail_version"} or any(
                not isinstance(value, str) or len(value) > 64 for value in self.parameters.values()
            ):
                raise ValueError("invalid guardrail parameters")
        elif (
            set(self.parameters) != {"model_arns"}
            or not isinstance(self.parameters["model_arns"], list)
            or not 1 <= len(self.parameters["model_arns"]) <= 20
            or any(
                not isinstance(arn, str) or len(arn) > 512 for arn in self.parameters["model_arns"]
            )
        ):
            raise ValueError("invalid model parameters")
        return self


class RequestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    preview_id: UUID
    preview_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    justification: str = Field(min_length=1, max_length=2000)
    expected_organization_id: str = Field(pattern=r"^org_[A-Za-z0-9]+$")
    confirm: Literal[True]

    @model_validator(mode="before")
    @classmethod
    def explicit(cls, value):
        if not isinstance(value, dict) or value.get("confirm") is not True:
            raise ValueError("explicit confirmation required")
        return value


class ReviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approved", "rejected"]
    review_note: str = Field(min_length=1, max_length=2000)
    expected_organization_id: str = Field(pattern=r"^org_[A-Za-z0-9]+$")
    confirm: Literal[True]

    @model_validator(mode="before")
    @classmethod
    def explicit(cls, value):
        if not isinstance(value, dict) or value.get("confirm") is not True:
            raise ValueError("explicit confirmation required")
        return value


class GatewayAction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["preview", "request", "review", "reconcile"]
    resource_action: Literal["github.guardrail_draft_pr", "aws.tighten_bedrock_inline_policy"]
    payload: dict[str, Any]
    request_id: UUID | None = None


class ReconcileInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_organization_id: str = Field(pattern=r"^org_[A-Za-z0-9]+$")


def register_remediation_routes(app: FastAPI):
    def service(request):
        value = getattr(request.app.state, "resource_write_service", None)
        if value is None:
            raise HTTPException(404, "resource actions disabled")
        return value

    def context(request, expected=None):
        identity = getattr(request.state, "denali_auth", None)
        tenant = getattr(request.state, "denali_tenant_id", None)
        if identity is None or not tenant or not identity.can_write:
            raise HTTPException(403, "organization admin required")
        if expected is not None and identity.organization_id != expected:
            raise HTTPException(409, "active organization changed")
        return tenant, identity

    def safe(call):
        try:
            return call()
        except RemediationError as error:
            code = str(error)
            status = (
                404
                if code.endswith("not_found") or code == "resource_action_disabled"
                else (
                    503
                    if "unavailable" in code
                    else 403
                    if "admin_required" in code or (code == "self_approval_forbidden")
                    else 409
                )
            )
            raise HTTPException(status, code) from None

    @app.post("/v1/resource-writes/previews")
    def preview(payload: PreviewInput, request: Request, response: Response):
        tenant, identity = context(request, payload.expected_organization_id)
        response.headers["Cache-Control"] = "no-store"
        return safe(
            lambda: service(request).preview(
                tenant_id=tenant,
                organization_id=identity.organization_id,
                actor=identity.user_id,
                finding_id=str(payload.finding_id),
                grant_id=str(payload.grant_id),
                action=payload.resource_action,
                parameters=payload.parameters,
            )
        )

    @app.post("/v1/resource-writes/requests", status_code=201)
    def submit(payload: RequestInput, request: Request, response: Response):
        tenant, identity = context(request, payload.expected_organization_id)
        import re

        key = request.headers.get("idempotency-key", "")
        if re.fullmatch(r"[A-Za-z0-9_-]{8,128}", key) is None:
            raise HTTPException(422, "valid idempotency key required")
        response.headers["Cache-Control"] = "no-store"
        return safe(
            lambda: service(request).request(
                tenant_id=tenant,
                organization_id=identity.organization_id,
                actor=identity.user_id,
                preview_id=str(payload.preview_id),
                preview_sha256=payload.preview_sha256,
                key=key,
                justification=payload.justification,
            )
        )

    @app.post("/v1/resource-writes/requests/{request_id}/review")
    def review(request_id: UUID, payload: ReviewInput, request: Request, response: Response):
        tenant, identity = context(request, payload.expected_organization_id)
        response.headers["Cache-Control"] = "no-store"
        value = safe(
            lambda: service(request).review(
                tenant_id=tenant,
                organization_id=identity.organization_id,
                actor=identity.user_id,
                request_id=str(request_id),
                decision=payload.decision,
                note=payload.review_note,
            )
        )
        if value["state"] == "approved":
            dispatcher = getattr(request.app.state, "resource_write_dispatcher", None)
            if dispatcher is None:
                raise HTTPException(503, "resource worker unavailable; approval recorded")
            try:
                call_id = dispatcher(str(request_id))
                service(request).store.record_dispatch(tenant, str(request_id), call_id)
            except Exception:
                raise HTTPException(
                    503, "resource dispatch unavailable; approval recorded"
                ) from None
        return value

    @app.get("/v1/resource-writes/requests/{request_id}")
    def status(request_id: UUID, request: Request, response: Response):
        tenant, _ = context(request)
        response.headers["Cache-Control"] = "no-store"
        return safe(lambda: service(request).status(tenant, str(request_id)))

    @app.post("/v1/resource-writes/requests/{request_id}/reconcile")
    def reconcile(request_id: UUID, payload: ReconcileInput, request: Request, response: Response):
        tenant, identity = context(request, payload.expected_organization_id)
        response.headers["Cache-Control"] = "no-store"
        return safe(
            lambda: service(request).reconcile(
                tenant_id=tenant,
                organization_id=identity.organization_id,
                actor=identity.user_id,
                request_id=str(request_id),
            )
        )

    @app.post(INTERNAL_PATH)
    def gateway(payload: GatewayAction, request: Request, response: Response):
        tenant, _ = context(request)
        receiver = service(request)
        if (
            getattr(request.state, "resource_write_purpose", None)
            != PURPOSES[payload.resource_action]
        ):
            raise HTTPException(403, "dedicated resource permission required")
        try:
            if payload.action == "preview":
                parsed = PreviewInput.model_validate(payload.payload)
                if parsed.resource_action != payload.resource_action:
                    raise HTTPException(422, "resource action mismatch")
                return preview(parsed, request, response)
            if payload.action == "request":
                parsed = RequestInput.model_validate(payload.payload)
                existing = receiver.store.get_preview(tenant, str(parsed.preview_id))
                if not existing or existing["action"] != payload.resource_action:
                    raise HTTPException(404, "resource request not found")
                return submit(parsed, request, response)
            if payload.request_id is None:
                raise HTTPException(422, "request id required")
            existing = receiver.store.get(tenant, str(payload.request_id))
            if not existing or existing["action"] != payload.resource_action:
                raise HTTPException(404, "resource request not found")
            if payload.action == "reconcile":
                return reconcile(
                    payload.request_id,
                    ReconcileInput.model_validate(payload.payload),
                    request,
                    response,
                )
            return review(
                payload.request_id, ReviewInput.model_validate(payload.payload), request, response
            )
        except ValueError:
            raise HTTPException(422, "invalid resource action") from None
