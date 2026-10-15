"""Durable, tenant-owned onboarding receipts; no provider code or credential storage."""

from __future__ import annotations

import hashlib
import re
import secrets
from typing import Any

RETURN_STATE_PATTERN = r"[A-Za-z0-9_-]{43}"
WORKFLOW_FIELDS = (
    "id",
    "provider",
    "management_source",
    "connection_id",
    "platform_connection_id",
    "stage",
    "status",
    "expires_at",
    "created_at",
    "updated_at",
    "error_code",
)


def new_return_state() -> tuple[str, str]:
    state = secrets.token_urlsafe(32)
    return state, state_digest(state)


def state_digest(state: str) -> str:
    if not re.fullmatch(RETURN_STATE_PATTERN, state):
        raise ValueError("invalid onboarding return state")
    return hashlib.sha256(state.encode("ascii")).hexdigest()


def workflow_projection(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row.get(key) for key in WORKFLOW_FIELDS}
