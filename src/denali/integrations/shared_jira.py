"""Bounded, read-only projections of Platform-owned Jira metadata.

No Jira token, credential reference, arbitrary JQL, or provider URL crosses this
product boundary. The Platform broker remains the only Jira API caller.
"""

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any
from uuid import UUID

_SITE = re.compile(r"https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.atlassian\.net")
_PROJECT_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,31}")
_NUMBER = re.compile(r"[1-9][0-9]{0,19}")
_ISSUE_KEY = re.compile(r"[A-Z][A-Z0-9_]{0,31}-[1-9][0-9]{0,19}")
_CURSOR = re.compile(r"[A-Za-z0-9_-]{1,8192}")
_SCOPES = {"jira.projects", "jira.issues", "jira.permissions"}
_EXPOSED_SCOPES = {"jira.projects", "jira.issues"}


def shared_jira_enabled() -> bool:
    """An absent or invalid flag never enables the external read bridge."""

    return os.environ.get("DENALI_ENABLE_SHARED_JIRA_READS", "false") == "true"


def _record(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("invalid shared Jira metadata")
    return value


def _text(value: Any, maximum: int) -> str:
    if not isinstance(value, str) or len(value) > maximum or any(
        ord(char) < 32 or ord(char) == 127 for char in value
    ):
        raise ValueError("invalid shared Jira metadata")
    return value


def _numeric_id(value: Any) -> int:
    if type(value) is not int or not 0 < value < 2**63:
        raise ValueError("invalid shared Jira project")
    return value


def _string_id(value: Any) -> str:
    if not isinstance(value, str) or _NUMBER.fullmatch(value) is None:
        raise ValueError("invalid shared Jira metadata")
    return value


def _enum(value: Any, allowed: set[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise ValueError("invalid shared Jira metadata")
    return value


def connection(value: Any, *, expected_id: UUID | None = None) -> dict[str, Any]:
    """Project only safe inventory/status fields and bind the selected UUID."""

    row = _record(value)
    try:
        connection_id = UUID(row["id"])
    except (KeyError, TypeError, ValueError, AttributeError) as error:
        raise ValueError("invalid shared Jira connection") from error
    if (
        str(connection_id) != row["id"]
        or (expected_id is not None and connection_id != expected_id)
        or row.get("provider") != "jira"
        or row.get("connection_kind") != "shared_jira"
        or not isinstance(row.get("site_url"), str)
        or _SITE.fullmatch(row["site_url"]) is None
    ):
        raise ValueError("invalid shared Jira connection")
    lifecycle_state = _enum(row.get("lifecycle_state"), {"active", "disabled"})
    health_state = _enum(row.get("health_state"), {"healthy", "unavailable", "disabled"})
    availability = _enum(
        row.get("availability"), {"ready", "unavailable", "disabled", "needs_scope_grant"}
    )
    projects = row.get("project_ids")
    if (
        not isinstance(projects, list)
        or not 1 <= len(projects) <= 25
        or len({_numeric_id(value) for value in projects}) != len(projects)
    ):
        raise ValueError("invalid shared Jira project selection")
    scopes = row.get("available_scopes")
    if (
        not isinstance(scopes, list)
        or len(scopes) > 3
        or any(not isinstance(scope, str) or scope not in _SCOPES for scope in scopes)
        or len(set(scopes)) != len(scopes)
    ):
        raise ValueError("invalid shared Jira scope selection")
    verified_at = row.get("verified_at")
    if verified_at is not None:
        _text(verified_at, 64)
        try:
            if datetime.fromisoformat(verified_at).tzinfo is None:
                raise ValueError("timezone required")
        except ValueError as error:
            raise ValueError("invalid shared Jira verification time") from error
    return {
        "id": str(connection_id),
        "site_url": row["site_url"],
        "project_ids": sorted(projects),
        "available_scopes": sorted(set(scopes) & _EXPOSED_SCOPES),
        "availability": availability,
        "lifecycle_state": lifecycle_state,
        "health_state": health_state,
        "verified_at": verified_at,
    }


def connections(value: Any, *, limit: int, offset: int) -> dict[str, Any]:
    rows = _record(value).get("items")
    if not isinstance(rows, list) or len(rows) > 100:
        raise ValueError("invalid shared Jira inventory")
    items = [connection(row) for row in rows]
    if len({row["id"] for row in items}) != len(items):
        raise ValueError("duplicate shared Jira connection")
    return {
        "items": items[offset : offset + limit],
        "limit": limit,
        "offset": offset,
        "has_more": offset + limit < len(items),
    }


def selected_projects(status: dict[str, Any], *, scope: str, project_id: int | None) -> list[int]:
    if status["availability"] != "ready" or scope not in status["available_scopes"]:
        raise PermissionError("shared Jira read unavailable")
    if project_id is not None:
        _numeric_id(project_id)
        if project_id not in status["project_ids"]:
            raise PermissionError("shared Jira project unavailable")
        return [project_id]
    return status["project_ids"]


def _project(value: Any, selected: set[int]) -> dict[str, Any]:
    row = _record(value)
    project_id = _string_id(row.get("id"))
    if int(project_id) not in selected:
        raise ValueError("shared Jira project outside selection")
    key = row.get("key")
    if not isinstance(key, str) or _PROJECT_KEY.fullmatch(key) is None:
        raise ValueError("invalid shared Jira project")
    result = {"id": project_id, "key": key, "name": _text(row.get("name"), 255)}
    if "project_type" in row:
        result["project_type"] = _enum(
            row["project_type"], {"software", "service_desk", "business"}
        )
    return result


def _named(value: Any, *, optional: bool = False) -> dict[str, str] | None:
    if value is None and optional:
        return None
    row = _record(value)
    return {"id": _string_id(row.get("id")), "name": _text(row.get("name"), 255)}


def _timestamp(value: Any) -> str | None:
    if value is None:
        return None
    _text(value, 64)
    try:
        if datetime.fromisoformat(value).tzinfo is None:
            raise ValueError("timezone required")
    except ValueError as error:
        raise ValueError("invalid shared Jira timestamp") from error
    return value


def _issue(value: Any, selected: set[int]) -> dict[str, Any]:
    row = _record(value)
    issue_id = _string_id(row.get("id"))
    key = row.get("key")
    if not isinstance(key, str) or _ISSUE_KEY.fullmatch(key) is None:
        raise ValueError("invalid shared Jira issue")
    project = _project(row.get("project"), selected)
    if not key.startswith(project["key"] + "-"):
        raise ValueError("inconsistent shared Jira issue")
    return {
        "id": issue_id,
        "key": key,
        "project": project,
        "summary": _text(row.get("summary"), 1024),
        "status": _named(row.get("status")),
        "issue_type": _named(row.get("issue_type")),
        "priority": _named(row.get("priority"), optional=True),
        "created": _timestamp(row.get("created")),
        "updated": _timestamp(row.get("updated")),
    }


def read_result(
    value: Any, *, operation: str, selected: list[int], limit: int, issue_id: str | None = None
) -> dict[str, Any]:
    """Rebuild exact public shapes; discard every unapproved broker field."""

    row = _record(value)
    if operation not in {"projects", "issues", "issue_detail"}:
        raise ValueError("unsupported shared Jira read")
    if operation == "issue_detail":
        issue = _issue(row.get("issue"), set(selected))
        if issue_id not in {issue["id"], issue["key"]}:
            raise ValueError("shared Jira issue identity changed")
        return {"issue": issue}
    field = operation
    items = row.get(field)
    if not isinstance(items, list) or len(items) > limit:
        raise ValueError("invalid shared Jira page")
    projector = _project if operation == "projects" else _issue
    projected = [projector(item, set(selected)) for item in items]
    if len({item["id"] for item in projected}) != len(projected):
        raise ValueError("duplicate shared Jira result")
    cursor = row.get("next_cursor")
    if cursor is not None and (not isinstance(cursor, str) or _CURSOR.fullmatch(cursor) is None):
        raise ValueError("invalid shared Jira cursor")
    return {field: projected, "next_cursor": cursor}
