"""Versioned deterministic templates, not model-generated executable patches."""

from __future__ import annotations

import copy
import difflib
import fnmatch
import hashlib
import json
import re
from typing import Any

from denali.connectors.repository_posture import (
    _balanced_object_end,
    _bedrock_command_sites,
    _bedrock_import_aliases,
    _skip_space_and_comments,
)
from denali.resource_writes.contract import RESOURCE_WRITE_PURPOSES

TEMPLATE_VERSION = 1
GITHUB_ACTION = "github.guardrail_draft_pr"
AWS_ACTION = "aws.tighten_bedrock_inline_policy"
PURPOSES = RESOURCE_WRITE_PURPOSES
MAX_SOURCE_BYTES = 100_000
_SECRET_SOURCE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\bgh[pousr]_[A-Za-z0-9_]{20,}|"
    r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}|"
    r"(?:api[_-]?key|access[_-]?token|client[_-]?secret|password|secret[_-]?key)"
    r"\s*[:=]\s*['\"][^'\"\r\n]{8,}['\"]",
    re.IGNORECASE,
)
_INVOKE_ACTIONS = frozenset(
    {
        "bedrock:invokemodel",
        "bedrock:invokemodelwithresponsestream",
        "bedrock:converse",
        "bedrock:conversestream",
    }
)


class RemediationError(ValueError):
    """Stable safe code only; provider exceptions must never escape into tools."""


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256(value: Any) -> str:
    data = value if isinstance(value, bytes) else canonical(value).encode()
    return hashlib.sha256(data).hexdigest()


def git_blob_sha(content: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()


def open_finding(finding: dict[str, Any], action: str) -> None:
    rules = {
        GITHUB_ACTION: {"DENALI-REPO-AI-GRD-001", "DENALI-REPO-AI-GRD-002"},
        AWS_ACTION: {"DENALI-AWS-AI-IAM-001"},
    }
    if (
        action not in rules
        or finding.get("rule_uid") not in rules[action]
        or (finding.get("state") != "open" or finding.get("evaluation_result") != "fail")
    ):
        raise RemediationError("unsupported_or_inactive_finding")


def _code_positions(text: str) -> list[bool]:
    """Conservative lexical guard around the existing detector's regex sites.

    v1 intentionally rejects regex/division/template syntax rather than guess.
    Comments and quoted strings cannot become executable patch locations.
    """
    positions = [False] * len(text)
    state, escaped, index = "code", False, 0
    while index < len(text):
        char, nxt = text[index], text[index + 1 : index + 2]
        if state in {"single", "double"}:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == ("'" if state == "single" else '"'):
                state = "code"
        elif state == "line":
            if char == "\n":
                state = "code"
        elif state == "block":
            if char == "*" and nxt == "/":
                state = "code"
                index += 1
        elif char in {"'", '"'}:
            state = "single" if char == "'" else "double"
        elif char == "/":
            if nxt == "/":
                state = "line"
                index += 1
            elif nxt == "*":
                state = "block"
                index += 1
            else:
                raise RemediationError("source_syntax_not_supported")
        elif char == "`":
            raise RemediationError("source_syntax_not_supported")
        else:
            positions[index] = True
        index += 1
    if state not in {"code", "line"}:
        raise RemediationError("source_syntax_not_supported")
    return positions


def eligible_source_path(path):
    if not isinstance(path, str) or (
        re.fullmatch(r"(?:src|app|lib)/[A-Za-z0-9_./-]+\.(?:js|ts)", path) is None
        or any(
            part in {"", ".", "..", "vendor", "generated", "node_modules"}
            for part in path.split("/")
        )
    ):
        raise RemediationError("source_path_not_eligible")


def _literal_property_keys(text, start, end, code_positions):
    """Positively classify outer keys; detector regex is not an executable proof.

    Only unquoted ASCII identifier: value properties are supported. Computed,
    escaped, quoted, shorthand, method/accessor/spread keys all fail closed.
    Strings/comments and nested expression commas do not split properties.
    """
    keys, position = [], start + 1
    while True:
        position = _skip_space_and_comments(text, position)
        if position == end:
            return keys
        match = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", text[position:end])
        if match is None or not code_positions[position]:
            raise RemediationError("source_property_shape_not_supported")
        key = match.group(0)
        position = _skip_space_and_comments(text, position + len(key))
        if position >= end or text[position] != ":" or key in keys:
            raise RemediationError("source_property_shape_not_supported")
        keys.append(key)
        position = _skip_space_and_comments(text, position + 1)
        if position >= end or text[position] == ",":
            raise RemediationError("source_property_shape_not_supported")
        depths = {"{": 0, "[": 0, "(": 0}
        closing = {"}": "{", "]": "[", ")": "("}
        while position < end:
            char = text[position]
            if code_positions[position]:
                if char in depths:
                    depths[char] += 1
                elif char in closing:
                    opening = closing[char]
                    if depths[opening] <= 0:
                        raise RemediationError("source_property_shape_not_supported")
                    depths[opening] -= 1
                elif char == "," and not any(depths.values()):
                    position += 1
                    break
            position += 1
        if position == end and any(depths.values()):
            raise RemediationError("source_property_shape_not_supported")


def github_patch(finding: dict[str, Any], content: bytes, parameters: dict[str, Any]):
    """Add only guardrail fields at one positively identified literal SDK call."""
    open_finding(finding, GITHUB_ACTION)
    if (
        set(parameters) != {"guardrail_id", "guardrail_version"}
        or re.fullmatch(r"[a-z0-9]{1,64}", str(parameters.get("guardrail_id", ""))) is None
        or re.fullmatch(r"[1-9][0-9]{0,7}", str(parameters.get("guardrail_version", ""))) is None
    ):
        raise RemediationError("invalid_guardrail_selection")
    attributes = finding.get("attributes") or {}
    path = attributes.get("source_path", "")
    eligible_source_path(path)
    if len(content) > MAX_SOURCE_BYTES:
        raise RemediationError("source_path_not_eligible")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        raise RemediationError("source_not_utf8") from None
    if _SECRET_SOURCE.search(text):
        raise RemediationError("source_requires_secret_review")
    if "\x00" in text or "`" in text:
        # The existing detector deliberately is not a full JS parser. Restrict
        # the first executable template beyond detection; no template literals.
        raise RemediationError("source_syntax_not_supported")
    code_positions = _code_positions(text)
    sites, warnings = _bedrock_command_sites(text, path)
    payload = (finding.get("evidence") or {}).get("payload") or {}
    selected = [
        site
        for site in sites
        if site.line == attributes.get("source_line") and site.command == payload.get("command")
    ]
    if warnings or len(selected) != 1 or selected[0].has_spread:
        raise RemediationError("source_call_not_unambiguous")
    site = selected[0]
    # Incomplete guardrail values could have semantic intent. v1 only inserts
    # wholly absent fields and never overrides an existing user's choice.
    required = (
        ("guardrailConfig",)
        if site.command.startswith("Converse")
        else ("guardrailIdentifier", "guardrailVersion")
    )
    if any(key in site.input_keys for key in required):
        raise RemediationError("guardrail_already_partially_configured")
    aliases = _bedrock_import_aliases(text)
    matches = []
    for alias, command in aliases.items():
        if command == site.command:
            for match in re.finditer(r"\bnew\s+" + re.escape(alias) + r"\s*\(", text):
                if text.count("\n", 0, match.start()) + 1 == site.line:
                    if not code_positions[match.start()]:
                        raise RemediationError("source_call_not_executable")
                    matches.append(match)
    if len(matches) != 1:
        raise RemediationError("source_call_not_unambiguous")
    start = _skip_space_and_comments(text, matches[0].end())
    end = _balanced_object_end(text, start)
    if end is None or text[start] != "{":
        raise RemediationError("source_literal_not_supported")
    property_keys = _literal_property_keys(text, start, end, code_positions)
    if any(key in property_keys for key in required):
        raise RemediationError("guardrail_already_partially_configured")
    identifier, version = (
        json.dumps(parameters["guardrail_id"]),
        json.dumps(parameters["guardrail_version"]),
    )
    fields = (
        f"guardrailConfig: {{ guardrailIdentifier: {identifier}, guardrailVersion: {version} }}"
        if site.command.startswith("Converse")
        else (f"guardrailIdentifier: {identifier}, guardrailVersion: {version}")
    )
    # Insertion at the beginning leaves all original expression values intact.
    new_text = (
        text[: start + 1]
        + fields
        + (", " if text[start + 1 : end].strip() else "")
        + (text[start + 1 :])
    )
    changed, changed_warnings = _bedrock_command_sites(new_text, path)
    if changed_warnings or not any(
        candidate.command == site.command
        and candidate.line == site.line
        and set(required) <= set(candidate.input_keys)
        for candidate in changed
    ):
        raise RemediationError("template_postcondition_failed")
    diff = "".join(
        difflib.unified_diff(
            text.splitlines(keepends=True),
            new_text.splitlines(keepends=True),
            fromfile="a/" + path,
            tofile="b/" + path,
        )
    )
    if len(diff.encode()) > 32_000:
        raise RemediationError("patch_limit_exceeded")
    return new_text.encode(), diff


def tighten_inline_policy(
    finding: dict[str, Any],
    document: dict[str, Any],
    parameters: dict[str, Any],
    resource: dict[str, Any],
):
    """Strict subset replacement; all non-matching policy structure is unchanged."""
    open_finding(finding, AWS_ACTION)
    if (
        set(parameters) != {"model_arns"}
        or not isinstance(parameters["model_arns"], list)
        or (
            not 1 <= len(parameters["model_arns"]) <= 20
            or any(not isinstance(arn, str) for arn in parameters["model_arns"])
            or len(set(parameters["model_arns"])) != len(parameters["model_arns"])
        )
    ):
        raise RemediationError("invalid_model_selection")
    payload = (finding.get("evidence") or {}).get("payload") or {}
    model_ids = payload.get("configured_model_ids") or []
    role = resource["target_role_arn"]
    if (finding.get("attributes") or {}).get("role_arn") != role:
        raise RemediationError("finding_role_mismatch")
    partition = role.split(":")[1]
    arns = sorted(parameters["model_arns"])
    for arn in arns:
        match = re.fullmatch(
            r"arn:([a-z-]+):bedrock:([a-z0-9-]+):([0-9]*):"
            r"(foundation-model|inference-profile)/([A-Za-z0-9_.:-]+)",
            arn,
        )
        if (
            not match
            or match.group(1) != partition
            or (match.group(3) not in {"", resource["account_id"]})
            or (match.group(4) == "foundation-model" and match.group(3) != "")
            or (match.group(4) == "inference-profile" and match.group(3) != resource["account_id"])
            or match.group(5) not in model_ids
            and arn not in model_ids
        ):
            raise RemediationError("model_not_in_finding_evidence")
    matches = [
        match
        for match in payload.get("matching_policy_statements", [])
        if match.get("policy_kind") == "inline"
        and match.get("policy_name") == resource["policy_name"]
    ]
    if not matches:
        raise RemediationError("policy_not_in_finding_evidence")
    proposed = copy.deepcopy(document)
    statements = proposed.get("Statement")
    if (
        not isinstance(statements, list)
        or len(statements) > 100
        or (len(canonical(document).encode()) > 10_000)
    ):
        raise RemediationError("policy_shape_not_supported")
    changed = 0
    for statement in statements:
        if not isinstance(statement, dict):
            raise RemediationError("policy_shape_not_supported")
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action")
        actions = [actions] if isinstance(actions, str) else actions
        resources = statement.get("Resource")
        resources = [resources] if isinstance(resources, str) else resources
        if (
            not isinstance(actions, list)
            or not isinstance(resources, list)
            or (not resources or any(not isinstance(item, str) for item in resources + actions))
        ):
            raise RemediationError("policy_shape_not_supported")
        if not any(str(action).lower() in _INVOKE_ACTIONS for action in actions):
            continue
        if any(str(action).lower() not in _INVOKE_ACTIONS for action in actions) or (
            "NotAction" in statement or "NotResource" in statement
        ):
            raise RemediationError("mixed_action_policy_not_supported")
        wildcard = [item for item in resources if isinstance(item, str) and "*" in item]
        if not wildcard:
            continue
        if not all(any(fnmatch.fnmatchcase(arn, pattern) for pattern in wildcard) for arn in arns):
            raise RemediationError("model_resource_not_subset")
        statement["Resource"] = sorted(
            set([item for item in resources if item not in wildcard] + arns)
        )
        changed += 1
    if not changed:
        raise RemediationError("policy_has_no_supported_wildcard")
    diff = "".join(
        difflib.unified_diff(
            json.dumps(document, indent=2, sort_keys=True).splitlines(keepends=True),
            json.dumps(proposed, indent=2, sort_keys=True).splitlines(keepends=True),
            fromfile="current-inline-policy",
            tofile="proposed-inline-policy",
        )
    )
    return proposed, diff
