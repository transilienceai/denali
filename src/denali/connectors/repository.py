"""Deterministic, evidence-bearing discovery from a local source repository.

This connector extracts the precision rules proven in the previous Denali work while
emitting only the new standalone contracts. It never executes repository code.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from denali.domain import (
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    Evidence,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.repository"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True)
INVENTORY_PLANE = "repository_inventory"
RELATIONSHIP_PLANE = "repository_relationships"
MAX_SOURCE_BYTES = 1_000_000

_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "build",
        "cdk.out",
        "dist",
        "fixtures",
        "node_modules",
        "test",
        "tests",
        "vendor",
    }
)
_SOURCE_SUFFIXES = frozenset({".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"})
_TEST_FILE_RE = re.compile(
    r"^(test_.*|.*(?:_test|\.test|\.spec)|conftest)\.(?:py|[cm]?[jt]sx?)$", re.IGNORECASE
)
_GENERATED_FILE_RE = re.compile(r"(?:^|\.)generated\.(?:py|[cm]?[jt]sx?)$", re.IGNORECASE)
_NORMALIZE_RE = re.compile(r"[^a-z0-9]+")

_FRAMEWORKS = {
    "autogen": "AutoGen",
    "crewai": "CrewAI",
    "dspy": "DSPy",
    "langchain": "LangChain",
    "langgraph": "LangGraph",
    "llama_cpp": "llama.cpp",
    "llama_index": "LlamaIndex",
    "semantic_kernel": "Semantic Kernel",
}

_PROVIDER_SIGNALS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("from openai", "openai", ("model",)),
    ("import openai", "openai", ("model",)),
    ("api.openai.com", "openai", ("model",)),
    ("from anthropic", "anthropic", ("model",)),
    ("import anthropic", "anthropic", ("model",)),
    ("api.anthropic.com", "anthropic", ("model",)),
    ("bedrock-runtime", "bedrock", ("modelId", "model_id")),
    ("bedrock_runtime", "bedrock", ("modelId", "model_id")),
    ("AzureOpenAI", "azure_openai", ("model", "azure_deployment", "deployment_name")),
    ("AzureChatOpenAI", "azure_openai", ("model", "azure_deployment", "deployment_name")),
    ("openai.azure.com", "azure_openai", ("model", "azure_deployment", "deployment_name")),
    ("azure.ai.inference", "azure_openai", ("model", "deployment_name")),
    ("google.generativeai", "google_ai", ("model", "model_name")),
    ("google.genai", "google_ai", ("model", "model_name")),
)
_AZURE_ENV_DEPLOYMENT_RE = re.compile(
    r"""os\.(?:getenv|environ(?:\.get)?)\s*[(\[]\s*["']"""
    r"""(AZURE_OPENAI_[A-Z0-9_]*(?:DEPLOYMENT|MODEL)[A-Z0-9_]*)["']"""
)
_BEDROCK_MODEL_ENV_LITERAL_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]*MODEL_ID)\s*(?::|=)\s*([\"'])([^\"'\r\n]{1,300})\2"
)
_VERTEX_MODEL_ENV_FALLBACK_RE = re.compile(
    r"\b(?:const|let|var)\s+model\s*=\s*process\.env\."
    r"(?:VERTEX_MODEL_ID|GEMINI_MODEL_ID|GOOGLE_MODEL_ID)\s*\|\|\s*"
    r"([\"'])(?P<model>[A-Za-z0-9][A-Za-z0-9._:-]{0,254})\1"
)
_TOOL_REFERENCE_RE = re.compile(r"\b([a-z][a-z0-9_-]{2,})__([a-z][a-z0-9_]{2,})\b")
_SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|secret|password)\b(\s*[:=]\s*)"
    r"([\"'])[^\"']+\3"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")
_MAX_STRING_RESOLUTION_DEPTH = 8


@dataclass(frozen=True, slots=True)
class SourceSite:
    path: str
    line: int
    snippet: str


@dataclass(frozen=True, slots=True)
class ToolDeclaration:
    name: str
    description: str
    line: int


@dataclass(frozen=True, slots=True)
class CapabilitySpec:
    pattern: re.Pattern[str]
    tool_key: str
    tool_name: str
    provider: str
    operation: str
    target_kind: AssetKind
    target_key: str
    target_name: str
    target_attributes: dict[str, Any]
    action: RelationshipKind


_CAPABILITY_SPECS = (
    CapabilitySpec(
        re.compile(r"\bthis\.call\(\s*['\"]chat\.postMessage['\"]"),
        "slack_post_message", "Post Slack message", "slack", "chat.postMessage",
        AssetKind.APPLICATION_ENDPOINT, "saas:slack:api", "Slack API",
        {"provider": "slack", "endpoint_class": "saas_api"}, RelationshipKind.CAN_WRITE,
    ),
    CapabilitySpec(
        re.compile(r"\bthis\.call\(\s*['\"]canvases\.(?:create|edit)['\"]"),
        "slack_canvas_write", "Write Slack canvas", "slack", "canvases.create/edit",
        AssetKind.APPLICATION_ENDPOINT, "saas:slack:api", "Slack API",
        {"provider": "slack", "endpoint_class": "saas_api"}, RelationshipKind.CAN_WRITE,
    ),
    CapabilitySpec(
        re.compile(r"https://api\.hubapi\.com/crm/v3/objects/deals"),
        "hubspot_deal_write", "Write HubSpot deal", "hubspot", "crm.deals.write",
        AssetKind.AI_DATASTORE, "saas:hubspot:crm:deals", "HubSpot deals",
        {"provider": "hubspot", "classification": "business_data"}, RelationshipKind.CAN_WRITE,
    ),
    CapabilitySpec(
        re.compile(r"\bnew\s+PutObjectCommand\s*\("),
        "s3_put_object", "Write proposal artifact", "aws", "s3:PutObject",
        AssetKind.AI_DATASTORE, "aws:s3:configured-bucket", "Configured S3 bucket",
        {"provider": "aws", "service": "s3", "classification": "business_data"},
        RelationshipKind.CAN_WRITE,
    ),
    CapabilitySpec(
        re.compile(r"\bnew\s+GetObjectCommand\s*\("),
        "s3_get_object", "Read proposal artifact", "aws", "s3:GetObject",
        AssetKind.AI_DATASTORE, "aws:s3:configured-bucket", "Configured S3 bucket",
        {"provider": "aws", "service": "s3", "classification": "business_data"},
        RelationshipKind.CAN_READ,
    ),
    CapabilitySpec(
        re.compile(r"\bnew\s+InvokeCommand\s*\("),
        "lambda_invoke", "Invoke AWS Lambda", "aws", "lambda:InvokeFunction",
        AssetKind.CLOUD_RESOURCE, "aws:lambda:configured-function", "Configured Lambda function",
        {"provider": "aws", "service": "lambda", "resource_binding": "runtime_configuration"},
        RelationshipKind.CAN_INVOKE,
    ),
    CapabilitySpec(
        re.compile(r"/messages/\$\{encodeURIComponent\(draftId\)\}/send"),
        "graph_send_mail", "Send Microsoft 365 email", "microsoft_graph", "mail.send",
        AssetKind.APPLICATION_ENDPOINT, "saas:microsoft-graph:mail", "Microsoft Graph Mail",
        {"provider": "microsoft_graph", "endpoint_class": "mail_api"},
        RelationshipKind.CAN_WRITE,
    ),
)


class CanonicalIdentityCollision(ValueError):
    """Two distinct source objects would otherwise become one Denali asset."""


class RepositoryConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        root: Path,
        *,
        repository_name: str | None = None,
        app_id: str | None = None,
        remote: str | None = None,
        commit: str | None = None,
        dirty: bool | None = None,
        source_type: str = "local_git_repository",
        source_locator: str | None = None,
    ):
        self.root = root.expanduser().resolve()
        if not self.root.is_dir():
            raise ValueError(f"repository path is not a directory: {self.root}")
        self.remote = remote if remote is not None else _git(
            self.root, "remote", "get-url", "origin"
        )
        self.commit = commit or _git(self.root, "rev-parse", "HEAD") or "working-tree"
        self.dirty = (
            dirty if dirty is not None else bool(_git(self.root, "status", "--porcelain"))
        )
        self.revision = f"{self.commit}+dirty" if self.dirty else self.commit
        self.repository_name = repository_name or _canonical_repository(self.remote, self.root)
        self.app_id = _normalize_name(app_id or self.repository_name.rsplit("/", 1)[-1])
        self.source_type = source_type
        self.source_locator = source_locator or f"file://{self.root}"

    def collect(self, *, connection_id: str | None = None) -> InventoryBatch:
        observed_at = datetime.now(UTC)
        connection = connection_id or self.repository_name
        scope = f"repository:{self.repository_name}"
        repo_ref = AssetRef(AssetKind.CODE_REPOSITORY, self.repository_name)
        assets: dict[AssetRef, AssetAssertion] = {}
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, AssertionType], RelationshipAssertion
        ] = {}
        warnings: list[str] = []

        assets[repo_ref] = AssetAssertion(
            asset=repo_ref,
            coverage_plane=INVENTORY_PLANE,
            display_name=self.repository_name.split("/")[-1],
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=Evidence(
                source_type=self.source_type,
                locator=self.source_locator,
                observed_at=observed_at,
                payload={"remote": self.remote, "commit": self.commit, "dirty": self.dirty},
            ),
            attributes={
                "remote": self.remote,
                "commit": self.commit,
                "dirty": self.dirty,
                **(
                    {"local_path": str(self.root)}
                    if self.source_type == "local_git_repository"
                    else {}
                ),
            },
        )

        for source_file in _source_files(self.root):
            relative = source_file.relative_to(self.root).as_posix()
            try:
                if source_file.stat().st_size > MAX_SOURCE_BYTES:
                    warnings.append(f"{relative}: larger than {MAX_SOURCE_BYTES} bytes")
                    continue
                text = source_file.read_text(encoding="utf-8", errors="replace")
            except OSError as error:
                warnings.append(f"{relative}: {error.__class__.__name__}")
                continue

            tree = None
            if source_file.suffix == ".py":
                try:
                    tree = ast.parse(text, filename=relative)
                except SyntaxError as error:
                    warnings.append(f"{relative}:{error.lineno or 0}: invalid Python syntax")

            if tree is not None:
                self._discover_frameworks(
                    tree, text, relative, observed_at, repo_ref, assets, relationships
                )
                try:
                    self._discover_mcp_python(
                        tree, text, relative, observed_at, repo_ref, assets, relationships
                    )
                except CanonicalIdentityCollision as error:
                    warnings.append(f"{relative}: {error}")
            self._discover_models(text, relative, observed_at, repo_ref, assets, relationships)
            self._discover_capabilities(
                text, relative, observed_at, repo_ref, assets, relationships
            )

        for config_file in _mcp_config_files(self.root):
            relative = config_file.relative_to(self.root).as_posix()
            try:
                text = config_file.read_text(encoding="utf-8", errors="replace")
                parsed = json.loads(text)
            except (OSError, json.JSONDecodeError) as error:
                warnings.append(f"{relative}: {error.__class__.__name__}")
                continue
            try:
                self._discover_mcp_config(
                    parsed, text, relative, observed_at, repo_ref, assets, relationships
                )
            except CanonicalIdentityCollision as error:
                warnings.append(f"{relative}: {error}")

        coverage_state = CoverageState.PARTIAL if warnings else CoverageState.COMPLETE
        detail = "; ".join(warnings[:10]) if warnings else None
        return InventoryBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=f"repo-{self.revision[:18]}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=(
                Coverage(INVENTORY_PLANE, coverage_state, scope, detail),
                Coverage(RELATIONSHIP_PLANE, coverage_state, scope, detail),
            ),
            assets=tuple(assets.values()),
            relationships=tuple(relationships.values()),
        )

    def _discover_frameworks(
        self,
        tree: ast.AST,
        text: str,
        relative: str,
        observed_at: datetime,
        repo_ref: AssetRef,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, AssertionType], RelationshipAssertion
        ],
    ) -> None:
        for node in ast.walk(tree):
            modules: list[str] = []
            if isinstance(node, ast.Import):
                modules = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module.split(".")[0]]
            for module in modules:
                if module not in _FRAMEWORKS:
                    continue
                site = _site(text, relative, node.lineno)
                framework_ref = AssetRef(AssetKind.AI_FRAMEWORK, f"pypi:{module}")
                self._add_asset(
                    assets,
                    framework_ref,
                    _FRAMEWORKS[module],
                    AssertionType.DECLARED,
                    1.0,
                    site,
                    observed_at,
                    {"package": module, "language": "python"},
                    "python_import",
                )
                self._add_relationship(
                    relationships,
                    repo_ref,
                    framework_ref,
                    RelationshipKind.USES,
                    AssertionType.DECLARED,
                    1.0,
                    site,
                    observed_at,
                    "python_import",
                )

    def _discover_models(
        self,
        text: str,
        relative: str,
        observed_at: datetime,
        repo_ref: AssetRef,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, AssertionType], RelationshipAssertion
        ],
    ) -> None:
        if "bedrock" in text.lower():
            for match in _BEDROCK_MODEL_ENV_LITERAL_RE.finditer(text):
                env_var = match.group(1)
                model_id = match.group(3)
                line = text[: match.start()].count("\n") + 1
                site = _site(text, relative, line)
                model_ref = AssetRef(AssetKind.AI_MODEL, _model_natural_key("bedrock", model_id))
                self._add_asset(
                    assets,
                    model_ref,
                    model_id,
                    AssertionType.DECLARED,
                    1.0,
                    site,
                    observed_at,
                    {
                        "provider": "bedrock",
                        "model_id": model_id,
                        "configuration_key": env_var,
                    },
                    "bedrock_model_environment",
                )
                self._add_relationship(
                    relationships,
                    repo_ref,
                    model_ref,
                    RelationshipKind.USES,
                    AssertionType.DECLARED,
                    1.0,
                    site,
                    observed_at,
                    "bedrock_model_environment",
                )
                self._link_agent_to_source_and_model(
                    assets, relationships, repo_ref, model_ref, site, observed_at
                )

        if "aiplatform.googleapis.com" in text:
            for match in _VERTEX_MODEL_ENV_FALLBACK_RE.finditer(text):
                model_id = match.group("model")
                line = text[: match.start()].count("\n") + 1
                site = _site(text, relative, line)
                model_ref = AssetRef(AssetKind.AI_MODEL, f"gcp:vertex:model:{model_id}")
                self._add_asset(
                    assets,
                    model_ref,
                    model_id,
                    AssertionType.DECLARED,
                    1.0,
                    site,
                    observed_at,
                    {
                        "provider": "gcp_vertex_ai",
                        "model_id": model_id,
                        "configuration_key": "VERTEX_MODEL_ID",
                    },
                    "vertex_model_environment_fallback",
                )
                self._add_relationship(
                    relationships,
                    repo_ref,
                    model_ref,
                    RelationshipKind.USES,
                    AssertionType.DECLARED,
                    1.0,
                    site,
                    observed_at,
                    "vertex_model_environment_fallback",
                )
                self._link_agent_to_source_and_model(
                    assets, relationships, repo_ref, model_ref, site, observed_at
                )

        providers: dict[str, tuple[str, ...]] = {}
        for marker, provider, model_fields in _PROVIDER_SIGNALS:
            if marker in text:
                providers.setdefault(provider, model_fields)
        if "azure_openai" in providers:
            providers.pop("openai", None)
        if not providers:
            return

        if "azure_openai" in providers:
            for match in _AZURE_ENV_DEPLOYMENT_RE.finditer(text):
                env_var = match.group(1)
                line = text[: match.start()].count("\n") + 1
                site = SourceSite(relative, line, f"deployment from ${env_var}")
                model_ref = AssetRef(AssetKind.AI_MODEL, f"azure_openai:env:{env_var}")
                self._add_asset(
                    assets,
                    model_ref,
                    f"Azure OpenAI deployment (${env_var})",
                    AssertionType.DECLARED,
                    0.6,
                    site,
                    observed_at,
                    {
                        "provider": "azure_openai",
                        "deployment_source": "environment",
                        "env_var": env_var,
                    },
                    "model_configuration",
                )
                self._add_relationship(
                    relationships,
                    repo_ref,
                    model_ref,
                    RelationshipKind.USES,
                    AssertionType.DECLARED,
                    0.6,
                    site,
                    observed_at,
                    "model_configuration",
                )

        for provider, fields in providers.items():
            for field in fields:
                patterns = (
                    re.compile(rf"\b{re.escape(field)}\s*=\s*[\"']([^\"']+)[\"']"),
                    re.compile(rf"[\"']{re.escape(field)}[\"']\s*:\s*[\"']([^\"']+)[\"']"),
                )
                for pattern in patterns:
                    for match in pattern.finditer(text):
                        model_id = match.group(1)
                        resolved = _resolve_provider(provider, model_id)
                        line = text[: match.start()].count("\n") + 1
                        site = _site(text, relative, line)
                        model_ref = AssetRef(
                            AssetKind.AI_MODEL, _model_natural_key(resolved, model_id)
                        )
                        self._add_asset(
                            assets,
                            model_ref,
                            model_id,
                            AssertionType.DECLARED,
                            1.0,
                            site,
                            observed_at,
                            {"provider": resolved, "model_id": model_id},
                            "model_configuration",
                        )
                        self._add_relationship(
                            relationships,
                            repo_ref,
                            model_ref,
                            RelationshipKind.USES,
                            AssertionType.DECLARED,
                            1.0,
                            site,
                            observed_at,
                            "model_configuration",
                        )
                        self._link_agent_to_source_and_model(
                            assets, relationships, repo_ref, model_ref, site, observed_at
                        )

    def _discover_capabilities(
        self,
        text: str,
        relative: str,
        observed_at: datetime,
        repo_ref: AssetRef,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, AssertionType], RelationshipAssertion
        ],
    ) -> None:
        for spec in _CAPABILITY_SPECS:
            match = spec.pattern.search(text)
            if match is None:
                continue
            line = text[: match.start()].count("\n") + 1
            site = _site(text, relative, line)
            agent_ref = self._ensure_agent(
                assets, relationships, repo_ref, site, observed_at
            )
            tool_ref = AssetRef(AssetKind.AI_TOOL, f"app:{self.app_id}:tool:{spec.tool_key}")
            target_ref = AssetRef(
                spec.target_kind, f"app:{self.app_id}:target:{spec.target_key}"
            )
            self._add_asset(
                assets,
                tool_ref,
                spec.tool_name,
                AssertionType.DECLARED,
                1.0,
                site,
                observed_at,
                {
                    "provider": spec.provider,
                    "operation": spec.operation,
                    "source_path": relative,
                    "execution_status": "not_observed",
                },
                "source_capability_call",
            )
            self._add_asset(
                assets,
                target_ref,
                spec.target_name,
                AssertionType.DECLARED,
                1.0,
                site,
                observed_at,
                {**spec.target_attributes, "execution_status": "not_observed"},
                "source_capability_target",
            )
            self._add_relationship(
                relationships,
                agent_ref,
                tool_ref,
                RelationshipKind.CAN_INVOKE,
                AssertionType.DECLARED,
                1.0,
                site,
                observed_at,
                "source_capability_call",
                {"execution_status": "not_observed"},
            )
            self._add_relationship(
                relationships,
                tool_ref,
                target_ref,
                spec.action,
                AssertionType.DECLARED,
                1.0,
                site,
                observed_at,
                "source_capability_call",
                {
                    "provider": spec.provider,
                    "operation": spec.operation,
                    "execution_status": "not_observed",
                },
            )

    def _link_agent_to_source_and_model(
        self,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, AssertionType], RelationshipAssertion
        ],
        repo_ref: AssetRef,
        model_ref: AssetRef,
        site: SourceSite,
        observed_at: datetime,
    ) -> None:
        agent_ref = self._ensure_agent(
            assets, relationships, repo_ref, site, observed_at
        )
        self._add_relationship(
            relationships,
            agent_ref,
            model_ref,
            RelationshipKind.USES,
            AssertionType.DECLARED,
            1.0,
            site,
            observed_at,
            "source_model_use",
        )

    def _ensure_agent(
        self,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, AssertionType], RelationshipAssertion
        ],
        repo_ref: AssetRef,
        site: SourceSite,
        observed_at: datetime,
    ) -> AssetRef:
        agent_ref = AssetRef(AssetKind.AI_AGENT, f"app:{self.app_id}:agent")
        repository_slug = self.repository_name.rsplit("/", 1)[-1].replace("-", " ").title()
        agent_display_name = (
            repository_slug
            if repository_slug.casefold().endswith(" agent")
            else f"{repository_slug} Agent"
        )
        self._add_asset(
            assets,
            agent_ref,
            agent_display_name,
            AssertionType.DECLARED,
            1.0,
            site,
            observed_at,
            {"repository": self.repository_name, "source_path": site.path},
            "source_ai_agent",
        )
        self._add_relationship(
            relationships,
            agent_ref,
            repo_ref,
            RelationshipKind.DEFINED_IN,
            AssertionType.DECLARED,
            1.0,
            site,
            observed_at,
            "source_ai_agent",
        )
        return agent_ref

    def _discover_mcp_python(
        self,
        tree: ast.AST,
        text: str,
        relative: str,
        observed_at: datetime,
        repo_ref: AssetRef,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, AssertionType], RelationshipAssertion
        ],
    ) -> None:
        servers: dict[str, tuple[str, int]] = {}
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or not isinstance(
                node.value, ast.Call
            ):
                continue
            constructor = _call_name(node.value.func)
            if constructor not in {"Server", "FastMCP"}:
                continue
            if not node.value.args or not _literal_string(node.value.args[0]):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if not targets or not isinstance(targets[0], ast.Name):
                continue
            servers[targets[0].id] = (_literal_string(node.value.args[0]) or "", node.lineno)

        for server_var, (server_name, line) in servers.items():
            site = _site(text, relative, line)
            server_ref = self._mcp_server_ref(server_name)
            self._add_asset(
                assets,
                server_ref,
                server_name,
                AssertionType.DECLARED,
                1.0,
                site,
                observed_at,
                {"runtime": "python", "source_path": relative},
                "mcp_declaration",
            )
            self._add_relationship(
                relationships,
                server_ref,
                repo_ref,
                RelationshipKind.DEFINED_IN,
                AssertionType.DECLARED,
                1.0,
                site,
                observed_at,
                "mcp_declaration",
            )
            for tool in _extract_tools(tree, server_var):
                tool_site = _site(text, relative, tool.line)
                tool_ref = self._mcp_tool_ref(server_name, tool.name)
                self._add_asset(
                    assets,
                    tool_ref,
                    tool.name,
                    AssertionType.DECLARED,
                    1.0,
                    tool_site,
                    observed_at,
                    {"mcp_server": server_name, "description": tool.description},
                    "mcp_tool_declaration",
                )
                self._add_relationship(
                    relationships,
                    server_ref,
                    tool_ref,
                    RelationshipKind.EXPOSES,
                    AssertionType.DECLARED,
                    1.0,
                    tool_site,
                    observed_at,
                    "mcp_tool_declaration",
                )
                for referenced_server, referenced_tool in sorted(
                    set(_TOOL_REFERENCE_RE.findall(tool.description))
                ):
                    if _normalize_server(referenced_server) == _normalize_server(
                        server_name
                    ) and _normalize_name(referenced_tool) == _normalize_name(tool.name):
                        continue
                    target_ref = self._mcp_tool_ref(referenced_server, referenced_tool)
                    self._add_relationship(
                        relationships,
                        tool_ref,
                        target_ref,
                        RelationshipKind.INFLUENCES,
                        AssertionType.INFERRED,
                        0.9,
                        tool_site,
                        observed_at,
                        "tool_description_reference",
                        {"mechanism": "tool_description"},
                    )

    def _discover_mcp_config(
        self,
        parsed: Any,
        text: str,
        relative: str,
        observed_at: datetime,
        repo_ref: AssetRef,
        assets: dict[AssetRef, AssetAssertion],
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, AssertionType], RelationshipAssertion
        ],
    ) -> None:
        if not isinstance(parsed, dict) or not isinstance(parsed.get("mcpServers"), dict):
            return
        for server_name, configuration in sorted(parsed["mcpServers"].items()):
            if not isinstance(server_name, str) or not isinstance(configuration, dict):
                continue
            line = next(
                (
                    number
                    for number, content in enumerate(text.splitlines(), 1)
                    if f'"{server_name}"' in content
                ),
                1,
            )
            site = _site(text, relative, line)
            server_ref = self._mcp_server_ref(server_name)
            attributes = {"runtime": "config", "source_path": relative}
            for key in ("url", "command", "transport"):
                if isinstance(configuration.get(key), str):
                    attributes[key] = configuration[key]
            self._add_asset(
                assets,
                server_ref,
                server_name,
                AssertionType.DECLARED,
                1.0,
                site,
                observed_at,
                attributes,
                "mcp_configuration",
            )
            self._add_relationship(
                relationships,
                server_ref,
                repo_ref,
                RelationshipKind.DEFINED_IN,
                AssertionType.DECLARED,
                1.0,
                site,
                observed_at,
                "mcp_configuration",
            )

    def _add_asset(
        self,
        assets: dict[AssetRef, AssetAssertion],
        asset_ref: AssetRef,
        display_name: str,
        assertion_type: AssertionType,
        confidence: float,
        site: SourceSite,
        observed_at: datetime,
        attributes: dict[str, Any],
        detector: str,
    ) -> None:
        existing = assets.get(asset_ref)
        if (
            existing is not None
            and asset_ref.kind in {AssetKind.MCP_SERVER, AssetKind.AI_TOOL}
            and existing.display_name != display_name
        ):
            raise CanonicalIdentityCollision(
                f"{existing.display_name!r} and {display_name!r} collide as "
                f"{asset_ref.natural_key!r}"
            )
        assets.setdefault(
            asset_ref,
            AssetAssertion(
                asset=asset_ref,
                coverage_plane=INVENTORY_PLANE,
                display_name=display_name,
                assertion_type=assertion_type,
                confidence=confidence,
                evidence=self._evidence(site, observed_at, detector),
                attributes=attributes,
            ),
        )

    def _add_relationship(
        self,
        relationships: dict[
            tuple[AssetRef, AssetRef, RelationshipKind, AssertionType], RelationshipAssertion
        ],
        source: AssetRef,
        target: AssetRef,
        kind: RelationshipKind,
        assertion_type: AssertionType,
        confidence: float,
        site: SourceSite,
        observed_at: datetime,
        detector: str,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        key = (source, target, kind, assertion_type)
        relationships.setdefault(
            key,
            RelationshipAssertion(
                source=source,
                target=target,
                coverage_plane=RELATIONSHIP_PLANE,
                kind=kind,
                assertion_type=assertion_type,
                confidence=confidence,
                evidence=self._evidence(site, observed_at, detector),
                attributes=attributes or {},
            ),
        )

    def _evidence(self, site: SourceSite, observed_at: datetime, detector: str) -> Evidence:
        return Evidence(
            source_type="repository_source",
            locator=f"repo://{self.repository_name}@{self.revision}/{site.path}#L{site.line}",
            observed_at=observed_at,
            payload={
                "path": site.path,
                "line": site.line,
                "snippet": site.snippet,
                "commit": self.commit,
                "dirty": self.dirty,
                "detector": detector,
            },
        )

    def _mcp_server_ref(self, name: str) -> AssetRef:
        return AssetRef(AssetKind.MCP_SERVER, f"app:{self.app_id}:mcp:{_normalize_server(name)}")

    def _mcp_tool_ref(self, server_name: str, tool_name: str) -> AssetRef:
        return AssetRef(
            AssetKind.AI_TOOL,
            f"app:{self.app_id}:mcp:{_normalize_server(server_name)}:tool:{_normalize_name(tool_name)}",
        )


def scan_main() -> None:
    parser = argparse.ArgumentParser(description="Scan a local repository into Denali inventory")
    parser.add_argument("repository", type=Path)
    parser.add_argument("--name", help="canonical repository name; defaults to the git remote")
    parser.add_argument("--app-id", help="application namespace for MCP identities")
    parser.add_argument("--connection-id", help="source connection id")
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        raise SystemExit("--dsn or DENALI_DSN is required")

    connector = RepositoryConnector(args.repository, repository_name=args.name, app_id=args.app_id)
    batch = connector.collect(connection_id=args.connection_id)
    migrate(args.dsn)
    result = PostgresInventoryRepository(args.dsn).ingest(args.tenant_id, batch)
    coverage = batch.coverage[0]
    print(
        f"Scanned {connector.repository_name}: {result['assets']} assets, "
        f"{result['relationships']} relationships, coverage={coverage.state.value}"
    )
    if coverage.detail:
        print(f"Coverage detail: {coverage.detail}")


def _source_files(root: Path) -> list[Path]:
    output: list[Path] = []
    for current_root, directory_names, file_names in os.walk(root):
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in _EXCLUDED_DIRS and not name.startswith(".")
        )
        current = Path(current_root)
        for file_name in sorted(file_names):
            if (
                Path(file_name).suffix.lower() not in _SOURCE_SUFFIXES
                or _TEST_FILE_RE.match(file_name)
                or _GENERATED_FILE_RE.search(file_name)
            ):
                continue
            candidate = current / file_name
            if not candidate.is_symlink():
                output.append(candidate)
    return output


def _mcp_config_files(root: Path) -> list[Path]:
    names = {"mcp.json", "claude_desktop_config.json"}
    output: list[Path] = []
    for current_root, directory_names, file_names in os.walk(root):
        directory_names[:] = sorted(
            name
            for name in directory_names
            if name not in _EXCLUDED_DIRS and not name.startswith(".")
        )
        current = Path(current_root)
        output.extend(
            candidate
            for file_name in sorted(file_names)
            if file_name in names
            if not (candidate := current / file_name).is_symlink()
        )
    return output


def _extract_tools(tree: ast.AST, server_var: str) -> list[ToolDeclaration]:
    tools: dict[str, ToolDeclaration] = {}
    module_scope = _string_bindings(getattr(tree, "body", []))
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        scopes = (_string_bindings(node.body), module_scope)
        for decorator in node.decorator_list:
            call = decorator if isinstance(decorator, ast.Call) else None
            expression = call.func if call else decorator
            if not isinstance(expression, ast.Attribute):
                continue
            if not isinstance(expression.value, ast.Name) or expression.value.id != server_var:
                continue
            if expression.attr == "tool":
                declared_name = node.name
                if call:
                    for keyword in call.keywords:
                        if keyword.arg == "name" and _literal_string(keyword.value):
                            declared_name = _literal_string(keyword.value) or node.name
                tools.setdefault(
                    declared_name,
                    ToolDeclaration(declared_name, ast.get_docstring(node) or "", node.lineno),
                )
            elif expression.attr == "list_tools":
                for subnode in ast.walk(node):
                    if not isinstance(subnode, ast.Return) or not isinstance(
                        subnode.value, ast.List
                    ):
                        continue
                    for element in subnode.value.elts:
                        declaration = _tool_declaration(element, scopes)
                        if declaration:
                            tools.setdefault(declaration.name, declaration)
    return list(tools.values())


def _tool_declaration(
    node: ast.AST, scopes: tuple[dict[str, ast.AST | None], ...]
) -> ToolDeclaration | None:
    if isinstance(node, ast.Dict):
        values = {
            key.value: value
            for key, value in zip(node.keys, node.values, strict=True)
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        }
        name = _literal_string(values.get("name"))
        if name:
            return ToolDeclaration(
                name, _resolve_string(values.get("description"), scopes) or "", node.lineno
            )
    if isinstance(node, ast.Call):
        values = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
        name = _literal_string(values.get("name"))
        if name:
            return ToolDeclaration(
                name, _resolve_string(values.get("description"), scopes) or "", node.lineno
            )
    return None


def _string_bindings(body: list[ast.stmt]) -> dict[str, ast.AST | None]:
    bindings: dict[str, ast.AST | None] = {}
    for statement in body:
        if isinstance(statement, ast.Assign):
            targets = statement.targets
        elif isinstance(statement, ast.AnnAssign):
            targets = [statement.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name):
                bindings[target.id] = None if target.id in bindings else statement.value
    return bindings


def _resolve_string(
    node: ast.AST | None,
    scopes: tuple[dict[str, ast.AST | None], ...],
    depth: int = 0,
) -> str | None:
    if depth > _MAX_STRING_RESOLUTION_DEPTH:
        return None
    literal = _literal_string(node)
    if literal is not None:
        return literal
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _resolve_string(node.left, scopes, depth + 1)
        right = _resolve_string(node.right, scopes, depth + 1)
        return left + right if left is not None and right is not None else None
    if isinstance(node, ast.Name):
        for scope in scopes:
            if node.id in scope:
                return _resolve_string(scope[node.id], scopes, depth + 1)
    return None


def _literal_string(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _site(text: str, relative: str, line: int) -> SourceSite:
    lines = text.splitlines()
    snippet = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    return SourceSite(relative, line, _redact_snippet(snippet)[:500])


def _redact_snippet(value: str) -> str:
    redacted = _SENSITIVE_ASSIGNMENT_RE.sub(r'\1\2"[REDACTED]"', value)
    return _BEARER_RE.sub("Bearer [REDACTED]", redacted)


def _resolve_provider(provider: str, model_id: str) -> str:
    if provider == "azure_openai":
        return provider
    if model_id.startswith("anthropic.claude"):
        return "bedrock"
    if model_id.startswith("claude-"):
        return "anthropic"
    if model_id.startswith("gpt-"):
        return "openai"
    if model_id.startswith("gemini-"):
        return "google_ai"
    return provider


def _model_natural_key(provider: str, model_id: str) -> str:
    if provider == "bedrock":
        return f"aws:bedrock:model:{model_id}"
    return f"{provider}:{model_id}"


def _normalize_server(value: str) -> str:
    normalized = value.lower().strip()
    if normalized.startswith("mcp-") or normalized.startswith("mcp_"):
        normalized = normalized[4:]
    return _normalize_name(normalized)


def _normalize_name(value: str) -> str:
    return _NORMALIZE_RE.sub("_", value.lower()).strip("_")


def _canonical_repository(remote: str | None, root: Path) -> str:
    if not remote:
        return f"local:{root.name}"
    value = remote.strip()
    if value.startswith("git@") and ":" in value:
        host, repository = value[4:].split(":", 1)
        value = f"{host}/{repository}"
    value = re.sub(r"^[a-z]+://", "", value)
    return value.removesuffix(".git").rstrip("/")


def _git(root: Path, *arguments: str) -> str | None:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=False,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 and result.stdout.strip() else None


if __name__ == "__main__":
    scan_main()
