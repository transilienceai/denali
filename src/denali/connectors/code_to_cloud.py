"""Deterministic repository-to-runtime correlation.

The connector joins literal deployment identifiers in source-controlled IaC to
independently observed cloud workloads. A shared model name is useful corroboration,
but is deliberately not sufficient to claim that a repository deployed a workload.
"""

from __future__ import annotations

import argparse
import json
import os
import posixpath
import re
from collections import deque
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

from denali.connectors.repository import MAX_SOURCE_BYTES, RepositoryConnector, _source_files
from denali.connectors.repository_posture import _balanced_object_end, _line
from denali.domain import (
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    DeploymentIdentifier,
    DeploymentIdentity,
    Evidence,
    IdentifierComparison,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.code_to_cloud"
CAPABILITIES = ConnectorCapabilities(inventory=True, relationships=True)
INVENTORY_PLANE = "code_to_cloud_inventory"
RELATIONSHIP_PLANE = "code_to_cloud_deployments"

_LAMBDA_RE = re.compile(
    r"new\s+(?:[A-Za-z_$][\w$]*\.)?(?:Nodejs)?Function\s*\(\s*this\s*,\s*"
    r"(?P<quote>['\"])(?P<construct>[^'\"]+)\1\s*,\s*\{"
)
_TASK_RE = re.compile(
    r"(?:const|let)\s+(?P<variable>[A-Za-z_$][\w$]*)\s*=\s*new\s+"
    r"(?:[A-Za-z_$][\w$]*\.)?(?:Fargate)?TaskDefinition\s*\(\s*this\s*,\s*"
    r"(?P<quote>['\"])(?P<construct>[^'\"]+)\2"
)
_TERRAFORM_RESOURCE_RE = re.compile(
    r"\bresource\s+(['\"])(?P<type>google_cloud_run_v2_service|"
    r"google_cloudfunctions2_function|azurerm_container_app|"
    r"azurerm_linux_function_app|azurerm_windows_function_app|"
    r"aws_lambda_function|aws_ecs_task_definition|aws_eks_cluster|"
    r"aws_sagemaker_endpoint)\1\s+"
    r"(['\"])(?P<label>[^'\"]+)\3\s*\{"
)
_AZURERM_PROVIDER_RE = re.compile(r"\bprovider\s+(['\"])azurerm\1\s*\{")
_AWS_PROVIDER_RE = re.compile(r"\bprovider\s+(['\"])aws\1\s*\{")
_TERRAFORM_VARIABLE_RE = re.compile(
    r"\bvariable\s+(['\"])(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\1\s*\{"
)
_TERRAFORM_LOCALS_RE = re.compile(r"\blocals\s*\{")
_TERRAFORM_MODULE_RE = re.compile(
    r"\bmodule\s+(['\"])(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\1\s*\{"
)
_AZURE_BICEP_RESOURCE_RE = re.compile(
    r"(?m)^\s*resource\s+(?P<symbol>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"(['\"])(?P<type>Microsoft\.(?:App/containerApps|Web/sites))@[^'\"]+\2\s*=\s*\{"
)
_AZURE_RESOURCE_ID_RE = re.compile(
    r"^/subscriptions/(?P<subscription>[0-9a-fA-F-]{36})/resourceGroups/"
    r"(?P<resource_group>[^/]+)/providers/Microsoft\.(?P<provider>App|Web)/"
    r"(?P<kind>containerApps|sites)/(?P<name>[^/]+)$",
    re.IGNORECASE,
)
_LITERAL_PROPERTY_TEMPLATE = r"\b{key}\s*:\s*(['\"])(?P<value>[^'\"\r\n]+)\1"
_STRING_BINDING_RE = re.compile(
    r"(?:const|let)\s+(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(['\"])(?P<value>[^'\"\r\n]+)\2"
)
_ASSET_CONTEXT_RE = re.compile(
    r"\bfromAsset\s*\(\s*(['\"])(?P<value>[^'\"\r\n]+)\1"
)
_STATIC_IMPORT_RE = re.compile(
    r"(?:^|[;\n])\s*import\s+(?!type\b)(?:[^'\"\n;]*?\s+from\s+)?"
    r"(?P<quote>['\"])(?P<value>\.[^'\"\r\n]+)(?P=quote)",
    re.MULTILINE,
)
_EXPORT_FROM_RE = re.compile(
    r"(?:^|[;\n])\s*export\s+(?!type\b)[^'\"\n;]*?\s+from\s+"
    r"(?P<quote>['\"])(?P<value>\.[^'\"\r\n]+)(?P=quote)",
    re.MULTILINE,
)
_DYNAMIC_IMPORT_RE = re.compile(
    r"\bimport\s*\(\s*(?P<quote>['\"])(?P<value>\.[^'\"\r\n]+)(?P=quote)\s*\)"
)
_ESBUILD_RE = re.compile(
    r"\besbuild\s+(?P<entry>[^\s\\]+)(?P<arguments>.*?)(?=\n\s*(?:FROM|RUN|CMD|ENTRYPOINT)\b|\Z)",
    re.DOTALL | re.IGNORECASE,
)
_MODULE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")
_MAX_CDK_MANIFESTS = 20
_MAX_CDK_MANIFEST_BYTES = 2_000_000
_MAX_CANDIDATE_OBSERVATIONS = 2_000
_MAX_CANDIDATE_MATCHES = 25
_MANIFEST_EXCLUDED_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "fixtures",
        "test",
        "tests",
    }
)
_IAC_SUFFIXES = frozenset({".tf", ".yaml", ".yml", ".json", ".bicep"})
_KUBERNETES_WORKLOAD_KINDS = frozenset(
    {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob"}
)
_KUBERNETES_DIGEST_IMAGE_RE = re.compile(r"^.+@sha256:(?P<digest>[0-9a-fA-F]{64})$")


@dataclass(frozen=True, slots=True)
class DeploymentTarget:
    natural_key: str
    display_name: str
    service: str
    identity: DeploymentIdentity
    evidence_locator: str
    evidence_payload: dict[str, Any]

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> DeploymentTarget:
        identity = record.get("identity")
        if isinstance(identity, dict):
            parsed_identity = DeploymentIdentity.from_record(identity)
        else:
            parsed_identity = _legacy_aws_target_identity(record)
        return cls(
            natural_key=str(record["natural_key"]),
            display_name=str(record["display_name"]),
            service=str(record["service"]),
            identity=parsed_identity,
            evidence_locator=str(record["evidence_locator"]),
            evidence_payload=dict(record.get("evidence_payload") or {}),
        )


def _legacy_aws_target_identity(record: dict[str, Any]) -> DeploymentIdentity:
    """Read pre-contract AWS target records during the persisted-data transition."""

    service = record.get("service")
    logical_id = record.get("logical_id")
    payload = record.get("evidence_payload")
    if service not in {"lambda", "ecs"} or not isinstance(logical_id, str):
        raise ValueError("deployment target identity must be an object")
    if service == "lambda":
        runtime_kind = "serverless_function"
        names = [record.get("display_name")]
        identifier_name = "function_name"
    else:
        runtime_kind = "container_task"
        names = payload.get("container_names", []) if isinstance(payload, dict) else []
        identifier_name = "container_name"
    identifiers = [DeploymentIdentifier("cloudformation_logical_id", logical_id)]
    identifiers.extend(
        DeploymentIdentifier(identifier_name, item)
        for item in names
        if isinstance(item, str) and item
    )
    return DeploymentIdentity("aws", runtime_kind, tuple(identifiers))


@dataclass(frozen=True, slots=True)
class DeploymentDeclaration:
    identity: DeploymentIdentity
    framework: str
    service: str
    construct_id: str
    deployment_name: str
    path: str
    line: int
    entry: str | None = None
    build_context: str | None = None
    build_file: str | None = None


@dataclass(frozen=True, slots=True)
class ArtifactReachability:
    entry: str | None
    build_file: str | None
    reachable_source_paths: tuple[str, ...]
    import_chains: dict[str, list[str]]
    warnings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TerraformModuleContext:
    bindings: dict[str, str]
    aws_scope: tuple[str, str] | None
    azure_subscription: str | None


class CodeToCloudConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def __init__(
        self,
        root: Path,
        *,
        targets: tuple[DeploymentTarget, ...],
        repository_name: str | None = None,
        remote: str | None = None,
        commit: str | None = None,
        dirty: bool | None = None,
        source_type: str = "local_git_repository",
        source_locator: str | None = None,
    ) -> None:
        metadata = RepositoryConnector(
            root,
            repository_name=repository_name,
            remote=remote,
            commit=commit,
            dirty=dirty,
            source_type=source_type,
            source_locator=source_locator,
        )
        self.root = metadata.root
        self.repository_name = metadata.repository_name
        self.commit = metadata.commit
        self.dirty = metadata.dirty
        self.revision = metadata.revision
        self.source_type = metadata.source_type
        self.source_locator = metadata.source_locator
        self.targets = targets

    def collect(self, *, connection_id: str | None = None) -> InventoryBatch:
        observed_at = datetime.now(UTC)
        connection = connection_id or self.repository_name
        scope = f"repository:{self.repository_name}"
        repo_ref = AssetRef(AssetKind.CODE_REPOSITORY, self.repository_name)
        warnings: list[str] = []
        declarations: list[DeploymentDeclaration] = []
        source_texts: dict[str, str] = {}
        asset_manifests, manifest_warnings = _load_cdk_asset_manifests(self.root)
        warnings.extend(manifest_warnings)

        for source_file in _deployment_source_files(self.root):
            relative = source_file.relative_to(self.root).as_posix()
            try:
                if source_file.stat().st_size > MAX_SOURCE_BYTES:
                    warnings.append(f"{relative}: larger than {MAX_SOURCE_BYTES} bytes")
                    continue
                text = source_file.read_text(encoding="utf-8", errors="replace")
            except OSError as error:
                warnings.append(f"{relative}: {error.__class__.__name__}")
                continue
            source_texts[relative] = text

        terraform_contexts = _terraform_module_contexts(source_texts)
        for relative, text in source_texts.items():
            found, file_warnings = _deployment_declarations(
                text,
                relative,
                terraform_context=terraform_contexts.get(posixpath.dirname(relative)),
            )
            declarations.extend(found)
            warnings.extend(file_warnings)

        relationships: list[RelationshipAssertion] = []
        matched_targets: set[str] = set()
        candidates: list[dict[str, Any]] = []
        dispositions = {"proven": 0, "ambiguous": 0, "unmatched": 0}
        for declaration in declarations:
            matches = _matching_targets(declaration, self.targets)
            if len(matches) > 1:
                dispositions["ambiguous"] += 1
                if len(candidates) < _MAX_CANDIDATE_OBSERVATIONS:
                    candidates.append(
                        _candidate_observation(
                            declaration,
                            status="ambiguous",
                            matches=matches,
                        )
                    )
                warnings.append(
                    f"{declaration.path}:{declaration.line}: deployment identifier "
                    f"{declaration.deployment_name!r} matched multiple active workloads"
                )
                continue
            if not matches:
                dispositions["unmatched"] += 1
                if len(candidates) < _MAX_CANDIDATE_OBSERVATIONS:
                    candidates.append(
                        _candidate_observation(declaration, status="unmatched", matches=())
                    )
                continue
            target = matches[0]
            dispositions["proven"] += 1
            if len(candidates) < _MAX_CANDIDATE_OBSERVATIONS:
                candidates.append(
                    _candidate_observation(declaration, status="proven", matches=(target,))
                )
            if target.natural_key in matched_targets:
                continue
            matched_targets.add(target.natural_key)
            artifact = _artifact_reachability(self.root, declaration, source_texts)
            warnings.extend(artifact.warnings)
            provenance = _artifact_provenance(
                target,
                asset_manifests,
                repository_revision=self.revision,
                framework=declaration.framework,
            )
            inclusion_method = (
                "static_local_module_graph"
                if declaration.framework == "aws_cdk"
                else "not_evaluated"
            )
            evidence = Evidence(
                source_type="code_to_cloud_correlation",
                locator=(
                    f"repo://{self.repository_name}@{self.revision}/"
                    f"{declaration.path}#L{declaration.line}"
                ),
                observed_at=observed_at,
                payload={
                    "repository_revision": self.revision,
                    "provider": declaration.identity.provider,
                    "runtime_kind": declaration.identity.runtime_kind,
                    "deployment_framework": declaration.framework,
                    "source_path": declaration.path,
                    "source_line": declaration.line,
                    "service": declaration.service,
                    "construct_id": declaration.construct_id,
                    "deployment_identifier": declaration.deployment_name,
                    "entry": artifact.entry,
                    "build_file": artifact.build_file,
                    "artifact_inclusion_method": inclusion_method,
                    "reachable_source_paths": list(artifact.reachable_source_paths),
                    "artifact_import_chains": artifact.import_chains,
                    "observed_workload": target.natural_key,
                    "observed_deployment_identifiers": target.identity.to_record()[
                        "identifiers"
                    ],
                    "control_plane_evidence": target.evidence_locator,
                    "match_basis": _match_basis(declaration),
                    **provenance,
                },
            )
            relationships.append(
                RelationshipAssertion(
                    source=AssetRef(AssetKind.AI_WORKLOAD, target.natural_key),
                    target=repo_ref,
                    coverage_plane=RELATIONSHIP_PLANE,
                    kind=RelationshipKind.DEPLOYED_BY,
                    assertion_type=AssertionType.INFERRED,
                    confidence=1.0,
                    evidence=evidence,
                    attributes={
                        "correlation": "deterministic",
                        "provider": declaration.identity.provider,
                        "runtime_kind": declaration.identity.runtime_kind,
                        "deployment_framework": declaration.framework,
                        "service": declaration.service,
                        "source_path": declaration.path,
                        "source_line": declaration.line,
                        "entry": artifact.entry,
                        "build_file": artifact.build_file,
                        "artifact_inclusion_method": inclusion_method,
                        "reachable_source_paths": list(artifact.reachable_source_paths),
                        "artifact_import_chains": artifact.import_chains,
                        **provenance,
                    },
                )
            )

        if len(declarations) > _MAX_CANDIDATE_OBSERVATIONS:
            warnings.append(
                "correlation candidate observations exceed safety limit of "
                f"{_MAX_CANDIDATE_OBSERVATIONS}"
            )

        repo_assertion = AssetAssertion(
            asset=repo_ref,
            coverage_plane=INVENTORY_PLANE,
            display_name=self.repository_name.rsplit("/", 1)[-1],
            assertion_type=AssertionType.OBSERVED,
            confidence=1.0,
            evidence=Evidence(
                source_type=self.source_type,
                locator=self.source_locator,
                observed_at=observed_at,
                payload={"commit": self.commit, "dirty": self.dirty},
            ),
            attributes={
                "commit": self.commit,
                "dirty": self.dirty,
                "repository_revision": self.revision,
                "correlation_summary": {
                    "declarations": len(declarations),
                    **dispositions,
                    "targets_evaluated": len(self.targets),
                },
                "correlation_candidates": candidates,
            },
        )
        state = CoverageState.PARTIAL if warnings else CoverageState.COMPLETE
        detail = "; ".join(dict.fromkeys(warnings))[:4_000] if warnings else None
        return InventoryBatch(
            connector_id=self.connector_id,
            connection_id=connection,
            run_id=f"code-to-cloud-{self.revision[:18]}-{observed_at.isoformat()}",
            scope_key=scope,
            collected_at=observed_at,
            coverage=(
                Coverage(INVENTORY_PLANE, state, scope, detail),
                Coverage(RELATIONSHIP_PLANE, state, scope, detail),
            ),
            assets=(repo_assertion,),
            relationships=tuple(relationships),
        )


def _candidate_observation(
    declaration: DeploymentDeclaration,
    *,
    status: str,
    matches: tuple[DeploymentTarget, ...],
) -> dict[str, Any]:
    """Record correlation disposition without manufacturing a deployment edge."""

    return {
        "status": status,
        "provider": declaration.identity.provider,
        "runtime_kind": declaration.identity.runtime_kind,
        "deployment_framework": declaration.framework,
        "service": declaration.service,
        "construct_id": declaration.construct_id,
        "deployment_identifier": declaration.deployment_name,
        "source_path": declaration.path,
        "source_line": declaration.line,
        "match_basis": _match_basis(declaration),
        "matched_workload_count": len(matches),
        "matched_workloads": [
            item.natural_key for item in matches[:_MAX_CANDIDATE_MATCHES]
        ],
    }


def _deployment_declarations(
    text: str,
    relative: str,
    *,
    terraform_context: TerraformModuleContext | None = None,
) -> tuple[list[DeploymentDeclaration], list[str]]:
    suffix = Path(relative).suffix.lower()
    if suffix == ".tf":
        return _terraform_declarations(text, relative, context=terraform_context)
    if suffix == ".json":
        azure, azure_warnings = _azure_json_declarations(text, relative)
        aws, aws_warnings = _aws_cloudformation_json_declarations(text, relative)
        return [*azure, *aws], [*azure_warnings, *aws_warnings]
    if suffix == ".bicep":
        return _azure_bicep_declarations(text, relative)
    if suffix in {".yaml", ".yml"}:
        gcp, gcp_warnings = _cloud_run_yaml_declarations(text, relative)
        aws, aws_warnings = _aws_sam_yaml_declarations(text, relative)
        kubernetes, kubernetes_warnings = _kubernetes_yaml_declarations(text, relative)
        return (
            [*gcp, *aws, *kubernetes],
            [*gcp_warnings, *aws_warnings, *kubernetes_warnings],
        )
    output: list[DeploymentDeclaration] = []
    warnings: list[str] = []
    scan_text = _strip_js_comments(text)
    bindings = {
        match.group("name"): match.group("value")
        for match in _STRING_BINDING_RE.finditer(scan_text)
    }

    for match in _LAMBDA_RE.finditer(scan_text):
        object_start = match.end() - 1
        object_end = _balanced_object_end(text, object_start)
        if object_end is None:
            warnings.append(
                f"{relative}:{_line(text, match.start())}: unbalanced Lambda declaration"
            )
            continue
        body = text[object_start : object_end + 1]
        function_name = _literal_property(body, "functionName")
        if function_name is None:
            warnings.append(
                f"{relative}:{_line(text, match.start())}: Lambda functionName is not literal"
            )
            continue
        output.append(
            DeploymentDeclaration(
                identity=_aws_cdk_identity(
                    service="lambda",
                    construct_id=match.group("construct"),
                    deployment_name=function_name,
                ),
                framework="aws_cdk",
                service="lambda",
                construct_id=match.group("construct"),
                deployment_name=function_name,
                path=relative,
                line=_line(text, match.start()),
                entry=_literal_property(body, "entry"),
            )
        )

    for match in _TASK_RE.finditer(scan_text):
        variable = re.escape(match.group("variable"))
        add_container = re.compile(rf"\b{variable}\.addContainer\s*\(")
        container_match = add_container.search(scan_text, match.end())
        next_task = _TASK_RE.search(scan_text, match.end())
        if container_match is None or (
            next_task is not None and container_match.start() >= next_task.start()
        ):
            warnings.append(
                f"{relative}:{_line(text, match.start())}: task container declaration not found"
            )
            continue
        object_start = scan_text.find("{", container_match.end())
        if object_start < 0:
            warnings.append(
                f"{relative}:{_line(text, container_match.start())}: task container is not literal"
            )
            continue
        object_end = _balanced_object_end(text, object_start)
        if object_end is None:
            warnings.append(
                f"{relative}:{_line(text, container_match.start())}: unbalanced task container"
            )
            continue
        body = text[object_start : object_end + 1]
        container_name = _literal_property(body, "containerName")
        if container_name is None:
            variable_match = re.search(
                r"\bcontainerName(?:\s*:\s*([A-Za-z_$][\w$]*))?\s*(?=,|})", body
            )
            binding_name = (
                variable_match.group(1)
                if variable_match and variable_match.group(1)
                else "containerName"
            )
            container_name = bindings.get(binding_name)
        if container_name is None:
            warnings.append(
                f"{relative}:{_line(text, container_match.start())}: containerName is not literal"
            )
            continue
        output.append(
            DeploymentDeclaration(
                identity=_aws_cdk_identity(
                    service="ecs",
                    construct_id=match.group("construct"),
                    deployment_name=container_name,
                ),
                framework="aws_cdk",
                service="ecs",
                construct_id=match.group("construct"),
                deployment_name=container_name,
                path=relative,
                line=_line(text, match.start()),
                build_context=_asset_context(body),
                build_file=_literal_property(body, "file"),
            )
        )
    return output, warnings


def _terraform_module_contexts(
    source_texts: dict[str, str],
) -> dict[str, TerraformModuleContext]:
    module_texts: dict[str, str] = {}
    for relative in sorted(path for path in source_texts if path.endswith(".tf")):
        directory = posixpath.dirname(relative)
        module_texts[directory] = "\n".join(
            part
            for part in (
                module_texts.get(directory),
                _strip_hcl_comments(source_texts[relative]),
            )
            if part
        )

    contexts = {
        directory: _terraform_context(text)
        for directory, text in module_texts.items()
    }
    for _ in range(8):
        inbound: dict[
            str,
            list[tuple[dict[str, str], tuple[str, str] | None, str | None]],
        ] = {}
        for parent, text in module_texts.items():
            context = contexts[parent]
            for child, arguments, inherits_default_provider in _terraform_module_calls(
                text, parent, context.bindings
            ):
                if child in module_texts:
                    inbound.setdefault(child, []).append(
                        (
                            arguments,
                            context.aws_scope if inherits_default_provider else None,
                            (
                                context.azure_subscription
                                if inherits_default_provider
                                else None
                            ),
                        )
                    )

        updated: dict[str, TerraformModuleContext] = {}
        for directory, text in module_texts.items():
            calls = inbound.get(directory, [])
            overrides: dict[str, str] = {}
            argument_names = {name for arguments, _, _ in calls for name in arguments}
            for name in argument_names:
                values = {
                    arguments[name]
                    for arguments, _, _ in calls
                    if name in arguments
                }
                if len(values) == 1 and all(name in arguments for arguments, _, _ in calls):
                    overrides[f"var.{name}"] = values.pop()
            context = _terraform_context(text, overrides=overrides)
            if not _AWS_PROVIDER_RE.search(text):
                inherited_aws = {scope for _, scope, _ in calls if scope is not None}
                if len(inherited_aws) == 1 and all(scope is not None for _, scope, _ in calls):
                    context = replace(context, aws_scope=inherited_aws.pop())
            if not _AZURERM_PROVIDER_RE.search(text):
                inherited_azure = {
                    subscription
                    for _, _, subscription in calls
                    if subscription is not None
                }
                if len(inherited_azure) == 1 and all(
                    subscription is not None for _, _, subscription in calls
                ):
                    context = replace(
                        context, azure_subscription=inherited_azure.pop()
                    )
            updated[directory] = context
        if updated == contexts:
            return updated
        contexts = updated
    return contexts


def _terraform_context(
    text: str, *, overrides: dict[str, str] | None = None
) -> TerraformModuleContext:
    bindings = _terraform_literal_bindings(text, overrides=overrides)
    return TerraformModuleContext(
        bindings=bindings,
        aws_scope=_terraform_aws_scope(text, bindings),
        azure_subscription=_terraform_azure_subscription(text, bindings),
    )


def _terraform_literal_bindings(
    text: str, *, overrides: dict[str, str] | None = None
) -> dict[str, str]:
    bindings: dict[str, str] = {}
    for match in _TERRAFORM_VARIABLE_RE.finditer(text):
        end = _balanced_object_end(text, match.end() - 1)
        if end is None:
            continue
        block = text[match.end() - 1 : end + 1]
        default = _hcl_top_level_resolved(block, "default", bindings)
        if default is not None:
            bindings[f"var.{match.group('name')}"] = default
    bindings.update(overrides or {})

    local_expressions: dict[str, str] = {}
    for match in _TERRAFORM_LOCALS_RE.finditer(text):
        end = _balanced_object_end(text, match.end() - 1)
        if end is None:
            continue
        block = text[match.end() - 1 : end + 1]
        local_expressions.update(_hcl_top_level_expressions(block))
    for _ in range(8):
        changed = False
        for name, expression in local_expressions.items():
            value = _terraform_resolve_expression(expression, bindings)
            key = f"local.{name}"
            if value is not None and bindings.get(key) != value:
                bindings[key] = value
                changed = True
        if not changed:
            break
    return bindings


def _terraform_module_calls(
    text: str, parent: str, bindings: dict[str, str]
) -> list[tuple[str, dict[str, str], bool]]:
    calls: list[tuple[str, dict[str, str], bool]] = []
    for match in _TERRAFORM_MODULE_RE.finditer(text):
        end = _balanced_object_end(text, match.end() - 1)
        if end is None:
            continue
        block = text[match.end() - 1 : end + 1]
        source = _hcl_top_level_resolved(block, "source", bindings)
        if source is None or not source.startswith(("./", "../")):
            continue
        child = posixpath.normpath(posixpath.join(parent, source))
        if child == ".." or child.startswith("../") or child.startswith("/"):
            continue
        expressions = _hcl_top_level_expressions(block)
        arguments: dict[str, str] = {}
        for name, expression in expressions.items():
            if name in {"source", "providers"}:
                continue
            value = _terraform_resolve_expression(expression, bindings)
            if value is not None:
                arguments[name] = value
        calls.append(
            ("" if child == "." else child, arguments, "providers" not in expressions)
        )
    return calls


def _terraform_declarations(
    text: str,
    relative: str,
    *,
    context: TerraformModuleContext | None = None,
) -> tuple[list[DeploymentDeclaration], list[str]]:
    output: list[DeploymentDeclaration] = []
    warnings: list[str] = []
    scan_text = _strip_hcl_comments(text)
    bindings = context.bindings if context else _terraform_literal_bindings(scan_text)
    azure_subscription = (
        context.azure_subscription
        if context
        else _terraform_azure_subscription(scan_text, bindings)
    )
    aws_scope = context.aws_scope if context else _terraform_aws_scope(scan_text, bindings)
    for match in _TERRAFORM_RESOURCE_RE.finditer(scan_text):
        block_start = match.end() - 1
        block_end = _balanced_object_end(scan_text, block_start)
        line = _line(text, match.start())
        if block_end is None:
            warnings.append(f"{relative}:{line}: unbalanced Terraform resource")
            continue
        block = scan_text[block_start : block_end + 1]
        resource_type = match.group("type")
        if "provider" in _hcl_top_level_expressions(block):
            warnings.append(
                f"{relative}:{line}: Terraform resource provider alias is not safely "
                "resolved"
            )
            continue
        location = _hcl_top_level_resolved(block, "location", bindings)
        name = _hcl_top_level_resolved(block, "name", bindings)
        if resource_type.startswith("google_"):
            project = _hcl_top_level_resolved(block, "project", bindings)
            if not project or not location or not name:
                warnings.append(
                    f"{relative}:{line}: Terraform GCP project, location, and name "
                    "must each resolve to one literal"
                )
                continue
            if resource_type == "google_cloud_run_v2_service":
                service = "cloud_run"
                runtime_kind = "container_service"
                name_identifier = "service_name"
                name_basis = "literal_cloud_run_service_name"
            else:
                service = "cloud_functions"
                runtime_kind = "serverless_function"
                name_identifier = "function_name"
                name_basis = "literal_cloud_functions_gen2_function_name"
            identity = DeploymentIdentity(
                provider="gcp",
                runtime_kind=runtime_kind,
                identifiers=(
                    DeploymentIdentifier(
                        "project", project, evidence_basis="literal_gcp_project_id"
                    ),
                    DeploymentIdentifier(
                        "location", location, evidence_basis="literal_gcp_location"
                    ),
                    DeploymentIdentifier(name_identifier, name, evidence_basis=name_basis),
                ),
            )
        elif resource_type.startswith("azurerm_"):
            resource_group = _hcl_top_level_resolved(
                block, "resource_group_name", bindings
            )
            if not azure_subscription or not resource_group or not location or not name:
                warnings.append(
                    f"{relative}:{line}: Terraform Azure provider subscription_id and "
                    "resource resource_group_name, location, and name must each resolve "
                    "to one literal"
                )
                continue
            is_container = resource_type == "azurerm_container_app"
            service = "azure_container_apps" if is_container else "azure_functions"
            runtime_kind = "container_service" if is_container else "serverless_function"
            name_identifier = "container_app_name" if is_container else "function_app_name"
            name_basis = (
                "literal_azure_container_app_name"
                if is_container
                else "literal_azure_function_app_name"
            )
            identity = _azure_deployment_identity(
                subscription_id=azure_subscription,
                resource_group=resource_group,
                location=location,
                name=name,
                runtime_kind=runtime_kind,
                name_identifier=name_identifier,
                name_basis=name_basis,
            )
        else:
            account_id, region = aws_scope if aws_scope else (None, None)
            field = "family" if resource_type == "aws_ecs_task_definition" else "name"
            if resource_type == "aws_lambda_function":
                field = "function_name"
            deployment_name = _hcl_top_level_resolved(block, field, bindings)
            if not account_id or not region or not deployment_name:
                warnings.append(
                    f"{relative}:{line}: Terraform AWS provider region and single "
                    f"allowed_account_ids value plus resource {field} must each resolve "
                    "to one literal"
                )
                continue
            service, runtime_kind, identifier_name = {
                "aws_lambda_function": ("lambda", "serverless_function", "function_name"),
                "aws_ecs_task_definition": ("ecs", "container_task", "task_family"),
                "aws_eks_cluster": ("eks", "kubernetes_cluster", "cluster_name"),
                "aws_sagemaker_endpoint": ("sagemaker", "model_endpoint", "endpoint_name"),
            }[resource_type]
            name = deployment_name
            identity = _aws_deployment_identity(
                account_id=account_id,
                region=region,
                runtime_kind=runtime_kind,
                identifier_name=identifier_name,
                identifier_value=deployment_name,
                identifier_basis=f"literal_aws_{identifier_name}",
            )
        output.append(
            DeploymentDeclaration(
                identity=identity,
                framework="terraform",
                service=service,
                construct_id=f"{resource_type}.{match.group('label')}",
                deployment_name=name,
                path=relative,
                line=line,
            )
        )
    return output, warnings


def _terraform_azure_subscription(
    text: str, bindings: dict[str, str] | None = None
) -> str | None:
    subscriptions: list[str] = []
    for match in _AZURERM_PROVIDER_RE.finditer(text):
        block_start = match.end() - 1
        block_end = _balanced_object_end(text, block_start)
        if block_end is None:
            continue
        block = text[block_start : block_end + 1]
        if "alias" in _hcl_top_level_expressions(block):
            continue
        subscription = _hcl_top_level_resolved(
            block, "subscription_id", bindings or {}
        )
        if subscription and _valid_azure_uuid(subscription):
            subscriptions.append(subscription.lower())
    return subscriptions[0] if len(set(subscriptions)) == 1 else None


def _terraform_aws_scope(
    text: str, bindings: dict[str, str] | None = None
) -> tuple[str, str] | None:
    scopes: list[tuple[str, str]] = []
    for match in _AWS_PROVIDER_RE.finditer(text):
        block_start = match.end() - 1
        block_end = _balanced_object_end(text, block_start)
        if block_end is None:
            continue
        block = text[block_start : block_end + 1]
        if "alias" in _hcl_top_level_expressions(block):
            continue
        resolved = bindings or {}
        region = _hcl_top_level_resolved(block, "region", resolved)
        accounts = _hcl_top_level_resolved_list(
            block, "allowed_account_ids", resolved
        )
        if region and len(accounts) == 1 and re.fullmatch(r"[0-9]{12}", accounts[0]):
            scopes.append((accounts[0], region))
    return scopes[0] if len(set(scopes)) == 1 else None


def _hcl_top_level_resolved_list(
    block: str, key: str, bindings: dict[str, str]
) -> tuple[str, ...]:
    pattern = re.compile(rf"(?m)^\s*{re.escape(key)}\s*=\s*\[(?P<value>[^\]]*)\]")
    for match in pattern.finditer(block):
        if _hcl_brace_depth(block, match.start()) != 1:
            continue
        expressions = [item.strip() for item in match.group("value").split(",")]
        values = tuple(
            value
            for expression in expressions
            if expression
            if (value := _terraform_resolve_expression(expression, bindings)) is not None
        )
        if len(values) == len([item for item in expressions if item]):
            return values
    return ()


def _hcl_top_level_expressions(block: str) -> dict[str, str]:
    output: dict[str, str] = {}
    pattern = re.compile(
        r"(?m)^\s*(?P<key>[A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(?P<value>[^\r\n#]+)"
    )
    for match in pattern.finditer(block):
        if _hcl_brace_depth(block, match.start()) == 1:
            output[match.group("key")] = match.group("value").strip()
    return output


def _hcl_top_level_resolved(
    block: str, key: str, bindings: dict[str, str]
) -> str | None:
    expression = _hcl_top_level_expressions(block).get(key)
    return (
        None
        if expression is None
        else _terraform_resolve_expression(expression, bindings)
    )


def _terraform_resolve_expression(
    expression: str, bindings: dict[str, str]
) -> str | None:
    value = expression.strip().removesuffix(",").strip()
    literal = re.fullmatch(r"(['\"])(?P<value>[^'\"\r\n]+)\1", value)
    if literal:
        resolved = literal.group("value")
        return None if "${" in resolved else resolved
    if re.fullmatch(r"(?:var|local)\.[A-Za-z_][A-Za-z0-9_-]*", value):
        return bindings.get(value)
    return None


def _aws_deployment_identity(
    *,
    account_id: str,
    region: str,
    runtime_kind: str,
    identifier_name: str,
    identifier_value: str,
    identifier_basis: str,
) -> DeploymentIdentity:
    return DeploymentIdentity(
        provider="aws",
        runtime_kind=runtime_kind,
        identifiers=(
            DeploymentIdentifier(
                "account_id", account_id, evidence_basis="literal_aws_account_id"
            ),
            DeploymentIdentifier(
                "region", region, evidence_basis="literal_aws_region"
            ),
            DeploymentIdentifier(
                identifier_name,
                identifier_value,
                evidence_basis=identifier_basis,
            ),
        ),
    )


def _aws_cloudformation_json_declarations(
    text: str, relative: str
) -> tuple[list[DeploymentDeclaration], list[str]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return [], []
    if not isinstance(payload, dict) or not isinstance(payload.get("Resources"), dict):
        return [], []
    metadata = payload.get("Metadata")
    denali = metadata.get("Denali") if isinstance(metadata, dict) else None
    account_id = denali.get("AccountId") if isinstance(denali, dict) else None
    region = denali.get("Region") if isinstance(denali, dict) else None
    return _aws_template_resources(
        payload["Resources"],
        account_id=account_id,
        region=region,
        relative=relative,
        framework="sam_cloudformation",
    )


def _aws_template_resources(
    resources: dict[str, Any],
    *,
    account_id: Any,
    region: Any,
    relative: str,
    framework: str,
) -> tuple[list[DeploymentDeclaration], list[str]]:
    output: list[DeploymentDeclaration] = []
    warnings: list[str] = []
    supported = {
        "AWS::Serverless::Function": (
            "lambda",
            "serverless_function",
            "FunctionName",
            "function_name",
        ),
        "AWS::Lambda::Function": ("lambda", "serverless_function", "FunctionName", "function_name"),
        "AWS::ECS::TaskDefinition": ("ecs", "container_task", "Family", "task_family"),
        "AWS::EKS::Cluster": ("eks", "kubernetes_cluster", "Name", "cluster_name"),
        "AWS::SageMaker::Endpoint": (
            "sagemaker",
            "model_endpoint",
            "EndpointName",
            "endpoint_name",
        ),
    }
    for logical_id, resource in resources.items():
        if not isinstance(logical_id, str) or not isinstance(resource, dict):
            continue
        resource_type = resource.get("Type")
        if resource_type not in supported:
            continue
        service, runtime_kind, property_name, identifier_name = supported[resource_type]
        properties = resource.get("Properties")
        name = properties.get(property_name) if isinstance(properties, dict) else None
        if (
            not isinstance(account_id, str)
            or re.fullmatch(r"[0-9]{12}", account_id) is None
            or not isinstance(region, str)
            or not region
            or not isinstance(name, str)
            or not name
        ):
            warnings.append(
                f"{relative}:1: SAM/CloudFormation Metadata.Denali AccountId/Region and "
                f"{logical_id} {property_name} must all be literal"
            )
            continue
        output.append(
            DeploymentDeclaration(
                identity=_aws_deployment_identity(
                    account_id=account_id,
                    region=region,
                    runtime_kind=runtime_kind,
                    identifier_name=identifier_name,
                    identifier_value=name,
                    identifier_basis=f"literal_aws_{identifier_name}",
                ),
                framework=framework,
                service=service,
                construct_id=logical_id,
                deployment_name=name,
                path=relative,
                line=1,
            )
        )
    return output, warnings


def _azure_json_declarations(
    text: str, relative: str
) -> tuple[list[DeploymentDeclaration], list[str]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return [], []
    if not isinstance(payload, dict):
        return [], []

    direct_id = payload.get("id")
    if isinstance(direct_id, str):
        declaration = _azure_resource_id_declaration(
            direct_id,
            location=payload.get("location"),
            relative=relative,
            framework="azure_resource_json",
            line=1,
        )
        return ([declaration], []) if declaration is not None else ([], [])

    resources = payload.get("resources")
    if not isinstance(resources, list):
        return [], []
    metadata = payload.get("metadata")
    denali = metadata.get("denali") if isinstance(metadata, dict) else None
    subscription = denali.get("subscriptionId") if isinstance(denali, dict) else None
    resource_group = denali.get("resourceGroup") if isinstance(denali, dict) else None
    output: list[DeploymentDeclaration] = []
    warnings: list[str] = []
    for index, resource in enumerate(resources):
        if not isinstance(resource, dict):
            continue
        resource_type = str(resource.get("type", "")).lower()
        if resource_type not in {
            "microsoft.app/containerapps",
            "microsoft.web/sites",
        }:
            continue
        name = resource.get("name")
        location = resource.get("location")
        if not all(
            isinstance(item, str) and item
            for item in (subscription, resource_group, name, location)
        ) or not _valid_azure_uuid(str(subscription)):
            warnings.append(
                f"{relative}:1: ARM Azure metadata subscriptionId/resourceGroup and "
                f"resource {index} name/location must all be literal"
            )
            continue
        output.append(
            _azure_declaration(
                subscription_id=str(subscription),
                resource_group=str(resource_group),
                location=str(location),
                name=str(name),
                resource_type=resource_type,
                framework="arm_template",
                construct_id=f"{resource.get('type')}/{name}",
                relative=relative,
                line=1,
            )
        )
    return output, warnings


def _azure_resource_id_declaration(
    resource_id: str,
    *,
    location: Any,
    relative: str,
    framework: str,
    line: int,
) -> DeploymentDeclaration | None:
    match = _AZURE_RESOURCE_ID_RE.fullmatch(resource_id)
    if match is None or not isinstance(location, str) or not location:
        return None
    resource_type = (
        "microsoft.app/containerapps"
        if match.group("kind").lower() == "containerapps"
        else "microsoft.web/sites"
    )
    return _azure_declaration(
        subscription_id=match.group("subscription"),
        resource_group=match.group("resource_group"),
        location=location,
        name=match.group("name"),
        resource_type=resource_type,
        framework=framework,
        construct_id=resource_id,
        relative=relative,
        line=line,
    )


def _azure_bicep_declarations(
    text: str, relative: str
) -> tuple[list[DeploymentDeclaration], list[str]]:
    subscription_match = re.search(
        r"(?m)^\s*metadata\s+denaliSubscriptionId\s*=\s*(['\"])(?P<value>[^'\"]+)\1\s*$",
        text,
    )
    resource_group_match = re.search(
        r"(?m)^\s*metadata\s+denaliResourceGroup\s*=\s*(['\"])(?P<value>[^'\"]+)\1\s*$",
        text,
    )
    subscription = subscription_match.group("value") if subscription_match else None
    resource_group = resource_group_match.group("value") if resource_group_match else None
    output: list[DeploymentDeclaration] = []
    warnings: list[str] = []
    for match in _AZURE_BICEP_RESOURCE_RE.finditer(text):
        line = _line(text, match.start())
        block_start = match.end() - 1
        block_end = _balanced_object_end(text, block_start)
        if block_end is None:
            warnings.append(f"{relative}:{line}: unbalanced Bicep resource")
            continue
        block = text[block_start : block_end + 1]
        name = _literal_property(block, "name")
        location = _literal_property(block, "location")
        if (
            not subscription
            or not _valid_azure_uuid(subscription)
            or not resource_group
            or not name
            or not location
        ):
            warnings.append(
                f"{relative}:{line}: Bicep Denali subscription/resource-group metadata "
                "and resource name/location must all be literal"
            )
            continue
        output.append(
            _azure_declaration(
                subscription_id=subscription,
                resource_group=resource_group,
                location=location,
                name=name,
                resource_type=match.group("type").lower(),
                framework="bicep",
                construct_id=match.group("symbol"),
                relative=relative,
                line=line,
            )
        )
    return output, warnings


def _azure_declaration(
    *,
    subscription_id: str,
    resource_group: str,
    location: str,
    name: str,
    resource_type: str,
    framework: str,
    construct_id: str,
    relative: str,
    line: int,
) -> DeploymentDeclaration:
    is_container = resource_type.lower() == "microsoft.app/containerapps"
    service = "azure_container_apps" if is_container else "azure_functions"
    runtime_kind = "container_service" if is_container else "serverless_function"
    name_identifier = "container_app_name" if is_container else "function_app_name"
    name_basis = (
        "literal_azure_container_app_name"
        if is_container
        else "literal_azure_function_app_name"
    )
    return DeploymentDeclaration(
        identity=_azure_deployment_identity(
            subscription_id=subscription_id,
            resource_group=resource_group,
            location=location,
            name=name,
            runtime_kind=runtime_kind,
            name_identifier=name_identifier,
            name_basis=name_basis,
        ),
        framework=framework,
        service=service,
        construct_id=construct_id,
        deployment_name=name,
        path=relative,
        line=line,
    )


def _azure_deployment_identity(
    *,
    subscription_id: str,
    resource_group: str,
    location: str,
    name: str,
    runtime_kind: str,
    name_identifier: str,
    name_basis: str,
) -> DeploymentIdentity:
    return DeploymentIdentity(
        provider="azure",
        runtime_kind=runtime_kind,
        identifiers=(
            DeploymentIdentifier(
                "subscription_id",
                subscription_id.lower(),
                evidence_basis="literal_azure_subscription_id",
            ),
            DeploymentIdentifier(
                "resource_group",
                resource_group.lower(),
                evidence_basis="literal_azure_resource_group",
            ),
            DeploymentIdentifier(
                "location",
                location.lower().replace(" ", ""),
                evidence_basis="literal_azure_location",
            ),
            DeploymentIdentifier(
                name_identifier,
                name.lower(),
                evidence_basis=name_basis,
            ),
        ),
    )


def _valid_azure_uuid(value: str) -> bool:
    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
            r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            value,
        )
    )


def _cloud_run_yaml_declarations(
    text: str, relative: str
) -> tuple[list[DeploymentDeclaration], list[str]]:
    output: list[DeploymentDeclaration] = []
    warnings: list[str] = []
    boundaries = [0, *(match.end() for match in re.finditer(r"(?m)^---\s*$", text)), len(text)]
    for index, start in enumerate(boundaries[:-1]):
        document = text[start : boundaries[index + 1]]
        api_version = _yaml_top_level_literal(document, "apiVersion")
        kind = _yaml_top_level_literal(document, "kind")
        if api_version != "serving.knative.dev/v1" or kind != "Service":
            continue
        line = _line(text, start)
        metadata = _yaml_top_level_block(document, "metadata")
        if metadata is None:
            warnings.append(f"{relative}:{line}: Cloud Run Service metadata is not literal")
            continue
        name = _yaml_direct_literal(metadata, "name")
        project_number = _yaml_direct_literal(metadata, "namespace")
        labels = _yaml_direct_block(metadata, "labels")
        location = (
            _yaml_direct_literal(labels, "cloud.googleapis.com/location")
            if labels is not None
            else None
        )
        if (
            not name
            or not project_number
            or not project_number.isdigit()
            or not location
        ):
            warnings.append(
                f"{relative}:{line}: Cloud Run YAML project number, location, and name "
                "must all be literal"
            )
            continue
        output.append(
            DeploymentDeclaration(
                identity=DeploymentIdentity(
                    provider="gcp",
                    runtime_kind="container_service",
                    identifiers=(
                        DeploymentIdentifier(
                            "project_number",
                            project_number,
                            evidence_basis="literal_gcp_project_number",
                        ),
                        DeploymentIdentifier(
                            "location", location, evidence_basis="literal_gcp_location"
                        ),
                        DeploymentIdentifier(
                            "service_name",
                            name,
                            evidence_basis="literal_cloud_run_service_name",
                        ),
                    ),
                ),
                framework="cloud_run_service_yaml",
                service="cloud_run",
                construct_id=f"serving.knative.dev/v1:Service/{name}",
                deployment_name=name,
                path=relative,
                line=line,
            )
        )
    return output, warnings


def _aws_sam_yaml_declarations(
    text: str, relative: str
) -> tuple[list[DeploymentDeclaration], list[str]]:
    metadata = _yaml_top_level_block(text, "Metadata")
    resources_block = _yaml_top_level_block(text, "Resources")
    if resources_block is None:
        return [], []
    denali = _yaml_direct_block(metadata, "Denali") if metadata is not None else None
    account_id = _yaml_direct_literal(denali, "AccountId") if denali is not None else None
    region = _yaml_direct_literal(denali, "Region") if denali is not None else None
    indent = _yaml_direct_indent(resources_block)
    if indent is None:
        return [], []
    matches = list(
        re.finditer(
            rf"(?m)^ {{{indent}}}(?P<logical>[A-Za-z0-9]+):\s*(?:#.*)?$",
            resources_block,
        )
    )
    resources: dict[str, Any] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(resources_block)
        resource_block = resources_block[match.end() : end]
        resource_type = _yaml_direct_literal(resource_block, "Type")
        properties = _yaml_direct_block(resource_block, "Properties")
        if resource_type is None:
            continue
        property_values: dict[str, str] = {}
        if properties is not None:
            for key in ("FunctionName", "Family", "Name", "EndpointName"):
                value = _yaml_direct_literal(properties, key)
                if value is not None:
                    property_values[key] = value
        resources[match.group("logical")] = {
            "Type": resource_type,
            "Properties": property_values,
        }
    if not any(
        isinstance(item, dict)
        and str(item.get("Type", "")).startswith(
            (
                "AWS::Serverless::",
                "AWS::Lambda::",
                "AWS::ECS::",
                "AWS::EKS::",
                "AWS::SageMaker::",
            )
        )
        for item in resources.values()
    ):
        return [], []
    return _aws_template_resources(
        resources,
        account_id=account_id,
        region=region,
        relative=relative,
        framework="sam_cloudformation",
    )


def _kubernetes_yaml_declarations(
    text: str, relative: str
) -> tuple[list[DeploymentDeclaration], list[str]]:
    """Read opt-in Kubernetes manifests without evaluating templates or substitutions."""

    if "denali.ai/workload" not in text:
        return [], []
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return [], [f"{relative}:1: opted-in Kubernetes YAML could not be parsed safely"]

    output: list[DeploymentDeclaration] = []
    warnings: list[str] = []
    for index, document in enumerate(documents):
        if not isinstance(document, dict) or document.get("kind") not in (
            _KUBERNETES_WORKLOAD_KINDS
        ):
            continue
        metadata = document.get("metadata")
        annotations = metadata.get("annotations") if isinstance(metadata, dict) else None
        if not isinstance(annotations, dict) or str(
            annotations.get("denali.ai/workload", "")
        ).lower() != "true":
            continue
        locator = f"{relative}:document-{index + 1}"
        try:
            output.append(
                _kubernetes_declaration(document, annotations, relative=relative)
            )
        except ValueError as error:
            warnings.append(f"{locator}: {error}")
    return output, warnings


def _kubernetes_declaration(
    document: dict[str, Any],
    annotations: dict[str, Any],
    *,
    relative: str,
) -> DeploymentDeclaration:
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise ValueError("metadata must be literal")
    kind = str(document["kind"])
    name = _manifest_literal(metadata.get("name"), "metadata.name")
    namespace = _manifest_literal(metadata.get("namespace") or "default", "metadata.namespace")
    service_account, images = _kubernetes_pod_identity(document)
    if not images:
        raise ValueError("pod template must contain at least one literal image")
    image_digests: list[str] = []
    for image in images:
        match = _KUBERNETES_DIGEST_IMAGE_RE.fullmatch(image)
        if match is None:
            raise ValueError("every container image must be pinned by a sha256 digest")
        image_digests.append(f"sha256:{match.group('digest').lower()}")

    provider = _manifest_literal(annotations.get("denali.ai/provider"), "provider").lower()
    cluster_name = _manifest_literal(
        annotations.get("denali.ai/cluster-name"), "cluster-name"
    )
    identifiers: list[DeploymentIdentifier]
    if provider == "aws":
        account_id = _manifest_literal(
            annotations.get("denali.ai/account-id"), "account-id"
        )
        region = _manifest_literal(annotations.get("denali.ai/region"), "region")
        if re.fullmatch(r"[0-9]{12}", account_id) is None:
            raise ValueError("AWS account-id must contain exactly 12 digits")
        identifiers = [
            DeploymentIdentifier(
                "account_id", account_id, evidence_basis="literal_kubernetes_account_id"
            ),
            DeploymentIdentifier("region", region, evidence_basis="literal_kubernetes_region"),
            DeploymentIdentifier(
                "cluster_name",
                cluster_name,
                evidence_basis="literal_kubernetes_cluster_name",
            ),
        ]
    elif provider == "gcp":
        project = annotations.get("denali.ai/project-id")
        project_number = annotations.get("denali.ai/project-number")
        if bool(project) == bool(project_number):
            raise ValueError("GCP requires exactly one project-id or project-number")
        location = _manifest_literal(
            annotations.get("denali.ai/location"), "location"
        )
        project_name = "project" if project else "project_number"
        project_value = _manifest_literal(project or project_number, project_name)
        identifiers = [
            DeploymentIdentifier(
                project_name,
                project_value,
                evidence_basis=f"literal_kubernetes_{project_name}",
            ),
            DeploymentIdentifier(
                "location", location, evidence_basis="literal_kubernetes_location"
            ),
            DeploymentIdentifier(
                "cluster_name",
                cluster_name,
                evidence_basis="literal_kubernetes_cluster_name",
            ),
        ]
    elif provider == "azure":
        subscription_id = _manifest_literal(
            annotations.get("denali.ai/subscription-id"), "subscription-id"
        )
        if not _valid_azure_uuid(subscription_id):
            raise ValueError("Azure subscription-id must be a UUID")
        resource_group = _manifest_literal(
            annotations.get("denali.ai/resource-group"), "resource-group"
        )
        location = _manifest_literal(
            annotations.get("denali.ai/location"), "location"
        )
        identifiers = [
            DeploymentIdentifier(
                "subscription_id",
                subscription_id.lower(),
                evidence_basis="literal_kubernetes_subscription_id",
            ),
            DeploymentIdentifier(
                "resource_group",
                resource_group.lower(),
                evidence_basis="literal_kubernetes_resource_group",
            ),
            DeploymentIdentifier(
                "location",
                location.lower().replace(" ", ""),
                evidence_basis="literal_kubernetes_location",
            ),
            DeploymentIdentifier(
                "cluster_name",
                cluster_name.lower(),
                evidence_basis="literal_kubernetes_cluster_name",
            ),
        ]
    else:
        raise ValueError("provider must be aws, gcp, or azure")

    identifiers.extend(
        (
            DeploymentIdentifier(
                "namespace", namespace, evidence_basis="literal_kubernetes_namespace"
            ),
            DeploymentIdentifier(
                "workload_kind", kind.lower(), evidence_basis="literal_kubernetes_kind"
            ),
            DeploymentIdentifier(
                "workload_name", name, evidence_basis="literal_kubernetes_name"
            ),
            DeploymentIdentifier(
                "service_account",
                service_account,
                evidence_basis="literal_kubernetes_service_account",
            ),
        )
    )
    identifiers.extend(
        DeploymentIdentifier(
            "image_digest", digest, evidence_basis="literal_kubernetes_image_digest"
        )
        for digest in sorted(set(image_digests))
    )
    for annotation, identifier in (
        ("denali.ai/workload-uid", "workload_uid"),
        ("denali.ai/workload-revision", "workload_revision"),
    ):
        value = annotations.get(annotation)
        if value is not None:
            identifiers.append(
                DeploymentIdentifier(
                    identifier,
                    _manifest_literal(value, annotation.removeprefix("denali.ai/")),
                    evidence_basis=f"literal_kubernetes_{identifier}",
                )
            )
    return DeploymentDeclaration(
        identity=DeploymentIdentity(provider, "kubernetes_workload", tuple(identifiers)),
        framework="kubernetes_manifest",
        service="kubernetes",
        construct_id=(
            f"{document.get('apiVersion', 'unknown')}:{kind}/{namespace}/{name}"
        ),
        deployment_name=f"{namespace}/{kind.lower()}/{name}",
        path=relative,
        line=1,
    )


def _kubernetes_pod_identity(document: dict[str, Any]) -> tuple[str, list[str]]:
    spec = document.get("spec")
    if not isinstance(spec, dict):
        raise ValueError("spec must be literal")
    if document["kind"] == "CronJob":
        job_template = spec.get("jobTemplate")
        job_spec = job_template.get("spec") if isinstance(job_template, dict) else None
        template = job_spec.get("template") if isinstance(job_spec, dict) else None
    else:
        template = spec.get("template")
    pod_spec = template.get("spec") if isinstance(template, dict) else None
    if not isinstance(pod_spec, dict):
        raise ValueError("pod template spec must be literal")
    service_account = _manifest_literal(
        pod_spec.get("serviceAccountName") or "default", "serviceAccountName"
    )
    containers = [
        container
        for field in ("initContainers", "containers")
        for container in pod_spec.get(field, [])
        if isinstance(container, dict)
    ]
    images = [
        _manifest_literal(container.get("image"), "container image")
        for container in containers
    ]
    return service_account, images


def _manifest_literal(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "${" in value or "{{" in value:
        raise ValueError(f"{field} must be a literal string")
    return value


def _yaml_top_level_literal(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(?P<value>[^\r\n]+)$", text)
    return _yaml_scalar(match.group("value")) if match else None


def _yaml_top_level_block(text: str, key: str) -> str | None:
    match = re.search(rf"(?m)^{re.escape(key)}:\s*(?:#.*)?$", text)
    if match is None:
        return None
    following = text[match.end() :]
    end = re.search(r"(?m)^\S", following)
    return following[: end.start()] if end else following


def _yaml_direct_literal(block: str, key: str) -> str | None:
    indent = _yaml_direct_indent(block)
    if indent is None:
        return None
    match = re.search(
        rf"(?m)^ {{{indent}}}{re.escape(key)}:\s*(?P<value>[^\r\n]+)$",
        block,
    )
    return _yaml_scalar(match.group("value")) if match else None


def _yaml_direct_block(block: str, key: str) -> str | None:
    indent = _yaml_direct_indent(block)
    if indent is None:
        return None
    match = re.search(rf"(?m)^ {{{indent}}}{re.escape(key)}:\s*(?:#.*)?$", block)
    if match is None:
        return None
    following = block[match.end() :]
    end = re.search(rf"(?m)^ {{0,{indent}}}\S", following)
    return following[: end.start()] if end else following


def _yaml_direct_indent(block: str) -> int | None:
    indents = [
        len(match.group("indent"))
        for match in re.finditer(r"(?m)^(?P<indent> +)\S", block)
    ]
    return min(indents) if indents else None


def _yaml_scalar(raw: str) -> str | None:
    value = re.sub(r"\s+#.*$", "", raw).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    if not value or value[0] in "[{*&!" or "${" in value:
        return None
    return value


def _hcl_top_level_literal(block: str, key: str) -> str | None:
    pattern = re.compile(
        rf"(?m)^\s*{re.escape(key)}\s*=\s*(['\"])(?P<value>[^'\"\r\n]+)\1\s*(?:$|#|//)"
    )
    for match in pattern.finditer(block):
        if _hcl_brace_depth(block, match.start()) != 1:
            continue
        value = match.group("value")
        if "${" not in value:
            return value
    return None


def _hcl_brace_depth(text: str, end: int) -> int:
    depth = 0
    quote: str | None = None
    escaped = False
    for char in text[:end]:
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char in {"'", '"'}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    return depth


def _strip_hcl_comments(text: str) -> str:
    output = re.sub(
        r"/\*.*?\*/",
        lambda match: "\n" * match.group(0).count("\n"),
        text,
        flags=re.DOTALL,
    )
    return re.sub(r"(?m)(?<!:)\s*(?:#|//).*?$", "", output)


def _deployment_source_files(root: Path) -> list[Path]:
    files = set(_source_files(root))
    for path in root.rglob("*"):
        if (
            path.is_file()
            and not path.is_symlink()
            and path.suffix.lower() in _IAC_SUFFIXES
            and not any(part in _MANIFEST_EXCLUDED_DIRS for part in path.relative_to(root).parts)
        ):
            files.add(path)
    return sorted(files)


def _literal_property(text: str, key: str) -> str | None:
    match = re.search(
        _LITERAL_PROPERTY_TEMPLATE.format(key=re.escape(key)),
        _strip_js_comments(text),
    )
    return match.group("value") if match else None


def _asset_context(text: str) -> str | None:
    match = _ASSET_CONTEXT_RE.search(_strip_js_comments(text))
    return match.group("value") if match else None


def _artifact_reachability(
    root: Path,
    declaration: DeploymentDeclaration,
    source_texts: dict[str, str],
) -> ArtifactReachability:
    if declaration.framework != "aws_cdk":
        return ArtifactReachability(None, None, (), {}, ())
    warnings: list[str] = []
    project_root = _project_root(root, declaration.path)
    entry = declaration.entry
    build_file: str | None = None

    if declaration.service == "ecs":
        if declaration.build_context is None or declaration.build_file is None:
            warnings.append(
                f"{declaration.path}:{declaration.line}: ECS artifact build context or "
                "Dockerfile is not literal"
            )
            return ArtifactReachability(None, None, (), {}, tuple(warnings))
        build_root = _safe_join(project_root, declaration.build_context)
        build_path = _safe_join(build_root, declaration.build_file) if build_root else None
        if build_path is None or not build_path.is_file() or not build_path.is_relative_to(root):
            warnings.append(
                f"{declaration.path}:{declaration.line}: declared Dockerfile could not be read"
            )
            return ArtifactReachability(None, None, (), {}, tuple(warnings))
        build_file = build_path.relative_to(root).as_posix()
        try:
            if build_path.stat().st_size > MAX_SOURCE_BYTES:
                raise OSError("Dockerfile exceeds source size limit")
            dockerfile = build_path.read_text(encoding="utf-8", errors="replace")
        except OSError as error:
            warnings.append(f"{build_file}: {error}")
            return ArtifactReachability(None, build_file, (), {}, tuple(warnings))
        entry = _esbuild_bundle_entry(dockerfile)
        if entry is None:
            warnings.append(f"{build_file}: no literal esbuild --bundle entry was found")
            return ArtifactReachability(None, build_file, (), {}, tuple(warnings))
        entry_path = _safe_join(build_root, entry)
    else:
        if entry is None:
            warnings.append(
                f"{declaration.path}:{declaration.line}: Lambda entry is not literal"
            )
            return ArtifactReachability(None, None, (), {}, tuple(warnings))
        entry_path = _safe_join(project_root, entry)

    if entry_path is None or not entry_path.is_relative_to(root):
        warnings.append(f"{declaration.path}:{declaration.line}: artifact entry escapes repository")
        return ArtifactReachability(None, build_file, (), {}, tuple(warnings))
    entry_relative = entry_path.relative_to(root).as_posix()
    if entry_relative not in source_texts:
        warnings.append(
            f"{declaration.path}:{declaration.line}: artifact entry {entry_relative!r} "
            "was not found in scanned source"
        )
        return ArtifactReachability(entry_relative, build_file, (), {}, tuple(warnings))

    reachable, chains, graph_warnings = _local_module_graph(entry_relative, source_texts)
    warnings.extend(graph_warnings)
    return ArtifactReachability(
        entry_relative,
        build_file,
        tuple(sorted(reachable)),
        chains,
        tuple(warnings),
    )


def _project_root(root: Path, declaration_path: str) -> Path:
    current = (root / declaration_path).resolve().parent
    while current.is_relative_to(root):
        if (current / "package.json").is_file():
            return current
        if current == root:
            break
        current = current.parent
    return root


def _safe_join(base: Path | None, relative: str) -> Path | None:
    if base is None or Path(relative).is_absolute():
        return None
    resolved = (base / relative).resolve()
    return resolved if resolved.is_relative_to(base) else None


def _esbuild_bundle_entry(dockerfile: str) -> str | None:
    normalized = re.sub(r"\\\s*\r?\n\s*", " ", dockerfile)
    for match in _ESBUILD_RE.finditer(normalized):
        if re.search(r"(?:^|\s)--bundle(?:\s|$)", match.group("arguments")):
            return match.group("entry")
    return None


def _local_module_graph(
    entry: str, source_texts: dict[str, str]
) -> tuple[set[str], dict[str, list[str]], list[str]]:
    reachable = {entry}
    parents: dict[str, str | None] = {entry: None}
    queue = deque([entry])
    warnings: list[str] = []
    while queue:
        current = queue.popleft()
        for specifier in _local_imports(source_texts[current]):
            matches = _resolve_local_module(current, specifier, source_texts)
            if len(matches) != 1:
                if not matches and ".generated." in PurePosixPath(specifier).name.lower():
                    continue
                outcome = "not found" if not matches else f"ambiguous ({', '.join(matches)})"
                warnings.append(f"{current}: local import {specifier!r} was {outcome}")
                continue
            target = matches[0]
            if target in reachable:
                continue
            reachable.add(target)
            parents[target] = current
            queue.append(target)
    chains = {path: _import_chain(path, parents) for path in sorted(reachable)}
    return reachable, chains, warnings


def _local_imports(text: str) -> tuple[str, ...]:
    uncommented = _strip_js_comments(text)
    matches = [
        *(match.group("value") for match in _STATIC_IMPORT_RE.finditer(uncommented)),
        *(match.group("value") for match in _EXPORT_FROM_RE.finditer(uncommented)),
        *(match.group("value") for match in _DYNAMIC_IMPORT_RE.finditer(uncommented)),
    ]
    return tuple(dict.fromkeys(matches))


def _strip_js_comments(text: str) -> str:
    output = list(text)
    state = "code"
    escaped = False
    index = 0
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if state in {"single", "double", "template"}:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "single" and char == "'") or (
                state == "double" and char == '"'
            ) or (state == "template" and char == "`"):
                state = "code"
        elif state == "line_comment":
            if char == "\n":
                state = "code"
            else:
                output[index] = " "
        elif state == "block_comment":
            output[index] = "\n" if char == "\n" else " "
            if char == "*" and nxt == "/":
                output[index + 1] = " "
                state = "code"
                index += 1
        elif char == "/" and nxt == "/":
            output[index] = output[index + 1] = " "
            state = "line_comment"
            index += 1
        elif char == "/" and nxt == "*":
            output[index] = output[index + 1] = " "
            state = "block_comment"
            index += 1
        elif char == "'":
            state = "single"
        elif char == '"':
            state = "double"
        elif char == "`":
            state = "template"
        index += 1
    return "".join(output)


def _resolve_local_module(
    importer: str, specifier: str, source_texts: dict[str, str]
) -> tuple[str, ...]:
    base = posixpath.normpath(posixpath.join(posixpath.dirname(importer), specifier))
    suffix = posixpath.splitext(base)[1]
    candidates: list[str] = []
    if suffix in {".js", ".jsx"}:
        stem = base[: -len(suffix)]
        candidates.extend(f"{stem}{item}" for item in (".ts", ".tsx", ".js", ".jsx"))
    elif suffix == ".mjs":
        stem = base[:-4]
        candidates.extend((f"{stem}.mts", f"{stem}.mjs"))
    elif suffix == ".cjs":
        stem = base[:-4]
        candidates.extend((f"{stem}.cts", f"{stem}.cjs"))
    elif suffix:
        candidates.append(base)
    else:
        candidates.extend(f"{base}{item}" for item in _MODULE_SUFFIXES)
        candidates.extend(f"{base}/index{item}" for item in _MODULE_SUFFIXES)
    return tuple(candidate for candidate in candidates if candidate in source_texts)


def _import_chain(path: str, parents: dict[str, str | None]) -> list[str]:
    chain: list[str] = []
    current: str | None = path
    while current is not None:
        chain.append(current)
        current = parents[current]
    chain.reverse()
    return chain


def _matching_targets(
    declaration: DeploymentDeclaration, targets: tuple[DeploymentTarget, ...]
) -> tuple[DeploymentTarget, ...]:
    matches: list[DeploymentTarget] = []
    for target in targets:
        if declaration.identity.matches(target.identity):
            matches.append(target)
    return tuple(matches)


def _match_basis(declaration: DeploymentDeclaration) -> list[str]:
    return declaration.identity.match_basis()


def _aws_cdk_identity(
    *, service: str, construct_id: str, deployment_name: str
) -> DeploymentIdentity:
    if service == "lambda":
        runtime_kind = "serverless_function"
        identifier_name = "function_name"
        identifier_basis = "literal_lambda_function_name"
    else:
        runtime_kind = "container_task"
        identifier_name = "container_name"
        identifier_basis = "literal_ecs_container_name"
    return DeploymentIdentity(
        provider="aws",
        runtime_kind=runtime_kind,
        identifiers=(
            DeploymentIdentifier(
                name="cloudformation_logical_id",
                value=construct_id,
                comparison=IdentifierComparison.PREFIX,
                evidence_basis="cloudformation_logical_id_prefix",
            ),
            DeploymentIdentifier(
                name=identifier_name,
                value=deployment_name,
                evidence_basis=identifier_basis,
            ),
        ),
    )


def _load_cdk_asset_manifests(
    root: Path,
) -> tuple[tuple[tuple[str, dict[str, Any]], ...], tuple[str, ...]]:
    manifests: list[tuple[str, dict[str, Any]]] = []
    warnings: list[str] = []
    candidates = sorted(
        path
        for path in root.rglob("*.assets.json")
        if not any(part in _MANIFEST_EXCLUDED_DIRS for part in path.relative_to(root).parts)
    )
    if len(candidates) > _MAX_CDK_MANIFESTS:
        warnings.append(
            f"CDK asset manifests exceed safety limit of {_MAX_CDK_MANIFESTS}"
        )
        candidates = candidates[:_MAX_CDK_MANIFESTS]
    for path in candidates:
        relative = path.relative_to(root).as_posix()
        try:
            if path.stat().st_size > _MAX_CDK_MANIFEST_BYTES:
                warnings.append(
                    f"{relative}: larger than {_MAX_CDK_MANIFEST_BYTES} bytes"
                )
                continue
            parsed = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            warnings.append(f"{relative}: {error.__class__.__name__}")
            continue
        if not isinstance(parsed, dict):
            warnings.append(f"{relative}: invalid CDK asset manifest shape")
            continue
        manifests.append((relative, parsed))
    return tuple(manifests), tuple(warnings)


def _artifact_provenance(
    target: DeploymentTarget,
    manifests: tuple[tuple[str, dict[str, Any]], ...],
    *,
    repository_revision: str,
    framework: str,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "artifact_identity_status": "not_evaluated",
        "source_revision_status": "unattested",
        "repository_revision": repository_revision,
        "source_revision_reason": (
            "The deployed artifact exposes no independently verifiable VCS revision."
        ),
    }
    if framework != "aws_cdk":
        return result
    artifact = target.evidence_payload.get("deployment_artifact")
    if not isinstance(artifact, dict) or not manifests:
        return result
    result["artifact_identity_status"] = "not_matched"
    result["artifact_identity_method"] = "cdk_asset_manifest"
    for manifest_path, manifest in manifests:
        match = _matching_manifest_asset(artifact, manifest)
        if match is None:
            continue
        asset_id, kind = match
        result.update(
            {
                "artifact_identity_status": "matched",
                "deployment_asset_id": asset_id,
                "deployment_artifact_kind": kind,
                "cdk_manifest_path": manifest_path,
            }
        )
        return result
    return result


def _matching_manifest_asset(
    artifact: dict[str, Any], manifest: dict[str, Any]
) -> tuple[str, str] | None:
    kind = artifact.get("kind")
    if kind == "s3_object":
        bucket = artifact.get("bucket")
        key = artifact.get("key")
        files = manifest.get("files")
        if not isinstance(bucket, str) or not isinstance(key, str) or not isinstance(files, dict):
            return None
        for asset_id, item in files.items():
            if not isinstance(asset_id, str) or not isinstance(item, dict):
                continue
            destinations = item.get("destinations")
            if not isinstance(destinations, dict):
                continue
            if any(
                isinstance(destination, dict)
                and destination.get("bucketName") == bucket
                and destination.get("objectKey") == key
                for destination in destinations.values()
            ):
                return asset_id, "s3_object"
        return None
    if kind == "container_image":
        image = artifact.get("image")
        parsed = _container_repository_and_tag(image) if isinstance(image, str) else None
        images = manifest.get("dockerImages")
        if parsed is None or not isinstance(images, dict):
            return None
        repository, tag = parsed
        for asset_id, item in images.items():
            if not isinstance(asset_id, str) or not isinstance(item, dict):
                continue
            destinations = item.get("destinations")
            if not isinstance(destinations, dict):
                continue
            if any(
                isinstance(destination, dict)
                and destination.get("repositoryName") == repository
                and destination.get("imageTag") == tag
                for destination in destinations.values()
            ):
                return asset_id, "container_image"
    return None


def _container_repository_and_tag(image: str) -> tuple[str, str] | None:
    path = image.split("/", 1)[-1]
    repository, separator, tag = path.rpartition(":")
    if not separator or not repository or not tag or "@" in tag:
        return None
    return repository, tag


def scan_main() -> None:
    parser = argparse.ArgumentParser(description="Correlate repository IaC to observed workloads")
    parser.add_argument("repository", type=Path)
    parser.add_argument("--name", help="canonical repository name; defaults to git remote")
    parser.add_argument("--connection-id", help="source connection id")
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        raise SystemExit("--dsn or DENALI_DSN is required")
    migrate(args.dsn)
    repository = PostgresInventoryRepository(args.dsn)
    targets = tuple(
        DeploymentTarget.from_record(item)
        for item in repository.deployment_targets(args.tenant_id)
    )
    connector = CodeToCloudConnector(args.repository, targets=targets, repository_name=args.name)
    batch = connector.collect(connection_id=args.connection_id)
    result = repository.ingest(args.tenant_id, batch)
    states = ",".join(f"{item.plane}={item.state.value}" for item in batch.coverage)
    print(
        f"Correlated {connector.repository_name}: {result['relationships']} deployments; {states}"
    )
    if batch.coverage[0].detail:
        print(f"Coverage detail: {batch.coverage[0].detail}")
