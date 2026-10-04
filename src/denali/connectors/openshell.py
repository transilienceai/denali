"""Bounded NVIDIA OpenShell evidence-bundle ingestion.

The connector consumes exported evidence; it does not call an OpenShell gateway and
never handles provider credentials.  OCSF records become immutable activity/finding
observations, while authored/effective/boundary policies and the standalone prover
result become separately attributable inventory assertions.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from denali.connectors.ocsf_findings import OcsfFindingConnector
from denali.domain import (
    ActivityBatch,
    ActivityCategory,
    ActivityCorrelation,
    ActivityEntity,
    ActivityEntityRole,
    ActivityOutcome,
    ActivityRecord,
    AssertionType,
    AssetAssertion,
    AssetKind,
    AssetRef,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    Evidence,
    FindingBatch,
    InventoryBatch,
    RelationshipAssertion,
    RelationshipKind,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.openshell"
CAPABILITIES = ConnectorCapabilities(
    findings=True, inventory=True, relationships=True, activity=True
)
MANIFEST_NAME = "manifest.json"
MANIFEST_SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 256 * 1024
MAX_POLICY_BYTES = 4 * 1024 * 1024
MAX_PROVER_BYTES = 1024 * 1024
MAX_OCSF_BYTES = 250 * 1024 * 1024
MAX_OCSF_RECORDS = 500_000
SUPPORTED_OCSF_CLASSES = frozenset({0, 1007, 2004, 4001, 4002, 4007, 5019, 6002})
ACTIVITY_CLASSES = SUPPORTED_OCSF_CLASSES - {2004}
DEFAULT_PROVER_DOMAINS = frozenset(
    {"filesystem", "network_l4", "network_rest", "process", "landlock"}
)
POLICY_ROLES = ("declared_policy", "effective_policy", "boundary_policy")
OCSF_PLANES = {
    0: "openshell_ocsf_base",
    1007: "openshell_ocsf_process",
    2004: "openshell_ocsf_findings",
    4001: "openshell_ocsf_network",
    4002: "openshell_ocsf_http",
    4007: "openshell_ocsf_ssh",
    5019: "openshell_ocsf_policy_config",
    6002: "openshell_ocsf_lifecycle",
}


class OpenShellImportError(ValueError):
    """A bounded import failure that never echoes arbitrary source content."""


class _UniqueKeyLoader(yaml.SafeLoader):
    pass


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode, deep: bool = False) -> Any:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise OpenShellImportError("policy contains a duplicate mapping key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


@dataclass(frozen=True, slots=True)
class OpenShellEvidence:
    inventory: InventoryBatch
    activity: ActivityBatch
    findings: FindingBatch


@dataclass(frozen=True, slots=True)
class _Artifact:
    name: str
    path: Path
    uri: str
    raw: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class _LoadedBundle:
    root: Path
    manifest: dict[str, Any]
    manifest_artifact: _Artifact
    artifacts: dict[str, _Artifact]
    events: tuple[dict[str, Any], ...]
    policies: dict[str, dict[str, Any]]
    prover: dict[str, Any]


class OpenShellConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def collect(
        self,
        bundle_path: Path,
        *,
        connection_id: str | None = None,
        run_id: str | None = None,
    ) -> OpenShellEvidence:
        loaded = load_bundle(bundle_path)
        collected_at = datetime.now(UTC)
        gateway_uid = _required_text(loaded.manifest.get("gateway_uid"), "gateway_uid", 512)
        sandbox_uid = _required_text(loaded.manifest.get("sandbox_uid"), "sandbox_uid", 512)
        sandbox_name = _required_text(loaded.manifest.get("sandbox_name"), "sandbox_name", 512)
        scope_key = f"gateway={gateway_uid},sandbox={sandbox_uid}"
        connection = connection_id or f"openshell:{gateway_uid}"
        identity = run_id or f"openshell-{loaded.manifest_artifact.sha256[:20]}"

        inventory = self._inventory(
            loaded,
            gateway_uid=gateway_uid,
            sandbox_uid=sandbox_uid,
            sandbox_name=sandbox_name,
            connection_id=connection,
            run_id=identity,
            scope_key=scope_key,
            collected_at=collected_at,
        )
        activity = self._activity(
            loaded,
            gateway_uid=gateway_uid,
            sandbox_uid=sandbox_uid,
            sandbox_name=sandbox_name,
            connection_id=connection,
            run_id=identity,
            scope_key=scope_key,
            collected_at=collected_at,
        )
        finding_records = [item for item in loaded.events if item.get("class_uid") == 2004]
        finding_lines = [
            position
            for position, item in enumerate(loaded.events, start=1)
            if item.get("class_uid") == 2004
        ]
        findings = OcsfFindingConnector().collect(
            finding_records,
            connection_id=connection,
            run_id=identity,
            scope_key=scope_key,
            source_locator=loaded.artifacts["ocsf"].uri,
            authoritative=False,
            record_positions=finding_lines,
        )
        finding_coverage = next(iter(findings.coverage))
        findings = FindingBatch(
            connector_id=f"{CONNECTOR_ID}.ocsf_findings",
            connection_id=findings.connection_id,
            run_id=findings.run_id,
            scope_key=findings.scope_key,
            collected_at=findings.collected_at,
            coverage=(
                Coverage(
                    "openshell_ocsf_findings",
                    _combine_coverage(_ocsf_coverage_state(loaded), finding_coverage.state),
                    scope_key,
                    _join_detail(_ocsf_coverage_detail(loaded), finding_coverage.detail),
                ),
            ),
            findings=findings.findings,
            authoritative=False,
        )
        return OpenShellEvidence(inventory=inventory, activity=activity, findings=findings)

    def _inventory(
        self,
        loaded: _LoadedBundle,
        *,
        gateway_uid: str,
        sandbox_uid: str,
        sandbox_name: str,
        connection_id: str,
        run_id: str,
        scope_key: str,
        collected_at: datetime,
    ) -> InventoryBatch:
        manifest_evidence = Evidence(
            source_type="openshell_bundle_manifest",
            locator=loaded.manifest_artifact.uri,
            observed_at=collected_at,
            payload={
                "sha256": loaded.manifest_artifact.sha256,
                "schema_version": MANIFEST_SCHEMA_VERSION,
                "gateway_uid": gateway_uid,
                "sandbox_uid": sandbox_uid,
            },
        )
        workload = AssetRef(
            AssetKind.AI_WORKLOAD, f"openshell:{gateway_uid}:sandbox:{sandbox_uid}"
        )
        assets: list[AssetAssertion] = [
            AssetAssertion(
                asset=workload,
                coverage_plane="openshell_runtime_identity",
                display_name=sandbox_name,
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                evidence=manifest_evidence,
                attributes={
                    "provider": "nvidia_openshell",
                    "gateway_uid": gateway_uid,
                    "sandbox_uid": sandbox_uid,
                    "capture_source": loaded.manifest["capture"]["source"],
                    "capture_started_at": loaded.manifest["capture"]["started_at"],
                    "capture_ended_at": loaded.manifest["capture"]["ended_at"],
                    "capture_complete": loaded.manifest["capture"]["complete"],
                    "loss_signals": loaded.manifest["capture"]["loss_signals"],
                    "policy_revision": _optional_text(
                        loaded.manifest.get("policy_revision"), 512
                    ),
                },
            )
        ]
        relationships: list[RelationshipAssertion] = []
        policy_refs: dict[str, AssetRef] = {}
        for role in POLICY_ROLES:
            artifact = loaded.artifacts[role]
            policy = loaded.policies[role]
            ref = AssetRef(
                AssetKind.AI_GUARDRAIL,
                f"openshell:{gateway_uid}:sandbox:{sandbox_uid}:{role}",
            )
            policy_refs[role] = ref
            evidence = Evidence(
                source_type="openshell_policy_yaml",
                locator=artifact.uri,
                observed_at=collected_at,
                payload={
                    "sha256": artifact.sha256,
                    "policy_role": role,
                    "policy_schema_version": policy["version"],
                },
            )
            assets.append(
                AssetAssertion(
                    asset=ref,
                    coverage_plane=f"openshell_{role}",
                    display_name=f"{sandbox_name} {role.replace('_', ' ')}",
                    assertion_type=(
                        AssertionType.DECLARED
                        if role != "effective_policy"
                        else AssertionType.OBSERVED
                    ),
                    confidence=1.0,
                    evidence=evidence,
                    attributes={
                        "provider": "nvidia_openshell",
                        "policy_role": role,
                        "policy_sha256": artifact.sha256,
                        "policy_schema_version": policy["version"],
                        "policy_revision": _optional_text(
                            loaded.manifest.get("policy_revision"), 512
                        ),
                        **_policy_summary(policy),
                    },
                )
            )
        effective = policy_refs["effective_policy"]
        relationships.append(
            RelationshipAssertion(
                source=workload,
                target=effective,
                coverage_plane="openshell_effective_policy",
                kind=RelationshipKind.PROTECTED_BY,
                assertion_type=AssertionType.OBSERVED,
                confidence=1.0,
                evidence=assets[2].evidence,
            )
        )

        prover_artifact = loaded.artifacts["prover"]
        prover = loaded.prover
        candidate_digest = loaded.artifacts["effective_policy"].sha256
        boundary_digest = loaded.artifacts["boundary_policy"].sha256
        check = AssetRef(
            AssetKind.AI_GUARDRAIL,
            (
                f"openshell:{gateway_uid}:sandbox:{sandbox_uid}:boundary-check:"
                f"{candidate_digest[:16]}:{boundary_digest[:16]}"
            ),
        )
        prover_coverage, prover_detail = _prover_coverage(loaded.manifest, prover)
        prover_evidence = Evidence(
            source_type="openshell_prover_json",
            locator=prover_artifact.uri,
            observed_at=collected_at,
            payload={
                "sha256": prover_artifact.sha256,
                "schema_version": prover["schema_version"],
                "prover_version": prover["prover_version"],
                "result": prover["result"],
                "coverage_domains": prover["coverage"]["domains"],
            },
        )
        assets.append(
            AssetAssertion(
                asset=check,
                coverage_plane="openshell_policy_prover",
                display_name=f"{sandbox_name} effective-policy boundary check",
                assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                confidence=1.0,
                evidence=prover_evidence,
                attributes={
                    "provider": "nvidia_openshell",
                    "check": "boundary",
                    "result": prover["result"],
                    "reason_code": prover.get("reason_code"),
                    "coverage_domains": prover["coverage"]["domains"],
                    "required_domains": _required_domains(loaded.manifest),
                    "prover_version": prover["prover_version"],
                    "prover_schema_version": prover["schema_version"],
                    "candidate_policy_sha256": candidate_digest,
                    "boundary_policy_sha256": boundary_digest,
                    "counterexample": _safe_counterexample(prover.get("counterexample")),
                },
            )
        )
        relationships.extend(
            (
                RelationshipAssertion(
                    source=effective,
                    target=check,
                    coverage_plane="openshell_policy_prover",
                    kind=RelationshipKind.DEPENDS_ON,
                    assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                    confidence=1.0,
                    evidence=prover_evidence,
                    attributes={"role": "candidate"},
                ),
                RelationshipAssertion(
                    source=check,
                    target=policy_refs["boundary_policy"],
                    coverage_plane="openshell_policy_prover",
                    kind=RelationshipKind.DEPENDS_ON,
                    assertion_type=AssertionType.EXTERNALLY_VERIFIED,
                    confidence=1.0,
                    evidence=prover_evidence,
                    attributes={"role": "boundary"},
                ),
            )
        )
        coverage = [
            Coverage("openshell_runtime_identity", CoverageState.COMPLETE, scope_key),
            *(
                Coverage(f"openshell_{role}", CoverageState.COMPLETE, scope_key)
                for role in POLICY_ROLES
            ),
            Coverage("openshell_policy_prover", prover_coverage, scope_key, prover_detail),
        ]
        return InventoryBatch(
            connector_id=f"{CONNECTOR_ID}.policy",
            connection_id=connection_id,
            run_id=run_id,
            scope_key=scope_key,
            collected_at=collected_at,
            coverage=tuple(coverage),
            assets=tuple(assets),
            relationships=tuple(relationships),
        )

    def _activity(
        self,
        loaded: _LoadedBundle,
        *,
        gateway_uid: str,
        sandbox_uid: str,
        sandbox_name: str,
        connection_id: str,
        run_id: str,
        scope_key: str,
        collected_at: datetime,
    ) -> ActivityBatch:
        workload = AssetRef(
            AssetKind.AI_WORKLOAD, f"openshell:{gateway_uid}:sandbox:{sandbox_uid}"
        )
        activities: list[ActivityRecord] = []
        warnings: list[str] = []
        ocsf_artifact = loaded.artifacts["ocsf"]
        for line_number, record in enumerate(loaded.events, start=1):
            class_uid = record.get("class_uid")
            if class_uid == 2004:
                continue
            try:
                activities.append(
                    _activity_record(
                        record,
                        line_number=line_number,
                        source=ocsf_artifact,
                        observed_at=collected_at,
                        sandbox_uid=sandbox_uid,
                        sandbox_name=sandbox_name,
                        workload=workload,
                    )
                )
            except OpenShellImportError as error:
                warnings.append(f"line {line_number}: {error}")
        capture_state = _ocsf_coverage_state(loaded)
        if loaded.events and not activities and not any(
            item.get("class_uid") == 2004 for item in loaded.events
        ):
            capture_state = CoverageState.FAILED
        elif warnings and capture_state is CoverageState.COMPLETE:
            capture_state = CoverageState.PARTIAL
        detail = _join_detail(_ocsf_coverage_detail(loaded), "; ".join(warnings[:20]))
        coverage = tuple(
            Coverage(plane, capture_state, scope_key, detail)
            for uid, plane in OCSF_PLANES.items()
            if uid != 2004
        )
        return ActivityBatch(
            connector_id=f"{CONNECTOR_ID}.ocsf_activity",
            connection_id=connection_id,
            run_id=run_id,
            scope_key=scope_key,
            collected_at=collected_at,
            coverage=coverage,
            activities=tuple(activities),
        )


def load_bundle(path: Path) -> _LoadedBundle:
    try:
        root = path.expanduser().resolve(strict=True)
    except OSError as error:
        raise OpenShellImportError("cannot read bundle directory") from error
    if not root.is_dir():
        raise OpenShellImportError("bundle path must be a directory")
    manifest_artifact = _read_artifact(root, MANIFEST_NAME, MAX_MANIFEST_BYTES)
    manifest = _decode_json_object(manifest_artifact.raw, "manifest")
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise OpenShellImportError("unsupported manifest schema_version")
    artifacts_value = manifest.get("artifacts")
    if not isinstance(artifacts_value, dict):
        raise OpenShellImportError("manifest artifacts must be an object")
    required = {"ocsf", "prover", *POLICY_ROLES}
    if set(artifacts_value) != required:
        raise OpenShellImportError("manifest artifacts must contain exactly the supported roles")
    limits = {
        "ocsf": MAX_OCSF_BYTES,
        "prover": MAX_PROVER_BYTES,
        "declared_policy": MAX_POLICY_BYTES,
        "effective_policy": MAX_POLICY_BYTES,
        "boundary_policy": MAX_POLICY_BYTES,
    }
    artifacts: dict[str, _Artifact] = {}
    for role in sorted(required):
        name = _required_text(artifacts_value.get(role), f"artifacts.{role}", 512)
        artifacts[role] = _read_artifact(root, name, limits[role])
    events = _decode_jsonl(artifacts["ocsf"])
    policies = {
        role: _decode_policy(artifacts[role].raw, role) for role in POLICY_ROLES
    }
    prover = _decode_prover(artifacts["prover"].raw)
    _validate_manifest(manifest, events)
    _validate_prover_inputs(prover, artifacts)
    return _LoadedBundle(
        root=root,
        manifest=manifest,
        manifest_artifact=manifest_artifact,
        artifacts=artifacts,
        events=events,
        policies=policies,
        prover=prover,
    )


def import_main() -> None:
    parser = argparse.ArgumentParser(description="Import an NVIDIA OpenShell evidence bundle")
    parser.add_argument("bundle", type=Path, help="directory containing manifest.json")
    parser.add_argument("--connection-id", help="stable OpenShell gateway connection id")
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        raise SystemExit("--dsn or DENALI_DSN is required")
    try:
        evidence = OpenShellConnector().collect(
            args.bundle, connection_id=args.connection_id
        )
    except OpenShellImportError as error:
        raise SystemExit(str(error)) from error
    migrate(args.dsn)
    repository = PostgresInventoryRepository(args.dsn)
    inventory = repository.ingest(args.tenant_id, evidence.inventory)
    activity = repository.ingest_activity(args.tenant_id, evidence.activity)
    findings = repository.ingest_findings(args.tenant_id, evidence.findings)
    states = {
        coverage.state.value
        for batch in (evidence.inventory, evidence.activity, evidence.findings)
        for coverage in batch.coverage
    }
    print(
        f"Imported {inventory['assets']} OpenShell assets, "
        f"{activity['activities']} activities, and {findings['findings']} findings; "
        f"coverage={','.join(sorted(states))}"
    )
    if CoverageState.FAILED.value in states:
        raise SystemExit(2)


def _read_artifact(root: Path, name: str, limit: int) -> _Artifact:
    candidate = Path(name)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise OpenShellImportError("artifact path must remain inside the bundle")
    try:
        resolved = (root / candidate).resolve(strict=True)
        resolved.relative_to(root)
        size = resolved.stat().st_size
    except (OSError, ValueError) as error:
        raise OpenShellImportError("cannot read bundle artifact") from error
    if not resolved.is_file():
        raise OpenShellImportError("bundle artifact is not a regular file")
    if size > limit:
        raise OpenShellImportError("bundle artifact exceeds its safety limit")
    try:
        raw = resolved.read_bytes()
    except OSError as error:
        raise OpenShellImportError("cannot read bundle artifact") from error
    return _Artifact(name, resolved, resolved.as_uri(), raw, hashlib.sha256(raw).hexdigest())


def _decode_json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OpenShellImportError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise OpenShellImportError(f"{label} root must be an object")
    return value


def _decode_jsonl(artifact: _Artifact) -> tuple[dict[str, Any], ...]:
    try:
        text = artifact.raw.decode()
    except UnicodeDecodeError as error:
        raise OpenShellImportError("OCSF JSONL is not UTF-8") from error
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if len(records) >= MAX_OCSF_RECORDS:
            raise OpenShellImportError("OCSF JSONL exceeds the record safety limit")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise OpenShellImportError(f"OCSF line {line_number} is not valid JSON") from error
        if not isinstance(record, dict):
            raise OpenShellImportError(f"OCSF line {line_number} is not an object")
        class_uid = record.get("class_uid")
        if class_uid not in SUPPORTED_OCSF_CLASSES:
            raise OpenShellImportError(f"OCSF line {line_number} has an unsupported class_uid")
        records.append(record)
    return tuple(records)


def _decode_policy(raw: bytes, role: str) -> dict[str, Any]:
    try:
        value = yaml.load(raw.decode(), Loader=_UniqueKeyLoader)
    except (UnicodeDecodeError, yaml.YAMLError, OpenShellImportError) as error:
        raise OpenShellImportError(f"{role} is not valid bounded YAML") from error
    if not isinstance(value, dict) or value.get("version") != 1:
        raise OpenShellImportError(f"{role} must be an OpenShell version 1 policy")
    if any(not isinstance(key, str) for key in value):
        raise OpenShellImportError(f"{role} contains a non-string root key")
    return value


def _decode_prover(raw: bytes) -> dict[str, Any]:
    value = _decode_json_object(raw, "prover result")
    if value.get("schema_version") != 1 or value.get("check") != "boundary":
        raise OpenShellImportError("unsupported prover result contract")
    if value.get("result") not in {
        "within_boundary",
        "exceeds_boundary",
        "unsupported",
        "inconclusive",
        "error",
    }:
        raise OpenShellImportError("prover result has an unknown result")
    if not _optional_text(value.get("prover_version"), 128):
        raise OpenShellImportError("prover result is missing prover_version")
    coverage = value.get("coverage")
    if not isinstance(coverage, dict) or not isinstance(coverage.get("domains"), list):
        raise OpenShellImportError("prover result is missing coverage.domains")
    domains = coverage["domains"]
    if any(not isinstance(item, str) or not item.strip() for item in domains):
        raise OpenShellImportError("prover coverage domains are invalid")
    if len(domains) != len(set(domains)):
        raise OpenShellImportError("prover coverage repeats a domain")
    return value


def _validate_manifest(manifest: dict[str, Any], events: tuple[dict[str, Any], ...]) -> None:
    capture = manifest.get("capture")
    if not isinstance(capture, dict):
        raise OpenShellImportError("manifest capture must be an object")
    if capture.get("source") not in {"sandbox_jsonl", "gateway_jsonl", "mxc_jsonl"}:
        raise OpenShellImportError("manifest capture source is unsupported")
    if not isinstance(capture.get("complete"), bool):
        raise OpenShellImportError("manifest capture.complete must be boolean")
    loss = capture.get("loss_signals")
    if not isinstance(loss, list) or any(not isinstance(item, str) for item in loss):
        raise OpenShellImportError("manifest capture.loss_signals must be a string array")
    started = _parse_time(capture.get("started_at"), "capture.started_at")
    ended = _parse_time(capture.get("ended_at"), "capture.ended_at")
    if ended < started:
        raise OpenShellImportError("capture ended_at precedes started_at")
    _required_text(manifest.get("gateway_uid"), "gateway_uid", 512)
    sandbox_uid = _required_text(manifest.get("sandbox_uid"), "sandbox_uid", 512)
    _required_text(manifest.get("sandbox_name"), "sandbox_name", 512)
    _required_domains(manifest)
    observed_containers = {
        _optional_text(record.get("container", {}).get("uid"), 512)
        for record in events
        if isinstance(record.get("container"), dict)
        and _optional_text(record.get("container", {}).get("uid"), 512)
    }
    if observed_containers and observed_containers != {sandbox_uid}:
        raise OpenShellImportError("OCSF records do not resolve to exactly the manifest sandbox")


def _validate_prover_inputs(prover: dict[str, Any], artifacts: dict[str, _Artifact]) -> None:
    inputs = prover.get("inputs")
    if not isinstance(inputs, dict):
        raise OpenShellImportError("prover result is missing input provenance")
    candidate = _optional_text(inputs.get("candidate"), 4096)
    boundary = _optional_text(inputs.get("boundary"), 4096)
    if not candidate or not boundary:
        raise OpenShellImportError("prover result has incomplete input provenance")
    # Paths can differ across collection hosts. The bundle manifest, artifact digests,
    # and the prover's named inputs are all retained; a path name is never treated as
    # a cryptographic binding.
    if Path(candidate).name != Path(artifacts["effective_policy"].name).name:
        raise OpenShellImportError("prover candidate does not name the effective policy artifact")
    if Path(boundary).name != Path(artifacts["boundary_policy"].name).name:
        raise OpenShellImportError("prover boundary does not name the boundary policy artifact")


def _capture_state(manifest: dict[str, Any]) -> CoverageState:
    capture = manifest["capture"]
    if not capture["complete"] or capture["loss_signals"]:
        return CoverageState.PARTIAL
    return CoverageState.COMPLETE


def _capture_detail(manifest: dict[str, Any]) -> str | None:
    capture = manifest["capture"]
    details: list[str] = []
    if not capture["complete"]:
        details.append("capture manifest does not attest a complete interval")
    if capture["loss_signals"]:
        details.append("loss signals: " + ",".join(sorted(set(capture["loss_signals"]))))
    return "; ".join(details) or None


def _ocsf_coverage_state(loaded: _LoadedBundle) -> CoverageState:
    if _capture_state(loaded.manifest) is not CoverageState.COMPLETE:
        return CoverageState.PARTIAL
    for record in loaded.events:
        metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        container = record.get("container") if isinstance(record.get("container"), dict) else {}
        unmapped = record.get("unmapped") if isinstance(record.get("unmapped"), dict) else {}
        if (
            not _optional_text(metadata.get("uid"), 2048)
            or not _optional_text(container.get("uid"), 512)
            or unmapped.get("downgraded_from")
            or metadata.get("version") != "1.8.0"
        ):
            return CoverageState.PARTIAL
    return CoverageState.COMPLETE


def _ocsf_coverage_detail(loaded: _LoadedBundle) -> str | None:
    details = [_capture_detail(loaded.manifest)]
    if any(
        isinstance(record.get("unmapped"), dict)
        and record["unmapped"].get("downgraded_from")
        for record in loaded.events
    ):
        details.append("OCSF export was schema-downgraded and is lossy")
    if any(
        not isinstance(record.get("metadata"), dict)
        or not _optional_text(record["metadata"].get("uid"), 2048)
        for record in loaded.events
    ):
        details.append("one or more OCSF records lack metadata.uid provenance")
    if any(
        not isinstance(record.get("container"), dict)
        or not _optional_text(record["container"].get("uid"), 512)
        for record in loaded.events
    ):
        details.append("one or more OCSF records lack container.uid runtime identity")
    versions = sorted(
        {
            str(record.get("metadata", {}).get("version"))
            for record in loaded.events
            if isinstance(record.get("metadata"), dict)
            and record.get("metadata", {}).get("version") != "1.8.0"
        }
    )
    if versions:
        details.append("non-native OCSF schema versions: " + ",".join(versions))
    return _join_detail(*details)


def _prover_coverage(
    manifest: dict[str, Any], prover: dict[str, Any]
) -> tuple[CoverageState, str | None]:
    required = set(_required_domains(manifest))
    observed = set(prover["coverage"]["domains"])
    missing = sorted(required - observed)
    result = prover["result"]
    detail: list[str] = []
    if missing:
        detail.append("missing required domains: " + ",".join(missing))
    if result == "unsupported":
        state = CoverageState.NOT_SUPPORTED
    elif result in {"inconclusive", "error"} or missing:
        state = CoverageState.PARTIAL
    else:
        state = CoverageState.COMPLETE
    if result in {"unsupported", "inconclusive", "error"}:
        detail.append(f"prover result={result}")
        reason_code = _optional_text(prover.get("reason_code"), 256)
        if reason_code:
            detail.append(f"reason_code={reason_code}")
    return state, "; ".join(detail) or None


def _activity_record(
    record: dict[str, Any],
    *,
    line_number: int,
    source: _Artifact,
    observed_at: datetime,
    sandbox_uid: str,
    sandbox_name: str,
    workload: AssetRef,
) -> ActivityRecord:
    class_uid = record.get("class_uid")
    if class_uid not in ACTIVITY_CLASSES:
        raise OpenShellImportError("record is not a supported activity class")
    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    source_uid = _optional_text(metadata.get("uid"), 2048)
    if not source_uid:
        raise OpenShellImportError("record is missing metadata.uid")
    container = record.get("container") if isinstance(record.get("container"), dict) else {}
    record_sandbox = _optional_text(container.get("uid"), 512)
    if record_sandbox and record_sandbox != sandbox_uid:
        raise OpenShellImportError("record container.uid does not match the manifest")
    occurred_at = _event_time(record)
    action = (_optional_text(record.get("action"), 128) or "").casefold()
    status = (_optional_text(record.get("status"), 128) or "").casefold()
    outcome = (
        ActivityOutcome.FAILURE
        if action in {"denied", "blocked"} or status in {"failure", "error"}
        else ActivityOutcome.SUCCESS
        if action in {"allowed"} or status in {"success"}
        else ActivityOutcome.UNKNOWN
    )
    category = (
        ActivityCategory.DATA_ACCESS
        if class_uid in {4001, 4002, 4007}
        else ActivityCategory.ADMIN_CHANGE
        if class_uid == 5019
        else ActivityCategory.OTHER
    )
    dst = record.get("dst_endpoint") if isinstance(record.get("dst_endpoint"), dict) else {}
    domain = _optional_text(dst.get("domain"), 512)
    ip = _optional_text(dst.get("ip"), 128)
    port = dst.get("port") if isinstance(dst.get("port"), int) else None
    process = record.get("actor") if isinstance(record.get("actor"), dict) else {}
    process = process.get("process") if isinstance(process.get("process"), dict) else {}
    process_name = _optional_text(process.get("name"), 1024)
    pid = process.get("pid") if isinstance(process.get("pid"), int) else None
    entities: list[ActivityEntity] = [
        ActivityEntity(
            role=ActivityEntityRole.WORKLOAD,
            external_uid=sandbox_uid,
            display_name=sandbox_name,
            asset=workload,
            correlation=ActivityCorrelation.EXACT_IDENTIFIER,
            confidence=1.0,
        )
    ]
    destination = domain or ip
    if destination:
        destination_uid = f"{destination}:{port}" if port is not None else destination
        entities.append(
            ActivityEntity(
                role=ActivityEntityRole.RESOURCE,
                external_uid=destination_uid,
                display_name=destination_uid,
            )
        )
    if process_name:
        process_uid = f"{sandbox_uid}:process:{pid}:{process_name}"
        entities.append(
            ActivityEntity(
                role=ActivityEntityRole.ACTOR,
                external_uid=process_uid,
                display_name=process_name,
                attributes={"pid": pid} if pid is not None else {},
            )
        )
    request = record.get("http_request") if isinstance(record.get("http_request"), dict) else {}
    response = record.get("http_response") if isinstance(record.get("http_response"), dict) else {}
    firewall = record.get("firewall_rule") if isinstance(record.get("firewall_rule"), dict) else {}
    unmapped = record.get("unmapped") if isinstance(record.get("unmapped"), dict) else {}
    schema_version = _optional_text(metadata.get("version"), 64)
    digest = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    safe_attributes = {
        "ocsf_class_uid": class_uid,
        "ocsf_class_name": _optional_text(record.get("class_name"), 256),
        "ocsf_activity_id": record.get("activity_id"),
        "ocsf_activity_name": _optional_text(record.get("activity_name"), 256),
        "ocsf_schema_version": schema_version,
        "action": _optional_text(record.get("action"), 128),
        "disposition": _optional_text(record.get("disposition"), 128),
        "status": _optional_text(record.get("status"), 128),
        "status_detail": _optional_text(record.get("status_detail"), 512),
        "destination_domain": domain,
        "destination_ip": ip,
        "destination_port": port,
        "process_name": process_name,
        "process_pid": pid,
        "policy_name": _optional_text(firewall.get("name"), 512),
        "policy_engine": _optional_text(firewall.get("type"), 128),
        "http_method": _optional_text(request.get("http_method"), 64),
        "http_status_code": response.get("code") if isinstance(response.get("code"), int) else None,
        "credential_binding_event": firewall.get("type") == "credential-binding",
        "policy_generation": _safe_integer(unmapped.get("policy_generation")),
        "mapping_generation": _safe_integer(unmapped.get("mapping_generation")),
        "chunk_id": _optional_text(unmapped.get("chunk_id"), 512),
        "policy_state": _optional_text(record.get("state"), 128),
        "policy_state_id": record.get("state_id")
        if isinstance(record.get("state_id"), int)
        else None,
    }
    attributes = {key: value for key, value in safe_attributes.items() if value is not None}
    product = metadata.get("product") if isinstance(metadata.get("product"), dict) else {}
    evidence = Evidence(
        source_type="openshell_ocsf_jsonl",
        locator=f"{source.uri}#line={line_number}",
        observed_at=observed_at,
        payload={
            "record_sha256": digest,
            "file_sha256": source.sha256,
            "metadata_uid": source_uid,
            "class_uid": class_uid,
            "schema_version": schema_version,
            "product_name": _optional_text(product.get("name"), 256),
            "product_version": _optional_text(product.get("version"), 128),
            "downgraded_from": _optional_text(unmapped.get("downgraded_from"), 64),
        },
    )
    return ActivityRecord(
        source_uid=source_uid,
        category=category,
        activity_name=f"openshell.ocsf.{class_uid}.{record.get('activity_id', 0)}",
        title=_activity_title(record, class_uid),
        occurred_at=occurred_at,
        observed_at=observed_at,
        outcome=outcome,
        provider="nvidia_openshell",
        session_uid=sandbox_uid,
        telemetry_convention=f"ocsf/{schema_version or 'unknown'}",
        content_policy="metadata_only",
        entities=tuple(entities),
        evidence=evidence,
        attributes=attributes,
    )


def _policy_summary(policy: dict[str, Any]) -> dict[str, Any]:
    network = policy.get("network_policies")
    network = network if isinstance(network, dict) else {}
    destinations: list[dict[str, Any]] = []
    binaries: set[str] = set()
    tools: set[str] = set()
    for name, raw_rule in list(network.items())[:2_000]:
        if not isinstance(name, str) or not isinstance(raw_rule, dict):
            continue
        for raw_binary in _bounded_list(raw_rule.get("binaries"), 2_000):
            if isinstance(raw_binary, dict):
                binary = _optional_text(raw_binary.get("path"), 1024)
                if binary:
                    binaries.add(binary)
        for endpoint in _bounded_list(raw_rule.get("endpoints"), 2_000):
            if not isinstance(endpoint, dict):
                continue
            host = _optional_text(endpoint.get("host"), 512)
            protocol = _optional_text(endpoint.get("protocol"), 64) or "tcp"
            port = endpoint.get("port") if isinstance(endpoint.get("port"), int) else None
            ports = [
                item
                for item in _bounded_list(endpoint.get("ports"), 100)
                if isinstance(item, int)
            ]
            credential = endpoint.get("credential_binding")
            credentialed = isinstance(credential, dict) or any(
                endpoint.get(key) is True
                for key in ("request_body_credential_rewrite", "websocket_credential_rewrite")
            ) or isinstance(endpoint.get("credential_signing"), str)
            methods: set[str] = set()
            for rule in _bounded_list(endpoint.get("rules"), 2_000):
                if not isinstance(rule, dict):
                    continue
                allow = rule.get("allow") if isinstance(rule.get("allow"), dict) else {}
                method = _optional_text(allow.get("method"), 128)
                if method:
                    methods.add(method)
                tool = allow.get("tool") or (
                    allow.get("params", {}).get("name")
                    if isinstance(allow.get("params"), dict)
                    else None
                )
                tools.update(_matchers(tool))
            destinations.append(
                {
                    "policy_name": name,
                    "host": host,
                    "port": port,
                    "ports": ports,
                    "protocol": protocol,
                    "enforcement": _optional_text(endpoint.get("enforcement"), 64),
                    "access": _optional_text(endpoint.get("access"), 64),
                    "credentialed": credentialed,
                    "methods": sorted(methods),
                }
            )
    filesystem = policy.get("filesystem_policy")
    filesystem = filesystem if isinstance(filesystem, dict) else {}
    process = policy.get("process")
    process = process if isinstance(process, dict) else policy.get("process_policy")
    process = process if isinstance(process, dict) else {}
    return {
        "network_destinations": destinations,
        "network_binaries": sorted(binaries),
        "declared_tool_names": sorted(tools),
        "network_policy_count": len(network),
        "filesystem_policy_present": "filesystem_policy" in policy,
        "filesystem_read_only_count": len(_bounded_list(filesystem.get("read_only"), 10_000)),
        "filesystem_read_write_count": len(_bounded_list(filesystem.get("read_write"), 10_000)),
        "run_as_user": _optional_text(process.get("run_as_user"), 256),
        "run_as_group": _optional_text(process.get("run_as_group"), 256),
    }


def _safe_counterexample(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    allowed = {
        "domain",
        "field",
        "boundary",
        "candidate",
        "access",
        "path",
        "binary",
        "ancestor_binary",
        "binary_identity_required",
        "host",
        "destination_ip",
        "trusted_gateway",
        "port",
        "protocol",
        "method",
    }
    output: dict[str, Any] = {}
    for key, item in value.items():
        if key not in allowed:
            continue
        if isinstance(item, str):
            output[key] = item[:2048]
        elif isinstance(item, bool | int | float) or item is None:
            output[key] = item
    return output


def _required_domains(manifest: dict[str, Any]) -> list[str]:
    value = manifest.get("required_prover_domains", sorted(DEFAULT_PROVER_DOMAINS))
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(item, str) or not item.strip() for item in value)
    ):
        raise OpenShellImportError("required_prover_domains must be a non-empty string array")
    result = [item.strip() for item in value]
    if len(result) != len(set(result)):
        raise OpenShellImportError("required_prover_domains contains duplicates")
    return result


def _event_time(record: dict[str, Any]) -> datetime:
    value = record.get("time")
    if isinstance(value, int | float) and not isinstance(value, bool):
        seconds = value / 1_000 if value > 10_000_000_000 else value
        try:
            return datetime.fromtimestamp(seconds, UTC)
        except (OverflowError, OSError, ValueError):
            pass
    value = record.get("time_dt")
    return _parse_time(value, "OCSF event time")


def _parse_time(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise OpenShellImportError(f"{label} must be an ISO-8601 timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise OpenShellImportError(f"{label} must be an ISO-8601 timestamp") from error
    if result.tzinfo is None:
        raise OpenShellImportError(f"{label} must include a timezone")
    return result


def _activity_title(record: dict[str, Any], class_uid: int) -> str:
    class_name = _optional_text(record.get("class_name"), 256) or OCSF_PLANES[class_uid]
    activity_name = _optional_text(record.get("activity_name"), 256) or "Observed"
    return f"OpenShell {class_name}: {activity_name}"


def _combine_coverage(left: CoverageState, right: CoverageState) -> CoverageState:
    order = {
        CoverageState.FAILED: 0,
        CoverageState.NOT_SUPPORTED: 1,
        CoverageState.UNKNOWN: 2,
        CoverageState.PARTIAL: 3,
        CoverageState.COMPLETE: 4,
    }
    return left if order[left] <= order[right] else right


def _join_detail(*parts: str | None) -> str | None:
    output = "; ".join(part for part in parts if part)
    return output[:4_000] or None


def _required_text(value: Any, label: str, limit: int) -> str:
    result = _optional_text(value, limit)
    if not result:
        raise OpenShellImportError(f"manifest {label} is missing or invalid")
    return result


def _optional_text(value: Any, limit: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    output = value.strip()
    return output if len(output) <= limit else output[:limit]


def _safe_integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _bounded_list(value: Any, limit: int) -> list[Any]:
    return value[:limit] if isinstance(value, list) else []


def _matchers(value: Any) -> set[str]:
    if isinstance(value, str) and value.strip():
        return {value.strip()[:512]}
    if isinstance(value, dict):
        any_value = value.get("any")
        if isinstance(any_value, list):
            return {
                item.strip()[:512]
                for item in any_value[:1_000]
                if isinstance(item, str) and item.strip()
            }
    return set()


if __name__ == "__main__":
    import_main()
