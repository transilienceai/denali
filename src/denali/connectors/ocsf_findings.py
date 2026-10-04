"""Conservative OCSF Findings import with a Prowler-compatible profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from denali.domain import (
    AffectedResource,
    ConnectorCapabilities,
    Coverage,
    CoverageState,
    EvaluationResult,
    Evidence,
    FindingAssertion,
    FindingBatch,
    FindingSeverity,
    FindingState,
)
from denali.store.db import migrate
from denali.store.repository import PostgresInventoryRepository

CONNECTOR_ID = "denali.ocsf_findings"
CAPABILITIES = ConnectorCapabilities(findings=True)
FINDINGS_PLANE = "ocsf_findings"
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_RECORDS = 250_000

_SEVERITY_BY_ID = {
    0: FindingSeverity.UNKNOWN,
    1: FindingSeverity.INFORMATIONAL,
    2: FindingSeverity.LOW,
    3: FindingSeverity.MEDIUM,
    4: FindingSeverity.HIGH,
    5: FindingSeverity.CRITICAL,
    6: FindingSeverity.CRITICAL,
    99: FindingSeverity.UNKNOWN,
}


class OcsfImportError(ValueError):
    """A bounded import error that does not echo arbitrary source content."""


class OcsfFindingConnector:
    connector_id = CONNECTOR_ID
    capabilities = CAPABILITIES

    def collect(
        self,
        records: list[Any],
        *,
        connection_id: str,
        run_id: str,
        scope_key: str,
        source_locator: str,
        authoritative: bool = False,
        record_positions: list[int] | None = None,
    ) -> FindingBatch:
        if record_positions is not None and len(record_positions) != len(records):
            raise OcsfImportError("record_positions must match the record count")
        collected_at = datetime.now(UTC)
        findings: dict[str, FindingAssertion] = {}
        warnings: list[str] = []

        for position, record in enumerate(records):
            source_position = (
                record_positions[position] if record_positions is not None else position
            )
            try:
                finding, item_warnings = _normalize_record(
                    record,
                    position=source_position,
                    source_locator=source_locator,
                    fallback_time=collected_at,
                )
            except OcsfImportError as error:
                warnings.append(f"item {position}: {error}")
                continue
            warnings.extend(f"item {position}: {warning}" for warning in item_warnings)
            if finding.source_uid in findings:
                warnings.append(f"item {position}: duplicate finding_info.uid")
                continue
            findings[finding.source_uid] = finding

        if records and not findings:
            state = CoverageState.FAILED
        elif warnings:
            state = CoverageState.PARTIAL
        else:
            state = CoverageState.COMPLETE
        detail = "; ".join(dict.fromkeys(warnings))[:4_000] if warnings else None
        coverage = Coverage(FINDINGS_PLANE, state, scope_key, detail)
        return FindingBatch(
            connector_id=CONNECTOR_ID,
            connection_id=connection_id,
            run_id=run_id,
            scope_key=scope_key,
            collected_at=collected_at,
            coverage=(coverage,),
            findings=tuple(findings.values()),
            authoritative=authoritative,
        )


def import_main() -> None:
    parser = argparse.ArgumentParser(description="Import OCSF Findings JSON into Denali")
    parser.add_argument("path", type=Path, help="OCSF JSON array, including Prowler output")
    parser.add_argument("--connection-id", help="stable source connection id")
    parser.add_argument("--scope-key", help="explicit reconciliation scope")
    parser.add_argument(
        "--authoritative",
        action="store_true",
        help="resolve absent findings; only use for a complete, unfiltered report",
    )
    parser.add_argument(
        "--tenant-id",
        default=os.environ.get("DENALI_TENANT_ID", "00000000-0000-4000-8000-000000000001"),
    )
    parser.add_argument("--dsn", default=os.environ.get("DENALI_DSN"))
    args = parser.parse_args()
    if not args.dsn:
        raise SystemExit("--dsn or DENALI_DSN is required")

    try:
        records, digest, locator = load_ocsf_file(args.path)
        identity = derive_report_identity(
            records,
            scope_key=args.scope_key,
            connection_id=args.connection_id,
        )
    except OcsfImportError as error:
        raise SystemExit(str(error)) from error
    scope_key = identity["scope_key"]
    connection_id = identity["connection_id"]
    run_id = f"ocsf-{digest[:20]}-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S%f')}"
    batch = OcsfFindingConnector().collect(
        records,
        connection_id=connection_id,
        run_id=run_id,
        scope_key=scope_key,
        source_locator=locator,
        authoritative=args.authoritative,
    )

    migrate(args.dsn)
    result = PostgresInventoryRepository(args.dsn).ingest_findings(args.tenant_id, batch)
    state = batch.coverage[0].state.value
    print(
        f"Imported {result['findings']} OCSF findings; {result['resolved_missing']} "
        f"resolved by absence; coverage={state}"
    )
    if state in {CoverageState.PARTIAL.value, CoverageState.FAILED.value}:
        raise SystemExit(2)


def load_ocsf_file(path: Path) -> tuple[list[Any], str, str]:
    try:
        resolved = path.expanduser().resolve(strict=True)
        size = resolved.stat().st_size
    except OSError as error:
        raise OcsfImportError(f"cannot read input file ({error.__class__.__name__})") from error
    if not resolved.is_file():
        raise OcsfImportError("input path is not a regular file")
    if size > MAX_FILE_BYTES:
        raise OcsfImportError(f"input exceeds the {MAX_FILE_BYTES} byte safety limit")
    try:
        raw = resolved.read_bytes()
        decoded = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise OcsfImportError(f"invalid JSON input ({error.__class__.__name__})") from error
    if not isinstance(decoded, list):
        raise OcsfImportError("OCSF report root must be a JSON array")
    if len(decoded) > MAX_RECORDS:
        raise OcsfImportError(f"report exceeds the {MAX_RECORDS} record safety limit")
    return decoded, hashlib.sha256(raw).hexdigest(), resolved.as_uri()


def derive_report_identity(
    records: list[Any],
    *,
    scope_key: str | None = None,
    connection_id: str | None = None,
) -> dict[str, str]:
    scopes: set[tuple[str, str]] = set()
    products: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        cloud = record.get("cloud")
        cloud = cloud if isinstance(cloud, dict) else {}
        account = cloud.get("account")
        account = account if isinstance(account, dict) else {}
        provider = _text(cloud.get("provider")) or "unknown-provider"
        account_uid = _text(account.get("uid")) or "unknown-account"
        scopes.add((provider, account_uid))
        metadata = record.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        product = metadata.get("product")
        product = product if isinstance(product, dict) else {}
        products.add(_text(product.get("uid")) or _text(product.get("name")) or "ocsf")
    if len(scopes) > 1 and not scope_key:
        raise OcsfImportError("report spans multiple provider/account scopes; use --scope-key")
    if len(products) > 1 and not connection_id:
        raise OcsfImportError("report spans multiple products; use --connection-id")
    provider, account_uid = (
        next(iter(scopes)) if len(scopes) == 1 else ("multiple-providers", "multiple-accounts")
    )
    product = next(iter(products), "ocsf")
    derived_scope = f"provider={provider},account={account_uid}"
    return {
        "scope_key": scope_key or derived_scope,
        "connection_id": connection_id or f"ocsf:{product}:{provider}:{account_uid}",
    }


def _normalize_record(
    record: Any,
    *,
    position: int,
    source_locator: str,
    fallback_time: datetime,
) -> tuple[FindingAssertion, list[str]]:
    if not isinstance(record, dict):
        raise OcsfImportError("expected an object")
    class_uid = record.get("class_uid")
    if (
        not isinstance(class_uid, int)
        or isinstance(class_uid, bool)
        or not 2_000 < class_uid < 3_000
    ):
        raise OcsfImportError("class_uid is not an OCSF Findings class")
    finding_info = record.get("finding_info")
    if not isinstance(finding_info, dict):
        raise OcsfImportError("missing finding_info object")
    source_uid = _required_text(finding_info.get("uid"), "finding_info.uid", 2_048)
    metadata = record.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    product = metadata.get("product")
    product = product if isinstance(product, dict) else {}
    event_code = _text(metadata.get("event_code"), 1_000)
    title = _text(finding_info.get("title"), 1_000) or event_code or source_uid
    analytic = finding_info.get("analytic")
    analytic = analytic if isinstance(analytic, dict) else {}
    rule_uid = event_code or _text(analytic.get("uid"), 1_000)
    rule_uid = rule_uid or source_uid
    observed_at = _event_time(record, finding_info, fallback_time)
    warnings: list[str] = []
    resources, resource_warnings = _resources(record, record.get("cloud"))
    warnings.extend(resource_warnings)
    compliance, compliance_warnings = _compliance(record.get("unmapped"))
    warnings.extend(compliance_warnings)
    severity = _severity(record)
    state, result = _state_and_result(record, product)
    remediation = record.get("remediation")
    remediation = remediation if isinstance(remediation, dict) else {}
    references = _references(remediation.get("references"))
    resource_fingerprint = _fingerprint(
        [
            {
                "uid": resource.uid,
                "name": resource.name,
                "resource_type": resource.resource_type,
                "provider": resource.provider,
                "account_uid": resource.account_uid,
                "region": resource.region,
            }
            for resource in resources
        ]
    )
    compliance_fingerprint = _fingerprint(compliance)
    record_digest = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    evidence = Evidence(
        source_type="ocsf_finding",
        locator=f"{source_locator}#item={position}",
        observed_at=observed_at,
        payload={
            "record_sha256": record_digest,
            "schema_version": _text(metadata.get("version"), 64),
            "class_uid": class_uid,
            "source_uid": source_uid,
            "product_uid": _text(product.get("uid"), 256),
        },
    )
    unmapped = record.get("unmapped")
    unmapped = unmapped if isinstance(unmapped, dict) else {}
    return (
        FindingAssertion(
            source_uid=source_uid,
            rule_uid=rule_uid,
            title=title,
            description=_text(finding_info.get("desc"), 10_000),
            risk=_text(record.get("risk_details"), 10_000),
            remediation=_text(remediation.get("desc"), 10_000),
            remediation_references=references,
            severity=severity,
            state=state,
            evaluation_result=result,
            class_uid=class_uid,
            class_name=_text(record.get("class_name"), 256) or f"OCSF Finding {class_uid}",
            observed_at=observed_at,
            evidence=evidence,
            affected_resources=resources,
            compliance=compliance,
            attributes={
                "schema_version": _text(metadata.get("version"), 64),
                "product_uid": _text(product.get("uid"), 256),
                "product_name": _text(product.get("name"), 256),
                "product_vendor": _text(product.get("vendor_name"), 256),
                "product_version": _text(product.get("version"), 128),
                "event_code": event_code,
                "status": _text(record.get("status"), 128),
                "status_code": _text(record.get("status_code"), 128),
                "severity_label": _text(record.get("severity"), 128),
                "finding_types": _string_list(finding_info.get("types"), 100, 256),
                "categories": _string_list(unmapped.get("categories"), 100, 256),
                "affected_resources_sha256": resource_fingerprint,
                "compliance_sha256": compliance_fingerprint,
            },
        ),
        warnings,
    )


def _resources(
    record: dict[str, Any], cloud_value: Any
) -> tuple[tuple[AffectedResource, ...], list[str]]:
    raw_resources = record.get("resources")
    if raw_resources is None and isinstance(record.get("resource"), dict):
        raw_resources = [record["resource"]]
    if raw_resources is None:
        return (), []
    if not isinstance(raw_resources, list):
        return (), ["resources was not an array"]
    cloud = cloud_value if isinstance(cloud_value, dict) else {}
    account = cloud.get("account")
    account = account if isinstance(account, dict) else {}
    provider = _text(cloud.get("provider"), 128)
    account_uid = _text(account.get("uid"), 512)
    output: dict[str, AffectedResource] = {}
    warnings: list[str] = []
    for position, item in enumerate(raw_resources[:1_000]):
        if not isinstance(item, dict):
            warnings.append(f"resource {position} was not an object")
            continue
        uid = _text(item.get("uid"))
        if not uid:
            warnings.append(f"resource {position} had no uid")
            continue
        if len(uid) > 4_096:
            warnings.append(f"resource {position} uid exceeded the identity limit")
            continue
        if uid in output:
            warnings.append(f"resource {position} repeated a uid")
            continue
        output[uid] = AffectedResource(
            uid=uid,
            name=_text(item.get("name"), 1_000),
            resource_type=_text(item.get("type"), 512),
            provider=provider,
            account_uid=account_uid,
            region=_text(item.get("region"), 256) or _text(cloud.get("region"), 256),
        )
    if len(raw_resources) > 1_000:
        warnings.append("resources exceeded the 1000 item normalization limit")
    return tuple(output.values()), warnings


def _compliance(unmapped_value: Any) -> tuple[dict[str, tuple[str, ...]], list[str]]:
    unmapped = unmapped_value if isinstance(unmapped_value, dict) else {}
    raw = unmapped.get("compliance")
    if raw is None:
        return {}, []
    if not isinstance(raw, dict):
        return {}, ["unmapped.compliance was not an object"]
    output: dict[str, tuple[str, ...]] = {}
    warnings: list[str] = []
    for position, (framework, controls) in enumerate(raw.items()):
        if position >= 100:
            warnings.append("compliance exceeded the 100 framework normalization limit")
            break
        key = _text(framework, 512)
        values = tuple(dict.fromkeys(_string_list(controls, 500, 512)))
        if key and values:
            output[key] = values
        elif key:
            warnings.append(f"compliance framework {position} had invalid controls")
    return output, warnings


def _severity(record: dict[str, Any]) -> FindingSeverity:
    severity_id = record.get("severity_id")
    if isinstance(severity_id, int) and not isinstance(severity_id, bool):
        return _SEVERITY_BY_ID.get(severity_id, FindingSeverity.UNKNOWN)
    label = (_text(record.get("severity"), 128) or "unknown").lower()
    aliases = {
        "info": FindingSeverity.INFORMATIONAL,
        "informational": FindingSeverity.INFORMATIONAL,
        "low": FindingSeverity.LOW,
        "medium": FindingSeverity.MEDIUM,
        "high": FindingSeverity.HIGH,
        "critical": FindingSeverity.CRITICAL,
        "fatal": FindingSeverity.CRITICAL,
    }
    return aliases.get(label, FindingSeverity.UNKNOWN)


def _state_and_result(
    record: dict[str, Any], product: dict[str, Any]
) -> tuple[FindingState, EvaluationResult]:
    product_identity = " ".join(
        filter(None, (_text(product.get("uid"), 256), _text(product.get("name"), 256)))
    ).lower()
    status_code = (_text(record.get("status_code"), 128) or "").upper()
    if "prowler" in product_identity:
        if status_code == "FAIL":
            return FindingState.OPEN, EvaluationResult.FAIL
        if status_code == "PASS":
            return FindingState.RESOLVED, EvaluationResult.PASS
        if status_code == "MANUAL":
            return FindingState.UNKNOWN, EvaluationResult.MANUAL
    status = (_text(record.get("status"), 128) or "").lower().replace("_", " ")
    if status in {"new", "open", "in progress"}:
        return FindingState.OPEN, EvaluationResult.UNKNOWN
    if status in {"resolved", "closed"}:
        return FindingState.RESOLVED, EvaluationResult.UNKNOWN
    if status in {"suppressed"}:
        return FindingState.SUPPRESSED, EvaluationResult.UNKNOWN
    return FindingState.UNKNOWN, EvaluationResult.UNKNOWN


def _event_time(
    record: dict[str, Any], finding_info: dict[str, Any], fallback: datetime
) -> datetime:
    for value in (record.get("time"), finding_info.get("created_time")):
        if isinstance(value, int | float) and not isinstance(value, bool):
            seconds = value / 1_000 if value > 10_000_000_000 else value
            try:
                return datetime.fromtimestamp(seconds, UTC)
            except (OverflowError, OSError, ValueError):
                pass
    for value in (record.get("time_dt"), finding_info.get("created_time_dt")):
        text = _text(value, 128)
        if text:
            try:
                parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
                return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed
            except ValueError:
                pass
    return fallback


def _references(value: Any) -> tuple[str, ...]:
    output: list[str] = []
    for item in _string_list(value, 50, 2_048):
        parsed = urlparse(item)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            output.append(item)
    return tuple(output)


def _string_list(value: Any, limit: int, item_limit: int) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(
        text for text in (_text(item, item_limit) for item in value[:limit]) if text is not None
    )


def _required_text(value: Any, field: str, limit: int) -> str:
    text = _text(value)
    if not text:
        raise OcsfImportError(f"missing {field}")
    if len(text) > limit:
        raise OcsfImportError(f"{field} exceeded the identity limit")
    return text


def _fingerprint(value: Any) -> str:
    normalized = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(normalized.encode()).hexdigest()


def _text(value: Any, limit: int | None = None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    output = value.strip()
    return output[:limit] if limit is not None else output


if __name__ == "__main__":
    import_main()
