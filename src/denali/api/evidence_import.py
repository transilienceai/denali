"""Durable hosted import of bounded Syft and Grype evidence."""

from __future__ import annotations

import json
import logging
import re
from base64 import b64encode
from collections.abc import Mapping
from dataclasses import replace
from typing import Any, Protocol

from denali.connectors.grype_json import GrypeJsonConnector
from denali.connectors.syft_json import SyftJsonConnector
from denali.domain import AssetKind, AssetRef

logger = logging.getLogger(__name__)

MAX_REPORT_BYTES = 16 * 1024 * 1024
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class EvidenceReportStore(Protocol):
    def put_documents(
        self,
        *,
        tenant_id: str,
        job_id: str,
        documents: Mapping[str, bytes],
    ) -> dict[str, str]: ...

    def get_document(self, object_key: str) -> Any: ...

    def delete_documents(self, object_keys: tuple[str, ...]) -> None: ...

    def staged_object_keys(self, *, tenant_id: str, job_id: str) -> dict[str, str]: ...

    def create_upload(
        self,
        *,
        object_key: str,
        sha256_hex: str,
        expires_in_seconds: int,
    ) -> dict[str, Any]: ...

    def verify_upload(self, *, object_key: str, size_bytes: int, sha256_hex: str) -> None: ...


class VulnerabilityImportRepository(Protocol):
    def claim_vulnerability_import_job(
        self, job_id: str, *, lease_seconds: int
    ) -> dict[str, Any] | None: ...

    def get_asset(self, tenant_id: str, asset_id: str) -> dict[str, Any] | None: ...

    def ingest(self, tenant_id: str, batch: Any) -> dict[str, int]: ...

    def ingest_vulnerabilities(self, tenant_id: str, batch: Any) -> dict[str, int]: ...

    def evaluate_issues(self, tenant_id: str) -> dict[str, Any]: ...

    def complete_vulnerability_import_job(self, job_id: str, result: dict[str, Any]) -> None: ...

    def record_vulnerability_import_failure(
        self, job_id: str, summary: str, *, max_attempts: int
    ) -> bool: ...


class S3EvidenceReportStore:
    """Private, encrypted transient report storage for durable workers."""

    def __init__(self, bucket_name: str, *, s3_client: Any | None = None):
        if not bucket_name.strip():
            raise ValueError("evidence bucket must not be blank")
        self._bucket_name = bucket_name
        self._s3_client = s3_client or _default_s3_client()

    def put_documents(
        self,
        *,
        tenant_id: str,
        job_id: str,
        documents: Mapping[str, bytes],
    ) -> dict[str, str]:
        object_keys: dict[str, str] = {}
        uploaded: list[str] = []
        try:
            for name, body in documents.items():
                if name not in {"syft", "grype"}:
                    raise ValueError("unsupported evidence document")
                if len(body) > MAX_REPORT_BYTES:
                    raise ValueError("evidence report exceeds the hosted size limit")
                object_key = f"denali/evidence-imports/{tenant_id}/{job_id}/{name}.json"
                self._s3_client.put_object(
                    Bucket=self._bucket_name,
                    Key=object_key,
                    Body=body,
                    ContentType="application/json",
                    CacheControl="no-store",
                    ServerSideEncryption="AES256",
                )
                uploaded.append(object_key)
                object_keys[name] = object_key
        except Exception:
            self.delete_documents(tuple(uploaded))
            raise
        return object_keys

    def staged_object_keys(self, *, tenant_id: str, job_id: str) -> dict[str, str]:
        return {
            name: f"denali/evidence-imports/{tenant_id}/{job_id}/{name}.json"
            for name in ("syft", "grype")
        }

    def create_upload(
        self,
        *,
        object_key: str,
        sha256_hex: str,
        expires_in_seconds: int,
    ) -> dict[str, Any]:
        if _SHA256_HEX_RE.fullmatch(sha256_hex) is None:
            raise ValueError("evidence checksum must be a sha256 digest")
        if not 60 <= expires_in_seconds <= 900:
            raise ValueError("evidence upload lifetime must be between 60 and 900 seconds")
        checksum = b64encode(bytes.fromhex(sha256_hex)).decode("ascii")
        headers = {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
            "x-amz-server-side-encryption": "AES256",
            "x-amz-checksum-sha256": checksum,
        }
        url = self._s3_client.generate_presigned_url(
            "put_object",
            Params={
                "Bucket": self._bucket_name,
                "Key": object_key,
                "ContentType": headers["Content-Type"],
                "CacheControl": headers["Cache-Control"],
                "ServerSideEncryption": "AES256",
                "ChecksumSHA256": checksum,
            },
            ExpiresIn=expires_in_seconds,
        )
        return {"url": url, "headers": headers}

    def verify_upload(self, *, object_key: str, size_bytes: int, sha256_hex: str) -> None:
        if not 1 <= size_bytes <= MAX_REPORT_BYTES:
            raise ValueError("evidence report size is outside the hosted limit")
        if _SHA256_HEX_RE.fullmatch(sha256_hex) is None:
            raise ValueError("evidence checksum must be a sha256 digest")
        response = self._s3_client.head_object(
            Bucket=self._bucket_name,
            Key=object_key,
            ChecksumMode="ENABLED",
        )
        expected_checksum = b64encode(bytes.fromhex(sha256_hex)).decode("ascii")
        if response.get("ContentLength") != size_bytes:
            raise ValueError("staged evidence size does not match its declaration")
        if response.get("ChecksumSHA256") != expected_checksum:
            raise ValueError("staged evidence checksum does not match its declaration")

    def get_document(self, object_key: str) -> Any:
        response = self._s3_client.get_object(Bucket=self._bucket_name, Key=object_key)
        body = response["Body"].read(MAX_REPORT_BYTES + 1)
        if len(body) > MAX_REPORT_BYTES:
            raise ValueError("stored evidence report exceeds the hosted size limit")
        try:
            return json.loads(body)
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("stored evidence report is not valid JSON") from error

    def delete_documents(self, object_keys: tuple[str, ...]) -> None:
        for object_key in object_keys:
            try:
                self._s3_client.delete_object(Bucket=self._bucket_name, Key=object_key)
            except Exception:
                logger.warning(
                    "transient evidence cleanup failed",
                    extra={"object_type": object_key.rsplit("/", 1)[-1]},
                )


def encode_report(document: Any) -> bytes:
    body = json.dumps(document, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_REPORT_BYTES:
        raise ValueError("evidence report exceeds the hosted size limit")
    return body


def validate_report_pair(
    syft_document: Any,
    grype_document: Any,
    *,
    expected_image_digest: str | None = None,
) -> None:
    """Require native reports that identify the same scanned container artifact."""

    syft_descriptor = _mapping(syft_document).get("descriptor")
    grype_descriptor = _mapping(grype_document).get("descriptor")
    if str(_mapping(syft_descriptor).get("name", "")).casefold() != "syft":
        raise ValueError("the SBOM is not a native Syft JSON report")
    if str(_mapping(grype_descriptor).get("name", "")).casefold() != "grype":
        raise ValueError("the vulnerability report is not a native Grype JSON report")

    syft_source = _mapping(_mapping(syft_document).get("source"))
    grype_source = _mapping(_mapping(grype_document).get("source"))
    if (
        str(syft_source.get("type", "")).casefold() != "image"
        or str(grype_source.get("type", "")).casefold() != "image"
    ):
        raise ValueError("both reports must describe a container image")

    syft_identifiers = _syft_subject_identifiers(syft_source)
    grype_identifiers = _grype_subject_identifiers(grype_source)
    if not syft_identifiers or not grype_identifiers:
        raise ValueError("both reports must identify the scanned container image")
    if syft_identifiers.isdisjoint(grype_identifiers):
        raise ValueError("the Syft and Grype reports describe different container images")
    if expected_image_digest is not None:
        expected = expected_image_digest.strip().casefold()
        if _SHA256_HEX_RE.fullmatch(expected.removeprefix("sha256:")) is None:
            raise ValueError("the expected image digest is invalid")
        if not expected.startswith("sha256:"):
            expected = f"sha256:{expected}"
        if expected not in syft_identifiers or expected not in grype_identifiers:
            raise ValueError("the reports do not describe the cloud-observed image digest")


def run_durable_vulnerability_import_job(
    repository: VulnerabilityImportRepository,
    report_store: EvidenceReportStore,
    job_id: str,
    *,
    lease_seconds: int = 900,
    max_attempts: int = 3,
) -> None:
    """Normalize and ingest both evidence streams under a durable leased job."""

    if not 1 <= max_attempts <= 5:
        raise ValueError("import attempts must be between 1 and 5")
    object_keys: tuple[str, ...] = ()
    for _attempt in range(max_attempts):
        job = repository.claim_vulnerability_import_job(job_id, lease_seconds=lease_seconds)
        if job is None:
            return
        tenant_id = str(job["tenant_id"])
        target_asset_id = str(job["target_asset_id"])
        object_keys = (str(job["syft_object_key"]), str(job["grype_object_key"]))
        try:
            asset = repository.get_asset(tenant_id, target_asset_id)
            if asset is None or asset.get("lifecycle_state") != "active":
                raise RuntimeError("target workload is unavailable")
            if asset.get("kind") != AssetKind.AI_WORKLOAD.value:
                raise RuntimeError("target asset is not an AI workload")
            target = AssetRef(AssetKind.AI_WORKLOAD, str(asset["natural_key"]))
            target_name = str(asset.get("display_name") or asset["natural_key"])
            syft_document = report_store.get_document(object_keys[0])
            grype_document = report_store.get_document(object_keys[1])
            validate_report_pair(
                syft_document,
                grype_document,
                expected_image_digest=job.get("source_image_digest"),
            )
            scope_key = target.canonical_key
            syft_batch = SyftJsonConnector().collect(
                syft_document,
                target=target,
                target_name=target_name,
                connection_id=f"hosted-syft:{target_asset_id}",
                run_id=f"hosted-syft-{job_id}",
                scope_key=scope_key,
                source_locator=f"evidence-import://{job_id}/syft",
            )
            syft_batch = replace(
                syft_batch,
                assets=tuple(
                    assertion
                    for assertion in syft_batch.assets
                    if assertion.asset.kind is AssetKind.SOFTWARE_COMPONENT
                ),
            )
            grype_batch = GrypeJsonConnector().collect(
                grype_document,
                target=target,
                connection_id=f"hosted-grype:{target_asset_id}",
                run_id=f"hosted-grype-{job_id}",
                scope_key=scope_key,
                source_locator=f"evidence-import://{job_id}/grype",
                authoritative=bool(job["authoritative"]),
            )
            component_result = repository.ingest(tenant_id, syft_batch)
            vulnerability_result = repository.ingest_vulnerabilities(tenant_id, grype_batch)
            issue_result = repository.evaluate_issues(tenant_id)
            result = {
                "state": "complete",
                "component_count": int(component_result.get("assets", 0)),
                "vulnerability_observations": int(vulnerability_result["observations"]),
                "vulnerability_count": int(vulnerability_result["vulnerabilities"]),
                "confirmed_issue_count": int(issue_result.get("confirmed_issues", 0)),
                "issue_evaluation_state": str(
                    issue_result.get("evaluation_state", "unknown")
                ),
                "syft_coverage": syft_batch.coverage[0].state.value,
                "grype_coverage": grype_batch.coverage[0].state.value,
            }
            repository.complete_vulnerability_import_job(job_id, result)
            report_store.delete_documents(object_keys)
            return
        except Exception as error:
            error_type = type(error).__name__
            logger.warning(
                "vulnerability evidence import attempt failed (%s)",
                error_type,
                extra={
                    "tenant_id": tenant_id,
                    "job_id": job_id,
                    "target_asset_id": target_asset_id,
                    "error_type": error_type,
                },
            )
            retry = repository.record_vulnerability_import_failure(
                job_id,
                f"Evidence import could not be completed ({error_type}).",
                max_attempts=max_attempts,
            )
            if not retry:
                report_store.delete_documents(object_keys)
                return


def _default_s3_client() -> Any:
    try:
        import boto3
    except ImportError as error:  # pragma: no cover - packaging guard
        raise RuntimeError("boto3 is required for hosted evidence storage") from error
    return boto3.client("s3")


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _normalized_identifier(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().casefold()
    if normalized.startswith("docker:"):
        normalized = normalized.removeprefix("docker:")
    return normalized or None


def _identifier_tokens(value: Any) -> set[str]:
    normalized = _normalized_identifier(value)
    if normalized is None:
        return set()
    tokens = {normalized}
    if "@" in normalized:
        _name, digest = normalized.rsplit("@", 1)
        if digest:
            tokens.add(digest)
    if _SHA256_HEX_RE.fullmatch(normalized):
        tokens.add(f"sha256:{normalized}")
    return tokens


def _syft_subject_identifiers(source: Mapping[str, Any]) -> set[str]:
    identifiers = _identifier_tokens(source.get("id"))
    version = _normalized_identifier(source.get("version"))
    name = _normalized_identifier(source.get("name"))
    if version is not None:
        identifiers.update(_identifier_tokens(version))
        if name is not None:
            identifiers.update(_identifier_tokens(f"{name}@{version}"))
    elif name is not None:
        identifiers.update(_identifier_tokens(name))
    return identifiers


def _grype_subject_identifiers(source: Mapping[str, Any]) -> set[str]:
    target = source.get("target")
    values: tuple[Any, ...]
    if isinstance(target, Mapping):
        values = (
            target.get("userInput"),
            target.get("imageID"),
            target.get("manifestDigest"),
        )
    else:
        values = (target,)
    identifiers: set[str] = set()
    for value in values:
        identifiers.update(_identifier_tokens(value))
    return identifiers
