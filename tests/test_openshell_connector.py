import json
from pathlib import Path

import pytest

from denali.connectors.openshell import OpenShellConnector, OpenShellImportError
from denali.domain import CoverageState


def _write_bundle(
    root: Path,
    *,
    loss_signals: list[str] | None = None,
    complete: bool = True,
    prover_result: str = "within_boundary",
    prover_domains: list[str] | None = None,
    downgraded: bool = False,
) -> Path:
    declared = """version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/bin/curl
"""
    effective = """version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /repos/**
    binaries:
      - path: /usr/bin/curl
"""
    boundary = """version: 1
network_policies:
  github:
    endpoints:
      - host: api.github.com
        port: 443
        protocol: rest
        enforcement: enforce
        access: read-only
    binaries:
      - path: /usr/bin/curl
"""
    (root / "declared-policy.yaml").write_text(declared)
    (root / "effective-policy.yaml").write_text(effective)
    (root / "boundary-policy.yaml").write_text(boundary)
    domains = prover_domains or [
        "filesystem",
        "network_l4",
        "network_rest",
        "process",
        "landlock",
    ]
    prover = {
        "schema_version": 1,
        "prover_version": "0.1.2",
        "check": "boundary",
        "coverage": {"domains": domains},
        "result": prover_result,
        "exit_code": 0 if prover_result == "within_boundary" else 3,
        "inputs": {
            "candidate": "effective-policy.yaml",
            "boundary": "boundary-policy.yaml",
        },
        "counterexample": None,
        "reason_code": "solver_timeout" if prover_result == "inconclusive" else None,
        "reason": "not retained by Denali" if prover_result == "inconclusive" else None,
    }
    (root / "prover.json").write_text(json.dumps(prover))
    common = {
        "category_uid": 4,
        "category_name": "Network Activity",
        "severity_id": 1,
        "severity": "Informational",
        "time": 1_795_000_000_000,
        "container": {"uid": "sandbox-123", "name": "review-agent"},
        "metadata": {
            "version": "1.8.0",
            "product": {
                "name": "OpenShell Sandbox Supervisor",
                "vendor_name": "NVIDIA",
                "version": "0.1.2",
            },
        },
    }
    network = {
        **common,
        "class_uid": 4001,
        "class_name": "Network Activity",
        "activity_id": 1,
        "activity_name": "Open",
        "action": "Denied",
        "status": "Failure",
        "status_detail": "no matching policy",
        "dst_endpoint": {"domain": "example.net", "port": 443},
        "actor": {"process": {"name": "/usr/bin/curl", "pid": 42}},
        "firewall_rule": {"name": "-", "type": "opa"},
        "metadata": {**common["metadata"], "uid": "event-network-1"},
    }
    if downgraded:
        network["metadata"]["version"] = "1.3"
        network["unmapped"] = {"downgraded_from": "1.8.0"}
    http = {
        **common,
        "class_uid": 4002,
        "class_name": "HTTP Activity",
        "activity_id": 3,
        "activity_name": "Get",
        "action": "Allowed",
        "status": "Success",
        "dst_endpoint": {"domain": "api.github.com", "port": 443},
        "http_request": {
            "http_method": "GET",
            "url": {
                "hostname": "api.github.com",
                "path": "/repos/private?token=do-not-retain",
            },
            "headers": [{"name": "authorization", "value": "Bearer secret"}],
        },
        "metadata": {**common["metadata"], "uid": "event-http-1"},
    }
    finding = {
        **common,
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "severity_id": 4,
        "severity": "High",
        "status": "New",
        "finding_info": {
            "uid": "openshell.provider_credential.endpoint_mismatch",
            "title": "Provider credential used at an unauthorized endpoint",
        },
        "metadata": {
            **common["metadata"],
            "uid": "event-finding-1",
            "event_code": "openshell.provider_credential.endpoint_mismatch",
        },
    }
    (root / "events.jsonl").write_text(
        "\n".join(json.dumps(item) for item in (network, http, finding)) + "\n"
    )
    manifest = {
        "schema_version": 1,
        "gateway_uid": "gateway-prod-1",
        "sandbox_uid": "sandbox-123",
        "sandbox_name": "review-agent",
        "policy_revision": "v7",
        "capture": {
            "source": "sandbox_jsonl",
            "started_at": "2026-10-04T10:00:00Z",
            "ended_at": "2026-10-04T11:00:00Z",
            "complete": complete,
            "loss_signals": loss_signals or [],
        },
        "required_prover_domains": [
            "filesystem",
            "network_l4",
            "network_rest",
            "process",
            "landlock",
        ],
        "artifacts": {
            "ocsf": "events.jsonl",
            "declared_policy": "declared-policy.yaml",
            "effective_policy": "effective-policy.yaml",
            "boundary_policy": "boundary-policy.yaml",
            "prover": "prover.json",
        },
    }
    (root / "manifest.json").write_text(json.dumps(manifest))
    return root


def test_openshell_bundle_preserves_exact_identity_provenance_and_safe_metadata(
    tmp_path: Path,
) -> None:
    evidence = OpenShellConnector().collect(_write_bundle(tmp_path))

    assert {coverage.state for coverage in evidence.activity.coverage} == {
        CoverageState.COMPLETE
    }
    assert len(evidence.activity.activities) == 2
    network, http = evidence.activity.activities
    assert network.source_uid == "event-network-1"
    assert network.entities[0].external_uid == "sandbox-123"
    assert network.entities[0].asset is not None
    assert network.entities[0].asset.natural_key == (
        "openshell:gateway-prod-1:sandbox:sandbox-123"
    )
    assert network.evidence.locator.endswith("events.jsonl#line=1")
    assert http.attributes["http_method"] == "GET"
    retained = json.dumps(
        {
            "attributes": dict(http.attributes),
            "evidence": dict(http.evidence.payload),
            "entities": [dict(item.attributes) for item in http.entities],
        }
    )
    assert "do-not-retain" not in retained
    assert "Bearer secret" not in retained

    roles = {
        asset.attributes.get("policy_role"): asset
        for asset in evidence.inventory.assets
        if asset.attributes.get("policy_role")
    }
    assert set(roles) == {"declared_policy", "effective_policy", "boundary_policy"}
    assert roles["effective_policy"].attributes["network_destinations"][0]["host"] == (
        "api.github.com"
    )
    proof = next(
        asset for asset in evidence.inventory.assets if asset.attributes.get("check") == "boundary"
    )
    assert proof.attributes["result"] == "within_boundary"
    assert proof.attributes["candidate_policy_sha256"] == roles["effective_policy"].attributes[
        "policy_sha256"
    ]
    assert evidence.findings.findings[0].evidence.locator.endswith("events.jsonl#item=3")


def test_openshell_capture_loss_and_schema_downgrade_never_claim_complete(
    tmp_path: Path,
) -> None:
    evidence = OpenShellConnector().collect(
        _write_bundle(tmp_path, loss_signals=["watch_stream_skip"], downgraded=True)
    )

    assert {coverage.state for coverage in evidence.activity.coverage} == {
        CoverageState.PARTIAL
    }
    assert "schema-downgraded" in (evidence.activity.coverage[0].detail or "")
    assert evidence.findings.coverage[0].state is CoverageState.PARTIAL


def test_openshell_inconclusive_or_missing_domain_is_partial_prover_coverage(
    tmp_path: Path,
) -> None:
    evidence = OpenShellConnector().collect(
        _write_bundle(
            tmp_path,
            prover_result="inconclusive",
            prover_domains=["filesystem", "network_l4"],
        )
    )

    coverage = next(
        item for item in evidence.inventory.coverage if item.plane == "openshell_policy_prover"
    )
    assert coverage.state is CoverageState.PARTIAL
    assert "missing required domains" in (coverage.detail or "")
    proof = next(
        asset for asset in evidence.inventory.assets if asset.attributes.get("check") == "boundary"
    )
    assert proof.attributes["result"] == "inconclusive"
    assert proof.attributes["reason_code"] == "solver_timeout"


def test_openshell_rejects_path_escape_and_sandbox_identity_contradiction(tmp_path: Path) -> None:
    _write_bundle(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"]["ocsf"] = "../events.jsonl"
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(OpenShellImportError, match="inside the bundle"):
        OpenShellConnector().collect(tmp_path)

    other = tmp_path / "other"
    other.mkdir()
    _write_bundle(other)
    events_path = other / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text().splitlines()]
    events[0]["container"]["uid"] = "another-sandbox"
    events_path.write_text("\n".join(json.dumps(item) for item in events) + "\n")
    with pytest.raises(OpenShellImportError, match="exactly the manifest sandbox"):
        OpenShellConnector().collect(other)


def test_openshell_policy_duplicate_keys_fail_closed(tmp_path: Path) -> None:
    _write_bundle(tmp_path)
    (tmp_path / "declared-policy.yaml").write_text("version: 1\nversion: 1\n")

    with pytest.raises(OpenShellImportError, match="valid bounded YAML"):
        OpenShellConnector().collect(tmp_path)
