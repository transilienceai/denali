from pathlib import Path

import pytest

from denali.golden_path import GoldenPathError, load_manifest


def test_repository_golden_path_manifest_is_valid_and_exact() -> None:
    manifest = load_manifest(Path("golden-paths/code-to-cloud.yaml"))

    assert manifest["name"] == "anna-aws-summit-gcp-and-entra-discovery"
    assert {item["provider"] for item in manifest["connections"]} == {
        "aws",
        "gcp",
        "github",
    }
    assert manifest["expected"]["repositories"] == [
        "github.com/kkmookhey/anna-the-sales-agent",
        "github.com/kkmookhey/denali-gemini-demo",
    ]
    assert manifest["budgets"]["vulnerabilities"] == 3
    assert "denali.grype" not in manifest["forbidden_connectors"]
    assert "denali.syft" not in manifest["forbidden_connectors"]
    assert "denali.entra_ai" not in manifest["forbidden_connectors"]
    gcp = next(item for item in manifest["connections"] if item["provider"] == "gcp")
    assert list(gcp["boundary"]["resource_display_names"].values()) == ["Summit"]


def test_manifest_rejects_duplicate_connection_ids(tmp_path: Path) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(
        """\
version: 1
name: duplicate
connections:
  - {id: same, provider: aws, declared_scopes: []}
  - {id: same, provider: gcp, declared_scopes: []}
expected: {repositories: [], ai_workloads: [], deployed_by: []}
"""
    )

    with pytest.raises(GoldenPathError, match="unique"):
        load_manifest(path)
