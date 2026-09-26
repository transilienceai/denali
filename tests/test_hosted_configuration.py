from __future__ import annotations

import pytest

from denali.hosted_configuration import (
    CONFIGURATION_REQUIREMENTS,
    P0_CONFIGURATION_GROUPS,
    configuration_report,
    require_configuration,
)


def test_p0_configuration_gate_covers_core_and_every_provider() -> None:
    assert P0_CONFIGURATION_GROUPS == (
        "core",
        "aws",
        "azure",
        "entra",
        "gcp",
        "google_workspace",
        "github",
        "azure_repos",
    )


def test_configuration_report_exposes_names_but_never_values() -> None:
    environment = {
        name: f"private-value-for-{name}"
        for requirements in CONFIGURATION_REQUIREMENTS.values()
        for name in requirements
    }
    environment["DENALI_AZURE_REPOS_CALLBACK_URL"] = ""

    report = configuration_report(environment)

    assert report["azure"] == ()
    assert report["azure_repos"] == ("DENALI_AZURE_REPOS_CALLBACK_URL",)
    assert "private-value" not in repr(report)


def test_required_configuration_fails_closed_for_incomplete_or_unknown_groups() -> None:
    report = configuration_report({})

    with pytest.raises(RuntimeError, match="core,github"):
        require_configuration(report, ("core", "github"))
    with pytest.raises(ValueError, match="unknown configuration groups: typo"):
        require_configuration(report, ("typo",))
