from __future__ import annotations

import pytest

from denali.hosted_configuration import (
    CONFIGURATION_REQUIREMENTS,
    P0_CONFIGURATION_GROUPS,
    configuration_report,
    require_configuration,
)


@pytest.mark.parametrize(
    ("present", "missing"),
    [
        (
            "DENALI_GCP_NATIVE_WORKLOAD_IDENTITY_PROVIDER",
            "DENALI_GCP_NATIVE_RUNTIME_SERVICE_ACCOUNT",
        ),
        (
            "DENALI_GCP_NATIVE_RUNTIME_SERVICE_ACCOUNT",
            "DENALI_GCP_NATIVE_WORKLOAD_IDENTITY_PROVIDER",
        ),
    ],
)
def test_optional_native_gcp_identity_requires_the_complete_pair(present, missing) -> None:
    environment = {
        name: "configured"
        for requirements in CONFIGURATION_REQUIREMENTS.values()
        for name in requirements
    }
    environment[present] = "private-test-value"
    environment[missing] = "   "

    report = configuration_report(environment)

    assert report["gcp"] == (missing,)
    assert report["google_workspace"] == ()
    assert "private-test-value" not in repr(report)
    with pytest.raises(RuntimeError, match="gcp"):
        require_configuration(report, ("gcp",))


def test_complete_optional_native_gcp_identity_preserves_existing_groups() -> None:
    environment = {
        name: "configured"
        for requirements in CONFIGURATION_REQUIREMENTS.values()
        for name in requirements
    }
    environment.update(
        {
            "DENALI_GCP_NATIVE_WORKLOAD_IDENTITY_PROVIDER": "configured",
            "DENALI_GCP_NATIVE_RUNTIME_SERVICE_ACCOUNT": "configured",
        }
    )

    report = configuration_report(environment)

    assert tuple(report) == P0_CONFIGURATION_GROUPS
    assert all(not missing for missing in report.values())


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
