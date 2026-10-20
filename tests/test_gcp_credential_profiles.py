"""Native GCP operator isolation never repoints the shared Google ADC identity."""

from __future__ import annotations

import os
from copy import deepcopy

import pytest

from denali.connections import gcp, gcp_credentials

PROVIDER_KEY = "DENALI_GCP_NATIVE_WORKLOAD_IDENTITY_PROVIDER"
RUNTIME_KEY = "DENALI_GCP_NATIVE_RUNTIME_SERVICE_ACCOUNT"
PROFILE = "native_gcp_wif_v1"
PROVIDER = (
    "projects/123456789012/locations/global/workloadIdentityPools/"
    "native-production/providers/modal-production"
)
RUNTIME = "native-runtime@native-operator.iam.gserviceaccount.com"
READER = "denali-reader@native-operator.iam.gserviceaccount.com"


@pytest.fixture(autouse=True)
def isolated_google_environment(monkeypatch):
    for key in (PROVIDER_KEY, RUNTIME_KEY, "MODAL_IDENTITY_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("DENALI_GCP_OPERATOR_PROJECT_ID", "native-operator")
    # A test must explicitly stub every legacy ADC acquisition it intends to use.
    import google.auth

    monkeypatch.setattr(
        google.auth,
        "default",
        lambda **_kwargs: pytest.fail("unexpected legacy ADC acquisition"),
    )


def configure_native(monkeypatch):
    monkeypatch.setenv(PROVIDER_KEY, PROVIDER)
    monkeypatch.setenv(RUNTIME_KEY, RUNTIME)
    monkeypatch.setenv("MODAL_IDENTITY_TOKEN", "synthetic-modal-identity-one")


def marked_reference(**updates):
    return {
        "principal_email": READER,
        "principal_unique_id": "123456789012345678901",
        "operator_project_id": "native-operator",
        "operator_credential_profile": PROFILE,
        **updates,
    }


def test_native_profile_is_opt_in_and_retains_the_versioned_marker(monkeypatch):
    assert gcp_credentials.NATIVE_GCP_CREDENTIAL_PROFILE == PROFILE
    assert gcp_credentials.native_gcp_profile_from_environment() is None
    configure_native(monkeypatch)
    assert gcp_credentials.native_gcp_profile_from_environment() == PROFILE


@pytest.mark.parametrize(
    "key,value",
    [
        (PROVIDER_KEY, None),
        (RUNTIME_KEY, None),
        (
            PROVIDER_KEY,
            "projects/not-a-number/locations/global/workloadIdentityPools/p/providers/p",
        ),
        (PROVIDER_KEY, "https://untrusted.example.test/provider"),
        (RUNTIME_KEY, "not-a-service-account"),
        (RUNTIME_KEY, "native-runtime@untrusted.example.test"),
    ],
)
def test_explicit_invalid_native_configuration_never_falls_back_to_adc(monkeypatch, key, value):
    configure_native(monkeypatch)
    if value is None:
        monkeypatch.delenv(key)
    else:
        monkeypatch.setenv(key, value)
    with pytest.raises((RuntimeError, ValueError)):
        gcp_credentials.native_gcp_profile_from_environment()
    with pytest.raises((RuntimeError, ValueError)):
        gcp_credentials.credential_for_gcp_reference(marked_reference())


def test_native_wif_is_explicit_in_memory_and_does_not_mutate_adc(monkeypatch, tmp_path):
    from google.auth import identity_pool

    configure_native(monkeypatch)
    legacy_adc = tmp_path / "legacy-adc.json"
    legacy_adc.write_text('{"type":"synthetic-legacy-adc"}', encoding="utf-8")
    legacy_subject = tmp_path / "legacy-subject-token"
    legacy_subject.write_text("synthetic-legacy-subject", encoding="utf-8")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(legacy_adc))
    monkeypatch.chdir(tmp_path)
    before_environment = dict(os.environ)
    before_files = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    source = object()
    captured = []

    def credentials(**kwargs):
        captured.append(kwargs)
        return source

    monkeypatch.setattr(identity_pool, "Credentials", credentials)
    assert gcp_credentials.native_gcp_source_credentials() is source
    assert len(captured) == 1
    options = captured[0]
    assert options["audience"] == f"//iam.googleapis.com/{PROVIDER}"
    assert options["subject_token_type"] == "urn:ietf:params:oauth:token-type:jwt"
    assert options["token_url"] == "https://sts.googleapis.com/v1/token"
    assert options["service_account_impersonation_url"] == (
        "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
        f"{RUNTIME}:generateAccessToken"
    )
    assert options["scopes"] == [gcp.GCP_CLOUD_PLATFORM_SCOPE]
    assert not options.get("credential_source")
    supplier = options["subject_token_supplier"]
    assert supplier.get_subject_token(None, None) == "synthetic-modal-identity-one"
    assert dict(os.environ) == before_environment
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before_files
    monkeypatch.setenv("MODAL_IDENTITY_TOKEN", "synthetic-modal-identity-two")
    assert supplier.get_subject_token(None, None) == "synthetic-modal-identity-two"
    monkeypatch.delenv("MODAL_IDENTITY_TOKEN")
    with pytest.raises((RuntimeError, ValueError)):
        supplier.get_subject_token(None, None)


def test_real_identity_pool_constructor_accepts_the_in_memory_supplier_without_network(
    monkeypatch,
):
    from google.auth import identity_pool
    from requests import Session

    configure_native(monkeypatch)
    monkeypatch.setattr(
        Session,
        "request",
        lambda *_args, **_kwargs: pytest.fail("credential construction contacted Google"),
    )
    credential = gcp_credentials.native_gcp_source_credentials()
    assert isinstance(credential, identity_pool.Credentials)
    assert credential._audience == f"//iam.googleapis.com/{PROVIDER}"
    assert credential._service_account_impersonation_url.endswith(f"/{RUNTIME}:generateAccessToken")
    assert credential.scopes == [gcp.GCP_CLOUD_PLATFORM_SCOPE]
    assert not credential.valid


def test_marked_reader_without_a_modal_token_cannot_refresh_or_fall_back(monkeypatch):
    from google.auth.exceptions import RefreshError

    configure_native(monkeypatch)
    monkeypatch.delenv("MODAL_IDENTITY_TOKEN")
    credential = gcp_credentials.credential_for_gcp_reference(marked_reference())
    with pytest.raises((ValueError, RefreshError)):
        credential.refresh(
            lambda *_args, **_kwargs: pytest.fail("missing token reached Google transport")
        )


def test_marked_reference_impersonates_only_its_exact_reader_for_900_seconds(monkeypatch):
    from google.auth import impersonated_credentials

    configure_native(monkeypatch)
    source = object()
    reader = object()
    captured = []
    monkeypatch.setattr(gcp_credentials, "native_gcp_source_credentials", lambda: source)
    monkeypatch.setattr(
        impersonated_credentials,
        "Credentials",
        lambda **kwargs: captured.append(kwargs) or reader,
    )
    reference = marked_reference()
    before = deepcopy(reference)
    assert gcp_credentials.credential_for_gcp_reference(reference) is reader
    assert captured == [
        {
            "source_credentials": source,
            "target_principal": READER,
            "target_scopes": [gcp.GCP_CLOUD_PLATFORM_SCOPE],
            "lifetime": 900,
        }
    ]
    assert reference == before


@pytest.mark.parametrize("profile", [None, "", "unknown", 17, [PROFILE]])
def test_explicit_unknown_profile_cannot_be_downgraded_to_legacy_adc(monkeypatch, profile):
    configure_native(monkeypatch)
    with pytest.raises((RuntimeError, ValueError)):
        gcp_credentials.credential_for_gcp_reference(
            marked_reference(operator_credential_profile=profile)
        )


@pytest.mark.parametrize(
    "updates",
    [
        {"operator_project_id": "other-operator"},
        {"operator_project_id": ""},
        {"principal_email": "denali-reader@other-operator.iam.gserviceaccount.com"},
        {"principal_email": "not-an-email"},
    ],
)
def test_marked_reference_rejects_project_or_principal_substitution(monkeypatch, updates):
    configure_native(monkeypatch)
    monkeypatch.setattr(
        gcp_credentials,
        "native_gcp_source_credentials",
        lambda: pytest.fail("invalid reader reached native credential acquisition"),
    )
    with pytest.raises((RuntimeError, ValueError)):
        gcp_credentials.credential_for_gcp_reference(marked_reference(**updates))


def test_marked_reference_requires_its_native_profile_after_configuration_removal():
    with pytest.raises((RuntimeError, ValueError)):
        gcp_credentials.credential_for_gcp_reference(marked_reference())


@pytest.mark.parametrize("partial_native_pair", [False, True])
def test_unmarked_reference_keeps_legacy_adc_even_when_native_profile_is_configured(
    monkeypatch,
    partial_native_pair,
):
    configure_native(monkeypatch)
    if partial_native_pair:
        monkeypatch.delenv(PROVIDER_KEY)
    monkeypatch.setattr(
        gcp_credentials,
        "native_gcp_source_credentials",
        lambda: pytest.fail("legacy reader silently migrated to native identity"),
    )
    result = object()
    principals = []
    monkeypatch.setattr(
        gcp, "_default_credential", lambda principal: principals.append(principal) or result
    )
    reference = marked_reference()
    del reference["operator_credential_profile"]
    before = deepcopy(reference)
    assert gcp_credentials.credential_for_gcp_reference(reference) is result
    assert principals == [READER]
    assert reference == before


def test_legacy_reader_retains_exact_adc_source_scope_and_impersonation(monkeypatch):
    import google.auth
    from google.auth import impersonated_credentials

    configure_native(monkeypatch)
    source = object()
    reader = object()
    adc_calls = []
    impersonations = []
    monkeypatch.setattr(
        google.auth,
        "default",
        lambda **kwargs: adc_calls.append(kwargs) or (source, "legacy-project"),
    )
    monkeypatch.setattr(
        impersonated_credentials,
        "Credentials",
        lambda **kwargs: impersonations.append(kwargs) or reader,
    )
    assert gcp._default_credential(READER) is reader
    assert adc_calls == [{"scopes": [gcp.GCP_CLOUD_PLATFORM_SCOPE]}]
    assert impersonations == [
        {
            "source_credentials": source,
            "target_principal": READER,
            "target_scopes": [gcp.GCP_CLOUD_PLATFORM_SCOPE],
            "lifetime": 900,
        }
    ]


def test_legacy_adc_already_bound_to_the_reader_is_returned_without_reimpersonation(monkeypatch):
    import google.auth
    from google.auth import impersonated_credentials

    configure_native(monkeypatch)

    class ExistingReader:
        service_account_email = READER

    source = ExistingReader()
    monkeypatch.setattr(google.auth, "default", lambda **_kwargs: (source, None))
    monkeypatch.setattr(
        impersonated_credentials,
        "Credentials",
        lambda **_kwargs: pytest.fail("legacy reader was unnecessarily reimpersonated"),
    )
    assert gcp_credentials.credential_for_gcp_reference({"principal_email": READER}) is source


def test_marked_public_helpers_reject_a_different_reader_argument(monkeypatch):
    configure_native(monkeypatch)
    for helper in (gcp.authorized_gcp_credential, gcp.authorized_gcp_request):
        with pytest.raises(ValueError):
            helper(
                "other-reader@native-operator.iam.gserviceaccount.com",
                credential_reference=marked_reference(),
            )


def test_workspace_keeps_its_legacy_adc_and_third_project_signer(monkeypatch):
    import google.auth
    from google.auth import impersonated_credentials

    from denali.connections.google_workspace import (
        GOOGLE_WORKSPACE_AUDIT_SCOPE,
        GoogleWorkspaceOperator,
    )
    from denali.connectors import google_workspace

    configure_native(monkeypatch)
    source = object()
    delegated = object()
    reports = object()
    adc_calls = []
    impersonations = []
    monkeypatch.setattr(
        gcp_credentials,
        "native_gcp_source_credentials",
        lambda: pytest.fail("Workspace used the isolated native GCP identity"),
    )
    monkeypatch.setattr(
        google.auth,
        "default",
        lambda **kwargs: adc_calls.append(kwargs) or (source, "legacy-project"),
    )
    monkeypatch.setattr(
        impersonated_credentials,
        "Credentials",
        lambda **kwargs: impersonations.append(kwargs) or delegated,
    )

    def client(credential):
        assert credential is delegated
        return reports

    monkeypatch.setattr(google_workspace, "GoogleWorkspaceReportsClient", client)
    operator = GoogleWorkspaceOperator(
        service_account="workspace-collector@third-project.iam.gserviceaccount.com",
        oauth_client_id="123456789012",
    )
    assert operator.reports_client("admin@example.test") is reports
    assert adc_calls == [{"scopes": [gcp.GCP_CLOUD_PLATFORM_SCOPE]}]
    assert impersonations == [
        {
            "source_credentials": source,
            "target_principal": "workspace-collector@third-project.iam.gserviceaccount.com",
            "target_scopes": [GOOGLE_WORKSPACE_AUDIT_SCOPE],
            "subject": "admin@example.test",
            "lifetime": 3600,
        }
    ]


def test_shasta_diagnostic_keeps_legacy_adc_when_native_gcp_is_configured(monkeypatch):
    import google.auth

    from denali.bridges.shasta_workspace import diagnose_pilot_workspace
    from denali.store import repository

    configure_native(monkeypatch)
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/synthetic-legacy-adc.json")
    monkeypatch.setenv("DENALI_SHASTA_WORKSPACE_TENANT_ID", "11111111-1111-4111-8111-111111111111")
    monkeypatch.setenv(
        "DENALI_SHASTA_WORKSPACE_CONNECTION_ID", "22222222-2222-4222-8222-222222222222"
    )
    monkeypatch.setenv(
        "DENALI_GOOGLE_WORKSPACE_SERVICE_ACCOUNT",
        "workspace-collector@third-project.iam.gserviceaccount.com",
    )
    monkeypatch.setenv("DENALI_DSN", "postgresql://unused-synthetic-test")
    monkeypatch.setattr(
        gcp_credentials,
        "native_gcp_source_credentials",
        lambda: pytest.fail("Shasta used the isolated native GCP identity"),
    )
    adc_calls = []

    class LegacySource:
        def refresh(self, _transport):
            raise RuntimeError("synthetic refresh stopped before any Google request")

    monkeypatch.setattr(
        google.auth,
        "default",
        lambda **kwargs: adc_calls.append(kwargs) or (LegacySource(), "legacy-project"),
    )

    class Repository:
        def get_connection_validation_target(self, _tenant, _connection):
            return {
                "provider": "google_workspace",
                "lifecycle_state": "active",
                "configuration": {"domain": "example.test", "admin_email": "admin@example.test"},
            }

    monkeypatch.setattr(repository, "PostgresInventoryRepository", lambda _dsn: Repository())
    result = diagnose_pilot_workspace()
    assert result["stage"] == "workload_identity"
    assert result["state"] == "failed"
    assert adc_calls == [{"scopes": [gcp.GCP_CLOUD_PLATFORM_SCOPE]}]


def test_shared_gcp_validation_and_collection_do_not_use_native_profiles(monkeypatch):
    from test_shared_gcp import Broker, connection

    from denali.connectors.gcp_deployments import GcpConnectionDeploymentCollector
    from denali.integrations.shared_gcp import SharedGcpReader

    configure_native(monkeypatch)
    monkeypatch.setenv("DENALI_PLATFORM_GCP_ENABLED", "true")
    monkeypatch.setattr(
        gcp_credentials,
        "native_gcp_source_credentials",
        lambda: pytest.fail("shared GCP fell back to native identity"),
    )
    broker = Broker()
    target = connection(["gcp.code_to_cloud"])
    before = deepcopy(target)

    def reader_factory(value):
        return SharedGcpReader(value, client=broker)

    validation = gcp.GcpConnectionValidator(shared_reader_factory=reader_factory).validate(target)
    assert validation["health_state"] == "healthy"

    class Sink:
        def ingest(self, tenant, batch):
            assert tenant == "tenant-alpha"
            return {"assets": len(batch.assets)}

    collection = GcpConnectionDeploymentCollector(shared_reader_factory=reader_factory).collect(
        tenant_id="tenant-alpha", connection=target, repository=Sink()
    )
    assert collection["state"] == "complete"
    assert target == before
    assert broker.calls
