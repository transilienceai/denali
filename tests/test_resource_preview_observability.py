"""Hermetic diagnostics/privacy proof; no Clerk, provider or database traffic."""

from __future__ import annotations

import json
from types import SimpleNamespace

import httpx
import pytest

from denali.resource_writes import observability
from denali.resource_writes.observability import observe_dependency, observe_preview
from denali.resource_writes.providers import GitHubRemediator, PlatformWriteLeases
from denali.resource_writes.service import RemediationService
from denali.resource_writes.templates import GITHUB_ACTION, RemediationError

PRIVATE = "SIMULATED_PRIVATE_TOKEN_SOURCE_CLAIMS_BODY_EMAIL_URL"
PHASES = {"preview", "membership", "lease_mint", "lease_post", "github_read"}
CATEGORIES = {
    "returned",
    "timeout",
    "http_status",
    "transport_error",
    "invalid_token",
    "invalid_response",
    "other",
    "rejected",
    "membership_unavailable",
    "resource_lease_unavailable",
    "github_provider_unavailable",
}


@pytest.fixture(autouse=True)
def preview_log_capture(caplog):
    """Capture this non-propagating logger without changing application logging."""
    observability._logger.addHandler(caplog.handler)
    try:
        yield
    finally:
        observability._logger.removeHandler(caplog.handler)


def records(caplog):
    observed = [record for record in caplog.records if record.name == "denali.resource_preview"]
    payloads = [json.loads(record.getMessage()) for record in observed]
    for record, payload in zip(observed, payloads, strict=True):
        assert record.exc_info is None and record.stack_info is None
        assert set(payload) in (
            {"event", "phase", "category", "elapsed_ms"},
            {"event", "phase", "category", "elapsed_ms", "status"},
        )
        assert payload["event"] == "resource_preview"
        assert payload["phase"] in PHASES and payload["category"] in CATEGORIES
        assert type(payload["elapsed_ms"]) is int and payload["elapsed_ms"] >= 0
        if "status" in payload:
            assert type(payload["status"]) is int and 100 <= payload["status"] <= 599
        assert PRIVATE not in record.getMessage()
    return payloads


def fail(error):
    raise error


def test_result_arguments_and_nested_payloads_never_enter_logs(caplog):
    calls = []
    result = {"token": PRIVATE, "source": PRIVATE, "claims": {"email": PRIVATE}}

    def callback(*args, **kwargs):
        calls.append((args, kwargs))
        return result

    assert (
        observe_preview(
            lambda: observe_dependency("lease_post", callback, PRIVATE, payload={"token": PRIVATE})
        )
        is result
    )
    assert calls == [((PRIVATE,), {"payload": {"token": PRIVATE}})]
    data = records(caplog)
    assert [row["phase"] for row in data] == ["lease_post", "preview"]
    assert [row["category"] for row in data] == ["returned", "returned"]
    assert data[-1]["status"] == 200


@pytest.mark.parametrize("phase", ["membership", "lease_mint", "lease_post", "github_read"])
@pytest.mark.parametrize(
    "kind,expected",
    [
        ("timeout", "timeout"),
        ("status", "http_status"),
        ("transport", "transport_error"),
        ("value", "invalid_response"),
        ("other", "other"),
    ],
)
def test_fixed_dependency_exception_classification_never_formats_material(
    caplog, phase, kind, expected
):
    request = httpx.Request(
        "GET", "https://invalid.example/" + PRIVATE, headers={"Authorization": "Bearer " + PRIVATE}
    )
    response = httpx.Response(502, request=request, json={"error": PRIVATE})
    error = {
        "timeout": httpx.ReadTimeout(PRIVATE, request=request),
        "status": httpx.HTTPStatusError(PRIVATE, request=request, response=response),
        "transport": httpx.ConnectError(PRIVATE, request=request),
        "value": ValueError(PRIVATE),
        "other": RuntimeError(PRIVATE),
    }[kind]
    with pytest.raises(type(error)) as caught:
        observe_preview(lambda: observe_dependency(phase, fail, error))
    assert caught.value is error
    data = records(caplog)
    assert data[0]["category"] == (
        "invalid_token" if phase == "lease_mint" and kind == "value" else expected
    )
    assert data[-1]["category"] == "other"
    assert data[0].get("status") == (502 if kind == "status" else None)


@pytest.mark.parametrize(
    "code,expected,status",
    [
        ("membership_unavailable", "membership_unavailable", 503),
        ("resource_lease_unavailable", "resource_lease_unavailable", 503),
        ("github_provider_unavailable", "github_provider_unavailable", 503),
        (PRIVATE, "rejected", None),
        ("preview_expired", "rejected", None),
    ],
)
def test_only_three_fixed_final_rejection_codes_are_emitted(caplog, code, expected, status):
    error = RemediationError(code)
    with pytest.raises(RemediationError) as caught:
        observe_preview(fail, error)
    assert caught.value is error
    event = records(caplog)[0]
    assert event["category"] == expected and event.get("status") == status


def test_no_diagnostics_outside_preview_and_context_restores_on_failure(caplog):
    assert observe_dependency("github_read", lambda: PRIVATE) == PRIVATE
    assert records(caplog) == []
    with pytest.raises(ValueError):
        observe_preview(lambda: observe_dependency("lease_mint", fail, ValueError(PRIVATE)))
    caplog.clear()
    assert observe_dependency("lease_post", lambda: PRIVATE) == PRIVATE
    assert records(caplog) == []


def test_nested_preview_context_restores_outer_scope(caplog):
    def outer():
        observe_preview(lambda: PRIVATE)
        return observe_dependency("membership", lambda: PRIVATE)

    assert observe_preview(outer) == PRIVATE
    assert [row["phase"] for row in records(caplog)] == ["preview", "membership", "preview"]
    caplog.clear()
    assert observe_dependency("membership", lambda: PRIVATE) == PRIVATE
    assert records(caplog) == []


def test_logger_failure_does_not_change_return_or_exception(monkeypatch):
    monkeypatch.setattr(observability._logger, "info", lambda *args: fail(RuntimeError(PRIVATE)))
    result = {"source": PRIVATE}
    assert observe_preview(lambda: observe_dependency("membership", lambda: result)) is result
    error = ValueError(PRIVATE)
    with pytest.raises(ValueError) as caught:
        observe_preview(lambda: observe_dependency("lease_mint", fail, error))
    assert caught.value is error and observability._preview_active.get() is False


def test_unknown_phase_fails_fixed_without_call_or_private_log(caplog):
    calls = []
    with pytest.raises(ValueError, match="^unknown resource preview phase$"):
        observe_dependency(PRIVATE, lambda: calls.append(True))
    assert calls == [] and records(caplog) == []


def test_membership_failure_emits_fixed_final_code_and_retains_error(caplog):
    product = RemediationService(
        store=None,
        inventory=None,
        leases=None,
        memberships=SimpleNamespace(role=lambda *args: fail(RuntimeError(PRIVATE))),
        enabled=frozenset({GITHUB_ACTION}),
    )
    with pytest.raises(RemediationError, match="^membership_unavailable$"):
        observe_preview(product._admin, PRIVATE, PRIVATE)
    assert [(row["phase"], row["category"]) for row in records(caplog)] == [
        ("membership", "other"),
        ("preview", "membership_unavailable"),
    ]


@pytest.mark.parametrize("kind", ["timeout", "http_status", "invalid_response"])
def test_github_read_failure_emits_only_fixed_transport_evidence(caplog, kind):
    calls = []
    request = httpx.Request("GET", "https://invalid.example/" + PRIVATE)

    def send(*args, **kwargs):
        calls.append((args, kwargs))
        if kind == "timeout":
            raise httpx.ReadTimeout(PRIVATE, request=request)
        return httpx.Response(
            403 if kind == "http_status" else 200,
            request=request,
            text=PRIVATE,
            headers={"X-Private": PRIVATE},
        )

    provider = GitHubRemediator(
        {"resource": {"full_name": PRIVATE}, "token": PRIVATE},
        client=SimpleNamespace(request=send),
    )
    with pytest.raises(RemediationError, match="^github_provider_unavailable$"):
        observe_preview(provider._api, "GET", "/" + PRIVATE)
    assert len(calls) == 1
    assert [(row["phase"], row["category"]) for row in records(caplog)] == [
        ("github_read", kind),
        ("preview", "github_provider_unavailable"),
    ]


def test_github_write_is_not_dependency_instrumented_even_in_preview(caplog):
    request = httpx.Request("POST", "https://invalid.example/" + PRIVATE)
    calls = []

    def send(*args, **kwargs):
        calls.append((args, kwargs))
        return httpx.Response(200, request=request, json={"source": PRIVATE})

    provider = GitHubRemediator(
        {"resource": {"full_name": PRIVATE}, "token": PRIVATE},
        client=SimpleNamespace(request=send),
    )
    assert observe_preview(provider._api, "POST", "/" + PRIVATE) == {"source": PRIVATE}
    assert len(calls) == 1
    assert [row["phase"] for row in records(caplog)] == ["preview"]


@pytest.mark.parametrize("stage", ["mint", "post"])
def test_lease_failure_is_classified_before_existing_sanitized_error(caplog, monkeypatch, stage):
    calls = []
    provider = PlatformWriteLeases.__new__(PlatformWriteLeases)
    provider._origin = "https://invalid.example"

    def mint(claims):
        calls.append("mint")
        if stage == "mint":
            raise ValueError(PRIVATE)
        return PRIVATE

    provider._lease_token = mint

    class Client:
        def __init__(self, **kwargs):
            assert kwargs == {"timeout": 15, "follow_redirects": False}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def post(self, *args, **kwargs):
            calls.append("post")
            raise httpx.ReadTimeout(PRIVATE)

    monkeypatch.setattr("denali.resource_writes.providers.httpx.Client", Client)
    with pytest.raises(RemediationError, match="^resource_lease_unavailable$"):
        observe_preview(
            provider.lease,
            organization_id=PRIVATE,
            grant_id=PRIVATE,
            action=GITHUB_ACTION,
            mode="preview",
            request_id=PRIVATE,
            request_sha256=PRIVATE,
            actor=PRIVATE,
        )
    data = records(caplog)
    assert calls == (["mint"] if stage == "mint" else ["mint", "post"])
    assert data[-1]["category"] == "resource_lease_unavailable"
    assert data[-2]["category"] == ("invalid_token" if stage == "mint" else "timeout")


def test_status_validation_never_accepts_bool_or_arbitrary_material():
    assert observability._status(200) == 200
    assert all(observability._status(value) is None for value in (True, PRIVATE, 99, 600, None))
