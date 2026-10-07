"""Offline SDK-contract and fail-closed lease-token checks; no Clerk/provider calls."""

from __future__ import annotations

import copy
import inspect
import json
from types import SimpleNamespace

import httpx
import pytest
from clerk_backend_api.m2m import M2m
from clerk_backend_api.models.createm2mtokenop import CreateM2MTokenResponseBody
from httpx import Client as OfflineHttpClient

from denali.resource_writes import providers
from denali.resource_writes.providers import PlatformWriteLeases
from denali.resource_writes.templates import RemediationError

NOW = 1_800_000_000_000
RECEIVER = "mch_PlatformReceiver1"
INPUT = {
    "organization_id": "org_Test1",
    "grant_id": "00000000-0000-4000-8000-000000000001",
    "action": "github.guardrail_draft_pr",
    "mode": "preview",
    "request_id": "00000000-0000-4000-8000-000000000002",
    "request_sha256": "a" * 64,
    "actor": "user_Actor1",
    "reviewer": None,
}
CLAIMS = {
    "purpose": "denali:resource-write-lease",
    "org_id": INPUT["organization_id"],
    "grant_id": INPUT["grant_id"],
    "action": INPUT["action"],
    "mode": INPUT["mode"],
    "request_id": INPUT["request_id"],
    "request_sha256": INPUT["request_sha256"],
    "actor_user_id": INPUT["actor"],
    "reviewer_user_id": None,
}


def valid_token(**changes):
    return SimpleNamespace(
        **{
            "object": "machine_to_machine_token",
            "id": "mt_Test1",
            "subject": "mch_DenaliSender1",
            "token": "mt_synthetic_offline_token",
            "revoked": False,
            "revocation_reason": None,
            "expired": False,
            "expiration": NOW + 60_000,
            "last_used_at": None,
            "created_at": NOW,
            "updated_at": NOW,
            "claims": copy.deepcopy(CLAIMS),
            "scopes": [RECEIVER],
            **changes,
        }
    )


class SignatureFaithfulM2m:
    def __init__(self, response, failure=None):
        self.response, self.failure, self.calls = response, failure, []

    # Deliberately no **kwargs/scopes: the removed SDK-incompatible argument
    # must fail this regression even when no real HTTP request is made.
    def create_token(self, *, seconds_until_expiration, claims, retries, timeout_ms):
        kwargs = {
            "seconds_until_expiration": seconds_until_expiration,
            "claims": claims,
            "retries": retries,
            "timeout_ms": timeout_ms,
        }
        inspect.signature(M2m.create_token).bind(self, **kwargs)
        self.calls.append(copy.deepcopy(kwargs))
        if self.failure:
            raise self.failure
        return self.response


@pytest.fixture
def bridge(monkeypatch):
    monkeypatch.setattr(providers.time, "time", lambda: NOW / 1000)
    calls, constructed = [], []
    sdk = SignatureFaithfulM2m(valid_token())

    def clerk(**kwargs):
        constructed.append(kwargs)
        return SimpleNamespace(m2m=sdk)

    monkeypatch.setattr("clerk_backend_api.Clerk", clerk)
    def response(request):
        calls.append(request)
        return httpx.Response(200, json={"lease": "synthetic-offline-result"})

    def client(**kwargs):
        assert kwargs == {"timeout": 15, "follow_redirects": False}
        return OfflineHttpClient(transport=httpx.MockTransport(response), **kwargs)

    monkeypatch.setattr(providers.httpx, "Client", client)
    leases = PlatformWriteLeases(
        "https://platform.example.test", "synthetic-offline-machine-key", RECEIVER
    )
    assert constructed == [
        {
            "bearer_auth": "synthetic-offline-machine-key",
            "timeout_ms": 5000,
            "retry_config": None,
        }
    ]
    return leases, sdk, calls


def test_lease_mints_with_installed_sdk_signature_and_posts_exact_bound_request(bridge):
    leases, sdk, calls = bridge
    sdk.response = CreateM2MTokenResponseBody(**vars(valid_token()))
    assert leases.lease(**INPUT) == {"lease": "synthetic-offline-result"}
    assert sdk.calls == [
        {
            "seconds_until_expiration": 60,
            "claims": CLAIMS,
            "retries": None,
            "timeout_ms": 5000,
        }
    ]
    assert len(calls) == 1
    request = calls[0]
    assert request.method == "POST"
    assert str(request.url) == (
        "https://platform.example.test/internal/v1/resource-write-grants/"
        + INPUT["grant_id"]
        + "/lease"
    )
    assert request.headers["Authorization"] == "Bearer mt_synthetic_offline_token"
    assert json.loads(request.content) == {
        "clerk_org_id": INPUT["organization_id"],
        "action": INPUT["action"],
        "mode": INPUT["mode"],
        "request_id": INPUT["request_id"],
        "request_sha256": INPUT["request_sha256"],
    }


@pytest.mark.parametrize(
    "changes",
    [
        {"scopes": None},
        {"scopes": []},
        {"scopes": "mch_PlatformReceiver1"},
        {"scopes": (RECEIVER,)},
        {"scopes": ["mch_OtherReceiver1"]},
        {"scopes": [RECEIVER, "mch_OtherReceiver1"]},
        {"scopes": [RECEIVER, RECEIVER]},
        {"claims": None},
        {"claims": []},
        {"claims": {**CLAIMS, "purpose": "denali:write"}},
        {"claims": {**CLAIMS, "org_id": "org_Other1"}},
        {"claims": {**CLAIMS, "grant_id": "other"}},
        {"claims": {**CLAIMS, "action": "aws.tighten_bedrock_inline_policy"}},
        {"claims": {**CLAIMS, "mode": "execute"}},
        {"claims": {**CLAIMS, "request_id": "other"}},
        {"claims": {**CLAIMS, "request_sha256": "b" * 64}},
        {"claims": {**CLAIMS, "actor_user_id": "user_Other1"}},
        {"claims": {**CLAIMS, "reviewer_user_id": "user_Other1"}},
        {"claims": {**CLAIMS, "unexpected": "value"}},
        {"claims": {key: value for key, value in CLAIMS.items() if key != "mode"}},
        {"subject": None},
        {"subject": ""},
        {"subject": "user_Actor1"},
        {"subject": "mch_Invalid-1"},
        {"subject": "mch_" + "a" * 129},
        {"subject": RECEIVER},
        {"revoked": True},
        {"revoked": 0},
        {"expired": True},
        {"expired": None},
        {"created_at": None},
        {"created_at": True},
        {"created_at": str(NOW)},
        {"created_at": float("nan")},
        {"created_at": float("inf")},
        {"created_at": 0},
        {"created_at": NOW + 5001},
        {"created_at": NOW - 1},
        {"expiration": None},
        {"expiration": True},
        {"expiration": str(NOW + 60_000)},
        {"expiration": float("nan")},
        {"expiration": float("inf")},
        {"expiration": NOW},
        {"expiration": NOW - 1},
        {"expiration": NOW + 60_001},
        {"created_at": NOW + 1000, "expiration": NOW + 1000},
        {"token": None},
        {"token": ""},
        {"token": "mt_token\r\nInjected: header"},
        {"token": "mt token"},
        {"token": "x" * 8193},
    ],
)
def test_invalid_mint_metadata_never_contacts_platform(bridge, changes):
    leases, sdk, calls = bridge
    sdk.response = valid_token(**changes)
    with pytest.raises(RemediationError) as caught:
        leases.lease(**INPUT)
    assert str(caught.value) == "resource_lease_unavailable"
    assert caught.value.__suppress_context__ is True
    assert len(sdk.calls) == 1
    assert calls == []


@pytest.mark.parametrize(
    "missing", ["scopes", "claims", "subject", "revoked", "expired", "created_at",
                "expiration", "token"]
)
def test_missing_mint_metadata_never_contacts_platform(bridge, missing):
    leases, sdk, calls = bridge
    delattr(sdk.response, missing)
    with pytest.raises(RemediationError, match="^resource_lease_unavailable$"):
        leases.lease(**INPUT)
    assert calls == []


def test_sdk_failure_is_sanitized_without_retry_or_platform_call(bridge):
    leases, sdk, calls = bridge
    sdk.failure = TypeError("synthetic-private-sdk-error")
    with pytest.raises(RemediationError) as caught:
        leases.lease(**INPUT)
    assert str(caught.value) == "resource_lease_unavailable"
    assert caught.value.__cause__ is None
    assert caught.value.__suppress_context__ is True
    assert len(sdk.calls) == 1
    assert calls == []


def test_fresh_execution_reviewer_and_bounded_clock_skew_are_preserved(bridge):
    leases, sdk, calls = bridge
    claims = {**CLAIMS, "mode": "execute", "reviewer_user_id": "user_Reviewer1"}
    sdk.response = valid_token(
        claims=claims, created_at=NOW + 5000, expiration=NOW + 65_000
    )
    leases.lease(**{**INPUT, "mode": "execute", "reviewer": "user_Reviewer1"})
    assert sdk.calls[0]["claims"] == claims
    assert len(calls) == 1


def test_reused_alive_short_token_is_valid_but_never_requested_by_this_client(bridge):
    leases, sdk, calls = bridge
    sdk.response = valid_token(created_at=NOW - 10_000, expiration=NOW + 50_000)
    leases.lease(**INPUT)
    assert "min_remaining_ttl_seconds" not in sdk.calls[0]
    assert len(calls) == 1


@pytest.mark.parametrize("failure", ["http", "json", "transport"])
def test_platform_errors_are_sanitized_and_not_retried(bridge, monkeypatch, failure):
    leases, sdk, calls = bridge
    def response(request):
        calls.append(request)
        if failure == "http":
            return httpx.Response(503, text="synthetic-private-platform-error")
        if failure == "transport":
            raise httpx.ReadTimeout("synthetic-private-timeout", request=request)
        return httpx.Response(200, text="synthetic-private-non-json-response")

    monkeypatch.setattr(
        providers.httpx,
        "Client",
        lambda **kwargs: OfflineHttpClient(transport=httpx.MockTransport(response), **kwargs),
    )
    with pytest.raises(RemediationError) as caught:
        leases.lease(**INPUT)
    assert str(caught.value) == "resource_lease_unavailable"
    assert caught.value.__suppress_context__ is True
    assert len(sdk.calls) == 1
    assert len(calls) == 1
