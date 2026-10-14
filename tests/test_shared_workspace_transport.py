"""Exercise the concrete bounded M2M client, not a permissive broker stand-in."""

from __future__ import annotations

import json
import threading
import time
from types import SimpleNamespace

import httpx
import pytest

import denali.integrations.shared_connections_client as module
from denali.integrations.shared_connections_client import (
    SharedConnectionsClient,
    SharedConnectionsError,
)

ORIGIN = "https://broker.example.test"
ROOT = "/internal/v1/connections/google-workspace"
ORG = "org_alpha"
PRIVATE = "synthetic-private-marker"


@pytest.fixture
def mint(monkeypatch):
    calls = []

    def create_token(**kwargs):
        calls.append(kwargs)
        return SimpleNamespace(token="synthetic-m2m-token")

    monkeypatch.setattr(
        module, "Clerk", lambda **_: SimpleNamespace(m2m=SimpleNamespace(create_token=create_token))
    )
    return calls


def transport(monkeypatch, handler):
    """Keep the real Client/stream/response stack, replace network transport only."""
    options = []

    def make_transport(**kwargs):
        options.append(kwargs)
        return httpx.MockTransport(handler)

    monkeypatch.setattr(module.httpx, "HTTPTransport", make_transport)
    return options


def client():
    return SharedConnectionsClient(
        ORIGIN, "synthetic-machine-key", allowed_clerk_org_ids=frozenset({ORG})
    )


def request(broker, **kwargs):
    return broker.request(
        "GET", ROOT + "/config", clerk_org_id=ORG, max_response_bytes=64, **kwargs
    )


def assert_sanitized(call, status=502):
    with pytest.raises(SharedConnectionsError) as caught:
        call()
    assert caught.value.status_code == status
    assert PRIVATE not in repr(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("method", ["GET", "POST"])
def test_real_client_signature_uses_fixed_origin_and_server_resolved_org(monkeypatch, mint, method):
    seen = []

    def handle(outbound):
        seen.append(outbound)
        return httpx.Response(200, json={"items": []})

    options = transport(monkeypatch, handle)
    broker = client()
    result = broker.request(
        method,
        ROOT + "/config",
        clerk_org_id=ORG,
        payload={"clerk_org_id": "org_spoof", "initiating_user_id": "user_alpha"},
        max_response_bytes=64,
    )
    assert result == {"items": []}
    assert len(seen) == 1
    outbound = seen[0]
    assert outbound.url.scheme == "https" and outbound.url.host == "broker.example.test"
    assert outbound.url.path == ROOT + "/config"
    assert json.loads(outbound.content)["clerk_org_id"] == ORG
    assert dict(outbound.url.params) == ({"clerk_org_id": ORG} if method == "GET" else {})
    assert outbound.headers["authorization"] == "Bearer synthetic-m2m-token"
    assert outbound.headers["accept-encoding"] == "identity"
    assert options == [{"retries": 0}]
    assert mint == [{"seconds_until_expiration": 120, "min_remaining_ttl_seconds": 90}]


def test_query_encoding_is_owned_by_httpx_and_payload_cannot_replace_org(monkeypatch, mint):
    seen = []
    transport(monkeypatch, lambda out: (seen.append(out), httpx.Response(200, json={}))[1])
    broker = SharedConnectionsClient(ORIGIN, "synthetic-machine-key")
    selection = "org_test+ &?=/%"
    broker.request("GET", ROOT + "/config", clerk_org_id=selection, max_response_bytes=64)
    assert seen[0].url.params["clerk_org_id"] == selection
    assert seen[0].url.query == b"clerk_org_id=org_test%2B+%26%3F%3D%2F%25"


def test_disallowed_org_and_path_rejected_before_mint_or_transport(monkeypatch, mint):
    transport(monkeypatch, lambda _: pytest.fail("network must not run"))
    broker = client()
    assert_sanitized(
        lambda: broker.request("GET", ROOT, clerk_org_id="org_beta", max_response_bytes=64), 404
    )
    with pytest.raises(ValueError):
        broker.request(
            "GET", "https://other.example.test/", clerk_org_id=ORG, max_response_bytes=64
        )
    assert mint == []


@pytest.mark.parametrize("limit", [True, 0, -1, 2_097_153, "64"])
def test_invalid_wire_budget_rejected_before_mint(monkeypatch, mint, limit):
    transport(monkeypatch, lambda _: pytest.fail("network must not run"))
    with pytest.raises(ValueError):
        client().request("GET", ROOT, clerk_org_id=ORG, max_response_bytes=limit)
    assert mint == []


def test_bounded_selection_never_accepts_text_mode(monkeypatch, mint):
    with pytest.raises(ValueError):
        client().request("GET", ROOT, clerk_org_id=ORG, max_response_bytes=64, expect_text=True)
    assert mint == []


@pytest.mark.parametrize(
    "status,expected",
    [
        (302, 502),
        (400, 502),
        (401, 502),
        (403, 502),
        (404, 404),
        (409, 409),
        (422, 422),
        (500, 502),
    ],
)
def test_redirects_and_error_bodies_are_never_followed_or_exported(
    monkeypatch, mint, status, expected
):
    seen = []
    transport(
        monkeypatch,
        lambda out: (
            seen.append(out),
            httpx.Response(
                status,
                json={"private": PRIVATE},
                headers={"location": "https://untrusted.example.test/"},
            ),
        )[1],
    )
    assert_sanitized(lambda: request(client()), expected)
    assert len(seen) == 1


class Chunks(httpx.SyncByteStream):
    def __iter__(self):
        yield b'{"text":"'
        yield b"x" * 80
        yield b'"}'


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, content=b"x" * 65),
        httpx.Response(200, headers={"content-length": "65"}, content=b"{}"),
        httpx.Response(200, headers={"content-length": "not-a-number"}, content=b"{}"),
        httpx.Response(200, stream=Chunks()),
        httpx.Response(200, headers={"content-encoding": "br"}, content=b""),
        httpx.Response(200, headers={"content-encoding": "gzip"}, content=b""),
        httpx.Response(200, content=(PRIVATE + " not JSON").encode()),
        httpx.Response(200, content=b"\xff"),
        httpx.Response(200, json=[PRIVATE]),
        httpx.Response(200, json=None),
    ],
)
def test_wire_caps_encoding_and_malformed_json_fail_closed(monkeypatch, mint, response):
    transport(monkeypatch, lambda _: response)
    assert_sanitized(lambda: request(client()))


def test_exact_wire_budget_and_empty_object_are_valid(monkeypatch, mint):
    body = b'{"text":"' + b"x" * 53 + b'"}'
    assert len(body) == 64
    transport(monkeypatch, lambda _: httpx.Response(200, content=body))
    assert request(client()) == {"text": "x" * 53}


def test_transport_exception_cannot_leak_request_credentials(monkeypatch, mint):
    def handle(outbound):
        raise httpx.ReadTimeout(PRIVATE, request=outbound)

    transport(monkeypatch, handle)
    assert_sanitized(lambda: request(client()))


@pytest.mark.parametrize("phase", ["mint", "transport", "parse"])
def test_absolute_watchdog_bounds_slow_mint_transport_and_parser(monkeypatch, mint, phase):
    monkeypatch.setattr(module, "_BOUNDED_RPC_SECONDS", 0.03)
    slots = threading.BoundedSemaphore(1)
    monkeypatch.setattr(module, "_BOUNDED_RPC_SLOTS", slots)
    blocked, release = threading.Event(), threading.Event()

    def stall():
        blocked.set()
        release.wait(1)

    broker = client()
    if phase == "mint":
        broker._clerk.m2m.create_token = lambda **_: (
            stall(),
            SimpleNamespace(token="synthetic-token"),
        )[1]

    def handle(_):
        if phase == "transport":
            stall()
        return httpx.Response(200, json={})

    transport(monkeypatch, handle)
    if phase == "parse":
        original_loads = json.loads
        monkeypatch.setattr(
            module, "json", SimpleNamespace(loads=lambda body: (stall(), original_loads(body))[1])
        )
    try:
        started = time.monotonic()
        assert_sanitized(lambda: request(broker))
        assert blocked.is_set() and time.monotonic() - started < 0.5
        # A timed-out worker retains its slot until it really stops: no unbounded
        # accumulation of SDK/transport threads behind a superficial timeout.
        started = time.monotonic()
        assert_sanitized(lambda: request(broker))
        assert time.monotonic() - started < 0.1
    finally:
        release.set()
    assert slots.acquire(timeout=1)
    slots.release()


def test_legacy_provider_request_remains_opt_in_and_unchanged(monkeypatch, mint):
    # No wire-budget argument means legacy providers still use their existing
    # ordinary JSON path. The new Workspace route always opts in explicitly.
    real = httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"legacy": True}))
    )
    monkeypatch.setattr(module.httpx, "Client", lambda **_: real)
    assert client().request("GET", "/v1/connections", clerk_org_id=ORG) == {"legacy": True}
