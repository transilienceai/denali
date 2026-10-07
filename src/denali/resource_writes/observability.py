"""Finite, credential-free diagnostics for a product preview, not authorization.

Only fixed labels, an HTTP status integer and elapsed milliseconds are emitted.
Call arguments, results and exception text never enter a logging operation.
The context is local to the synchronous preview call, not a provider/job retry.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from contextvars import ContextVar
from time import monotonic
from typing import Literal, TypeVar

import httpx

from denali.resource_writes.templates import RemediationError

_T = TypeVar("_T")
_preview_active: ContextVar[bool] = ContextVar("resource_preview_active", default=False)
_logger = logging.getLogger("denali.resource_preview")
_logger.setLevel(logging.INFO)
Phase = Literal["membership", "lease_mint", "lease_post", "github_read"]
_PHASES = frozenset({"membership", "lease_mint", "lease_post", "github_read"})
_REJECTIONS = frozenset(
    {"membership_unavailable", "resource_lease_unavailable", "github_provider_unavailable"}
)


def _status(value: object) -> int | None:
    return value if type(value) is int and 100 <= value <= 599 else None


def _emit(*, phase: str, category: str, started: float, status: int | None = None) -> None:
    # A logging handler failure must not change the existing product outcome.
    try:
        _logger.info(
            json.dumps(
                {
                    "event": "resource_preview",
                    "phase": phase,
                    "category": category,
                    "elapsed_ms": max(0, round((monotonic() - started) * 1000)),
                    **({"status": status} if status is not None else {}),
                },
                separators=(",", ":"),
            )
        )
    except Exception:
        pass


def observe_dependency(phase: Phase, call: Callable[..., _T], /, *args, **kwargs) -> _T:
    """Call exactly once; emit no event outside the named preview context."""
    if phase not in _PHASES:
        raise ValueError("unknown resource preview phase")
    if not _preview_active.get():
        return call(*args, **kwargs)
    started = monotonic()
    category = "returned"
    status: int | None = None
    try:
        return call(*args, **kwargs)
    except httpx.TimeoutException:
        category = "timeout"
        raise
    except httpx.HTTPStatusError as error:
        category = "http_status"
        status = _status(error.response.status_code)
        raise
    except httpx.RequestError:
        category = "transport_error"
        raise
    except ValueError:
        category = "invalid_token" if phase == "lease_mint" else "invalid_response"
        raise
    except Exception:
        category = "other"
        raise
    finally:
        _emit(phase=phase, category=category, started=started, status=status)


def observe_preview(call: Callable[..., _T], /, *args, **kwargs) -> _T:
    """Record a fixed final outcome without reflecting a rejection's input."""
    token = _preview_active.set(True)
    started = monotonic()
    category = "returned"
    status: int | None = 200
    try:
        return call(*args, **kwargs)
    except RemediationError as error:
        candidate = error.args[0] if error.args else None
        category = candidate if type(candidate) is str and candidate in _REJECTIONS else "rejected"
        status = 503 if category in _REJECTIONS else None
        raise
    except Exception:
        category = "other"
        status = None
        raise
    finally:
        _emit(phase="preview", category=category, started=started, status=status)
        _preview_active.reset(token)
