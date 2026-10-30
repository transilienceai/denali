"""Standard-library-only native enrollment validation for deploy and runtime."""

from __future__ import annotations

import re
from collections.abc import Mapping
from uuid import UUID

NATIVE_PILOT_CONNECTION_COUNT = 6


def native_enrollment(environ: Mapping[str, str]) -> tuple[frozenset[str], frozenset[str]]:
    def values(name: str) -> list[str]:
        items = [value.strip() for value in environ.get(name, "").split(",") if value.strip()]
        if len(set(items)) != len(items):
            raise ValueError("native connection settings enrollment invalid")
        return items

    organizations = values("DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CLERK_ORG_IDS")
    connections = values("DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CONNECTION_IDS")
    if (len(organizations) != 1 or not re.fullmatch(r"org_[A-Za-z0-9]{1,124}", organizations[0])
            or len(connections) != NATIVE_PILOT_CONNECTION_COUNT):
        raise ValueError("native connection settings enrollment invalid")
    try:
        if any(str(UUID(value)) != value or UUID(value).int == 0 for value in connections):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        raise ValueError("native connection settings enrollment invalid") from None
    return frozenset(organizations), frozenset(connections)


def native_candidate_connection(environ: Mapping[str, str], connection_id: str) -> bool:
    """Recognize intended IDs without allowing malformed pins to affect other IDs."""
    values = environ.get("DENALI_NATIVE_CONNECTION_SETTINGS_ALLOWED_CONNECTION_IDS", "").split(",")
    for value in values:
        try:
            if str(UUID(value.strip())) == connection_id:
                return True
        except (ValueError, TypeError, AttributeError):
            continue
    return False
