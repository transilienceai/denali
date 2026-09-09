"""Strict container image digest helpers shared by deployment collectors."""

from __future__ import annotations

import re
from collections.abc import Iterable

_DIGEST_RE = re.compile(r"(?:^|@)(sha256:[0-9a-fA-F]{64})(?:$|[^0-9a-fA-F])")


def image_digests(values: Iterable[object]) -> list[str]:
    """Return only immutable sha256 digests explicitly present in image identifiers."""

    digests: set[str] = set()
    for value in values:
        if not isinstance(value, str):
            continue
        match = _DIGEST_RE.search(value.strip())
        if match:
            digests.add(match.group(1).lower())
    return sorted(digests)


def normalize_image_digest(value: str) -> str:
    normalized = value.strip().lower()
    if re.fullmatch(r"sha256:[0-9a-f]{64}", normalized) is None:
        raise ValueError("image digest must be an immutable sha256 identifier")
    return normalized
