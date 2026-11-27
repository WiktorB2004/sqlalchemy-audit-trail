"""Text encodings shared by the integrity formats."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from audit_trail.integrity._canonical import CanonicalEncodingError


def context(name: str) -> bytes:
    """The domain separation string ``sqlalchemy-audit-trail/<name>/v1``.

    A change to a format gets a new name or version, never an edit of the
    bytes an existing one gives.
    """
    return f"sqlalchemy-audit-trail/{name}/v1".encode()


def b64(raw: bytes) -> str:
    """Standard base64 with padding, as ASCII text."""
    return base64.b64encode(raw).decode("ascii")


def rfc3339(value: datetime) -> str:
    """A timestamp as RFC 3339 UTC text with six fraction digits and ``Z``.

    Raises:
        CanonicalEncodingError: The timestamp is naive.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        raise CanonicalEncodingError("cannot encode a naive timestamp")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
