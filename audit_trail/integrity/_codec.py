"""Text encodings shared by the integrity formats."""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import TypeGuard

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


def decode_strict(text: object, length: int | None = None) -> bytes | None:
    """The bytes of strict base64 text, or ``None``.

    Args:
        text: The text; anything but a ``str`` gives ``None``.
        length: The number of bytes wanted, if any.

    Returns:
        The bytes, or ``None`` when ``text`` is not a ``str`` of valid base64
        or decodes to another length.
    """
    if not isinstance(text, str):
        return None
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw if length is None or len(raw) == length else None


def decode_canonical(text: str) -> bytes | None:
    """The bytes of canonical base64 text, or ``None``.

    Strict, and also refuses text that ``b64`` would not give for its bytes:
    an encoding with nonzero padding bits decodes too, and signed notes
    must reject it.
    """
    raw = decode_strict(text)
    return raw if raw is not None and b64(raw) == text else None


def rfc3339(value: datetime) -> str:
    """A timestamp as RFC 3339 UTC text with six fraction digits and ``Z``.

    Raises:
        CanonicalEncodingError: The timestamp is naive.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        raise CanonicalEncodingError("cannot encode a naive timestamp")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_rfc3339(value: object) -> datetime | None:
    """Read back UTC text ending in ``Z``, as ``rfc3339`` writes it, or ``None``."""
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None


def is_int(value: object) -> TypeGuard[int]:
    """Tell whether a parsed JSON value is an integer, not a ``bool``."""
    return isinstance(value, int) and not isinstance(value, bool)
