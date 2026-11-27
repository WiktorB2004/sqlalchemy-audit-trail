"""Text encodings shared by the integrity formats."""

from __future__ import annotations

import base64


def context(name: str) -> bytes:
    """The domain separation string ``sqlalchemy-audit-trail/<name>/v1``.

    A change to a format gets a new name or version, never an edit of the
    bytes an existing one gives.
    """
    return f"sqlalchemy-audit-trail/{name}/v1".encode()


def b64(raw: bytes) -> str:
    """Standard base64 with padding, as ASCII text."""
    return base64.b64encode(raw).decode("ascii")
