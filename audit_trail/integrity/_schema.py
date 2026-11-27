"""The integrity columns and indexes of the audit tables.

They are declared only when integrity is on, so a library upgraded without
it never writes or selects a column an older schema lacks.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import Column, Index, Table, text
from sqlalchemy.dialects.postgresql import JSONB

from audit_trail.integrity._types import Xid8

XID = "xid"
"""Transaction id of the row, ``pg_current_xact_id()`` at insert."""

COMMITMENTS = "seal_commitments"
"""``{group: base64 commitment}``; never changes after insert."""

SALTS = "seal_salts"
"""``{group: base64 salt}``; a scrub removes the groups it erases."""

ERASED = "seal_erased"
"""``{group: xid of the scrub}``; a scrub adds the groups it erases."""

SEAL_COLUMNS: tuple[str, ...] = (COMMITMENTS, SALTS, ERASED)
"""The JSONB integrity columns, which every writer row carries."""

INTEGRITY_COLUMNS: tuple[str, ...] = (XID, *SEAL_COLUMNS)
"""Every integrity column, which reads of entries never select."""

XID_DEFAULT = "pg_current_xact_id()"
"""Default of the ``xid`` column."""


def columns() -> list[Column[Any]]:
    """New ``Column`` objects for one audit table.

    ``xid`` is ``NOT NULL`` here, as on a fresh install; one added by
    ``migrations.add_integrity`` stays nullable, ``NULL`` on older rows.
    The JSONB columns store Python ``None`` as SQL ``NULL``.
    """
    return [
        Column(XID, Xid8(), nullable=False, server_default=text(XID_DEFAULT)),
        *(Column(name, JSONB(none_as_null=True)) for name in SEAL_COLUMNS),
    ]


def xid_index_name(table_name: str) -> str:
    """Name of the ``(xid, id)`` index of a table."""
    return f"{table_name}_xid_idx"


def add_xid_index(table: Table) -> Index:
    """Declare the ``(xid, id)`` index on a table with the integrity columns."""
    return Index(xid_index_name(table.name), table.c[XID], table.c.id)


def has_integrity(table: Table) -> bool:
    """Tell whether a table was built with the integrity columns."""
    return COMMITMENTS in table.c
