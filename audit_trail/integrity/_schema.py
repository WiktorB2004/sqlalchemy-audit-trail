"""The integrity columns and indexes of the audit tables.

They are declared only when integrity is on, so a library upgraded without
it never writes or selects a column an older schema lacks.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    Index,
    MetaData,
    Table,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import BYTEA, JSONB

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

DEFAULT_CHUNK_ROWS = 2_000
"""Audit rows fetched per round trip by the readers that stream them."""


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


BLOCK_TABLE = "audit_seal_block"
"""Default name of the table of sealed blocks, in the schema of the audit
tables."""

# Longest suffix of a name derived from the block table's.
BLOCK_SUFFIX_LENGTH = len("_retired_partition_key")

BLOCK_KINDS: tuple[str, ...] = (
    "genesis",
    "seal",
    "retire",
    "checkpoint",
    "ack",
    "fork",
)
"""The kinds of block."""


def block_table(metadata: MetaData, name: str = BLOCK_TABLE) -> Table:
    """Declare the table of sealed blocks, ``name``, in ``metadata``.

    One row per block of the hash chain, unpartitioned and small:

    - ``seq``: gapless from 1; the primary key keeps a second sealer from
      committing a block with the same number.
    - ``kind``: one of ``BLOCK_KINDS``; the body names it too, and only the
      body is hashed.
    - ``body``: the canonical bytes, stored exactly as hashed.
    - ``prev_hash``, ``block_hash``: the chain (see ``_block.block_hash``).
    - ``retired_partition``: set on ``retire`` blocks, unique where not null,
      so retiring a partition twice adds no second block.
    - ``signature``, ``key_id``, ``alg``: null unless block signing is on.
    - ``sealed_at``: when the block was written; informational, not hashed.
    """
    kinds = ", ".join(f"'{kind}'" for kind in BLOCK_KINDS)
    table = Table(
        name,
        metadata,
        Column("seq", BigInteger, primary_key=True, autoincrement=False),
        Column("kind", Text, nullable=False),
        Column("body", BYTEA, nullable=False),
        Column("prev_hash", BYTEA, nullable=False),
        Column("block_hash", BYTEA, nullable=False),
        Column("retired_partition", Text),
        Column("signature", BYTEA),
        Column("key_id", Text),
        Column("alg", Text),
        Column(
            "sealed_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=text("now()"),
        ),
        CheckConstraint(f"kind IN ({kinds})", name=f"{name}_kind_check"),
        CheckConstraint("seq >= 1", name=f"{name}_seq_check"),
    )
    Index(
        f"{name}_retired_partition_key",
        table.c.retired_partition,
        unique=True,
        postgresql_where=table.c.retired_partition.is_not(None),
    )
    return table
