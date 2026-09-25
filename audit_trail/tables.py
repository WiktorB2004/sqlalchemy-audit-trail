"""Core table definitions for the audit log.

Both tables are partitioned in PostgreSQL, so their primary keys include the
partition keys and nothing has a foreign key to them:

* ``audit_transaction``: ``PARTITION BY RANGE (issued_at)``, one partition per
  month.
* ``audit_activity``: ``PARTITION BY LIST (severity)``, and each severity
  partition is itself ``PARTITION BY RANGE (created_at)``, one partition per
  month.

The partitions are not part of the metadata; ``audit_trail.migrations``
creates the parents and severity partitions, ``audit_trail.maintenance`` the
monthly ones.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass

from sqlalchemy import (
    BigInteger,
    Column,
    DateTime,
    Identity,
    Index,
    MetaData,
    PrimaryKeyConstraint,
    SmallInteger,
    Table,
    Text,
    literal_column,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID

MAX_IDENTIFIER_LENGTH = 63
"""PostgreSQL's limit on identifier length in bytes; longer names are truncated."""

DEFAULT_INDEXES: frozenset[str] = frozenset(
    {"severity", "actor", "object", "target", "scope", "transaction", "correlation"}
)
"""Keys of the ``audit_activity`` indexes created unless ``indexes`` says otherwise."""

OPTIONAL_INDEXES: frozenset[str] = frozenset({"changes_gin"})
"""Keys of the indexes that exist but are off by default."""

ALL_INDEXES: frozenset[str] = DEFAULT_INDEXES | OPTIONAL_INDEXES
"""Every valid key for ``build_tables(indexes=...)``."""

# Longest suffix a partition name gets: "_<smallint>_pYYYY_MM".
_PARTITION_SUFFIX_LENGTH = len("_-32768_p2026_01")


@dataclass(frozen=True)
class AuditTables:
    """The audit tables and the metadata they are bound to.

    Attributes:
        metadata: Metadata holding both tables and the activity indexes.
        transaction: The ``audit_transaction`` table.
        activity: The ``audit_activity`` table.
    """

    metadata: MetaData
    transaction: Table
    activity: Table


def build_tables(
    *,
    schema: str = "audit",
    transaction_table: str = "audit_transaction",
    activity_table: str = "audit_activity",
    indexes: Collection[str] | None = None,
) -> AuditTables:
    """Build the audit tables in a new ``MetaData``.

    Args:
        schema: Schema holding the tables.
        transaction_table: Name of the transaction (context) table.
        activity_table: Name of the activity (event) table.
        indexes: Keys of the ``audit_activity`` indexes to create, from
            ``ALL_INDEXES``. ``None`` uses ``DEFAULT_INDEXES``. ``changes_gin``
            is a GIN index on ``data -> 'changes'`` and is off by default.

    Returns:
        The tables and their metadata.

    Raises:
        ValueError: If a name is empty or too long for PostgreSQL once a
            partition suffix is added, the table names are equal, or an index
            key is unknown.
    """
    _check_name(schema, "schema", 0)
    _check_name(transaction_table, "transaction_table", _PARTITION_SUFFIX_LENGTH)
    _check_name(activity_table, "activity_table", _PARTITION_SUFFIX_LENGTH)
    if transaction_table == activity_table:
        raise ValueError("transaction_table and activity_table must differ")
    index_keys = DEFAULT_INDEXES if indexes is None else frozenset(indexes)
    unknown = index_keys - ALL_INDEXES
    if unknown:
        raise ValueError(f"unknown index keys: {sorted(unknown)}")

    metadata = MetaData(schema=schema)
    transaction = Table(
        transaction_table,
        metadata,
        Column("id", BigInteger, Identity(always=True), nullable=False),
        Column(
            "issued_at",
            DateTime(timezone=True),
            nullable=False,
            server_default=text("now()"),
        ),
        Column("actor_type", Text, nullable=False),
        Column("actor_id", Text),
        Column("actor_label", Text),
        Column("remote_addr", INET),
        Column("user_agent", Text),
        Column("method", Text),
        Column("path", Text),
        Column("channel", Text),
        Column("auth_method", Text),
        Column("request_id", UUID(as_uuid=True)),
        Column("correlation_id", UUID(as_uuid=True)),
        Column("meta", JSONB),
        PrimaryKeyConstraint("id", "issued_at", name=f"{transaction_table}_pkey"),
        postgresql_partition_by="RANGE (issued_at)",
    )
    activity = Table(
        activity_table,
        metadata,
        Column("id", BigInteger, Identity(always=True), nullable=False),
        Column("transaction_id", BigInteger, nullable=False),
        Column("verb", Text, nullable=False),
        Column("severity", SmallInteger, nullable=False),
        Column("object_type", Text),
        Column("object_id", Text),
        Column("object_label", Text),
        Column("target_type", Text),
        Column("target_id", Text),
        Column("actor_id", Text),
        Column("scope_id", Text),
        Column("correlation_id", UUID(as_uuid=True)),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("data", JSONB, nullable=False, server_default=text("'{}'::jsonb")),
        PrimaryKeyConstraint(
            "id", "severity", "created_at", name=f"{activity_table}_pkey"
        ),
        postgresql_partition_by="LIST (severity)",
    )
    for key in sorted(index_keys):
        _activity_index(activity, key)
    return AuditTables(metadata=metadata, transaction=transaction, activity=activity)


def _activity_index(table: Table, key: str) -> Index:
    c = table.c
    name = f"{table.name}_{key}_idx"
    newest_first = (c.created_at.desc(), c.id.desc())
    if key == "severity":
        return Index(name, c.severity, *newest_first)
    if key == "actor":
        return Index(name, c.actor_id, *newest_first)
    if key == "object":
        return Index(name, c.object_type, c.object_id, *newest_first)
    if key == "target":
        return Index(
            name,
            c.target_type,
            c.target_id,
            *newest_first,
            postgresql_where=c.target_type.is_not(None),
        )
    if key == "scope":
        return Index(
            name, c.scope_id, *newest_first, postgresql_where=c.scope_id.is_not(None)
        )
    if key == "transaction":
        return Index(name, c.transaction_id, c.created_at)
    if key == "correlation":
        return Index(
            name,
            c.correlation_id,
            c.created_at,
            postgresql_where=c.correlation_id.is_not(None),
        )
    # changes_gin. Default jsonb_ops, not jsonb_path_ops: only jsonb_ops
    # supports the key-exists operator ? used by "who changed field X" queries
    # (data -> 'changes' ? 'x'). Spelled with -> so the planner matches such
    # queries; SQLAlchemy's data["changes"] renders the subscript data['changes'].
    changes = c.data.op("->", return_type=JSONB)(literal_column("'changes'"))
    return Index(name, changes, postgresql_using="gin")


def _check_name(name: str, what: str, reserve: int) -> None:
    if not name:
        raise ValueError(f"{what} must not be empty")
    limit = MAX_IDENTIFIER_LENGTH - reserve
    if len(name.encode()) > limit:
        raise ValueError(
            f"{what} {name!r} is longer than {limit} bytes; PostgreSQL would "
            "truncate the names derived from it"
        )
