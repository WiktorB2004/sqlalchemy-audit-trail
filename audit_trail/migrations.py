"""Alembic helpers and DDL for the partitioned audit tables.

Alembic's autogenerate does not understand partitioning, so the audit tables
are created from this module instead. Nothing here imports Alembic; in a
migration::

    from audit_trail import migrations
    from audit_trail.tables import build_tables

    tables = build_tables(schema="audit")

    def upgrade() -> None:
        migrations.create_audit_tables(op.get_bind(), tables, MySeverity)

    def downgrade() -> None:
        migrations.drop_audit_tables(op.get_bind(), tables)

``create_sql`` renders the same DDL as a plain SQL script. Passing
``create_statements`` to ``op.execute`` also works, unless a schema or table
name contains ``:``, which ``op.execute`` would read as a bind parameter.

The DDL creates the partitioned parents, one partition per severity and the
indexes, but no monthly partitions: those depend on the date the code runs,
not the date the migration was written. Run
``audit_trail.maintenance.ensure_partitions`` (or ``PartitionManager``) after
migrating and before the first write; until then every insert fails with
SQLSTATE ``23514``.

Naming:

* severity partition: ``<activity table>_<severity value>``, for example
  ``audit_activity_10``;
* monthly partition: ``<parent>_pYYYY_MM``, where the parent is the
  transaction table or a severity partition, for example
  ``audit_transaction_p2026_09`` and ``audit_activity_10_p2026_09``.

Monthly bounds are UTC-anchored ``timestamptz`` literals: the partition for
September 2026 holds ``['2026-09-01 00:00:00+00', '2026-10-01 00:00:00+00')``
whatever the session or server time zone.
"""

from __future__ import annotations

import logging
import random
import time
from collections.abc import Callable, Iterable
from datetime import UTC, date, datetime

from sqlalchemy import Connection, MetaData, text
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.exc import DBAPIError
from sqlalchemy.schema import CreateIndex, CreateTable

from audit_trail import _pg
from audit_trail.integrity import _schema as integrity_schema
from audit_trail.integrity import _seal
from audit_trail.integrity._seal import Genesis
from audit_trail.integrity._sign import Signer
from audit_trail.tables import AuditTables

logger = logging.getLogger(__name__)

# With the "named" paramstyle a "%" in a name is not doubled.
_DIALECT = PGDialect(paramstyle="named")  # type: ignore[no-untyped-call]
_PREPARER = _DIALECT.identifier_preparer


def severity_values(severities: Iterable[int]) -> list[int]:
    """Return the distinct severity values, sorted.

    Args:
        severities: A severity ``IntEnum`` class, or any iterable of ints.

    Returns:
        The values as plain ints.
    """
    return sorted({int(s) for s in severities})


def severity_partition_name(activity_table: str, severity: int) -> str:
    """Name of the partition holding one severity.

    Args:
        activity_table: Name of the activity table.
        severity: Severity value.

    Returns:
        ``<activity_table>_<severity>``.
    """
    return f"{activity_table}_{int(severity)}"


def month_partition_name(parent: str, month: date) -> str:
    """Name of a monthly partition.

    Args:
        parent: Name of the partitioned parent: the transaction table or a
            severity partition.
        month: Any day of the month.

    Returns:
        ``<parent>_pYYYY_MM``.
    """
    return f"{parent}_p{month.year:04d}_{month.month:02d}"


def month_bounds(month: date) -> tuple[datetime, datetime]:
    """UTC bounds of a month.

    Args:
        month: Any day of the month.

    Returns:
        The first instant of the month and of the next one, both in UTC.
    """
    start = datetime(month.year, month.month, 1, tzinfo=UTC)
    if month.month == 12:
        end = datetime(month.year + 1, 1, 1, tzinfo=UTC)
    else:
        end = datetime(month.year, month.month + 1, 1, tzinfo=UTC)
    return start, end


def qualified_name(schema: str | None, name: str) -> str:
    """Quote ``schema.name`` for use in DDL.

    Args:
        schema: Schema name, or ``None`` for the search path.
        name: Table name.

    Returns:
        The quoted, schema-qualified name.
    """
    quoted = _PREPARER.quote(name)
    if schema is None:
        return quoted
    return f"{_PREPARER.quote_schema(schema)}.{quoted}"


def create_severity_partition_sql(
    tables: AuditTables, severity: int, name: str | None = None
) -> str:
    """DDL for one severity partition of the activity table.

    The partition is itself partitioned by ``created_at`` and holds no rows
    until its monthly partitions exist.

    Args:
        tables: The audit tables.
        severity: Severity value.
        name: Partition name. ``None`` uses ``severity_partition_name``.

    Returns:
        A ``CREATE TABLE ... PARTITION OF`` statement.
    """
    activity = tables.activity
    name = name or severity_partition_name(activity.name, severity)
    return (
        f"CREATE TABLE {qualified_name(activity.schema, name)} "
        f"PARTITION OF {qualified_name(activity.schema, activity.name)} "
        f"FOR VALUES IN ({int(severity)}) PARTITION BY RANGE (created_at)"
    )


def create_month_partition_sql(
    schema: str | None, parent: str, month: date, name: str | None = None
) -> str:
    """DDL for one monthly partition.

    Args:
        schema: Schema of the parent; the partition goes in the same one.
        parent: Name of the partitioned parent: the transaction table or a
            severity partition.
        month: Any day of the month.
        name: Partition name. ``None`` uses ``month_partition_name``.

    Returns:
        A ``CREATE TABLE ... PARTITION OF ... FOR VALUES FROM ... TO ...``
        statement with UTC bounds.
    """
    start, end = month_bounds(month)
    name = name or month_partition_name(parent, month)
    return (
        f"CREATE TABLE {qualified_name(schema, name)} "
        f"PARTITION OF {qualified_name(schema, parent)} "
        f"FOR VALUES FROM ({_timestamptz(start)}) TO ({_timestamptz(end)})"
    )


def create_statements(tables: AuditTables, severities: Iterable[int]) -> list[str]:
    """DDL creating the audit tables, their severity partitions and indexes.

    No monthly partition is created: run
    ``audit_trail.maintenance.ensure_partitions`` before the first write, or
    every insert fails with SQLSTATE ``23514``. Indexes are created on the
    partitioned parents, so PostgreSQL adds them to every partition, including
    the ones created later. Tables built with integrity also get the table of
    sealed blocks.

    Args:
        tables: The audit tables, from ``build_tables``.
        severities: A severity ``IntEnum`` class, or any iterable of ints.

    Returns:
        The statements, in order, without trailing semicolons.
    """
    statements: list[str] = []
    schema = tables.metadata.schema
    if schema is not None:
        statements.append(
            f"CREATE SCHEMA IF NOT EXISTS {_PREPARER.quote_schema(schema)}"
        )
    block = tables.seal_block
    created = [tables.transaction, tables.activity, *([] if block is None else [block])]
    for table in created:
        statements.append(_compile(CreateTable(table)))
    statements.extend(
        create_severity_partition_sql(tables, value)
        for value in severity_values(severities)
    )
    for table in created:
        statements.extend(
            _compile(CreateIndex(index))
            for index in sorted(table.indexes, key=lambda i: str(i.name))
        )
    return statements


def drop_statements(tables: AuditTables) -> list[str]:
    """DDL dropping the audit tables with all their partitions.

    The schema itself is kept.

    Args:
        tables: The audit tables.

    Returns:
        The statements, in order, without trailing semicolons.
    """
    block = tables.seal_block
    return [
        f"DROP TABLE IF EXISTS {qualified_name(t.schema, t.name)}"
        for t in (
            *([] if block is None else [block]),
            tables.activity,
            tables.transaction,
        )
    ]


def create_sql(tables: AuditTables, severities: Iterable[int]) -> str:
    """``create_statements`` as one SQL script.

    Args:
        tables: The audit tables, from ``build_tables``.
        severities: A severity ``IntEnum`` class, or any iterable of ints.

    Returns:
        The statements, each terminated by a semicolon.
    """
    return _script(create_statements(tables, severities))


def drop_sql(tables: AuditTables) -> str:
    """``drop_statements`` as one SQL script.

    Args:
        tables: The audit tables.

    Returns:
        The statements, each terminated by a semicolon.
    """
    return _script(drop_statements(tables))


def create_audit_tables(
    connection: Connection, tables: AuditTables, severities: Iterable[int]
) -> None:
    """Execute ``create_statements`` on ``connection``.

    Runs in the connection's current transaction; the caller commits. Run
    ``audit_trail.maintenance.ensure_partitions`` before the first write.

    Args:
        connection: Connection to run on, such as Alembic's ``op.get_bind()``.
        tables: The audit tables, from ``build_tables``.
        severities: A severity ``IntEnum`` class, or any iterable of ints.
    """
    for statement in create_statements(tables, severities):
        _pg.execute_ddl(connection, statement)


def drop_audit_tables(connection: Connection, tables: AuditTables) -> None:
    """Execute ``drop_statements`` on ``connection``.

    Args:
        connection: Connection to run on, such as Alembic's ``op.get_bind()``.
        tables: The audit tables.
    """
    for statement in drop_statements(tables):
        _pg.execute_ddl(connection, statement)


def add_integrity_statements(tables: AuditTables) -> list[str]:
    """DDL adding the integrity columns to existing audit tables.

    On both parents (PostgreSQL adds the columns to every partition): ``xid``
    and the ``seal_*`` columns in one ``ALTER``, then the ``xid`` default in
    a second one. The default must be a statement of its own:
    ``pg_current_xact_id()`` is ``STABLE``, so ``ADD COLUMN ... DEFAULT
    pg_current_xact_id()`` would stamp every existing row with the
    migration's own ``xid``. Existing rows keep ``xid`` ``NULL``, and the
    column stays nullable. Last, the table of sealed blocks (named by
    ``build_tables(seal_block_table=...)``, also for tables built without
    integrity) and its index, in the schema of the transaction table. Every
    statement is idempotent. The ``(xid, id)`` indexes are not here:
    ``add_integrity_indexes`` builds them online.

    Args:
        tables: The audit tables.

    Returns:
        The statements, in order, without trailing semicolons.
    """
    statements: list[str] = []
    for table in (tables.transaction, tables.activity):
        name = qualified_name(table.schema, table.name)
        added = ", ".join(
            [
                f"ADD COLUMN IF NOT EXISTS {integrity_schema.XID} xid8",
                *(
                    f"ADD COLUMN IF NOT EXISTS {column} jsonb"
                    for column in integrity_schema.SEAL_COLUMNS
                ),
            ]
        )
        statements.append(f"ALTER TABLE {name} {added}")
        statements.append(
            f"ALTER TABLE {name} ALTER COLUMN {integrity_schema.XID} "
            f"SET DEFAULT {integrity_schema.XID_DEFAULT}"
        )
    block = tables.seal_block
    if block is None:
        block = integrity_schema.block_table(
            MetaData(schema=tables.transaction.schema), tables.seal_block_table
        )
    statements.append(_compile(CreateTable(block, if_not_exists=True)))
    statements.extend(
        _compile(CreateIndex(index, if_not_exists=True))
        for index in sorted(block.indexes, key=lambda i: str(i.name))
    )
    return statements


def add_integrity(
    connection: Connection,
    tables: AuditTables,
    *,
    lock_timeout: str = "2s",
    attempts: int = 5,
) -> None:
    """Add the integrity columns to existing audit tables.

    The first of two steps; ``add_integrity_indexes`` is the second. Executes
    ``add_integrity_statements`` in a savepoint of the connection's current
    transaction; the caller commits. The ``ALTER`` statements take an
    ``ACCESS EXCLUSIVE`` lock on each parent and its partitions, without
    rewriting or scanning them, so the lock is held only briefly. While one
    waits for that lock, new audit writes queue behind it, so the wait is
    capped by ``lock_timeout``; on a timeout (SQLSTATE ``55P03``) the
    savepoint is rolled back, which changes nothing, and the statements are
    retried after a random pause. The transaction's own ``lock_timeout`` is
    restored afterwards, also when this raises. Running it again later is
    safe.

    In an Alembic migration::

        def upgrade() -> None:
            migrations.add_integrity(op.get_bind(), tables)
            with op.get_context().autocommit_block():
                migrations.add_integrity_indexes(op.get_bind(), tables)

    Args:
        connection: Connection with DDL privileges, not in ``AUTOCOMMIT``.
        tables: The audit tables.
        lock_timeout: PostgreSQL ``lock_timeout`` of each attempt.
        attempts: Attempts before giving up, at least 1.

    Raises:
        ValueError: ``attempts`` is below 1, or the connection is in
            ``AUTOCOMMIT`` mode.
        DBAPIError: A statement failed, or the last attempt still timed out.
    """
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    if _is_autocommit(connection):
        raise ValueError("add_integrity needs a transaction, not AUTOCOMMIT")
    statements = add_integrity_statements(tables)

    def alter() -> None:
        with connection.begin_nested():
            for statement in statements:
                _pg.execute_ddl(connection, statement)

    previous = _pg.set_config(connection, "lock_timeout", lock_timeout, local=True)
    try:
        _retry("add_integrity", alter, lock_timeout, attempts)
    finally:
        # A broken connection is discarded by the pool; touching it would
        # hide the real error.
        if not connection.invalidated:
            _pg.set_config(connection, "lock_timeout", previous, local=True)


def add_integrity_indexes(
    connection: Connection,
    tables: AuditTables,
    *,
    lock_timeout: str = "2s",
    attempts: int = 5,
) -> list[str]:
    """Build the ``(xid, id)`` indexes of the integrity columns online.

    The second step after ``add_integrity``; a fresh install made with
    integrity on already has the indexes, and this does nothing there. The
    index of a partitioned table cannot be built ``CONCURRENTLY``, so it is
    built the way PostgreSQL documents for partitioned tables, from the top:

    1. ``CREATE INDEX IF NOT EXISTS ... ON ONLY`` the parent (and each
       severity partition, which is partitioned by month) creates an empty,
       invalid index. It takes a ``SHARE`` lock on that table alone, which
       waits for open transactions that wrote audit rows and holds up new
       writes while it waits, but reads no rows, so it is held only briefly.
    2. ``CREATE INDEX CONCURRENTLY`` on each monthly partition builds its
       index. It takes ``SHARE UPDATE EXCLUSIVE`` on that partition, which
       lets reads and writes go on. It waits for every older transaction in
       the database to end, so it runs without a ``lock_timeout``; a build
       that failed leaves an invalid index, which the next call drops (with
       ``DROP INDEX CONCURRENTLY``) and builds again.
    3. ``ALTER INDEX ... ATTACH PARTITION`` attaches it to the parent's
       index. It takes ``SHARE UPDATE EXCLUSIVE`` on the parent's index and
       ``ACCESS EXCLUSIVE`` on the partition's index, which waits for writes
       to that partition, but only briefly. Once every partition's index is
       attached, PostgreSQL marks the parent's index valid.

    The waits of steps 1 and 3 are capped by ``lock_timeout``; a statement
    that times out (SQLSTATE ``55P03``) is retried after a random pause, up
    to ``attempts`` times. The session's ``lock_timeout`` is restored
    afterwards, also when this raises. Every step is idempotent, so running
    it again after a failure finishes the job.

    Args:
        connection: ``AUTOCOMMIT`` connection with DDL privileges, on tables
            that ``add_integrity`` has already changed.
        tables: The audit tables.
        lock_timeout: PostgreSQL ``lock_timeout`` of each attempt of the
            statements of steps 1 and 3.
        attempts: Attempts per statement before giving up, at least 1.

    Returns:
        Schema-qualified names of the partition indexes built by this call.

    Raises:
        ValueError: ``attempts`` is below 1, the connection is not in
            ``AUTOCOMMIT`` mode, an audit table does not exist, or an index
            name is taken by an index on another table.
        DBAPIError: A statement failed, or its last attempt still timed out.
    """
    if attempts < 1:
        raise ValueError("attempts must be at least 1")
    if not _is_autocommit(connection):
        raise ValueError(
            "add_integrity_indexes needs an AUTOCOMMIT connection: CREATE "
            "INDEX CONCURRENTLY cannot run inside a transaction block"
        )
    builder = _IndexBuilder(connection, lock_timeout, attempts)
    previous = _pg.set_config(connection, "lock_timeout", lock_timeout, local=False)
    try:
        for table in (tables.transaction, tables.activity):
            oid: int | None = connection.execute(
                text("SELECT to_regclass(:name)::oid"),
                {"name": qualified_name(table.schema, table.name)},
            ).scalar_one()
            if oid is None:
                raise ValueError(
                    f"table {qualified_name(table.schema, table.name)} does "
                    "not exist; create the audit tables first"
                )
            builder.partitioned(oid, integrity_schema.xid_index_name(table.name))
    finally:
        if not connection.invalidated:
            _pg.set_config(connection, "lock_timeout", previous, local=False)
    return builder.built


def write_genesis(
    connection: Connection, tables: AuditTables, *, signer: Signer | None = None
) -> Genesis:
    """Start the hash chain of the audit log with its genesis block.

    The last step of turning integrity on, after ``add_integrity`` and
    ``add_integrity_indexes``, and only once every writer runs with
    ``Integrity``. The block records ``enforce_from``, the horizon
    ``pg_snapshot_xmin(pg_current_snapshot())`` at this moment: rows with a
    lower ``xid`` are out of scope, and every later row must carry
    commitments. Calling it again returns the existing genesis block, also
    when another call committed it after this transaction's snapshot was
    taken. It takes the sealer's advisory lock and runs in the connection's
    current transaction; the caller commits.

    Args:
        connection: Connection that may insert into the block table, not in
            ``AUTOCOMMIT`` mode.
        tables: Audit tables built with integrity.
        signer: Signs the block; ``None`` leaves it unsigned.

    Returns:
        The genesis block, and whether this call wrote it.

    Raises:
        ValueError: The tables were built without integrity, the connection
            is in ``AUTOCOMMIT`` mode, the block table does not exist yet
            (run ``add_integrity`` first), or it holds blocks but no genesis
            block. The transaction stays usable.
    """
    return _seal.write_genesis(connection, tables, signer=signer)


_TABLE = text(
    """
    SELECT n.nspname, c.relname
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE c.oid = :oid
    """
)

_CHILDREN = text(
    """
    SELECT c.oid, n.nspname, c.relname, c.relkind::text
    FROM pg_catalog.pg_inherits i
    JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE i.inhparent = :parent
    ORDER BY c.relname
    """
)

# The index named :name in the schema of table :table, on that table.
_INDEX = text(
    """
    SELECT x.indexrelid::oid, x.indisvalid
    FROM pg_catalog.pg_index x
    JOIN pg_catalog.pg_class ic ON ic.oid = x.indexrelid
    WHERE x.indrelid = :table AND ic.relname = :name
    """
)

# The index of table :table attached to index :parent, if any.
_ATTACHED = text(
    """
    SELECT ic.relname
    FROM pg_catalog.pg_inherits h
    JOIN pg_catalog.pg_index x ON x.indexrelid = h.inhrelid
    JOIN pg_catalog.pg_class ic ON ic.oid = h.inhrelid
    WHERE h.inhparent = :parent AND x.indrelid = :table
    """
)


class _IndexBuilder:
    """The recursive steps of ``add_integrity_indexes``."""

    def __init__(self, connection: Connection, lock_timeout: str, attempts: int):
        self.connection = connection
        self.lock_timeout = lock_timeout
        self.attempts = attempts
        self.built: list[str] = []

    def partitioned(self, table: int, index: str) -> int:
        """Create the ``ON ONLY`` index of a partitioned table, fill it in."""
        schema, name = self._names(table)
        quoted = qualified_name(schema, name)
        self._short(
            f"CREATE INDEX IF NOT EXISTS {_PREPARER.quote(index)} ON ONLY "
            f"{quoted} ({_XID_KEY})"
        )
        index_oid = self._index(table, index)
        if index_oid is None:
            raise ValueError(
                f"index {index} exists in schema {schema}, but not on {name}"
            )
        children = self.connection.execute(_CHILDREN, {"parent": table}).all()
        for child, child_schema, child_name, kind in children:
            attached: str | None = self.connection.execute(
                _ATTACHED, {"parent": index_oid, "table": child}
            ).scalar_one_or_none()
            child_index = attached or integrity_schema.xid_index_name(child_name)
            if kind == "p":
                self.partitioned(child, child_index)
            elif attached is None:
                self._leaf(child, child_schema, child_name, child_index)
            if attached is None:
                self._short(
                    f"ALTER INDEX {qualified_name(schema, index)} ATTACH "
                    f"PARTITION {qualified_name(child_schema, child_index)}"
                )
        return index_oid

    def _leaf(self, table: int, schema: str, name: str, index: str) -> None:
        existing = self.connection.execute(
            _INDEX, {"table": table, "name": index}
        ).one_or_none()
        if existing is not None and existing.indisvalid:
            return
        _pg.set_config(self.connection, "lock_timeout", "0", local=False)
        try:
            if existing is not None:
                # Left invalid by a build that failed.
                _pg.execute_ddl(
                    self.connection,
                    f"DROP INDEX CONCURRENTLY IF EXISTS "
                    f"{qualified_name(schema, index)}",
                )
            _pg.execute_ddl(
                self.connection,
                f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {_PREPARER.quote(index)} "
                f"ON {qualified_name(schema, name)} ({_XID_KEY})",
            )
        finally:
            if not self.connection.invalidated:
                _pg.set_config(
                    self.connection, "lock_timeout", self.lock_timeout, local=False
                )
        self.built.append(f"{schema}.{index}")

    def _short(self, statement: str) -> None:
        _retry(
            "add_integrity_indexes",
            lambda: _pg.execute_ddl(self.connection, statement),
            self.lock_timeout,
            self.attempts,
        )

    def _names(self, table: int) -> tuple[str, str]:
        schema, name = self.connection.execute(_TABLE, {"oid": table}).one()
        return schema, name

    def _index(self, table: int, name: str) -> int | None:
        row = self.connection.execute(
            _INDEX, {"table": table, "name": name}
        ).one_or_none()
        return None if row is None else int(row.indexrelid)


_XID_KEY = f"{integrity_schema.XID}, id"

# The first retry pauses up to this many seconds, each later one twice as long.
_RETRY_PAUSE = 0.5
_sleep = time.sleep


def _retry(
    name: str, action: Callable[[], None], lock_timeout: str, attempts: int
) -> None:
    """Run ``action``, again after a random pause when it hits ``lock_timeout``."""
    for attempt in range(1, attempts + 1):
        try:
            action()
            return
        except DBAPIError as exc:
            if attempt == attempts or not _pg.is_sqlstate(exc, _pg.LOCK_NOT_AVAILABLE):
                raise
            pause = random.uniform(0, _RETRY_PAUSE * 2 ** (attempt - 1))
            logger.warning(
                "%s: a lock was not granted within lock_timeout=%r "
                "(attempt %d of %d); retrying in %.2f s.",
                name,
                lock_timeout,
                attempt,
                attempts,
                pause,
            )
            _sleep(pause)


def _is_autocommit(connection: Connection) -> bool:
    return bool(getattr(connection.connection.dbapi_connection, "autocommit", False))


def _compile(element: CreateTable | CreateIndex) -> str:
    return str(element.compile(dialect=_DIALECT)).strip()


def _script(statements: list[str]) -> str:
    return "".join(f"{statement};\n" for statement in statements)


def _timestamptz(value: datetime) -> str:
    # Explicit +00 offset: the literal means the same instant in any TimeZone.
    return f"'{value.astimezone(UTC):%Y-%m-%d %H:%M:%S}+00'"
