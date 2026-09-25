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

from collections.abc import Iterable
from datetime import date, datetime, timezone

from sqlalchemy import Connection
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.schema import CreateIndex, CreateTable

from audit_trail.tables import AuditTables

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
    start = datetime(month.year, month.month, 1, tzinfo=timezone.utc)
    if month.month == 12:
        end = datetime(month.year + 1, 1, 1, tzinfo=timezone.utc)
    else:
        end = datetime(month.year, month.month + 1, 1, tzinfo=timezone.utc)
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
    the ones created later.

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
    for table in (tables.transaction, tables.activity):
        statements.append(_compile(CreateTable(table)))
    statements.extend(
        create_severity_partition_sql(tables, value)
        for value in severity_values(severities)
    )
    for table in (tables.transaction, tables.activity):
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
    return [
        f"DROP TABLE IF EXISTS {qualified_name(t.schema, t.name)}"
        for t in (tables.activity, tables.transaction)
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
        _execute_ddl(connection, statement)


def drop_audit_tables(connection: Connection, tables: AuditTables) -> None:
    """Execute ``drop_statements`` on ``connection``.

    Args:
        connection: Connection to run on, such as Alembic's ``op.get_bind()``.
        tables: The audit tables.
    """
    for statement in drop_statements(tables):
        _execute_ddl(connection, statement)


def _execute_ddl(connection: Connection, statement: str) -> None:
    """Execute one DDL statement from this module as-is.

    The statement goes to the driver without parameters, so ``%`` and ``:``
    inside quoted names are not taken for placeholders.

    Args:
        connection: Connection to run on.
        statement: A statement built by this module.
    """
    connection.exec_driver_sql(statement, execution_options={"no_parameters": True})


def _compile(element: CreateTable | CreateIndex) -> str:
    return str(element.compile(dialect=_DIALECT)).strip()


def _script(statements: list[str]) -> str:
    return "".join(f"{statement};\n" for statement in statements)


def _timestamptz(value: datetime) -> str:
    # Explicit +00 offset: the literal means the same instant in any TimeZone.
    return f"'{value.astimezone(timezone.utc):%Y-%m-%d %H:%M:%S}+00'"
