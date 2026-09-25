"""Partition management, retention and health checks.

``ensure_partitions`` creates the partitions writes will need: every
severity partition of the activity table, and the monthly partitions of the
transaction table and of each severity partition, from the current UTC month
``months_ahead`` months forward. There is no ``DEFAULT`` partition, so a row
without a partition fails with SQLSTATE ``23514``; run it on a schedule
(cron, worker, application start) with enough months ahead to cover a missed
run.

Existing partitions are found by their bounds in the catalog, not by name: a
partition created by hand or by another tool under a different name, with the
same (or wider) bounds, counts as present. Names and bounds are described in
``audit_trail.migrations``.

Locking: ``CREATE TABLE ... PARTITION OF`` takes an ``ACCESS EXCLUSIVE`` lock
on the parent, so it waits for every open transaction that has touched the
parent, including business transactions with uncommitted audit rows. Under
PostgreSQL's documented lock queueing, later lock requests that conflict with
the waiting one, such as new audit inserts, queue behind it. ``lock_timeout``
bounds that wait: past it the whole call is rolled back and
``PartitionLockTimeoutError`` is raised; retrying later is safe.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import Connection, Engine, bindparam, text
from sqlalchemy.exc import DBAPIError

from audit_trail.migrations import (
    _execute_ddl,
    create_month_partition_sql,
    create_severity_partition_sql,
    month_bounds,
    month_partition_name,
    qualified_name,
    severity_partition_name,
    severity_values,
)
from audit_trail.tables import MAX_IDENTIFIER_LENGTH, AuditTables

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncEngine

LOCK_NOT_AVAILABLE = "55P03"
"""SQLSTATE raised when ``lock_timeout`` expires."""

_RANGE_BOUND = r"^FOR VALUES FROM \((.*)\) TO \((.*)\)$"
_LIST_BOUND = re.compile(r"^FOR VALUES IN \((.*)\)$")

# Bounds are cast back to timestamptz in the same statement that renders them,
# so the round trip is exact whatever the session's TimeZone and DateStyle.
# MINVALUE / MAXVALUE come out as NULL, meaning unbounded.
_CHILDREN = text(
    """
    SELECT oid, nspname, relname, relkind, bound, m IS NOT NULL AS is_range,
           CASE WHEN m[1] LIKE '''%' THEN btrim(m[1], '''')::timestamptz END
               AS lower,
           CASE WHEN m[2] LIKE '''%' THEN btrim(m[2], '''')::timestamptz END
               AS upper
    FROM (
        SELECT c.oid, n.nspname, c.relname, c.relkind::text AS relkind, b.bound,
               regexp_match(b.bound, :range_pattern) AS m
        FROM pg_catalog.pg_inherits i
        JOIN pg_catalog.pg_class c ON c.oid = i.inhrelid
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL pg_catalog.pg_get_expr(c.relpartbound, c.oid) AS b(bound)
        WHERE i.inhparent = :parent
    ) s
    """
).bindparams(bindparam("range_pattern", _RANGE_BOUND))


class PartitionError(Exception):
    """Partition maintenance could not be done."""


class PartitionLockTimeoutError(PartitionError):
    """A lock needed to create partitions was not granted within ``lock_timeout``.

    Nothing was created. Retry later; ``months_ahead`` leaves room for that.
    """


@dataclass(frozen=True)
class _Child:
    oid: int
    schema: str
    name: str
    relkind: str
    bound: str
    is_range: bool
    lower: datetime | None
    upper: datetime | None

    def covers(self, start: datetime, end: datetime) -> bool:
        return (
            self.is_range
            and (self.lower is None or self.lower <= start)
            and (self.upper is None or self.upper >= end)
        )

    def list_values(self) -> set[int]:
        match = _LIST_BOUND.match(self.bound)
        if match is None:
            return set()
        values = (v.strip().strip("'") for v in match.group(1).split(","))
        return {int(v) for v in values if v.lstrip("-").isdigit()}


def ensure_partitions(
    connection: Connection,
    tables: AuditTables,
    severities: Iterable[int],
    *,
    months_ahead: int = 3,
    now: datetime | None = None,
    lock_timeout: str | None = "5s",
) -> list[str]:
    """Create the missing severity and monthly partitions.

    Covers the UTC month of ``now`` and the ``months_ahead`` months after it,
    for the transaction table and for every severity. Idempotent: a partition
    that already exists with the same or wider bounds, under any name, is
    left alone.

    Runs in the connection's current transaction, which must not be
    ``AUTOCOMMIT``; the caller commits, or rolls back on error. Concurrent
    calls are serialized with a transaction-level advisory lock.

    Args:
        connection: Connection with DDL privileges.
        tables: The audit tables, from ``audit_trail.tables.build_tables``.
        severities: A severity ``IntEnum`` class, or any iterable of ints.
        months_ahead: Months to create after the current one.
        now: Reference time. ``None`` uses the database's ``now()``.
        lock_timeout: PostgreSQL ``lock_timeout`` for this transaction, such
            as ``"5s"``. ``None`` keeps the session's setting.

    Returns:
        Schema-qualified names of the partitions created, parents first.

    Raises:
        ValueError: If ``months_ahead`` is negative or the connection is in
            ``AUTOCOMMIT`` mode.
        PartitionError: If a parent table does not exist, or a monthly
            partition name derived from an existing severity partition would
            be longer than PostgreSQL allows.
        PartitionLockTimeoutError: If a lock was not granted within
            ``lock_timeout``; the transaction must be rolled back.
    """
    if months_ahead < 0:
        raise ValueError("months_ahead must not be negative")
    if getattr(connection.connection.dbapi_connection, "autocommit", False):
        raise ValueError("ensure_partitions needs a transaction, not AUTOCOMMIT")
    try:
        return _ensure(
            connection,
            tables,
            severity_values(severities),
            months_ahead,
            now,
            lock_timeout,
        )
    except DBAPIError as exc:
        if getattr(exc.orig, "sqlstate", None) == LOCK_NOT_AVAILABLE:
            raise PartitionLockTimeoutError(
                f"partitions were not created: a lock was not granted within "
                f"lock_timeout={lock_timeout!r}; retry later"
            ) from exc
        raise


class PartitionManager:
    """Creates partitions on the library's own connection and transaction.

    Args:
        engine: Sync or async engine with DDL privileges. Must not be
            configured for ``AUTOCOMMIT``.
        tables: The audit tables, from ``audit_trail.tables.build_tables``.
        severities: A severity ``IntEnum`` class, or any iterable of ints.
    """

    def __init__(
        self,
        engine: Engine | AsyncEngine,
        tables: AuditTables,
        severities: Iterable[int],
    ) -> None:
        self.engine = engine
        self.tables = tables
        self.severities = severity_values(severities)

    def ensure_partitions(
        self, months_ahead: int = 3, *, lock_timeout: str | None = "5s"
    ) -> list[str]:
        """Create missing partitions in one transaction; see ``ensure_partitions``.

        Args:
            months_ahead: Months to create after the current UTC month.
            lock_timeout: PostgreSQL ``lock_timeout`` for the transaction.

        Returns:
            Schema-qualified names of the partitions created.

        Raises:
            TypeError: If the manager was built with an ``AsyncEngine``.
            PartitionLockTimeoutError: If a lock was not granted in time.
        """
        if not isinstance(self.engine, Engine):
            raise TypeError("the engine is async; use aensure_partitions")
        with self.engine.begin() as conn:
            return ensure_partitions(
                conn,
                self.tables,
                self.severities,
                months_ahead=months_ahead,
                lock_timeout=lock_timeout,
            )

    async def aensure_partitions(
        self, months_ahead: int = 3, *, lock_timeout: str | None = "5s"
    ) -> list[str]:
        """Async ``ensure_partitions``, for a manager built with an ``AsyncEngine``.

        Args:
            months_ahead: Months to create after the current UTC month.
            lock_timeout: PostgreSQL ``lock_timeout`` for the transaction.

        Returns:
            Schema-qualified names of the partitions created.

        Raises:
            TypeError: If the manager was built with a sync ``Engine``.
            PartitionLockTimeoutError: If a lock was not granted in time.
        """
        if isinstance(self.engine, Engine):
            raise TypeError("the engine is sync; use ensure_partitions")
        async with self.engine.begin() as conn:
            return await conn.run_sync(
                lambda sync_conn: ensure_partitions(
                    sync_conn,
                    self.tables,
                    self.severities,
                    months_ahead=months_ahead,
                    lock_timeout=lock_timeout,
                )
            )


def _ensure(
    conn: Connection,
    tables: AuditTables,
    severities: list[int],
    months_ahead: int,
    now: datetime | None,
    lock_timeout: str | None,
) -> list[str]:
    transaction, activity = tables.transaction, tables.activity
    parents = [qualified_name(t.schema, t.name) for t in (transaction, activity)]
    previous_timeout: str | None = None
    if lock_timeout is not None:
        previous_timeout = _set_local(conn, "lock_timeout", lock_timeout)
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
        {"key": "audit_trail.partitions:" + ",".join(parents)},
    )
    if now is None:
        now = conn.execute(text("SELECT now()")).scalar_one()
    months = _months(now, months_ahead)
    transaction_oid, activity_oid = (_oid(conn, name) for name in parents)

    created: list[str] = []
    schema = str(transaction.schema)
    created += _ensure_months(conn, schema, transaction.name, transaction_oid, months)

    by_severity: dict[int, _Child] = {}
    for partition in _children(conn, activity_oid):
        for value in partition.list_values():
            by_severity.setdefault(value, partition)
    schema = str(activity.schema)
    for value in severities:
        child = by_severity.get(value)
        if child is None:
            name = severity_partition_name(activity.name, value)
            _execute_ddl(conn, create_severity_partition_sql(tables, value, name))
            created.append(f"{schema}.{name}")
            created += _ensure_months(conn, schema, name, None, months)
        elif child.relkind == "p":
            created += _ensure_months(conn, child.schema, child.name, child.oid, months)
        # A severity partition that is a plain table takes any date.

    if previous_timeout is not None:
        _set_local(conn, "lock_timeout", previous_timeout)
    return created


def _ensure_months(
    conn: Connection,
    schema: str,
    parent: str,
    parent_oid: int | None,
    months: list[date],
) -> list[str]:
    existing = [] if parent_oid is None else _children(conn, parent_oid)
    created = []
    for month in months:
        start, end = month_bounds(month)
        if any(child.covers(start, end) for child in existing):
            continue
        name = month_partition_name(parent, month)
        if len(name.encode()) > MAX_IDENTIFIER_LENGTH:
            raise PartitionError(
                f"cannot name the {month:%Y-%m} partition of {schema}.{parent}: "
                f"{name!r} is longer than {MAX_IDENTIFIER_LENGTH} bytes and "
                "PostgreSQL would truncate it; rename the parent partition"
            )
        _execute_ddl(conn, create_month_partition_sql(schema, parent, month, name))
        created.append(f"{schema}.{name}")
    return created


def _children(conn: Connection, parent_oid: int) -> list[_Child]:
    rows = conn.execute(_CHILDREN, {"parent": parent_oid})
    return [_Child(*row) for row in rows]


def _oid(conn: Connection, qualified: str) -> int:
    oid: int | None = conn.execute(
        text("SELECT to_regclass(:name)::oid"), {"name": qualified}
    ).scalar_one()
    if oid is None:
        raise PartitionError(
            f"table {qualified} does not exist; create the audit tables first"
        )
    return oid


def _months(now: datetime, months_ahead: int) -> list[date]:
    utc = now.astimezone(timezone.utc)
    index = utc.year * 12 + utc.month - 1
    return [
        date(i // 12, i % 12 + 1, 1) for i in range(index, index + months_ahead + 1)
    ]


def _set_local(conn: Connection, setting: str, value: str) -> str:
    """Set ``setting`` for the rest of the transaction; return the old value."""
    previous: str = conn.execute(
        text("SELECT current_setting(:name)"), {"name": setting}
    ).scalar_one()
    conn.execute(
        text("SELECT set_config(:name, :value, true)"),
        {"name": setting, "value": value},
    )
    return previous
