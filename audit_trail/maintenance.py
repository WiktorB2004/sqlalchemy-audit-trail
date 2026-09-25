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

``drop_expired`` removes monthly partitions older than a per-severity
retention, with ``ALTER TABLE ... DETACH PARTITION ... CONCURRENTLY`` and then
``DROP TABLE``. ``health`` reports how many months ahead are covered, detaches
left pending and leftover tables that look like detached partitions.

Locks taken by ``drop_expired``, as observed in ``pg_locks`` on PostgreSQL 14
and 18:

* ``DETACH ... CONCURRENTLY`` first takes ``SHARE UPDATE EXCLUSIVE`` on the
  parent, which does not conflict with inserts. It then waits for every
  transaction that has used the parent, holding no lock on any table while
  it waits, so new audit inserts go ahead. Last, it takes ``SHARE UPDATE
  EXCLUSIVE`` on the parent and ``ACCESS EXCLUSIVE`` on the partition, which
  waits for readers of that partition.
* ``DETACH ... FINALIZE`` takes the same locks as that last step, and waits
  for the same transactions.
* ``DROP TABLE`` of the detached table takes ``ACCESS EXCLUSIVE`` on that
  table only.

``lock_timeout`` bounds each of these waits, including the wait for other
transactions. An application transaction left open on an audit table for
longer than ``lock_timeout`` therefore makes ``drop_expired`` fail with
``PartitionLockTimeoutError``; this is expected. If that happens after a
detach has started, the partition stays "pending detach" and the next call
finalizes and drops it.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import TYPE_CHECKING, Literal, TypeVar

from sqlalchemy import Connection, Engine, Table, bindparam, text
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

logger = logging.getLogger(__name__)

# Lets a mapping keyed by a severity IntEnum pass where ints are expected.
_Severity = TypeVar("_Severity", bound=int)

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
               AS upper,
           pending
    FROM (
        SELECT c.oid, n.nspname, c.relname, c.relkind::text AS relkind, b.bound,
               regexp_match(b.bound, :range_pattern) AS m,
               i.inhdetachpending AS pending
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
    """A lock needed for partition maintenance was not granted within ``lock_timeout``.

    From ``ensure_partitions``, nothing was created; ``months_ahead`` leaves
    room for a later retry. From ``drop_expired``, the partitions dropped
    before the timeout stay dropped (each one is logged), and a detach left
    pending is finalized by the next call.
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
    pending: bool

    @property
    def qualified(self) -> str:
        return qualified_name(self.schema, self.name)

    @property
    def display(self) -> str:
        return f"{self.schema}.{self.name}"

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


@dataclass(frozen=True)
class PartitionHealth:
    """How far ahead one partitioned parent is covered by monthly partitions.

    Attributes:
        table: Schema-qualified name of the parent (the transaction table or a
            severity partition), or ``None`` if the severity has no partition.
        covers_now: Whether the current UTC month has a partition.
        months_ahead: Whole months after the current one covered without a
            gap; ``0`` when the current month is not covered, ``None`` when
            there is no upper bound (a ``MAXVALUE`` partition, or a severity
            partition that is a plain table).
        below: Whether the current month is not covered or ``months_ahead``
            is below the threshold.
    """

    table: str | None
    covers_now: bool
    months_ahead: int | None
    below: bool


@dataclass(frozen=True)
class HealthReport:
    """Result of ``health``.

    Attributes:
        min_months_ahead: The threshold the report was made with.
        transaction: Coverage of the transaction table.
        activity: Coverage of each requested severity, by severity value.
        pending_detach: Schema-qualified names of partitions left "pending
            detach" by an interrupted ``drop_expired``; its next call
            finalizes them.
        orphaned: Schema-qualified names of tables in the audit schemas that
            are named like monthly partitions but are no partition. A crash
            between the detach and the drop in ``drop_expired`` leaves one
            behind; nothing drops them automatically. Check the name, then
            ``DROP TABLE`` it by hand.
    """

    min_months_ahead: int
    transaction: PartitionHealth
    activity: dict[int, PartitionHealth]
    pending_detach: list[str]
    orphaned: list[str]

    @property
    def ok(self) -> bool:
        """Whether nothing is below the threshold, pending or orphaned."""
        return not (
            self.transaction.below
            or any(h.below for h in self.activity.values())
            or self.pending_detach
            or self.orphaned
        )


def drop_expired(
    connection: Connection,
    tables: AuditTables,
    retention: Mapping[_Severity, timedelta | None],
    *,
    transaction_retention: timedelta | None = None,
    now: datetime | None = None,
    lock_timeout: str | None = "5s",
) -> list[str]:
    """Detach and drop the monthly partitions past their retention.

    A partition is dropped when its upper bound is earlier than
    ``now - retention``; one whose upper bound is exactly that instant is
    kept. Each partition is detached with ``DETACH PARTITION ...
    CONCURRENTLY`` from its parent (the transaction table or a severity
    partition) and then dropped, one at a time. Detaches left pending by an
    interrupted call are finalized first. Concurrent calls, and
    ``ensure_partitions``, are serialized with an advisory lock.

    ``DETACH ... CONCURRENTLY`` cannot run inside a transaction block, so
    ``connection`` must be in ``AUTOCOMMIT`` mode. ``lock_timeout`` is set for
    the session during the call and restored afterwards. The locks taken are
    listed in the module documentation. Waiting for application transactions
    that have used an audit table counts against ``lock_timeout``, so a long
    open transaction makes this call fail; that is expected, and retrying
    later is safe.

    Args:
        connection: ``AUTOCOMMIT`` connection with DDL privileges.
        tables: The audit tables, from ``audit_trail.tables.build_tables``.
        retention: Retention by severity value. ``None`` keeps a severity
            forever. A severity that has a partition but no key here is also
            kept forever, and a warning names it, so an empty mapping drops no
            activity partition. A severity partition holding several values
            keeps the longest of their retentions.
        transaction_retention: Retention of the transaction table. It is
            capped at the shortest finite severity retention, with a warning
            if it is longer; ``None`` uses that shortest retention. When no
            severity has a finite retention and this is ``None``, transaction
            partitions are kept.
        now: Reference time, timezone-aware. ``None`` uses the database's
            ``now()``.
        lock_timeout: PostgreSQL ``lock_timeout`` for each statement, such as
            ``"5s"``. ``None`` keeps the session's setting.

    Returns:
        Schema-qualified names of the partitions dropped, in order.

    Raises:
        ValueError: If the connection is not in ``AUTOCOMMIT`` mode, a
            retention is negative, or ``now`` is naive.
        PartitionError: If a parent table does not exist.
        PartitionLockTimeoutError: If a lock was not granted within
            ``lock_timeout``. Partitions dropped before that stay dropped.
    """
    if not getattr(connection.connection.dbapi_connection, "autocommit", False):
        raise ValueError(
            "drop_expired needs an AUTOCOMMIT connection: DETACH PARTITION "
            "... CONCURRENTLY cannot run inside a transaction block"
        )
    if any(r is not None and r < timedelta(0) for r in retention.values()) or (
        transaction_retention is not None and transaction_retention < timedelta(0)
    ):
        raise ValueError("retention must not be negative")
    _check_aware(now)
    try:
        return _drop(
            connection, tables, retention, transaction_retention, now, lock_timeout
        )
    except DBAPIError as exc:
        if getattr(exc.orig, "sqlstate", None) == LOCK_NOT_AVAILABLE:
            raise PartitionLockTimeoutError(
                f"expired partitions were not all dropped: a lock was not "
                f"granted within lock_timeout={lock_timeout!r}. An application "
                "transaction left open on an audit table for longer than that "
                "causes this and is expected; retry later, and a detach left "
                "pending is finalized then"
            ) from exc
        raise


def health(
    connection: Connection,
    tables: AuditTables,
    severities: Iterable[int],
    *,
    min_months_ahead: int = 2,
    now: datetime | None = None,
) -> HealthReport:
    """Report partition coverage, pending detaches and orphaned partitions.

    Read-only; runs on any connection.

    Args:
        connection: Connection that can read the catalog.
        tables: The audit tables, from ``audit_trail.tables.build_tables``.
        severities: A severity ``IntEnum`` class, or any iterable of ints.
        min_months_ahead: Coverage below this many months after the current
            one is flagged. The default of ``2`` flags one missed run of
            ``ensure_partitions(months_ahead=3)``.
        now: Reference time, timezone-aware. ``None`` uses the database's
            ``now()``.

    Returns:
        The report.

    Raises:
        ValueError: If ``now`` is naive.
        PartitionError: If a parent table does not exist.
    """
    _check_aware(now)
    transaction_oid = _oid(connection, _qualified(tables.transaction))
    activity_oid = _oid(connection, _qualified(tables.activity))
    if now is None:
        now = connection.execute(text("SELECT now()")).scalar_one()

    transaction_months = _children(connection, transaction_oid)
    severity_parents = _children(connection, activity_oid)
    months = {
        parent.oid: _children(connection, parent.oid)
        for parent in severity_parents
        if parent.relkind == "p"
    }
    by_severity: dict[int, _Child] = {}
    for parent in severity_parents:
        for value in parent.list_values():
            by_severity.setdefault(value, parent)

    def check(table: str | None, children: list[_Child] | None) -> PartitionHealth:
        if children is None:  # a plain table takes any date
            covers_now, months_ahead = True, None
        else:
            covers_now, months_ahead = _coverage(children, now)
        below = not covers_now or (
            months_ahead is not None and months_ahead < min_months_ahead
        )
        return PartitionHealth(table, covers_now, months_ahead, below)

    activity: dict[int, PartitionHealth] = {}
    for value in severity_values(severities):
        severity_parent = by_severity.get(value)
        if severity_parent is None:
            activity[value] = check(None, [])
        else:
            activity[value] = check(
                severity_parent.display, months.get(severity_parent.oid)
            )

    return HealthReport(
        min_months_ahead=min_months_ahead,
        transaction=check(_display(tables.transaction), transaction_months),
        activity=activity,
        pending_detach=[
            child.display
            for children in (transaction_months, *months.values())
            for child in children
            if child.pending
        ],
        orphaned=_orphans(connection, tables, severity_parents),
    )


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

    def drop_expired(
        self,
        retention: Mapping[_Severity, timedelta | None],
        *,
        transaction_retention: timedelta | None = None,
        lock_timeout: str | None = "5s",
    ) -> list[str]:
        """Drop expired partitions on an ``AUTOCOMMIT`` connection; see ``drop_expired``.

        Args:
            retention: Retention by severity value; ``None`` keeps forever.
            transaction_retention: Retention of the transaction table.
            lock_timeout: PostgreSQL ``lock_timeout`` for each statement.

        Returns:
            Schema-qualified names of the partitions dropped.

        Raises:
            TypeError: If the manager was built with an ``AsyncEngine``.
            PartitionLockTimeoutError: If a lock was not granted in time.
        """
        if not isinstance(self.engine, Engine):
            raise TypeError("the engine is async; use adrop_expired")
        with self.engine.connect() as conn:
            return drop_expired(
                conn.execution_options(isolation_level="AUTOCOMMIT"),
                self.tables,
                retention,
                transaction_retention=transaction_retention,
                lock_timeout=lock_timeout,
            )

    async def adrop_expired(
        self,
        retention: Mapping[_Severity, timedelta | None],
        *,
        transaction_retention: timedelta | None = None,
        lock_timeout: str | None = "5s",
    ) -> list[str]:
        """Async ``drop_expired``, for a manager built with an ``AsyncEngine``.

        Args:
            retention: Retention by severity value; ``None`` keeps forever.
            transaction_retention: Retention of the transaction table.
            lock_timeout: PostgreSQL ``lock_timeout`` for each statement.

        Returns:
            Schema-qualified names of the partitions dropped.

        Raises:
            TypeError: If the manager was built with a sync ``Engine``.
            PartitionLockTimeoutError: If a lock was not granted in time.
        """
        if isinstance(self.engine, Engine):
            raise TypeError("the engine is sync; use drop_expired")
        async with self.engine.connect() as conn:
            auto = await conn.execution_options(isolation_level="AUTOCOMMIT")
            return await auto.run_sync(
                lambda sync_conn: drop_expired(
                    sync_conn,
                    self.tables,
                    retention,
                    transaction_retention=transaction_retention,
                    lock_timeout=lock_timeout,
                )
            )

    def health(self, min_months_ahead: int = 2) -> HealthReport:
        """Report partition health; see ``health``.

        Args:
            min_months_ahead: Coverage threshold in months after the current one.

        Returns:
            The report.

        Raises:
            TypeError: If the manager was built with an ``AsyncEngine``.
        """
        if not isinstance(self.engine, Engine):
            raise TypeError("the engine is async; use ahealth")
        with self.engine.connect() as conn:
            return health(
                conn, self.tables, self.severities, min_months_ahead=min_months_ahead
            )

    async def ahealth(self, min_months_ahead: int = 2) -> HealthReport:
        """Async ``health``, for a manager built with an ``AsyncEngine``.

        Args:
            min_months_ahead: Coverage threshold in months after the current one.

        Returns:
            The report.

        Raises:
            TypeError: If the manager was built with a sync ``Engine``.
        """
        if isinstance(self.engine, Engine):
            raise TypeError("the engine is sync; use health")
        async with self.engine.connect() as conn:
            return await conn.run_sync(
                lambda sync_conn: health(
                    sync_conn,
                    self.tables,
                    self.severities,
                    min_months_ahead=min_months_ahead,
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
    parents = [_qualified(t) for t in (transaction, activity)]
    previous_timeout: str | None = None
    if lock_timeout is not None:
        previous_timeout = _set_local(conn, "lock_timeout", lock_timeout)
    conn.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
        {"key": _lock_key(tables)},
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


_DetachMode = Literal["CONCURRENTLY", "FINALIZE"]


def _drop(
    conn: Connection,
    tables: AuditTables,
    retention: Mapping[_Severity, timedelta | None],
    transaction_retention: timedelta | None,
    now: datetime | None,
    lock_timeout: str | None,
) -> list[str]:
    transaction, activity = tables.transaction, tables.activity
    transaction_oid = _oid(conn, _qualified(transaction))
    activity_oid = _oid(conn, _qualified(activity))
    limits = {int(k): v for k, v in retention.items()}

    previous_timeout: str | None = None
    if lock_timeout is not None:
        previous_timeout = _set_session(conn, "lock_timeout", lock_timeout)
    key = {"key": _lock_key(tables)}
    locked = False
    try:
        conn.execute(text("SELECT pg_advisory_lock(hashtext(:key))"), key)
        locked = True
        if now is None:
            now = conn.execute(text("SELECT now()")).scalar_one()

        # (quoted parent, its monthly partitions, retention)
        parents: list[tuple[str, int, timedelta | None]] = [
            (
                _qualified(transaction),
                transaction_oid,
                _transaction_limit(limits, transaction_retention),
            )
        ]
        undeclared: set[int] = set()
        for child in _children(conn, activity_oid):
            values = child.list_values()
            undeclared |= values - limits.keys()
            if child.relkind == "p":
                parents.append((child.qualified, child.oid, _longest(limits, values)))
        for value in sorted(undeclared):
            logger.warning(
                "severity %s has no retention; its partitions are kept. "
                "Declare it, with None to keep it forever.",
                value,
            )

        dropped: list[str] = []
        for parent, parent_oid, limit in parents:
            dropped += _drop_months(conn, parent, parent_oid, limit, now)
        return dropped
    finally:
        if locked:
            conn.execute(text("SELECT pg_advisory_unlock(hashtext(:key))"), key)
        if previous_timeout is not None:
            _set_session(conn, "lock_timeout", previous_timeout)


def _drop_months(
    conn: Connection,
    parent: str,
    parent_oid: int,
    limit: timedelta | None,
    now: datetime,
) -> list[str]:
    cutoff = None if limit is None else now - limit

    def expired(child: _Child) -> bool:
        return (
            cutoff is not None
            and child.is_range
            and child.upper is not None
            and child.upper < cutoff
        )

    children = _children(conn, parent_oid)
    dropped: list[str] = []
    # At most one partition per parent can be pending; finish it first.
    for child in (c for c in children if c.pending):
        _execute_ddl(conn, _detach_sql(parent, child, "FINALIZE"))
        if expired(child):
            dropped.append(_drop_table(conn, child))
        else:
            logger.warning(
                "finalized the pending detach of %s, which has not expired; "
                "it is left as a standalone table",
                child.display,
            )
    live = [c for c in children if not c.pending and expired(c)]
    for child in sorted(live, key=lambda c: c.upper or now):
        _execute_ddl(conn, _detach_sql(parent, child, "CONCURRENTLY"))
        dropped.append(_drop_table(conn, child))
    return dropped


def _drop_table(conn: Connection, child: _Child) -> str:
    _execute_ddl(conn, f"DROP TABLE {child.qualified}")
    logger.info("dropped expired partition %s", child.display)
    return child.display


def _detach_sql(parent: str, child: _Child, mode: _DetachMode) -> str:
    return f"ALTER TABLE {parent} DETACH PARTITION {child.qualified} {mode}"


def _transaction_limit(
    limits: dict[int, timedelta | None], requested: timedelta | None
) -> timedelta | None:
    finite = [limit for limit in limits.values() if limit is not None]
    shortest = min(finite, default=None)
    if requested is None or shortest is None:
        return requested if shortest is None else shortest
    if requested > shortest:
        logger.warning(
            "transaction_retention %s is longer than the shortest severity "
            "retention %s; using %s, so no transaction row outlives the "
            "activity it describes",
            requested,
            shortest,
            shortest,
        )
        return shortest
    return requested


def _longest(limits: dict[int, timedelta | None], values: set[int]) -> timedelta | None:
    longest = timedelta(0)
    for value in values:
        limit = limits.get(value)
        if limit is None:
            return None
        longest = max(longest, limit)
    return longest if values else None


def _coverage(children: list[_Child], now: datetime) -> tuple[bool, int | None]:
    """Whether the current month is covered, and how many months after it."""
    live = [c for c in children if not c.pending]
    month = _months(now, 0)[0]
    months_ahead = -1
    while True:
        start, end = month_bounds(month)
        covering = next((c for c in live if c.covers(start, end)), None)
        if covering is None:
            return months_ahead >= 0, max(months_ahead, 0)
        if covering.upper is None:
            return True, None
        months_ahead += 1
        month = end.date()


def _orphans(
    conn: Connection, tables: AuditTables, severity_parents: list[_Child]
) -> list[str]:
    prefixes = [
        re.escape(tables.transaction.name),
        re.escape(tables.activity.name) + r"_-?\d+",
        *(re.escape(p.name) for p in severity_parents),
    ]
    pattern = re.compile(rf"^(?:{'|'.join(prefixes)})_p\d{{4}}_\d{{2}}$")
    rows = conn.execute(
        text(
            """
            SELECT n.nspname, c.relname
            FROM pg_catalog.pg_class c
            JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
              AND c.relnamespace IN (
                  SELECT relnamespace FROM pg_catalog.pg_class
                  WHERE oid IN (to_regclass(:transaction), to_regclass(:activity))
              )
            ORDER BY n.nspname, c.relname
            """
        ),
        {
            "transaction": _qualified(tables.transaction),
            "activity": _qualified(tables.activity),
        },
    )
    return [f"{schema}.{name}" for schema, name in rows if pattern.match(name)]


def _check_aware(now: datetime | None) -> None:
    if now is not None and now.tzinfo is None:
        raise ValueError("now must be timezone-aware")


def _qualified(table: Table) -> str:
    return qualified_name(table.schema, table.name)


def _display(table: Table) -> str:
    return table.name if table.schema is None else f"{table.schema}.{table.name}"


def _lock_key(tables: AuditTables) -> str:
    parents = (_qualified(t) for t in (tables.transaction, tables.activity))
    return "audit_trail.partitions:" + ",".join(parents)


def _set_session(conn: Connection, setting: str, value: str) -> str:
    """Set ``setting`` for the session; return the old value."""
    previous: str = conn.execute(
        text("SELECT current_setting(:name)"), {"name": setting}
    ).scalar_one()
    conn.execute(
        text("SELECT set_config(:name, :value, false)"),
        {"name": setting, "value": value},
    )
    return previous
