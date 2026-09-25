"""``drop_expired`` and ``health`` against a real PostgreSQL."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator, Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from enum import IntEnum
from typing import Any, TypeVar

import pytest
from sqlalchemy import (
    Connection,
    Engine,
    MetaData,
    create_engine,
    insert,
    select,
    text,
)
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from audit_trail.maintenance import (
    PartitionLockTimeoutError,
    PartitionManager,
    drop_expired,
    ensure_partitions,
    health,
)
from audit_trail.migrations import create_audit_tables, qualified_name
from audit_trail.tables import AuditTables, build_tables


class Sev(IntEnum):
    INFO = 10
    NOTICE = 20
    CRITICAL = 40


NOW = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)
DAY = timedelta(days=1)
# Watchdog for tests that block on locks: a regression fails instead of hanging.
CAP = 15

S = TypeVar("S", bound=int)


@pytest.fixture
def tables(engine: Engine, schema: str) -> AuditTables:
    """Audit tables with monthly partitions from June to September 2026."""
    t = build_tables(schema=schema)
    with engine.begin() as conn:
        create_audit_tables(conn, t, Sev)
        ensure_partitions(
            conn, t, Sev, months_ahead=3, now=datetime(2026, 6, 5, tzinfo=timezone.utc)
        )
    return t


def drop(
    engine: Engine,
    tables: AuditTables,
    retention: Mapping[S, timedelta | None],
    **kwargs: Any,
) -> list[str]:
    kwargs.setdefault("now", NOW)
    with engine.connect() as conn:
        auto = conn.execution_options(isolation_level="AUTOCOMMIT")
        return drop_expired(auto, tables, retention, **kwargs)


def months(engine: Engine, schema: str) -> set[str]:
    """Names of the monthly partitions attached in ``schema``."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                """
                SELECT c.relname FROM pg_inherits i
                JOIN pg_class c ON c.oid = i.inhrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE n.nspname = :schema AND c.relname LIKE '%\\_p20__\\___'
                """
            ),
            {"schema": schema},
        )
        return set(rows.scalars())


def pending(engine: Engine, schema: str) -> list[str]:
    with engine.connect() as conn:
        return list(
            conn.execute(
                text(
                    "SELECT c.relname FROM pg_inherits i "
                    "JOIN pg_class c ON c.oid = i.inhrelid "
                    "JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "WHERE n.nspname = :schema AND i.inhdetachpending"
                ),
                {"schema": schema},
            ).scalars()
        )


def all_months(prefix: str) -> set[str]:
    return {f"{prefix}_p2026_{m:02d}" for m in (6, 7, 8, 9)}


def warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.levelno == logging.WARNING and r.name == "audit_trail.maintenance"
    ]


def add_rows(conn: Connection, tables: AuditTables, at: datetime) -> None:
    """One transaction row and one activity row per severity, at ``at``."""
    conn.execute(insert(tables.transaction).values(actor_type="system", issued_at=at))
    for sev in Sev:
        conn.execute(
            insert(tables.activity).values(
                transaction_id=1, verb="x", severity=sev, created_at=at
            )
        )


@pytest.fixture
def pool() -> Iterator[ThreadPoolExecutor]:
    with ThreadPoolExecutor(max_workers=4) as executor:
        yield executor


def poll(probe: Callable[[], list[Any]]) -> list[Any]:
    """Call ``probe`` until it returns something, for at most ``CAP`` seconds."""
    deadline = time.monotonic() + CAP
    while not (found := probe()):
        assert time.monotonic() < deadline, "nothing found before the cap"
        time.sleep(0.02)
    return found


def detach_waits(engine: Engine) -> list[tuple[str, str, str | None]]:
    """Lock requests not yet granted to a backend running a DETACH."""
    with engine.connect() as conn:
        return [
            (locktype, mode, relation)
            for locktype, mode, relation in conn.execute(
                text(
                    """
                    SELECT l.locktype, l.mode, l.relation::regclass::text
                    FROM pg_locks l JOIN pg_stat_activity a USING (pid)
                    WHERE NOT l.granted AND a.query LIKE '%DETACH PARTITION%'
                      AND a.pid <> pg_backend_pid()
                    """
                )
            )
        ]


def detach_holds_relation_locks(engine: Engine) -> list[str]:
    """Table locks held by a backend running a DETACH."""
    with engine.connect() as conn:
        return list(
            conn.execute(
                text(
                    """
                    SELECT l.relation::regclass::text || ' ' || l.mode
                    FROM pg_locks l JOIN pg_stat_activity a USING (pid)
                    WHERE l.granted AND l.locktype = 'relation'
                      AND a.query LIKE '%DETACH PARTITION%'
                      AND a.pid <> pg_backend_pid()
                    """
                )
            ).scalars()
        )


def test_info_window_drops_transactions_too(
    engine: Engine, tables: AuditTables, schema: str, caplog: pytest.LogCaptureFixture
) -> None:
    with engine.begin() as conn:
        add_rows(conn, tables, datetime(2026, 6, 15, tzinfo=timezone.utc))
    retention = {Sev.INFO: 30 * DAY, Sev.NOTICE: None, Sev.CRITICAL: None}

    dropped = drop(engine, tables, retention)

    # NOW - 30 days is 2026-08-11 12:00: June and July have ended before it.
    assert dropped == [
        f"{schema}.audit_transaction_p2026_06",
        f"{schema}.audit_transaction_p2026_07",
        f"{schema}.audit_activity_10_p2026_06",
        f"{schema}.audit_activity_10_p2026_07",
    ]
    assert months(engine, schema) == (
        {"audit_transaction_p2026_08", "audit_transaction_p2026_09"}
        | {"audit_activity_10_p2026_08", "audit_activity_10_p2026_09"}
        | all_months("audit_activity_20")
        | all_months("audit_activity_40")
    )
    with engine.connect() as conn:
        rows = conn.execute(select(tables.activity.c.severity)).all()
    assert sorted(row.severity for row in rows) == [Sev.NOTICE, Sev.CRITICAL]
    assert warnings(caplog) == []
    assert pending(engine, schema) == []


def test_longer_transaction_retention_is_capped_with_warning(
    engine: Engine, tables: AuditTables, schema: str, caplog: pytest.LogCaptureFixture
) -> None:
    retention = {Sev.INFO: 30 * DAY, Sev.NOTICE: None, Sev.CRITICAL: None}

    dropped = drop(engine, tables, retention, transaction_retention=365 * DAY)

    assert f"{schema}.audit_transaction_p2026_07" in dropped
    assert "audit_transaction_p2026_07" not in months(engine, schema)
    [warning] = warnings(caplog)
    assert "transaction_retention 365 days" in warning
    assert "30 days" in warning


def test_shorter_transaction_retention_is_used(
    engine: Engine, tables: AuditTables, schema: str, caplog: pytest.LogCaptureFixture
) -> None:
    retention = {Sev.INFO: 60 * DAY, Sev.NOTICE: None, Sev.CRITICAL: None}

    dropped = drop(engine, tables, retention, transaction_retention=30 * DAY)

    # NOW - 60 days is 2026-07-12: only June activity; transactions to July.
    assert dropped == [
        f"{schema}.audit_transaction_p2026_06",
        f"{schema}.audit_transaction_p2026_07",
        f"{schema}.audit_activity_10_p2026_06",
    ]
    assert warnings(caplog) == []


def test_all_unlimited_keeps_transactions(
    engine: Engine, tables: AuditTables, schema: str, caplog: pytest.LogCaptureFixture
) -> None:
    before = months(engine, schema)

    assert drop(engine, tables, dict.fromkeys(Sev)) == []
    assert months(engine, schema) == before
    assert warnings(caplog) == []


def test_absent_severity_is_kept_with_warning(
    engine: Engine, tables: AuditTables, schema: str, caplog: pytest.LogCaptureFixture
) -> None:
    dropped = drop(engine, tables, {Sev.INFO: 30 * DAY})

    assert dropped == [
        f"{schema}.audit_transaction_p2026_06",
        f"{schema}.audit_transaction_p2026_07",
        f"{schema}.audit_activity_10_p2026_06",
        f"{schema}.audit_activity_10_p2026_07",
    ]
    assert all_months("audit_activity_20") <= months(engine, schema)
    assert all_months("audit_activity_40") <= months(engine, schema)
    found = warnings(caplog)
    assert len(found) == 2
    assert found[0].startswith("severity 20 has no retention")
    assert found[1].startswith("severity 40 has no retention")


def test_empty_retention_drops_nothing_and_warns_for_each(
    engine: Engine, tables: AuditTables, schema: str, caplog: pytest.LogCaptureFixture
) -> None:
    before = months(engine, schema)

    assert drop(engine, tables, {}) == []

    assert months(engine, schema) == before
    assert [w.split(" has ")[0] for w in warnings(caplog)] == [
        "severity 10",
        "severity 20",
        "severity 40",
    ]


def test_partition_ending_exactly_at_cutoff_is_kept(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    july_end = datetime(2026, 8, 1, tzinfo=timezone.utc)
    retention = {Sev.INFO: 30 * DAY, Sev.NOTICE: None, Sev.CRITICAL: None}

    at_cutoff = drop(engine, tables, retention, now=july_end + 30 * DAY)
    after_cutoff = drop(
        engine, tables, retention, now=july_end + 30 * DAY + timedelta(microseconds=1)
    )

    assert at_cutoff == [
        f"{schema}.audit_transaction_p2026_06",
        f"{schema}.audit_activity_10_p2026_06",
    ]
    assert after_cutoff == [
        f"{schema}.audit_transaction_p2026_07",
        f"{schema}.audit_activity_10_p2026_07",
    ]


def test_multi_value_severity_partition_keeps_longest_retention(
    engine: Engine, schema: str, caplog: pytest.LogCaptureFixture
) -> None:
    tables = build_tables(schema=schema)
    activity = qualified_name(schema, "audit_activity")
    with engine.begin() as conn:
        create_audit_tables(conn, tables, [])
        conn.exec_driver_sql(
            f"CREATE TABLE {schema}.low PARTITION OF {activity} "
            "FOR VALUES IN (10, 20) PARTITION BY RANGE (created_at)"
        )
        ensure_partitions(
            conn,
            tables,
            [10, 20],
            months_ahead=3,
            now=datetime(2026, 6, 5, tzinfo=timezone.utc),
        )

    dropped = drop(engine, tables, {10: 30 * DAY, 20: 60 * DAY})

    # NOW - 60 days is 2026-07-12: only June has ended before it.
    assert f"{schema}.low_p2026_06" in dropped
    assert f"{schema}.low_p2026_07" not in dropped
    assert warnings(caplog) == []


def test_detach_concurrently_needs_autocommit(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    sql = (
        f"ALTER TABLE {qualified_name(schema, 'audit_activity_10')} DETACH PARTITION "
        f"{qualified_name(schema, 'audit_activity_10_p2026_06')} CONCURRENTLY"
    )
    with engine.connect() as conn:
        with pytest.raises(DBAPIError, match="cannot run inside a transaction block"):
            conn.exec_driver_sql(sql)
        conn.rollback()
        with pytest.raises(ValueError, match="AUTOCOMMIT"):
            drop_expired(conn, tables, {Sev.INFO: DAY}, now=NOW)
        conn.rollback()

        auto = conn.execution_options(isolation_level="AUTOCOMMIT")
        auto.exec_driver_sql(sql)

    assert "audit_activity_10_p2026_06" not in months(engine, schema)


def test_lock_timeout_fails_fast_leaves_pending_then_finalizes(
    engine: Engine,
    tables: AuditTables,
    schema: str,
    pool: ThreadPoolExecutor,
) -> None:
    retention = {Sev.INFO: 30 * DAY, Sev.NOTICE: None, Sev.CRITICAL: None}
    with engine.connect() as blocker:
        # An open business transaction with uncommitted audit rows.
        add_rows(blocker, tables, NOW)

        def watch() -> tuple[list[Any], list[str], list[Any]]:
            waits = poll(lambda: detach_waits(engine))
            held = detach_holds_relation_locks(engine)
            with engine.begin() as conn:
                # Fails instead of waiting if the insert queues behind the detach.
                conn.execute(text("SET LOCAL lock_timeout = '200ms'"))
                add_rows(conn, tables, NOW)
            return waits, held, detach_waits(engine)

        try:
            watcher = pool.submit(watch)
            started = time.monotonic()
            attempt = pool.submit(drop, engine, tables, retention, lock_timeout="3s")
            with pytest.raises(PartitionLockTimeoutError, match="expected"):
                attempt.result(timeout=CAP)
            elapsed = time.monotonic() - started
            waits, held, still_waiting = watcher.result(timeout=CAP)
        finally:
            blocker.rollback()

    assert elapsed < 8
    # Between its phases, DETACH CONCURRENTLY waits on the blocker's virtual
    # transaction id and holds no table lock, so new inserts go ahead.
    assert [(t, m) for t, m, _ in waits] == [("virtualxid", "ShareLock")]
    assert held == []
    assert still_waiting == waits
    assert pending(engine, schema) == ["audit_transaction_p2026_06"]

    dropped = drop(engine, tables, retention)

    assert dropped == [
        f"{schema}.audit_transaction_p2026_06",
        f"{schema}.audit_transaction_p2026_07",
        f"{schema}.audit_activity_10_p2026_06",
        f"{schema}.audit_activity_10_p2026_07",
    ]
    assert pending(engine, schema) == []


def test_reader_of_expired_partition_blocks_with_access_exclusive(
    engine: Engine,
    tables: AuditTables,
    schema: str,
    pool: ThreadPoolExecutor,
) -> None:
    retention = {Sev.INFO: 30 * DAY, Sev.NOTICE: 30 * DAY, Sev.CRITICAL: 30 * DAY}
    target = f"{schema}.audit_transaction_p2026_06"
    with engine.connect() as blocker:
        blocker.execute(
            text(
                f"SELECT count(*) FROM {qualified_name(schema, 'audit_transaction_p2026_06')}"
            )
        )
        try:
            watcher = pool.submit(poll, lambda: detach_waits(engine))
            attempt = pool.submit(drop, engine, tables, retention, lock_timeout="1s")
            with pytest.raises(PartitionLockTimeoutError):
                attempt.result(timeout=CAP)
            waits = watcher.result(timeout=CAP)
        finally:
            blocker.rollback()

    assert waits == [("relation", "AccessExclusiveLock", target)]
    assert pending(engine, schema) == ["audit_transaction_p2026_06"]
    assert f"{schema}.audit_transaction_p2026_06" in drop(engine, tables, retention)


def test_waiting_detach_and_ensure_partitions_do_not_hang(
    engine: Engine,
    tables: AuditTables,
    schema: str,
    pool: ThreadPoolExecutor,
) -> None:
    lock_timeout = 1.0
    with engine.connect() as conn:
        deadlock_timeout: float = conn.execute(
            text(
                "SELECT setting::float / 1000 FROM pg_settings WHERE name = 'deadlock_timeout'"
            )
        ).scalar_one()
    bound = lock_timeout + deadlock_timeout + 1  # 1 s of slack for the test itself

    def timed(call: Callable[[], object]) -> tuple[float, BaseException | None]:
        started = time.monotonic()
        try:
            call()
        except (PartitionLockTimeoutError, DBAPIError) as exc:
            return time.monotonic() - started, exc
        return time.monotonic() - started, None

    def ensure() -> list[str]:
        with engine.begin() as conn:
            return ensure_partitions(
                conn, tables, Sev, months_ahead=1, now=NOW, lock_timeout="1s"
            )

    retention = dict.fromkeys(Sev, 30 * DAY)
    with engine.connect() as blocker:
        add_rows(blocker, tables, NOW)
        try:
            dropping: Future[tuple[float, BaseException | None]] = pool.submit(
                timed, lambda: drop(engine, tables, retention, lock_timeout="1s")
            )
            poll(lambda: detach_waits(engine))
            ensuring = pool.submit(timed, ensure)
            drop_time, drop_error = dropping.result(timeout=CAP)
            ensure_time, ensure_error = ensuring.result(timeout=CAP)
        finally:
            blocker.rollback()

    assert drop_time < bound
    assert ensure_time < bound
    for error in (drop_error, ensure_error):
        deadlock = getattr(getattr(error, "orig", None), "sqlstate", None) == "40P01"
        assert error is None or isinstance(error, PartitionLockTimeoutError) or deadlock
    # Both succeed once the application transaction has ended.
    drop(engine, tables, retention)
    ensure()
    assert pending(engine, schema) == []


def test_session_lock_timeout_and_advisory_lock_are_released(
    engine: Engine, tables: AuditTables, pool: ThreadPoolExecutor
) -> None:
    retention = dict.fromkeys(Sev, 30 * DAY)

    def advisory_locks(conn: Connection) -> int:
        count: int = conn.execute(
            text(
                "SELECT count(*) FROM pg_locks "
                "WHERE locktype = 'advisory' AND pid = pg_backend_pid()"
            )
        ).scalar_one()
        return count

    with engine.connect() as blocker:
        add_rows(blocker, tables, NOW)
        try:
            with engine.connect() as conn:
                auto = conn.execution_options(isolation_level="AUTOCOMMIT")
                auto.execute(text("SET lock_timeout = '42s'"))
                with pytest.raises(PartitionLockTimeoutError):
                    drop_expired(auto, tables, retention, now=NOW, lock_timeout="200ms")
                assert auto.execute(text("SHOW lock_timeout")).scalar_one() == "42s"
                assert advisory_locks(auto) == 0
        finally:
            blocker.rollback()

    with engine.connect() as conn:
        auto = conn.execution_options(isolation_level="AUTOCOMMIT")
        auto.execute(text("SET lock_timeout = '42s'"))
        assert drop_expired(auto, tables, retention, now=NOW, lock_timeout="1s")
        assert auto.execute(text("SHOW lock_timeout")).scalar_one() == "42s"
        assert advisory_locks(auto) == 0


def test_retention_for_severity_without_partition_warns(
    engine: Engine, tables: AuditTables, caplog: pytest.LogCaptureFixture
) -> None:
    retention = {Sev.INFO: 30 * DAY, Sev.NOTICE: None, Sev.CRITICAL: None}

    drop(engine, tables, {**retention, 30: DAY, 99: None})

    assert [w.split(",")[0] for w in warnings(caplog)] == [
        "retention names severity 30",
        "retention names severity 99",
    ]


def test_broken_connection_error_is_not_hidden(
    engine: Engine, tables: AuditTables, pool: ThreadPoolExecutor
) -> None:
    def kill_waiting_detach() -> None:
        poll(lambda: detach_waits(engine))
        with engine.connect() as conn:
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE query LIKE '%DETACH PARTITION%' "
                    "AND pid <> pg_backend_pid()"
                )
            )

    with engine.connect() as blocker:
        add_rows(blocker, tables, NOW)
        try:
            killer = pool.submit(kill_waiting_detach)
            attempt = pool.submit(
                drop, engine, tables, dict.fromkeys(Sev, DAY), lock_timeout="10s"
            )
            # The disconnect itself, not an error from the cleanup after it.
            with pytest.raises(DBAPIError) as caught:
                attempt.result(timeout=CAP)
            killer.result(timeout=CAP)
        finally:
            blocker.rollback()

    assert caught.value.connection_invalidated


@pytest.fixture
def search_path_engine(database_url: str, schema: str) -> Iterator[Engine]:
    """An engine whose search_path is ``schema``, for tables built without one."""
    eng = create_engine(
        database_url, connect_args={"options": f"-c search_path={schema}"}
    )
    yield eng
    eng.dispose()


@pytest.fixture
def unqualified_tables(search_path_engine: Engine) -> AuditTables:
    # build_tables always sets a schema; an AuditTables built by hand may not.
    # to_metadata takes schema=None at runtime; its annotation omits it.
    source = build_tables()
    metadata = MetaData()
    t = AuditTables(
        metadata,
        source.transaction.to_metadata(metadata, schema=None),  # type: ignore[arg-type]
        source.activity.to_metadata(metadata, schema=None),  # type: ignore[arg-type]
    )
    with search_path_engine.begin() as conn:
        create_audit_tables(conn, t, [Sev.INFO])
    return t


def test_ensure_names_without_schema(
    search_path_engine: Engine, unqualified_tables: AuditTables, schema: str
) -> None:
    with search_path_engine.begin() as conn:
        created = ensure_partitions(
            conn, unqualified_tables, [Sev.INFO, Sev.NOTICE], months_ahead=0, now=NOW
        )

    # Names under a declared parent follow its (absent) schema; months under a
    # severity partition found in the catalog carry the schema it lives in.
    assert created == [
        "audit_transaction_p2026_09",
        f"{schema}.audit_activity_10_p2026_09",
        "audit_activity_20",
        "audit_activity_20_p2026_09",
    ]


def test_drop_expired_names_without_schema(
    search_path_engine: Engine, unqualified_tables: AuditTables, schema: str
) -> None:
    with search_path_engine.begin() as conn:
        ensure_partitions(
            conn,
            unqualified_tables,
            [Sev.INFO],
            months_ahead=1,
            now=datetime(2026, 7, 5, tzinfo=timezone.utc),
        )

    dropped = drop(search_path_engine, unqualified_tables, {Sev.INFO: 30 * DAY})

    assert dropped == [
        f"{schema}.audit_transaction_p2026_07",
        f"{schema}.audit_activity_10_p2026_07",
    ]


def test_health_names_without_schema(
    search_path_engine: Engine, unqualified_tables: AuditTables, schema: str
) -> None:
    with search_path_engine.connect() as conn:
        report = health(conn, unqualified_tables, [Sev.INFO], now=NOW)

    assert report.transaction.table == "audit_transaction"
    assert report.activity[Sev.INFO].table == f"{schema}.audit_activity_10"


def test_rejects_negative_retention_and_naive_now(
    engine: Engine, tables: AuditTables
) -> None:
    with pytest.raises(ValueError, match="negative"):
        drop(engine, tables, {Sev.INFO: -DAY})
    with pytest.raises(ValueError, match="negative"):
        drop(engine, tables, {}, transaction_retention=-DAY)
    with pytest.raises(ValueError, match="timezone-aware"):
        drop(engine, tables, {}, now=NOW.replace(tzinfo=None))


def test_health_reports_coverage(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    with engine.connect() as conn:
        report = health(conn, tables, [*Sev, 30], now=NOW)
        strict = health(conn, tables, Sev, now=NOW, min_months_ahead=1)

    # Partitions run June to September; NOW is in September.
    assert report.transaction.table == f"{schema}.audit_transaction"
    assert report.transaction.covers_now
    assert report.transaction.months_ahead == 0
    assert report.transaction.below
    assert report.activity[Sev.INFO].table == f"{schema}.audit_activity_10"
    assert report.activity[Sev.INFO].months_ahead == 0
    assert report.activity[30].table is None
    assert not report.activity[30].covers_now
    assert report.activity[30].below
    assert not report.ok
    assert strict.transaction.below

    with engine.begin() as conn:
        ensure_partitions(conn, tables, Sev, months_ahead=2, now=NOW)
    with engine.connect() as conn:
        report = health(conn, tables, Sev, now=NOW)
        later = health(conn, tables, Sev, now=datetime(2027, 1, 1, tzinfo=timezone.utc))

    assert report.transaction.months_ahead == 2
    assert all(h.months_ahead == 2 for h in report.activity.values())
    assert report.ok
    assert report.pending_detach == []
    assert report.orphaned == []
    assert not later.transaction.covers_now
    assert later.transaction.months_ahead == 0
    assert later.transaction.below


def test_health_reports_pending_and_orphaned(
    engine: Engine, tables: AuditTables, schema: str, pool: ThreadPoolExecutor
) -> None:
    with engine.connect() as blocker:
        add_rows(blocker, tables, NOW)
        try:
            attempt = pool.submit(
                drop, engine, tables, dict.fromkeys(Sev, 30 * DAY), lock_timeout="200ms"
            )
            with pytest.raises(PartitionLockTimeoutError):
                attempt.result(timeout=CAP)
        finally:
            blocker.rollback()
    with engine.begin() as conn:
        # What a crash between detach and drop leaves behind, and a table
        # whose name does not match the partition naming.
        for name in ("audit_activity_20_p2025_01", "audit_transaction_notes"):
            conn.exec_driver_sql(
                f"CREATE TABLE {qualified_name(schema, name)} (id int)"
            )

    with engine.connect() as conn:
        report = health(conn, tables, Sev, now=NOW)

    assert report.pending_detach == [f"{schema}.audit_transaction_p2026_06"]
    assert report.orphaned == [f"{schema}.audit_activity_20_p2025_01"]
    assert not report.ok


@pytest.fixture
def old_tables(engine: Engine, schema: str) -> AuditTables:
    """Audit tables with monthly partitions for January and February 2020 only."""
    t = build_tables(schema=schema)
    with engine.begin() as conn:
        create_audit_tables(conn, t, Sev)
        ensure_partitions(
            conn, t, Sev, months_ahead=1, now=datetime(2020, 1, 5, tzinfo=timezone.utc)
        )
    return t


def test_manager_sync(engine: Engine, old_tables: AuditTables, schema: str) -> None:
    manager = PartitionManager(engine, old_tables, Sev)

    dropped = manager.drop_expired(
        {Sev.INFO: DAY, Sev.NOTICE: None, Sev.CRITICAL: None}
    )

    assert dropped == [
        f"{schema}.audit_transaction_p2020_01",
        f"{schema}.audit_transaction_p2020_02",
        f"{schema}.audit_activity_10_p2020_01",
        f"{schema}.audit_activity_10_p2020_02",
    ]
    assert not manager.health().transaction.covers_now
    manager.ensure_partitions(months_ahead=3)
    assert manager.health().ok


async def test_manager_async(
    async_engine: AsyncEngine, engine: Engine, old_tables: AuditTables, schema: str
) -> None:
    manager = PartitionManager(async_engine, old_tables, Sev)

    dropped = await manager.adrop_expired(dict.fromkeys(Sev, DAY))

    assert len(dropped) == 2 * 4
    assert months(engine, schema) == set()
    assert not (await manager.ahealth()).ok
    await manager.aensure_partitions(months_ahead=3)
    assert (await manager.ahealth()).ok


async def test_manager_rejects_wrong_engine_kind(
    async_engine: AsyncEngine, engine: Engine
) -> None:
    tables = build_tables()
    with pytest.raises(TypeError, match="adrop_expired"):
        PartitionManager(async_engine, tables, Sev).drop_expired({})
    with pytest.raises(TypeError, match="use drop_expired"):
        await PartitionManager(engine, tables, Sev).adrop_expired({})
    with pytest.raises(TypeError, match="ahealth"):
        PartitionManager(async_engine, tables, Sev).health()
    with pytest.raises(TypeError, match="use health"):
        await PartitionManager(engine, tables, Sev).ahealth()
