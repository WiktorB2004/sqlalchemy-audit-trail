"""``ensure_partitions`` and ``PartitionManager`` against a real PostgreSQL."""

from __future__ import annotations

import threading
import time
import uuid
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from enum import IntEnum

import pytest
from sqlalchemy import Connection, Engine, insert, text
from sqlalchemy.ext.asyncio import AsyncEngine

from audit_trail.maintenance import (
    PartitionError,
    PartitionLockTimeoutError,
    PartitionManager,
    ensure_partitions,
)
from audit_trail.migrations import create_audit_tables, qualified_name
from audit_trail.tables import AuditTables, build_tables


class Sev(IntEnum):
    INFO = 10
    NOTICE = 20


SEPT = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)


@pytest.fixture
def tables(engine: Engine, schema: str) -> AuditTables:
    t = build_tables(schema=schema)
    with engine.begin() as conn:
        create_audit_tables(conn, t, Sev)
    return t


def partitions(conn: Connection, schema: str) -> dict[str, str]:
    """Every partition in ``schema``: name -> parent and bound, in UTC."""
    conn.execute(text("SET LOCAL TimeZone = 'UTC'"))
    rows = conn.execute(
        text(
            """
            SELECT c.relname, p.relname || ' ' || pg_get_expr(c.relpartbound, c.oid)
            FROM pg_inherits i
            JOIN pg_class c ON c.oid = i.inhrelid
            JOIN pg_class p ON p.oid = i.inhparent
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = :schema AND c.relkind IN ('r', 'p')
            """
        ),
        {"schema": schema},
    )
    return {name: bound for name, bound in rows}


def ensure(
    engine: Engine,
    tables: AuditTables,
    *,
    severities: type[IntEnum] | list[int] = Sev,
    months_ahead: int = 0,
    now: datetime = SEPT,
    time_zone: str = "UTC",
    lock_timeout: str | None = "5s",
) -> list[str]:
    with engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('TimeZone', :tz, true)"), {"tz": time_zone}
        )
        return ensure_partitions(
            conn,
            tables,
            severities,
            months_ahead=months_ahead,
            now=now,
            lock_timeout=lock_timeout,
        )


def test_creates_named_partitions_across_year_end(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    created = ensure(
        engine, tables, months_ahead=2, now=datetime(2026, 11, 30, tzinfo=timezone.utc)
    )

    months = ["p2026_11", "p2026_12", "p2027_01"]
    assert created == [
        *(f"{schema}.audit_transaction_{m}" for m in months),
        *(f"{schema}.audit_activity_10_{m}" for m in months),
        *(f"{schema}.audit_activity_20_{m}" for m in months),
    ]
    with engine.begin() as conn:
        found = partitions(conn, schema)
    assert found["audit_activity_10"] == "audit_activity FOR VALUES IN ('10')"
    assert found["audit_transaction_p2026_12"] == (
        "audit_transaction FOR VALUES FROM ('2026-12-01 00:00:00+00') "
        "TO ('2027-01-01 00:00:00+00')"
    )
    assert found["audit_activity_20_p2027_01"] == (
        "audit_activity_20 FOR VALUES FROM ('2027-01-01 00:00:00+00') "
        "TO ('2027-02-01 00:00:00+00')"
    )


def test_second_call_changes_nothing(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    assert ensure(engine, tables, months_ahead=3, time_zone="Asia/Kolkata")
    with engine.begin() as conn:
        before = partitions(conn, schema)

    assert ensure(engine, tables, months_ahead=3, time_zone="America/New_York") == []
    with engine.begin() as conn:
        assert partitions(conn, schema) == before


def test_month_with_same_bounds_under_other_name_is_reused(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    tx = qualified_name(schema, "audit_transaction")
    sev10 = qualified_name(schema, "audit_activity_10")
    with engine.begin() as conn:
        # Same instants as the library's UTC bounds, written in another offset.
        bounds = "FROM ('2026-09-01 02:00:00+02') TO ('2026-10-01 02:00:00+02')"
        conn.exec_driver_sql(
            f"CREATE TABLE {schema}.legacy_tx PARTITION OF {tx} FOR VALUES {bounds}"
        )
        conn.exec_driver_sql(
            f"CREATE TABLE {schema}.legacy_10 PARTITION OF {sev10} FOR VALUES {bounds}"
        )

    created = ensure(engine, tables, time_zone="America/Los_Angeles")

    assert created == [f"{schema}.audit_activity_20_p2026_09"]
    with engine.begin() as conn:
        found = partitions(conn, schema)
    assert "audit_transaction_p2026_09" not in found
    assert "audit_activity_10_p2026_09" not in found


def test_wider_existing_partition_counts_as_present(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    tx = qualified_name(schema, "audit_transaction")
    with engine.begin() as conn:
        conn.exec_driver_sql(
            f"CREATE TABLE {schema}.tx_q3 PARTITION OF {tx} "
            "FOR VALUES FROM ('2026-07-01 00:00:00+00') TO ('2026-10-01 00:00:00+00')"
        )
        conn.exec_driver_sql(
            f"CREATE TABLE {schema}.tx_rest PARTITION OF {tx} "
            "FOR VALUES FROM ('2026-10-01 00:00:00+00') TO (MAXVALUE)"
        )

    created = ensure(engine, tables, months_ahead=2)

    assert not [name for name in created if "audit_transaction" in name]


def test_severity_partition_under_other_name_is_reused(
    engine: Engine, schema: str
) -> None:
    tables = build_tables(schema=schema)
    activity = qualified_name(schema, "audit_activity")
    with engine.begin() as conn:
        create_audit_tables(conn, tables, [])
        conn.exec_driver_sql(
            f"CREATE TABLE {schema}.low PARTITION OF {activity} "
            "FOR VALUES IN (10, 20) PARTITION BY RANGE (created_at)"
        )
        conn.exec_driver_sql(
            f"CREATE TABLE {schema}.high PARTITION OF {activity} FOR VALUES IN (40)"
        )

    created = ensure(engine, tables, severities=[10, 20, 30, 40], months_ahead=1)

    assert created == [
        f"{schema}.audit_transaction_p2026_09",
        f"{schema}.audit_transaction_p2026_10",
        f"{schema}.low_p2026_09",
        f"{schema}.low_p2026_10",
        f"{schema}.audit_activity_30",
        f"{schema}.audit_activity_30_p2026_09",
        f"{schema}.audit_activity_30_p2026_10",
    ]
    assert ensure(engine, tables, severities=[10, 20, 30, 40], months_ahead=1) == []


def test_new_severity_is_added(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    ensure(engine, tables)

    created = ensure(engine, tables, severities=[10, 20, 30])

    assert created == [
        f"{schema}.audit_activity_30",
        f"{schema}.audit_activity_30_p2026_09",
    ]


@pytest.mark.parametrize("time_zone", ["UTC", "Europe/Warsaw", "America/New_York"])
def test_row_at_month_start_lands_in_that_month(
    engine: Engine, tables: AuditTables, schema: str, time_zone: str
) -> None:
    ensure(
        engine,
        tables,
        months_ahead=1,
        now=datetime(2026, 8, 5, tzinfo=timezone.utc),
        time_zone=time_zone,
    )
    first_instant = datetime(2026, 9, 1, tzinfo=timezone.utc)
    last_instant = datetime(2026, 8, 31, 23, 59, 59, 999999, tzinfo=timezone.utc)

    with engine.begin() as conn:
        conn.execute(
            text("SELECT set_config('TimeZone', :tz, true)"), {"tz": time_zone}
        )
        landed: dict[datetime, tuple[str, str]] = {}
        for at in (first_instant, last_instant):
            tx_part: str = conn.execute(
                insert(tables.transaction)
                .values(actor_type="system", issued_at=at)
                .returning(text("tableoid::regclass::text"))
            ).scalar_one()
            act_part: str = conn.execute(
                insert(tables.activity)
                .values(transaction_id=1, verb="x", severity=Sev.INFO, created_at=at)
                .returning(text("tableoid::regclass::text"))
            ).scalar_one()
            landed[at] = (tx_part.split(".")[-1], act_part.split(".")[-1])

    assert landed[first_instant] == (
        "audit_transaction_p2026_09",
        "audit_activity_10_p2026_09",
    )
    assert landed[last_instant] == (
        "audit_transaction_p2026_08",
        "audit_activity_10_p2026_08",
    )


def test_lock_timeout_fails_fast_then_retry_succeeds(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    ensure(engine, tables)
    target = qualified_name(schema, "audit_activity_10")
    observed: list[str] = []

    with engine.connect() as blocker:
        # An open business transaction with an uncommitted audit row.
        blocker.execute(
            insert(tables.activity).values(
                transaction_id=1, verb="x", severity=Sev.INFO, created_at=SEPT
            )
        )

        stop = threading.Event()

        def watch_locks() -> None:
            with engine.connect() as conn:
                while not stop.is_set() and not observed:
                    observed.extend(
                        conn.execute(
                            text(
                                "SELECT mode FROM pg_locks WHERE NOT granted "
                                "AND relation = to_regclass(:t)"
                            ),
                            {"t": target},
                        ).scalars()
                    )
                    conn.rollback()
                    time.sleep(0.01)

        with ThreadPoolExecutor(max_workers=2) as pool:
            watcher = pool.submit(watch_locks)
            started = time.monotonic()
            attempt = pool.submit(
                ensure, engine, tables, months_ahead=1, lock_timeout="500ms"
            )
            # A regression hangs visibly here instead of forever.
            with pytest.raises(PartitionLockTimeoutError, match="not created"):
                attempt.result(timeout=30)
            elapsed = time.monotonic() - started
            stop.set()
            watcher.result(timeout=30)

        blocker.commit()

    assert elapsed < 10
    assert observed == ["AccessExclusiveLock"]
    with engine.begin() as conn:
        assert "audit_transaction_p2026_10" not in partitions(conn, schema)
    assert ensure(engine, tables, months_ahead=1) == [
        f"{schema}.audit_transaction_p2026_10",
        f"{schema}.audit_activity_10_p2026_10",
        f"{schema}.audit_activity_20_p2026_10",
    ]


def test_manager_sync(engine: Engine, tables: AuditTables) -> None:
    manager = PartitionManager(engine, tables, Sev)

    created = manager.ensure_partitions(months_ahead=3)

    assert len(created) == 3 * 4
    assert manager.ensure_partitions(months_ahead=3) == []


@pytest.fixture
async def async_schema(async_engine: AsyncEngine) -> AsyncIterator[str]:
    # Every character that could break naive quoting or placeholder parsing.
    name = f'Au"dit %s :x {uuid.uuid4().hex[:8]}'
    yield name
    async with async_engine.begin() as conn:
        await conn.exec_driver_sql(
            f"DROP SCHEMA IF EXISTS {qualified_name(None, name)} CASCADE",
            execution_options={"no_parameters": True},
        )


async def test_manager_async(async_engine: AsyncEngine, async_schema: str) -> None:
    tables = build_tables(
        schema=async_schema, transaction_table="Tx", activity_table="Act ivity"
    )
    async with async_engine.begin() as conn:
        await conn.run_sync(create_audit_tables, tables, Sev)
    manager = PartitionManager(async_engine, tables, Sev)

    created = await manager.aensure_partitions(months_ahead=1)

    assert len(created) == 3 * 2
    assert f"{async_schema}.Act ivity_20_p" in created[-1]
    assert await manager.aensure_partitions(months_ahead=1) == []
    async with async_engine.begin() as conn:
        tx_part = (
            await conn.execute(
                insert(tables.transaction)
                .values(actor_type="system")
                .returning(text("tableoid::regclass::text"))
            )
        ).scalar_one()
    assert "Tx_p" in tx_part


async def test_manager_rejects_wrong_engine_kind(
    async_engine: AsyncEngine, engine: Engine
) -> None:
    tables = build_tables()
    with pytest.raises(TypeError, match="aensure_partitions"):
        PartitionManager(async_engine, tables, Sev).ensure_partitions()
    with pytest.raises(TypeError, match="use ensure_partitions"):
        await PartitionManager(engine, tables, Sev).aensure_partitions()


def test_rejects_autocommit_and_negative_months(
    engine: Engine, tables: AuditTables
) -> None:
    with engine.connect() as conn:
        auto = conn.execution_options(isolation_level="AUTOCOMMIT")
        with pytest.raises(ValueError, match="AUTOCOMMIT"):
            ensure_partitions(auto, tables, Sev)
    with engine.begin() as conn, pytest.raises(ValueError, match="negative"):
        ensure_partitions(conn, tables, Sev, months_ahead=-1)


def test_missing_parent_is_reported(engine: Engine, schema: str) -> None:
    with engine.begin() as conn, pytest.raises(PartitionError, match="does not exist"):
        ensure_partitions(conn, build_tables(schema=schema), Sev)


def test_restores_session_lock_timeout(engine: Engine, tables: AuditTables) -> None:
    with engine.begin() as conn:
        conn.execute(text("SET LOCAL lock_timeout = '42s'"))
        ensure_partitions(conn, tables, Sev, lock_timeout="1s")
        assert conn.execute(text("SHOW lock_timeout")).scalar_one() == "42s"
