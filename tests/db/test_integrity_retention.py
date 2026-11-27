"""``drop_expired`` with integrity: seal, verify, retire, then drop.

Every partition is dropped by ``drop_expired`` itself, against a real
PostgreSQL; lock conflicts come from real open transactions and a short
``lock_timeout``, never from sleeps.
"""

from __future__ import annotations

import time
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime, timedelta
from enum import IntEnum
from typing import Any

import pytest
from sqlalchemy import (
    Connection,
    Engine,
    create_engine,
    event,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine

from audit_trail import migrations
from audit_trail.integrity import _retire, _seal
from audit_trail.integrity._block import block_hash, parse_body, retire_body
from audit_trail.integrity._commit import (
    activity_groups,
    seal_columns,
    transaction_groups,
)
from audit_trail.integrity._verify import (
    FailureKind,
    NoteKind,
    Status,
    VerificationReport,
)
from audit_trail.integrity._verify_db import verify
from audit_trail.maintenance import (
    DroppedPartitions,
    PartitionError,
    PartitionManager,
    drop_expired,
    ensure_partitions,
)
from audit_trail.migrations import create_audit_tables
from audit_trail.tables import AuditTables, build_tables

pytestmark = pytest.mark.filterwarnings("ignore:Did not recognize type 'xid8'")


class Sev(IntEnum):
    INFO = 10
    NOTICE = 20


NOW = datetime(2026, 9, 10, 12, tzinfo=UTC)
JUNE = datetime(2026, 6, 15, tzinfo=UTC)
DAY = timedelta(days=1)
# NOW - 30 days is 2026-08-11: June and July have expired for INFO, and the
# transaction table follows the shortest retention.
RETENTION: dict[Sev, timedelta | None] = {Sev.INFO: 30 * DAY, Sev.NOTICE: None}


def expired(schema: str) -> list[str]:
    return [
        f"{schema}.audit_transaction_p2026_06",
        f"{schema}.audit_transaction_p2026_07",
        f"{schema}.audit_activity_10_p2026_06",
        f"{schema}.audit_activity_10_p2026_07",
    ]


def build(engine: Engine, schema: str, *, integrity: bool) -> AuditTables:
    """Audit tables with monthly partitions from June to September 2026."""
    tables = build_tables(schema=schema, integrity=integrity)
    with engine.begin() as conn:
        create_audit_tables(conn, tables, Sev)
        ensure_partitions(
            conn, tables, Sev, months_ahead=3, now=datetime(2026, 6, 5, tzinfo=UTC)
        )
        if integrity:
            migrations.write_genesis(conn, tables)
    return tables


@pytest.fixture
def tables(engine: Engine, schema: str) -> AuditTables:
    return build(engine, schema, integrity=True)


def add_rows(conn: Connection, tables: AuditTables, at: datetime) -> None:
    """One transaction row and one activity row per severity, committed to."""
    values: dict[str, Any] = {"actor_type": "system", "issued_at": at}
    values.update(seal_columns(transaction_groups(values)))
    conn.execute(insert(tables.transaction).values(values))
    for sev in Sev:
        data = {"v": 1, "payload": {"n": int(sev)}}
        conn.execute(
            insert(tables.activity).values(
                transaction_id=1,
                verb="x",
                severity=sev,
                created_at=at,
                data=data,
                **seal_columns(activity_groups(None, data)),
            )
        )


def write(engine: Engine, tables: AuditTables, at: datetime = JUNE) -> None:
    with engine.begin() as conn:
        add_rows(conn, tables, at)


def drop(
    engine: Engine,
    tables: AuditTables,
    retention: Mapping[Sev, timedelta | None] = RETENTION,
    **kwargs: Any,
) -> DroppedPartitions:
    kwargs.setdefault("now", NOW)
    with engine.connect() as conn:
        auto = conn.execution_options(isolation_level="AUTOCOMMIT")
        return drop_expired(auto, tables, retention, **kwargs)


def run(engine: Engine, tables: AuditTables, **options: Any) -> VerificationReport:
    return verify(engine, tables, **options)


def retire_blocks(engine: Engine, tables: AuditTables) -> dict[str, dict[str, Any]]:
    """Body of each retire block, by its ``retired_partition``."""
    block = _seal.block_table(tables)
    with engine.connect() as conn:
        rows = conn.execute(
            select(block.c.retired_partition, block.c.body)
            .where(block.c.kind == "retire")
            .order_by(block.c.seq)
        ).all()
    return {str(name): parse_body(bytes(body)) for name, body in rows}


def block_count(engine: Engine, tables: AuditTables) -> int:
    block = _seal.block_table(tables)
    with engine.connect() as conn:
        return len(conn.execute(select(block.c.seq)).all())


def attached(engine: Engine, schema: str) -> dict[str, bool]:
    """Monthly partitions still attached in ``schema``, and whether pending."""
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT c.relname, i.inhdetachpending FROM pg_inherits i "
                "JOIN pg_class c ON c.oid = i.inhrelid "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = :schema AND c.relname LIKE '%\\_p20__\\___'"
            ),
            {"schema": schema},
        )
        return {str(name): bool(pending) for name, pending in rows}


def exists(engine: Engine, schema: str, name: str) -> bool:
    with engine.connect() as conn:
        found = conn.execute(
            text("SELECT to_regclass(:name) IS NOT NULL"),
            {"name": f'"{schema}"."{name}"'},
        ).scalar_one()
    return bool(found)


def short(names: list[str]) -> list[str]:
    return [name.rpartition(".")[2] for name in names]


# -- integrity off ----------------------------------------------------------------


def test_integrity_off_drops_as_before(engine: Engine, schema: str) -> None:
    tables = build(engine, schema, integrity=False)
    with engine.begin() as conn:
        conn.execute(
            insert(tables.transaction).values(actor_type="system", issued_at=JUNE)
        )
    checkouts: list[object] = []

    def count(*_args: object) -> None:
        checkouts.append(_args)

    event.listen(engine, "checkout", count)
    try:
        dropped = drop(engine, tables)
    finally:
        event.remove(engine, "checkout", count)
    # A list of the names, as before; no second connection, nothing skipped.
    assert isinstance(dropped, list)
    assert dropped == expired(schema)
    assert dropped.skipped == []
    assert len(checkouts) == 1
    assert sorted(attached(engine, schema)) == sorted(
        {f"audit_transaction_p2026_{m:02d}" for m in (8, 9)}
        | {f"audit_activity_10_p2026_{m:02d}" for m in (8, 9)}
        | {f"audit_activity_20_p2026_{m:02d}" for m in (6, 7, 8, 9)}
    )


# -- retire blocks ------------------------------------------------------------------


def test_an_empty_partition_gets_a_retire_block(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    dropped = drop(engine, tables)
    assert dropped == expired(schema)
    assert dropped.skipped == []
    retired = retire_blocks(engine, tables)
    assert list(retired) == short(expired(schema))
    june = retired["audit_transaction_p2026_06"]
    assert (june["seals"], june["segments"], june["rows"]) == (None, 0, 0)
    assert (june["table"], june["streams"]) == ("transaction", ["transaction"])
    assert june["upper_bound"] == "2026-07-01T00:00:00.000000Z"
    assert june["retention"] == 30 * 86400
    info = retired["audit_activity_10_p2026_06"]
    assert (info["table"], info["streams"]) == ("activity", ["activity.10"])
    assert run(engine, tables).status is Status.VALID


def test_a_partition_with_rows_is_sealed_then_retired(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    write(engine, tables)
    # Nothing sealed yet: drop_expired seals first.
    dropped = drop(engine, tables)
    assert dropped == expired(schema)
    retired = retire_blocks(engine, tables)
    june = retired["audit_transaction_p2026_06"]
    assert (june["seals"], june["segments"], june["rows"]) == (
        {"first": 2, "last": 2},
        1,
        1,
    )
    assert retired["audit_activity_10_p2026_06"]["rows"] == 1
    report = run(engine, tables)
    assert report.failures == []
    assert {(f.kind, f.partition) for f in report.notes} == {
        (NoteKind.RETIRED, "audit_transaction_p2026_06"),
        (NoteKind.RETIRED, "audit_activity_10_p2026_06"),
    }
    # The NOTICE row of June is kept and still checked.
    assert attached(engine, schema)["audit_activity_20_p2026_06"] is False


def test_a_retire_inside_the_retention_is_retired_early(
    engine: Engine, tables: AuditTables
) -> None:
    write(engine, tables)
    drop(engine, tables)
    assert run(engine, tables, retention=RETENTION).failures == []
    # Ten years for INFO: every retire block of an INFO partition, and of
    # the transaction table capped to it, came too early.
    longer = {Sev.INFO: 3650 * DAY, Sev.NOTICE: None}
    report = run(engine, tables, retention=longer)
    assert {f.kind for f in report.failures} == {FailureKind.RETIRED_EARLY}
    assert sorted(str(f.partition) for f in report.failures) == sorted(
        [
            "audit_transaction_p2026_06",
            "audit_transaction_p2026_07",
            "audit_activity_10_p2026_06",
            "audit_activity_10_p2026_07",
        ]
    )


def test_a_partition_dropped_without_a_retire_block_is_segment_missing(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    write(engine, tables)
    drop(engine, tables)
    assert run(engine, tables).failures == []
    # The NOTICE partition of June, dropped by hand under a forged retire
    # block that claims it held nothing.
    name = "audit_activity_20_p2026_06"
    block = _seal.block_table(tables)
    with engine.begin() as conn:
        last = _seal.last_block(conn, block)
        chain = _seal._sealed_to(conn, block)
        assert chain is not None
        body = retire_body(
            chain[0],
            int(last.seq) + 1,
            table="activity",
            partition=name,
            streams=["activity.20"],
            upper_bound=datetime(2026, 7, 1, tzinfo=UTC),
            retention=None,
            segments=[],
        )
        _seal.insert_block(
            conn, block, int(last.seq) + 1, "retire", last.block_hash, body
        )
        parent = f'"{schema}"."audit_activity_20"'
        conn.execute(text(f'ALTER TABLE {parent} DETACH PARTITION "{schema}"."{name}"'))
        conn.execute(text(f'DROP TABLE "{schema}"."{name}"'))
    report = run(engine, tables)
    assert {(f.kind, f.partition) for f in report.failures} == {
        (FailureKind.MALFORMED_BLOCK, None),
        (FailureKind.SEGMENT_MISSING, name),
    }


def test_a_retry_or_finalize_adds_no_second_block(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    write(engine, tables)
    with engine.connect() as reader:
        # An open transaction that read the June transaction partition.
        reader.execute(
            text(f'SELECT count(*) FROM "{schema}"."audit_transaction_p2026_06"')
        )
        first = drop(engine, tables, lock_timeout="500ms")
        reader.rollback()
    assert short(first) == ["audit_activity_10_p2026_06", "audit_activity_10_p2026_07"]
    # Both transaction partitions were retired before their detach.
    assert sorted(retire_blocks(engine, tables)) == sorted(short(expired(schema)))
    blocks = block_count(engine, tables)

    second = drop(engine, tables)

    # The pending June detach is finalized, July detached; neither adds a
    # retire block, and the chain verifies.
    assert short(second) == ["audit_transaction_p2026_06", "audit_transaction_p2026_07"]
    assert second.skipped == []
    assert block_count(engine, tables) == blocks
    report = run(engine, tables)
    assert report.failures == []
    assert NoteKind.RETIRED in report.kinds()


def test_an_open_transaction_skips_the_partition_and_reports_it(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    write(engine, tables)
    with engine.connect() as reader:
        reader.execute(
            text(f'SELECT count(*) FROM "{schema}"."audit_transaction_p2026_06"')
        )
        dropped = drop(engine, tables, lock_timeout="500ms")
        assert [(s.partition, s.reason) for s in dropped.skipped] == [
            (f"{schema}.audit_transaction_p2026_06", "lock_not_available"),
            (f"{schema}.audit_transaction_p2026_07", "detach_pending"),
        ]
        reader.rollback()
    assert f"{schema}.audit_transaction_p2026_06" not in dropped
    # June stays, pending detach; July stays attached. verify reports the
    # pending one until the next call finishes it.
    state = attached(engine, schema)
    assert state["audit_transaction_p2026_06"] is True
    assert state["audit_transaction_p2026_07"] is False
    report = run(engine, tables)
    assert [(f.kind, f.partition) for f in report.failures] == [
        (FailureKind.DETACHED_PARTITION, "audit_transaction_p2026_06")
    ]


# -- crash windows ------------------------------------------------------------------


class Crash(Exception):
    pass


def crash_on(monkeypatch: pytest.MonkeyPatch, statement: str) -> None:
    """Make ``drop_expired`` stop when it runs its first ``statement``."""
    ddl = _retire.Retirer.ddl

    def crashing(self: _retire.Retirer, conn: Connection, sql: str, child: Any) -> bool:
        if sql.startswith(statement):
            raise Crash(sql)
        return ddl(self, conn, sql, child)

    monkeypatch.setattr(_retire.Retirer, "ddl", crashing)


def test_a_crash_between_retire_and_drop_verifies_clean(
    engine: Engine,
    tables: AuditTables,
    schema: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(engine, tables)
    crash_on(monkeypatch, "ALTER TABLE")
    with pytest.raises(Crash):
        drop(engine, tables)
    # The first partition is retired, and still attached with its rows.
    assert list(retire_blocks(engine, tables)) == ["audit_transaction_p2026_06"]
    assert attached(engine, schema)["audit_transaction_p2026_06"] is False
    report = run(engine, tables)
    assert report.failures == []
    assert report.status is Status.VALID

    monkeypatch.undo()
    blocks = block_count(engine, tables)
    assert drop(engine, tables) == expired(schema)
    # One retire block more for each partition not retired yet.
    assert block_count(engine, tables) == blocks + 3
    assert run(engine, tables).failures == []


def test_a_crash_between_detach_and_drop_is_reported(
    engine: Engine,
    tables: AuditTables,
    schema: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(engine, tables)
    crash_on(monkeypatch, "DROP TABLE")
    with pytest.raises(Crash):
        drop(engine, tables)
    name = "audit_transaction_p2026_06"
    assert name not in attached(engine, schema)
    assert exists(engine, schema, name)
    report = run(engine, tables)
    assert [(f.kind, f.partition) for f in report.failures] == [
        (FailureKind.DETACHED_PARTITION, name)
    ]

    # The next call drops the detached table under its retire block.
    monkeypatch.undo()
    blocks = block_count(engine, tables)
    dropped = drop(engine, tables)
    assert dropped == expired(schema)
    assert dropped.skipped == []
    assert not exists(engine, schema, name)
    assert block_count(engine, tables) == blocks + 3
    assert run(engine, tables).failures == []


# -- detached partitions left by an earlier call ------------------------------------


def before_drop(monkeypatch: pytest.MonkeyPatch, name: str, action: Any) -> None:
    """Run ``action(engine)`` just before ``drop_expired`` drops ``name``."""
    ddl = _retire.Retirer.ddl

    def patched(self: _retire.Retirer, conn: Connection, sql: str, child: Any) -> bool:
        if sql.startswith("DROP TABLE") and child.name == name:
            action()
        return ddl(self, conn, sql, child)

    monkeypatch.setattr(_retire.Retirer, "ddl", patched)


def test_a_detached_table_kept_by_a_lock_is_dropped_next_time(
    engine: Engine,
    tables: AuditTables,
    schema: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(engine, tables)
    name = "audit_transaction_p2026_06"
    with engine.connect() as locker:

        def lock() -> None:
            # Detached already; the drop waits for this lock and times out.
            locker.execute(text(f'LOCK TABLE "{schema}"."{name}" IN ACCESS SHARE MODE'))

        before_drop(monkeypatch, name, lock)
        first = drop(engine, tables, lock_timeout="500ms")
        locker.rollback()
    assert [(s.partition, s.reason) for s in first.skipped] == [
        (f"{schema}.{name}", "lock_not_available")
    ]
    assert name not in attached(engine, schema)
    assert exists(engine, schema, name)

    monkeypatch.undo()
    blocks = block_count(engine, tables)
    second = drop(engine, tables)
    assert second == [f"{schema}.{name}"]
    assert second.skipped == []
    assert not exists(engine, schema, name)
    # Its retire block was written by the first call.
    assert block_count(engine, tables) == blocks
    assert run(engine, tables).failures == []


def test_a_detached_table_kept_by_a_failed_drop_is_dropped_next_time(
    engine: Engine,
    tables: AuditTables,
    schema: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(engine, tables)
    name = "audit_transaction_p2026_06"
    view = f'"{schema}"."depends_on_june"'

    def depend() -> None:
        with engine.begin() as conn:
            conn.execute(
                text(f'CREATE VIEW {view} AS SELECT * FROM "{schema}"."{name}"')
            )

    before_drop(monkeypatch, name, depend)
    with pytest.raises(DBAPIError, match="depends_on_june"):
        drop(engine, tables)
    assert name not in attached(engine, schema)
    assert exists(engine, schema, name)

    monkeypatch.undo()
    with engine.begin() as conn:
        conn.execute(text(f"DROP VIEW {view}"))
    dropped = drop(engine, tables)
    assert dropped == expired(schema)
    assert dropped.skipped == []
    assert not exists(engine, schema, name)
    assert run(engine, tables).failures == []


def test_a_detached_table_without_a_retire_block_is_kept(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    write(engine, tables)
    name = "audit_transaction_p2026_06"
    with engine.begin() as conn:
        # Detached by hand: no retire block covers it.
        conn.execute(
            text(
                f'ALTER TABLE "{schema}"."audit_transaction" '
                f'DETACH PARTITION "{schema}"."{name}"'
            )
        )
    dropped = drop(engine, tables)
    assert [(s.partition, s.reason) for s in dropped.skipped] == [
        (f"{schema}.{name}", "not_retired")
    ]
    assert dropped == [n for n in expired(schema) if not n.endswith(name)]
    assert exists(engine, schema, name)
    assert name not in retire_blocks(engine, tables)


def test_a_detached_table_under_a_forged_retire_block_is_kept(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    write(engine, tables)
    name = "audit_transaction_p2026_06"
    with engine.connect() as conn:
        assert _seal.seal(conn, tables).blocks == 1
    block = _seal.block_table(tables)
    with engine.begin() as conn:
        last = _seal.last_block(conn, block)
        chain = _seal._sealed_to(conn, block)
        assert chain is not None
        seq = int(last.seq) + 1
        # It claims the partition held nothing; the chain sealed a row of it.
        body = retire_body(
            chain[0],
            seq,
            table="transaction",
            partition=name,
            streams=["transaction"],
            upper_bound=datetime(2026, 7, 1, tzinfo=UTC),
            retention=30 * 86400,
            segments=[],
        )
        prev = bytes(last.block_hash)
        conn.execute(
            insert(block).values(
                seq=seq,
                kind="retire",
                body=body,
                prev_hash=prev,
                block_hash=block_hash(prev, body),
                retired_partition=name,
            )
        )
        conn.execute(
            text(
                f'ALTER TABLE "{schema}"."audit_transaction" '
                f'DETACH PARTITION "{schema}"."{name}"'
            )
        )
    # Without the verify, which would refuse the whole chain.
    dropped = drop(engine, tables, verify_before_drop=False)
    assert [(s.partition, s.reason) for s in dropped.skipped] == [
        (f"{schema}.{name}", "not_retired")
    ]
    assert exists(engine, schema, name)


# -- what keeps a partition -----------------------------------------------------------


def test_an_unsealed_row_keeps_its_partition(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    with engine.connect() as holder:
        # An open transaction with an xid holds the horizon back, so a row
        # committed after it stays unsealed. It touches no audit table, so
        # it blocks no detach.
        holder.execute(text("SELECT pg_current_xact_id()"))
        write(engine, tables)
        dropped = drop(engine, tables)
        holder.rollback()
    unsealed = [s.partition for s in dropped.skipped if s.reason == "unsealed"]
    assert unsealed == [
        f"{schema}.audit_transaction_p2026_06",
        f"{schema}.audit_activity_10_p2026_06",
    ]
    assert short(dropped) == [
        "audit_transaction_p2026_07",
        "audit_activity_10_p2026_07",
    ]
    assert "audit_transaction_p2026_06" not in retire_blocks(engine, tables)
    assert attached(engine, schema)["audit_transaction_p2026_06"] is False
    # Once the holder has ended, the next call seals the rows and drops them.
    assert short(drop(engine, tables)) == [
        "audit_transaction_p2026_06",
        "audit_activity_10_p2026_06",
    ]
    assert run(engine, tables).failures == []


def test_a_failed_verify_keeps_the_partition(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    write(engine, tables)
    with engine.connect() as conn:
        assert _seal.seal(conn, tables).blocks == 1
    with engine.begin() as conn:
        conn.execute(
            update(tables.activity)
            .where(tables.activity.c.severity == Sev.INFO)
            .values(object_id="forged")
        )
    dropped = drop(engine, tables)
    assert [(s.partition, s.reason) for s in dropped.skipped] == [
        (f"{schema}.audit_activity_10_p2026_06", "verify_failed")
    ]
    assert "ROOT_MISMATCH" in dropped.skipped[0].detail
    assert "audit_activity_10_p2026_06" not in retire_blocks(engine, tables)
    assert attached(engine, schema)["audit_activity_10_p2026_06"] is False
    # Without verify_before_drop it goes, retired as the chain sealed it.
    assert short(drop(engine, tables, verify_before_drop=False)) == [
        "audit_activity_10_p2026_06"
    ]
    assert run(engine, tables).failures == []


def test_rows_after_the_retire_block_keep_the_detached_table(
    engine: Engine,
    tables: AuditTables,
    schema: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    retire = _retire.Retirer.retire

    def retire_then_write(self: _retire.Retirer, target: Any, child: Any) -> bool:
        done = retire(self, target, child)
        if child.name == "audit_transaction_p2026_06":
            # A row lands in the partition after its retire block.
            values: dict[str, Any] = {"actor_type": "system", "issued_at": JUNE}
            values.update(seal_columns(transaction_groups(values)))
            with engine.begin() as conn:
                conn.execute(insert(tables.transaction).values(values))
        return done

    monkeypatch.setattr(_retire.Retirer, "retire", retire_then_write)
    dropped = drop(engine, tables)
    name = "audit_transaction_p2026_06"
    assert [(s.partition, s.reason) for s in dropped.skipped] == [
        (f"{schema}.{name}", "changed_after_retire")
    ]
    assert name not in attached(engine, schema)
    assert exists(engine, schema, name)
    report = run(engine, tables)
    assert (FailureKind.DETACHED_PARTITION, name) in {
        (f.kind, f.partition) for f in report.failures
    }


# -- the chain must be started --------------------------------------------------------


def test_an_empty_chain_drops_as_without_integrity(engine: Engine, schema: str) -> None:
    tables = build_tables(schema=schema, integrity=True)
    with engine.begin() as conn:
        create_audit_tables(conn, tables, Sev)
        ensure_partitions(
            conn, tables, Sev, months_ahead=3, now=datetime(2026, 6, 5, tzinfo=UTC)
        )
    checkouts: list[object] = []

    def count(*_args: object) -> None:
        checkouts.append(_args)

    event.listen(engine, "checkout", count)
    try:
        dropped = drop(engine, tables)
    finally:
        event.remove(engine, "checkout", count)
    # No block yet: nothing was sealed, so nothing is retired or skipped,
    # and no second connection is taken.
    assert dropped == expired(schema)
    assert dropped.skipped == []
    assert len(checkouts) == 1
    assert block_count(engine, tables) == 0


def test_blocks_without_a_genesis_drop_nothing(engine: Engine, schema: str) -> None:
    tables = build_tables(schema=schema, integrity=True)
    with engine.begin() as conn:
        create_audit_tables(conn, tables, Sev)
        ensure_partitions(
            conn, tables, Sev, months_ahead=3, now=datetime(2026, 6, 5, tzinfo=UTC)
        )
        # A chain whose only block is not a genesis block.
        block = _seal.block_table(tables)
        body = b'{"kind":"ack"}'
        _seal.insert_block(conn, block, 1, "ack", bytes(32), body)
    with pytest.raises(_seal.SealRefusedError, match="NO_GENESIS"):
        drop(engine, tables)
    assert len(attached(engine, schema)) == 4 * 3


# -- reading the chain ---------------------------------------------------------------


def test_each_block_is_read_once_per_call(
    engine: Engine,
    tables: AuditTables,
    schema: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    write(engine, tables)
    write(engine, tables, JUNE + 20 * DAY)
    with engine.connect() as reader:
        # The transaction partitions are retired but kept: the next call
        # checks each against the blocks after its retire block.
        reader.execute(
            text(f'SELECT count(*) FROM "{schema}"."audit_transaction_p2026_06"')
        )
        drop(engine, tables, lock_timeout="500ms")
        reader.rollback()
    read: list[int] = []
    seal_blocks = _retire.Retirer._seal_blocks

    def counting(self: _retire.Retirer, *args: Any, **kwargs: Any) -> Iterator[Any]:
        for item in seal_blocks(self, *args, **kwargs):
            read.append(item[0])
            yield item

    monkeypatch.setattr(_retire.Retirer, "_seal_blocks", counting)
    assert short(drop(engine, tables)) == [
        "audit_transaction_p2026_06",
        "audit_transaction_p2026_07",
    ]
    # Every block, retire blocks included, is read at most once, however many
    # partitions are checked against it.
    assert len(read) == len(set(read))
    assert len(read) == block_count(engine, tables)


# -- the second connection ----------------------------------------------------------


def test_a_full_pool_raises_at_once(engine: Engine, tables: AuditTables) -> None:
    # One connection in all: drop_expired has it, so the second cannot come.
    # A long pool_timeout shows the call does not wait for it.
    small = create_engine(engine.url, pool_size=1, max_overflow=0, pool_timeout=60)
    try:
        started = time.monotonic()
        with pytest.raises(PartitionError, match="second connection"):
            drop(small, tables)
        assert time.monotonic() - started < 30
    finally:
        small.dispose()
    assert retire_blocks(engine, tables) == {}


# -- the manager ----------------------------------------------------------------------


def test_manager_sync_retires(engine: Engine, tables: AuditTables, schema: str) -> None:
    write(engine, tables)
    manager = PartitionManager(engine, tables, Sev)
    # The database's now(): every month from June to September has expired.
    dropped = manager.drop_expired({Sev.INFO: DAY, Sev.NOTICE: None})
    assert len(dropped) == 8
    assert dropped.skipped == []
    assert len(retire_blocks(engine, tables)) == 8


async def test_manager_async_retires(
    engine: Engine,
    async_engine: AsyncEngine,
    tables: AuditTables,
    schema: str,
) -> None:
    write(engine, tables)
    manager = PartitionManager(async_engine, tables, Sev)
    dropped = await manager.adrop_expired({Sev.INFO: DAY, Sev.NOTICE: None})
    assert len(dropped) == 8
    assert dropped.skipped == []
    assert len(retire_blocks(engine, tables)) == 8
    report = run(engine, tables)
    assert report.failures == []
