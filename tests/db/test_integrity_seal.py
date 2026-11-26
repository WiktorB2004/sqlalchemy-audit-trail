"""The sealer, the genesis block and the sealing lag against a real PostgreSQL.

Every test that checks a seal block rebuilds its segment roots from the rows
in its ``xid`` range, read with SQL of its own, which is what the verifier
will do.
"""

from __future__ import annotations

import dataclasses
import threading
import time
import uuid
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, create_engine, insert, inspect, select, text
from sqlalchemy import event as sqlalchemy_event
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.orm import sessionmaker

from audit_trail import (
    AuditContext,
    AuditEvent,
    AuditTrail,
    Severity,
    event,
    migrations,
    testing,
)
from audit_trail.integrity import _block, _seal
from audit_trail.integrity._block import (
    ZERO_HASH,
    activity_leaf_row,
    activity_stream,
    block_hash,
    node_hash,
    parse_body,
    seal_body,
    transaction_leaf_row,
)
from audit_trail.integrity._commit import leaf_hash
from audit_trail.integrity._options import Integrity
from audit_trail.integrity._seal import SealRefusedError, SealResult
from audit_trail.maintenance import PartitionManager, health
from audit_trail.migrations import create_sql
from audit_trail.tables import AuditTables, build_tables
from audit_trail.writer import insert_transaction, transaction_values
from tests.db.listener_support import Env, make_env, record_statements

# Reflection does not know xid8.
pytestmark = pytest.mark.filterwarnings("ignore:Did not recognize type 'xid8'")

ANN = AuditContext(actor_type="user", actor_id="ann", actor_label="Ann")


class SealEvent(AuditEvent):
    NOTED = event("seal_test.noted", Severity.INFO)
    WARNED = event("seal_test.warned", Severity.WARNING)


OPTIONS: dict[str, Any] = {
    "events": [SealEvent],
    "severities": Severity,
    "integrity": Integrity(),
}


@pytest.fixture
def env(engine: Engine, schema: str) -> Iterator[Env]:
    """Integrity on, with the chain started."""
    built = make_env(engine, schema, **OPTIONS)
    with engine.begin() as conn:
        migrations.write_genesis(conn, built.trail.tables)
    yield built
    built.trail.dispose()


def write(env: Env, entries: int = 1, *, warned: int = 0) -> int:
    """Commit one transaction with ``entries`` + ``warned`` entries; its xid."""
    with env.trail.context(ANN), env.factory() as session:
        for _ in range(entries):
            env.trail.log(session, SealEvent.NOTED, payload={"n": 1})
        for _ in range(warned):
            env.trail.log(session, SealEvent.WARNED)
        xid = int(
            session.execute(text("SELECT pg_current_xact_id()::text")).scalar_one()
        )
        session.commit()
    return xid


@dataclass
class Block:
    seq: int
    kind: str
    raw: bytes
    body: dict[str, Any]
    prev_hash: bytes
    block_hash: bytes


def blocks(env: Env) -> list[Block]:
    block = _seal.block_table(env.trail.tables)
    with env.engine.connect() as conn:
        rows = conn.execute(select(block).order_by(block.c.seq)).all()
    return [
        Block(
            r.seq,
            r.kind,
            bytes(r.body),
            parse_body(bytes(r.body)),
            bytes(r.prev_hash),
            bytes(r.block_hash),
        )
        for r in rows
    ]


def reference_root(leaves: Sequence[bytes]) -> bytes:
    """RFC 6962 section 2.1, written recursively."""
    if len(leaves) == 1:
        return leaves[0]
    split = 1
    while split * 2 < len(leaves):
        split *= 2
    return node_hash(reference_root(leaves[:split]), reference_root(leaves[split:]))


_ROWS = """
    SELECT c.relname AS partition, t.*, t.xid::text AS xid_text
    FROM {table} t
    JOIN pg_catalog.pg_class c ON c.oid = t.tableoid
    WHERE t.xid >= CAST(:lower AS text)::xid8 AND t.xid < CAST(:upper AS text)::xid8
    ORDER BY t.xid, t.id
"""


def rebuilt_segments(env: Env, lower: int, upper: int) -> list[dict[str, Any]]:
    """The segments of ``[lower, upper)`` rebuilt from the rows."""
    leaves: dict[tuple[str, str], list[bytes]] = {}
    tables = env.trail.tables
    with env.engine.connect() as conn:
        for table in (tables.transaction, tables.activity):
            sql = _ROWS.format(table=f'"{table.schema}"."{table.name}"')
            params = {"lower": str(lower), "upper": str(upper)}
            for row in conn.execute(text(sql), params).mappings():
                fields = {**row, "xid": int(row["xid_text"])}
                if table is tables.transaction:
                    stream, leaf = "transaction", transaction_leaf_row(fields)
                else:
                    stream = activity_stream(row["severity"])
                    leaf = activity_leaf_row(fields)
                leaves.setdefault((stream, row["partition"]), []).append(
                    leaf_hash(leaf)
                )
    return [
        {
            "stream": stream,
            "partition": partition,
            "rows": len(hashes),
            "root": _block.b64(reference_root(hashes)),
        }
        for (stream, partition), hashes in sorted(leaves.items())
    ]


def check_chain(env: Env) -> list[Block]:
    """Every block links to the one before and covers exactly its rows."""
    chain = blocks(env)
    assert chain[0].kind == "genesis"
    assert chain[0].prev_hash == ZERO_HASH
    previous = ZERO_HASH
    lower = chain[0].body["enforce_from"]
    for number, block in enumerate(chain, start=1):
        assert block.seq == block.body["seq"] == number
        assert block.kind == block.body["kind"]
        assert block.body["chain"] == chain[0].body["chain"]
        assert block.prev_hash == previous
        assert block.block_hash == block_hash(previous, block.raw)
        if block.kind == "seal":
            assert block.body["xid_from"] == lower
            assert block.body["xid_to"] > lower
            assert block.body["segments"] == rebuilt_segments(
                env, lower, block.body["xid_to"]
            )
            lower = block.body["xid_to"]
        previous = block.block_hash
    return chain


def seal(env: Env, **options: Any) -> SealResult:
    return env.trail.maintenance.seal(**options)


def rows_in(block: Block) -> int:
    return sum(segment["rows"] for segment in block.body["segments"])


def current_horizon(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(
            conn.execute(
                text("SELECT pg_snapshot_xmin(pg_current_snapshot())::text")
            ).scalar_one()
        )


# -- genesis -------------------------------------------------------------------


def test_genesis_starts_the_chain_once(env: Env) -> None:
    with env.engine.begin() as conn:
        again = migrations.write_genesis(conn, env.trail.tables)
    assert again.created is False
    (genesis,) = check_chain(env)
    assert genesis.body == {
        "v": 1,
        "kind": "genesis",
        "chain": again.chain,
        "seq": 1,
        "enforce_from": again.enforce_from,
    }
    assert str(uuid.UUID(again.chain)) == again.chain
    assert again.enforce_from <= current_horizon(env.engine)


def test_genesis_on_a_stale_snapshot_returns_the_committed_one(
    engine: Engine, schema: str
) -> None:
    env = make_env(engine, schema, **OPTIONS)
    tables = env.trail.tables
    with engine.connect() as late:
        late = late.execution_options(isolation_level="REPEATABLE READ")
        late.execute(text("SELECT 1"))  # takes the snapshot
        with engine.begin() as conn:
            first = migrations.write_genesis(conn, tables)
        again = migrations.write_genesis(late, tables)
        # The caller's transaction is still usable.
        assert late.execute(text("SELECT 1")).scalar() == 1
        late.commit()
    assert first.created is True
    assert again == dataclasses.replace(first, created=False)
    assert [b.kind for b in blocks(env)] == ["genesis"]
    env.trail.dispose()


def test_rows_below_enforce_from_are_never_sealed(engine: Engine, schema: str) -> None:
    env = make_env(engine, schema, **OPTIONS)
    write(env)  # before the genesis block
    with engine.begin() as conn:
        genesis = migrations.write_genesis(conn, env.trail.tables)
    assert genesis.created is True
    assert seal(env).blocks == 0
    write(env)
    result = seal(env)
    assert (result.blocks, result.rows) == (1, 2)
    check_chain(env)
    env.trail.dispose()


def test_seal_refuses_without_a_genesis_block(engine: Engine, schema: str) -> None:
    env = make_env(engine, schema, **OPTIONS)
    write(env)
    with pytest.raises(SealRefusedError) as info:
        seal(env)
    assert info.value.reason == "NO_GENESIS"
    assert "write_genesis" in str(info.value)
    assert blocks(env) == []
    env.trail.dispose()


# -- sealing -------------------------------------------------------------------


def test_seal_chains_blocks_over_finished_transactions(env: Env) -> None:
    write(env, 2, warned=1)
    write(env)
    first = seal(env)
    assert (first.blocks, first.rows, first.capped) == (1, 6, False)
    assert seal(env) == SealResult(0, 0, first.horizon)  # nothing new
    write(env)
    second = seal(env)
    assert (second.blocks, second.rows) == (1, 2)
    _genesis, one, two = check_chain(env)
    assert one.body["xid_to"] == first.horizon
    assert two.body["xid_from"] == first.horizon
    streams = {segment["stream"] for segment in one.body["segments"]}
    assert streams == {"transaction", "activity.10", "activity.30"}
    assert all(
        segment["partition"].startswith(("audit_transaction_p", "audit_activity_"))
        for segment in one.body["segments"]
    )


def test_seal_never_updates_audit_rows(env: Env) -> None:
    write(env)
    before = env.activities(), env.transactions()
    with record_statements(env.engine) as log:
        log.recording = True
        seal(env)
    assert (env.activities(), env.transactions()) == before
    verbs = [s.split()[0].upper() for s in log.statements]
    assert "UPDATE" not in verbs
    assert "DELETE" not in verbs
    (written,) = [s for s in log.statements if s.split()[0].upper() == "INSERT"]
    assert "audit_seal_block" in written


def test_a_lower_xid_committing_after_a_seal_lands_in_the_next_block(
    env: Env,
) -> None:
    write(env)
    with env.trail.context(ANN), env.factory() as early:
        # The early transaction gets its xid first and commits last.
        env.trail.log(early, SealEvent.NOTED)
        early_xid = int(
            early.execute(text("SELECT pg_current_xact_id()::text")).scalar_one()
        )
        late_xid = write(env)
        assert early_xid < late_xid
        first = seal(env)
        early.commit()
    second = seal(env)

    _genesis, one, two = check_chain(env)
    # The first block stops below the open transaction, so neither it nor
    # the later one that had already committed is in it.
    assert one.body["xid_to"] <= early_xid
    assert rows_in(one) == first.rows == 2
    assert two.body["xid_from"] <= early_xid < late_xid < two.body["xid_to"]
    assert rows_in(two) == second.rows == 4


def test_one_transaction_above_max_rows_is_sealed_whole(env: Env) -> None:
    big = write(env, 4)  # 5 rows
    small = write(env)
    first = seal(env, max_rows=2)
    assert (first.blocks, first.rows, first.capped) == (1, 5, True)
    assert first.horizon == small
    second = seal(env, max_rows=2)
    assert (second.blocks, second.rows, second.capped) == (1, 2, False)
    _genesis, one, _two = check_chain(env)
    assert one.body["xid_from"] <= big < one.body["xid_to"] == small


def test_max_rows_cuts_between_transactions(env: Env) -> None:
    xids = [write(env) for _ in range(3)]  # 2 rows each
    first = seal(env, max_rows=3)
    assert (first.rows, first.capped, first.horizon) == (2, True, xids[1])
    second = seal(env, max_rows=4)
    assert (second.rows, second.capped, second.horizon) == (4, False, second.horizon)
    check_chain(env)


def test_a_concurrent_sealer_returns_without_sealing(
    env: Env, database_url: str
) -> None:
    write(env)
    block = _seal.block_table(env.trail.tables)
    results: list[SealResult] = []
    with env.engine.connect() as holder:
        # Lets the first sealer take the advisory lock and read, then makes
        # it wait at its INSERT with the lock still held.
        holder.execute(text(f"LOCK TABLE {qualified(block)} IN EXCLUSIVE MODE"))
        first = threading.Thread(target=lambda: results.append(seal(env)))
        first.start()
        try:
            wait_for_insert_waiting(env.engine, block.name)
            other = create_engine(
                database_url, connect_args={"options": "-c lock_timeout=5s"}
            )
            try:
                second = PartitionManager(other, env.trail.tables, Severity).seal()
            finally:
                other.dispose()
        finally:
            holder.rollback()
            first.join(timeout=30)
    assert second == SealResult(0, 0, None, skipped="busy")
    assert results == [SealResult(1, 2, results[0].horizon)]
    assert [b.kind for b in check_chain(env)] == ["genesis", "seal"]


def test_a_sealer_with_a_stale_snapshot_returns_busy(env: Env) -> None:
    write(env)
    others: list[SealResult] = []

    def stale(
        conn: Any, cursor: Any, statement: str, *args: Any, **kwargs: Any
    ) -> None:
        if "pg_try_advisory_xact_lock" in statement and not others:
            # Take this transaction's snapshot first, then let another
            # sealer seal and commit before this one tries the lock.
            cursor.execute("SELECT 1")
            cursor.fetchall()
            others.append(seal(env))

    with env.engine.connect() as conn:
        sqlalchemy_event.listen(conn, "before_cursor_execute", stale)
        result = _seal.seal(conn, env.trail.tables)
        # The connection is usable: the transaction was rolled back.
        assert not conn.in_transaction()
        assert conn.execute(text("SELECT 1")).scalar() == 1
    assert others[0].blocks == 1
    assert result == SealResult(0, 0, None, skipped="busy")
    assert [b.kind for b in check_chain(env)] == ["genesis", "seal"]


def test_two_sets_of_tables_in_one_schema_seal_independently(
    env: Env, schema: str
) -> None:
    other = build_tables(
        schema=schema,
        transaction_table="other_transaction",
        activity_table="other_activity",
        seal_block_table="other_seal_block",
        integrity=True,
    )
    manager = PartitionManager(env.engine, other, Severity)
    with env.engine.begin() as conn:
        migrations.create_audit_tables(conn, other, Severity)
    manager.ensure_partitions()
    with env.engine.begin() as conn:
        assert migrations.write_genesis(conn, other).created is True
        insert_transaction(conn, other.transaction, transaction_values(ANN, None))
    write(env)
    own = _seal.block_table(env.trail.tables)
    with env.engine.connect() as holder:
        # The sealer lock of the first chain does not hold the other back.
        holder.execute(
            text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
            {"key": _seal.lock_key(own)},
        )
        assert seal(env) == SealResult(0, 0, None, skipped="busy")
        sealed = manager.seal()
        holder.rollback()
    assert (sealed.blocks, sealed.rows) == (1, 1)
    assert seal(env).rows == 2
    with env.engine.connect() as conn:
        block = _seal.block_table(other)
        kinds = conn.execute(select(block.c.kind).order_by(block.c.seq)).scalars()
        assert list(kinds) == ["genesis", "seal"]
    assert [b.kind for b in check_chain(env)] == ["genesis", "seal"]


def qualified(table: Any) -> str:
    return f'"{table.schema}"."{table.name}"'


def wait_for_insert_waiting(engine: Engine, table: str) -> None:
    deadline = time.monotonic() + 15
    with engine.connect() as conn:
        while time.monotonic() < deadline:
            waiting = conn.execute(
                text(
                    "SELECT count(*) FROM pg_locks l "
                    "JOIN pg_class c ON c.oid = l.relation "
                    "WHERE NOT l.granted AND c.relname = :table"
                ),
                {"table": table},
            ).scalar_one()
            conn.rollback()
            if waiting:
                return
            time.sleep(0.05)
    raise AssertionError("the first sealer never reached its INSERT")


def test_seal_refuses_on_xid_rewind(env: Env) -> None:
    # A block table restored into a cluster whose xids are far lower, as
    # after pg_dump and pg_restore: its last horizon is above the current one.
    write(env)
    (genesis,) = blocks(env)
    ahead = current_horizon(env.engine) + 1_000_000
    body = seal_body(genesis.body["chain"], 2, genesis.body["enforce_from"], ahead, [])
    block = _seal.block_table(env.trail.tables)
    with env.engine.begin() as conn:
        conn.execute(
            insert(block).values(
                seq=2,
                kind="seal",
                body=body,
                prev_hash=genesis.block_hash,
                block_hash=block_hash(genesis.block_hash, body),
            )
        )
    with pytest.raises(SealRefusedError) as info:
        seal(env)
    assert info.value.reason == "XID_REWIND"
    assert len(blocks(env)) == 2


# -- a hot standby ------------------------------------------------------------


@pytest.fixture(scope="module")
def standby_url(
    engine: Engine, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[str]:
    """A server in recovery, with the audit tables and a genesis block.

    The image's init scripts create them and then add ``standby.signal``, so
    the server starts as a hot standby that has no primary.
    """
    try:
        from testcontainers.community.postgres import PostgresContainer
    except ImportError:  # pragma: no cover
        pytest.skip("testcontainers is not installed")
    with engine.connect() as conn:
        version = int(conn.execute(text("SHOW server_version_num")).scalar_one())
    init = tmp_path_factory.mktemp("standby-init")
    init.chmod(0o755)
    tables = build_tables(integrity=True)
    body = _block.genesis_body(str(uuid.uuid4()), 3)
    genesis = (
        "INSERT INTO audit.audit_seal_block (seq, kind, body, prev_hash, block_hash) "
        f"VALUES (1, 'genesis', '\\x{body.hex()}', '\\x{ZERO_HASH.hex()}', "
        f"'\\x{block_hash(ZERO_HASH, body).hex()}');\n"
    )
    write_init(init / "01-tables.sql", create_sql(tables, Severity) + genesis)
    write_init(init / "02-standby.sh", 'touch "$PGDATA/standby.signal"\n')
    container = PostgresContainer(
        f"postgres:{version // 10000}", driver="psycopg"
    ).with_volume_mapping(str(init), "/docker-entrypoint-initdb.d", "ro")
    try:
        container.start()
    except Exception as exc:  # no Docker
        pytest.skip(f"cannot start a standby container: {exc}")
    try:
        yield container.get_connection_url()
    finally:
        container.stop()


def write_init(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o644)


def test_seal_returns_without_sealing_on_a_standby(standby_url: str) -> None:
    standby = create_engine(standby_url)
    try:
        with standby.connect() as conn:
            assert conn.execute(text("SELECT pg_is_in_recovery()")).scalar() is True
        manager = PartitionManager(standby, build_tables(integrity=True), Severity)
        assert manager.seal() == SealResult(0, 0, None, skipped="standby")
    finally:
        standby.dispose()


# -- what holds the horizon -----------------------------------------------------


def test_an_idle_read_only_session_does_not_hold_the_horizon(env: Env) -> None:
    activity = env.trail.tables.activity
    with env.engine.connect() as reader:
        reader.execute(text("BEGIN ISOLATION LEVEL REPEATABLE READ"))
        reader.execute(select(activity.c.id)).all()
        no_xid = reader.execute(text("SELECT pg_current_xact_id_if_assigned()"))
        assert no_xid.scalar() is None
        xid = write(env)
        result = seal(env)
        reader.rollback()
    assert result.rows == 2
    assert result.horizon is not None
    assert result.horizon > xid
    check_chain(env)


@pytest.fixture
def prepare(env: Env) -> Iterator[Callable[[], str]]:
    """Prepare transactions that wrote an audit row; rolled back afterwards."""
    with env.engine.connect() as conn:
        allowed = int(conn.execute(text("SHOW max_prepared_transactions")).scalar_one())
    if not allowed:
        pytest.skip("the server has max_prepared_transactions = 0")
    gids: list[str] = []

    def prepared() -> str:
        gid = f"audit-test-{uuid.uuid4().hex}"
        with env.engine.connect() as conn:
            auto = conn.execution_options(isolation_level="AUTOCOMMIT")
            auto.exec_driver_sql("BEGIN")
            insert_transaction(
                auto, env.trail.tables.transaction, transaction_values(ANN, None)
            )
            auto.exec_driver_sql(f"PREPARE TRANSACTION '{gid}'")
        gids.append(gid)
        return gid

    yield prepared
    rollback_prepared(env.engine, gids)


def rollback_prepared(engine: Engine, gids: list[str]) -> None:
    with engine.connect() as conn:
        auto = conn.execution_options(isolation_level="AUTOCOMMIT")
        left = set(auto.execute(text("SELECT gid FROM pg_prepared_xacts")).scalars())
        for gid in gids:
            if gid in left:
                auto.exec_driver_sql(f"ROLLBACK PREPARED '{gid}'")
    gids.clear()


def test_a_prepared_transaction_holds_the_horizon_and_health_flags_it(
    env: Env, prepare: Callable[[], str]
) -> None:
    write(env)
    gid = prepare()
    later = write(env)
    result = seal(env)
    assert result.rows == 2  # only the row before the prepared transaction
    assert result.horizon is not None
    assert result.horizon < later

    held = env.trail.maintenance.health(max_seal_lag=timedelta(0)).seal
    assert held is not None
    assert held.prepared == [gid]
    assert held.unsealed_rows == 2
    assert not held.ok
    fresh = env.trail.maintenance.health(max_seal_lag=timedelta(hours=1)).seal
    assert fresh is not None
    assert fresh.prepared == []
    assert fresh.ok

    rollback_prepared(env.engine, [gid])
    assert seal(env).rows == 2
    check_chain(env)


# -- health --------------------------------------------------------------------


def test_health_reports_the_sealing_lag(env: Env) -> None:
    env.trail.maintenance.ensure_partitions()
    report = env.trail.maintenance.health()
    assert report.seal is not None
    assert (report.seal.started, report.seal.unsealed_rows) == (True, 0)
    assert report.seal.seal_lag is None
    assert report.ok

    write(env, warned=1)
    lagging = env.trail.maintenance.health(max_seal_lag=timedelta(0))
    assert lagging.seal is not None
    assert lagging.seal.unsealed_rows == 3
    assert lagging.seal.seal_lag is not None
    assert lagging.seal.seal_lag > timedelta(0)
    assert not lagging.seal.ok
    assert not lagging.ok
    patient = env.trail.maintenance.health(max_seal_lag=timedelta(hours=1))
    assert patient.seal is not None
    assert patient.seal.ok
    assert patient.ok

    sealed = seal(env)
    after = env.trail.maintenance.health(max_seal_lag=timedelta(0))
    assert after.seal is not None
    assert after.seal.sealed_to == sealed.horizon
    assert (after.seal.unsealed_rows, after.seal.seal_lag) == (0, None)
    assert after.ok


def test_health_flags_a_chain_that_was_never_started(
    engine: Engine, schema: str
) -> None:
    env = make_env(engine, schema, **OPTIONS)
    env.trail.maintenance.ensure_partitions()
    report = env.trail.maintenance.health()
    assert report.seal is not None
    assert report.seal.started is False
    assert report.seal.problem is not None
    assert "migrations.write_genesis()" in report.seal.problem
    assert not report.ok
    env.trail.dispose()


def test_before_add_integrity_health_and_genesis_name_it(
    engine: Engine, schema: str
) -> None:
    old = make_env(engine, schema, events=[SealEvent], severities=Severity)
    old.trail.maintenance.ensure_partitions()
    write(old)
    old.trail.dispose()
    tables = build_tables(schema=schema, integrity=True)
    with engine.begin() as conn:
        report = health(conn, tables, Severity).seal
        assert report is not None
        assert (report.started, report.ok) == (False, False)
        assert report.problem is not None
        assert "does not exist" in report.problem
        assert "migrations.add_integrity()" in report.problem
        with pytest.raises(ValueError, match=r"migrations\.add_integrity\(\)"):
            migrations.write_genesis(conn, tables)
        # Neither aborted the caller's transaction.
        assert conn.execute(text("SELECT 1")).scalar() == 1


# -- async ---------------------------------------------------------------------


async def test_aseal_seals_on_an_async_engine(
    env: Env, async_engine: AsyncEngine
) -> None:
    write(env, 3, warned=2)
    manager = PartitionManager(async_engine, env.trail.tables, Severity)
    result = await manager.aseal()
    assert (result.blocks, result.rows) == (1, 6)
    report = await manager.ahealth(max_seal_lag=timedelta(0))
    assert report.seal is not None
    assert report.seal.unsealed_rows == 0
    check_chain(env)
    with pytest.raises(TypeError, match="use seal"):
        await PartitionManager(env.engine, env.trail.tables, Severity).aseal()
    with pytest.raises(TypeError, match="use aseal"):
        manager.seal()


# -- misuse --------------------------------------------------------------------


def test_seal_needs_a_connection_outside_a_transaction(env: Env) -> None:
    tables = env.trail.tables
    with env.engine.connect() as conn:
        conn.execute(text("SELECT 1"))
        with pytest.raises(ValueError, match="not in a transaction"):
            _seal.seal(conn, tables)
    with env.engine.connect() as conn:
        auto = conn.execution_options(isolation_level="AUTOCOMMIT")
        with pytest.raises(ValueError, match="AUTOCOMMIT"):
            _seal.seal(auto, tables)
    with env.engine.connect() as conn, pytest.raises(ValueError, match="max_rows"):
        _seal.seal(conn, tables, max_rows=0)


def test_seal_runs_at_repeatable_read(env: Env) -> None:
    write(env)
    with record_statements(env.engine) as log:
        log.recording = True
        seal(env)
    first, second = log.statements[:2]
    assert first == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"
    assert "pg_try_advisory_xact_lock" in second
    assert "pg_snapshot_xmin(pg_current_snapshot())" in second


def test_the_cut_and_health_read_bounded_index_ranges(env: Env) -> None:
    write(env, 4)  # one transaction above max_rows: the cut looks past it
    write(env)
    tables = env.trail.tables
    with record_statements(env.engine) as log:
        log.recording = True
        seal(env, max_rows=2)
        env.trail.maintenance.health()
    audit_reads = [
        s
        for s in log.statements
        if "tableoid" not in s  # the leaf rows, read between the cut bounds
        and (tables.transaction.name in s or tables.activity.name in s)
    ]
    assert len(audit_reads) == 3  # first cut, the transaction after it, health
    for statement in audit_reads:
        # Every read of an audit table is an ordered LIMIT, which walks its
        # (xid, id) indexes instead of sorting or counting the whole range.
        for segment in statement.split("FROM ")[1:]:
            name = segment.split()[0].rsplit(".", 1)[-1]
            if name in (tables.transaction.name, tables.activity.name):
                branch = segment.split("UNION ALL")[0]
                assert f"ORDER BY {segment.split()[0]}.xid" in branch, statement
                assert "LIMIT" in branch, statement


# -- integrity off ---------------------------------------------------------------


def test_without_integrity_nothing_changes(engine: Engine, schema: str) -> None:
    env = make_env(engine, schema, events=[SealEvent], severities=Severity)
    tables = env.trail.tables
    assert tables.seal_block is None
    assert "audit_seal_block" not in inspect(engine).get_table_names(schema=schema)
    assert "audit_seal_block" not in create_sql(tables, Severity)
    assert "audit_seal_block" not in migrations.drop_sql(tables)
    write(env)
    env.trail.maintenance.ensure_partitions()
    report = env.trail.maintenance.health()
    assert report.seal is None
    assert report.ok
    with engine.connect() as conn:
        assert health(conn, tables, Severity).seal is None
    with pytest.raises(ValueError, match="without integrity"):
        env.trail.maintenance.seal()
    with engine.begin() as conn, pytest.raises(ValueError, match="without integrity"):
        migrations.write_genesis(conn, tables)
    with engine.begin() as conn:
        testing.clear_audit_entries(env.trail, conn)
    assert env.activities() == []
    env.trail.dispose()


def test_clear_audit_entries_deletes_the_blocks(env: Env) -> None:
    write(env)
    seal(env)
    with env.engine.begin() as conn:
        testing.clear_audit_entries(env.trail, conn)
    assert blocks(env) == []
    assert env.activities() == []


def test_drop_audit_tables_drops_the_block_table(env: Env, schema: str) -> None:
    with env.engine.begin() as conn:
        migrations.drop_audit_tables(conn, env.trail.tables)
    assert inspect(env.engine).get_table_names(schema=schema) == []


# -- an upgraded install ---------------------------------------------------------


def test_add_integrity_creates_the_block_table(engine: Engine, schema: str) -> None:
    old = make_env(engine, schema, events=[SealEvent], severities=Severity)
    write(old)
    tables: AuditTables = old.trail.tables
    with engine.begin() as conn:
        migrations.add_integrity(conn, tables)
    with engine.begin() as conn:  # idempotent
        migrations.add_integrity(conn, tables)
    assert "audit_seal_block" in inspect(engine).get_table_names(schema=schema)
    old.trail.dispose()

    new = make_env_on(engine, schema)
    write(new)  # between add_integrity and write_genesis: pre-genesis
    with engine.begin() as conn:
        migrations.write_genesis(conn, new.trail.tables)
    write(new)
    result = seal(new)
    assert result.rows == 2  # neither the old row nor the pre-genesis one
    check_chain(new)
    new.trail.dispose()


def make_env_on(engine: Engine, schema: str) -> Env:
    """An integrity trail on tables that already exist."""
    trail = AuditTrail(engine, schema=schema, **OPTIONS)
    factory = sessionmaker(engine)
    trail.install(factory)
    return Env(engine, trail, factory)
