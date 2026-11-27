"""``verify`` and ``acknowledge`` against a real PostgreSQL.

Every tamper test first verifies the untouched database as ``VALID``, so no
test passes for nothing, then changes exactly one thing and expects exactly
one kind of failure.
"""

from __future__ import annotations

import base64
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import (
    Engine,
    MetaData,
    create_engine,
    func,
    insert,
    select,
    text,
    update,
)
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

import audit_trail
from audit_trail import (
    AuditContext,
    Audited,
    AuditEvent,
    AuditOptions,
    AuditTrail,
    Severity,
    event,
    migrations,
    privacy,
)
from audit_trail.integrity import _seal, _verify_db
from audit_trail.integrity._block import (
    SealedSegment,
    Segment,
    ack_body,
    activity_stream,
    block_hash,
    parse_body,
    retire_body,
    seal_body,
)
from audit_trail.integrity._options import Integrity
from audit_trail.integrity._verify import (
    FailureKind,
    NoteKind,
    Status,
    VerificationReport,
)
from audit_trail.integrity._verify_db import (
    aacknowledge,
    acknowledge,
    averify,
    verify,
)
from tests.db.listener_support import Env, make_env, record_statements
from tests.db.replication_support import Subscriber, subscribed, wait_for_rows
from tests.db.replication_support import write as write_replica

pytestmark = pytest.mark.filterwarnings("ignore:Did not recognize type 'xid8'")

ANN = AuditContext(
    actor_type="user",
    actor_id="ann",
    actor_label="Ann",
    remote_addr="192.0.2.7",
    user_agent="Firefox",
)
ADMIN = AuditContext(actor_type="user", actor_id="admin", actor_label="Admin")


class VerifyEvent(AuditEvent):
    NOTED = event("verify_test.noted", Severity.INFO)


@dataclass
class Models:
    Doc: Any


@pytest.fixture
def models(engine: Engine, schema: str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    class Doc(Base, Audited):
        __tablename__ = "doc"
        id: Mapped[int] = mapped_column(primary_key=True)
        title: Mapped[str] = mapped_column(default="")

        __audit__ = AuditOptions(label=lambda doc: doc.title)

    Base.metadata.create_all(engine)
    return Models(Doc)


OPTIONS: dict[str, Any] = {
    "events": [VerifyEvent],
    "severities": Severity,
    "integrity": Integrity(),
    "allow_scrub": True,
}


@pytest.fixture
def env(engine: Engine, schema: str, models: Models) -> Iterator[Env]:
    """Integrity on, the chain started, a few entries written and sealed."""
    built = make_env(engine, schema, **OPTIONS)
    with engine.begin() as conn:
        migrations.write_genesis(conn, built.trail.tables)
    write_docs(built, models)
    seal(built)
    yield built
    built.trail.dispose()


def write_docs(env: Env, models: Models) -> None:
    with env.trail.context(ANN), env.factory() as session:
        session.add(models.Doc(id=1, title="One"))
        session.commit()
        doc = session.get(models.Doc, 1)
        assert doc is not None
        doc.title = "Two"
        env.trail.log(session, VerifyEvent.NOTED, obj=doc, payload={"n": 1})
        session.commit()


def seal(env: Env) -> None:
    result = env.trail.maintenance.seal()
    assert result.skipped is None


def run(env: Env, **options: Any) -> VerificationReport:
    return verify(env.engine, env.trail.tables, **options)


def failed(report: VerificationReport) -> set[FailureKind]:
    return {FailureKind(finding.kind) for finding in report.failures}


def noted(report: VerificationReport) -> set[NoteKind]:
    return {NoteKind(finding.kind) for finding in report.notes}


def assert_valid(env: Env) -> None:
    report = run(env)
    assert report.failures == []
    assert report.notes == []
    assert report.status is Status.VALID


def execute(env: Env, sql: str, **params: Any) -> None:
    with env.engine.begin() as conn:
        conn.execute(text(sql), params)


def table_name(env: Env, which: str) -> str:
    table = getattr(env.trail.tables, which)
    return f'"{table.schema}"."{table.name}"'


def first_id(env: Env, verb: str) -> int:
    (row,) = [r for r in env.activities() if r["verb"] == verb][:1]
    return int(row["id"])


def append_block(env: Env, kind: str, make_body: Any) -> int:
    """Append a correctly chained block; ``make_body(chain, seq)``."""
    block = _seal.block_table(env.trail.tables)
    with env.engine.begin() as conn:
        first = conn.execute(select(block.c.body).where(block.c.seq == 1)).scalar_one()
        chain = parse_body(bytes(first))["chain"]
        last = _seal.last_block(conn, block)
        seq = int(last.seq) + 1
        _seal.insert_block(
            conn, block, seq, kind, bytes(last.block_hash), make_body(chain, seq)
        )
    return seq


def sealed_to(env: Env) -> int:
    block = _seal.block_table(env.trail.tables)
    with env.engine.connect() as conn:
        found = _seal.sealed_horizon(conn, block)
    assert found is not None
    return found[1]


def transaction_partition(env: Env) -> str:
    """The partition holding the transaction rows, read from the rows.

    Not from the clock: a test that runs across a month boundary would
    otherwise name the wrong month.
    """
    table = env.trail.tables.transaction
    with env.engine.connect() as conn:
        (name,) = conn.execute(
            text(
                "SELECT DISTINCT c.relname FROM "
                f'"{table.schema}"."{table.name}" t '
                "JOIN pg_catalog.pg_class c ON c.oid = t.tableoid"
            )
        ).scalars()
    return str(name)


# -- clean ------------------------------------------------------------------


def test_an_untouched_log_is_valid(env: Env) -> None:
    report = run(env)
    assert report.status is Status.VALID
    assert report.verified_to == 2
    assert report.anchor == "UNANCHORED"


def test_small_chunks_page_through_ties(env: Env, models: Models) -> None:
    # Rows of one transaction share their xid, so the keyset needs the id.
    with record_statements(env.engine) as log:
        log.recording = True
        report = run(env, chunk_rows=1)
    assert report.status is Status.VALID
    read_only = [s for s in log.statements if s == "SET TRANSACTION READ ONLY"]
    keyset = [s for s in log.statements if ") > (" in s and "LIMIT" in s]
    # Every chunk ran in its own READ ONLY transaction.
    assert len(read_only) > len(env.activities()) + len(env.transactions())
    # Later chunks start after the (xid, id) of the last row.
    assert keyset


def test_a_chunk_size_that_divides_the_rows_exactly(env: Env) -> None:
    # Two transactions; the last full chunk is followed by an empty one.
    assert len(env.transactions()) == 2
    with record_statements(env.engine) as log:
        log.recording = True
        report = run(env, chunk_rows=2)
    assert report.status is Status.VALID
    table = env.trail.tables.transaction.name
    reads = [s for s in log.statements if f"{table}_p" in s and "LIMIT" in s]
    assert len(reads) == 2
    assert ") > (" in reads[1]


def test_a_scrub_and_a_scrub_actor_in_one_transaction_verify_clean(
    env: Env,
) -> None:
    assert_valid(env)
    record = env.trail._scrubbed_record()
    with env.engine.begin() as conn:
        tables = env.trail.tables
        privacy.scrub(
            conn,
            tables,
            "Doc",
            "1",
            include_targets=True,
            since=None,
            scope_ids=None,
            record=record,
        )
        privacy.scrub_actor(conn, tables, "ann", scope_ids=None, record=record)
    seal(env)
    report = run(env)
    assert report.failures == []
    assert noted(report) == {NoteKind.ERASED}
    assert report.status is Status.VALID_WITH_NOTES


def test_scrubs_verify_clean(env: Env) -> None:
    with env.trail.context(ADMIN):
        env.trail.scrub("Doc", "1")
        env.trail.scrub_actor("ann")
    seal(env)
    report = run(env)
    assert report.failures == []
    assert noted(report) == {NoteKind.ERASED}


def test_rows_before_genesis_and_after_the_last_seal_are_noted(
    engine: Engine, schema: str, models: Models
) -> None:
    built = make_env(engine, schema, **OPTIONS)
    try:
        write_docs(built, models)
        with engine.begin() as conn:
            migrations.write_genesis(conn, built.trail.tables)
        report = run(built)
        assert report.failures == []
        assert noted(report) == {NoteKind.PRE_GENESIS}
        seal(built)
        with built.trail.context(ANN), built.factory() as session:
            built.trail.log(session, VerifyEvent.NOTED, payload={"n": 2})
            session.commit()
        report = run(built)
        assert report.failures == []
        assert noted(report) == {NoteKind.PRE_GENESIS, NoteKind.UNSEALED_TAIL}
        seal(built)
        assert noted(run(built)) == {NoteKind.PRE_GENESIS}
    finally:
        built.trail.dispose()


# -- one tamper per kind -------------------------------------------------------


def test_a_changed_sealed_column_is_root_mismatch(env: Env) -> None:
    assert_valid(env)
    row_id = first_id(env, "entity.created")
    execute(
        env,
        f"UPDATE {table_name(env, 'activity')} SET object_id = '9' WHERE id = :id",
        id=row_id,
    )
    report = run(env)
    assert failed(report) == {FailureKind.ROOT_MISMATCH}
    (finding,) = report.failures
    assert finding.seq == 2
    assert finding.stream == activity_stream(Severity.INFO)


def test_a_deleted_row_is_row_count_mismatch(env: Env) -> None:
    assert_valid(env)
    execute(
        env,
        f"DELETE FROM {table_name(env, 'activity')} WHERE id = :id",
        id=first_id(env, "verify_test.noted"),
    )
    assert failed(run(env)) == {FailureKind.ROW_COUNT_MISMATCH}


def test_a_row_inserted_into_a_sealed_range_is_row_count_mismatch(env: Env) -> None:
    assert_valid(env)
    # A copy of a sealed row, with its xid, under a new id.
    (row,) = env.transactions()[:1]
    table = env.trail.tables.transaction
    with env.engine.begin() as conn:
        conn.execute(insert(table).values({c: row[c] for c in row if c != "id"}))
    report = run(env)
    assert failed(report) == {FailureKind.ROW_COUNT_MISMATCH}
    (finding,) = report.failures
    assert finding.table == "transaction"
    assert finding.count == 3


def test_a_changed_erasable_value_is_commitment_mismatch(env: Env) -> None:
    assert_valid(env)
    row_id = first_id(env, "verify_test.noted")
    execute(
        env,
        f"UPDATE {table_name(env, 'activity')} "
        "SET data = jsonb_set(data, '{payload,n}', '2') WHERE id = :id",
        id=row_id,
    )
    report = run(env)
    assert failed(report) == {FailureKind.COMMITMENT_MISMATCH}
    (finding,) = report.failures
    assert (finding.table, finding.id, finding.group) == ("activity", row_id, "payload")
    assert finding.partition is not None
    assert finding.xid is not None
    # No salt or commitment is ever part of a finding.
    (row,) = [r for r in env.activities() if r["id"] == row_id]
    shown = repr(report)
    for secret in (*row["seal_salts"].values(), *row["seal_commitments"].values()):
        assert secret not in shown


def test_an_erasable_value_added_without_commitment_is_commitment_mismatch(
    env: Env,
) -> None:
    assert_valid(env)
    row_id = first_id(env, "verify_test.noted")
    execute(
        env,
        f"UPDATE {table_name(env, 'activity')} "
        'SET data = data || \'{"changes": {"x": [1, 2]}}\' WHERE id = :id',
        id=row_id,
    )
    assert failed(run(env)) == {FailureKind.COMMITMENT_MISMATCH}


def test_a_removed_salt_is_erasure_unexplained(env: Env) -> None:
    assert_valid(env)
    row_id = first_id(env, "verify_test.noted")
    execute(
        env,
        f"UPDATE {table_name(env, 'activity')} "
        "SET seal_salts = seal_salts - 'payload' WHERE id = :id",
        id=row_id,
    )
    report = run(env)
    assert failed(report) == {FailureKind.ERASURE_UNEXPLAINED}
    (finding,) = report.failures
    assert finding.group == "payload"


def test_a_stamped_value_that_is_not_erased_is_erasure_unexplained(
    env: Env,
) -> None:
    with env.trail.context(ADMIN):
        env.trail.scrub("Doc", "1")
    seal(env)
    report = run(env)
    assert report.failures == []
    row_id = first_id(env, "verify_test.noted")
    execute(
        env,
        f"UPDATE {table_name(env, 'activity')} "
        "SET data = jsonb_set(data, '{payload,n}', '5') WHERE id = :id",
        id=row_id,
    )
    assert failed(run(env)) == {FailureKind.ERASURE_UNEXPLAINED}


def forge_record(env: Env, payload: dict[str, Any]) -> None:
    """An ``audit.scrubbed`` entry the app writes itself, with commitments.

    ``log`` refuses the verb, so this uses the library's own writer, as an
    app with insert rights could.
    """
    with env.engine.begin() as conn:
        privacy._write_record(
            conn,
            env.trail.tables,
            ADMIN,
            env.trail._scrubbed_record(),
            object_type="Doc",
            object_id="1",
            payload=payload,
        )


def test_an_app_forged_scrubbed_record_is_scrub_count_mismatch(env: Env) -> None:
    assert_valid(env)
    forge_record(
        env,
        {
            "operation": "scrub",
            "object_type": "Doc",
            "object_id": "1",
            "activity_rows": 3,
        },
    )
    seal(env)
    report = run(env)
    assert failed(report) == {FailureKind.SCRUB_COUNT_MISMATCH}
    assert {f.group for f in report.failures} == {"label", "changes", "payload"}
    assert report.notes == []


def test_a_record_without_an_operation_is_scrub_count_mismatch(env: Env) -> None:
    assert_valid(env)
    forge_record(env, {"activity_rows": 0})
    seal(env)
    report = run(env)
    assert failed(report) == {FailureKind.SCRUB_COUNT_MISMATCH}
    (finding,) = report.failures
    assert finding.id is not None


def test_a_moved_pointer_is_scrub_count_mismatch(env: Env) -> None:
    with env.trail.context(ADMIN):
        env.trail.scrub("Doc", "1")
    seal(env)
    assert run(env).failures == []
    row_id = first_id(env, "verify_test.noted")
    execute(
        env,
        f"UPDATE {table_name(env, 'activity')} SET seal_erased = "
        "jsonb_set(seal_erased, '{changes}', '\"3\"') WHERE id = :id",
        id=row_id,
    )
    report = run(env)
    assert failed(report) == {FailureKind.SCRUB_COUNT_MISMATCH}
    # The stamp names a transaction before the row's own, and the scrub's
    # record counts one row more than carry its stamp.
    assert {(f.group, f.id) for f in report.failures} == {
        ("changes", row_id),
        ("changes", None),
    }


def detach(env: Env, partition: str) -> None:
    parent = table_name(env, "transaction")
    schema = env.trail.tables.transaction.schema
    execute(env, f'ALTER TABLE {parent} DETACH PARTITION "{schema}"."{partition}"')


def test_a_dropped_partition_is_segment_missing(env: Env) -> None:
    assert_valid(env)
    partition = transaction_partition(env)
    detach(env, partition)
    schema = env.trail.tables.transaction.schema
    execute(env, f'DROP TABLE "{schema}"."{partition}"')
    report = run(env)
    assert failed(report) == {FailureKind.SEGMENT_MISSING}
    (finding,) = report.failures
    assert finding.partition == partition


def test_a_detached_partition_is_detached_partition(env: Env) -> None:
    assert_valid(env)
    partition = transaction_partition(env)
    detach(env, partition)
    report = run(env)
    assert failed(report) == {FailureKind.DETACHED_PARTITION}
    (finding,) = report.failures
    assert finding.partition == partition


def drop_partition(env: Env, which: str) -> str:
    """Detach and drop the partition holding the first row of a table."""
    table = getattr(env.trail.tables, which)
    with env.engine.begin() as conn:
        name, parent = conn.execute(
            text(
                "SELECT c.relname, i.inhparent::regclass::text FROM "
                f'"{table.schema}"."{table.name}" t '
                "JOIN pg_catalog.pg_class c ON c.oid = t.tableoid "
                "JOIN pg_catalog.pg_inherits i ON i.inhrelid = c.oid "
                "ORDER BY t.id LIMIT 1"
            )
        ).one()
        child = f'"{table.schema}"."{name}"'
        conn.execute(text(f"ALTER TABLE {parent} DETACH PARTITION {child}"))
        conn.execute(text(f"DROP TABLE {child}"))
    return str(name)


def after_catalog(monkeypatch: pytest.MonkeyPatch, *hooks: Any) -> None:
    """Run ``hooks[n]`` right after the ``n``-th catalog read of verify."""
    read = _verify_db._catalog
    pending = list(hooks)

    def catalog(conn: Any, tables: Any) -> Any:
        found = read(conn, tables)
        if pending:
            pending.pop(0)()
        return found

    monkeypatch.setattr(_verify_db, "_catalog", catalog)


def test_a_partition_retired_and_dropped_mid_run_is_read_again(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert_valid(env)
    partition = transaction_partition(env)

    def drop_expired() -> None:
        # What drop_expired does: the retire block, then the drop.
        retire(env, LONG_AGO)
        assert drop_partition(env, "transaction") == partition

    after_catalog(monkeypatch, drop_expired)
    report = run(env)
    assert report.failures == []
    assert noted(report) == {NoteKind.RETIRED}
    assert [f.partition for f in report.notes] == [partition]


def test_a_partition_dropped_again_on_the_retry_is_reported(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert_valid(env)
    dropped: list[str] = []
    after_catalog(
        monkeypatch,
        lambda: dropped.append(drop_partition(env, "transaction")),
        lambda: dropped.append(drop_partition(env, "activity")),
    )
    report = run(env)
    # Retried once; the second drop is reported, not retried again.
    assert failed(report) == {FailureKind.SEGMENT_MISSING}
    assert sorted(str(f.partition) for f in report.failures) == sorted(dropped)


def test_a_seal_between_the_reads_is_no_rewind(
    env: Env, models: Models, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The chain is read before the horizon: a seal that commits just before
    # the chain is read is below the horizon read after it.
    assert_valid(env)

    def seal_more() -> None:
        with env.trail.context(ANN), env.factory() as session:
            env.trail.log(session, VerifyEvent.NOTED, payload={"n": 2})
            session.commit()
        seal(env)

    read = _verify_db._blocks

    def blocks(conn: Any, block: Any) -> Any:
        seal_more()
        yield from read(conn, block)

    monkeypatch.setattr(_verify_db, "_blocks", blocks)
    report = run(env)
    assert report.failures == []
    assert report.status is Status.VALID
    assert report.verified_to == 3


FLIP_FIRST_BYTE = "set_byte(block_hash, 0, get_byte(block_hash, 0) # 1)"


def test_a_changed_block_hash_is_hash_mismatch(env: Env) -> None:
    assert_valid(env)
    block = _seal.block_table(env.trail.tables)
    with env.engine.begin() as conn:
        conn.execute(
            update(block)
            .where(block.c.seq == 2)
            .values(block_hash=text(FLIP_FIRST_BYTE))
        )
    report = run(env)
    assert failed(report) == {FailureKind.HASH_MISMATCH}
    assert [f.seq for f in report.failures] == [2]


def test_a_relinked_block_is_prev_mismatch(env: Env) -> None:
    assert_valid(env)
    block = _seal.block_table(env.trail.tables)
    with env.engine.begin() as conn:
        body = bytes(
            conn.execute(select(block.c.body).where(block.c.seq == 2)).scalar_one()
        )
        forged = bytes(32)[:-1] + b"\x01"
        conn.execute(
            update(block)
            .where(block.c.seq == 2)
            .values(prev_hash=forged, block_hash=block_hash(forged, body))
        )
    report = run(env)
    assert failed(report) == {FailureKind.PREV_MISMATCH}
    assert [f.seq for f in report.failures] == [2]


def test_a_block_kind_changed_is_malformed_block(env: Env) -> None:
    seq = append_block(
        env,
        "ack",
        lambda chain, seq: ack_body(
            chain,
            seq,
            failure="COMMITMENT_MISSING",
            scope={"xid": 1},
            waives=[{"table": "activity", "id": 1}],
            reason="x",
        ),
    )
    assert_valid(env)
    block = _seal.block_table(env.trail.tables)
    with env.engine.begin() as conn:
        conn.execute(update(block).where(block.c.seq == seq).values(kind="checkpoint"))
    report = run(env)
    assert failed(report) == {FailureKind.MALFORMED_BLOCK}
    assert [f.seq for f in report.failures] == [seq]


def test_a_chain_sealed_past_the_database_is_xid_rewind(env: Env) -> None:
    assert_valid(env)
    lower = sealed_to(env)
    append_block(
        env,
        "seal",
        lambda chain, seq: seal_body(chain, seq, lower, lower + 10_000_000, []),
    )
    report = run(env)
    assert failed(report) == {FailureKind.XID_REWIND}


def test_a_row_from_the_future_is_xid_rewind(env: Env) -> None:
    assert_valid(env)
    # A copy of a row under an xid no transaction has had yet: it would sit
    # in the unsealed tail forever.
    (row,) = env.transactions()[:1]
    table = env.trail.tables.transaction
    future = 10**15
    with env.engine.begin() as conn:
        values = {c: row[c] for c in row if c != "id"}
        conn.execute(insert(table).values({**values, "xid": future}))
    report = run(env)
    assert failed(report) == {FailureKind.XID_REWIND}
    (finding,) = report.failures
    assert (finding.table, finding.xid) == ("transaction", future)


def sealed_segments(env: Env, partition: str) -> list[SealedSegment]:
    """The segments of ``partition`` in the seal blocks, read with SQL of its own."""
    block = _seal.block_table(env.trail.tables)
    with env.engine.connect() as conn:
        rows = conn.execute(
            select(block.c.seq, block.c.body)
            .where(block.c.kind == "seal")
            .order_by(block.c.seq)
        ).all()
    return [
        SealedSegment(
            int(row.seq),
            Segment(
                item["stream"], partition, item["rows"], base64.b64decode(item["root"])
            ),
        )
        for row in rows
        for item in parse_body(bytes(row.body))["segments"]
        if item["partition"] == partition
    ]


def retire(env: Env, upper_bound: datetime) -> int:
    """A retire block of the transaction partition, as drop_expired writes it."""
    partition = transaction_partition(env)
    segments = sealed_segments(env, partition)
    return append_block(
        env,
        "retire",
        lambda chain, seq: retire_body(
            chain,
            seq,
            table="transaction",
            partition=partition,
            streams=["transaction"],
            upper_bound=upper_bound,
            retention=None,
            segments=segments,
        ),
    )


# Retire bounds pinned far from any clock the tests run at: inside every
# retention, or past it.
FAR_FUTURE = datetime(2999, 1, 1, tzinfo=UTC)
LONG_AGO = datetime(2000, 1, 1, tzinfo=UTC)

RETENTION = {Severity.INFO: timedelta(days=30), Severity.WARNING: timedelta(days=30)}


def test_a_retire_inside_the_retention_is_retired_early(env: Env) -> None:
    assert run(env, retention=RETENTION).status is Status.VALID
    retire(env, FAR_FUTURE)
    # Without the retention, the retire block is not judged.
    assert run(env).status is Status.VALID
    report = run(env, retention=RETENTION)
    assert failed(report) == {FailureKind.RETIRED_EARLY}
    assert report.notes == []


def test_a_retired_partition_that_is_gone_is_a_note(env: Env) -> None:
    assert_valid(env)
    retire(env, LONG_AGO)
    partition = transaction_partition(env)
    detach(env, partition)
    schema = env.trail.tables.transaction.schema
    execute(env, f'DROP TABLE "{schema}"."{partition}"')
    report = run(env, retention=RETENTION)
    assert report.failures == []
    assert noted(report) == {NoteKind.RETIRED}


# -- a writer without Integrity, and acks ---------------------------------------


def write_without_integrity(env: Env) -> int:
    """One entry by a process configured without Integrity; its xid."""
    legacy = AuditTrail(
        env.engine, schema=env.trail.schema, events=[VerifyEvent], severities=Severity
    )
    factory = sessionmaker(env.engine)
    legacy.install(factory)
    try:
        with legacy.context(ANN), factory() as session:
            legacy.log(session, VerifyEvent.NOTED, payload={"n": 3})
            xid = int(
                session.execute(text("SELECT pg_current_xact_id()::text")).scalar_one()
            )
            session.commit()
    finally:
        legacy.dispose()
    return xid


def ack(env: Env, kind: FailureKind | str, scope: dict[str, object]) -> int:
    with env.engine.connect() as conn:
        return acknowledge(conn, env.trail.tables, kind, scope, "why")


def test_a_writer_without_integrity_is_commitment_missing_until_acknowledged(
    env: Env, models: Models
) -> None:
    assert_valid(env)
    xid = write_without_integrity(env)
    seal(env)
    report = run(env)
    assert failed(report) == {FailureKind.COMMITMENT_MISSING}
    assert {(f.table, f.xid) for f in report.failures} == {
        ("transaction", xid),
        ("activity", xid),
    }

    with env.engine.connect() as conn:
        seq = acknowledge(
            conn,
            env.trail.tables,
            FailureKind.COMMITMENT_MISSING,
            {"xid_from": xid, "xid_to": xid + 1},
            "rolling deploy",
        )
    report = run(env)
    assert report.failures == []
    assert noted(report) == {NoteKind.ACKNOWLEDGED}
    assert {(f.waived, f.ack, f.xid) for f in report.notes} == {
        (FailureKind.COMMITMENT_MISSING, seq, xid)
    }
    assert report.status is Status.VALID_WITH_NOTES
    # The sealer goes on after the ack block.
    with env.trail.context(ANN), env.factory() as session:
        env.trail.log(session, VerifyEvent.NOTED, payload={"n": 4})
        session.commit()
    seal(env)
    assert run(env).failures == []


def test_a_row_ack_waives_only_the_rows_it_saw(env: Env) -> None:
    first = write_without_integrity(env)
    seal(env)
    # A scope wide enough to take in later transactions too.
    ack(env, FailureKind.COMMITMENT_MISSING, {"xid_from": first})
    assert run(env).failures == []
    later = write_without_integrity(env)
    seal(env)
    report = run(env)
    assert failed(report) == {FailureKind.COMMITMENT_MISSING}
    assert {f.xid for f in report.failures} == {later}
    assert {f.xid for f in report.notes} == {first}


def test_tampering_after_an_ack_is_reported_again(env: Env) -> None:
    assert_valid(env)
    activity = table_name(env, "activity")
    row_id = first_id(env, "entity.created")
    execute(env, f"UPDATE {activity} SET object_id = '9' WHERE id = :id", id=row_id)
    seq = ack(env, FailureKind.ROOT_MISMATCH, {"seq": 2})
    report = run(env)
    assert report.failures == []
    (note,) = report.notes
    assert (note.waived, note.ack, note.seq) == (FailureKind.ROOT_MISMATCH, seq, 2)
    # The ack pinned the root it saw; another change to the segment is new.
    execute(env, f"UPDATE {activity} SET object_id = '8' WHERE id = :id", id=row_id)
    report = run(env)
    assert failed(report) == {FailureKind.ROOT_MISMATCH}
    assert report.notes == []


def test_an_ack_is_hashed_into_the_chain(env: Env) -> None:
    activity = table_name(env, "activity")
    row_id = first_id(env, "entity.created")
    execute(env, f"UPDATE {activity} SET object_id = '9' WHERE id = :id", id=row_id)
    (failure,) = run(env).failures
    seq = ack(env, "ROOT_MISMATCH", {"seq": 2, "partition": str(failure.partition)})
    block = _seal.block_table(env.trail.tables)
    with env.engine.connect() as conn:
        rows = conn.execute(select(block).order_by(block.c.seq)).all()
    assert [r.kind for r in rows] == ["genesis", "seal", "ack"]
    found = rows[-1]
    assert found.seq == seq
    assert bytes(found.prev_hash) == bytes(rows[-2].block_hash)
    assert bytes(found.block_hash) == block_hash(
        bytes(found.prev_hash), bytes(found.body)
    )
    assert parse_body(bytes(found.body)) == {
        "v": 1,
        "kind": "ack",
        "chain": parse_body(bytes(rows[0].body))["chain"],
        "seq": seq,
        "failure": "ROOT_MISMATCH",
        "scope": {"seq": 2, "partition": failure.partition},
        "waives": [
            {
                "seq": 2,
                "table": "activity",
                "partition": failure.partition,
                "stream": failure.stream,
                "count": failure.count,
                "root": failure.root,
            }
        ],
        "reason": "why",
    }
    report = run(env)
    assert report.failures == []
    assert noted(report) == {NoteKind.ACKNOWLEDGED}


@pytest.mark.parametrize(
    ("kind", "scope", "match"),
    [
        ("HASH_MISMATCH", {"xid": 1}, "cannot be acknowledged"),
        ("NO_SUCH_KIND", {"xid": 1}, "not a failure kind"),
        ("COMMITMENT_MISSING", {}, "needs a scope"),
        ("COMMITMENT_MISSING", {"salt": "x"}, "unknown ack scope key"),
        ("COMMITMENT_MISSING", {"xid": "1"}, "takes an integer"),
        ("COMMITMENT_MISSING", {"table": "activity"}, "only table"),
        # Nothing fails there: an ack would waive nothing.
        ("COMMITMENT_MISSING", {"xid": 1}, "no COMMITMENT_MISSING failure"),
    ],
)
def test_acknowledge_refuses_what_it_cannot_waive(
    env: Env, kind: str, scope: dict[str, object], match: str
) -> None:
    with env.engine.connect() as conn, pytest.raises(ValueError, match=match):
        acknowledge(conn, env.trail.tables, kind, scope, "why")
    block = _seal.block_table(env.trail.tables)
    with env.engine.connect() as conn:
        assert conn.execute(select(func.count()).select_from(block)).scalar() == 2


def test_verify_needs_one_connection(env: Env, database_url: str) -> None:
    # It takes no lock and holds nothing between its short transactions, so
    # a pool of one does, and two runs side by side do not block each other.
    single = create_engine(database_url, pool_size=1, max_overflow=0, pool_timeout=5)
    try:
        assert verify(single, env.trail.tables).status is Status.VALID
        with env.engine.connect() as other:
            other.execute(text("SELECT 1"))
            assert verify(single, env.trail.tables).status is Status.VALID
    finally:
        single.dispose()


# -- async ---------------------------------------------------------------------


async def test_averify_and_aacknowledge_on_an_async_engine(
    env: Env, async_engine: AsyncEngine
) -> None:
    tables = env.trail.tables
    assert (await averify(async_engine, tables)).status is Status.VALID
    activity = table_name(env, "activity")
    row_id = first_id(env, "entity.created")
    execute(env, f"UPDATE {activity} SET object_id = '9' WHERE id = :id", id=row_id)
    assert failed(await averify(async_engine, tables)) == {FailureKind.ROOT_MISMATCH}
    async with async_engine.connect() as conn:
        seq = await aacknowledge(conn, tables, "ROOT_MISMATCH", {"seq": 2}, "why")
    report = await averify(async_engine, tables)
    assert report.failures == []
    assert [(f.waived, f.ack) for f in report.notes] == [
        (FailureKind.ROOT_MISMATCH, seq)
    ]
    assert report == run(env)
    with pytest.raises(TypeError, match="use averify"):
        verify(async_engine, tables)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="use verify"):
        await averify(env.engine, tables)  # type: ignore[arg-type]


async def test_averify_reads_a_dropped_partition_again(
    env: Env, async_engine: AsyncEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The driver's error for a vanished relation is recognised.
    def drop_expired() -> None:
        retire(env, LONG_AGO)
        drop_partition(env, "transaction")

    after_catalog(monkeypatch, drop_expired)
    report = await averify(async_engine, env.trail.tables)
    assert report.failures == []
    assert noted(report) == {NoteKind.RETIRED}


# -- integrity off ---------------------------------------------------------------


def test_integrity_off_changes_nothing(engine: Engine, schema: str) -> None:
    plain = make_env(engine, schema, events=[VerifyEvent], severities=Severity)
    try:
        with pytest.raises(ValueError, match="without integrity"):
            verify(engine, plain.trail.tables)
        with engine.connect() as conn, pytest.raises(ValueError, match="integrity"):
            acknowledge(
                conn, plain.trail.tables, "COMMITMENT_MISSING", {"xid": 1}, "why"
            )
        with engine.connect() as conn:
            names = conn.execute(
                text(
                    "SELECT count(*) FROM pg_class c JOIN pg_namespace n "
                    "ON n.oid = c.relnamespace WHERE n.nspname = :schema "
                    "AND c.relname = 'audit_seal_block'"
                ),
                {"schema": schema},
            ).scalar_one()
        assert names == 0
    finally:
        plain.trail.dispose()
    # Integrity stays private.
    assert not {"verify", "acknowledge", "VerificationReport"} & set(
        audit_trail.__all__
    )


def test_a_scrub_over_rows_written_before_integrity_verifies_clean(
    engine: Engine, schema: str, models: Models
) -> None:
    old = make_env(engine, schema, events=[VerifyEvent], severities=Severity)
    try:
        with old.trail.context(ANN), old.factory() as session:
            session.add(models.Doc(id=1, title="Old"))
            session.commit()
        with engine.begin() as conn:
            migrations.add_integrity(conn, old.trail.tables)
    finally:
        old.trail.dispose()
    new = AuditTrail(engine, schema=schema, **OPTIONS)
    factory = sessionmaker(engine)
    new.install(factory)
    built = Env(engine, new, factory)
    try:
        with engine.begin() as conn:
            migrations.write_genesis(conn, new.tables)
        write_docs_again(built, models)
        with new.context(ADMIN):
            # Changes the old row too, which has nothing to stamp.
            assert new.scrub("Doc", "1").activity_rows == 2
        seal(built)
        report = run(built)
        assert report.failures == []
        assert noted(report) == {NoteKind.PRE_GENESIS, NoteKind.ERASED}
    finally:
        new.dispose()


def write_docs_again(env: Env, models: Models) -> None:
    with env.trail.context(ANN), env.factory() as session:
        doc = session.get(models.Doc, 1)
        assert doc is not None
        doc.title = "New"
        session.commit()


# -- logical replication --------------------------------------------------------


@pytest.fixture(scope="module")
def subscriber(engine: Engine) -> Iterator[Subscriber]:
    with subscribed(engine) as databases:
        yield databases


def test_verify_on_a_subscriber_says_to_verify_on_the_publisher(
    subscriber: Subscriber,
) -> None:
    tables = subscriber.tables
    write_replica(subscriber.publisher_trail, subscriber.publisher)
    write_replica(subscriber.subscriber_trail, subscriber.subscriber)
    assert subscriber.publisher_trail.maintenance.seal().blocks == 1
    wait_for_rows(subscriber.subscriber, tables, 2)
    assert verify(subscriber.publisher, tables).status is Status.VALID
    with pytest.raises(ValueError, match="verify on the publisher"):
        verify(subscriber.subscriber, tables)
