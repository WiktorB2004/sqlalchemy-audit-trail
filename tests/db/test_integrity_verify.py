"""``verify`` and ``acknowledge`` against a real PostgreSQL.

Every tamper test first verifies the untouched database as ``VALID``, so no
test passes for nothing, then changes exactly one thing and expects exactly
one kind of failure.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import Engine, MetaData, insert, select, text, update
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
from audit_trail.integrity._verify_db import VerifyBusyError, acknowledge, verify
from tests.db.listener_support import Env, make_env, record_statements

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
        last = _seal._last(conn, block)
        seq = int(last.seq) + 1
        _seal._insert(
            conn, block, seq, kind, bytes(last.block_hash), make_body(chain, seq)
        )
    return seq


def sealed_to(env: Env) -> int:
    block = _seal.block_table(env.trail.tables)
    with env.engine.connect() as conn:
        found = _seal._sealed_to(conn, block)
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
    assert {(f.group, f.xid == 3) for f in report.failures} == {
        ("changes", True),
        ("changes", False),
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
    with env.engine.connect() as conn:
        seq = acknowledge(
            conn, env.trail.tables, FailureKind.COMMITMENT_MISSING, {"xid": 1}, "x"
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


def retire(env: Env, upper_bound: datetime) -> int:
    partition = transaction_partition(env)
    return append_block(
        env,
        "retire",
        lambda chain, seq: retire_body(
            chain,
            seq,
            stream="transaction",
            partition=partition,
            upper_bound=upper_bound,
            retention=None,
            rows=2,
            segments_digest=bytes(32),
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


def test_a_writer_without_integrity_is_commitment_missing_until_acknowledged(
    env: Env, models: Models
) -> None:
    assert_valid(env)
    # The same tables, written by a process configured without Integrity.
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


def test_an_ack_is_hashed_into_the_chain(env: Env) -> None:
    with env.engine.connect() as conn:
        seq = acknowledge(
            conn, env.trail.tables, "COMMITMENT_MISSING", {"xid": 5}, "why"
        )
    block = _seal.block_table(env.trail.tables)
    with env.engine.connect() as conn:
        rows = conn.execute(select(block).order_by(block.c.seq)).all()
    assert [r.kind for r in rows] == ["genesis", "seal", "ack"]
    ack = rows[-1]
    assert ack.seq == seq
    assert bytes(ack.prev_hash) == bytes(rows[-2].block_hash)
    assert bytes(ack.block_hash) == block_hash(bytes(ack.prev_hash), bytes(ack.body))
    assert parse_body(bytes(ack.body)) == {
        "v": 1,
        "kind": "ack",
        "chain": parse_body(bytes(rows[0].body))["chain"],
        "seq": seq,
        "failure": "COMMITMENT_MISSING",
        "scope": {"xid": 5},
        "reason": "why",
    }
    assert_valid(env)


@pytest.mark.parametrize(
    ("kind", "scope"),
    [
        ("HASH_MISMATCH", {"xid": 1}),
        ("NO_SUCH_KIND", {"xid": 1}),
        ("COMMITMENT_MISSING", {}),
        ("COMMITMENT_MISSING", {"salt": "x"}),
        ("COMMITMENT_MISSING", {"xid": "1"}),
    ],
)
def test_acknowledge_refuses_what_it_cannot_waive(
    env: Env, kind: str, scope: dict[str, object]
) -> None:
    with env.engine.connect() as conn, pytest.raises(ValueError, match=r"."):
        acknowledge(conn, env.trail.tables, kind, scope, "why")


def test_one_verify_at_a_time(env: Env) -> None:
    block = _seal.block_table(env.trail.tables)
    with env.engine.connect() as holder:
        holder.execute(
            text("SELECT pg_advisory_lock(hashtext(:key))"),
            {"key": _verify_db.verify_lock_key(block)},
        )
        with pytest.raises(VerifyBusyError):
            run(env)
        holder.execute(text("SELECT pg_advisory_unlock_all()"))
    assert run(env).status is Status.VALID


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
