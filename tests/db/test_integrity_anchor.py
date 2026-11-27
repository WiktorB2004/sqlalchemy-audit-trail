"""Signed blocks, checkpoints, ``require_replicated`` and forks on PostgreSQL.

Each test that expects a failure first verifies the untouched database, so
no test passes for nothing.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import Engine, delete, select, text
from sqlalchemy import event as sa_event

from audit_trail import AuditEvent, Severity, event, migrations
from audit_trail.integrity import _anchor, _seal
from audit_trail.integrity._anchor import (
    ReplicationError,
    declare_fork,
    export_checkpoint,
)
from audit_trail.integrity._block import checkpoint_body, parse_body
from audit_trail.integrity._checkpoint import Checkpoint
from audit_trail.integrity._ed25519 import Ed25519Signer, Ed25519Verifier
from audit_trail.integrity._options import Integrity
from audit_trail.integrity._seal import SealRefusedError
from audit_trail.integrity._verify import (
    Anchor,
    FailureKind,
    NoteKind,
    Status,
    VerificationReport,
)
from audit_trail.integrity._verify_db import verify
from tests.db.listener_support import Env, make_env

pytestmark = pytest.mark.filterwarnings("ignore:Did not recognize type 'xid8'")

OLD = Ed25519Signer.from_seed("audit.example/sealer-2026", bytes(range(32)))
NEW = Ed25519Signer.from_seed("audit.example/sealer-2027", bytes(range(32, 64)))
BOTH = Ed25519Verifier([OLD.vkey, NEW.vkey])


class AnchorEvent(AuditEvent):
    NOTED = event("anchor_test.noted", Severity.INFO)


@pytest.fixture
def env(engine: Engine, schema: str) -> Iterator[Env]:
    """Integrity on, the chain started (genesis signed by ``OLD``), rows sealed."""
    built = make_env(
        engine, schema, events=[AnchorEvent], severities=Severity, integrity=Integrity()
    )
    with engine.begin() as conn:
        migrations.write_genesis(conn, built.trail.tables, signer=OLD)
    write(built, 3)
    seal(built, OLD)
    yield built
    built.trail.dispose()


def write(env: Env, count: int) -> None:
    for n in range(count):
        with env.factory() as session:
            env.trail.log(session, AnchorEvent.NOTED, payload={"n": n})
            session.commit()


def seal(env: Env, signer: Ed25519Signer | None = None) -> None:
    result = env.trail.maintenance.seal(signer=signer)
    assert result.skipped is None
    assert result.blocks == 1


def run(env: Env, **options: Any) -> VerificationReport:
    return verify(env.engine, env.trail.tables, **options)


def failed(report: VerificationReport) -> set[FailureKind]:
    return {FailureKind(finding.kind) for finding in report.failures}


def noted(report: VerificationReport) -> set[NoteKind]:
    return {NoteKind(finding.kind) for finding in report.notes}


def checkpoint(env: Env, signer: Ed25519Signer | None = OLD, **options: Any) -> str:
    with env.engine.connect() as conn:
        return export_checkpoint(
            conn, env.trail.tables, signer=signer, **options
        ).to_note()


def blocks(env: Env) -> list[Any]:
    block = _seal.block_table(env.trail.tables)
    with env.engine.connect() as conn:
        return list(conn.execute(select(block).order_by(block.c.seq)).all())


def drop_blocks_from(env: Env, seq: int) -> None:
    """What a restore to an earlier point, or an attacker, leaves of the chain."""
    block = _seal.block_table(env.trail.tables)
    with env.engine.begin() as conn:
        conn.execute(delete(block).where(block.c.seq >= seq))


# -- signed blocks -------------------------------------------------------------------


def test_blocks_are_signed_and_verify(env: Env) -> None:
    rows = blocks(env)
    assert [(r.kind, r.key_id, r.alg) for r in rows] == [
        ("genesis", OLD.key_id, "ed25519"),
        ("seal", OLD.key_id, "ed25519"),
    ]
    report = run(env, verifier=BOTH, require_signatures=True)
    assert report.status is Status.VALID


def test_a_tampered_signature_is_bad(env: Env) -> None:
    assert run(env, verifier=BOTH).status is Status.VALID
    block = _seal.block_table(env.trail.tables)
    with env.engine.begin() as conn:
        conn.execute(block.update().where(block.c.seq == 2).values(signature=bytes(64)))
    report = run(env, verifier=BOTH)
    assert failed(report) == {FailureKind.BAD_SIGNATURE}


def test_key_rotation_with_several_keys(env: Env) -> None:
    write(env, 2)
    seal(env, NEW)
    checkpoint(env, signer=NEW)
    assert [r.key_id for r in blocks(env)] == [OLD.key_id] * 2 + [NEW.key_id] * 2
    report = run(env, verifier=BOTH, require_signatures=True)
    assert report.status is Status.VALID
    only_new = run(env, verifier=Ed25519Verifier([NEW.vkey]))
    assert failed(only_new) == {FailureKind.UNKNOWN_KEY}
    assert sorted(f.seq or 0 for f in only_new.failures) == [1, 2]


def test_an_unsigned_block_fails_when_signatures_are_required(env: Env) -> None:
    write(env, 1)
    seal(env)
    assert run(env, verifier=BOTH).status is Status.VALID
    report = run(env, verifier=BOTH, require_signatures=True)
    assert failed(report) == {FailureKind.BAD_SIGNATURE}
    assert [f.seq for f in report.failures] == [3]


# -- checkpoints ----------------------------------------------------------------------


def test_a_checkpoint_round_trips_through_its_note(env: Env) -> None:
    note = checkpoint(env)
    parsed = Checkpoint.from_note(note)
    assert parsed.to_note() == note
    last = blocks(env)[-1]
    assert (last.kind, last.seq, bytes(last.block_hash)) == (
        "checkpoint",
        parsed.seq,
        parsed.block_hash,
    )
    assert parse_body(bytes(last.body))["xid_to"] == parsed.xid_to
    assert parsed.verify(BOTH) == [OLD.key_id]
    report = run(env, checkpoints=[note], verifier=BOTH)
    assert (report.status, report.anchor) == (Status.VALID, Anchor.ANCHORED)
    unsigned = checkpoint(env, signer=None)
    assert "\n\n" not in unsigned
    report = run(env, checkpoints=[note, unsigned])
    assert (report.status, report.anchor) == (Status.VALID, Anchor.ANCHORED)


def test_without_checkpoints_the_chain_is_unanchored(env: Env) -> None:
    checkpoint(env)
    assert run(env).anchor is Anchor.UNANCHORED


def test_blocks_after_the_checkpoint_are_an_unanchored_tail(env: Env) -> None:
    note = checkpoint(env)
    write(env, 1)
    seal(env, OLD)
    report = run(env, checkpoints=[note])
    assert report.anchor is Anchor.ANCHORED
    assert noted(report) == {NoteKind.UNANCHORED_TAIL}


def test_a_chain_cut_below_a_checkpoint_is_truncated(env: Env) -> None:
    note = checkpoint(env)
    assert run(env, checkpoints=[note]).status is Status.VALID
    drop_blocks_from(env, Checkpoint.from_note(note).seq)
    report = run(env, checkpoints=[note])
    assert failed(report) == {FailureKind.TRUNCATED}
    assert report.anchor is Anchor.UNANCHORED


def test_a_rewritten_chain_is_a_chain_mismatch(env: Env) -> None:
    note = checkpoint(env)
    assert run(env, checkpoints=[note]).status is Status.VALID
    seq = Checkpoint.from_note(note).seq
    drop_blocks_from(env, seq)
    block = _seal.block_table(env.trail.tables)
    with env.engine.begin() as conn:
        last = _seal.last_block(conn, block)
        chain = parse_body(
            conn.execute(select(block.c.body).where(block.c.seq == 1)).scalar_one()
        )["chain"]
        # A consistent chain again, with another block at the same seq.
        body = checkpoint_body(chain, seq, 1)
        _seal.insert_block(conn, block, seq, "checkpoint", bytes(last.block_hash), body)
    report = run(env, checkpoints=[note])
    assert failed(report) == {FailureKind.CHAIN_MISMATCH}


def test_require_replicated_without_a_standby(env: Env) -> None:
    before = len(blocks(env))
    with env.engine.connect() as conn, pytest.raises(ReplicationError) as info:
        export_checkpoint(conn, env.trail.tables, require_replicated=True)
    assert info.value.reason == "NO_SYNC_STANDBY"
    assert info.value.lsn
    # The block is in the chain; only the checkpoint was refused.
    after = blocks(env)
    assert len(after) == before + 1
    assert after[-1].kind == "checkpoint"
    assert info.value.seq == after[-1].seq
    assert run(env).status is Status.VALID


def test_an_error_after_the_commit_is_a_replication_error(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        _anchor, "_STANDBYS", text("SELECT no_such_column FROM pg_stat_replication")
    )
    before = len(blocks(env))
    with env.engine.connect() as conn, pytest.raises(ReplicationError) as info:
        export_checkpoint(conn, env.trail.tables, require_replicated=True)
    assert info.value.reason == "CHECK_FAILED"
    assert info.value.__cause__ is not None
    after = blocks(env)
    assert len(after) == before + 1
    assert (info.value.seq, bool(info.value.lsn)) == (after[-1].seq, True)


# -- forks without an id window (PITR) -------------------------------------------------


def pitr(env: Env) -> tuple[str, str]:
    """Take two checkpoints, then lose the blocks after the first one.

    The last good checkpoint and the lost one, as notes.
    """
    good = checkpoint(env)
    lost = checkpoint(env)
    assert run(env, checkpoints=[good, lost], verifier=BOTH).status is Status.VALID
    drop_blocks_from(env, Checkpoint.from_note(lost).seq)
    return good, lost


def test_a_declared_fork_is_forked(env: Env) -> None:
    good, lost = pitr(env)
    with env.engine.connect() as conn:
        fork = declare_fork(
            conn, env.trail.tables, good, reason="PITR to 03:00", signer=OLD
        )
    assert (fork.incarnation, fork.id_floor, fork.closing_seq) == (2, None, None)
    write(env, 2)
    seal(env, OLD)
    report = run(env, checkpoints=[good, lost], verifier=BOTH)
    assert report.failures == []
    assert NoteKind.FORKED in noted(report)
    forked = [n for n in report.notes if n.kind is NoteKind.FORKED]
    assert len(forked) == 2  # the fork block, and the checkpoint it explains
    assert report.anchor is Anchor.ANCHORED


def test_a_checkpoint_after_the_fork_is_not_explained_by_it(env: Env) -> None:
    good, lost = pitr(env)
    with env.engine.connect() as conn:
        fork = declare_fork(
            conn, env.trail.tables, good, reason="PITR to 03:00", signer=OLD
        )
    write(env, 2)
    seal(env, OLD)
    after = checkpoint(env)
    assert Checkpoint.from_note(after).incarnation == fork.incarnation == 2
    assert Checkpoint.from_note(lost).incarnation == 1
    write(env, 2)
    seal(env, OLD)
    notes = [good, lost, after]
    assert run(env, checkpoints=notes, verifier=BOTH).failures == []
    drop_blocks_from(env, Checkpoint.from_note(after).seq)
    report = run(env, checkpoints=notes, verifier=BOTH)
    assert failed(report) == {FailureKind.TRUNCATED}
    assert [f.seq for f in report.failures] == [Checkpoint.from_note(after).seq]


def test_an_undeclared_fork_fails(env: Env) -> None:
    good, lost = pitr(env)
    assert failed(run(env, checkpoints=[good, lost])) == {FailureKind.TRUNCATED}
    write(env, 2)
    seal(env, OLD)
    report = run(env, checkpoints=[good, lost], verifier=BOTH)
    assert failed(report) == {FailureKind.CHAIN_MISMATCH}
    assert NoteKind.FORKED not in noted(report)


def test_an_unsigned_fork_explains_nothing(env: Env) -> None:
    good, lost = pitr(env)
    with env.engine.connect() as conn:
        declare_fork(conn, env.trail.tables, good, reason="PITR")
    write(env, 2)
    seal(env, OLD)
    report = run(env, checkpoints=[good, lost], verifier=BOTH)
    assert failed(report) == {FailureKind.CHAIN_MISMATCH}


def test_a_fork_seals_what_was_left_unsealed(env: Env) -> None:
    good = checkpoint(env)
    write(env, 2)
    with env.engine.connect() as conn:
        fork = declare_fork(conn, env.trail.tables, good, reason="PITR", signer=OLD)
    assert fork.closing_seq == fork.seq - 1
    kinds = [r.kind for r in blocks(env)][-2:]
    assert kinds == ["seal", "fork"]
    report = run(env, verifier=BOTH, require_signatures=True)
    assert report.failures == []
    assert noted(report) == {NoteKind.FORKED}


def test_a_fork_needs_a_checkpoint_of_the_chain(env: Env) -> None:
    good = Checkpoint.from_note(checkpoint(env))
    other = Checkpoint(good.chain, good.seq, bytes(32), good.xid_to, good.sealed_at)
    with (
        env.engine.connect() as conn,
        pytest.raises(ValueError, match="does not match"),
    ):
        declare_fork(conn, env.trail.tables, other, reason="x")
    beyond = Checkpoint(
        good.chain, good.seq + 5, good.block_hash, good.xid_to, good.sealed_at
    )
    with (
        env.engine.connect() as conn,
        pytest.raises(ValueError, match="does not match"),
    ):
        declare_fork(conn, env.trail.tables, beyond, reason="x")
    seal_block = blocks(env)[1]
    named = Checkpoint(
        good.chain, 2, bytes(seal_block.block_hash), good.xid_to, good.sealed_at
    )
    with env.engine.connect() as conn, pytest.raises(ValueError, match="not a check"):
        declare_fork(conn, env.trail.tables, named, reason="x")
    assert [r.kind for r in blocks(env)][-1] == "checkpoint"


# -- forks with an id window, and the refusal checks ----------------------------


def window_fork(env: Env) -> None:
    """A fork with an id window on a database whose ids were not rewound."""
    good = checkpoint(env)
    with env.engine.connect() as conn:
        fork = declare_fork(
            conn, env.trail.tables, good, reason="restore", signer=OLD, id_window=True
        )
    assert fork.id_floor is not None
    assert fork.id_count is not None
    assert set(fork.id_count.values()) == {3}


def execute(env: Env, sql: str) -> None:
    with env.engine.begin() as conn:
        conn.execute(text(sql))


def qualified(env: Env, which: str) -> str:
    table = getattr(env.trail.tables, which)
    return f'"{table.schema}"."{table.name}"'


def test_a_fork_with_an_id_window_verifies(env: Env) -> None:
    window_fork(env)
    write(env, 2)
    seal(env, OLD)
    report = run(env, verifier=BOTH, require_signatures=True)
    assert report.failures == []
    assert noted(report) == {NoteKind.FORKED}


def test_an_identity_reset_is_refused_by_the_sealer(env: Env) -> None:
    window_fork(env)
    for which in ("transaction", "activity"):
        execute(env, f"ALTER TABLE {qualified(env, which)} ALTER COLUMN id RESTART")
    write(env, 1)
    with pytest.raises(SealRefusedError) as info:
        env.trail.maintenance.seal()
    assert info.value.reason == "ID_FLOOR_VIOLATION"
    assert "sequence" in str(info.value)


def test_a_reset_that_climbed_past_the_floor_is_refused_by_count(env: Env) -> None:
    window_fork(env)
    for which in ("transaction", "activity"):
        execute(env, f"ALTER TABLE {qualified(env, which)} ALTER COLUMN id RESTART")
    write(env, 1)  # ids 1 again: at or below the floor
    for which in ("transaction", "activity"):
        # Past the floor (3), within id_count (3) of it.
        execute(
            env,
            f"ALTER TABLE {qualified(env, which)} ALTER COLUMN id RESTART WITH 5",
        )
    with pytest.raises(SealRefusedError) as info:
        env.trail.maintenance.seal()
    assert info.value.reason == "ID_FLOOR_VIOLATION"
    assert "more rows" in str(info.value)


def floor_counts(env: Env) -> int:
    """How many id-floor counts one seal runs."""
    statements: list[str] = []

    def record(*args: Any) -> None:
        statements.append(str(args[2]))

    sa_event.listen(env.engine, "before_cursor_execute", record)
    try:
        env.trail.maintenance.seal(signer=OLD)
    finally:
        sa_event.remove(env.engine, "before_cursor_execute", record)
    return sum("count(*)" in sql and ".id <= " in sql for sql in statements)


def test_the_floor_count_runs_only_near_the_floor(env: Env) -> None:
    window_fork(env)
    # Floor 3 and id_count 3 for each stream: the count reads at most 4
    # entries, while the sequence is within 3 of the floor.
    write(env, 1)
    assert floor_counts(env) == 2
    for which in ("transaction", "activity"):
        execute(
            env,
            f"ALTER TABLE {qualified(env, which)} ALTER COLUMN id RESTART WITH 100",
        )
    write(env, 1)
    assert floor_counts(env) == 0
    assert run(env, verifier=BOTH).failures == []


def test_a_fork_is_refused_while_a_sequence_is_behind(env: Env) -> None:
    good = checkpoint(env)
    execute(
        env,
        f"ALTER TABLE {qualified(env, 'activity')} ALTER COLUMN id RESTART WITH 2",
    )
    before = len(blocks(env))
    with env.engine.connect() as conn, pytest.raises(SealRefusedError) as info:
        declare_fork(conn, env.trail.tables, good, reason="x", id_window=True)
    assert info.value.reason == "ID_FLOOR_VIOLATION"
    assert len(blocks(env)) == before
