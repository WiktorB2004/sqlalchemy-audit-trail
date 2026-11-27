"""The verifier core with signatures, checkpoints and forks, built in memory."""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import create_engine

from audit_trail.integrity._block import (
    SegmentBuilder,
    activity_leaf_row,
    checkpoint_body,
    fork_body,
    parse_body,
    seal_body,
)
from audit_trail.integrity._checkpoint import Checkpoint
from audit_trail.integrity._ed25519 import Ed25519Signer, Ed25519Verifier
from audit_trail.integrity._seal import window_clause
from audit_trail.integrity._sign import Signer, sign_block
from audit_trail.integrity._verify import (
    Anchor,
    FailureKind,
    NoteKind,
    Partition,
    Status,
    VerificationReport,
    Verifier,
)
from audit_trail.tables import build_tables
from tests.unit.test_integrity_verify import (
    ACT_PART,
    CHAIN,
    TX_PART,
    Chain,
    Sealed,
    activity_row,
    check,
    failures,
    record,
    scrub,
    transaction_row,
)

OLD = Ed25519Signer.from_seed("audit.example/sealer-2026", bytes(range(32)))
NEW = Ed25519Signer.from_seed("audit.example/sealer-2027", bytes(range(32, 64)))
BOTH = Ed25519Verifier([OLD.vkey, NEW.vkey])
WHEN = datetime(2026, 11, 26, 12, tzinfo=UTC)


@pytest.fixture
def sealed() -> Sealed:
    transactions = [transaction_row(1, 200)]
    activities = [activity_row(1, 200), activity_row(2, 200)]
    chain = Chain()
    chain.seal(300, transactions, activities)
    return chain, transactions, activities


def sign(chain: Chain, signer: Signer, *seqs: int) -> None:
    """Sign the blocks ``seqs`` (all when none) of ``chain`` with ``signer``."""
    for index, block in enumerate(chain.blocks):
        if seqs and block.seq not in seqs:
            continue
        signature, key_id, alg = sign_block(signer, block.block_hash)
        chain.blocks[index] = dataclasses.replace(
            block, signature=signature, key_id=key_id, alg=alg
        )


def notes(report: VerificationReport) -> set[Any]:
    return {finding.kind for finding in report.notes}


def checkpoint_of(chain: Chain, seq: int, incarnation: int = 1) -> Checkpoint:
    block = chain.blocks[seq - 1]
    xid_to = int(parse_body(block.body).get("xid_to", 0))
    return Checkpoint(
        CHAIN, seq, block.block_hash, xid_to, block.sealed_at, incarnation
    )


def take_checkpoint(chain: Chain, incarnation: int = 1) -> Checkpoint:
    """Append a checkpoint block and return its checkpoint, as exported."""
    seq = chain.add("checkpoint", checkpoint_body(CHAIN, chain.next, chain.sealed_to))
    return checkpoint_of(chain, seq, incarnation)


# -- block signatures -----------------------------------------------------------


def test_a_signed_chain_verifies(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    sign(chain, OLD)
    report = check(
        chain, transactions, activities, signatures=BOTH, require_signatures=True
    )
    assert report.status is Status.VALID


def test_signatures_are_not_checked_without_a_verifier(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    sign(chain, OLD)
    chain.blocks[1] = dataclasses.replace(chain.blocks[1], signature=bytes(64))
    assert check(chain, transactions, activities).status is Status.VALID


def test_a_wrong_signature_is_bad(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    sign(chain, OLD)
    assert check(chain, transactions, activities, signatures=BOTH).status is (
        Status.VALID
    )
    chain.blocks[1] = dataclasses.replace(chain.blocks[1], signature=bytes(64))
    report = check(chain, transactions, activities, signatures=BOTH)
    assert failures(report) == {FailureKind.BAD_SIGNATURE}
    assert [f.seq for f in report.failures] == [2]


def test_a_signature_over_another_block_is_bad(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    sign(chain, OLD)
    first = chain.blocks[0]
    chain.blocks[1] = dataclasses.replace(chain.blocks[1], signature=first.signature)
    report = check(chain, transactions, activities, signatures=BOTH)
    assert failures(report) == {FailureKind.BAD_SIGNATURE}


def test_an_unknown_key_is_reported(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    sign(chain, OLD)
    report = check(
        chain, transactions, activities, signatures=Ed25519Verifier([NEW.vkey])
    )
    assert failures(report) == {FailureKind.UNKNOWN_KEY}
    assert sorted(f.seq or 0 for f in report.failures) == [1, 2]


def test_an_unsigned_block_fails_when_signatures_are_required(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    sign(chain, OLD, 1)
    assert check(chain, transactions, activities, signatures=BOTH).status is (
        Status.VALID
    )
    report = check(
        chain, transactions, activities, signatures=BOTH, require_signatures=True
    )
    assert failures(report) == {FailureKind.BAD_SIGNATURE}
    assert [f.seq for f in report.failures] == [2]


def test_a_partial_signature_or_another_algorithm_is_bad(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    sign(chain, OLD)
    chain.blocks[0] = dataclasses.replace(chain.blocks[0], alg=None)
    chain.blocks[1] = dataclasses.replace(chain.blocks[1], alg="ecdsa")
    report = check(chain, transactions, activities, signatures=BOTH)
    assert failures(report) == {FailureKind.BAD_SIGNATURE}
    assert sorted(f.seq or 0 for f in report.failures) == [1, 2]


def test_key_rotation_keeps_old_blocks_verifiable(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    more = [transaction_row(2, 350)]
    chain.seal(400, more)
    sign(chain, OLD, 1, 2)
    sign(chain, NEW, 3)
    rows = transactions + more
    report = check(chain, rows, activities, signatures=BOTH, require_signatures=True)
    assert report.status is Status.VALID
    only_new = check(chain, rows, activities, signatures=Ed25519Verifier([NEW.vkey]))
    assert failures(only_new) == {FailureKind.UNKNOWN_KEY}
    assert sorted(f.seq or 0 for f in only_new.failures) == [1, 2]


def test_require_signatures_needs_a_verifier() -> None:
    with pytest.raises(ValueError, match="verifier"):
        Verifier(Chain().blocks, horizon=1, require_signatures=True)


# -- checkpoints ----------------------------------------------------------------


def test_a_matching_checkpoint_anchors_the_chain(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    plain = check(chain, transactions, activities)
    assert plain.anchor is Anchor.UNANCHORED
    checkpoint = take_checkpoint(chain)
    report = check(chain, transactions, activities, checkpoints=[checkpoint])
    assert (report.status, report.anchor) == (Status.VALID, Anchor.ANCHORED)


def test_a_checkpoint_round_trips_into_the_verifier(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    note = take_checkpoint(chain).signed([OLD]).to_note()
    checkpoint = Checkpoint.from_note(note)
    report = check(
        chain, transactions, activities, checkpoints=[checkpoint], signatures=BOTH
    )
    assert (report.status, report.anchor) == (Status.VALID, Anchor.ANCHORED)


def test_blocks_after_the_newest_checkpoint_are_an_unanchored_tail(
    sealed: Sealed,
) -> None:
    chain, transactions, activities = sealed
    checkpoint = take_checkpoint(chain)
    more = [transaction_row(2, 350)]
    chain.seal(400, more)
    last = transaction_row(3, 450)  # salted: build each row once
    chain.seal(500, [last])
    rows = [*transactions, *more, last]
    report = check(chain, rows, activities, checkpoints=[checkpoint])
    assert report.anchor is Anchor.ANCHORED
    assert report.status is Status.VALID_WITH_NOTES
    (tail,) = report.notes
    assert (tail.kind, tail.seq, tail.count) == (NoteKind.UNANCHORED_TAIL, 4, 2)


def test_a_chain_shorter_than_a_checkpoint_is_truncated(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    chain.seal(400, [transaction_row(2, 350)])
    checkpoint = take_checkpoint(chain)
    full = [*transactions, transaction_row(2, 350)]
    assert check(chain, full, activities, checkpoints=[checkpoint]).anchor is (
        Anchor.ANCHORED
    )
    # The head blocks are deleted, and the rows they sealed with them.
    del chain.blocks[2:]
    report = check(chain, transactions, activities, checkpoints=[checkpoint])
    assert failures(report) == {FailureKind.TRUNCATED}
    assert report.failures[0].seq == checkpoint.seq
    assert report.anchor is Anchor.UNANCHORED


def test_a_rewritten_chain_is_a_chain_mismatch(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    checkpoint = take_checkpoint(chain)
    assert check(chain, transactions, activities, checkpoints=[checkpoint]).status is (
        Status.VALID
    )
    # The whole chain rebuilt with one row less: every hash is consistent.
    rebuilt = Chain()
    rebuilt.seal(300, transactions, activities[:1])
    take_checkpoint(rebuilt)
    report = check(rebuilt, transactions, activities[:1], checkpoints=[checkpoint])
    assert failures(report) == {FailureKind.CHAIN_MISMATCH}
    assert report.anchor is Anchor.UNANCHORED


def test_a_checkpoint_of_another_chain_is_a_chain_mismatch(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    checkpoint = dataclasses.replace(take_checkpoint(chain), chain="other")
    report = check(chain, transactions, activities, checkpoints=[checkpoint])
    assert failures(report) == {FailureKind.CHAIN_MISMATCH}


def test_a_badly_signed_checkpoint_is_not_used(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    good = take_checkpoint(chain).signed([OLD])
    forged = dataclasses.replace(good, xid_to=good.xid_to + 1)
    report = check(
        chain, transactions, activities, checkpoints=[forged], signatures=BOTH
    )
    assert failures(report) == {FailureKind.BAD_SIGNATURE}
    assert report.anchor is Anchor.UNANCHORED
    unknown = check(
        chain,
        transactions,
        activities,
        checkpoints=[good],
        signatures=Ed25519Verifier([NEW.vkey]),
    )
    assert failures(unknown) == {FailureKind.UNKNOWN_KEY}


def test_an_unsigned_checkpoint_fails_when_signatures_are_required(
    sealed: Sealed,
) -> None:
    chain, transactions, activities = sealed
    sign(chain, OLD)
    unsigned = take_checkpoint(chain)
    sign(chain, OLD, unsigned.seq)
    options: dict[str, Any] = {"signatures": BOTH, "checkpoints": [unsigned]}
    assert check(chain, transactions, activities, **options).anchor is (Anchor.ANCHORED)
    report = check(chain, transactions, activities, require_signatures=True, **options)
    assert failures(report) == {FailureKind.BAD_SIGNATURE}
    assert [f.seq for f in report.failures] == [unsigned.seq]
    assert report.anchor is Anchor.UNANCHORED
    signed = unsigned.signed([OLD])
    report = check(
        chain,
        transactions,
        activities,
        signatures=BOTH,
        require_signatures=True,
        checkpoints=[signed],
    )
    assert (report.status, report.anchor) == (Status.VALID, Anchor.ANCHORED)


# -- forks ----------------------------------------------------------------------


def declare_fork(
    chain: Chain,
    prior: Checkpoint,
    xid_at_fork: int,
    *,
    floors: dict[str, int] | None = None,
    counts: dict[str, int] | None = None,
    incarnation: int = 2,
) -> int:
    body = fork_body(
        CHAIN,
        chain.next,
        incarnation=incarnation,
        reason="restored from a backup",
        prior_seq=prior.seq,
        prior_hash=prior.block_hash,
        xid_at_fork=xid_at_fork,
        id_floor=floors,
        id_count=counts,
    )
    seq = chain.add("fork", body)
    chain.sealed_to = xid_at_fork
    return seq


@pytest.fixture
def pitr() -> tuple[Chain, Checkpoint, Checkpoint, list[dict[str, Any]]]:
    """A chain checkpointed at seq 3 and 5, restored to seq 3 and forked.

    Returns the chain as it is after the restore and the fork, the last good
    checkpoint (seq 3), the lost one (seq 5), and the rows now present.
    """
    lost = Chain()
    first = [transaction_row(1, 200)]
    lost.seal(300, first)
    good = take_checkpoint(lost)
    lost.seal(400, [transaction_row(2, 350)])
    later = take_checkpoint(lost)
    # PITR to just after seq 3: seq 4 and 5 are gone, xids are reused.
    chain = Chain()
    chain.seal(300, first)
    assert take_checkpoint(chain) == good
    reused = [transaction_row(2, 360)]
    chain.seal(380, reused)
    fork = declare_fork(chain, good, 380)
    sign(chain, OLD, fork)
    new = [transaction_row(3, 390)]
    chain.seal(450, new)
    return chain, good, later, [*first, *reused, *new]


def test_a_signed_fork_explains_a_chain_mismatch(
    pitr: tuple[Chain, Checkpoint, Checkpoint, list[dict[str, Any]]],
) -> None:
    chain, good, lost, rows = pitr
    report = check(chain, rows, [], checkpoints=[good, lost], signatures=BOTH)
    assert report.failures == []
    assert report.status is Status.VALID_WITH_NOTES
    forked = [n for n in report.notes if n.kind is NoteKind.FORKED]
    # The fork block itself, and the checkpoint it explains.
    assert sorted(n.seq or 0 for n in forked) == [5, 5]
    assert "CHAIN_MISMATCH" in forked[-1].detail
    assert report.anchor is Anchor.ANCHORED


def test_a_signed_fork_explains_a_truncated_chain(
    pitr: tuple[Chain, Checkpoint, Checkpoint, list[dict[str, Any]]],
) -> None:
    chain, good, _lost, rows = pitr
    far = dataclasses.replace(good, seq=20)
    report = check(chain, rows, [], checkpoints=[far], signatures=BOTH)
    assert report.failures == []
    assert NoteKind.FORKED in notes(report)
    assert any("TRUNCATED" in n.detail for n in report.notes)


def test_an_unsigned_fork_explains_nothing(
    pitr: tuple[Chain, Checkpoint, Checkpoint, list[dict[str, Any]]],
) -> None:
    chain, good, lost, rows = pitr
    fork = chain.blocks[4]
    chain.blocks[4] = dataclasses.replace(fork, signature=None, key_id=None, alg=None)
    report = check(chain, rows, [], checkpoints=[good, lost], signatures=BOTH)
    assert failures(report) == {FailureKind.CHAIN_MISMATCH}
    # Without a verifier nothing is signed, so nothing is explained either.
    plain = check(chain, rows, [], checkpoints=[good, lost])
    assert failures(plain) == {FailureKind.CHAIN_MISMATCH}


def test_an_unsigned_fork_is_noted_when_signatures_are_checked(
    pitr: tuple[Chain, Checkpoint, Checkpoint, list[dict[str, Any]]],
) -> None:
    chain, _good, _lost, rows = pitr
    assert notes(check(chain, rows, [], signatures=BOTH)) == {NoteKind.FORKED}
    fork = chain.blocks[4]
    chain.blocks[4] = dataclasses.replace(fork, signature=None, key_id=None, alg=None)
    report = check(chain, rows, [], signatures=BOTH)
    assert report.failures == []
    assert notes(report) == {NoteKind.FORKED, NoteKind.FORKED_UNSIGNED}
    (unsigned,) = [n for n in report.notes if n.kind is NoteKind.FORKED_UNSIGNED]
    assert unsigned.seq == fork.seq
    # By a key the verifier does not know: UNKNOWN_KEY, and noted too.
    sign(chain, NEW, fork.seq)
    report = check(chain, rows, [], signatures=Ed25519Verifier([OLD.vkey]))
    assert failures(report) == {FailureKind.UNKNOWN_KEY}
    assert NoteKind.FORKED_UNSIGNED in notes(report)
    # Without a verifier signatures are not checked, so nothing is noted.
    assert notes(check(chain, rows, [])) == {NoteKind.FORKED}


def test_an_undeclared_restore_fails(
    pitr: tuple[Chain, Checkpoint, Checkpoint, list[dict[str, Any]]],
) -> None:
    _chain, good, lost, present = pitr
    restored = Chain()
    first = present[:1]  # the row sealed before the last good checkpoint
    restored.seal(300, first)
    take_checkpoint(restored)
    second, third = transaction_row(2, 360), transaction_row(3, 390)
    restored.seal(380, [second])
    rows = [*first, second]
    truncated = check(restored, rows, [], checkpoints=[good, lost], signatures=BOTH)
    assert failures(truncated) == {FailureKind.TRUNCATED}
    restored.seal(450, [third])
    rows.append(third)
    report = check(restored, rows, [], checkpoints=[good, lost], signatures=BOTH)
    assert failures(report) == {FailureKind.CHAIN_MISMATCH}


def test_a_fork_is_noted_without_checkpoints(
    pitr: tuple[Chain, Checkpoint, Checkpoint, list[dict[str, Any]]],
) -> None:
    chain, _good, _lost, rows = pitr
    report = check(chain, rows, [])
    assert report.failures == []
    assert notes(report) == {NoteKind.FORKED}


def test_a_fork_before_the_checkpoints_prior_explains_nothing(
    pitr: tuple[Chain, Checkpoint, Checkpoint, list[dict[str, Any]]],
) -> None:
    chain, good, _lost, rows = pitr
    # A checkpoint at or below the fork's own prior must still match.
    wrong = dataclasses.replace(good, block_hash=bytes(32))
    report = check(chain, rows, [], checkpoints=[wrong], signatures=BOTH)
    assert failures(report) == {FailureKind.CHAIN_MISMATCH}


def seal_to(chain: Chain, seq: int) -> None:
    """Empty seal blocks until the next block is ``seq``."""
    while chain.next < seq:
        chain.seal(chain.sealed_to + 10)


@pytest.fixture
def forked_at_10() -> tuple[Chain, Checkpoint, Checkpoint]:
    """A chain with a signed fork at seq 10, and a checkpoint at 40 after it.

    Returns the chain, the fork's prior checkpoint (seq 5) and the one at 40,
    taken in incarnation 2.
    """
    chain = Chain()
    seal_to(chain, 5)
    prior = take_checkpoint(chain)
    seal_to(chain, 10)
    fork = declare_fork(chain, prior, chain.sealed_to)
    sign(chain, OLD, fork)
    assert fork == 10
    seal_to(chain, 40)
    after = take_checkpoint(chain, incarnation=2)
    assert after.seq == 40
    seal_to(chain, 45)
    return chain, prior, after


def test_a_checkpoint_after_a_fork_is_not_explained_by_it(
    forked_at_10: tuple[Chain, Checkpoint, Checkpoint],
) -> None:
    chain, prior, after = forked_at_10
    options: dict[str, Any] = {"signatures": BOTH, "checkpoints": [prior, after]}
    report = check(chain, [], [], **options)
    assert report.failures == []
    assert report.anchor is Anchor.ANCHORED
    # The tail cut below the checkpoint: the fork at 10 does not explain it.
    truncated = Chain()
    truncated.blocks = chain.blocks[:35]
    report = check(truncated, [], [], **options)
    assert failures(report) == {FailureKind.TRUNCATED}
    assert [f.seq for f in report.failures] == [40]
    # The tail rewritten from seq 20: every hash is consistent, but the
    # block at 40 is another.
    rewritten = Chain()
    rewritten.blocks = chain.blocks[:19]
    rewritten.sealed_to = int(parse_body(chain.blocks[18].body)["xid_to"])
    seal_to(rewritten, 41)
    rewritten.seal(rewritten.sealed_to + 3)
    report = check(rewritten, [], [], **options)
    assert failures(report) == {FailureKind.CHAIN_MISMATCH}
    assert [f.seq for f in report.failures] == [40]
    assert not any("explained" in n.detail for n in report.notes)


def test_a_checkpoint_lost_with_the_old_incarnation_is_explained(
    forked_at_10: tuple[Chain, Checkpoint, Checkpoint],
) -> None:
    chain, prior, _after = forked_at_10
    # Taken in incarnation 1 before the restore, at a seq above the fork's.
    lost = dataclasses.replace(prior, seq=30, block_hash=bytes(32))
    report = check(chain, [], [], signatures=BOTH, checkpoints=[prior, lost])
    assert report.failures == []
    assert any("CHAIN_MISMATCH explained" in n.detail for n in report.notes)
    # One between the prior checkpoint and the fork is explained too.
    between = dataclasses.replace(lost, seq=8)
    report = check(chain, [], [], signatures=BOTH, checkpoints=[between])
    assert report.failures == []


def test_a_checkpoint_naming_another_incarnation_is_a_chain_mismatch(
    forked_at_10: tuple[Chain, Checkpoint, Checkpoint],
) -> None:
    chain, _prior, after = forked_at_10
    relabelled = dataclasses.replace(after, incarnation=1)
    report = check(chain, [], [], signatures=BOTH, checkpoints=[relabelled])
    assert failures(report) == {FailureKind.CHAIN_MISMATCH}
    assert report.anchor is Anchor.UNANCHORED


@pytest.mark.parametrize(
    "change",
    ["incarnation", "prior hash", "prior seal", "floors", "rewind"],
)
def test_a_fork_block_that_does_not_fit_is_malformed(change: str) -> None:
    chain = Chain()
    rows = [transaction_row(1, 200)]
    chain.seal(300, rows)
    good = take_checkpoint(chain)
    options: dict[str, Any] = {}
    xid_at_fork = 300
    if change == "incarnation":
        options["incarnation"] = 3
    elif change == "prior hash":
        good = dataclasses.replace(good, block_hash=bytes(32))
    elif change == "prior seal":
        good = checkpoint_of(chain, 2)
    elif change == "floors":
        options.update(floors={"transaction": 1}, counts={"activity.20": 1})
    else:
        xid_at_fork = 299
    declare_fork(chain, good, xid_at_fork, **options)
    report = check(chain, rows, [])
    assert failures(report) == {FailureKind.MALFORMED_BLOCK}


@pytest.fixture
def dumped() -> tuple[Chain, list[dict[str, Any]], list[dict[str, Any]]]:
    """A chain restored from ``pg_dump`` into a new cluster and forked.

    Old xids run up to 900, the new cluster starts at 150; new rows get ids
    above the floor, and xids inside old seal ranges.
    """
    chain = Chain()
    old = [transaction_row(1, 200), transaction_row(2, 900)]
    old_activity = [activity_row(1, 210)]
    chain.seal(300, old[:1], old_activity)
    good = take_checkpoint(chain)
    # The closing seal over the unsealed tail, up to the highest xid + 1.
    chain.seal(901, old[1:])
    floors = {"transaction": 2, "activity.20": 1}
    fork = declare_fork(chain, good, 150, floors=floors, counts=dict(floors))
    sign(chain, OLD, fork)
    new = [transaction_row(3, 250), transaction_row(4, 260)]
    new_activity = [activity_row(2, 250)]
    chain.seal(400, new, new_activity)
    transactions = sorted([*old, *new], key=lambda r: (r["xid"], r["id"]))
    activities = sorted([*old_activity, *new_activity], key=lambda r: r["xid"])
    return chain, transactions, activities


def test_a_fork_with_an_id_window_verifies(
    dumped: tuple[Chain, list[dict[str, Any]], list[dict[str, Any]]],
) -> None:
    chain, transactions, activities = dumped
    report = check(chain, transactions, activities, horizon=500)
    assert report.failures == []
    (forked,) = report.notes
    assert (forked.kind, forked.seq) == (NoteKind.FORKED, 5)


def test_a_stream_that_appears_after_a_windowed_fork_verifies() -> None:
    chain = Chain()
    old = [transaction_row(1, 200)]
    old_activity = [activity_row(1, 210)]
    chain.seal(300, old, old_activity)
    good = take_checkpoint(chain)
    floors = {"transaction": 1, "activity.20": 1}
    fork = declare_fork(chain, good, 150, floors=floors, counts=dict(floors))
    sign(chain, OLD, fork)
    # Severity 3 had no row before the fork; its first one, in the new
    # cluster, has an xid inside the old sealed range.
    new_stream = activity_row(500, 260)
    new_stream["severity"] = 3
    new = [transaction_row(2, 250)]
    chain.seal(400, new, [new_stream])
    verifier = Verifier(chain.blocks, horizon=500)
    assert verifier.incarnation_of("activity.3", 500, 260) is verifier.incarnations[1]
    assert verifier.incarnation_of("activity.20", 1, 210) is verifier.incarnations[0]
    activities = sorted([*old_activity, new_stream], key=lambda r: (r["xid"], r["id"]))
    report = check(chain, [*old, *new], activities, horizon=500)
    assert report.failures == []
    assert notes(report) == {NoteKind.FORKED}


def test_old_rows_above_the_new_xmax_are_not_from_the_future(
    dumped: tuple[Chain, list[dict[str, Any]], list[dict[str, Any]]],
) -> None:
    chain, transactions, activities = dumped
    # Row 2 has xid 900, far above the new cluster's xmax of 500.
    verifier = Verifier(chain.blocks, horizon=500, xmax=500)
    verifier.check_partition(Partition("transaction", TX_PART), transactions)
    verifier.check_partition(Partition("activity", ACT_PART), activities)
    verifier.schema([])
    assert verifier.report().failures == []
    # A new row (above the floor) with such an xid still is.
    future = transaction_row(5, 600)
    verifier = Verifier(chain.blocks, horizon=500, xmax=500)
    verifier.check_partition(Partition("transaction", TX_PART), [*transactions, future])
    verifier.check_partition(Partition("activity", ACT_PART), activities)
    verifier.schema([])
    assert {f.kind for f in verifier.report().failures} == {FailureKind.XID_REWIND}


def test_an_old_row_scrubbed_after_the_fork_counts(
    dumped: tuple[Chain, list[dict[str, Any]], list[dict[str, Any]]],
) -> None:
    chain, transactions, activities = dumped
    # A stamp of a scrub at xid 450 in the new cluster, on an old row of
    # xid 900: older than its row by number, but in the current xid space.
    stamped = dict(transactions[-1])
    assert stamped["xid"] == 900
    stamped["seal_erased"] = {"actor": "450"}
    verifier = Verifier(chain.blocks, horizon=500, xmax=500, count_scrubs=False)
    rows = [*transactions[:-1], stamped]
    verifier.check_partition(Partition("transaction", TX_PART), rows)
    verifier.check_partition(Partition("activity", ACT_PART), activities)
    verifier.schema([])
    assert verifier.report().failures == []


def test_an_old_row_left_past_the_closing_seal_fails(
    dumped: tuple[Chain, list[dict[str, Any]], list[dict[str, Any]]],
) -> None:
    chain, transactions, activities = dumped
    stray = transaction_row(1, 950)  # id at or below the floor, xid past 901
    rows = sorted([*transactions, stray], key=lambda r: (r["xid"], r["id"]))
    report = check(chain, rows, activities, horizon=500)
    assert failures(report) == {FailureKind.ROW_COUNT_MISMATCH}
    assert report.failures[0].xid == 950


def window_sql(floors: dict[str, int], *, above: bool, table: str) -> str | None:
    tables = build_tables(integrity=True)
    clause = window_clause(getattr(tables, table), floors, above=above)
    if clause is None:
        return None
    compiled = clause.compile(
        dialect=create_engine("postgresql+psycopg://").dialect,
        compile_kwargs={"literal_binds": True},
    )
    return (
        str(compiled)
        .replace("audit.audit_activity.", "")
        .replace("audit.audit_transaction.", "")
    )


def test_the_sealer_window_of_a_stream_the_fork_does_not_name() -> None:
    # A stream the fork does not name had no row then: above its floor every
    # row of it, at or below it none.
    only_tx = {"transaction": 5}
    assert window_sql(only_tx, above=True, table="activity") is None
    assert window_sql(only_tx, above=False, table="activity") == "false"
    only_activity = {"activity.20": 5}
    assert window_sql(only_activity, above=True, table="transaction") is None
    assert window_sql(only_activity, above=False, table="transaction") == "false"
    assert window_sql(only_activity, above=True, table="activity") == (
        "severity = 20 AND id > 5 OR (severity NOT IN (20))"
    )
    assert window_sql(only_activity, above=False, table="activity") == (
        "severity = 20 AND id <= 5"
    )


# -- scrubs in two xid spaces -------------------------------------------------

REC_PART = "audit_activity_20_p2026_01"


def two_spaces(
    old: list[dict[str, Any]],
    new: list[dict[str, Any]],
    *,
    retired: Sequence[dict[str, Any]] = (),
    closing: Sequence[dict[str, Any]] = (),
) -> Chain:
    """A chain restored by ``pg_dump`` into a new cluster, as ``dumped``.

    ``old`` rows are sealed in ``[100, 300)``, with ``retired`` ones in a
    partition retired since, and ``closing`` ones by the closing seal up to
    901; the fork's floor is the highest old id, the new cluster starts at
    xid 150, and ``new`` rows are sealed in ``[150, 400)``.
    """
    chain = Chain()
    builder = SegmentBuilder()
    for row in old:
        builder.add("activity.20", ACT_PART, activity_leaf_row(row))
    for row in retired:
        builder.add("activity.20", REC_PART, activity_leaf_row(row))
    chain.add("seal", seal_body(CHAIN, chain.next, 100, 300, builder.segments()))
    chain.sealed_to = 300
    if retired:
        chain.retire(REC_PART, ["activity.20"], datetime(2026, 2, 1, tzinfo=UTC))
    good = take_checkpoint(chain)
    if closing:
        chain.seal(901, [], closing)
    floor = max(row["id"] for row in [*old, *retired, *closing])
    floors = {"activity.20": floor}
    fork = declare_fork(chain, good, 150, floors=floors, counts=dict(floors))
    sign(chain, OLD, fork)
    chain.seal(400, [], new)
    return chain


def check_spaces(
    chain: Chain, rows: list[dict[str, Any]], *, horizon: int = 500, xmax: int = 500
) -> VerificationReport:
    verifier = Verifier(chain.blocks, horizon=horizon, xmax=xmax, system_severity=20)
    verifier.check_partition(Partition("transaction", TX_PART), [])
    ordered = sorted(rows, key=lambda r: (r["xid"], r["id"]))
    verifier.check_partition(Partition("activity", ACT_PART), ordered)
    verifier.schema([])
    return verifier.report()


def test_an_old_scrub_with_a_retired_record_and_a_new_one_at_its_xid() -> None:
    # Old cluster: row 1 scrubbed at xid 250, its record (2) retired since.
    # New cluster: row 3 scrubbed at xid 250 too, its record (4) present.
    old_row, new_row = activity_row(1, 200), activity_row(3, 240)
    scrub(old_row, 250)
    scrub(new_row, 250)
    old_record = record(2, 250, operation="scrub", activity_rows=1)
    new_record = record(4, 250, operation="scrub", activity_rows=1)
    chain = two_spaces([old_row], [new_row, new_record], retired=[old_record])
    report = check_spaces(chain, [old_row, new_row, new_record])
    assert report.failures == []
    assert NoteKind.ERASED_RECEIPT_RETIRED in notes(report)


def test_a_new_erasure_is_not_explained_by_an_old_retired_record() -> None:
    # The old cluster's block over [100, 300) has a retired partition; a new
    # row erased at xid 260, with no record, is in the new cluster's block.
    kept = activity_row(1, 200)
    gone = activity_row(2, 210)
    erased = activity_row(3, 245)
    chain = two_spaces([kept], [erased], retired=[gone])
    assert check_spaces(chain, [kept, erased]).failures == []
    scrub(erased, 260)
    report = check_spaces(chain, [kept, erased])
    assert failures(report) == {FailureKind.SCRUB_COUNT_MISMATCH}
    assert NoteKind.ERASED_RECEIPT_RETIRED not in notes(report)


def test_an_old_record_at_a_running_xid_of_the_new_cluster_is_counted() -> None:
    # An old record at xid 455 that accounts for a row nobody stamped. 455
    # is between the new cluster's horizon and xmax, where a scrub of the
    # new cluster could still be running; the old one cannot.
    old_row = activity_row(1, 200)
    old_record = record(2, 455, operation="scrub", activity_rows=1)
    chain = two_spaces([old_row], [], closing=[old_record])
    report = check_spaces(chain, [old_row, old_record], horizon=450, xmax=460)
    assert failures(report) == {FailureKind.SCRUB_COUNT_MISMATCH}
    assert {(f.xid, f.group) for f in report.failures} == {
        (455, "label"),
        (455, "changes"),
        (455, "payload"),
    }


def test_an_old_row_scrubbed_after_the_fork_is_counted_in_the_new_space() -> None:
    # Row 1 of the old cluster, scrubbed at xid 250 of the new one: the
    # stamp fits both spaces, and the new record accounts for it.
    old_row = activity_row(1, 200)
    scrub(old_row, 250)
    new_record = record(4, 250, operation="scrub", activity_rows=1)
    chain = two_spaces([old_row], [new_record])
    report = check_spaces(chain, [old_row, new_record])
    assert report.failures == []
    # Without the record, nothing accounts for it.
    chain = two_spaces([old_row], [])
    report = check_spaces(chain, [old_row])
    assert failures(report) == {FailureKind.SCRUB_COUNT_MISMATCH}
