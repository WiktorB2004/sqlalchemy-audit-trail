"""The pure verifier core, fed with rows and blocks built in memory."""

from __future__ import annotations

import ast
import base64
import dataclasses
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from audit_trail.diff import ERASED
from audit_trail.events import AuditSystem
from audit_trail.integrity import _verify
from audit_trail.integrity._block import (
    ZERO_HASH,
    SealedSegment,
    Segment,
    SegmentBuilder,
    ack_body,
    activity_leaf_row,
    activity_stream,
    block_hash,
    checkpoint_body,
    fork_body,
    genesis_body,
    parse_body,
    retire_body,
    seal_body,
    transaction_leaf_row,
)
from audit_trail.integrity._canonical import canonical
from audit_trail.integrity._commit import (
    activity_groups,
    seal_columns,
    transaction_groups,
)
from audit_trail.integrity._verify import (
    Ack,
    FailureKind,
    Finding,
    Incarnation,
    NoteKind,
    Partition,
    Seal,
    Status,
    StoredBlock,
    Verifier,
    check_scope,
    is_erased,
    stream_retention,
)

CHAIN = "6f1d1c0e-0000-4000-8000-000000000000"
NOW = datetime(2026, 11, 26, 12, tzinfo=UTC)
TX_PART = "audit_transaction_p2026_11"
ACT_PART = "audit_activity_20_p2026_11"


def transaction_row(row_id: int, xid: int) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": row_id,
        "issued_at": NOW,
        "actor_type": "user",
        "actor_id": "ann",
        "actor_label": "Ann",
        "remote_addr": "192.0.2.1",
        "user_agent": None,
        "meta": None,
        "method": None,
        "path": None,
        "channel": None,
        "auth_method": None,
        "request_id": None,
        "correlation_id": None,
        "xid": xid,
    }
    row.update(seal_columns(transaction_groups(row)))
    return row


def activity_row(row_id: int, xid: int, **data: Any) -> dict[str, Any]:
    body = {"v": 1, "payload": {"n": 1}, "context": {"actor_label": "Ann"}, **data}
    row: dict[str, Any] = {
        "id": row_id,
        "transaction_id": 1,
        "verb": "test.noted",
        "severity": 20,
        "object_type": "Doc",
        "object_id": "1",
        "object_label": "One",
        "target_type": None,
        "target_id": None,
        "actor_id": "ann",
        "scope_id": None,
        "correlation_id": None,
        "created_at": NOW,
        "data": body,
        "xid": xid,
    }
    row.update(seal_columns(activity_groups(row["object_label"], body)))
    return row


class Chain:
    """Blocks built the way the sealer builds them."""

    def __init__(self, enforce_from: int = 100) -> None:
        self.blocks: list[StoredBlock] = []
        self.sealed_to = enforce_from
        self.add("genesis", genesis_body(CHAIN, enforce_from))

    def add(self, kind: str, body: bytes, sealed_at: datetime = NOW) -> int:
        prev = self.blocks[-1].block_hash if self.blocks else ZERO_HASH
        seq = len(self.blocks) + 1
        self.blocks.append(
            StoredBlock(seq, kind, body, prev, block_hash(prev, body), sealed_at)
        )
        return seq

    @property
    def next(self) -> int:
        return len(self.blocks) + 1

    def seal(
        self,
        xid_to: int,
        transactions: Iterable[dict[str, Any]] = (),
        activities: Iterable[dict[str, Any]] = (),
    ) -> int:
        builder = SegmentBuilder()
        for row in transactions:
            builder.add("transaction", TX_PART, transaction_leaf_row(row))
        for row in activities:
            stream = activity_stream(row["severity"])
            builder.add(stream, ACT_PART, activity_leaf_row(row))
        body = seal_body(CHAIN, self.next, self.sealed_to, xid_to, builder.segments())
        self.sealed_to = xid_to
        return self.add("seal", body)

    def sealed(self, partition: str) -> list[SealedSegment]:
        """The segments of ``partition`` in the seal blocks so far."""
        found = []
        for block in self.blocks:
            if block.kind != "seal":
                continue
            for item in parse_body(block.body)["segments"]:
                if item["partition"] == partition:
                    segment = Segment(
                        item["stream"],
                        partition,
                        item["rows"],
                        base64.b64decode(item["root"]),
                    )
                    found.append(SealedSegment(block.seq, segment))
        return found

    def retire(
        self,
        partition: str,
        streams: list[str],
        upper_bound: datetime,
        *,
        segments: list[SealedSegment] | None = None,
        sealed_at: datetime = NOW,
    ) -> int:
        """A retire block covering the segments sealed so far, as written."""
        table = "transaction" if streams == ["transaction"] else "activity"
        body = retire_body(
            CHAIN,
            self.next,
            table=table,
            partition=partition,
            streams=streams,
            upper_bound=upper_bound,
            retention=None,
            segments=self.sealed(partition) if segments is None else segments,
        )
        return self.add("retire", body, sealed_at)


def check(
    chain: Chain,
    transactions: list[dict[str, Any]],
    activities: list[dict[str, Any]],
    *,
    horizon: int = 10_000,
    detached: Iterable[str] = (),
    **options: Any,
) -> _verify.VerificationReport:
    verifier = Verifier(chain.blocks, horizon=horizon, **options)
    verifier.check_partition(Partition("transaction", TX_PART), transactions)
    verifier.check_partition(Partition("activity", ACT_PART), activities)
    verifier.schema(detached)
    return verifier.report()


def failures(report: _verify.VerificationReport) -> set[Any]:
    return {finding.kind for finding in report.failures}


@pytest.fixture
def sealed() -> tuple[Chain, list[dict[str, Any]], list[dict[str, Any]]]:
    transactions = [transaction_row(1, 200)]
    activities = [activity_row(1, 200), activity_row(2, 200)]
    chain = Chain()
    chain.seal(300, transactions, activities)
    return chain, transactions, activities


Sealed = tuple[Chain, list[dict[str, Any]], list[dict[str, Any]]]


# -- the core stays pure ----------------------------------------------------------


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_the_core_imports_no_sqlalchemy() -> None:
    package = Path(_verify.__file__).parent
    seen: set[str] = set()
    todo = ["audit_trail.integrity._verify"]
    while todo:
        module = todo.pop()
        if module in seen:
            continue
        seen.add(module)
        imports = _imports(package / f"{module.rpartition('.')[2]}.py")
        assert not any(name.split(".")[0] == "sqlalchemy" for name in imports), module
        todo.extend(name for name in imports if name.startswith("audit_trail."))
    assert seen == {
        "audit_trail.integrity._verify",
        "audit_trail.integrity._block",
        "audit_trail.integrity._commit",
        "audit_trail.integrity._canonical",
        "audit_trail.integrity._codec",
        "audit_trail.integrity._merkle",
        "audit_trail.integrity._checkpoint",
        "audit_trail.integrity._note",
        "audit_trail.integrity._sign",
    }


def test_constants_match_the_library() -> None:
    assert _verify.ERASED_VALUE == ERASED
    assert AuditSystem.SCRUBBED.value == _verify.SCRUBBED_VERB


def test_the_kinds_are_the_closed_sets() -> None:
    assert [kind.value for kind in FailureKind] == [
        "PREV_MISMATCH",
        "HASH_MISMATCH",
        "ROOT_MISMATCH",
        "ROW_COUNT_MISMATCH",
        "COMMITMENT_MISMATCH",
        "COMMITMENT_MISSING",
        "ERASURE_UNEXPLAINED",
        "SCRUB_COUNT_MISMATCH",
        "SEGMENT_MISSING",
        "RETIRED_EARLY",
        "DETACHED_PARTITION",
        "TRUNCATED",
        "CHAIN_MISMATCH",
        "BAD_SIGNATURE",
        "UNKNOWN_KEY",
        "MALFORMED_BLOCK",
        "XID_REWIND",
    ]
    assert [kind.value for kind in NoteKind] == [
        "ERASED",
        "ERASED_RECEIPT_RETIRED",
        "RETIRED",
        "PRE_GENESIS",
        "UNSEALED_TAIL",
        "UNANCHORED_TAIL",
        "FORKED",
        "FORKED_UNSIGNED",
        "ACKNOWLEDGED",
    ]


# -- verdicts -------------------------------------------------------------------


def test_rows_as_sealed_are_valid(sealed: Sealed) -> None:
    report = check(*sealed)
    assert report.status is Status.VALID
    assert report.verified_to == 2


def test_every_failure_is_collected(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    activities[0]["verb"] = "changed"
    activities[1]["data"]["payload"] = {"n": 2}
    del transactions[0]["seal_salts"]["actor"]
    report = check(chain, transactions, activities, detached=["audit_x_p2026_01"])
    assert failures(report) == {
        FailureKind.ROOT_MISMATCH,
        FailureKind.COMMITMENT_MISMATCH,
        FailureKind.ERASURE_UNEXPLAINED,
        FailureKind.DETACHED_PARTITION,
    }


def test_a_pending_detach_is_detached_partition(sealed: Sealed) -> None:
    chain, _transactions, activities = sealed
    verifier = Verifier(chain.blocks, horizon=10_000)
    verifier.check_partition(Partition("activity", ACT_PART), activities)
    # The transaction partition is pending detach: not read, reported once.
    verifier.schema([TX_PART])
    report = verifier.report()
    assert failures(report) == {FailureKind.DETACHED_PARTITION}
    assert [f.partition for f in report.failures] == [TX_PART]


def test_a_horizon_below_the_chain_is_xid_rewind(sealed: Sealed) -> None:
    assert failures(check(*sealed, horizon=299)) == {FailureKind.XID_REWIND}
    assert check(*sealed, horizon=300).status is Status.VALID


def test_a_row_from_the_future_is_xid_rewind(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    future = activity_row(9, 10**15)
    report = check(chain, transactions, [*activities, future])
    assert failures(report) == {FailureKind.XID_REWIND}
    (finding,) = report.failures
    assert (finding.table, finding.id, finding.xid) == ("activity", 9, 10**15)


def test_a_row_below_a_later_xmax_is_in_the_tail(sealed: Sealed) -> None:
    # A transaction that started after the horizon was read, seen by a
    # later chunk whose snapshot reaches it.
    chain, transactions, activities = sealed
    verifier = Verifier(chain.blocks, horizon=10_000)
    verifier.observe_xmax(10_005)
    verifier.check_partition(Partition("transaction", TX_PART), transactions)
    late = activity_row(9, 10_004)
    verifier.check_partition(Partition("activity", ACT_PART), [*activities, late])
    verifier.schema([])
    report = verifier.report()
    assert report.failures == []
    assert {(f.kind, f.count) for f in report.notes} == {(NoteKind.UNSEALED_TAIL, 1)}


def test_a_partition_read_that_fails_leaves_nothing_behind(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    broken = [*activities, transaction_row(9, 10**15)]
    scrub(activities[0], 250)
    verifier = Verifier(chain.blocks, horizon=10_000)

    def rows() -> Iterable[dict[str, Any]]:
        yield from broken[:-1]
        raise LookupError("the partition was dropped")

    with pytest.raises(LookupError):
        verifier.check_partition(Partition("activity", ACT_PART), rows())
    # The partition is read again as if the first attempt never happened.
    verifier.check_partition(Partition("transaction", TX_PART), transactions)
    verifier.schema([])
    report = verifier.report()
    assert failures(report) == {FailureKind.SEGMENT_MISSING}
    assert report.notes == []


def test_the_horizon_can_be_given_after_the_chain(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    verifier = Verifier(chain.blocks)
    verifier.set_horizon(10_000, 10_000)
    verifier.check_partition(Partition("transaction", TX_PART), transactions)
    verifier.check_partition(Partition("activity", ACT_PART), activities)
    verifier.schema([])
    assert verifier.report().status is Status.VALID
    with pytest.raises(ValueError, match="horizon"):
        Verifier(chain.blocks).report()


def test_a_seal_that_does_not_start_where_the_last_ended_is_malformed(
    sealed: Sealed,
) -> None:
    chain, transactions, activities = sealed
    chain.add("seal", seal_body(CHAIN, chain.next, 301, 400, []))
    report = check(chain, transactions, activities)
    assert failures(report) == {FailureKind.MALFORMED_BLOCK}


def test_a_fork_that_names_a_seal_block_as_its_checkpoint_is_malformed(
    sealed: Sealed,
) -> None:
    chain, transactions, activities = sealed
    body = fork_body(
        CHAIN,
        chain.next,
        incarnation=2,
        reason="restore",
        prior_seq=2,
        prior_hash=chain.blocks[-1].block_hash,
        xid_at_fork=300,
        id_floor=None,
        id_count=None,
    )
    chain.add("fork", body)
    assert failures(check(chain, transactions, activities)) == {
        FailureKind.MALFORMED_BLOCK
    }


def test_checkpoint_blocks_are_accepted(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    chain.add("checkpoint", checkpoint_body(CHAIN, chain.next, 300))
    assert check(chain, transactions, activities).status is Status.VALID


def test_a_checkpoint_block_without_xid_to_is_malformed(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    body = parse_body(genesis_body(CHAIN, 1))
    body.update(kind="checkpoint", seq=chain.next)
    chain.add("checkpoint", canonical(body))
    assert failures(check(chain, transactions, activities)) == {
        FailureKind.MALFORMED_BLOCK
    }


def test_no_genesis_block_raises() -> None:
    with pytest.raises(ValueError, match="genesis"):
        Verifier([], horizon=1)


def test_rows_are_scoped_to_their_incarnation(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    early = transaction_row(9, 50)
    late = activity_row(9, 300)
    report = check(chain, [early, *transactions], [*activities, late])
    assert report.failures == []
    assert {(f.kind, f.table, f.count) for f in report.notes} == {
        (NoteKind.PRE_GENESIS, "transaction", 1),
        (NoteKind.UNSEALED_TAIL, "activity", 1),
    }


def test_an_incarnation_judges_only_its_id_window() -> None:
    incarnation = Incarnation(
        2,
        enforce_from=10,
        seals=[Seal(5, 10, 20), Seal(6, 20, 30)],
        id_floor={"transaction": 100},
        id_ceiling={"transaction": 200},
    )
    assert not incarnation.holds("transaction", 100)
    assert incarnation.holds("transaction", 101)
    assert incarnation.holds("transaction", 200)
    assert not incarnation.holds("transaction", 201)
    # A stream the closing fork did not name had no row then: none is held.
    assert not incarnation.holds("activity.20", 1)
    assert Incarnation(1, 10, id_floor={"transaction": 100}).holds("activity.20", 1)
    assert incarnation.is_pre_genesis(9)
    assert incarnation.seal_of(19) == Seal(5, 10, 20)
    assert incarnation.seal_of(20) == Seal(6, 20, 30)
    assert incarnation.seal_of(30) is None
    assert incarnation.is_unsealed(30)


# -- erasures and scrub counts ----------------------------------------------------


def scrub(row: dict[str, Any], xid: int) -> None:
    """What ``scrub`` does to an activity row."""
    data = row["data"]
    data["payload"] = dict.fromkeys(data["payload"], ERASED)
    row["object_label"] = None
    for group in ("label", "changes", "payload"):
        row["seal_salts"].pop(group, None)
    row["seal_erased"] = {
        **(row["seal_erased"] or {}),
        "label": str(xid),
        "changes": str(xid),
        "payload": str(xid),
    }


def record(row_id: int, xid: int, **payload: Any) -> dict[str, Any]:
    row = activity_row(row_id, xid, payload=payload)
    row["verb"] = "audit.scrubbed"
    row["object_label"] = None
    row.update(seal_columns(activity_groups(None, row["data"])))
    return row


def test_scrubbed_rows_are_noted_and_counted() -> None:
    activities = [activity_row(1, 200), activity_row(2, 200)]
    for row in activities:
        scrub(row, 250)
    scrubbed = record(3, 250, operation="scrub", activity_rows=2)
    chain = Chain()
    chain.seal(300, [], [*activities, scrubbed])
    report = check(chain, [], [*activities, scrubbed])
    assert report.failures == []
    assert [(f.kind, f.count) for f in report.notes] == [(NoteKind.ERASED, 2)]


def test_stamped_counts_win_over_row_counts() -> None:
    activities = [activity_row(1, 200)]
    scrub(activities[0], 250)
    scrubbed = record(
        3, 250, operation="scrub", activity_rows=5, stamped_activity_rows=1
    )
    chain = Chain()
    chain.seal(300, [], [*activities, scrubbed])
    assert check(chain, [], [*activities, scrubbed]).failures == []


def test_a_count_off_by_one_is_scrub_count_mismatch() -> None:
    activities = [activity_row(1, 200)]
    scrub(activities[0], 250)
    scrubbed = record(3, 250, operation="scrub", activity_rows=2)
    chain = Chain()
    chain.seal(300, [], [*activities, scrubbed])
    report = check(chain, [], [*activities, scrubbed])
    assert failures(report) == {FailureKind.SCRUB_COUNT_MISMATCH}


def test_scrubs_after_the_horizon_are_not_counted_yet() -> None:
    activities = [activity_row(1, 200)]
    scrub(activities[0], 250)
    chain = Chain()
    chain.seal(240, [], activities)
    # The scrub at 250 may still be running when the rows are read: noted,
    # and counted by a later run.
    report = check(chain, [], activities, horizon=250, xmax=260)
    assert report.failures == []
    tail = [f for f in report.notes if f.kind is NoteKind.UNSEALED_TAIL]
    assert sorted((f.xid, f.group, f.count) for f in tail) == [
        (250, "changes", 1),
        (250, "label", 1),
        (250, "payload", 1),
    ]


def test_a_stamp_from_the_future_is_scrub_count_mismatch() -> None:
    activities = [activity_row(1, 200)]
    # No transaction with this xid has started: the stamp points nowhere.
    scrub(activities[0], 10**15)
    chain = Chain()
    chain.seal(300, [], activities)
    report = check(chain, [], activities)
    assert failures(report) == {FailureKind.SCRUB_COUNT_MISMATCH}
    assert {(f.id, f.group) for f in report.failures} == {
        (1, "label"),
        (1, "changes"),
        (1, "payload"),
    }
    # Just below the snapshot's xmax it is a scrub still running.
    activities = [activity_row(1, 200)]
    scrub(activities[0], 10**15)
    chain = Chain()
    chain.seal(300, [], activities)
    report = check(chain, [], activities, horizon=10**15, xmax=10**15 + 1)
    assert report.failures == []


def test_a_stamp_older_than_its_row_is_scrub_count_mismatch() -> None:
    activities = [activity_row(1, 200)]
    scrub(activities[0], 150)
    scrubbed = record(3, 150, operation="scrub", activity_rows=1)
    chain = Chain()
    chain.seal(300, [], [*activities, scrubbed])
    report = check(chain, [], [*activities, scrubbed])
    assert failures(report) == {FailureKind.SCRUB_COUNT_MISMATCH}


def test_a_record_before_genesis_is_no_receipt() -> None:
    # A record written before the chain began explains no sealed erasure.
    activities = [activity_row(1, 200)]
    scrub(activities[0], 50)
    scrubbed = record(900, 50, operation="scrub", activity_rows=1)
    chain = Chain()
    chain.seal(300, [], activities)
    report = check(chain, [], [*activities, scrubbed])
    assert failures(report) == {FailureKind.SCRUB_COUNT_MISMATCH}
    assert {f.id for f in report.failures} == {1}


def test_a_scrub_before_genesis_is_out_of_scope() -> None:
    old = activity_row(1, 50)
    scrub(old, 60)
    scrubbed = record(2, 60, operation="scrub", activity_rows=1)
    chain = Chain()
    chain.seal(300, [], [])
    report = check(chain, [], [old, scrubbed])
    assert report.failures == []
    assert {f.kind for f in report.notes} == {NoteKind.PRE_GENESIS}


def test_a_scrub_after_genesis_counts_rows_from_before_it() -> None:
    old = activity_row(1, 50)
    scrub(old, 250)
    scrubbed = record(2, 250, operation="scrub", activity_rows=1)
    chain = Chain()
    chain.seal(300, [], [scrubbed])
    assert check(chain, [], [old, scrubbed]).failures == []
    # Without the record, the stamp on the old row is unexplained.
    assert failures(check(chain, [], [old])) == {
        FailureKind.ROW_COUNT_MISMATCH,
        FailureKind.SCRUB_COUNT_MISMATCH,
    }


def test_a_retired_receipt_is_a_note() -> None:
    activities = [activity_row(1, 200)]
    scrub(activities[0], 250)
    scrubbed = record(3, 250, operation="scrub", activity_rows=1)
    chain = Chain()
    chain.seal(300, [], [*activities])
    # The record sits in a partition of its own, retired since.
    builder = SegmentBuilder()
    builder.add(
        "activity.40", "audit_activity_40_p2026_01", activity_leaf_row(scrubbed)
    )
    chain.blocks.pop()
    chain.sealed_to = 100
    segments = [
        *_segments_of(activities),
        *builder.segments(),
    ]
    chain.add("seal", seal_body(CHAIN, chain.next, 100, 300, segments))
    chain.sealed_to = 300
    chain.retire(
        "audit_activity_40_p2026_01",
        ["activity.40"],
        datetime(2026, 2, 1, tzinfo=UTC),
    )
    report = check(chain, [], activities, system_severity=40)
    assert report.failures == []
    assert {f.kind for f in report.notes} == {
        NoteKind.ERASED,
        NoteKind.ERASED_RECEIPT_RETIRED,
        NoteKind.RETIRED,
    }
    # The record's severity is 40: a retired partition of another stream,
    # or no known severity, explains nothing.
    for severity in (20, None):
        report = check(chain, [], activities, system_severity=severity)
        assert failures(report) == {FailureKind.SCRUB_COUNT_MISMATCH}


def test_a_retired_receipt_must_be_in_the_records_stream() -> None:
    activities = [activity_row(1, 200)]
    scrub(activities[0], 250)
    other = activity_row(3, 250)
    other["severity"] = 30
    chain = Chain()
    builder = SegmentBuilder()
    builder.add("activity.30", "audit_activity_30_p2026_01", activity_leaf_row(other))
    segments = [*_segments_of(activities), *builder.segments()]
    chain.add("seal", seal_body(CHAIN, chain.next, 100, 300, segments))
    chain.sealed_to = 300
    chain.retire(
        "audit_activity_30_p2026_01",
        ["activity.30"],
        datetime(2026, 2, 1, tzinfo=UTC),
    )
    # A retired partition of severity 30 sealed with the scrub, while the
    # records are written at 40: the missing record is not explained.
    report = check(chain, [], activities, system_severity=40)
    assert failures(report) == {FailureKind.SCRUB_COUNT_MISMATCH}
    assert NoteKind.ERASED_RECEIPT_RETIRED not in report.kinds()


def test_a_retired_receipt_must_be_covered_by_its_retire_block() -> None:
    # The same record partition, retired before the block that sealed the
    # record: the retire block covers none of its segments, so it attests
    # nothing about the record, and the record's segment is missing.
    activities = [activity_row(1, 200)]
    scrub(activities[0], 250)
    scrubbed = record(3, 250, operation="scrub", activity_rows=1)
    chain = Chain()
    retired = "audit_activity_40_p2026_01"
    chain.retire(retired, ["activity.40"], datetime(2026, 2, 1, tzinfo=UTC))
    builder = SegmentBuilder()
    builder.add("activity.40", retired, activity_leaf_row(scrubbed))
    segments = [*_segments_of(activities), *builder.segments()]
    chain.add("seal", seal_body(CHAIN, chain.next, 100, 300, segments))
    chain.sealed_to = 300
    report = check(chain, [], activities, system_severity=40)
    assert failures(report) == {
        FailureKind.SCRUB_COUNT_MISMATCH,
        FailureKind.SEGMENT_MISSING,
    }
    assert NoteKind.ERASED_RECEIPT_RETIRED not in report.kinds()


def _segments_of(activities: list[dict[str, Any]]) -> list[Any]:
    builder = SegmentBuilder()
    for row in activities:
        builder.add(activity_stream(row["severity"]), ACT_PART, activity_leaf_row(row))
    return builder.segments()


ERASED_FORMS: list[tuple[str, dict[str, Any], bool]] = [
    ("changes", {"changes": {"a": [ERASED, None]}}, True),
    ("changes", {"changes": {"a": {"added": [ERASED], "removed": []}}}, True),
    ("changes", {"changes": {"a": {"added": ERASED}}}, True),
    ("changes", {"changes": {"a": ["x", None]}}, False),
    ("changes", {"changes": ERASED}, True),
    ("changes", {"changes": [1]}, False),
    ("changes", {}, True),
    ("payload", {"payload": {"a": ERASED, "b": None}}, True),
    ("payload", {"payload": {"a": {"nested": ERASED}}}, False),
    ("actor", {"context": {"actor_type": "user"}}, True),
    ("actor", {"context": {"remote_addr": None}}, False),
]


@pytest.mark.parametrize(("group", "data", "expected"), ERASED_FORMS)
def test_the_erased_form_mirrors_the_scrub(
    group: str, data: dict[str, Any], expected: bool
) -> None:
    assert is_erased("activity", group, {"data": data}) is expected


def test_the_erased_form_of_label_and_transaction_actor() -> None:
    assert is_erased("activity", "label", {"data": {}, "object_label": None})
    assert not is_erased("activity", "label", {"data": {}, "object_label": "x"})
    cleared = dict.fromkeys(("actor_label", "remote_addr", "user_agent", "meta"))
    assert is_erased("transaction", "actor", cleared)
    assert not is_erased("transaction", "actor", {**cleared, "meta": {}})


def test_a_null_changes_scrubbed_without_commitment_is_valid() -> None:
    row = activity_row(1, 200, changes=None)
    assert "changes" not in row["seal_commitments"]
    scrub(row, 250)
    row["data"]["changes"] = ERASED
    scrubbed = record(3, 250, operation="scrub", activity_rows=1)
    chain = Chain()
    chain.seal(300, [], [row, scrubbed])
    assert check(chain, [], [row, scrubbed]).failures == []


# -- acks, retention and findings -----------------------------------------------


def test_an_ack_turns_failures_into_notes() -> None:
    # Written without Integrity: no commitments, as sealed.
    transactions = [transaction_row(1, 200)]
    activities = [activity_row(1, 200)]
    for row in (*transactions, *activities):
        row.update(seal_commitments=None, seal_salts=None)
    chain = Chain()
    chain.seal(300, transactions, activities)
    ack = chain.add(
        "ack",
        ack_body(
            CHAIN,
            chain.next,
            failure="COMMITMENT_MISSING",
            scope={"table": "activity", "xid_from": 200, "xid_to": 201},
            waives=[{"table": "activity", "id": 1}],
            reason="deploy",
        ),
    )
    report = check(chain, transactions, activities)
    # Only the activity row is in the scope.
    assert [(f.kind, f.table) for f in report.failures] == [
        (FailureKind.COMMITMENT_MISSING, "transaction")
    ]
    assert [(f.kind, f.waived, f.ack, f.id) for f in report.notes] == [
        (NoteKind.ACKNOWLEDGED, FailureKind.COMMITMENT_MISSING, ack, 1)
    ]


def test_an_ack_of_a_chain_failure_is_malformed(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    chain.add(
        "ack",
        ack_body(
            CHAIN,
            chain.next,
            failure="HASH_MISMATCH",
            scope={"seq": 2},
            waives=[{"seq": 2}],
            reason="no",
        ),
    )
    assert failures(check(chain, transactions, activities)) == {
        FailureKind.MALFORMED_BLOCK
    }


def test_ack_scope_ranges_are_half_open() -> None:
    ack = Ack(9, FailureKind.COMMITMENT_MISSING, {"xid_from": 10, "xid_to": 20})
    found = Finding(FailureKind.COMMITMENT_MISSING, "", xid=10)
    assert ack.in_scope(found)
    assert not ack.in_scope(dataclasses.replace(found, xid=20))
    assert not ack.in_scope(dataclasses.replace(found, xid=None))
    ack = dataclasses.replace(ack, waives=frozenset({_verify.pin_key(found)}))
    assert ack.covers(found)
    assert not ack.covers(dataclasses.replace(found, xid=20))
    assert not ack.covers(dataclasses.replace(found, xid=None))
    assert not ack.covers(dataclasses.replace(found, kind=FailureKind.ROOT_MISMATCH))


@pytest.mark.parametrize(
    "scope",
    [{}, {"salt": "x"}, {"xid": "1"}, {"table": 1}, {"table": "activity"}],
)
def test_check_scope_refuses_bad_scopes(scope: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="scope"):
        check_scope(scope)


def broken_segment(sealed: Sealed) -> None:
    """Change a sealed column of the first activity row."""
    _chain, _transactions, activities = sealed
    activities[0]["verb"] = "changed"


def ack_of(chain: Chain, failure: str, scope: dict[str, Any], *found: Any) -> int:
    pins = [_verify.pin(f) for f in found if f.kind == failure]
    return chain.add(
        "ack",
        ack_body(
            CHAIN, chain.next, failure=failure, scope=scope, waives=pins, reason="x"
        ),
    )


def test_a_segment_ack_pins_the_root_and_count(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    broken_segment(sealed)
    (found,) = check(chain, transactions, activities).failures
    assert found.kind is FailureKind.ROOT_MISMATCH
    assert found.root is not None
    assert found.count == 2
    ack = ack_of(chain, "ROOT_MISMATCH", {"seq": 2}, found)
    report = check(chain, transactions, activities)
    assert report.failures == []
    assert [(f.waived, f.ack) for f in report.notes] == [
        (FailureKind.ROOT_MISMATCH, ack)
    ]
    # Another change to the same segment is not the one acknowledged.
    activities[1]["verb"] = "changed too"
    report = check(chain, transactions, activities)
    assert failures(report) == {FailureKind.ROOT_MISMATCH}
    # Nor is a row deleted from it, though its count was acknowledged.
    activities.pop()
    assert failures(check(chain, transactions, activities)) == {
        FailureKind.ROW_COUNT_MISMATCH
    }


def test_a_count_ack_pins_the_rows_left(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    activities.pop()
    (found,) = check(chain, transactions, activities).failures
    assert found.kind is FailureKind.ROW_COUNT_MISMATCH
    ack_of(chain, "ROW_COUNT_MISMATCH", {"seq": 2, "table": "activity"}, found)
    assert check(chain, transactions, activities).failures == []
    # The one row left changed: same count, another root.
    activities[0]["verb"] = "changed"
    assert failures(check(chain, transactions, activities)) == {
        FailureKind.ROW_COUNT_MISMATCH
    }


def test_a_row_ack_pins_the_row_ids() -> None:
    # Written without Integrity, and sealed so.
    activities = [activity_row(1, 200), activity_row(2, 200)]
    for row in activities:
        row.update(seal_commitments=None, seal_salts=None)
    chain = Chain()
    chain.seal(300, [], activities)
    first, second = check(chain, [], activities).failures
    # The ack saw only the first row fail.
    ack_of(chain, "COMMITMENT_MISSING", {"seq": 2}, first)
    report = check(chain, [], activities)
    assert [(f.kind, f.id) for f in report.failures] == [
        (FailureKind.COMMITMENT_MISSING, second.id)
    ]
    assert [f.id for f in report.notes] == [first.id]


@pytest.mark.parametrize(
    "waives",
    [None, [], [{"id": "1"}], [{"salt": "x"}], ["x"], [{"count": True}]],
)
def test_an_ack_without_valid_pins_is_malformed(sealed: Sealed, waives: Any) -> None:
    chain, transactions, activities = sealed
    body = parse_body(
        ack_body(
            CHAIN,
            chain.next,
            failure="ROOT_MISMATCH",
            scope={"seq": 2},
            waives=[],
            reason="x",
        )
    )
    if waives is None:
        del body["waives"]
    else:
        body["waives"] = waives
    chain.add("ack", canonical(body))
    assert failures(check(chain, transactions, activities)) == {
        FailureKind.MALFORMED_BLOCK
    }


def test_retention_by_stream() -> None:
    day = timedelta(days=1)
    assert stream_retention({20: day, 40: None}) == {
        "activity.20": day,
        "activity.40": None,
        "transaction": day,
    }
    assert stream_retention({20: day}, 2 * day)["transaction"] == day
    assert stream_retention({40: None}, day)["transaction"] == day


def test_retired_early_needs_the_retention(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    chain.retire(TX_PART, ["transaction"], NOW - timedelta(days=10))
    long = {"transaction": timedelta(days=30)}
    short = {"transaction": timedelta(days=5)}
    assert check(chain, transactions, activities).status is Status.VALID
    assert failures(check(chain, transactions, activities, retention=long)) == {
        FailureKind.RETIRED_EARLY
    }
    assert check(chain, transactions, activities, retention=short).failures == []


def test_findings_show_no_salt_or_value(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    activities[1]["data"]["payload"] = {"n": "secret-value"}
    report = check(chain, transactions, activities)
    shown = repr(report)
    assert "secret-value" not in shown
    for row in (*transactions, *activities):
        for secret in (*row["seal_salts"].values(), *row["seal_commitments"].values()):
            assert secret not in shown


# -- retire blocks are bound to the chain ------------------------------------


def check_without_transactions(
    chain: Chain, activities: list[dict[str, Any]], **options: Any
) -> _verify.VerificationReport:
    """Verify with the transaction partition gone."""
    verifier = Verifier(chain.blocks, horizon=10_000, **options)
    verifier.check_partition(Partition("activity", ACT_PART), activities)
    verifier.schema([])
    return verifier.report()


def test_a_retired_partition_still_present_is_checked(sealed: Sealed) -> None:
    # A crash after the retire block and before the drop.
    chain, transactions, activities = sealed
    chain.retire(TX_PART, ["transaction"], datetime(2026, 1, 1, tzinfo=UTC))
    report = check(chain, transactions, activities)
    assert report.status is Status.VALID
    transactions[0]["actor_type"] = "forged"
    assert failures(check(chain, transactions, activities)) == {
        FailureKind.ROOT_MISMATCH
    }


def test_a_retired_partition_that_is_gone_is_a_note(sealed: Sealed) -> None:
    chain, _transactions, activities = sealed
    seq = chain.retire(TX_PART, ["transaction"], datetime(2026, 1, 1, tzinfo=UTC))
    report = check_without_transactions(chain, activities)
    assert report.failures == []
    assert [(f.kind, f.seq, f.partition, f.count) for f in report.notes] == [
        (NoteKind.RETIRED, seq, TX_PART, 1)
    ]


def test_a_partition_gone_without_a_retire_block_is_segment_missing(
    sealed: Sealed,
) -> None:
    chain, _transactions, activities = sealed
    report = check_without_transactions(chain, activities)
    assert failures(report) == {FailureKind.SEGMENT_MISSING}
    assert [f.partition for f in report.failures] == [TX_PART]


def test_an_empty_partition_retires_with_no_segments() -> None:
    chain = Chain()
    seq = chain.retire(
        "audit_transaction_p2026_01", ["transaction"], datetime(2026, 2, 1, tzinfo=UTC)
    )
    body = parse_body(chain.blocks[-1].body)
    assert (body["seals"], body["segments"], body["rows"]) == (None, 0, 0)
    report = check(chain, [], [])
    assert report.status is Status.VALID
    assert report.verified_to == seq


@pytest.mark.parametrize(
    "forge",
    [
        pytest.param({"rows": 2}, id="rows"),
        pytest.param({"segments": 0}, id="segments"),
        pytest.param({"seals": None}, id="seals"),
        pytest.param({"seals": {"first": 2, "last": 3}}, id="seal-range"),
        pytest.param(
            {"segments_digest": base64.b64encode(bytes(32)).decode()}, id="digest"
        ),
        pytest.param({"partition": ACT_PART}, id="other-partition"),
        pytest.param({"streams": ["activity.20"]}, id="other-stream"),
        pytest.param({"table": "activity"}, id="other-table"),
        pytest.param({"streams": []}, id="no-stream"),
    ],
)
def test_a_retire_block_that_does_not_match_the_chain_retires_nothing(
    sealed: Sealed, forge: dict[str, Any]
) -> None:
    chain, _transactions, activities = sealed
    body = parse_body(
        retire_body(
            CHAIN,
            chain.next,
            table="transaction",
            partition=TX_PART,
            streams=["transaction"],
            upper_bound=datetime(2026, 1, 1, tzinfo=UTC),
            retention=None,
            segments=chain.sealed(TX_PART),
        )
    )
    seq = chain.add("retire", canonical({**body, **forge}))
    report = check_without_transactions(chain, activities)
    assert [(f.kind, f.seq) for f in report.failures if f.seq == seq] == [
        (FailureKind.MALFORMED_BLOCK, seq)
    ]
    # The partition it should have retired is gone without a retire block.
    assert [(f.kind, f.partition) for f in report.failures if f.seq != seq] == [
        (FailureKind.SEGMENT_MISSING, TX_PART)
    ]
    assert NoteKind.RETIRED not in report.kinds()


def test_a_segment_sealed_after_the_retire_block_is_not_covered() -> None:
    transactions = [transaction_row(1, 200)]
    chain = Chain()
    chain.seal(300, transactions)
    chain.retire(TX_PART, ["transaction"], datetime(2026, 1, 1, tzinfo=UTC))
    late = transaction_row(2, 400)
    after = chain.seal(500, [late])
    # Present, the partition is checked as usual.
    assert check(chain, [*transactions, late], []).status is Status.VALID
    # Gone, the segment sealed after its retire block is missing.
    report = check_without_transactions(chain, [])
    assert [(f.kind, f.seq, f.count) for f in report.failures] == [
        (FailureKind.SEGMENT_MISSING, after, 1)
    ]
    assert [f.kind for f in report.notes] == [NoteKind.RETIRED]


def test_a_partition_retired_twice_is_malformed(sealed: Sealed) -> None:
    chain, transactions, activities = sealed
    chain.retire(TX_PART, ["transaction"], datetime(2026, 1, 1, tzinfo=UTC))
    again = chain.retire(TX_PART, ["transaction"], datetime(2026, 1, 1, tzinfo=UTC))
    report = check(chain, transactions, activities)
    assert [(f.kind, f.seq) for f in report.failures] == [
        (FailureKind.MALFORMED_BLOCK, again)
    ]


def test_a_partition_of_several_severities_keeps_the_longest() -> None:
    chain = Chain()
    upper = NOW - timedelta(days=10)
    chain.retire("audit_activity_x_p2026_01", ["activity.10", "activity.20"], upper)
    short, long = timedelta(days=5), timedelta(days=30)
    both_short = {"activity.10": short, "activity.20": short}
    one_long = {"activity.10": short, "activity.20": long}
    assert check(chain, [], [], retention=both_short).failures == []
    report = check(chain, [], [], retention=one_long)
    assert [(f.kind, f.stream) for f in report.failures] == [
        (FailureKind.RETIRED_EARLY, "activity.20")
    ]
