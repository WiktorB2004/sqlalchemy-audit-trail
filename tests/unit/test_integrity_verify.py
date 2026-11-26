"""The pure verifier core, fed with rows and blocks built in memory."""

from __future__ import annotations

import ast
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
    SegmentBuilder,
    ack_body,
    activity_leaf_row,
    activity_stream,
    block_hash,
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


def test_a_seal_that_does_not_start_where_the_last_ended_is_malformed(
    sealed: Sealed,
) -> None:
    chain, transactions, activities = sealed
    chain.add("seal", seal_body(CHAIN, chain.next, 301, 400, []))
    report = check(chain, transactions, activities)
    assert failures(report) == {FailureKind.MALFORMED_BLOCK}


def test_a_fork_block_is_not_supported_yet(sealed: Sealed) -> None:
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
    body = parse_body(genesis_body(CHAIN, 1))
    body.update(kind="checkpoint", seq=chain.next)
    chain.add("checkpoint", canonical(body))
    assert check(chain, transactions, activities).status is Status.VALID


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
    assert incarnation.holds("activity.20", 1)
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
    # The scrub at 250 may still be running when the rows are read.
    report = check(chain, [], activities, horizon=250)
    assert report.failures == []


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
    chain.add(
        "retire",
        retire_body(
            CHAIN,
            chain.next,
            stream="activity.40",
            partition="audit_activity_40_p2026_01",
            upper_bound=datetime(2026, 2, 1, tzinfo=UTC),
            retention=None,
            rows=1,
            segments_digest=bytes(32),
        ),
    )
    report = check(chain, [], activities)
    assert report.failures == []
    assert {f.kind for f in report.notes} == {
        NoteKind.ERASED,
        NoteKind.ERASED_RECEIPT_RETIRED,
        NoteKind.RETIRED,
    }


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
            reason="no",
        ),
    )
    assert failures(check(chain, transactions, activities)) == {
        FailureKind.MALFORMED_BLOCK
    }


def test_ack_scope_ranges_are_half_open() -> None:
    ack = Ack(9, FailureKind.COMMITMENT_MISSING, {"xid_from": 10, "xid_to": 20})
    found = Finding(FailureKind.COMMITMENT_MISSING, "", xid=10)
    assert ack.covers(found)
    assert not ack.covers(dataclasses.replace(found, xid=20))
    assert not ack.covers(dataclasses.replace(found, xid=None))
    assert not ack.covers(dataclasses.replace(found, kind=FailureKind.ROOT_MISMATCH))


@pytest.mark.parametrize("scope", [{}, {"salt": "x"}, {"xid": "1"}, {"table": 1}])
def test_check_scope_refuses_bad_scopes(scope: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="scope"):
        check_scope(scope)


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
    chain.add(
        "retire",
        retire_body(
            CHAIN,
            chain.next,
            stream="transaction",
            partition=TX_PART,
            upper_bound=NOW - timedelta(days=10),
            retention=None,
            rows=1,
            segments_digest=bytes(32),
        ),
    )
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
