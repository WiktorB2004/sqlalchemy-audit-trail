"""The verifier core: checks blocks and rows, and reports what it finds.

Private for now. Nothing here touches the database: ``Verifier`` is fed the
blocks of the chain and then the rows of each partition, and returns a
``VerificationReport``. The leaves are rebuilt with the functions the sealer
uses (``_block``, ``_commit``), so the two cannot drift.

What it checks:

- Each block: the ``prev_hash`` link to the stored hash of the block before
  it (``PREV_MISMATCH``), its ``block_hash`` over the stored body
  (``HASH_MISMATCH``), and the body itself (``MALFORMED_BLOCK``): it parses,
  names the block's ``kind``, ``seq`` and chain, and a seal block starts
  where the one before ended.
- Each segment of a seal block, in a partition that is present: the leaves
  rebuilt from the rows, with the row count first (``ROW_COUNT_MISMATCH``)
  and then the root (``ROOT_MISMATCH``). A row in a sealed range whose block
  has no segment for its partition counts against an empty segment.
- Each sealed row: its commitments where a salt is present
  (``COMMITMENT_MISMATCH``, also for a value where there is no commitment),
  ``COMMITMENT_MISSING`` when it has none, and for a group whose salt was
  removed, a stamp and the erased form (``ERASURE_UNEXPLAINED``); erased
  groups are counted in ``ERASED`` notes.
- The ``audit.scrubbed`` records against the stamps that point to them, per
  operation and group (``SCRUB_COUNT_MISMATCH``). A stamp must name a
  transaction after its row's and before the snapshot's ``xmax``; a record
  or stamp from before the genesis block is no receipt. Scrubs at or above
  the horizon may still be running and are noted (``UNSEALED_TAIL``), to be
  counted by a later run.
- The partitions named by segments: present ones are checked, retired ones
  (a ``retire`` block) are accepted with a ``RETIRED`` note, detached or
  pending ones are ``DETACHED_PARTITION`` and absent ones
  ``SEGMENT_MISSING``. Given the retention, a retire block whose partition
  was still inside it is ``RETIRED_EARLY``.
- The horizon of the database against the chain's: ``XID_REWIND`` when it
  is lower, and for a row whose ``xid`` is at or above the ``xmax`` of the
  snapshot that read it (a row from the future).

Rows are judged per *incarnation* of the chain: an ``xid`` below its
``enforce_from`` is ``PRE_GENESIS``, one at or above its sealed horizon is
in the ``UNSEALED_TAIL``, and anything between belongs to one of its seal
blocks. There is one incarnation until forks exist; ``Incarnation`` holds
what a fork will add (an ``id`` window).

``ack`` blocks waive failures of one kind in a scope, each pinned as it was
observed (``pin``); such a failure is reported as an ``ACKNOWLEDGED`` note
naming the ack, and a failure that changed since is reported again. Every failure is
collected, never only the first. Findings name rows by table, ``id``,
``xid`` and partition, never by a value or a salt.
"""

from __future__ import annotations

import bisect
import hmac
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from audit_trail.integrity._block import (
    FORMAT_VERSION,
    TRANSACTION_STREAM,
    ZERO_HASH,
    activity_leaf_row,
    activity_stream,
    block_hash,
    parse_body,
    transaction_leaf_row,
)
from audit_trail.integrity._canonical import CanonicalEncodingError
from audit_trail.integrity._codec import b64, decode_strict, is_int, parse_rfc3339
from audit_trail.integrity._commit import (
    ACTIVITY_GROUPS,
    ACTOR_FIELDS,
    TRANSACTION_GROUPS,
    activity_groups,
    commitment,
    leaf_hash,
    transaction_groups,
)
from audit_trail.integrity._merkle import MerkleTree

ERASED_VALUE = "[erased]"
"""The marker a scrub writes; the same as ``audit_trail.diff.ERASED``."""

SCRUBBED_VERB = "audit.scrubbed"
"""Verb of the record a scrub writes; ``AuditSystem.SCRUBBED``."""

TRANSACTION = "transaction"
"""``table`` of a finding about an ``audit_transaction`` row."""

ACTIVITY = "activity"
"""``table`` of a finding about an ``audit_activity`` row."""

# The groups each scrub operation stamps, by the table whose rows it counts.
_SCRUB_GROUPS = ("label", "changes", "payload")


class FailureKind(StrEnum):
    """What can make a verification fail; a closed set."""

    PREV_MISMATCH = "PREV_MISMATCH"
    HASH_MISMATCH = "HASH_MISMATCH"
    ROOT_MISMATCH = "ROOT_MISMATCH"
    ROW_COUNT_MISMATCH = "ROW_COUNT_MISMATCH"
    COMMITMENT_MISMATCH = "COMMITMENT_MISMATCH"
    COMMITMENT_MISSING = "COMMITMENT_MISSING"
    ERASURE_UNEXPLAINED = "ERASURE_UNEXPLAINED"
    SCRUB_COUNT_MISMATCH = "SCRUB_COUNT_MISMATCH"
    SEGMENT_MISSING = "SEGMENT_MISSING"
    RETIRED_EARLY = "RETIRED_EARLY"
    DETACHED_PARTITION = "DETACHED_PARTITION"
    TRUNCATED = "TRUNCATED"
    CHAIN_MISMATCH = "CHAIN_MISMATCH"
    BAD_SIGNATURE = "BAD_SIGNATURE"
    UNKNOWN_KEY = "UNKNOWN_KEY"
    MALFORMED_BLOCK = "MALFORMED_BLOCK"
    XID_REWIND = "XID_REWIND"


class NoteKind(StrEnum):
    """What a verification notes without failing."""

    ERASED = "ERASED"
    ERASED_RECEIPT_RETIRED = "ERASED_RECEIPT_RETIRED"
    RETIRED = "RETIRED"
    PRE_GENESIS = "PRE_GENESIS"
    UNSEALED_TAIL = "UNSEALED_TAIL"
    UNANCHORED_TAIL = "UNANCHORED_TAIL"
    FORKED = "FORKED"
    ACKNOWLEDGED = "ACKNOWLEDGED"


class Status(StrEnum):
    """Overall result of a verification."""

    VALID = "VALID"
    VALID_WITH_NOTES = "VALID_WITH_NOTES"
    FAILED = "FAILED"


class Anchor(StrEnum):
    """Whether the chain was checked against a trusted checkpoint."""

    ANCHORED = "ANCHORED"
    UNANCHORED = "UNANCHORED"


ACKNOWLEDGEABLE: frozenset[FailureKind] = frozenset(
    {
        FailureKind.ROOT_MISMATCH,
        FailureKind.ROW_COUNT_MISMATCH,
        FailureKind.COMMITMENT_MISMATCH,
        FailureKind.COMMITMENT_MISSING,
        FailureKind.ERASURE_UNEXPLAINED,
        FailureKind.SCRUB_COUNT_MISMATCH,
        FailureKind.SEGMENT_MISSING,
        FailureKind.RETIRED_EARLY,
        FailureKind.DETACHED_PARTITION,
    }
)
"""Failures an ``ack`` block can waive: those about rows and partitions. A
broken chain cannot be waived from inside it."""

SCOPE_KEYS: frozenset[str] = frozenset(
    {
        "table",
        "partition",
        "stream",
        "seq",
        "group",
        "id",
        "xid",
        "xid_from",
        "xid_to",
        "id_from",
        "id_to",
    }
)
"""Keys of an ack's scope. ``table``, ``partition``, ``stream`` and ``group``
are text, the others integers; ``xid_from``/``xid_to`` and
``id_from``/``id_to`` are ``[from, to)`` ranges. A finding matches when it
has every field the scope names, with a matching value."""

_TEXT_SCOPE_KEYS = frozenset({"table", "partition", "stream", "group"})

ROW_KINDS: frozenset[FailureKind] = frozenset(
    {
        FailureKind.COMMITMENT_MISMATCH,
        FailureKind.COMMITMENT_MISSING,
        FailureKind.ERASURE_UNEXPLAINED,
    }
)
"""Failures about one row; an ack pins them by the row's table, ``id`` and
group."""

PIN_FIELDS = ("seq", "table", "partition", "stream", "id", "xid", "group", "count")
"""Fields of a finding an ack pins, with ``root``; a row kind pins only
``table``, ``id`` and ``group``."""

_TEXT_PIN_FIELDS = frozenset({"table", "partition", "stream", "group", "root"})

PinKey = tuple[tuple[str, object], ...]


@dataclass(frozen=True)
class Finding:
    """One failure or note.

    Attributes:
        kind: What was found.
        detail: A sentence for people; never a stored value or a salt.
        seq: The block it concerns.
        table: ``"transaction"`` or ``"activity"``.
        partition: Name of the partition, without schema.
        stream: The segment's stream.
        id: The row's ``id``.
        xid: The row's ``xid``, or the scrub's for a count.
        group: The erasable group.
        count: How many rows a note or a count covers.
        root: For a root or row count mismatch, the root rebuilt from the
            rows, base64; a hash of leaves, never a value.
        waived: For an ``ACKNOWLEDGED`` note, the failure it stands for.
        ack: For an ``ACKNOWLEDGED`` note, the ``seq`` of the ack block.
    """

    kind: FailureKind | NoteKind
    detail: str
    seq: int | None = None
    table: str | None = None
    partition: str | None = None
    stream: str | None = None
    id: int | None = None
    xid: int | None = None
    group: str | None = None
    count: int | None = None
    root: str | None = None
    waived: FailureKind | None = None
    ack: int | None = None


@dataclass(frozen=True)
class VerificationReport:
    """What ``verify`` found.

    Attributes:
        status: ``FAILED`` with any failure, else ``VALID_WITH_NOTES`` with
            any note, else ``VALID``.
        anchor: ``UNANCHORED`` until checkpoints exist.
        verified_to: ``seq`` of the last block checked.
        failures: Every failure, in the order found.
        notes: Every note, acknowledged failures included.
    """

    status: Status
    anchor: Anchor
    verified_to: int | None
    failures: list[Finding]
    notes: list[Finding]

    def kinds(self) -> set[FailureKind | NoteKind]:
        """The kinds of every failure and note."""
        return {finding.kind for finding in (*self.failures, *self.notes)}


@dataclass(frozen=True)
class StoredBlock:
    """One row of the block table, as stored.

    Attributes:
        seq: Block number.
        kind: The ``kind`` column.
        body: The stored body bytes.
        prev_hash: The stored ``prev_hash``.
        block_hash: The stored ``block_hash``.
        sealed_at: When it was written.
    """

    seq: int
    kind: str
    body: bytes
    prev_hash: bytes
    block_hash: bytes
    sealed_at: datetime


@dataclass(frozen=True)
class ExpectedSegment:
    """A segment as a seal block names it."""

    seq: int
    stream: str
    partition: str
    rows: int
    root: bytes


@dataclass(frozen=True)
class Seal:
    """The ``xid`` range of one seal block."""

    seq: int
    xid_from: int
    xid_to: int


@dataclass
class Incarnation:
    """One run of the chain between forks.

    Attributes:
        number: 1 for the chain started by the genesis block.
        enforce_from: Rows with a lower ``xid`` are out of its scope.
        seals: Its seal blocks, in order; their ranges are contiguous.
        id_floor: Rows of a stream with ``id`` at or below this belong to an
            earlier incarnation; none until forks exist.
        id_ceiling: Rows of a stream with ``id`` above this belong to a later
            incarnation; none until forks exist.
    """

    number: int
    enforce_from: int
    seals: list[Seal] = field(default_factory=list)
    id_floor: dict[str, int] | None = None
    id_ceiling: dict[str, int] | None = None

    @property
    def sealed_to(self) -> int:
        """The ``xid`` the incarnation is sealed up to (exclusive)."""
        return self.seals[-1].xid_to if self.seals else self.enforce_from

    def holds(self, stream: str, row_id: int) -> bool:
        """Whether a row of ``stream`` with this ``id`` is in its window."""
        if self.id_floor is not None and row_id <= self.id_floor.get(stream, -1):
            return False
        ceiling = None if self.id_ceiling is None else self.id_ceiling.get(stream)
        return ceiling is None or row_id <= ceiling

    def is_pre_genesis(self, xid: int) -> bool:
        """Whether a row of this incarnation is below its scope."""
        return xid < self.enforce_from

    def is_unsealed(self, xid: int) -> bool:
        """Whether a row of this incarnation is past its last seal block."""
        return xid >= self.sealed_to

    def seal_of(self, xid: int) -> Seal | None:
        """The seal block whose range holds ``xid``, if any."""
        starts = [seal.xid_from for seal in self.seals]
        index = bisect.bisect_right(starts, xid) - 1
        if index < 0:
            return None
        found = self.seals[index]
        return found if found.xid_from <= xid < found.xid_to else None


@dataclass(frozen=True)
class Ack:
    """An ``ack`` block.

    Attributes:
        seq: Its block number.
        failure: The kind it waives.
        scope: The findings it covers, by ``SCOPE_KEYS``.
        waives: The failures it waives, by ``pin_key``, as they were when it
            was written.
    """

    seq: int
    failure: FailureKind
    scope: Mapping[str, object]
    waives: frozenset[PinKey] = frozenset()

    def covers(self, finding: Finding) -> bool:
        """Whether the ack waives a failure: in its scope, and as pinned."""
        return self.in_scope(finding) and pin_key(finding) in self.waives

    def in_scope(self, finding: Finding) -> bool:
        """Whether a failure is of the ack's kind and in its scope."""
        if finding.kind != self.failure:
            return False
        for key, wanted in self.scope.items():
            if key in ("xid_from", "xid_to", "id_from", "id_to"):
                name = key.partition("_")[0]
                value = getattr(finding, name)
                if not isinstance(value, int) or not isinstance(wanted, int):
                    return False
                if key.endswith("_from") and value < wanted:
                    return False
                if key.endswith("_to") and value >= wanted:
                    return False
            elif getattr(finding, key) != wanted:
                return False
        return True


@dataclass(frozen=True)
class Retired:
    """A ``retire`` block."""

    seq: int
    stream: str
    partition: str
    upper_bound: datetime
    sealed_at: datetime


@dataclass(frozen=True)
class Partition:
    """A partition of an audit table that holds rows.

    Attributes:
        table: ``"transaction"`` or ``"activity"``.
        name: Its name, without schema.
        pending: Whether a detach of it is pending.
    """

    table: str
    name: str
    pending: bool = False


def pin(finding: Finding) -> dict[str, object]:
    """What an ack stores of a failure it waives.

    A row kind pins the row (``table``, ``id``, ``group``); any other kind
    every field it has, with the ``count`` and ``root`` observed. A later
    change to a pinned segment gives another root or count, so it is not
    waived.
    """
    names = ("table", "id", "group") if finding.kind in ROW_KINDS else PIN_FIELDS
    found = {name: getattr(finding, name) for name in (*names, "root")}
    if finding.kind in ROW_KINDS:
        del found["root"]
    return {name: value for name, value in found.items() if value is not None}


def pin_key(finding: Finding) -> PinKey:
    """The pin of a failure, as ``Ack.waives`` holds it."""
    return _pin_key(pin(finding))


def _pin_key(pinned: Mapping[str, object]) -> PinKey:
    return tuple(sorted(pinned.items()))


def check_waives(value: object) -> frozenset[PinKey]:
    """Validate the ``waives`` of an ack block.

    Raises:
        ValueError: Not a non-empty list of pins with known fields.
    """
    if not isinstance(value, list) or not value:
        raise ValueError("an ack waives a non-empty list of failures")
    keys: set[PinKey] = set()
    for item in value:
        if not isinstance(item, Mapping) or not item:
            raise ValueError("an ack pin is a non-empty object")
        for name, field_value in item.items():
            if name not in (*PIN_FIELDS, "root"):
                raise ValueError(f"unknown ack pin field {name!r}")
            if name in _TEXT_PIN_FIELDS:
                if not isinstance(field_value, str):
                    raise ValueError(f"ack pin field {name!r} takes text")
            elif not is_int(field_value):
                raise ValueError(f"ack pin field {name!r} takes an integer")
        keys.add(_pin_key(item))
    return frozenset(keys)


def check_scope(scope: Mapping[str, object]) -> dict[str, object]:
    """Validate the scope of an ack.

    Raises:
        ValueError: The scope is empty or names only ``table``, has a key not
            in ``SCOPE_KEYS``, or a value of the wrong type.
    """
    if not scope:
        raise ValueError("an ack needs a scope; an empty one would waive everything")
    if set(scope) == {"table"}:
        raise ValueError(
            "an ack scope of only table would waive a whole table; narrow it"
        )
    checked: dict[str, object] = {}
    for key, value in scope.items():
        if key not in SCOPE_KEYS:
            raise ValueError(f"unknown ack scope key {key!r}")
        if key in _TEXT_SCOPE_KEYS:
            if not isinstance(value, str):
                raise ValueError(f"ack scope key {key!r} takes text")
        elif not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"ack scope key {key!r} takes an integer")
        checked[key] = value
    return checked


def failure_kind(name: object) -> FailureKind:
    """The failure kind an ack may waive, by name.

    Raises:
        ValueError: Not a failure kind, or one that cannot be waived.
    """
    try:
        if not isinstance(name, str):
            raise ValueError(name)
        kind = FailureKind(name)
    except ValueError:
        raise ValueError(f"{name!r} is not a failure kind") from None
    if kind not in ACKNOWLEDGEABLE:
        raise ValueError(f"{kind} cannot be acknowledged")
    return kind


# -- erasable groups --------------------------------------------------------


def _is_erased_scalar(value: object) -> bool:
    return value is None or value == ERASED_VALUE


def _is_erased_items(value: object) -> bool:
    return isinstance(value, list) and all(_is_erased_scalar(v) for v in value)


def _is_erased_change(value: object) -> bool:
    if isinstance(value, list):
        return _is_erased_items(value)
    if isinstance(value, dict):
        return all(
            _is_erased_items(v) if isinstance(v, list) else _is_erased_scalar(v)
            for v in value.values()
        )
    return _is_erased_scalar(value)


def is_erased(table: str, group: str, row: Mapping[str, Any]) -> bool:
    """Whether a group of a row is in the form a scrub leaves.

    The structural mirror of the scrub ``UPDATE`` statements: keys of
    ``changes`` and ``payload`` kept, a JSON null stays null, array elements
    erased one by one, a ``NULL`` label, the context keys absent, and the
    actor columns ``NULL``. A ``changes`` or ``payload`` key that is absent
    stays absent.
    """
    if table == TRANSACTION:
        return all(row.get(name) is None for name in ACTOR_FIELDS)
    data = row.get("data")
    if not isinstance(data, Mapping):
        return False
    if group == "label":
        return row.get("object_label") is None
    if group == "actor":
        context = data.get("context")
        if context is None:
            return True
        return isinstance(context, Mapping) and not any(
            key in context for key in ACTOR_FIELDS
        )
    if group not in data:
        return True
    value = data[group]
    if group == "changes" and isinstance(value, dict):
        return all(_is_erased_change(v) for v in value.values())
    if group == "payload" and isinstance(value, dict):
        return all(_is_erased_scalar(v) for v in value.values())
    return bool(value == ERASED_VALUE)


def _stamp(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isascii() and value.isdigit():
        return int(value)
    return None


@dataclass(frozen=True)
class GroupCheck:
    """The outcome for one group of a row."""

    group: str
    failure: FailureKind | None
    erased: bool
    detail: str = ""


def check_groups(table: str, row: Mapping[str, Any]) -> list[GroupCheck]:
    """Check the commitments and erasures of a sealed row's groups.

    ``row`` holds the row's columns: ``seal_commitments``, ``seal_salts``,
    ``seal_erased``, and ``object_label`` and ``data`` (activity) or the
    actor columns (transaction). The caller has checked that
    ``seal_commitments`` is not ``NULL``.
    """
    commitments = row.get("seal_commitments") or {}
    salts = row.get("seal_salts") or {}
    stamps = row.get("seal_erased") or {}
    if not all(isinstance(m, Mapping) for m in (commitments, salts, stamps)):
        return [GroupCheck("", FailureKind.COMMITMENT_MISMATCH, False, "not objects")]
    try:
        if table == TRANSACTION:
            groups = transaction_groups(row)
        else:
            data = row.get("data")
            if not isinstance(data, Mapping):
                raise CanonicalEncodingError("data is not an object")
            groups = activity_groups(row.get("object_label"), data)
    except CanonicalEncodingError:
        return [
            GroupCheck("", FailureKind.COMMITMENT_MISMATCH, False, "unreadable values")
        ]
    names = TRANSACTION_GROUPS if table == TRANSACTION else ACTIVITY_GROUPS
    checks: list[GroupCheck] = []
    for group in names:
        checks.append(
            _check_group(table, row, group, groups[group], commitments, salts, stamps)
        )
    extra = (set(commitments) | set(salts) | set(stamps)) - set(names)
    for group in sorted(extra):
        checks.append(
            GroupCheck(group, FailureKind.COMMITMENT_MISMATCH, False, "unknown group")
        )
    return checks


def _check_group(
    table: str,
    row: Mapping[str, Any],
    group: str,
    value: object,
    commitments: Mapping[str, Any],
    salts: Mapping[str, Any],
    stamps: Mapping[str, Any],
) -> GroupCheck:
    committed = group in commitments
    if group in salts:
        salt = decode_strict(salts[group], 16)
        expected = decode_strict(commitments.get(group), 32)
        if salt is None or expected is None or value is None:
            return GroupCheck(
                group, FailureKind.COMMITMENT_MISMATCH, False, "salt without a match"
            )
        try:
            actual = commitment(group, salt, value)
        except (CanonicalEncodingError, ValueError):
            actual = b""
        if not hmac.compare_digest(actual, expected):
            return GroupCheck(
                group, FailureKind.COMMITMENT_MISMATCH, False, "value does not match"
            )
        return GroupCheck(group, None, False)
    if group in stamps:
        if _stamp(stamps[group]) is None or not is_erased(table, group, row):
            return GroupCheck(
                group, FailureKind.ERASURE_UNEXPLAINED, False, "not in erased form"
            )
        return GroupCheck(group, None, committed)
    if committed:
        return GroupCheck(
            group, FailureKind.ERASURE_UNEXPLAINED, False, "salt removed, no stamp"
        )
    if value is not None:
        return GroupCheck(
            group, FailureKind.COMMITMENT_MISMATCH, False, "value without commitment"
        )
    return GroupCheck(group, None, False)


# -- the verifier ------------------------------------------------------------


@dataclass
class _PartitionState:
    partition: Partition
    trees: dict[tuple[int, str], MerkleTree] = field(default_factory=dict)
    closed: set[tuple[int, str]] = field(default_factory=set)
    erased: int = 0
    pre_genesis: int = 0
    unsealed: int = 0


@dataclass(frozen=True)
class _Record:
    xid: int
    id: int
    partition: str
    payload: object


class Verifier:
    """Checks a chain and the rows it seals.

    Private for now. Use: build it with the blocks in ``seq`` order, give
    the horizon (here or with ``set_horizon``, read after the blocks), call
    ``check_partition`` for every partition that holds rows (its rows in
    ``(xid, id)`` order), ``schema`` once with the detached partitions, and
    ``report`` last.

    Args:
        blocks: Every block of the chain, in ``seq`` order; read once, as
            they come.
        horizon: ``pg_snapshot_xmin`` read after the blocks and before any
            row: every transaction below it had finished, so scrubs below it
            are counted, and every seal block read is below it.
        xmax: ``pg_snapshot_xmax`` read with the horizon: no transaction at
            or above it had started. ``None`` for the horizon itself, as on
            an idle database.
        retention: Retention by stream (``transaction`` and
            ``activity.<severity>``), ``None`` for forever. Enables
            ``RETIRED_EARLY``; a stream without a key is not checked.
        system_severity: Severity of the ``audit.scrubbed`` records. A
            retired partition explains a missing record only in that
            stream; ``None`` accepts no retired record.
    """

    def __init__(
        self,
        blocks: Iterable[StoredBlock],
        *,
        horizon: int | None = None,
        xmax: int | None = None,
        retention: Mapping[str, timedelta | None] | None = None,
        system_severity: int | None = None,
    ) -> None:
        self._failures: list[Finding] = []
        self._notes: list[Finding] = []
        self._horizon = 0
        self._xmax = 0
        self._has_horizon = False
        if horizon is not None:
            self.set_horizon(horizon, xmax)
        self._retention = retention
        self._scrubbed_stream = (
            None if system_severity is None else activity_stream(system_severity)
        )
        self.incarnations: list[Incarnation] = []
        self._segments: dict[str, dict[tuple[int, str], ExpectedSegment]] = {}
        self._acks: list[Ack] = []
        self._retired: dict[str, Retired] = {}
        self._last_seq: int | None = None
        self._detached: set[str] = set()
        self._checked: set[str] = set()
        self._records: list[_Record] = []
        # (group, xid) -> rows stamped, per table.
        self._stamps: dict[str, Counter[tuple[str, int]]] = {
            TRANSACTION: Counter(),
            ACTIVITY: Counter(),
        }
        self._chain(blocks)

    # -- blocks --

    def _fail(self, kind: FailureKind, detail: str, **where: Any) -> None:
        self._failures.append(Finding(kind, detail, **where))

    def _note(self, kind: NoteKind, detail: str, **where: Any) -> None:
        self._notes.append(Finding(kind, detail, **where))

    def _chain(self, blocks: Iterable[StoredBlock]) -> None:
        previous: bytes | None = None
        chain: str | None = None
        incarnation: Incarnation | None = None
        for number, block in enumerate(blocks, start=1):
            self._last_seq = block.seq
            expected_prev = ZERO_HASH if previous is None else previous
            if block.prev_hash != expected_prev:
                self._fail(
                    FailureKind.PREV_MISMATCH,
                    "prev_hash is not the hash of the block before",
                    seq=block.seq,
                )
            if len(block.prev_hash) != 32 or block.block_hash != block_hash(
                block.prev_hash, block.body
            ):
                self._fail(
                    FailureKind.HASH_MISMATCH,
                    "block_hash is not the hash of the stored body",
                    seq=block.seq,
                )
            previous = block.block_hash
            body = self._body(block, number, chain)
            if body is None:
                continue
            if number == 1:
                chain = str(body["chain"])
                incarnation = Incarnation(1, int(body["enforce_from"]))
                self.incarnations.append(incarnation)
                continue
            assert incarnation is not None
            self._read(block, body, incarnation)
        if not self.incarnations:
            raise ValueError("the chain has no genesis block")

    def _body(
        self, block: StoredBlock, number: int, chain: str | None
    ) -> dict[str, Any] | None:
        def malformed(why: str) -> None:
            self._fail(FailureKind.MALFORMED_BLOCK, why, seq=block.seq)

        try:
            body = parse_body(block.body)
        except (UnicodeDecodeError, ValueError):
            malformed("the body is not a JSON object")
            return None
        if block.seq != number or body.get("seq") != block.seq:
            malformed(f"expected block number {number}")
            return None
        if body.get("v") != FORMAT_VERSION:
            malformed("unknown format version")
            return None
        if body.get("kind") != block.kind:
            malformed("the kind column does not match the body")
            return None
        if number == 1:
            if block.kind != "genesis" or not is_int(body.get("enforce_from")):
                malformed("block 1 is not a genesis block")
                return None
            if not isinstance(body.get("chain"), str):
                malformed("the genesis block names no chain")
                return None
            return body
        if body.get("chain") != chain:
            malformed("the body names another chain")
            return None
        return body

    def _read(
        self, block: StoredBlock, body: Mapping[str, Any], incarnation: Incarnation
    ) -> None:
        def malformed(why: str) -> None:
            self._fail(FailureKind.MALFORMED_BLOCK, why, seq=block.seq)

        kind = block.kind
        if kind == "seal":
            xid_from, xid_to = body.get("xid_from"), body.get("xid_to")
            segments = body.get("segments")
            if not (is_int(xid_from) and is_int(xid_to) and xid_from < xid_to):
                malformed("the seal block has no valid xid range")
                return
            if xid_from != incarnation.sealed_to:
                malformed("the seal block does not start where the last one ended")
                return
            parsed = _segments(block.seq, segments)
            if parsed is None:
                malformed("the seal block has malformed segments")
                return
            incarnation.seals.append(Seal(block.seq, xid_from, xid_to))
            for segment in parsed:
                self._segments.setdefault(segment.partition, {})[
                    (segment.seq, segment.stream)
                ] = segment
        elif kind == "ack":
            try:
                failure = failure_kind(body.get("failure"))
                scope = body.get("scope")
                if not isinstance(scope, Mapping):
                    raise ValueError("no scope")
                waives = check_waives(body.get("waives"))
                self._acks.append(Ack(block.seq, failure, check_scope(scope), waives))
            except ValueError:
                malformed("the ack block has no valid failure, scope and pins")
        elif kind == "retire":
            stream, partition = body.get("stream"), body.get("partition")
            upper = parse_rfc3339(body.get("upper_bound"))
            if (
                not isinstance(stream, str)
                or not isinstance(partition, str)
                or upper is None
            ):
                malformed("the retire block names no partition and bound")
                return
            retired = Retired(block.seq, stream, partition, upper, block.sealed_at)
            self._retired[partition] = retired
            self._check_retention(retired)
        elif kind == "checkpoint":
            pass
        else:
            malformed(f"{kind!r} blocks are not supported by this verifier")

    def _check_retention(self, retired: Retired) -> None:
        if self._retention is None or retired.stream not in self._retention:
            return
        limit = self._retention[retired.stream]
        if limit is None or retired.upper_bound > retired.sealed_at - limit:
            self._fail(
                FailureKind.RETIRED_EARLY,
                "the partition was retired while still inside its retention",
                seq=retired.seq,
                stream=retired.stream,
                partition=retired.partition,
            )

    def set_horizon(self, horizon: int, xmax: int | None = None) -> None:
        """Give the horizon and ``xmax``, read after the blocks."""
        self._horizon = horizon
        self._xmax = max(self._xmax, horizon if xmax is None else max(xmax, horizon))
        self._has_horizon = True

    # -- rows --

    def incarnation_of(self, stream: str, row_id: int) -> Incarnation | None:
        """The incarnation whose ``id`` window holds a row."""
        for incarnation in self.incarnations:
            if incarnation.holds(stream, row_id):
                return incarnation
        return None

    def check_partition(
        self, partition: Partition, rows: Iterable[Mapping[str, Any]]
    ) -> None:
        """Check the rows of one partition, given in ``(xid, id)`` order.

        Rows with a ``NULL`` ``xid`` are left out; see ``null_xid_rows``.
        When ``rows`` raises, the partition is left as if never checked, so
        it can be checked again or reported as absent.
        """
        if not self._has_horizon:
            raise ValueError("set the horizon before checking rows")
        marks = (len(self._failures), len(self._notes), len(self._records))
        stamps = {table: Counter(counts) for table, counts in self._stamps.items()}
        try:
            state = _PartitionState(partition)
            for row in rows:
                self._row(state, row)
        except BaseException:
            del self._failures[marks[0] :]
            del self._notes[marks[1] :]
            del self._records[marks[2] :]
            self._stamps = stamps
            raise
        self._checked.add(partition.name)
        self._close(state, final=True)
        where = {"table": partition.table, "partition": partition.name}
        if state.erased:
            self._note(
                NoteKind.ERASED, "rows with erased groups", count=state.erased, **where
            )
        if state.pre_genesis:
            self._note(
                NoteKind.PRE_GENESIS,
                "rows older than the genesis block",
                count=state.pre_genesis,
                **where,
            )
        if state.unsealed:
            self._note(
                NoteKind.UNSEALED_TAIL,
                "rows not sealed yet",
                count=state.unsealed,
                **where,
            )

    def observe_xmax(self, xmax: int) -> None:
        """Raise the ``xmax`` bound to one read after the horizon.

        The reader calls it with ``pg_snapshot_xmax`` read after each chunk
        of rows, before handing the chunk over: a transaction that started
        after the horizon was read may have committed rows by then, and they
        belong to the unsealed tail, not the future.
        """
        self._xmax = max(self._xmax, xmax)

    def null_xid_rows(self, partition: Partition, count: int) -> None:
        """Note rows written before the ``xid`` column existed."""
        if count:
            self._note(
                NoteKind.PRE_GENESIS,
                "rows written before integrity was added",
                table=partition.table,
                partition=partition.name,
                count=count,
            )

    def _row(self, state: _PartitionState, row: Mapping[str, Any]) -> None:
        table = state.partition.table
        row_id, xid = int(row["id"]), int(row["xid"])
        if table == TRANSACTION:
            stream = TRANSACTION_STREAM
        else:
            stream = activity_stream(row["severity"])
        where = {
            "table": table,
            "partition": state.partition.name,
            "id": row_id,
            "xid": xid,
        }
        if xid >= self._xmax:
            # No transaction with this xid had started when the row was
            # read; left alone, it would sit in the unsealed tail forever.
            self._fail(
                FailureKind.XID_REWIND,
                "the row's xid is from a transaction that has not started",
                **where,
            )
            return
        incarnation = self.incarnation_of(stream, row_id)
        pre_genesis = incarnation is None or incarnation.is_pre_genesis(xid)
        enforce_from = (incarnation or self.incarnations[0]).enforce_from
        self._count_stamps(table, row, where, pre_genesis, enforce_from)
        if (
            table == ACTIVITY
            and row.get("verb") == SCRUBBED_VERB
            # A record from before the chain began is no receipt.
            and not pre_genesis
        ):
            data = row.get("data")
            payload = data.get("payload") if isinstance(data, Mapping) else None
            self._records.append(_Record(xid, row_id, state.partition.name, payload))
        if incarnation is None or pre_genesis:
            state.pre_genesis += 1
            return
        if incarnation.is_unsealed(xid):
            state.unsealed += 1
            return
        sealed = incarnation.seal_of(xid)
        assert sealed is not None  # the ranges are contiguous
        self._close(state, before=sealed.seq)
        key = (sealed.seq, stream)
        tree = state.trees.get(key)
        if tree is None:
            tree = state.trees[key] = MerkleTree()
        tree.add(_leaf(table, row))
        if row.get("seal_commitments") is None:
            self._fail(
                FailureKind.COMMITMENT_MISSING,
                "a sealed row has no commitments",
                seq=sealed.seq,
                **where,
            )
            return
        erased = False
        for check in check_groups(table, row):
            if check.failure is not None:
                self._fail(
                    check.failure,
                    f"group {check.group or '?'}: {check.detail}",
                    seq=sealed.seq,
                    group=check.group or None,
                    **where,
                )
            erased = erased or check.erased
        if erased:
            state.erased += 1

    def _count_stamps(
        self,
        table: str,
        row: Mapping[str, Any],
        where: Mapping[str, Any],
        pre_genesis: bool,
        enforce_from: int,
    ) -> None:
        """Count the stamps of a row by the scrub they name.

        A scrub runs after the row was written and before the snapshot that
        reads it; a stamp outside that names no real scrub, so no record can
        explain it. A scrub of a row before genesis, itself before genesis,
        is out of scope.
        """
        stamps = row.get("seal_erased")
        if not isinstance(stamps, Mapping):
            return
        for group, value in stamps.items():
            xid = _stamp(value)
            if xid is None:
                continue
            if pre_genesis and xid < enforce_from:
                continue
            if xid < where["xid"] or xid >= self._xmax:
                why = "older than its row" if xid < where["xid"] else "in the future"
                self._fail(
                    FailureKind.SCRUB_COUNT_MISMATCH,
                    f"group {group}: the stamp names a scrub {why}",
                    group=str(group),
                    **where,
                )
                continue
            self._stamps[table][(str(group), xid)] += 1

    def _close(
        self, state: _PartitionState, *, before: int | None = None, final: bool = False
    ) -> None:
        """Compare the finished segments of a partition with their blocks."""
        name = state.partition.name
        expected = self._segments.get(name, {})
        done = [
            key
            for key in state.trees
            if final or (before is not None and key[0] < before)
        ]
        for key in done:
            tree = state.trees.pop(key)
            state.closed.add(key)
            segment = expected.get(key)
            rows = 0 if segment is None else segment.rows
            root = tree.root()
            where = {
                "seq": key[0],
                "stream": key[1],
                "partition": name,
                "table": state.partition.table,
                "count": tree.size,
                "root": b64(root),
            }
            if tree.size != rows:
                self._fail(
                    FailureKind.ROW_COUNT_MISMATCH,
                    f"the segment seals {rows} rows, the partition has {tree.size}",
                    **where,
                )
            elif segment is not None and not hmac.compare_digest(root, segment.root):
                self._fail(
                    FailureKind.ROOT_MISMATCH,
                    "the rebuilt root differs from the sealed one",
                    **where,
                )
        if final:
            for key, segment in expected.items():
                if key not in state.closed:
                    self._fail(
                        FailureKind.ROW_COUNT_MISMATCH,
                        f"the segment seals {segment.rows} rows, the partition has 0",
                        table=state.partition.table,
                        seq=segment.seq,
                        stream=segment.stream,
                        partition=name,
                        count=0,
                        root=b64(MerkleTree().root()),
                    )

    # -- schema and scrubs --

    def schema(self, detached: Iterable[str]) -> None:
        """Report detached partitions, and the sealed ones that are absent.

        Args:
            detached: Names, without schema, of tables that look like
                detached partitions, and of partitions pending detach.
        """
        for name in sorted(set(detached)):
            self._detached.add(name)
            self._fail(
                FailureKind.DETACHED_PARTITION,
                "a partition is detached or pending detach",
                partition=name,
            )
        for name, segments in sorted(self._segments.items()):
            if name in self._checked or name in self._detached:
                continue
            first = min(segments.values(), key=lambda s: s.seq)
            retired = self._retired.get(name)
            if retired is not None:
                self._note(
                    NoteKind.RETIRED,
                    "a retired partition",
                    seq=retired.seq,
                    stream=retired.stream,
                    partition=name,
                    count=len(segments),
                )
            else:
                self._fail(
                    FailureKind.SEGMENT_MISSING,
                    f"{len(segments)} sealed segments name an absent partition",
                    seq=first.seq,
                    stream=first.stream,
                    partition=name,
                    count=len(segments),
                )

    def _check_scrubs(self) -> None:
        recorded: Counter[tuple[str, str, int]] = Counter()
        seen: set[int] = set()
        for record in self._records:
            seen.add(record.xid)
            counts = _record_counts(record.payload)
            where = {
                "table": ACTIVITY,
                "partition": record.partition,
                "id": record.id,
                "xid": record.xid,
            }
            if counts is None:
                self._fail(
                    FailureKind.SCRUB_COUNT_MISMATCH,
                    "an audit.scrubbed record without a known operation and counts",
                    **where,
                )
                continue
            for (table, group), count in counts.items():
                recorded[(table, group, record.xid)] += count
        stamped: dict[tuple[str, str, int], int] = {
            (table, group, xid): count
            for table, stamps in self._stamps.items()
            for (group, xid), count in stamps.items()
        }
        for key in sorted(set(recorded) | set(stamped)):
            table, group, xid = key
            want, have = recorded.get(key, 0), stamped.get(key, 0)
            if xid >= self._horizon:
                # The scrub may still be running: its rows are not all
                # visible yet. A later run, past it, counts them.
                self._note(
                    NoteKind.UNSEALED_TAIL,
                    "a scrub not finished when verify started; not counted yet",
                    table=table,
                    xid=xid,
                    group=group,
                    count=have,
                )
                continue
            if want == have:
                continue
            if xid not in seen and self._receipt_retired(xid):
                self._note(
                    NoteKind.ERASED_RECEIPT_RETIRED,
                    "rows erased by a scrub whose record was retired",
                    table=table,
                    xid=xid,
                    group=group,
                    count=have,
                )
                continue
            self._fail(
                FailureKind.SCRUB_COUNT_MISMATCH,
                f"scrubs at this xid recorded {want} rows, {have} rows carry the stamp",
                table=table,
                xid=xid,
                group=group,
                count=have,
            )

    def _receipt_retired(self, xid: int) -> bool:
        """Whether the record of the scrub at ``xid`` was sealed and retired.

        The record has the xid of its scrub, so it was sealed by the block
        whose range holds that xid, in the stream of its severity. A retired
        partition with a segment of that block and stream attests it.
        """
        stream = self._scrubbed_stream
        if stream is None:
            return False
        for incarnation in self.incarnations:
            sealed = incarnation.seal_of(xid)
            if sealed is None:
                continue
            for name, segments in self._segments.items():
                retired = self._retired.get(name)
                if (
                    retired is not None
                    and retired.stream == stream
                    and (sealed.seq, stream) in segments
                ):
                    return True
        return False

    # -- report --

    def report(self) -> VerificationReport:
        """Finish: the scrub counts and the horizon, then the report."""
        if not self._has_horizon:
            raise ValueError("set the horizon before the report")
        self._check_scrubs()
        current = self.incarnations[-1]
        if self._horizon < current.sealed_to:
            self._fail(
                FailureKind.XID_REWIND,
                "the database's horizon is below the chain's sealed horizon",
                xid=self._horizon,
            )
        failures: list[Finding] = []
        notes = list(self._notes)
        for finding in self._failures:
            ack = next((a for a in self._acks if a.covers(finding)), None)
            if ack is None:
                failures.append(finding)
            else:
                assert isinstance(finding.kind, FailureKind)
                notes.append(
                    _acknowledged(finding, ack.seq),
                )
        if failures:
            status = Status.FAILED
        elif notes:
            status = Status.VALID_WITH_NOTES
        else:
            status = Status.VALID
        return VerificationReport(
            status, Anchor.UNANCHORED, self._last_seq, failures, notes
        )


def _acknowledged(finding: Finding, ack: int) -> Finding:
    assert isinstance(finding.kind, FailureKind)
    return Finding(
        NoteKind.ACKNOWLEDGED,
        f"acknowledged {finding.kind}: {finding.detail}",
        seq=finding.seq,
        table=finding.table,
        partition=finding.partition,
        stream=finding.stream,
        id=finding.id,
        xid=finding.xid,
        group=finding.group,
        count=finding.count,
        root=finding.root,
        waived=finding.kind,
        ack=ack,
    )


def _record_counts(payload: object) -> dict[tuple[str, str], int] | None:
    """Rows per (table, group) an ``audit.scrubbed`` payload accounts for."""
    if not isinstance(payload, Mapping):
        return None
    operation = payload.get("operation")

    def count(name: str, default: int | None = None) -> int | None:
        value = payload.get(f"stamped_{name}", payload.get(name, default))
        return value if is_int(value) and value >= 0 else None

    if operation == "scrub":
        activity = count("activity_rows")
        if activity is None:
            return None
        return {(ACTIVITY, group): activity for group in _SCRUB_GROUPS}
    if operation == "scrub_actor":
        activity, transaction = count("activity_rows"), count("transaction_rows")
        if activity is None or transaction is None:
            return None
        return {(ACTIVITY, "actor"): activity, (TRANSACTION, "actor"): transaction}
    return None


def _leaf(table: str, row: Mapping[str, Any]) -> bytes:
    try:
        if table == TRANSACTION:
            return leaf_hash(transaction_leaf_row(row))
        return leaf_hash(activity_leaf_row(row))
    except (CanonicalEncodingError, KeyError, TypeError, AttributeError):
        # A row that cannot be encoded matches no sealed leaf.
        return bytes(32)


def _segments(seq: int, value: object) -> list[ExpectedSegment] | None:
    if not isinstance(value, list):
        return None
    parsed: list[ExpectedSegment] = []
    for item in value:
        if not isinstance(item, Mapping):
            return None
        stream, partition, rows = (item.get(k) for k in ("stream", "partition", "rows"))
        root = decode_strict(item.get("root"), 32)
        if not (
            isinstance(stream, str)
            and isinstance(partition, str)
            and is_int(rows)
            and rows > 0
            and root is not None
        ):
            return None
        parsed.append(ExpectedSegment(seq, stream, partition, rows, root))
    keys = [(s.stream, s.partition) for s in parsed]
    return parsed if len(set(keys)) == len(keys) else None


def stream_retention(
    retention: Mapping[int, timedelta | None],
    transaction_retention: timedelta | None = None,
) -> dict[str, timedelta | None]:
    """Retention by stream, from the arguments ``drop_expired`` takes.

    The transaction stream gets ``transaction_retention`` capped at the
    shortest finite severity retention, or that shortest one when it is
    ``None``, as ``drop_expired`` uses them.
    """
    streams: dict[str, timedelta | None] = {
        activity_stream(severity): limit for severity, limit in retention.items()
    }
    finite = [limit for limit in retention.values() if limit is not None]
    shortest = min(finite, default=None)
    if shortest is None:
        streams[TRANSACTION_STREAM] = transaction_retention
    elif transaction_retention is None:
        streams[TRANSACTION_STREAM] = shortest
    else:
        streams[TRANSACTION_STREAM] = min(transaction_retention, shortest)
    return streams
