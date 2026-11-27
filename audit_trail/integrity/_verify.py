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
  operation and group (``SCRUB_COUNT_MISMATCH``), within one xid space: a
  scrub of one cluster never explains a stamp of another that happens to
  have the same number. A stamp must name a transaction after its row's
  and before the snapshot's ``xmax``; a record or stamp from before the
  genesis block is no receipt. Scrubs at or above the horizon of the
  current space may still be running and are noted (``UNSEALED_TAIL``), to
  be counted by a later run.
- The partitions named by segments: present ones are checked, retired ones
  (a ``retire`` block) are accepted with a ``RETIRED`` note, detached or
  pending ones are ``DETACHED_PARTITION`` and absent ones
  ``SEGMENT_MISSING``. A retire block covers only the segments of its
  partition sealed before it, and must match them (``retire_coverage``),
  or it is ``MALFORMED_BLOCK`` and retires nothing; a segment sealed after
  it is ``SEGMENT_MISSING`` once the partition is gone. Given the
  retention, a retire block whose partition was still inside it, for any
  of its streams, is ``RETIRED_EARLY``.
- The horizon of the database against the chain's: ``XID_REWIND`` when it
  is lower, and for a row whose ``xid`` is at or above the ``xmax`` of the
  snapshot that read it (a row from the future).

- Signatures, given a ``SignatureVerifier``: a signed block by an unknown
  key is ``UNKNOWN_KEY``, one that does not verify ``BAD_SIGNATURE``, and
  with ``require_signatures`` so is an unsigned one.
- Trusted checkpoints (``_checkpoint``): ``TRUNCATED`` when the chain ends
  below one, ``CHAIN_MISMATCH`` when its block has another hash or is of
  another incarnation, a ``FORKED`` note instead when a signed fork block
  explains it: one from a later incarnation than the checkpoint's. With a
  signature verifier, a fork block not signed by a key it knows is also a
  ``FORKED_UNSIGNED`` note: it explains no checkpoint. A match
  makes the report ``ANCHORED``; the blocks after the newest match are an
  ``UNANCHORED_TAIL`` note.

Rows are judged per *incarnation* of the chain: an ``xid`` below its
``enforce_from`` is ``PRE_GENESIS``, one at or above its sealed horizon is
in the ``UNSEALED_TAIL``, and anything between belongs to one of its seal
blocks. The genesis block starts the first incarnation, and each ``fork``
block the next one (a ``FORKED`` note). A fork with an id window
(``id_floor``, after ``pg_restore`` into a new cluster, whose transaction
ids start low again) splits the rows by ``id``: those at or below the floor
belong to the incarnations before it, which it caps there, and those above
to the new one, in a new xid space. A row of an earlier xid space is never
"from the future", and a row left past the last seal of an incarnation a
fork closed is ``ROW_COUNT_MISMATCH``.

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
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any

from audit_trail.integrity._block import (
    FORMAT_VERSION,
    TRANSACTION_STREAM,
    ZERO_HASH,
    ExpectedSegment,
    SealedSegment,
    Segment,
    activity_leaf_row,
    activity_stream,
    block_hash,
    parse_body,
    parse_segments,
    retire_coverage,
    transaction_leaf_row,
)
from audit_trail.integrity._canonical import CanonicalEncodingError
from audit_trail.integrity._checkpoint import Checkpoint
from audit_trail.integrity._codec import b64, decode_strict, is_int, parse_rfc3339
from audit_trail.integrity._commit import (
    ACTIVITY_GROUPS,
    ACTOR_FIELDS,
    SCRUB_GROUPS,
    TRANSACTION_GROUPS,
    activity_groups,
    commitment,
    leaf_hash,
    transaction_groups,
)
from audit_trail.integrity._merkle import MerkleTree
from audit_trail.integrity._note import NoteError
from audit_trail.integrity._sign import (
    SignatureVerifier,
    block_signature_message,
)

ERASED_VALUE = "[erased]"
"""The marker a scrub writes; the same as ``audit_trail.diff.ERASED``."""

SCRUBBED_VERB = "audit.scrubbed"
"""Verb of the record a scrub writes; ``AuditSystem.SCRUBBED``."""

TRANSACTION = "transaction"
"""``table`` of a finding about an ``audit_transaction`` row."""

ACTIVITY = "activity"
"""``table`` of a finding about an ``audit_activity`` row."""


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
    FORKED_UNSIGNED = "FORKED_UNSIGNED"
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
        signature: The stored ``signature``; ``None`` unsigned.
        key_id: The stored ``key_id``.
        alg: The stored ``alg``.
    """

    seq: int
    kind: str
    body: bytes
    prev_hash: bytes
    block_hash: bytes
    sealed_at: datetime
    signature: bytes | None = None
    key_id: str | None = None
    alg: str | None = None


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
        number: 1 for the chain started by the genesis block, then one more
            for each fork block.
        enforce_from: Rows with a lower ``xid`` are out of its scope: the
            genesis block's ``enforce_from``, or the fork's ``xid_at_fork``.
        seals: Its seal blocks, in order; their ranges are contiguous.
        id_floor: Rows of a stream with ``id`` at or below this belong to an
            earlier incarnation; set by a fork with an id window.
        id_ceiling: Rows of a stream with ``id`` above this belong to a later
            incarnation; set by the next fork with an id window. A stream
            it does not name had no row at that fork: its ceiling is -1, so
            the incarnation holds none of its rows.
        space: ``number`` of the first incarnation of its xid space. A fork
            with an id window starts a new one (the restored cluster counts
            xids from low again); a fork without one keeps the space.
    """

    number: int
    enforce_from: int
    seals: list[Seal] = field(default_factory=list)
    id_floor: dict[str, int] | None = None
    id_ceiling: dict[str, int] | None = None
    space: int = 1

    @property
    def sealed_to(self) -> int:
        """The ``xid`` the incarnation is sealed up to (exclusive)."""
        return self.seals[-1].xid_to if self.seals else self.enforce_from

    def holds(self, stream: str, row_id: int) -> bool:
        """Whether a row of ``stream`` with this ``id`` is in its window."""
        if self.id_floor is not None and row_id <= self.id_floor.get(stream, -1):
            return False
        return self.id_ceiling is None or row_id <= self.id_ceiling.get(stream, -1)

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
    """A ``retire`` block that matches the chain before it.

    Attributes:
        seq: Its block number.
        table: ``transaction`` or ``activity``.
        partition: The partition it retires.
        streams: The streams of the partition.
        upper_bound: The partition's exclusive upper bound.
        sealed_at: When the block was written.
        covered: The ``(seq, stream)`` of every segment it covers: those of
            the partition in the seal blocks before it.
    """

    seq: int
    table: str
    partition: str
    streams: tuple[str, ...]
    upper_bound: datetime
    sealed_at: datetime
    covered: frozenset[tuple[int, str]]


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
class _Fork:
    """A valid fork block: its number, its prior checkpoint's and the
    incarnation it starts."""

    seq: int
    prior_seq: int
    incarnation: int


@dataclass(frozen=True)
class _Record:
    space: int
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
        count_scrubs: Compare the ``audit.scrubbed`` records with the
            stamps. ``False`` for a run that reads only some partitions
            (``skip_partition`` for the others), where neither count is
            whole.
        signatures: Checks the signatures of signed blocks: one by a key it
            does not know is ``UNKNOWN_KEY``, one that does not verify
            ``BAD_SIGNATURE``. ``None`` checks none.
        require_signatures: Every block and every checkpoint must be signed
            (``BAD_SIGNATURE`` for one that is not); for a chain whose
            writers all sign.
        checkpoints: Trusted checkpoints to check the chain against; see
            ``report``.
    """

    def __init__(
        self,
        blocks: Iterable[StoredBlock],
        *,
        horizon: int | None = None,
        xmax: int | None = None,
        retention: Mapping[str, timedelta | None] | None = None,
        system_severity: int | None = None,
        count_scrubs: bool = True,
        signatures: SignatureVerifier | None = None,
        require_signatures: bool = False,
        checkpoints: Sequence[Checkpoint] = (),
    ) -> None:
        if require_signatures and signatures is None:
            raise ValueError("require_signatures needs a signature verifier")
        self._signatures = signatures
        self._require_signatures = require_signatures
        self.signed: set[int] = set()
        """Blocks whose signature verified with a known key."""
        self._checkpoints = tuple(checkpoints)
        self._chain_id: str | None = None
        # Stored hashes of the blocks the checkpoints name, and the
        # incarnation each block is in.
        self._hashes: dict[int, bytes] = {}
        self._incarnation_at: dict[int, int] = {}
        # Hashes of the blocks a fork may name as its prior checkpoint.
        self._anchors: dict[int, bytes] = {}
        self._forks: list[_Fork] = []
        # Seal block -> the incarnation it belongs to.
        self._seal_owner: dict[int, int] = {}
        self._count_scrubs = count_scrubs
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
        # (group, xid space, xid) -> rows stamped, per table.
        self._stamps: dict[str, Counter[tuple[str, int, int]]] = {
            TRANSACTION: Counter(),
            ACTIVITY: Counter(),
        }
        # (group, xid space, xid) -> rows of that earlier space whose stamp
        # may name a scrub of it or one of the current space since the fork.
        self._shared: dict[str, Counter[tuple[str, int, int]]] = {
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
        wanted = {checkpoint.seq for checkpoint in self._checkpoints}
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
            self._check_signature(block)
            chain = self._read_block(block, number, chain)
            if block.seq in wanted:
                self._hashes[block.seq] = block.block_hash
                # A fork block is the first block of the incarnation it starts.
                self._incarnation_at[block.seq] = len(self.incarnations)
        if not self.incarnations:
            raise ValueError("the chain has no genesis block")

    def _read_block(
        self, block: StoredBlock, number: int, chain: str | None
    ) -> str | None:
        """Read the body of one block; the chain id, once the genesis gave it."""
        body = self._body(block, number, chain)
        if body is None:
            return chain
        if number == 1:
            chain = self._chain_id = str(body["chain"])
            self.incarnations.append(Incarnation(1, int(body["enforce_from"])))
            self._anchors[block.seq] = block.block_hash
            return chain
        if self.incarnations:
            # Without them block 1 was malformed: nothing after it is read.
            self._read(block, body, self.incarnations[-1])
        return chain

    def _check_signature(self, block: StoredBlock) -> None:
        """``UNKNOWN_KEY`` or ``BAD_SIGNATURE`` for a block's signature.

        The signature is over ``block_signature_message(block_hash)`` of the
        stored hash; a block whose hash does not match its body already fails
        with ``HASH_MISMATCH``.
        """
        verifier = self._signatures
        columns = (block.signature, block.key_id, block.alg)
        if verifier is None:
            return
        if all(column is None for column in columns):
            if self._require_signatures:
                self._fail(
                    FailureKind.BAD_SIGNATURE, "the block is not signed", seq=block.seq
                )
            return
        if block.signature is None or block.key_id is None or block.alg is None:
            self._fail(
                FailureKind.BAD_SIGNATURE,
                "the block has a partial signature",
                seq=block.seq,
            )
            return
        algorithm = verifier.key_algorithm(block.key_id)
        if algorithm is None:
            self._fail(
                FailureKind.UNKNOWN_KEY,
                f"the block is signed by an unknown key {block.key_id}",
                seq=block.seq,
            )
            return
        try:
            message = block_signature_message(block.block_hash)
        except ValueError:
            message = b""
        if (
            algorithm != block.alg
            or not message
            or not verifier.verify(block.key_id, algorithm, message, block.signature)
        ):
            self._fail(
                FailureKind.BAD_SIGNATURE,
                f"the signature by {block.key_id} does not verify",
                seq=block.seq,
            )
            return
        self.signed.add(block.seq)

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
            parsed = parse_segments(block.seq, segments)
            if parsed is None:
                malformed("the seal block has malformed segments")
                return
            incarnation.seals.append(Seal(block.seq, xid_from, xid_to))
            self._seal_owner[block.seq] = incarnation.number
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
            self._read_retire(block, body)
        elif kind == "checkpoint":
            if not is_int(body.get("xid_to")):
                malformed("the checkpoint block has no xid_to")
                return
            self._anchors[block.seq] = block.block_hash
        elif kind == "fork":
            self._read_fork(block, body, incarnation)
        else:
            malformed(f"{kind!r} blocks are not supported by this verifier")

    def _read_fork(
        self, block: StoredBlock, body: Mapping[str, Any], current: Incarnation
    ) -> None:
        """Start the next incarnation, as a valid fork block declares it.

        The fork must be the next incarnation and name a genesis, checkpoint
        or fork block before it, with its hash, as its prior checkpoint. A
        fork with an id window (``id_floor``) caps every incarnation of the
        current xid space at the floor, and the new one starts above it, in
        a new xid space; one without continues the xid space, and must not
        start below where the current incarnation is sealed to.
        """

        def malformed(why: str) -> None:
            self._fail(FailureKind.MALFORMED_BLOCK, why, seq=block.seq)

        number, reason = body.get("incarnation"), body.get("reason")
        prior, xid_at_fork = body.get("prior_checkpoint"), body.get("xid_at_fork")
        if number != current.number + 1 or not isinstance(reason, str):
            malformed("the fork block does not start the next incarnation")
            return
        if not is_int(xid_at_fork) or xid_at_fork < 0:
            malformed("the fork block has no valid xid_at_fork")
            return
        prior_seq = prior.get("seq") if isinstance(prior, Mapping) else None
        prior_hash = (
            decode_strict(prior.get("block_hash"), 32)
            if isinstance(prior, Mapping)
            else None
        )
        if (
            not is_int(prior_seq)
            or prior_hash is None
            or self._anchors.get(prior_seq) != prior_hash
        ):
            malformed("the fork block names no checkpoint of this chain before it")
            return
        try:
            floors = _id_window(body.get("id_floor"), body.get("id_count"))
        except ValueError:
            malformed("the fork block has no valid id_floor and id_count")
            return
        if floors is None and xid_at_fork < current.sealed_to:
            malformed("a fork without an id window starts below the sealed horizon")
            return
        if floors is None:
            started = Incarnation(
                current.number + 1,
                xid_at_fork,
                id_floor=current.id_floor,
                space=current.space,
            )
        else:
            for earlier in self.incarnations:
                if earlier.space == current.space:
                    earlier.id_ceiling = dict(floors)
            started = Incarnation(
                current.number + 1, xid_at_fork, id_floor=dict(floors), space=number
            )
        self.incarnations.append(started)
        self._anchors[block.seq] = block.block_hash
        self._forks.append(_Fork(block.seq, prior_seq, started.number))
        self._note(
            NoteKind.FORKED,
            f"incarnation {number} starts here: {reason}",
            seq=block.seq,
        )
        if self._signatures is not None and block.seq not in self.signed:
            # Anyone who can write the block table can add such a fork.
            self._note(
                NoteKind.FORKED_UNSIGNED,
                "the fork block is not signed by a known key; it explains no "
                "checkpoint",
                seq=block.seq,
            )

    def _read_retire(self, block: StoredBlock, body: Mapping[str, Any]) -> None:
        """Accept a retire block only as a match for the chain before it.

        Its partition, table and streams must name the segments sealed so
        far, and its coverage must be theirs (``retire_coverage``); a retire
        block that does not match retires nothing, so the partition's
        segments are ``SEGMENT_MISSING`` once it is gone.
        """

        def malformed(why: str) -> None:
            self._fail(FailureKind.MALFORMED_BLOCK, why, seq=block.seq)

        table, partition = body.get("table"), body.get("partition")
        streams = body.get("streams")
        upper = parse_rfc3339(body.get("upper_bound"))
        if (
            table not in (TRANSACTION, ACTIVITY)
            or not isinstance(partition, str)
            or not isinstance(streams, list)
            or not streams
            or not all(_stream_of(table, s) for s in streams)
            or upper is None
        ):
            malformed("the retire block names no partition, streams and bound")
            return
        if partition in self._retired:
            malformed("the partition was retired before")
            return
        sealed = self._segments.get(partition, {})
        coverage = retire_coverage(
            SealedSegment(s.seq, Segment(s.stream, s.partition, s.rows, s.root))
            for s in sealed.values()
        )
        found = {name: body.get(name) for name in coverage}
        if found != coverage or not {stream for _, stream in sealed} <= set(streams):
            malformed("the retire block does not match the segments sealed before it")
            return
        retired = Retired(
            block.seq,
            str(table),
            partition,
            tuple(streams),
            upper,
            block.sealed_at,
            frozenset(sealed),
        )
        self._retired[partition] = retired
        self._check_retention(retired)

    def _check_retention(self, retired: Retired) -> None:
        """``RETIRED_EARLY`` when a stream of the partition still kept it.

        A partition of several streams is kept for the longest of their
        retentions, as ``drop_expired`` keeps it.
        """
        if self._retention is None:
            return
        for stream in retired.streams:
            if stream not in self._retention:
                continue
            limit = self._retention[stream]
            if limit is None or retired.upper_bound > retired.sealed_at - limit:
                self._fail(
                    FailureKind.RETIRED_EARLY,
                    "the partition was retired while still inside its retention",
                    seq=retired.seq,
                    table=retired.table,
                    stream=stream,
                    partition=retired.partition,
                )
                return

    def set_horizon(self, horizon: int, xmax: int | None = None) -> None:
        """Give the horizon and ``xmax``, read after the blocks."""
        self._horizon = horizon
        self._xmax = max(self._xmax, horizon if xmax is None else max(xmax, horizon))
        self._has_horizon = True

    # -- rows --

    def incarnation_of(self, stream: str, row_id: int, xid: int) -> Incarnation | None:
        """The incarnation a row belongs to.

        The first incarnation whose ``id`` window holds the row; forks
        without an id window share one window in one xid space, and of
        those the last one that starts at or below the row's ``xid``. The
        first when none does, for which the row is ``PRE_GENESIS``.
        """
        chosen: Incarnation | None = None
        for incarnation in self.incarnations:
            if not incarnation.holds(stream, row_id):
                continue
            if chosen is None or (
                incarnation.space == chosen.space and incarnation.enforce_from <= xid
            ):
                chosen = incarnation
        return chosen

    def _in_current_space(self, incarnation: Incarnation | None) -> bool:
        """Whether an incarnation counts xids the way the database does now."""
        return incarnation is None or incarnation.space == self.incarnations[-1].space

    def _xid_limit(self, incarnation: Incarnation | None) -> int:
        """No row or stamp of the incarnation has this ``xid`` or a higher one.

        ``xmax`` in the current xid space; in an earlier one, the end of its
        last incarnation, which a fork closed with a seal block up to the
        highest ``xid`` stored then.
        """
        if self._in_current_space(incarnation):
            return self._xmax
        assert incarnation is not None
        return max(
            i.sealed_to for i in self.incarnations if i.space == incarnation.space
        )

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
        shared = {table: Counter(counts) for table, counts in self._shared.items()}
        try:
            state = _PartitionState(partition)
            for row in rows:
                self._row(state, row)
        except BaseException:
            del self._failures[marks[0] :]
            del self._notes[marks[1] :]
            del self._records[marks[2] :]
            self._stamps = stamps
            self._shared = shared
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

    def skip_partition(self, partition: Partition) -> None:
        """Take a partition that holds rows as present, without reading it.

        For a run that checks only some partitions: its segments are neither
        checked nor ``SEGMENT_MISSING``.
        """
        self._checked.add(partition.name)

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
        incarnation = self.incarnation_of(stream, row_id, xid)
        if xid >= self._xmax and self._in_current_space(incarnation):
            # No transaction with this xid had started when the row was
            # read; left alone, it would sit in the unsealed tail forever.
            self._fail(
                FailureKind.XID_REWIND,
                "the row's xid is from a transaction that has not started",
                **where,
            )
            return
        pre_genesis = incarnation is None or incarnation.is_pre_genesis(xid)
        enforce_from = (incarnation or self.incarnations[0]).enforce_from
        self._count_stamps(table, row, where, pre_genesis, enforce_from, incarnation)
        if (
            table == ACTIVITY
            and row.get("verb") == SCRUBBED_VERB
            # A record from before the chain began is no receipt.
            and not pre_genesis
        ):
            data = row.get("data")
            payload = data.get("payload") if isinstance(data, Mapping) else None
            self._records.append(
                _Record(
                    self._space_of(incarnation),
                    xid,
                    row_id,
                    state.partition.name,
                    payload,
                )
            )
        if incarnation is None or pre_genesis:
            state.pre_genesis += 1
            return
        if incarnation.is_unsealed(xid):
            if incarnation is not self.incarnations[-1]:
                # A fork closed the incarnation: nothing seals it any more.
                self._fail(
                    FailureKind.ROW_COUNT_MISMATCH,
                    "a row past the last seal block of an incarnation a fork "
                    "closed; no block can seal it",
                    **where,
                )
                return
            state.unsealed += 1
            return
        sealed = incarnation.seal_of(xid)
        assert sealed is not None  # the ranges are contiguous
        self._close(state, before=sealed.seq, incarnation=incarnation.number)
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
        incarnation: Incarnation | None = None,
    ) -> None:
        """Count the stamps of a row by the scrub they name.

        A scrub runs after the row was written and before the snapshot that
        reads it; a stamp outside that names no real scrub, so no record can
        explain it. A scrub of a row before genesis, itself before genesis,
        is out of scope. A row of an earlier xid space (before a fork with
        an id window) may also carry the stamp of a scrub run since the
        fork, in the current space. Each stamp is counted in its space; one
        that fits both is counted as shared, and ``_check_scrubs`` gives it
        to whichever space's records account for it.
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
            space, current = self._space_of(incarnation), self.incarnations[-1].space
            # A scrub in the row's own xid space, after the row...
            own = where["xid"] <= xid < self._xid_limit(incarnation)
            # ... or, for a row of an earlier space, one since the fork.
            since_fork = space != current and (self._space_start() <= xid < self._xmax)
            if not own and not since_fork:
                why = "older than its row" if xid < where["xid"] else "in the future"
                self._fail(
                    FailureKind.SCRUB_COUNT_MISMATCH,
                    f"group {group}: the stamp names a scrub {why}",
                    group=str(group),
                    **where,
                )
                continue
            if own and since_fork:
                self._shared[table][(str(group), space, xid)] += 1
            else:
                self._stamps[table][(str(group), space if own else current, xid)] += 1

    def _space_of(self, incarnation: Incarnation | None) -> int:
        """The xid space of a row's incarnation; the current one for none."""
        if incarnation is None:
            return self.incarnations[-1].space
        return incarnation.space

    def _space_start(self) -> int:
        """The first ``xid`` of the current xid space."""
        space = self.incarnations[-1].space
        return min(i.enforce_from for i in self.incarnations if i.space == space)

    def _close(
        self,
        state: _PartitionState,
        *,
        before: int | None = None,
        incarnation: int | None = None,
        final: bool = False,
    ) -> None:
        """Compare the finished segments of a partition with their blocks.

        Rows come in ``(xid, id)`` order, so within one incarnation a row of
        seal block ``before`` ends every segment of an earlier one. Rows of
        several incarnations interleave (their xid ranges overlap after a
        fork with an id window), so only the incarnation's own end.
        """
        name = state.partition.name
        expected = self._segments.get(name, {})
        done = [
            key
            for key in state.trees
            if final
            or (
                before is not None
                and key[0] < before
                and self._seal_owner.get(key[0]) == incarnation
            )
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
            retired = self._retired.get(name)
            missing = [
                segment
                for key, segment in segments.items()
                if retired is None or key not in retired.covered
            ]
            if retired is not None and retired.covered:
                self._note(
                    NoteKind.RETIRED,
                    "a retired partition",
                    seq=retired.seq,
                    table=retired.table,
                    stream=retired.streams[0] if len(retired.streams) == 1 else None,
                    partition=name,
                    count=len(retired.covered),
                )
            if missing:
                first = min(missing, key=lambda s: s.seq)
                why = "sealed after its retire block" if retired else "absent"
                self._fail(
                    FailureKind.SEGMENT_MISSING,
                    f"{len(missing)} sealed segments name a partition {why}",
                    seq=first.seq,
                    stream=first.stream,
                    partition=name,
                    count=len(missing),
                )

    def _check_scrubs(self) -> None:
        """Compare the records of each scrub with the stamps that name it.

        Per table, group, xid space and xid. Stamps shared between an
        earlier space and the current one go to the space whose records
        account for them, when some split does.
        """
        current = self.incarnations[-1].space
        recorded: Counter[tuple[str, str, int, int]] = Counter()
        seen: set[tuple[int, int]] = set()
        for record in self._records:
            seen.add((record.space, record.xid))
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
                recorded[(table, group, record.space, record.xid)] += count
        stamped: Counter[tuple[str, str, int, int]] = Counter(
            {
                (table, group, space, xid): count
                for table, stamps in self._stamps.items()
                for (group, space, xid), count in stamps.items()
            }
        )
        shared: dict[tuple[str, str, int], dict[int, int]] = {}
        for table, stamps in self._shared.items():
            for (group, space, xid), count in stamps.items():
                shared.setdefault((table, group, xid), {})[space] = count
        scrubs: dict[tuple[str, str, int], set[int]] = {}
        for table, group, space, xid in (*recorded, *stamped):
            scrubs.setdefault((table, group, xid), set()).add(space)
        for key, pools in shared.items():
            scrubs.setdefault(key, set()).update((*pools, current))
        for (table, group, xid), spaces in sorted(scrubs.items()):
            want = {s: recorded[(table, group, s, xid)] for s in spaces}
            have = {s: stamped[(table, group, s, xid)] for s in spaces}
            pools = shared.get((table, group, xid), {})
            if pools:
                bounds = {s: self._bounds(s, xid, want[s], seen) for s in spaces}
                for space, count in _split(pools, current, have, bounds).items():
                    have[space] += count
            for space in sorted(spaces):
                self._judge(table, group, space, xid, want[space], have[space], seen)

    def _running(self, space: int, xid: int) -> bool:
        """Whether a scrub may still be running: only in the current space."""
        return (
            space == self.incarnations[-1].space and self._horizon <= xid < self._xmax
        )

    def _bounds(
        self, space: int, xid: int, want: int, seen: set[tuple[int, int]]
    ) -> tuple[int, int | None]:
        """How many stamps the records of a scrub accept: ``(low, high)``.

        Exactly the recorded rows, or any number (``high`` ``None``) for a
        scrub that may still be running or whose record was retired.
        """
        if self._running(space, xid) or (
            (space, xid) not in seen and self._receipt_retired(space, xid)
        ):
            return 0, None
        return want, want

    def _judge(
        self,
        table: str,
        group: str,
        space: int,
        xid: int,
        want: int,
        have: int,
        seen: set[tuple[int, int]],
    ) -> None:
        """Report a scrub whose stamps and records disagree."""
        if self._running(space, xid):
            # The scrub may still be running: its rows are not all visible
            # yet. A later run, past it, counts them.
            self._note(
                NoteKind.UNSEALED_TAIL,
                "a scrub not finished when verify started; not counted yet",
                table=table,
                xid=xid,
                group=group,
                count=have,
            )
            return
        if want == have:
            return
        where = {"table": table, "xid": xid, "group": group, "count": have}
        if (space, xid) not in seen and self._receipt_retired(space, xid):
            self._note(
                NoteKind.ERASED_RECEIPT_RETIRED,
                "rows erased by a scrub whose record was retired",
                **where,
            )
            return
        earlier = (
            ""
            if space == self.incarnations[-1].space
            else (f" (in the xid space of incarnation {space})")
        )
        self._fail(
            FailureKind.SCRUB_COUNT_MISMATCH,
            f"scrubs at this xid{earlier} recorded {want} rows, {have} rows "
            "carry the stamp",
            **where,
        )

    def _receipt_retired(self, space: int, xid: int) -> bool:
        """Whether the record of the scrub at ``xid`` was sealed and retired.

        The record has the xid of its scrub, so it was sealed by the block
        of an incarnation of the scrub's xid space whose range holds that
        xid, in the stream of its severity. A retire block attests it when
        it names that stream and covers the segment of that block and stream
        in its partition, and the partition is gone.
        """
        stream = self._scrubbed_stream
        if stream is None:
            return False
        for incarnation in self.incarnations:
            sealed = incarnation.seal_of(xid) if incarnation.space == space else None
            if sealed is None:
                continue
            for name, retired in self._retired.items():
                if (
                    name not in self._checked
                    and stream in retired.streams
                    and (sealed.seq, stream) in retired.covered
                ):
                    return True
        return False

    # -- report --

    def report(self) -> VerificationReport:
        """Finish: the scrub counts and the horizon, then the report."""
        if not self._has_horizon:
            raise ValueError("set the horizon before the report")
        if self._count_scrubs:
            self._check_scrubs()
        current = self.incarnations[-1]
        if self._horizon < current.sealed_to:
            self._fail(
                FailureKind.XID_REWIND,
                "the database's horizon is below the chain's sealed horizon",
                xid=self._horizon,
            )
        anchored = self._check_checkpoints()
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
        anchor = Anchor.ANCHORED if anchored else Anchor.UNANCHORED
        return VerificationReport(status, anchor, self._last_seq, failures, notes)

    def _check_checkpoints(self) -> bool:
        """Match the chain against each trusted checkpoint; whether one matched.

        A checkpoint whose signatures do not verify (with a signature
        verifier given) is not used, nor is an unsigned one when signatures
        are required (``BAD_SIGNATURE``). One that names a block the chain does
        not have is ``TRUNCATED``, one whose block has another hash, or that
        is of another chain, ``CHAIN_MISMATCH``, as is one whose block is
        in another incarnation than the checkpoint names. A ``TRUNCATED`` or
        ``CHAIN_MISMATCH`` is a ``FORKED`` note instead when a fork block
        that starts a later incarnation than the checkpoint's, and whose
        prior checkpoint is below it, carries a signature that verified:
        the fork declares that the chain was rebuilt from that prior
        checkpoint, so the checkpoint names a block of an incarnation the
        fork ended. A checkpoint taken at or after the fork (of its
        incarnation or a later one) is never explained: the chain it saw
        held the fork block already, so a divergence since is a rewrite. An
        unsigned fork block explains nothing either: anyone who can write
        the block table can add one.
        """
        matched: list[int] = []
        for checkpoint in self._checkpoints:
            where: dict[str, Any] = {"seq": checkpoint.seq}
            if self._require_signatures and not checkpoint.signatures:
                self._fail(
                    FailureKind.BAD_SIGNATURE, "the checkpoint is not signed", **where
                )
                continue
            if self._signatures is not None and checkpoint.signatures:
                try:
                    checkpoint.verify(self._signatures)
                except NoteError as exc:
                    kind = (
                        FailureKind.UNKNOWN_KEY
                        if exc.reason == "UNKNOWN_KEY"
                        else FailureKind.BAD_SIGNATURE
                    )
                    self._fail(kind, f"checkpoint: {exc}", **where)
                    continue
            if checkpoint.chain != self._chain_id:
                self._fail(
                    FailureKind.CHAIN_MISMATCH,
                    "the checkpoint is of another chain",
                    **where,
                )
                continue
            stored = self._hashes.get(checkpoint.seq)
            if stored is not None and hmac.compare_digest(
                stored, checkpoint.block_hash
            ):
                if self._incarnation_at.get(checkpoint.seq) != checkpoint.incarnation:
                    self._fail(
                        FailureKind.CHAIN_MISMATCH,
                        f"the checkpoint names incarnation {checkpoint.incarnation}"
                        ", its block is in another",
                        **where,
                    )
                    continue
                matched.append(checkpoint.seq)
                continue
            kind = FailureKind.CHAIN_MISMATCH if stored else FailureKind.TRUNCATED
            fork = self._fork_explaining(checkpoint)
            if fork is not None:
                self._note(
                    NoteKind.FORKED,
                    f"the checkpoint names a block before the fork in block "
                    f"{fork.seq} ({kind} explained)",
                    **where,
                )
                continue
            if stored is None:
                detail = f"the chain ends below the checkpoint, at {self._last_seq}"
            else:
                detail = "the block at the checkpoint's seq has another hash"
            self._fail(kind, detail, **where)
        if matched and self._last_seq is not None and self._last_seq > max(matched):
            self._note(
                NoteKind.UNANCHORED_TAIL,
                "blocks after the newest checkpoint",
                seq=max(matched) + 1,
                count=self._last_seq - max(matched),
            )
        return bool(matched)

    def _fork_explaining(self, checkpoint: Checkpoint) -> _Fork | None:
        """A signed fork block that explains a diverging checkpoint.

        One that starts a later incarnation than the checkpoint was taken
        in, rebuilt from a prior checkpoint below it.
        """
        for fork in self._forks:
            if (
                fork.incarnation > checkpoint.incarnation
                and fork.prior_seq < checkpoint.seq
                and fork.seq in self.signed
            ):
                return fork
        return None


def _split(
    pools: Mapping[int, int],
    current: int,
    have: Mapping[int, int],
    bounds: Mapping[int, tuple[int, int | None]],
) -> dict[int, int]:
    """Share out the stamps that fit an earlier space and the current one.

    ``pools`` holds, by earlier space, the stamps that may name a scrub of
    that space or of the current one; ``have`` the stamps counted in each
    space already, and ``bounds`` how many each space's records accept.
    Returns the stamps to add to each space: a split that satisfies every
    bound when there is one, else one that leaves the mismatch to report.
    """
    low: dict[int, int] = {}
    high: dict[int, int] = {}
    for space, pool in pools.items():
        least, most = bounds[space]
        low[space] = min(max(least - have[space], 0), pool)
        high[space] = pool if most is None else min(max(most - have[space], 0), pool)
    least = bounds[current][0]
    base = have[current] + sum(pools.values())
    # The current space gets base - taken; aim for its lowest acceptable.
    taken = min(max(base - least, sum(low.values())), sum(high.values()))
    split: dict[int, int] = {}
    rest = taken - sum(low.values())
    for space in sorted(pools):
        extra = min(rest, high[space] - low[space])
        rest -= extra
        split[space] = low[space] + extra
    split[current] = base - have[current] - taken
    return split


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
        return {(ACTIVITY, group): activity for group in SCRUB_GROUPS}
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


def _id_window(floors: object, counts: object) -> dict[str, int] | None:
    """The ``id_floor`` of a fork block, or ``None`` when it has none.

    Both are ``None``, or objects with the same streams as keys and
    non-negative integers as values.

    Raises:
        ValueError: Neither.
    """
    if floors is None and counts is None:
        return None
    if not isinstance(floors, Mapping) or not isinstance(counts, Mapping):
        raise ValueError("id_floor and id_count are objects")
    if set(floors) != set(counts):
        raise ValueError("id_floor and id_count name other streams")
    for stream in floors:
        table = TRANSACTION if stream == TRANSACTION_STREAM else ACTIVITY
        if not _stream_of(table, stream):
            raise ValueError("not a stream")
        if not all(is_int(v[stream]) and v[stream] >= 0 for v in (floors, counts)):
            raise ValueError("not a count")
    return {str(stream): int(value) for stream, value in floors.items()}


def _stream_of(table: object, stream: object) -> bool:
    """Whether ``stream`` is a stream of the rows of ``table``."""
    if table == TRANSACTION:
        return stream == TRANSACTION_STREAM
    if not isinstance(stream, str) or not stream.startswith("activity."):
        return False
    severity = stream.removeprefix("activity.")
    return severity.lstrip("-").isdigit() and activity_stream(int(severity)) == stream


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
