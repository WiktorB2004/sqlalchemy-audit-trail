"""Sealed blocks: leaf rows, segment roots, block bodies and the chain hash.

Nothing here touches the database, so the sealer and the verifier share it.

A ``seal`` block covers every audit row whose ``xid`` is in
``[xid_from, xid_to)``. Its rows are split into *segments*, one per
(stream, monthly partition) that has rows in the range; the streams are
``transaction`` and ``activity.<severity>``. A segment's ``root`` is the RFC
6962 Merkle tree hash of its leaves in ``(xid, id)`` order, with::

    leaf = SHA-256(0x00 || "sqlalchemy-audit-trail/leaf/v1" || canonical(row))
    node = SHA-256(0x01 || left || right)

where ``row`` holds the fields of the row that never change after insert
(``transaction_leaf_row`` and ``activity_leaf_row``). The erasable parts are
covered by ``seal_commitments``, which is one of those fields.

A body is the ``canonical`` encoding of a JSON object naming its format
version ``v``, its ``kind``, the ``chain`` id and its ``seq``; the table
stores it exactly as hashed::

    block_hash = SHA-256("sqlalchemy-audit-trail/block/v1" || 0x00
                         || prev_hash || body)

The first block is a ``genesis`` block with ``prev_hash`` of 32 zero bytes.
Hashes inside a body are base64, as in ``seal_commitments``.

A ``retire`` block is written before a partition is dropped. It names the
partition, its table and streams, and covers every segment of it in the
seal blocks before it: their seal range, count, rows and a digest of them
(``retire_coverage``).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from audit_trail.integrity._canonical import canonical
from audit_trail.integrity._codec import b64, context, decode_strict, is_int, rfc3339
from audit_trail.integrity._commit import ACTOR_FIELDS, leaf_hash
from audit_trail.integrity._merkle import MerkleTree

FORMAT_VERSION = 1
"""Value of ``v`` in every body."""

BLOCK_CONTEXT = context("block")
"""Domain separation string of a block hash."""

ZERO_HASH = bytes(32)
"""``prev_hash`` of the genesis block."""

TRANSACTION_STREAM = "transaction"
"""Stream of the ``audit_transaction`` rows."""

TRANSACTION_LEAF_COLUMNS: tuple[str, ...] = (
    "id",
    "issued_at",
    "actor_type",
    "actor_id",
    "method",
    "path",
    "channel",
    "auth_method",
    "request_id",
    "correlation_id",
    "xid",
    "seal_commitments",
)
"""Columns of an ``audit_transaction`` leaf: all but the ``actor`` group
(``ACTOR_FIELDS``), ``seal_salts`` and ``seal_erased``."""

ACTIVITY_LEAF_COLUMNS: tuple[str, ...] = (
    "id",
    "transaction_id",
    "verb",
    "severity",
    "object_type",
    "object_id",
    "target_type",
    "target_id",
    "actor_id",
    "scope_id",
    "correlation_id",
    "created_at",
    "data",
    "xid",
    "seal_commitments",
)
"""Columns of an ``audit_activity`` leaf: all but ``object_label`` (the
``label`` group), ``seal_salts`` and ``seal_erased``. Of ``data`` only the
part no scrub changes is kept (``clear_data``)."""

ERASABLE_DATA_KEYS: tuple[str, ...] = ("changes", "payload")
"""Keys of ``data`` that ``scrub`` erases; left out of the leaf."""


def activity_stream(severity: int) -> str:
    """Stream of the activity rows of one severity."""
    return f"activity.{int(severity)}"


def transaction_leaf_row(row: Mapping[Any, Any]) -> dict[str, object]:
    """The fields of an ``audit_transaction`` row that its leaf hashes.

    Args:
        row: The row as read back, with at least ``TRANSACTION_LEAF_COLUMNS``.

    Returns:
        Those columns, timestamps as RFC 3339 UTC text and UUIDs as text.

    Raises:
        CanonicalEncodingError: A timestamp is naive.
    """
    return {name: _value(row[name]) for name in TRANSACTION_LEAF_COLUMNS}


def activity_leaf_row(row: Mapping[Any, Any]) -> dict[str, object]:
    """The fields of an ``audit_activity`` row that its leaf hashes.

    Args:
        row: The row as read back, with at least ``ACTIVITY_LEAF_COLUMNS``.

    Returns:
        Those columns, with ``data`` reduced by ``clear_data``, timestamps as
        RFC 3339 UTC text and UUIDs as text.

    Raises:
        CanonicalEncodingError: A timestamp is naive.
    """
    fields = {name: _value(row[name]) for name in ACTIVITY_LEAF_COLUMNS}
    fields["data"] = clear_data(row["data"])
    return fields


def clear_data(data: Mapping[str, Any]) -> dict[str, Any]:
    """The part of an activity row's ``data`` that no scrub changes.

    ``changes`` and ``payload`` are left out (``scrub``), and so are the
    ``ACTOR_FIELDS`` keys of ``context`` (``scrub_actor``). Every other key
    stays, ``context`` too, even when nothing is left in it.
    """
    clear = {key: value for key, value in data.items() if key not in ERASABLE_DATA_KEYS}
    context = clear.get("context")
    if isinstance(context, Mapping):
        clear["context"] = {
            key: value for key, value in context.items() if key not in ACTOR_FIELDS
        }
    return clear


def _value(value: object) -> object:
    match value:
        case datetime():
            return rfc3339(value)
        case UUID():
            return str(value)
        case _:
            return value


@dataclass(frozen=True)
class Segment:
    """The rows of one stream in one partition, within one seal block.

    Attributes:
        stream: ``transaction`` or ``activity.<severity>``.
        partition: Name of the monthly partition, without schema.
        rows: Number of leaves.
        root: Merkle tree hash of the leaves.
    """

    stream: str
    partition: str
    rows: int
    root: bytes


class SegmentBuilder:
    """Segment roots of rows streamed in ``(xid, id)`` order."""

    def __init__(self) -> None:
        self._trees: dict[tuple[str, str], MerkleTree] = {}

    def add(self, stream: str, partition: str, row: Mapping[str, object]) -> None:
        """Hash a leaf row into its segment."""
        key = (stream, partition)
        tree = self._trees.get(key)
        if tree is None:
            tree = self._trees[key] = MerkleTree()
        tree.add(leaf_hash(row))

    @property
    def rows(self) -> int:
        """Leaves added so far."""
        return sum(tree.size for tree in self._trees.values())

    def segments(self) -> list[Segment]:
        """The segments, sorted by stream and partition."""
        return [
            Segment(stream, partition, tree.size, tree.root())
            for (stream, partition), tree in sorted(self._trees.items())
        ]


@dataclass(frozen=True)
class ExpectedSegment:
    """A segment as a seal block names it."""

    seq: int
    stream: str
    partition: str
    rows: int
    root: bytes


def parse_segments(seq: int, value: object) -> list[ExpectedSegment] | None:
    """The segments a parsed seal body names, or ``None`` when malformed.

    Args:
        seq: The block's number.
        value: The body's ``segments``.

    Returns:
        The segments, or ``None`` unless ``value`` is a list of distinct
        (stream, partition) entries, each with a positive ``rows`` and a
        32-byte ``root``.
    """
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


def genesis_body(chain: str, enforce_from: int) -> bytes:
    """Body of the genesis block (``seq`` 1).

    Args:
        chain: The chain id, a UUID as text.
        enforce_from: The horizon when the chain started; rows with a lower
            ``xid`` are out of scope.
    """
    return _body(
        {
            "v": FORMAT_VERSION,
            "kind": "genesis",
            "chain": chain,
            "seq": 1,
            "enforce_from": enforce_from,
        }
    )


def seal_body(
    chain: str, seq: int, xid_from: int, xid_to: int, segments: Iterable[Segment]
) -> bytes:
    """Body of a seal block covering ``xid`` in ``[xid_from, xid_to)``."""
    return _body(
        {
            "v": FORMAT_VERSION,
            "kind": "seal",
            "chain": chain,
            "seq": seq,
            "xid_from": xid_from,
            "xid_to": xid_to,
            "segments": [
                {
                    "stream": segment.stream,
                    "partition": segment.partition,
                    "rows": segment.rows,
                    "root": b64(segment.root),
                }
                for segment in segments
            ],
        }
    )


def fork_body(
    chain: str,
    seq: int,
    *,
    incarnation: int,
    reason: str,
    prior_seq: int,
    prior_hash: bytes,
    xid_at_fork: int,
    id_floor: Mapping[str, int] | None,
    id_count: Mapping[str, int] | None,
) -> bytes:
    """Body of a fork block, which starts a new incarnation of the chain.

    Args:
        chain: The chain id.
        seq: The block's number.
        incarnation: Number of the incarnation the fork starts, from 2.
        reason: Why the database was restored, as the operator wrote it.
        prior_seq: ``seq`` of the last good checkpoint.
        prior_hash: ``block_hash`` of that checkpoint.
        xid_at_fork: ``pg_current_xact_id()`` when the fork was declared.
        id_floor: Highest ``id`` of each stream before the fork, or ``None``
            when blocks select by ``xid`` alone.
        id_count: Rows of each stream with ``id <= id_floor``, or ``None``
            together with ``id_floor``.
    """
    return _body(
        {
            "v": FORMAT_VERSION,
            "kind": "fork",
            "chain": chain,
            "seq": seq,
            "incarnation": incarnation,
            "reason": reason,
            "prior_checkpoint": {"seq": prior_seq, "block_hash": b64(prior_hash)},
            "xid_at_fork": xid_at_fork,
            "id_floor": None if id_floor is None else dict(id_floor),
            "id_count": None if id_count is None else dict(id_count),
        }
    )


def horizon_of(body: Mapping[str, Any]) -> int:
    """The ``xid`` a parsed genesis or seal body seals up to, exclusive."""
    if body["kind"] == "genesis":
        return int(body["enforce_from"])
    return int(body["xid_to"])


def ack_body(
    chain: str,
    seq: int,
    *,
    failure: str,
    scope: Mapping[str, object],
    waives: Sequence[Mapping[str, object]],
    reason: str,
) -> bytes:
    """Body of an ack block, which waives failures of one kind in a scope.

    Args:
        chain: The chain id.
        seq: The block's number.
        failure: Name of the failure kind it waives.
        scope: The findings it covers, as the verifier matches them.
        waives: The failures it waives, each pinned as it was observed: the
            row for a row, the root and count for a segment.
        reason: Why, as the operator wrote it.
    """
    return _body(
        {
            "v": FORMAT_VERSION,
            "kind": "ack",
            "chain": chain,
            "seq": seq,
            "failure": failure,
            "scope": dict(scope),
            "waives": [dict(pin) for pin in waives],
            "reason": reason,
        }
    )


RETIRE_CONTEXT = context("retire")
"""Domain separation string of a retire block's ``segments_digest``."""


@dataclass(frozen=True)
class SealedSegment:
    """A segment as the chain holds it: the seal block it is in, and itself.

    Attributes:
        seq: The seal block.
        segment: The segment.
    """

    seq: int
    segment: Segment


def retire_coverage(segments: Iterable[SealedSegment]) -> dict[str, object]:
    """What a retire block says about the sealed segments of its partition.

    Args:
        segments: Every segment of the partition in the seal blocks before
            the retire block.

    Returns:
        ``seals``: ``{"first": seq, "last": seq}`` of the first and last
        seal block with a segment of the partition, ``None`` when there is
        none; ``segments``: how many; ``rows``: their rows together;
        ``segments_digest``: base64 of
        ``SHA-256("sqlalchemy-audit-trail/retire/v1" || 0x00 || c1 || c2 ...)``
        where ``ci`` is the canonical ``{seq, stream, rows, root}`` of each
        segment, in ``(seq, stream)`` order.
    """
    ordered = sorted(segments, key=lambda s: (s.seq, s.segment.stream))
    digest = hashlib.sha256(RETIRE_CONTEXT + b"\x00")
    for item in ordered:
        digest.update(
            canonical(
                {
                    "seq": item.seq,
                    "stream": item.segment.stream,
                    "rows": item.segment.rows,
                    "root": b64(item.segment.root),
                }
            )
        )
    seals = {"first": ordered[0].seq, "last": ordered[-1].seq} if ordered else None
    return {
        "seals": seals,
        "segments": len(ordered),
        "rows": sum(item.segment.rows for item in ordered),
        "segments_digest": b64(digest.digest()),
    }


def retire_body(
    chain: str,
    seq: int,
    *,
    table: str,
    partition: str,
    streams: Iterable[str],
    upper_bound: datetime,
    retention: int | None,
    segments: Iterable[SealedSegment],
) -> bytes:
    """Body of a retire block, written before a partition is dropped.

    It binds the drop to the chain: the partition, the streams it holds,
    and every segment of it sealed before the block (``retire_coverage``).
    A segment of the partition sealed after the block is not covered.

    Args:
        chain: The chain id.
        seq: The block's number.
        table: ``transaction`` or ``activity``.
        partition: Name of the partition, without schema.
        streams: The streams its rows belong to: ``transaction``, or
            ``activity.<severity>`` for each severity its parent holds.
        upper_bound: The partition's exclusive upper bound.
        retention: The retention it was dropped under, in whole seconds;
            ``None`` when it had none.
        segments: Every segment of the partition in the seal blocks before
            this one.
    """
    return _body(
        {
            "v": FORMAT_VERSION,
            "kind": "retire",
            "chain": chain,
            "seq": seq,
            "table": table,
            "partition": partition,
            "streams": sorted(streams),
            "upper_bound": rfc3339(upper_bound),
            "retention": retention,
            **retire_coverage(segments),
        }
    )


def block_hash(prev_hash: bytes, body: bytes) -> bytes:
    """The hash chaining a block to the one before it."""
    if len(prev_hash) != 32:
        raise ValueError("prev_hash is a 32-byte SHA-256 digest")
    return hashlib.sha256(BLOCK_CONTEXT + b"\x00" + prev_hash + body).digest()


def parse_body(body: bytes) -> dict[str, Any]:
    """Read a stored body back; it is valid JSON.

    Raises:
        ValueError: The body is not a JSON object.
    """
    parsed = json.loads(body.decode())
    if not isinstance(parsed, dict):
        raise ValueError("a block body is a JSON object")
    return parsed


def _body(fields: Mapping[str, object]) -> bytes:
    return canonical(fields)
