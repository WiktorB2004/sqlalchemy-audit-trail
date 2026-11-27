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
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from audit_trail.integrity._canonical import CanonicalEncodingError, canonical
from audit_trail.integrity._commit import ACTOR_FIELDS, leaf_hash

FORMAT_VERSION = 1
"""Value of ``v`` in every body."""

BLOCK_CONTEXT = b"sqlalchemy-audit-trail/block/v1"
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


def rfc3339(value: datetime) -> str:
    """A timestamp as RFC 3339 UTC text with six fraction digits and ``Z``.

    Raises:
        CanonicalEncodingError: The timestamp is naive.
    """
    if value.tzinfo is None or value.utcoffset() is None:
        raise CanonicalEncodingError("cannot encode a naive timestamp")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _value(value: object) -> object:
    match value:
        case datetime():
            return rfc3339(value)
        case UUID():
            return str(value)
        case _:
            return value


def node_hash(left: bytes, right: bytes) -> bytes:
    """The RFC 6962 hash of an inner node."""
    return hashlib.sha256(b"\x01" + left + right).digest()


class MerkleTree:
    """The RFC 6962 Merkle tree hash of leaves added one at a time.

    Holds one hash per set bit of the leaf count, so memory is O(log n)
    however many leaves a segment has.
    """

    def __init__(self) -> None:
        self.size = 0
        # (leaf count, hash) of perfect subtrees, largest first.
        self._stack: list[tuple[int, bytes]] = []

    def add(self, leaf: bytes) -> None:
        """Append a leaf hash (from ``leaf_hash``)."""
        self.size += 1
        count, digest = 1, leaf
        while self._stack and self._stack[-1][0] == count:
            left_count, left = self._stack.pop()
            count, digest = left_count + count, node_hash(left, digest)
        self._stack.append((count, digest))

    def root(self) -> bytes:
        """The tree hash; ``SHA-256("")`` for no leaves, as RFC 6962 has it."""
        if not self._stack:
            return hashlib.sha256(b"").digest()
        digest = self._stack[-1][1]
        for _count, left in reversed(self._stack[:-1]):
            digest = node_hash(left, digest)
        return digest


def merkle_root(leaves: Iterable[bytes]) -> bytes:
    """The RFC 6962 Merkle tree hash of a sequence of leaf hashes."""
    tree = MerkleTree()
    for leaf in leaves:
        tree.add(leaf)
    return tree.root()


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


def b64(raw: bytes) -> str:
    """Base64 text of a hash, as bodies hold it."""
    return base64.b64encode(raw).decode("ascii")


def _body(fields: Mapping[str, object]) -> bytes:
    return canonical(fields)
