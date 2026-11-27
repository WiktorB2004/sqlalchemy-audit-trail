"""The RFC 6962 Merkle tree hash.

Leaves are hashed by the caller (``_commit.leaf_hash``, with its ``0x00``
prefix); inner nodes are ``SHA-256(0x01 || left || right)``.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable


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
