"""Checkpoints: the head of the chain, signed, for keeping off the database.

A checkpoint states which block was the head of the chain
at a moment. Kept where whoever can rewrite the database cannot reach it, it
lets ``verify`` catch a chain rewritten or cut short since (``CHAIN_MISMATCH``
and ``TRUNCATED``).

Its text is the library's own statement, two lines:

    sqlalchemy-audit-trail/checkpoint/v1
    {"block_hash":"<base64>","chain":"<uuid>","incarnation":1,...}

the second being the ``canonical`` JSON of ``{v, chain, seq, block_hash,
xid_to, sealed_at, incarnation}``. ``incarnation`` is the one the chain was
in when the checkpoint was taken: a fork explains a checkpoint only from an
incarnation before its own, never one taken after it. It travels as a C2SP
signed note (``_note``), so existing note tooling can check the signatures.
It is not a C2SP tlog-checkpoint: the head is a hash chain, not a Merkle
tree over the blocks, so there is no tree size and no consistency proof. A checkpoint
exported without a key is the text alone.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from audit_trail.integrity._block import FORMAT_VERSION
from audit_trail.integrity._canonical import canonical
from audit_trail.integrity._codec import (
    b64,
    context,
    decode_strict,
    is_int,
    parse_rfc3339,
    rfc3339,
)
from audit_trail.integrity._note import (
    Note,
    NoteError,
    NoteSignature,
    add_signatures,
    parse_note,
    verify_note,
)
from audit_trail.integrity._sign import SignatureVerifier, Signer

HEADER = context("checkpoint").decode()
"""First line of a checkpoint's text."""

_FIELDS = ("block_hash", "chain", "incarnation", "sealed_at", "seq", "v", "xid_to")


@dataclass(frozen=True)
class Checkpoint:
    """A checkpoint of the chain.

    Attributes:
        chain: The chain id.
        seq: The block it names, a ``checkpoint`` block when exported.
        block_hash: That block's hash.
        xid_to: The ``xid`` the chain was sealed up to (exclusive) then.
        sealed_at: When the block was written, as the database had it.
        incarnation: The incarnation of the chain then: 1 before any fork,
            then the number of the newest fork block's.
        signatures: The note's signature lines; empty when unsigned.
    """

    chain: str
    seq: int
    block_hash: bytes
    xid_to: int
    sealed_at: datetime
    incarnation: int = 1
    signatures: tuple[NoteSignature, ...] = ()

    @property
    def text(self) -> str:
        """The statement: the note text, two lines."""
        statement = canonical(
            {
                "v": FORMAT_VERSION,
                "chain": self.chain,
                "seq": self.seq,
                "block_hash": b64(self.block_hash),
                "xid_to": self.xid_to,
                "sealed_at": rfc3339(self.sealed_at),
                "incarnation": self.incarnation,
            }
        )
        return f"{HEADER}\n{statement.decode()}\n"

    @property
    def note(self) -> Note:
        """The checkpoint as a note."""
        return Note(self.text, self.signatures)

    def to_note(self) -> str:
        """The signed note to store; the text alone when unsigned."""
        return str(self.note)

    def signed(self, signers: Iterable[Signer]) -> Checkpoint:
        """The checkpoint with a signature by each of ``signers`` added."""
        note = add_signatures(self.note, signers)
        return _replace_signatures(self, note.signatures)

    def verify(self, verifier: SignatureVerifier) -> list[str]:
        """Check the signatures; the ``key_id`` of each that verified.

        Raises:
            NoteError: ``BAD_SIGNATURE`` or ``UNKNOWN_KEY``.
        """
        return verify_note(self.note, verifier)

    @classmethod
    def from_note(cls, note: str) -> Checkpoint:
        """Read a checkpoint back from ``to_note``.

        Signatures are read, not checked; ``verify`` checks them, with the
        keys trusted for it.

        Raises:
            NoteError: ``MALFORMED``: not a note, or its text is not a
                checkpoint statement of this format.
        """
        parsed = parse_note(note)
        checkpoint = _statement(parsed.text)
        if checkpoint.text != parsed.text:
            raise NoteError("MALFORMED", "the checkpoint statement is not canonical")
        return _replace_signatures(checkpoint, parsed.signatures)


def _replace_signatures(
    checkpoint: Checkpoint, signatures: tuple[NoteSignature, ...]
) -> Checkpoint:
    return Checkpoint(
        checkpoint.chain,
        checkpoint.seq,
        checkpoint.block_hash,
        checkpoint.xid_to,
        checkpoint.sealed_at,
        checkpoint.incarnation,
        signatures,
    )


def _statement(text: str) -> Checkpoint:
    def malformed(why: str) -> NoteError:
        return NoteError("MALFORMED", f"not a checkpoint: {why}")

    header, _, rest = text.partition("\n")
    if header != HEADER:
        raise malformed(f"the first line is not {HEADER}")
    line, _, tail = rest.partition("\n")
    if tail:
        raise malformed("the text has more than two lines")
    try:
        fields: Any = json.loads(line)
    except ValueError:
        raise malformed("the statement is not JSON") from None
    if not isinstance(fields, dict) or sorted(fields) != list(_FIELDS):
        raise malformed("the statement has other fields")
    if fields["v"] != FORMAT_VERSION:
        raise malformed("unknown format version")
    chain, seq, xid_to = fields["chain"], fields["seq"], fields["xid_to"]
    incarnation = fields["incarnation"]
    if not isinstance(chain, str) or not all(
        is_int(value) for value in (seq, xid_to, incarnation)
    ):
        raise malformed("chain, seq, xid_to or incarnation has the wrong type")
    block_hash = decode_strict(fields["block_hash"], 32)
    sealed_at = parse_rfc3339(fields["sealed_at"])
    if block_hash is None or sealed_at is None or seq < 1 or incarnation < 1:
        raise malformed("block_hash, sealed_at, seq or incarnation is invalid")
    return Checkpoint(chain, seq, block_hash, xid_to, sealed_at, incarnation)
