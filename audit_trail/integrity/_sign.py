"""The signing hooks: who signs blocks and checkpoints, and who checks them.

The core never imports a crypto library: it calls a
``Signer`` and a ``SignatureVerifier`` given by the caller. The reference
implementation, Ed25519 with ``cryptography``, is in
``audit_trail.integrity.ed25519`` behind the
``sqlalchemy-audit-trail[integrity]`` extra; a KMS, an HSM or a sealer on
another machine implement the same two protocols.

Signing comes in tiers:

- no key: ``verify`` alone, and checkpoints stored off the database host;
- a key on the sealer host: blocks and checkpoints carry signatures, which
  attribute them, but a key on the database host itself adds no more;
- an external signer (KMS, HSM, a sealer on another machine): a rewrite of
  the chain is caught even between two checkpoints.

A key is named the way a C2SP signed note names it (c2sp.org/signed-note):
``key_id`` is ``<key name>+<key hash>``, the key name and the 4-byte key ID
as 8 lowercase hex digits; that is a verifier key without its last part, so
one name serves block signatures and checkpoint notes. For an Ed25519 key
the key hash is ``SHA-256(key name || 0x0A || 0x01 || public key)[:4]``.
"""

from __future__ import annotations

import hashlib
import unicodedata
from typing import Protocol, runtime_checkable

from audit_trail.integrity._codec import context

ED25519 = "ed25519"
"""``algorithm`` of an Ed25519 key."""

NOTE_SIGNATURE_TYPES: dict[str, int] = {ED25519: 0x01}
"""C2SP signature type bytes by algorithm (c2sp.org/signed-note)."""

BLOCK_SIGNATURE_CONTEXT = context("block-signature")
"""Domain separation string of a block signature."""


@runtime_checkable
class Signer(Protocol):
    """Signs blocks and checkpoints.

    Attributes:
        key_id: ``<key name>+<8 hex digits of the key hash>``; see the module
            documentation. Stored with every block it signs.
        algorithm: Name of the signature algorithm, such as ``"ed25519"``.
    """

    @property
    def key_id(self) -> str: ...

    @property
    def algorithm(self) -> str: ...

    def sign(self, message: bytes) -> bytes:
        """The signature of ``message``, without the key hash."""
        ...


@runtime_checkable
class SignatureVerifier(Protocol):
    """Checks signatures made by known keys."""

    def key_algorithm(self, key_id: str) -> str | None:
        """The algorithm of a known key; ``None`` for an unknown one."""
        ...

    def verify(
        self, key_id: str, algorithm: str, message: bytes, signature: bytes
    ) -> bool:
        """Whether ``signature`` is the signature of ``message`` by the key."""
        ...


def note_key_hash(name: str, signature_type: int, public_key: bytes) -> bytes:
    """The C2SP key ID of a key, 4 bytes.

    ``SHA-256(key name || 0x0A || signature type || public key)[:4]``, as
    c2sp.org/signed-note recommends.
    """
    check_key_name(name)
    digest = hashlib.sha256(
        name.encode() + b"\n" + bytes([signature_type]) + public_key
    ).digest()
    return digest[:4]


def make_key_id(name: str, key_hash: bytes) -> str:
    """``<key name>+<key hash as 8 hex digits>``.

    Takes any name a note may carry (``check_note_key_name``), so the key of
    every parsed signature line has an id.
    """
    check_note_key_name(name)
    if len(key_hash) != 4:
        raise ValueError("a key hash is 4 bytes")
    return f"{name}+{key_hash.hex()}"


def split_key_id(key_id: str) -> tuple[str, bytes]:
    """The key name and the 4-byte key hash of a ``key_id``.

    Raises:
        ValueError: Not ``<key name>+<8 lowercase hex digits>``.
    """
    name, plus, digits = key_id.rpartition("+")
    if (
        not plus
        or len(digits) != 8
        or digits != digits.lower()
        or not all(c in "0123456789abcdef" for c in digits)
    ):
        raise ValueError(
            f"key id {key_id!r} is not <key name>+<8 lowercase hex digits>"
        )
    check_key_name(name)
    return name, bytes.fromhex(digits)


def check_note_key_name(name: str) -> None:
    """Refuse a key name that c2sp.org/signed-note does not allow.

    The spec forbids only Unicode spaces and ``+``. A note holds no C0
    control character anyway; DEL and C1 controls are allowed, so a note
    signed by such a key still parses (``check_key_name`` is for keys made
    here).

    Raises:
        ValueError: Empty, or with a Unicode space or a ``+``.
    """
    if not name or "+" in name or any(c.isspace() for c in name):
        raise ValueError(f"key name {name!r} must be non-empty, without spaces or '+'")


def check_key_name(name: str) -> None:
    """Refuse a key name for a key made or loaded here.

    Stricter than the spec (``check_note_key_name``): control characters
    (DEL and the C0 and C1 ranges) are refused too, so a name of our own
    cannot hide in a log or a terminal.

    Raises:
        ValueError: Empty, or with a Unicode space, a control character or
            a ``+``.
    """
    if (
        not name
        or "+" in name
        or any(c.isspace() or unicodedata.category(c) == "Cc" for c in name)
    ):
        raise ValueError(
            f"key name {name!r} must be non-empty, without spaces, control "
            "characters or '+'"
        )


def block_signature_message(block_hash: bytes) -> bytes:
    """What a block signature signs: its ``block_hash``, domain-separated.

    ``"sqlalchemy-audit-trail/block-signature/v1" || 0x00 || block_hash``.
    The block hash covers the body and the hash of the block before, so a
    signature attests the chain up to the block.
    """
    if len(block_hash) != 32:
        raise ValueError("block_hash is a 32-byte SHA-256 digest")
    return BLOCK_SIGNATURE_CONTEXT + b"\x00" + block_hash


def sign_block(signer: Signer, block_hash: bytes) -> tuple[bytes, str, str]:
    """``(signature, key_id, alg)`` columns of a block signed by ``signer``.

    Raises:
        ValueError: The signer's ``key_id`` is not a valid key id.
    """
    split_key_id(signer.key_id)
    signature = signer.sign(block_signature_message(block_hash))
    return bytes(signature), signer.key_id, signer.algorithm
