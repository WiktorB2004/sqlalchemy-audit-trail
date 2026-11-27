"""C2SP signed notes: the frame a checkpoint travels in.

Follows https://c2sp.org/signed-note (the editor's copy
read on 2026-11-27):

    A signed note consists of a text ending in newline (U+000A), followed by
    a blank line (only a newline), followed by one or more signature lines
    of this form: em dash (U+2014), space (U+0020), key name, space,
    base64-encoded signature, newline.

- The note is UTF-8 with no ASCII control character but the newline.
- The text includes its final newline, not the blank line; the text is
  separated from the signatures by the last empty line.
- A key name is non-empty, with no Unicode space and no ``+``. DEL and C1
  controls are read; only keys made here refuse them (``check_key_name``).
- A signature is the base64 (RFC 4648 section 4, ``=`` padded, canonical:
  decoders reject other encodings) of the 4-byte big-endian key ID and the
  signature over the text.
- Verifiers ignore signatures of unknown keys, even with a known name or
  ID (not both), and even when a line repeats; they verify every one of a
  known key; one that fails rejects the note (the spec says SHOULD; here it
  always does), and a note with no verified signature of a known key is
  rejected. They accept at least 16 signatures; this one stops at
  ``MAX_SIGNATURES``. Two signatures of one known key (the same name and
  key ID) make a note malformed, so that no signature can be counted
  twice; the spec allows that, and a signer here never writes one.

A note without signatures is not a signed note. ``parse_note`` still reads
one, a text alone, so that a checkpoint exported without a key can be fed
back; ``verify_note`` rejects it.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

from audit_trail.integrity._codec import b64, decode_canonical
from audit_trail.integrity._sign import (
    SignatureVerifier,
    Signer,
    check_note_key_name,
    make_key_id,
    split_key_id,
)

DASH = "—"
"""The em dash that starts a signature line."""

MAX_SIGNATURES = 100
"""Most signatures read from one note; the spec asks for at least 16."""


class NoteError(ValueError):
    """A note that is not a well-formed signed note, or that fails to verify.

    Attributes:
        reason: ``MALFORMED``: not in the format. ``BAD_SIGNATURE``: a
            signature of a known key does not verify. ``UNKNOWN_KEY``: no
            signature is from a known key (or there is none).
    """

    def __init__(
        self, reason: Literal["MALFORMED", "BAD_SIGNATURE", "UNKNOWN_KEY"], message: str
    ) -> None:
        super().__init__(f"{reason}: {message}")
        self.reason = reason


@dataclass(frozen=True)
class NoteSignature:
    """One signature line.

    Attributes:
        name: The key name.
        key_hash: The 4-byte key ID.
        signature: The signature over the note text.
    """

    name: str
    key_hash: bytes
    signature: bytes

    @property
    def key_id(self) -> str:
        """``<key name>+<key hash as hex>``, as a ``Signer`` names its key."""
        return make_key_id(self.name, self.key_hash)

    def line(self) -> str:
        """The signature line, with its newline."""
        encoded = b64(self.key_hash + self.signature)
        return f"{DASH} {self.name} {encoded}\n"


@dataclass(frozen=True)
class Note:
    """A note: its text and its signatures.

    Attributes:
        text: The text, ending in a newline.
        signatures: The signature lines, in order.
    """

    text: str
    signatures: tuple[NoteSignature, ...] = ()

    def __str__(self) -> str:
        """The note as text: the text alone when it has no signature."""
        if not self.signatures:
            return self.text
        return self.text + "\n" + "".join(s.line() for s in self.signatures)


def check_text(text: str) -> None:
    """Refuse a note text the spec does not allow.

    Raises:
        NoteError: ``MALFORMED``: empty, without a final newline, or with a
            control character other than newline.
    """
    if not text or not text.endswith("\n"):
        raise NoteError("MALFORMED", "a note text ends in a newline")
    if any(ord(c) < 0x20 and c != "\n" for c in text):
        raise NoteError("MALFORMED", "a note has no control characters but newline")


def sign_note(text: str, signers: Iterable[Signer]) -> Note:
    """Sign a text with each signer, in order.

    Raises:
        NoteError: ``MALFORMED``: the text is not a valid note text.
        ValueError: A signer's ``key_id`` is not a valid key id.
    """
    check_text(text)
    signatures = []
    for signer in signers:
        name, key_hash = split_key_id(signer.key_id)
        signatures.append(
            NoteSignature(name, key_hash, bytes(signer.sign(text.encode())))
        )
    _check_unique(signatures)
    return Note(text, tuple(signatures))


def add_signatures(note: Note, signers: Iterable[Signer]) -> Note:
    """The note with more signatures over the same text.

    Raises:
        NoteError: ``MALFORMED``: a signer's key signed the note already.
    """
    more = sign_note(note.text, signers).signatures
    signed = {(s.name, s.key_hash) for s in note.signatures}
    for signature in more:
        if (signature.name, signature.key_hash) in signed:
            raise NoteError(
                "MALFORMED", f"two signatures of the key {signature.key_id}"
            )
    return Note(note.text, note.signatures + more)


def _check_unique(signatures: Iterable[NoteSignature]) -> None:
    """Refuse two signatures of one key: the same name and key ID."""
    seen: set[tuple[str, bytes]] = set()
    for signature in signatures:
        key = (signature.name, signature.key_hash)
        if key in seen:
            raise NoteError(
                "MALFORMED", f"two signatures of the key {signature.key_id}"
            )
        seen.add(key)


def parse_note(note: str) -> Note:
    """Read a note; one without a blank line is a text with no signature.

    Repeated signature lines are read: which keys are known, and so whether
    a repeat matters, is for ``verify_note``.

    Raises:
        NoteError: ``MALFORMED``: not a note in the format, or with more
            than ``MAX_SIGNATURES`` signatures.
    """
    if not isinstance(note, str):
        raise NoteError("MALFORMED", "a note is text")
    try:
        note.encode("utf-8")
    except UnicodeEncodeError:
        raise NoteError("MALFORMED", "a note is valid UTF-8") from None
    check_text(note)
    split = note.rfind("\n\n")
    if split < 0:
        return Note(note)
    text, lines = note[: split + 1], note[split + 2 :]
    if not lines:
        raise NoteError("MALFORMED", "a blank line with no signature after it")
    check_text(text)
    signatures = [_signature(line) for line in lines[:-1].split("\n")]
    if len(signatures) > MAX_SIGNATURES:
        raise NoteError("MALFORMED", f"more than {MAX_SIGNATURES} signatures")
    return Note(text, tuple(signatures))


def _signature(line: str) -> NoteSignature:
    prefix = DASH + " "
    if not line.startswith(prefix):
        raise NoteError("MALFORMED", "a signature line starts with an em dash")
    name, space, encoded = line[len(prefix) :].partition(" ")
    if not space:
        raise NoteError("MALFORMED", "a signature line has a key name and a signature")
    try:
        check_note_key_name(name)
    except ValueError as exc:
        raise NoteError("MALFORMED", str(exc)) from None
    raw = decode_canonical(encoded)
    if raw is None or len(raw) <= 4:
        raise NoteError("MALFORMED", "a signature is canonical base64 of 4+n bytes")
    return NoteSignature(name, raw[:4], raw[4:])


def verify_note(note: Note, verifier: SignatureVerifier) -> list[str]:
    """Check a note's signatures; the ``key_id`` of each that verified.

    Signatures of keys the verifier does not know are ignored, repeated
    ones too.

    Raises:
        NoteError: ``MALFORMED`` for two signatures of one known key;
            ``BAD_SIGNATURE`` when a signature of a known key does not
            verify; ``UNKNOWN_KEY`` when no signature is of a known key.
    """
    verified: list[str] = []
    message = note.text.encode()
    for signature in note.signatures:
        key_id = signature.key_id
        algorithm = verifier.key_algorithm(key_id)
        if algorithm is None:
            continue
        if key_id in verified:
            raise NoteError("MALFORMED", f"two signatures of the key {key_id}")
        if not verifier.verify(key_id, algorithm, message, signature.signature):
            raise NoteError(
                "BAD_SIGNATURE", f"the signature of {key_id} does not verify"
            )
        verified.append(key_id)
    if not verified:
        raise NoteError("UNKNOWN_KEY", "no signature of a known key")
    return verified
