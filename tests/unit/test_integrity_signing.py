"""Signed notes, checkpoints and the Ed25519 reference, against golden vectors.

The notes follow c2sp.org/signed-note; the spec's own example is one of the
vectors. A change to any vector is a format change.
"""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import textwrap
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from audit_trail.integrity._checkpoint import Checkpoint
from audit_trail.integrity._ed25519 import Ed25519Signer, Ed25519Verifier
from audit_trail.integrity._note import (
    DASH,
    MAX_SIGNATURES,
    Note,
    NoteError,
    NoteSignature,
    parse_note,
    sign_note,
    verify_note,
)
from audit_trail.integrity._sign import (
    SignatureVerifier,
    Signer,
    block_signature_message,
    note_key_hash,
    sign_block,
    split_key_id,
)

VECTOR_DIR = Path(__file__).parent.parent / "fixtures" / "integrity" / "vectors"
VECTORS: dict[str, Any] = json.loads((VECTOR_DIR / "notes.json").read_text())
KEYS = VECTORS["keys"]
CHECKPOINT = VECTORS["checkpoint"]


def signer(index: int) -> Ed25519Signer:
    key = KEYS[index]
    return Ed25519Signer.from_seed(key["name"], bytes.fromhex(key["seed"]))


def verifier(*indexes: int) -> Ed25519Verifier:
    return Ed25519Verifier(KEYS[i]["vkey"] for i in indexes)


# -- the spec's example ------------------------------------------------------


def test_the_spec_example_verifies() -> None:
    example = VECTORS["spec_example"]
    note = parse_note(example["note"])
    assert note.text == "This is an example message.\n"
    assert verify_note(note, Ed25519Verifier([example["vkey"]])) == [
        "example.com/foo+530d903a"
    ]
    assert str(note) == example["note"]


def test_the_spec_example_fails_with_another_text() -> None:
    example = VECTORS["spec_example"]
    note = parse_note(example["note"].replace("example", "Example", 1))
    with pytest.raises(NoteError) as info:
        verify_note(note, Ed25519Verifier([example["vkey"]]))
    assert info.value.reason == "BAD_SIGNATURE"


# -- keys ----------------------------------------------------------------------


@pytest.mark.parametrize("index", [0, 1])
def test_key_vectors(index: int) -> None:
    key, made = KEYS[index], signer(index)
    assert made.key_id == key["key_id"]
    assert made.vkey == key["vkey"]
    assert made.skey == key["skey"]
    assert Ed25519Signer.from_skey(key["skey"]).vkey == key["vkey"]
    name, key_hash = split_key_id(made.key_id)
    assert name == key["name"]
    assert key_hash == note_key_hash(name, 0x01, made.public_key)


def test_the_reference_meets_the_protocols() -> None:
    assert isinstance(signer(0), Signer)
    assert isinstance(verifier(0), SignatureVerifier)


@pytest.mark.parametrize(
    "vkey",
    [
        "example.com/foo+530d903b+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
        "example.com/foo+530d903a+AukyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
        "example.com/foo+530D903A+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
        "example.com/foo+530d903a",
        "+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
    ],
    ids=["wrong hash", "wrong type", "upper hex", "no key", "no name"],
)
def test_a_bad_vkey_is_refused(vkey: str) -> None:
    with pytest.raises(ValueError, match=r"key|hash|Ed25519"):
        Ed25519Verifier([vkey])


def test_a_skey_with_a_wrong_hash_is_refused() -> None:
    skey = KEYS[0]["skey"].replace(KEYS[0]["key_id"], KEYS[0]["name"] + "+00000000")
    with pytest.raises(ValueError, match="hash"):
        Ed25519Signer.from_skey(skey)


@pytest.mark.parametrize(
    "name", ["", "a b", "a+b", "a\u00a0b", "a\x7fb", "a\x00b", "a\x1bb", "a\x85b"]
)
def test_key_names_follow_the_spec(name: str) -> None:
    with pytest.raises(ValueError, match="key name"):
        Ed25519Signer.generate(name)


@pytest.mark.parametrize("control", ["\x7f", "\x00", "\x1b", "\x9b"])
def test_a_note_with_a_control_character_in_a_key_name_is_refused(
    control: str,
) -> None:
    note = signed().replace(KEYS[0]["name"], KEYS[0]["name"] + control)
    with pytest.raises(NoteError) as info:
        parse_note(note)
    assert info.value.reason == "MALFORMED"


def test_two_keys_with_one_key_id_are_refused() -> None:
    # Two real Ed25519 keys whose 4-byte key hashes collide (found by a
    # birthday search over the seeds).
    first = Ed25519Signer.from_seed("audit.example/k", (36918).to_bytes(32, "big"))
    second = Ed25519Signer.from_seed("audit.example/k", (72891).to_bytes(32, "big"))
    assert first.key_id == second.key_id
    assert first.public_key != second.public_key
    with pytest.raises(ValueError, match="two different keys"):
        Ed25519Verifier([first.vkey, second.vkey])
    # The same key twice is one key.
    assert Ed25519Verifier([first.vkey, first.vkey]).key_algorithm(first.key_id)


# -- block signatures -----------------------------------------------------------


def test_block_signature_vector() -> None:
    vector = VECTORS["block_signature"]
    block_hash = bytes.fromhex(vector["block_hash"])
    message = block_signature_message(block_hash)
    assert message == b"sqlalchemy-audit-trail/block-signature/v1\x00" + block_hash
    assert message.hex() == vector["message"]
    signature, key_id, alg = sign_block(signer(0), block_hash)
    assert (base64.b64encode(signature).decode(), key_id, alg) == (
        vector["signature"],
        vector["key_id"],
        "ed25519",
    )
    assert verifier(0).verify(key_id, alg, message, signature)
    assert not verifier(0).verify(key_id, alg, message + b"x", signature)
    assert not verifier(1).verify(key_id, alg, message, signature)


# -- checkpoints ----------------------------------------------------------------


def vector_checkpoint() -> Checkpoint:
    return Checkpoint(
        CHECKPOINT["chain"],
        CHECKPOINT["seq"],
        bytes.fromhex(CHECKPOINT["block_hash"]),
        CHECKPOINT["xid_to"],
        datetime(2026, 11, 27, 10, 30, 0, 123456, tzinfo=UTC),
    )


def test_checkpoint_text_vector() -> None:
    checkpoint = vector_checkpoint()
    assert checkpoint.text == CHECKPOINT["text"]
    header, statement, end = checkpoint.text.split("\n")
    assert (header, end) == ("sqlalchemy-audit-trail/checkpoint/v1", "")
    assert json.loads(statement) == {
        "v": 1,
        "chain": CHECKPOINT["chain"],
        "seq": 3,
        "block_hash": base64.b64encode(checkpoint.block_hash).decode(),
        "xid_to": CHECKPOINT["xid_to"],
        "sealed_at": CHECKPOINT["sealed_at"],
    }


def test_checkpoint_note_vectors() -> None:
    checkpoint = vector_checkpoint()
    assert checkpoint.to_note() == CHECKPOINT["unsigned_note"] == CHECKPOINT["text"]
    assert checkpoint.signed([signer(0)]).to_note() == CHECKPOINT["signed_note"]
    cosigned = checkpoint.signed([signer(0), signer(1)]).to_note()
    assert cosigned == CHECKPOINT["cosigned_note"]
    # The frame, by the spec: text, blank line, one line per signature.
    text, signatures = cosigned.split("\n\n")
    assert text + "\n" == CHECKPOINT["text"]
    lines = signatures.splitlines()
    assert [line.split(" ")[:2] for line in lines] == [
        [DASH, KEYS[0]["name"]],
        [DASH, KEYS[1]["name"]],
    ]
    raw = base64.b64decode(lines[0].split(" ")[2])
    assert raw[:4].hex() == KEYS[0]["key_id"].rpartition("+")[2]
    assert len(raw) == 4 + 64


@pytest.mark.parametrize("name", ["unsigned_note", "signed_note", "cosigned_note"])
def test_a_checkpoint_round_trips_through_its_note(name: str) -> None:
    checkpoint = Checkpoint.from_note(CHECKPOINT[name])
    assert checkpoint.text == CHECKPOINT["text"]
    assert checkpoint.to_note() == CHECKPOINT[name]
    assert (checkpoint.seq, checkpoint.block_hash.hex(), checkpoint.xid_to) == (
        3,
        CHECKPOINT["block_hash"],
        CHECKPOINT["xid_to"],
    )
    assert checkpoint.sealed_at == vector_checkpoint().sealed_at


def test_key_rotation_on_a_cosigned_checkpoint() -> None:
    checkpoint = Checkpoint.from_note(CHECKPOINT["cosigned_note"])
    old, new = KEYS[0]["key_id"], KEYS[1]["key_id"]
    assert checkpoint.verify(verifier(0)) == [old]
    assert checkpoint.verify(verifier(1)) == [new]
    assert checkpoint.verify(verifier(0, 1)) == [old, new]
    # A key the note does not have is ignored; one it has is enough.
    other = Ed25519Signer.generate("audit.example/sealer-2028")
    assert checkpoint.verify(Ed25519Verifier([other.vkey, KEYS[1]["vkey"]])) == [new]
    with pytest.raises(NoteError) as info:
        checkpoint.verify(Ed25519Verifier([other.vkey]))
    assert info.value.reason == "UNKNOWN_KEY"


def test_one_bad_signature_of_a_known_key_rejects_the_note() -> None:
    good = Checkpoint.from_note(CHECKPOINT["cosigned_note"])
    first, second = good.signatures
    broken = NoteSignature(second.name, second.key_hash, bytes(64))
    checkpoint = Checkpoint.from_note(str(Note(good.text, (first, broken))))
    assert checkpoint.verify(verifier(0)) == [KEYS[0]["key_id"]]
    with pytest.raises(NoteError) as info:
        checkpoint.verify(verifier(0, 1))
    assert info.value.reason == "BAD_SIGNATURE"


def test_an_unsigned_checkpoint_has_no_known_key() -> None:
    checkpoint = Checkpoint.from_note(CHECKPOINT["unsigned_note"])
    with pytest.raises(NoteError) as info:
        checkpoint.verify(verifier(0))
    assert info.value.reason == "UNKNOWN_KEY"


def test_a_signature_with_a_known_name_and_another_hash_is_ignored() -> None:
    note = parse_note(CHECKPOINT["signed_note"])
    (signature,) = note.signatures
    other = NoteSignature(signature.name, b"\0\0\0\0", signature.signature)
    with pytest.raises(NoteError) as info:
        verify_note(Note(note.text, (other,)), verifier(0))
    assert info.value.reason == "UNKNOWN_KEY"


@pytest.mark.parametrize(
    "text",
    [
        CHECKPOINT["text"].replace('"seq":3', '"seq": 3'),
        CHECKPOINT["text"].replace("checkpoint/v1", "checkpoint/v2"),
        CHECKPOINT["text"].replace('"v":1', '"v":2'),
        CHECKPOINT["text"] + "more\n",
        CHECKPOINT["text"].replace('"seq":3', '"seq":"3"'),
        CHECKPOINT["text"].replace('"xid_to"', '"xid"'),
    ],
    ids=["not canonical", "header", "version", "third line", "type", "field"],
)
def test_a_statement_that_is_not_a_checkpoint_is_refused(text: str) -> None:
    with pytest.raises(NoteError) as info:
        Checkpoint.from_note(text)
    assert info.value.reason == "MALFORMED"


# -- the note frame -------------------------------------------------------------


def signed(text: str = "hello\n") -> str:
    return str(sign_note(text, [signer(0)]))


@pytest.mark.parametrize(
    "note",
    [
        "",
        "no newline",
        "tab\there\n",
        "text\n\n",
        signed().replace(DASH, "-"),
        signed().replace(f"{DASH} ", DASH),
        signed()[:-1] + "x\n",
        signed().replace(KEYS[0]["name"], "a+b"),
        signed().rstrip("\n").rstrip("=") + "\n",
        "text\n\n" + DASH + " name AAAA\n",
    ],
    ids=[
        "empty",
        "no final newline",
        "control character",
        "no signature after the blank line",
        "not an em dash",
        "no space after the dash",
        "not base64",
        "plus in the key name",
        "no padding",
        "no signature bytes",
    ],
)
def test_malformed_notes_are_refused(note: str) -> None:
    with pytest.raises(NoteError) as info:
        parse_note(note)
    assert info.value.reason == "MALFORMED"


def test_non_canonical_base64_is_refused() -> None:
    note = signed()
    line = note.split("\n\n")[1]
    encoded = line.split(" ")[2].rstrip("\n")
    raw = base64.b64decode(encoded)
    # 68 bytes: one padding character, so the last data character carries
    # two unused bits; setting one gives the same bytes, non-canonically.
    assert encoded.endswith("=")
    assert not encoded.endswith("==")
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    last = alphabet[alphabet.index(encoded[-2]) | 1]
    loose = encoded[:-2] + last + "="
    assert loose != encoded
    assert base64.b64decode(loose) == raw
    with pytest.raises(NoteError, match="canonical"):
        parse_note(note.replace(encoded, loose))


def test_the_text_may_hold_empty_lines() -> None:
    text = "first\n\nthird\n"
    note = parse_note(signed(text))
    assert note.text == text
    assert verify_note(note, verifier(0)) == [KEYS[0]["key_id"]]


def test_at_least_sixteen_signatures_are_read_and_too_many_refused() -> None:
    keys = [
        Ed25519Signer.from_seed(f"audit.example/k{n}", n.to_bytes(32, "big"))
        for n in range(MAX_SIGNATURES + 1)
    ]
    many = sign_note("hello\n", keys[:16])
    assert len(parse_note(str(many)).signatures) == 16
    too_many = sign_note("hello\n", keys)
    with pytest.raises(NoteError, match="more than"):
        parse_note(str(too_many))


def test_two_signatures_of_one_key_are_refused() -> None:
    note = signed()
    line = note.split("\n\n")[1]
    doubled = note + line
    with pytest.raises(NoteError) as info:
        parse_note(doubled)
    assert info.value.reason == "MALFORMED"
    # Also when the second line carries another signature of the same key.
    (signature,) = parse_note(note).signatures
    other = NoteSignature(signature.name, signature.key_hash, bytes(64))
    with pytest.raises(NoteError) as info:
        parse_note(str(Note("hello\n", (signature, other))))
    assert info.value.reason == "MALFORMED"
    with pytest.raises(NoteError) as info:
        verify_note(Note("hello\n", (signature, signature)), verifier(0))
    assert info.value.reason == "MALFORMED"
    with pytest.raises(NoteError, match="two signatures"):
        sign_note("hello\n", [signer(0), signer(0)])
    checkpoint = vector_checkpoint().signed([signer(0)])
    with pytest.raises(NoteError, match="two signatures"):
        checkpoint.signed([signer(0)])


# -- the optional dependency ---------------------------------------------------


def run_without_cryptography(code: str) -> subprocess.CompletedProcess[str]:
    """Run ``code`` in a fresh interpreter where ``cryptography`` is absent."""
    prelude = "import sys\nsys.modules['cryptography'] = None\n"
    return subprocess.run(
        [sys.executable, "-c", prelude + textwrap.dedent(code)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_the_core_does_not_import_cryptography() -> None:
    result = run_without_cryptography(
        """
        import importlib, pkgutil, sys
        import audit_trail, audit_trail.integrity
        for module in pkgutil.iter_modules(audit_trail.integrity.__path__):
            if module.name != "_ed25519":
                importlib.import_module(f"audit_trail.integrity.{module.name}")
        import audit_trail.maintenance, audit_trail.migrations
        assert sys.modules["cryptography"] is None
        print("ok")
        """
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"


def test_the_reference_names_the_extra_when_cryptography_is_missing() -> None:
    result = run_without_cryptography("import audit_trail.integrity._ed25519\n")
    assert result.returncode != 0
    assert "ImportError" in result.stderr
    assert "sqlalchemy-audit-trail[integrity]" in result.stderr
