"""The reference signer and verifier: Ed25519, with ``cryptography``.

Needs the ``sqlalchemy-audit-trail[integrity]`` extra; the
rest of the library never imports this module or ``cryptography``.

Keys are named as C2SP signed notes name them (c2sp.org/signed-note):

- a verifier key ("vkey") is ``<name>+<key hash>+base64(0x01 || public
  key)``, the key hash being ``SHA-256(name || 0x0A || 0x01 || public
  key)[:4]`` in hex;
- a signer key ("skey") is ``PRIVATE+KEY+<name>+<key hash>+base64(0x01 ||
  32-byte seed)``, the encoding of Go's ``golang.org/x/mod/sumdb/note``.

So the notes and keys work with the existing note tooling.
"""

from __future__ import annotations

from collections.abc import Iterable

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )
except ImportError as exc:  # pragma: no cover - exercised in a subprocess
    raise ImportError(
        "the Ed25519 signer needs the cryptography package; install "
        "sqlalchemy-audit-trail[integrity]"
    ) from exc

from audit_trail.integrity._codec import b64, decode_strict
from audit_trail.integrity._sign import (
    ED25519,
    NOTE_SIGNATURE_TYPES,
    make_key_id,
    note_key_hash,
    split_key_id,
)

_TYPE = NOTE_SIGNATURE_TYPES[ED25519]
_SKEY_PREFIX = "PRIVATE+KEY+"


class Ed25519Signer:
    """Signs with an Ed25519 private key.

    Args:
        name: The key name, such as ``"audit.example.com/sealer-2026"``: no
            spaces and no ``+``. A new name for each new key makes rotation
            easy to follow.
        private_key: The key.

    Attributes:
        name: The key name.
        key_id: ``<name>+<key hash>``.
        algorithm: ``"ed25519"``.
    """

    algorithm = ED25519

    def __init__(self, name: str, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key
        self.name = name
        self.public_key = private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        self.key_id = make_key_id(name, note_key_hash(name, _TYPE, self.public_key))

    @classmethod
    def generate(cls, name: str) -> Ed25519Signer:
        """A signer with a new random key."""
        return cls(name, Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, name: str, seed: bytes) -> Ed25519Signer:
        """A signer from the 32-byte RFC 8032 private key (the seed)."""
        return cls(name, Ed25519PrivateKey.from_private_bytes(seed))

    @classmethod
    def from_skey(cls, skey: str) -> Ed25519Signer:
        """A signer from its ``PRIVATE+KEY+...`` encoding (see ``skey``).

        Raises:
            ValueError: Not an Ed25519 signer key, or the key hash does not
                match the key.
        """
        if not skey.startswith(_SKEY_PREFIX):
            raise ValueError("a signer key starts with PRIVATE+KEY+")
        name, key_hash, material = _parts(skey.removeprefix(_SKEY_PREFIX))
        signer = cls.from_seed(name, material)
        if signer.key_id != make_key_id(name, key_hash):
            raise ValueError("the signer key's hash does not match its key")
        return signer

    @property
    def skey(self) -> str:
        """The signer key as text; keep it secret."""
        seed = self._key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        return _SKEY_PREFIX + self.key_id + "+" + b64(bytes([_TYPE]) + seed)

    @property
    def vkey(self) -> str:
        """The verifier key as text, for ``Ed25519Verifier``."""
        return self.key_id + "+" + b64(bytes([_TYPE]) + self.public_key)

    def sign(self, message: bytes) -> bytes:
        """The 64-byte RFC 8032 signature of ``message``."""
        return self._key.sign(message)


class Ed25519Verifier:
    """Checks Ed25519 signatures of known keys.

    Args:
        vkeys: The verifier keys, as ``Ed25519Signer.vkey`` gives them. Give
            the old keys with the new one while blocks or checkpoints signed
            by them are still checked.

    Raises:
        ValueError: A key is not an Ed25519 verifier key, its key hash does
            not match it, or two keys have one ``key_id`` (a collision of
            the 4-byte key hash): a signature could not tell them apart.
    """

    def __init__(self, vkeys: Iterable[str]) -> None:
        self._keys: dict[str, Ed25519PublicKey] = {}
        self._material: dict[str, bytes] = {}
        for vkey in vkeys:
            name, key_hash, material = _parts(vkey)
            if note_key_hash(name, _TYPE, material) != key_hash:
                raise ValueError(f"the key hash of {vkey!r} does not match its key")
            key_id = make_key_id(name, key_hash)
            if self._material.setdefault(key_id, material) != material:
                raise ValueError(f"two different keys have the key id {key_id}")
            self._keys[key_id] = Ed25519PublicKey.from_public_bytes(material)

    def key_algorithm(self, key_id: str) -> str | None:
        """``"ed25519"`` for a known key, else ``None``."""
        return ED25519 if key_id in self._keys else None

    def verify(
        self, key_id: str, algorithm: str, message: bytes, signature: bytes
    ) -> bool:
        """Whether ``signature`` is the key's Ed25519 signature of ``message``."""
        key = self._keys.get(key_id)
        if key is None or algorithm != ED25519:
            return False
        try:
            key.verify(signature, message)
        except InvalidSignature:
            return False
        return True


def _parts(text: str) -> tuple[str, bytes, bytes]:
    """``(name, key hash, 32-byte key)`` of ``<name>+<hash>+<base64>``."""
    # The name has no "+"; the base64 may.
    parts = text.split("+", 2)
    if len(parts) != 3:
        raise ValueError("a key is <name>+<key hash>+<base64 key>")
    name, key_hash = split_key_id(f"{parts[0]}+{parts[1]}")
    encoded = parts[2]
    raw = decode_strict(encoded)
    if raw is None:
        raise ValueError("the key material is not base64")
    if b64(raw) != encoded or len(raw) != 33 or raw[0] != _TYPE:
        raise ValueError("not an Ed25519 key: base64 of 0x01 and 32 bytes")
    return name, key_hash, raw[1:]
