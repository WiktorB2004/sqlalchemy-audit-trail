"""The reference signer and verifier: Ed25519, with ``cryptography``.

Needs the ``sqlalchemy-audit-trail[integrity]`` extra; importing this module
without it raises ``ImportError`` naming the extra. The rest of the library
never imports it or ``cryptography``.

Keys are named the way C2SP signed notes name them (c2sp.org/signed-note),
so checkpoints signed with them can be checked with existing note tooling:

- the verifier key (``vkey``) is ``<name>+<key hash>+base64(0x01 || public
  key)``;
- the signer key (``skey``) is ``PRIVATE+KEY+<name>+<key hash>+base64(0x01
  || 32-byte seed)``.

A key on the database host adds attribution only: whoever controls the host
can use it. For a signature that catches a rewritten chain, keep the key
elsewhere, or implement ``Signer`` against a KMS or HSM.
"""

from __future__ import annotations

from audit_trail.integrity._ed25519 import Ed25519Signer, Ed25519Verifier

__all__ = ["Ed25519Signer", "Ed25519Verifier"]
