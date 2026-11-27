"""Tamper evidence for the audit log.

With ``AuditTrail(integrity=Integrity())`` every audit row carries its
PostgreSQL transaction id (``xid``) and salted commitments to the parts of
the entry that scrubbing may erase. A sealer job (``maintenance.seal()``)
hashes the rows of finished transactions into blocks chained by hash, in the
block table; ``drop_expired`` appends a ``retire`` block before it drops a
partition, and ``scrub``/``scrub_actor`` delete the salt of each erased part
and stamp it with the scrub's own ``xid``. ``verify`` walks the chain,
rebuilds every block from the rows it can still read and reports every
break. ``export_checkpoint`` gives a signed statement of the head of the
chain to keep where the database cannot reach it.

This makes the log tamper-evident, not tamper-proof: a change is detected,
not prevented, and what verification can detect depends on where the
checkpoints and signing keys are kept. See the integrity guide.

The reference Ed25519 signer is in ``audit_trail.integrity.ed25519`` and
needs the ``sqlalchemy-audit-trail[integrity]`` extra; nothing else here
does.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from audit_trail.integrity._options import Integrity

if TYPE_CHECKING:
    from audit_trail.integrity._anchor import (
        Fork,
        ReplicationError,
        declare_fork,
        export_checkpoint,
    )
    from audit_trail.integrity._canonical import CanonicalEncodingError
    from audit_trail.integrity._checkpoint import Checkpoint
    from audit_trail.integrity._note import NoteError
    from audit_trail.integrity._seal import (
        Genesis,
        SealHealth,
        SealRefusedError,
        SealResult,
    )
    from audit_trail.integrity._sign import SignatureVerifier, Signer
    from audit_trail.integrity._verify import (
        ACKNOWLEDGEABLE,
        SCOPE_KEYS,
        Anchor,
        FailureKind,
        Finding,
        NoteKind,
        Status,
        VerificationReport,
    )
    from audit_trail.integrity._verify_db import (
        aacknowledge,
        acknowledge,
        averify,
        verify,
    )

# The rest loads on first use: ``verify`` and the checkpoint functions import
# ``audit_trail.maintenance``, which imports this package, and a writer needs
# none of them.
_LAZY = {
    "ACKNOWLEDGEABLE": "_verify",
    "SCOPE_KEYS": "_verify",
    "Anchor": "_verify",
    "CanonicalEncodingError": "_canonical",
    "Checkpoint": "_checkpoint",
    "FailureKind": "_verify",
    "Finding": "_verify",
    "Fork": "_anchor",
    "Genesis": "_seal",
    "NoteError": "_note",
    "NoteKind": "_verify",
    "ReplicationError": "_anchor",
    "SealHealth": "_seal",
    "SealRefusedError": "_seal",
    "SealResult": "_seal",
    "SignatureVerifier": "_sign",
    "Signer": "_sign",
    "Status": "_verify",
    "VerificationReport": "_verify",
    "aacknowledge": "_verify_db",
    "acknowledge": "_verify_db",
    "averify": "_verify_db",
    "declare_fork": "_anchor",
    "export_checkpoint": "_anchor",
    "verify": "_verify_db",
}


def __getattr__(name: str) -> Any:
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(importlib.import_module(f"{__name__}.{module}"), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *_LAZY})


__all__ = [
    "ACKNOWLEDGEABLE",
    "SCOPE_KEYS",
    "Anchor",
    "CanonicalEncodingError",
    "Checkpoint",
    "FailureKind",
    "Finding",
    "Fork",
    "Genesis",
    "Integrity",
    "NoteError",
    "NoteKind",
    "ReplicationError",
    "SealHealth",
    "SealRefusedError",
    "SealResult",
    "SignatureVerifier",
    "Signer",
    "Status",
    "VerificationReport",
    "aacknowledge",
    "acknowledge",
    "averify",
    "declare_fork",
    "export_checkpoint",
    "verify",
]
