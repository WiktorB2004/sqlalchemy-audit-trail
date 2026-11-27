"""The public surface of ``audit_trail.integrity``."""

from __future__ import annotations

import inspect
import subprocess
import sys
import textwrap
from enum import IntEnum
from pathlib import Path

import pytest
from sqlalchemy import create_engine

import audit_trail
from audit_trail import AuditTrail, integrity
from audit_trail.integrity import (
    _anchor,
    _canonical,
    _checkpoint,
    _note,
    _options,
    _seal,
    _sign,
    _verify,
    _verify_db,
)
from audit_trail.maintenance import _DEFAULT_CHUNK_ROWS

PUBLIC = {
    "ACKNOWLEDGEABLE": _verify,
    "SCOPE_KEYS": _verify,
    "Anchor": _verify,
    "CanonicalEncodingError": _canonical,
    "Checkpoint": _checkpoint,
    "FailureKind": _verify,
    "Finding": _verify,
    "Fork": _anchor,
    "Genesis": _seal,
    "Integrity": _options,
    "NoteError": _note,
    "NoteKind": _verify,
    "ReplicationError": _anchor,
    "SealHealth": _seal,
    "SealRefusedError": _seal,
    "SealResult": _seal,
    "SignatureVerifier": _sign,
    "Signer": _sign,
    "Status": _verify,
    "VerificationReport": _verify,
    "aacknowledge": _verify_db,
    "acknowledge": _verify_db,
    "averify": _verify_db,
    "declare_fork": _anchor,
    "export_checkpoint": _anchor,
    "verify": _verify_db,
}

ROOT = Path(__file__).parents[2] / "audit_trail"


def run(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_all_lists_the_public_names() -> None:
    assert set(integrity.__all__) == set(PUBLIC)


@pytest.mark.parametrize("name", sorted(PUBLIC))
def test_each_name_is_the_implementation(name: str) -> None:
    assert getattr(integrity, name) is getattr(PUBLIC[name], name)
    assert name in dir(integrity)


def test_an_unknown_name_raises_attribute_error() -> None:
    with pytest.raises(AttributeError, match="no attribute 'seal_columns'"):
        integrity.seal_columns  # noqa: B018


def test_the_package_exports_integrity() -> None:
    assert "Integrity" in audit_trail.__all__
    assert audit_trail.Integrity is integrity.Integrity


def test_importing_integrity_needs_no_asyncio_and_no_crypto() -> None:
    # Sync-only hosts lack greenlet, and the extra is optional.
    result = run(
        """
        import sys
        import audit_trail.integrity
        from audit_trail.integrity import Checkpoint, Integrity, verify
        assert "sqlalchemy.ext.asyncio" not in sys.modules, "asyncio"
        assert "cryptography" not in sys.modules, "cryptography"
        """
    )
    assert result.returncode == 0, result.stderr


def test_the_ed25519_reference_needs_the_extra() -> None:
    from audit_trail.integrity import _ed25519, ed25519

    assert ed25519.__all__ == ["Ed25519Signer", "Ed25519Verifier"]
    assert ed25519.Ed25519Signer is _ed25519.Ed25519Signer
    assert ed25519.Ed25519Verifier is _ed25519.Ed25519Verifier
    assert "ed25519" not in integrity.__all__
    result = run(
        """
        import sys
        sys.modules["cryptography"] = None
        import audit_trail.integrity.ed25519
        """
    )
    assert result.returncode != 0
    assert "sqlalchemy-audit-trail[integrity]" in result.stderr


def test_the_reference_implements_the_protocols() -> None:
    from audit_trail.integrity.ed25519 import Ed25519Signer, Ed25519Verifier

    signer = Ed25519Signer.generate("audit.example/test")
    assert isinstance(signer, integrity.Signer)
    assert isinstance(Ed25519Verifier([signer.vkey]), integrity.SignatureVerifier)


class Level(IntEnum):
    LOW = 1
    HIGH = 9


def test_audit_trail_passes_its_system_severity_to_maintenance() -> None:
    engine = create_engine("postgresql+psycopg://localhost/unused")
    default = AuditTrail(engine, events=[], severities=Level)
    assert default.maintenance.system_severity == 9
    chosen = AuditTrail(engine, events=[], severities=Level, system_severity=Level.LOW)
    assert chosen.maintenance.system_severity == 1


def test_manager_methods_take_verify_defaults() -> None:
    assert _DEFAULT_CHUNK_ROWS == _verify_db.DEFAULT_CHUNK_ROWS
    for name in ("verify", "averify", "acknowledge", "aacknowledge"):
        method = getattr(audit_trail.maintenance.PartitionManager, name)
        chunk = inspect.signature(method).parameters["chunk_rows"]
        assert chunk.default == _DEFAULT_CHUNK_ROWS, name


def test_no_docstring_calls_the_feature_private() -> None:
    for path in ROOT.rglob("*.py"):
        assert "private for now" not in path.read_text().lower(), path
