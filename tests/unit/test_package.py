from __future__ import annotations

import subprocess
import sys

from sqlalchemy import create_engine

import audit_trail
from audit_trail import AuditTrail


def test_version_is_set() -> None:
    assert audit_trail.__version__


def test_audit_trail_keeps_defaults() -> None:
    audit = AuditTrail(create_engine("postgresql+psycopg://localhost/unused"))
    assert audit.schema == "audit"
    assert audit.on_error == "log"
    assert audit.warn_on_bulk is True
    assert audit.allow_scrub is False


def test_import_does_not_need_greenlet() -> None:
    # Sync-only hosts install without greenlet; importing the package must not
    # pull in sqlalchemy.ext.asyncio.
    code = "import sys, audit_trail; sys.exit('sqlalchemy.ext.asyncio' in sys.modules)"
    subprocess.run([sys.executable, "-c", code], check=True)
