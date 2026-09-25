"""Audit trail for SQLAlchemy on PostgreSQL."""

from importlib.metadata import PackageNotFoundError, version

from audit_trail.config import AuditOptions, AuditTrail
from audit_trail.context import Actor, AuditContext
from audit_trail.serialization import Pseudonymized

try:
    __version__ = version("sqlalchemy-audit-trail")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0"

__all__ = [
    "Actor",
    "AuditContext",
    "AuditOptions",
    "AuditTrail",
    "Pseudonymized",
    "__version__",
]
