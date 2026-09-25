"""Audit trail for SQLAlchemy on PostgreSQL."""

from importlib.metadata import PackageNotFoundError, version

from audit_trail.config import AuditOptions, AuditTrail

try:
    __version__ = version("sqlalchemy-audit-trail")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0"

__all__ = ["AuditOptions", "AuditTrail", "__version__"]
