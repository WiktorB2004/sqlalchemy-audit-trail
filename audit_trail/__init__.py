"""Audit trail for SQLAlchemy on PostgreSQL."""

from importlib.metadata import PackageNotFoundError, version

from audit_trail.checks import ModelIssue, check_models
from audit_trail.config import AuditOptions, AuditTrail
from audit_trail.context import Actor, AuditContext
from audit_trail.diff import AuditOptionError, FieldPolicyError
from audit_trail.events import AuditEvent, Severity, event
from audit_trail.mixin import Audited
from audit_trail.serialization import Pseudonymized

try:
    __version__ = version("sqlalchemy-audit-trail")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0"

__all__ = [
    "Actor",
    "AuditContext",
    "AuditEvent",
    "AuditOptionError",
    "AuditOptions",
    "AuditTrail",
    "Audited",
    "FieldPolicyError",
    "ModelIssue",
    "Pseudonymized",
    "Severity",
    "__version__",
    "check_models",
    "event",
]
