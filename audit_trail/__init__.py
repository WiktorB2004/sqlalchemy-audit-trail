"""Audit trail for SQLAlchemy on PostgreSQL."""

from importlib.metadata import PackageNotFoundError, version

from audit_trail.checks import ModelIssue, check_models
from audit_trail.config import AuditOptions, AuditTrail, Target
from audit_trail.context import Actor, AuditContext
from audit_trail.diff import AuditOptionError, FieldPolicyError
from audit_trail.events import AuditEvent, Severity, event
from audit_trail.mixin import Audited
from audit_trail.privacy import ScrubNotAllowedError, ScrubResult
from audit_trail.query import (
    ALL_HISTORY,
    AccessCount,
    ActivityDetail,
    AllHistory,
    Cursor,
    FieldLabels,
    Group,
    LabelResolver,
    Page,
    RelationshipLabels,
    TransactionHeader,
    Visibility,
)
from audit_trail.serialization import Pseudonymized
from audit_trail.writer import AuditWriteError

try:
    __version__ = version("sqlalchemy-audit-trail")
except PackageNotFoundError:  # pragma: no cover - running from a source tree
    __version__ = "0.0.0"

__all__ = [
    "ALL_HISTORY",
    "AccessCount",
    "ActivityDetail",
    "Actor",
    "AllHistory",
    "AuditContext",
    "AuditEvent",
    "AuditOptionError",
    "AuditOptions",
    "AuditTrail",
    "AuditWriteError",
    "Audited",
    "Cursor",
    "FieldLabels",
    "FieldPolicyError",
    "Group",
    "LabelResolver",
    "ModelIssue",
    "Page",
    "Pseudonymized",
    "RelationshipLabels",
    "ScrubNotAllowedError",
    "ScrubResult",
    "Severity",
    "Target",
    "TransactionHeader",
    "Visibility",
    "__version__",
    "check_models",
    "event",
]
