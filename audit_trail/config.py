"""Library configuration: ``AuditTrail`` and per-model ``AuditOptions``."""

from __future__ import annotations

import json
from collections.abc import Callable, Collection
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine
    from sqlalchemy.ext.asyncio import AsyncEngine

OnError = Literal["log", "raise"]


@dataclass(frozen=True)
class AuditOptions:
    """Audit settings for one model, set as ``__audit__`` on the class.

    ``label``, ``scope`` and ``target`` run while the session flushes and get
    a read-only view of the instance instead of the instance itself. They may
    read only attributes already loaded on it: reading an expired or unloaded
    attribute emits no SQL, logs a warning on ``audit_trail.diff`` (once per
    model, attribute and option) and the option falls back (``label`` and
    ``target`` to ``None``, ``scope`` to the context). Reading a
    ``functools.cached_property`` raises ``AuditOptionError``. Any other
    exception they raise propagates and aborts the flush.

    Attributes:
        severity: Severity of the model's ``entity.*`` entries. ``None`` uses
            the configured default.
        verb_severity: Per-verb severity overrides, keyed by verb
            (for example ``{"entity.deleted": MySeverity.HIGH}``).
        track_relationships: Relationship names whose membership changes are
            recorded as ``{"added": [...], "removed": [...]}``.
        snapshot_on_load: JSON columns deep-copied on load and refresh, so an
            in-place mutation still has an old value.
        object_type: Name stored in ``object_type``. Defaults to the class name.
        label: Returns the object's label, stored in ``object_label``.
        scope: Returns the scope id, stored in ``scope_id``. Returning
            ``None`` means "no scope"; the scope comes from the context only
            when this option is not set or it read an attribute that is not
            loaded.
        target: Returns ``(type, id)`` of the parent object, or ``None``. An
            id of ``None`` also means no target; a tuple id is formatted as a
            composite ``object_id``.
    """

    severity: IntEnum | None = None
    verb_severity: dict[str, IntEnum] = field(default_factory=dict)
    track_relationships: Collection[str] = frozenset()
    snapshot_on_load: Collection[str] = frozenset()
    object_type: str | None = None
    label: Callable[[Any], str | None] | None = None
    scope: Callable[[Any], object] | None = None
    target: Callable[[Any], tuple[str, object] | None] | None = None


class AuditTrail:
    """Entry point of the library: configuration plus the public operations.

    Args:
        engine: Sync or async engine used for DDL and maintenance.
        schema: Database schema holding the audit tables.
        severities: The application's severity ``IntEnum``. ``None`` uses the
            built-in ``Severity``.
        durable_engine: Engine for durable writes. ``None`` builds a small
            separate pool from ``engine``'s URL.
        on_error: ``"log"`` keeps the business transaction alive when an audit
            write fails; ``"raise"`` propagates. ``fail_closed`` events always
            raise.
        pseudonymize_key: HMAC key as ``bytes`` (version 1) or
            ``{version: key}``.
        session_provider: Returns the current session, for hosts that keep it
            in a context variable.
        context_provider: Returns the current audit context.
        json_encoder: Extra encoder for types the built-in one does not handle.
        indexes: Names of the indexes to create. ``None`` uses the defaults.
        warn_on_bulk: Log a warning when a bulk ``update()``/``delete()`` hits
            an audited table.
        auto_create_partitions: Let durable writes create a missing partition
            and retry once. Needs DDL privileges.
        allow_scrub: Enable ``scrub``/``scrub_actor``.
    """

    def __init__(
        self,
        engine: Engine | AsyncEngine,
        *,
        schema: str = "audit",
        severities: type[IntEnum] | None = None,
        durable_engine: Engine | AsyncEngine | None = None,
        on_error: OnError = "log",
        pseudonymize_key: bytes | dict[int, bytes] | None = None,
        session_provider: Callable[[], Any] | None = None,
        context_provider: Callable[[], Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        indexes: Collection[str] | None = None,
        warn_on_bulk: bool = True,
        auto_create_partitions: bool = False,
        allow_scrub: bool = False,
    ) -> None:
        self.engine = engine
        self.schema = schema
        self.severities = severities
        self.durable_engine = durable_engine
        self.on_error: OnError = on_error
        self.pseudonymize_key = pseudonymize_key
        self.session_provider = session_provider
        self.context_provider = context_provider
        self.json_encoder = json_encoder
        self.indexes = indexes
        self.warn_on_bulk = warn_on_bulk
        self.auto_create_partitions = auto_create_partitions
        self.allow_scrub = allow_scrub
