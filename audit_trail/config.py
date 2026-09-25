"""Library configuration: ``AuditTrail`` and per-model ``AuditOptions``."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Literal, NamedTuple

from audit_trail.context import Actor, resolve_context
from audit_trail.context import bind as _bind
from audit_trail.context import context as _context
from audit_trail.context import set_actor as _set_actor
from audit_trail.events import (
    RESERVED_PREFIXES,
    AuditEvent,
    EventRegistry,
    Severity,
    resolve_write_flags,
    validate_payload,
)
from audit_trail.maintenance import PartitionManager
from audit_trail.serialization import KeyRing
from audit_trail.serialization import pseudonymize as _pseudonymize
from audit_trail.tables import build_tables

if TYPE_CHECKING:
    from pydantic import BaseModel
    from sqlalchemy.engine import Engine
    from sqlalchemy.ext.asyncio import AsyncEngine
    from sqlalchemy.orm import Session, sessionmaker

OnError = Literal["log", "raise"]


class Target(NamedTuple):
    """A parent object referred to by type name and primary key.

    Returned by the ``target`` option and accepted by ``AuditTrail.log``.
    A plain ``(type, id)`` tuple works too.

    Attributes:
        type: Name stored in ``target_type``.
        id: The primary key; a tuple for a composite key. ``None`` means no
            target.
    """

    type: str
    id: object


@dataclass(frozen=True)
class AuditOptions:
    """Audit settings for one model, set as ``__audit__`` on the class.

    ``label``, ``scope`` and ``target`` run while the session flushes and get
    a read-only view of the instance instead of the instance itself. They may
    read only attributes already loaded on it: reading an expired or unloaded
    attribute emits no SQL, logs a warning on ``audit_trail.diff`` (once per
    model, attribute and option) and the option falls back (``label`` and
    ``target`` to ``None``, ``scope`` to the context). A column that was
    never set on a new instance reads as ``None``, as stored, unless it has a
    server-side default. Reading a
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
        target: Returns the parent object as a ``Target`` (or a plain
            ``(type, id)`` tuple), or ``None``. An id of ``None`` also means
            no target; a tuple id is formatted as a composite ``object_id``.
    """

    severity: IntEnum | None = None
    verb_severity: dict[str, IntEnum] = field(default_factory=dict)
    track_relationships: Collection[str] = frozenset()
    snapshot_on_load: Collection[str] = frozenset()
    object_type: str | None = None
    label: Callable[[Any], str | None] | None = None
    scope: Callable[[Any], object] | None = None
    target: Callable[[Any], Target | tuple[str, object] | None] | None = None


class AuditTrail:
    """Entry point of the library: configuration plus the public operations.

    Args:
        engine: Sync or async engine used for DDL and maintenance.
        schema: Database schema holding the audit tables.
        severities: The application's severity ``IntEnum``. ``None`` uses the
            built-in ``Severity``.
        default_severity: Severity of ``entity.*`` entries whose model sets
            none. ``None`` uses the lowest member of ``severities``.
        system_severity: Severity of the library's own ``audit.*`` events.
            ``None`` uses the highest member of ``severities``.
        events: Event classes to register. ``None`` registers every
            ``AuditEvent`` subclass with members defined when the
            ``AuditTrail`` is created, so import them first or list them here.
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
        global_redact: Attribute keys or column names redacted in
            ``entity.*`` changes when the column has no explicit policy. A
            safety net, not a replacement for per-column policies.
        warn_on_bulk: Log a warning when a bulk ``update()``/``delete()`` hits
            an audited table.
        auto_create_partitions: Let durable writes create a missing partition
            and retry once. Needs DDL privileges.
        allow_scrub: Enable ``scrub``/``scrub_actor``.

    Attributes:
        severities: The severity enum in use.
        registry: The registered events.
        tables: The audit tables built from ``schema`` and ``indexes``.
        keys: Key ring built from ``pseudonymize_key``, or ``None``.
        maintenance: Partition management on ``engine``, for example
            ``audit.maintenance.ensure_partitions()``.

    Raises:
        EventRegistryError: An event or a severity setting is invalid.
        ValueError: A table name or an index key is invalid, or
            ``pseudonymize_key`` is too short.
        TypeError: ``pseudonymize_key`` has the wrong type.
    """

    context = staticmethod(_context)
    set_actor = staticmethod(_set_actor)
    bind = staticmethod(_bind)

    def __init__(
        self,
        engine: Engine | AsyncEngine,
        *,
        schema: str = "audit",
        severities: type[IntEnum] | None = None,
        default_severity: IntEnum | None = None,
        system_severity: IntEnum | None = None,
        events: Iterable[type[AuditEvent]] | None = None,
        durable_engine: Engine | AsyncEngine | None = None,
        on_error: OnError = "log",
        pseudonymize_key: bytes | dict[int, bytes] | None = None,
        session_provider: Callable[[], Any] | None = None,
        context_provider: Callable[[], Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        indexes: Collection[str] | None = None,
        global_redact: Collection[str] = (),
        warn_on_bulk: bool = True,
        auto_create_partitions: bool = False,
        allow_scrub: bool = False,
    ) -> None:
        self.engine = engine
        self.schema = schema
        self.severities: type[IntEnum] = Severity if severities is None else severities
        self.registry = EventRegistry(
            self.severities,
            events=events,
            default_severity=default_severity,
            system_severity=system_severity,
        )
        self.durable_engine = durable_engine
        self.on_error: OnError = on_error
        self.pseudonymize_key = pseudonymize_key
        self.session_provider = session_provider
        self.context_provider = context_provider
        self.json_encoder = json_encoder
        self.indexes = indexes
        self.global_redact = frozenset(global_redact)
        self.warn_on_bulk = warn_on_bulk
        self.auto_create_partitions = auto_create_partitions
        self.allow_scrub = allow_scrub
        self.keys = None if pseudonymize_key is None else KeyRing(pseudonymize_key)
        self.tables = build_tables(schema=schema, indexes=indexes)
        self.maintenance = PartitionManager(engine, self.tables, self.severities)

    def install(self, session_factory: sessionmaker[Any] | type[Session]) -> None:
        """Audit the sessions of a factory.

        Registers the listeners on the factory's session class only (for a
        ``sessionmaker``, the class it builds), so other sessions, a second
        ``sessionmaker`` and tools such as Alembic are not audited. Set
        ``session.info["audit_enabled"] = False`` to switch capture off for
        one session of that class.

        Args:
            session_factory: A ``sessionmaker`` or a ``Session`` subclass.

        Raises:
            TypeError: ``session_factory`` is neither, or is asynchronous
                (not supported yet).
            ValueError: ``session_factory`` is the base ``Session``, or an
                ``AuditTrail`` is already installed on its class, a base
                class or a subclass of it.
        """
        from audit_trail.listener import install

        install(self, session_factory)

    def pseudonymize(self, value: object, *, purpose: str) -> str:
        """Replace a value with a keyed pseudonym, e.g. ``audit.<purpose>.v1:<hex>``.

        Args:
            value: The value. Must not be ``None``.
            purpose: Snake_case name separating unrelated uses.

        Returns:
            The pseudonym token.

        Raises:
            ValueError: No ``pseudonymize_key`` is configured, or ``purpose``
                is not snake_case.
            TypeError: ``value`` is ``None``.
            UnserializableValueError: ``value`` cannot be encoded.
        """
        if self.keys is None:
            raise ValueError("pseudonymize needs pseudonymize_key")
        return _pseudonymize(
            value, purpose=purpose, keys=self.keys, json_encoder=self.json_encoder
        )

    def log(
        self,
        session: Session,
        event: AuditEvent,
        *,
        obj: object | None = None,
        target: Target | object | None = None,
        payload: Mapping[str, object] | BaseModel | None = None,
        actor: Actor | None = None,
        durable: bool | None = None,
    ) -> None:
        """Record an explicit event in the session's current transaction.

        The entry is inserted immediately on ``session.connection()``, in the
        same database transaction as the session's changes: it is committed
        or rolled back with them, and shares their ``audit_transaction`` row.
        It is written even when ``session.info["audit_enabled"]`` is
        ``False``, which only switches off the automatic ``entity.*`` entries.
        Write failures follow ``on_error``.

        Args:
            session: A session of a class this ``AuditTrail`` is installed on.
            event: A registered host event.
            obj: The object the event is about; sets ``object_type``,
                ``object_id``, ``object_label`` and, through its options,
                ``scope_id`` and the default target. It must have a primary
                key: flush a new object first.
            target: The parent object, as an instance or a ``Target`` (a
                plain ``(type, id)`` tuple works too). A tuple id is formatted
                as a composite ``object_id``; an id of ``None`` means no
                target. Defaults to the ``target`` option of ``obj``.
            payload: The payload, validated against the event's schema.
                ``Pseudonymized`` fields of a schema are pseudonymized with
                their field name as the purpose.
            actor: The actor of this entry. It sets the entry's ``actor_id``
                and the actor fields of its ``data.context``; the
                ``audit_transaction`` row keeps the actor of the context.
            durable: Overrides the event's ``durable`` setting.

        Raises:
            TypeError: The session's class is not installed by this
                ``AuditTrail``.
            ValueError: The event uses a reserved prefix, ``obj`` or an
                instance ``target`` has no primary key, or a
                ``Pseudonymized`` field cannot be pseudonymized.
            NotImplementedError: The write would be durable; durable writes
                are not supported yet.
            UnknownEventError: The event is not registered.
            PayloadError: The payload does not match the event's schema, or a
                ``Pseudonymized`` field already holds a pseudonym token.
        """
        from audit_trail.diff import (
            USE_CONTEXT,
            format_target,
            object_type_of,
            options_of,
            resolve_label,
            resolve_scope,
            resolve_target,
        )
        from audit_trail.listener import installed_trail, write_entries
        from audit_trail.writer import ENVELOPE_VERSION, context_data, encode_payload

        if str(event).startswith(RESERVED_PREFIXES):
            raise ValueError(f"{event!s} is reserved for the library")
        severity = self.registry.severity_of(event)
        if resolve_write_flags(event, durable).durable:
            raise NotImplementedError("durable writes are not supported yet")
        if installed_trail(session) is not self:
            raise TypeError(
                "log() needs a session of a class this AuditTrail is installed on"
            )
        encoded = encode_payload(
            validate_payload(event, payload),
            keys=self.keys,
            json_encoder=self.json_encoder,
        )

        ctx = resolve_context(session, self.context_provider)
        entry_ctx = ctx
        if actor is not None:
            entry_ctx = dataclasses.replace(
                ctx, actor_type=actor.type, actor_id=actor.id, actor_label=actor.label
            )

        object_type = object_id = label = None
        target_type: str | None = None
        target_id: str | None = None
        scope_id = ctx.scope_id
        if obj is not None:
            object_type, object_id = object_type_of(obj), _required_id(obj, "obj")
            options = options_of(type(obj))
            label = resolve_label(obj, options)
            scope = resolve_scope(obj, options)
            if scope is not USE_CONTEXT:
                scope_id = scope
            target_type, target_id = resolve_target(obj, options) or (None, None)
        if isinstance(target, tuple):
            target_type, target_id = format_target(Target(*target)) or (None, None)
        elif target is not None:
            target_type = object_type_of(target)
            target_id = _required_id(target, "target")

        write_entries(
            session,
            self,
            [
                {
                    "verb": event.value,
                    "severity": int(severity),
                    "object_type": object_type,
                    "object_id": object_id,
                    "object_label": label,
                    "target_type": target_type,
                    "target_id": target_id,
                    "actor_id": entry_ctx.actor_id,
                    "scope_id": scope_id,
                    "data": {
                        "v": ENVELOPE_VERSION,
                        "payload": encoded,
                        "context": context_data(entry_ctx, self.json_encoder),
                    },
                }
            ],
            ctx,
        )


def _required_id(obj: object, name: str) -> str:
    from audit_trail.diff import object_id_of

    try:
        return object_id_of(obj)
    except ValueError:
        raise ValueError(
            f"{name} has no primary key yet; flush the session before logging"
        ) from None
