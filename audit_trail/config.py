"""Library configuration: ``AuditTrail`` and per-model ``AuditOptions``."""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable, Collection, Iterable, Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Literal, NamedTuple, overload

from sqlalchemy import Engine, create_engine

from audit_trail.context import Actor, AuditContext, resolve_context
from audit_trail.context import bind as _bind
from audit_trail.context import context as _context
from audit_trail.context import set_actor as _set_actor
from audit_trail.events import (
    RESERVED_PREFIXES,
    AuditEvent,
    EventRegistry,
    Severity,
    WriteFlags,
    resolve_write_flags,
    validate_payload,
)
from audit_trail.maintenance import PartitionManager
from audit_trail.serialization import KeyRing
from audit_trail.serialization import pseudonymize as _pseudonymize
from audit_trail.tables import build_tables

if TYPE_CHECKING:
    from datetime import datetime, timedelta

    from pydantic import BaseModel
    from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
    from sqlalchemy.orm import Session, sessionmaker

    from audit_trail.privacy import ScrubbedRecord, ScrubResult
    from audit_trail.writer import Entry, TransactionValues

OnError = Literal["log", "raise"]

DURABLE_POOL_SIZE = 5
"""Connections in the durable engine the library builds."""

DURABLE_POOL_TIMEOUT = 5.0
"""Seconds a durable write waits for a connection of that engine."""


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
        durable_engine: Engine for durable writes: sync for ``log``, async
            for ``alog``. Must not be configured for ``AUTOCOMMIT``. ``None``
            builds one from ``engine``'s URL (only the URL: pass your own
            engine for ``connect_args`` and similar settings), sync or async
            like ``engine``, with its own small pool (``DURABLE_POOL_SIZE``
            connections, no overflow, ``DURABLE_POOL_TIMEOUT``, pre-ping).
            It connects on the first durable write; ``dispose`` or
            ``adispose`` closes it.
        on_error: ``"log"`` keeps the business transaction alive when an audit
            write fails; ``"raise"`` propagates. ``fail_closed`` events always
            raise.
        pseudonymize_key: HMAC key as ``bytes`` (version 1) or
            ``{version: key}``.
        session_provider: Returns the current session, or ``None`` when there
            is none, for hosts that keep it in a context variable. ``log`` and
            ``alog`` call it when no session is passed.
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
        allow_scrub: Enable ``scrub``/``scrub_actor``. They run on ``engine``,
            whose role then needs ``UPDATE`` on the audit tables.
        default_query_window: How far back ``query.list_groups`` reads when
            it is not given ``since``, for example ``timedelta(days=30)``;
            ``since=ALL_HISTORY`` still lists the whole log. ``None`` reads
            the whole log, which gets slower as it grows.

    Attributes:
        severities: The severity enum in use.
        registry: The registered events.
        tables: The audit tables built from ``schema`` and ``indexes``.
        keys: Key ring built from ``pseudonymize_key``, or ``None``.
        maintenance: Partition management on ``engine``, for example
            ``audit.maintenance.ensure_partitions()``.
        query: Read queries, for example ``audit.query.list_groups(session)``.
        durable_engine: The engine durable writes use.

    Raises:
        EventRegistryError: An event or a severity setting is invalid.
        ValueError: A table name or an index key is invalid,
            ``pseudonymize_key`` is too short, or ``default_query_window`` is
            not positive.
        TypeError: ``pseudonymize_key`` or ``default_query_window`` has the
            wrong type.
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
        session_provider: Callable[[], Session | AsyncSession | None] | None = None,
        context_provider: Callable[[], Any] | None = None,
        json_encoder: type[json.JSONEncoder] | None = None,
        indexes: Collection[str] | None = None,
        global_redact: Collection[str] = (),
        warn_on_bulk: bool = True,
        auto_create_partitions: bool = False,
        allow_scrub: bool = False,
        default_query_window: timedelta | None = None,
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
        self._owns_durable_engine = durable_engine is None
        self.durable_engine: Engine | AsyncEngine = (
            _default_durable_engine(engine)
            if durable_engine is None
            else durable_engine
        )
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
        from audit_trail.query import AuditQuery

        self.query = AuditQuery(
            self.tables, self.severities, default_window=default_query_window
        )

    def install(
        self,
        session_factory: type[Session | AsyncSession]
        | sessionmaker[Any]
        | async_sessionmaker[Any],
    ) -> None:
        """Audit the sessions of a factory.

        Registers the listeners on the factory's session class only (for a
        ``sessionmaker``, the class it builds), so other sessions, a second
        ``sessionmaker`` and tools such as Alembic are not audited. Set
        ``session.info["audit_enabled"] = False`` to switch capture off for
        one session of that class.

        An ``AsyncSession`` runs a sync ``Session`` in a greenlet, and the
        listeners are registered on that class: give the async factory your
        own ``Session`` subclass, as in
        ``async_sessionmaker(engine, sync_session_class=AppSession)`` or as
        ``sync_session_class`` of an ``AsyncSession`` subclass.

        Args:
            session_factory: A ``sessionmaker`` or ``Session`` subclass, or
                an ``async_sessionmaker`` or ``AsyncSession`` subclass.

        Raises:
            TypeError: ``session_factory`` is none of these, or its
                ``sync_session_class`` is not a ``Session`` subclass.
            ValueError: The session class is the base ``Session`` (for an
                async factory: no ``sync_session_class`` was given), or an
                ``AuditTrail`` is already installed on it, a base class or a
                subclass of it.
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

    def dispose(self) -> None:
        """Close the pooled connections of a durable engine the library built.

        A ``durable_engine`` passed in is the host's to dispose; this leaves it
        alone.

        Raises:
            TypeError: The library's durable engine is async; use ``adispose``.
        """
        if not self._owns_durable_engine:
            return
        if not isinstance(self.durable_engine, Engine):
            raise TypeError("the durable engine is async; use adispose")
        self.durable_engine.dispose()

    async def adispose(self) -> None:
        """Async ``dispose``, for a durable engine the library built async.

        Raises:
            TypeError: The library's durable engine is sync; use ``dispose``.
        """
        if not self._owns_durable_engine:
            return
        if isinstance(self.durable_engine, Engine):
            raise TypeError("the durable engine is sync; use dispose")
        await self.durable_engine.dispose()

    @overload
    def log(
        self,
        session: Session | None,
        event: AuditEvent,
        /,
        *,
        obj: object | None = None,
        target: Target | object | None = None,
        payload: Mapping[str, object] | BaseModel | None = None,
        actor: Actor | None = None,
        durable: bool | None = None,
    ) -> None: ...

    @overload
    def log(
        self,
        event: AuditEvent,
        /,
        *,
        obj: object | None = None,
        target: Target | object | None = None,
        payload: Mapping[str, object] | BaseModel | None = None,
        actor: Actor | None = None,
        durable: bool | None = None,
    ) -> None: ...

    def log(
        self,
        session_or_event: Session | AuditEvent | None,
        event: AuditEvent | None = None,
        /,
        *,
        obj: object | None = None,
        target: Target | object | None = None,
        payload: Mapping[str, object] | BaseModel | None = None,
        actor: Actor | None = None,
        durable: bool | None = None,
    ) -> None:
        """Record an explicit event.

        Called as ``log(session, event, ...)`` or, with a ``session_provider``
        configured, as ``log(event, ...)``: without a session (or with
        ``None``), the entry goes to the session ``session_provider()``
        returns.

        A non-durable entry is inserted immediately on the session's
        connection, in the same database transaction as the session's changes:
        it is committed or rolled back with them, and shares their
        ``audit_transaction`` row. Write failures follow ``on_error``. With
        ``obj``, the connection is the one ``obj`` is flushed on; without, the
        one for the audit tables: their bind in ``Session(binds=...)``, else
        the session's default bind.

        A durable entry (the event's ``durable`` or ``fail_closed``, or
        ``durable=True``) is written on a connection of ``durable_engine`` in
        a transaction of its own, with its own ``audit_transaction`` row built
        from the current context, and committed before this returns, so it
        survives a rollback of the session. A failed write is logged with
        ``on_error="log"``; with ``on_error="raise"``, and always for a
        ``fail_closed`` event, it raises ``AuditWriteError``. With
        ``auto_create_partitions``, a missing partition is created and the
        write retried once. Creating a partition waits for every open
        transaction that has written audit rows, including the session's own:
        if it has, the retry fails after the ``ensure_partitions`` lock
        timeout (about 5 to 10 seconds) and a ``fail_closed`` event raises
        ``AuditWriteError``. Run ``ensure_partitions`` ahead of time rather
        than relying on the retry.

        Either kind is written even when ``session.info["audit_enabled"]`` is
        ``False``, which only switches off the automatic ``entity.*`` entries.

        Args:
            session_or_event: A session of a class this ``AuditTrail`` is
                installed on, followed by the event; or the event alone, or
                after ``None``, to use ``session_provider``.
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
            durable: Overrides the event's ``durable`` setting; ``False``
                cannot weaken a ``fail_closed`` event.

        Raises:
            RuntimeError: No session is passed and there is no
                ``session_provider``, or it returns ``None``.
            TypeError: The arguments are not ``(session, event)`` or
                ``(event)``, the session is not a ``Session`` (use ``alog``
                for an ``AsyncSession``), its class is not installed by this
                ``AuditTrail``, or the write is durable and ``durable_engine``
                is async.
            ValueError: The event uses a reserved prefix, ``durable=False``
                is given for a ``fail_closed`` event, ``obj`` or an instance
                ``target`` has no primary key, or a ``Pseudonymized`` field
                cannot be pseudonymized.
            UnknownEventError: The event is not registered.
            PayloadError: The payload does not match the event's schema, or a
                ``Pseudonymized`` field already holds a pseudonym token.
            AuditWriteError: A durable write failed and the policy says to
                raise.
            UnboundExecutionError: A non-durable entry without ``obj``, and
                the session has neither a bind for the audit tables nor a
                default bind.
        """
        from sqlalchemy.orm import Session

        from audit_trail.listener import PendingEntry, write_entries
        from audit_trail.writer import (
            DURABLE_WRITE_ERRORS,
            handle_durable_failure,
            write_durable,
        )

        call = _split_call("log", session_or_event, event)
        session = self._session_for("log", call.session)
        if not isinstance(session, Session):
            raise TypeError(
                f"log() needs a Session, not {type(session).__qualname__}; "
                "use alog() for an AsyncSession"
            )
        entry = self._prepare(session, call.event, obj, target, payload, actor, durable)
        if not entry.flags.durable:
            write_entries(session, self, [PendingEntry(entry.entry, obj)], entry.ctx)
            return
        engine = self.durable_engine
        if not isinstance(engine, Engine):
            raise TypeError(
                "log() writes durable entries with a sync durable_engine; "
                "this one is async: use alog()"
            )
        values = self._transaction_values(entry.ctx)
        try:
            with engine.connect() as conn:
                write_durable(
                    conn,
                    self.tables,
                    self._severity_values(),
                    values,
                    [entry.entry],
                    auto_create_partitions=self.auto_create_partitions,
                )
        except DURABLE_WRITE_ERRORS as exc:
            handle_durable_failure(exc, self.on_error, entry.flags.fail_closed)

    @overload
    async def alog(
        self,
        session: AsyncSession | None,
        event: AuditEvent,
        /,
        *,
        obj: object | None = None,
        target: Target | object | None = None,
        payload: Mapping[str, object] | BaseModel | None = None,
        actor: Actor | None = None,
        durable: bool | None = None,
    ) -> None: ...

    @overload
    async def alog(
        self,
        event: AuditEvent,
        /,
        *,
        obj: object | None = None,
        target: Target | object | None = None,
        payload: Mapping[str, object] | BaseModel | None = None,
        actor: Actor | None = None,
        durable: bool | None = None,
    ) -> None: ...

    async def alog(
        self,
        session_or_event: AsyncSession | AuditEvent | None,
        event: AuditEvent | None = None,
        /,
        *,
        obj: object | None = None,
        target: Target | object | None = None,
        payload: Mapping[str, object] | BaseModel | None = None,
        actor: Actor | None = None,
        durable: bool | None = None,
    ) -> None:
        """Async ``log``, for an ``AsyncSession`` of an installed factory.

        Called as ``alog(session, event, ...)`` or, with a
        ``session_provider`` configured, as ``alog(event, ...)``; see ``log``.

        A non-durable entry is written in the session's transaction, a
        durable one on the async ``durable_engine``; see ``log``.

        Args:
            session_or_event: An ``AsyncSession`` whose ``sync_session_class``
                this ``AuditTrail`` is installed on, followed by the event; or
                the event alone, or after ``None``, to use
                ``session_provider``.
            event: A registered host event.
            obj: The object the event is about; see ``log``.
            target: The parent object; see ``log``.
            payload: The payload; see ``log``.
            actor: The actor of this entry; see ``log``.
            durable: Overrides the event's ``durable`` setting.

        Raises:
            RuntimeError: No session is passed and there is no
                ``session_provider``, or it returns ``None``.
            TypeError: The arguments are not ``(session, event)`` or
                ``(event)``, the session is not an ``AsyncSession`` (use
                ``log`` for a ``Session``), its class is not installed by this
                ``AuditTrail``, or the write is durable and ``durable_engine``
                is sync.
            ValueError: As for ``log``.
            UnknownEventError: The event is not registered.
            PayloadError: The payload does not match the event's schema.
            AuditWriteError: A durable write failed and the policy says to
                raise.
            UnboundExecutionError: As for ``log``.
        """
        from sqlalchemy.ext.asyncio import AsyncSession

        from audit_trail.listener import PendingEntry, write_entries
        from audit_trail.writer import (
            DURABLE_WRITE_ERRORS,
            handle_durable_failure,
            write_durable,
        )

        call = _split_call("alog", session_or_event, event)
        session = self._session_for("alog", call.session)
        if not isinstance(session, AsyncSession):
            raise TypeError(
                f"alog() needs an AsyncSession, not {type(session).__qualname__}; "
                "use log() for a Session"
            )
        entry = self._prepare(
            session.sync_session, call.event, obj, target, payload, actor, durable
        )
        if not entry.flags.durable:
            await session.run_sync(
                lambda sync_session: write_entries(
                    sync_session, self, [PendingEntry(entry.entry, obj)], entry.ctx
                )
            )
            return
        engine = self.durable_engine
        if isinstance(engine, Engine):
            raise TypeError(
                "alog() writes durable entries with an async durable_engine; "
                "this one is sync: use log()"
            )
        values = self._transaction_values(entry.ctx)
        try:
            async with engine.connect() as conn:
                await conn.run_sync(
                    write_durable,
                    self.tables,
                    self._severity_values(),
                    values,
                    [entry.entry],
                    auto_create_partitions=self.auto_create_partitions,
                )
        except DURABLE_WRITE_ERRORS as exc:
            handle_durable_failure(exc, self.on_error, entry.flags.fail_closed)

    def scrub(
        self,
        object_type: str,
        object_id: str,
        *,
        include_targets: bool = True,
        since: datetime | None = None,
        scope_ids: Collection[str] | None = None,
    ) -> ScrubResult:
        """Erase the values the entries of one object hold.

        Every non-null value in ``data.changes`` and ``data.payload`` of the
        object's entries becomes ``"[erased]"`` (field keys stay, ``null``
        stays ``null``) and ``object_label`` becomes ``NULL``. ``data.context``
        is left to ``scrub_actor``. Runs in one transaction on ``engine``
        together with an ``audit.scrubbed`` entry recording who scrubbed
        which object and how many rows, without any erased value; nothing is
        committed if either fails. With ``auto_create_partitions``, the
        partitions of the current month are ensured first.

        Args:
            object_type: Stored ``object_type`` of the object.
            object_id: Stored ``object_id`` of the object, as
                ``audit_trail.diff.object_id_for`` formats it.
            include_targets: Also erase entries whose target is the object,
                such as changes of its children.
            since: Only entries created at or after this aware datetime,
                which also limits the partitions scanned. ``None`` for all.
            scope_ids: Only entries whose ``scope_id`` is one of these, such
                as the tenants of an admin. ``None`` for no restriction; an
                empty collection erases nothing, and an entry without a
                scope never matches a restriction. Recorded in the
                ``audit.scrubbed`` entry.

        Returns:
            A ``ScrubResult``: ``activity_rows`` is the number of entries
            erased (entries already erased are not counted);
            ``transaction_rows`` is always ``0``.

        Raises:
            ScrubNotAllowedError: ``allow_scrub`` is ``False``.
            TypeError: ``engine`` is async; use ``ascrub``; or
                ``scope_ids`` is a ``str``.
            ValueError: ``since`` is naive, or ``engine`` is in
                ``AUTOCOMMIT`` mode.
        """
        from audit_trail import privacy

        privacy.check_allowed(self.allow_scrub)
        engine = self.engine
        if not isinstance(engine, Engine):
            raise TypeError("the engine is async; use ascrub")
        privacy.check_since(since)
        privacy.check_scope_ids(scope_ids)
        record = self._scrubbed_record()
        if self.auto_create_partitions:
            self.maintenance.ensure_partitions(months_ahead=0)
        with engine.begin() as conn:
            return privacy.scrub(
                conn,
                self.tables,
                object_type,
                object_id,
                include_targets=include_targets,
                since=since,
                scope_ids=scope_ids,
                record=record,
            )

    async def ascrub(
        self,
        object_type: str,
        object_id: str,
        *,
        include_targets: bool = True,
        since: datetime | None = None,
        scope_ids: Collection[str] | None = None,
    ) -> ScrubResult:
        """Async ``scrub``, for an ``AuditTrail`` built with an ``AsyncEngine``.

        Args:
            object_type: Stored ``object_type`` of the object.
            object_id: Stored ``object_id`` of the object.
            include_targets: Also erase entries whose target is the object.
            since: Only entries created at or after this aware datetime.
            scope_ids: Only entries with one of these ``scope_id`` values;
                see ``scrub``.

        Returns:
            A ``ScrubResult``; see ``scrub``.

        Raises:
            ScrubNotAllowedError: ``allow_scrub`` is ``False``.
            TypeError: ``engine`` is sync; use ``scrub``; or ``scope_ids``
                is a ``str``.
            ValueError: As for ``scrub``.
        """
        from audit_trail import privacy

        privacy.check_allowed(self.allow_scrub)
        engine = self.engine
        if isinstance(engine, Engine):
            raise TypeError("the engine is sync; use scrub")
        privacy.check_since(since)
        privacy.check_scope_ids(scope_ids)
        record = self._scrubbed_record()
        if self.auto_create_partitions:
            await self.maintenance.aensure_partitions(months_ahead=0)
        async with engine.begin() as conn:
            return await conn.run_sync(
                lambda sync_conn: privacy.scrub(
                    sync_conn,
                    self.tables,
                    object_type,
                    object_id,
                    include_targets=include_targets,
                    since=since,
                    scope_ids=scope_ids,
                    record=record,
                )
            )

    def scrub_actor(
        self, actor_id: str, *, scope_ids: Collection[str] | None = None
    ) -> ScrubResult:
        """Clear the personal context stored for one actor.

        ``audit_transaction`` rows created with this ``actor_id`` get
        ``actor_label``, ``remote_addr``, ``user_agent`` and ``meta`` set to
        ``NULL``, and entries with this ``actor_id`` lose those keys from
        ``data.context``. ``actor_id`` stays. A transaction row keeps the
        actor it was created with: a request that wrote its first entry
        anonymously and called ``set_actor`` afterwards keeps its address
        and user agent on that row. Runs in one transaction on ``engine``
        with an ``audit.scrubbed`` entry, as ``scrub`` does.

        With ``scope_ids``, only entries whose ``scope_id`` is one of them
        lose the keys, and a transaction row is cleared only when it has
        entries and all of them, whoever their actor, are in those scopes:
        its fields are shared by all its entries, so a request that also
        wrote entries of another scope or without one keeps them, as does a
        transaction row without entries. Clearing an actor completely
        across scopes takes a run without ``scope_ids``.

        Args:
            actor_id: The actor's ``actor_id``.
            scope_ids: The scopes the scrub is restricted to, such as the
                tenants of an admin. ``None`` for no restriction; an empty
                collection changes nothing. Recorded in the
                ``audit.scrubbed`` entry.

        Returns:
            A ``ScrubResult`` with the numbers of activity and transaction
            rows changed.

        Raises:
            ScrubNotAllowedError: ``allow_scrub`` is ``False``.
            TypeError: ``engine`` is async; use ``ascrub_actor``; or
                ``scope_ids`` is a ``str``.
            ValueError: ``engine`` is in ``AUTOCOMMIT`` mode.
        """
        from audit_trail import privacy

        privacy.check_allowed(self.allow_scrub)
        engine = self.engine
        if not isinstance(engine, Engine):
            raise TypeError("the engine is async; use ascrub_actor")
        privacy.check_scope_ids(scope_ids)
        record = self._scrubbed_record()
        if self.auto_create_partitions:
            self.maintenance.ensure_partitions(months_ahead=0)
        with engine.begin() as conn:
            return privacy.scrub_actor(
                conn, self.tables, actor_id, scope_ids=scope_ids, record=record
            )

    async def ascrub_actor(
        self, actor_id: str, *, scope_ids: Collection[str] | None = None
    ) -> ScrubResult:
        """Async ``scrub_actor``, for an ``AuditTrail`` built with an ``AsyncEngine``.

        Args:
            actor_id: The actor's ``actor_id``.
            scope_ids: The scopes the scrub is restricted to; see
                ``scrub_actor``.

        Returns:
            A ``ScrubResult`` with the numbers of activity and transaction
            rows changed.

        Raises:
            ScrubNotAllowedError: ``allow_scrub`` is ``False``.
            TypeError: ``engine`` is sync; use ``scrub_actor``; or
                ``scope_ids`` is a ``str``.
            ValueError: ``engine`` is in ``AUTOCOMMIT`` mode.
        """
        from audit_trail import privacy

        privacy.check_allowed(self.allow_scrub)
        engine = self.engine
        if isinstance(engine, Engine):
            raise TypeError("the engine is sync; use scrub_actor")
        privacy.check_scope_ids(scope_ids)
        record = self._scrubbed_record()
        if self.auto_create_partitions:
            await self.maintenance.aensure_partitions(months_ahead=0)
        async with engine.begin() as conn:
            return await conn.run_sync(
                lambda sync_conn: privacy.scrub_actor(
                    sync_conn,
                    self.tables,
                    actor_id,
                    scope_ids=scope_ids,
                    record=record,
                )
            )

    def _scrubbed_record(self) -> ScrubbedRecord:
        from audit_trail.events import AuditSystem
        from audit_trail.privacy import ScrubbedRecord, scrub_context

        return ScrubbedRecord(
            int(self.registry.severity_of(AuditSystem.SCRUBBED)),
            scrub_context(self.context_provider),
            self.json_encoder,
        )

    def _transaction_values(self, ctx: AuditContext) -> TransactionValues:
        from audit_trail.writer import transaction_values

        return transaction_values(ctx, self.json_encoder)

    def _severity_values(self) -> list[int]:
        return [int(member) for member in self.severities]

    def _session_for(
        self, method: str, session: Session | AsyncSession | None
    ) -> Session | AsyncSession:
        # The explicit session, else the provider's; never silently nothing.
        if session is not None:
            return session
        if self.session_provider is None:
            raise RuntimeError(
                f"{method}() needs a session: pass one or configure "
                "AuditTrail(session_provider=...)"
            )
        provided = self.session_provider()
        if provided is None:
            raise RuntimeError(
                f"{method}() got no session from session_provider "
                "(is it called outside a request?): pass one"
            )
        return provided

    def _prepare(
        self,
        session: Session,
        event: AuditEvent,
        obj: object | None,
        target: Target | object | None,
        payload: Mapping[str, object] | BaseModel | None,
        actor: Actor | None,
        durable: bool | None,
    ) -> _PreparedEntry:
        # Everything of log() before the write; no I/O.
        from audit_trail.diff import (
            USE_CONTEXT,
            format_target,
            object_type_of,
            options_of,
            resolve_label,
            resolve_scope,
            resolve_target,
        )
        from audit_trail.listener import installed_trail
        from audit_trail.writer import ENVELOPE_VERSION, context_data, encode_payload

        if str(event).startswith(RESERVED_PREFIXES):
            raise ValueError(f"{event!s} is reserved for the library")
        severity = self.registry.severity_of(event)
        flags = resolve_write_flags(event, durable)
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

        return _PreparedEntry(
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
            },
            ctx,
            flags,
        )


class _Call(NamedTuple):
    session: Session | AsyncSession | None
    event: AuditEvent


def _split_call(
    method: str,
    first: Session | AsyncSession | AuditEvent | None,
    second: AuditEvent | None,
) -> _Call:
    # log(event) or log(session, event); a session is never an AuditEvent.
    match first, second:
        case AuditEvent(), None:
            return _Call(None, first)
        case _, AuditEvent() if not isinstance(first, AuditEvent):
            return _Call(first, second)
        case _:
            raise TypeError(f"{method}() takes (session, event) or (event)")


class _PreparedEntry(NamedTuple):
    entry: Entry
    ctx: AuditContext
    flags: WriteFlags


def _default_durable_engine(engine: Engine | AsyncEngine) -> Engine | AsyncEngine:
    # The URL object keeps the password (its string form masks it).
    if isinstance(engine, Engine):
        return create_engine(
            engine.url,
            pool_size=DURABLE_POOL_SIZE,
            max_overflow=0,
            pool_timeout=DURABLE_POOL_TIMEOUT,
            pool_pre_ping=True,
        )
    # An AsyncEngine means the host has loaded asyncio support already.
    from sqlalchemy.ext.asyncio import create_async_engine

    return create_async_engine(
        engine.url,
        pool_size=DURABLE_POOL_SIZE,
        max_overflow=0,
        pool_timeout=DURABLE_POOL_TIMEOUT,
        pool_pre_ping=True,
    )


def _required_id(obj: object, name: str) -> str:
    from audit_trail.diff import object_id_of

    try:
        return object_id_of(obj)
    except ValueError:
        raise ValueError(
            f"{name} has no primary key yet; flush the session before logging"
        ) from None
