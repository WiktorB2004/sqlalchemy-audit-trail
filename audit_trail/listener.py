"""Session event listeners that capture ORM changes.

``install`` registers the listeners on one session class: the class a
``sessionmaker`` builds, or a ``Session`` subclass (and so its subclasses).
Never on the base ``Session``, which would also cover Alembic, other engines
and every other session in the process. An ``AsyncSession`` runs a sync
``Session`` of its ``sync_session_class`` in a greenlet, so an async factory
is installed through that class, which must be the host's own subclass.

``after_flush`` turns the flushed ``Audited`` instances into ``entity.*``
entries and writes them with plain SQL on the session's connection for each
object (resolved like the flush does), in the same database transaction as
the changes, so a rollback undoes both.

The ``audit_transaction`` row is inserted by the first entry of a database
transaction on each connection and cached in ``session.info``, per
connection, together with the ``SessionTransaction`` (root or savepoint) it
was inserted in:

- rolling back that ``SessionTransaction`` or one of its ancestors
  (``after_soft_rollback``) drops the cached row, because it is gone;
- ``after_transaction_end`` drops the cache when the outermost transaction ends,
  however it ends: commit, rollback, or ``Session.close()`` (which fires no
  commit or rollback event). Releasing a savepoint also ends a
  ``SessionTransaction``, but the row then lives on in the enclosing one;
- ``after_rollback`` never touches it, since it also fires when a savepoint
  is rolled back, which may leave a row of the enclosing transaction intact.

``do_orm_execute`` warns (``warn_on_bulk``) about ORM or Core bulk
``UPDATE``/``DELETE`` statements on an audited table executed through the
session: they bypass the flush and get no entry.

A second ``do_orm_execute`` handler explains loads that fail under
``AsyncSession``. Loading an unloaded attribute outside an awaited call needs
I/O that SQLAlchemy cannot run there, so it raises ``MissingGreenlet``. For
the loads the library is responsible for (an expired column of an
``Audited`` instance, which ``Audited`` also loads on assignment to keep the
old value, and a collection named in ``track_relationships``) the error is
replaced by ``AsyncLoadError``, which names the attribute and the fix. The
handler adds no SQL and checks nothing in advance: it only translates the
error once the load has failed, and only on an async dialect.

These state listeners run even when ``session.info["audit_enabled"]`` is
``False``; only capture is switched off, so toggling the flag in the middle
of a transaction cannot leave a stale cache behind.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterable, Sequence
from itertools import chain
from typing import TYPE_CHECKING, Any, NamedTuple, TypeVar, cast

from sqlalchemy import event, inspect
from sqlalchemy.exc import MissingGreenlet, StatementError
from sqlalchemy.orm import Session, sessionmaker

from audit_trail._compaction import FieldChange
from audit_trail.context import AuditContext, ContextSnapshot, resolve_context
from audit_trail.diff import (
    USE_CONTEXT,
    ChangeKind,
    entity_changes,
    object_id_of,
    object_type_of,
    options_of,
    resolve_label,
    resolve_scope,
    resolve_target,
)
from audit_trail.events import Crud
from audit_trail.mixin import Audited, refresh_snapshot
from audit_trail.relations import (
    discard_relationship_changes,
    pop_relationship_changes,
    track_relationships,
)
from audit_trail.tables import audit_connection
from audit_trail.writer import (
    ENVELOPE_VERSION,
    Entry,
    TransactionRow,
    context_data,
    insert_activities,
    insert_transaction,
    run_isolated,
    transaction_values,
)

if TYPE_CHECKING:
    from sqlalchemy import Connection, Result
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    from sqlalchemy.orm import (
        InstanceState,
        Mapper,
        ORMExecuteState,
        SessionTransaction,
        UOWTransaction,
    )

    from audit_trail.config import AuditTrail

logger = logging.getLogger(__name__)

AUDIT_ENABLED_KEY = "audit_enabled"
"""``session.info`` key; ``False`` switches capture off for one session."""

_CACHE_KEY = "audit_trail.transaction"

_A = TypeVar("_A", bound=Audited)

_VERBS: dict[ChangeKind, Crud] = {
    "created": Crud.CREATED,
    "updated": Crud.UPDATED,
    "deleted": Crud.DELETED,
}

# Session class -> the AuditTrail installed on it.
_installed: dict[type[Session], AuditTrail] = {}


class AsyncLoadError(MissingGreenlet):
    """An audited attribute needed a load that ``AsyncSession`` cannot run.

    Raised in place of SQLAlchemy's ``MissingGreenlet`` (or, with psycopg,
    the ``StatementError`` wrapping it) when host code touches, outside an
    awaited call:

    - an expired or unloaded column of an ``Audited`` instance, read or
      assigned (``Audited`` loads an expired column's old value when it is
      assigned);
    - a collection named in the model's ``track_relationships`` that is not
      loaded.

    The message names the model and attribute and how to load it. The
    original exception is the ``__cause__``. A subclass of
    ``MissingGreenlet``, so existing handlers of that error still catch it.
    """


class _CachedRow(NamedTuple):
    owner: SessionTransaction
    row: TransactionRow


class PendingEntry(NamedTuple):
    """An entry to write and the object it is about, if any."""

    entry: Entry
    obj: object | None


def install(
    trail: AuditTrail,
    session_factory: type[Session | AsyncSession]
    | sessionmaker[Any]
    | async_sessionmaker[Any],
) -> None:
    """Register the audit listeners on a session factory's class.

    Also starts tracking the ``track_relationships`` of every ``Audited``
    model, configured now or later. Tracking is attached to the model
    classes, so it is process-wide: tracked collections record their net
    changes in any session, and those records are dropped when the instance
    is expired or garbage collected.

    Args:
        trail: The configuration the listeners write with.
        session_factory: A ``sessionmaker`` or a ``Session`` subclass; or
            an ``async_sessionmaker`` or ``AsyncSession`` subclass whose
            ``sync_session_class`` is a ``Session`` subclass, e.g.
            ``async_sessionmaker(engine, sync_session_class=AppSession)``.

    Raises:
        TypeError: ``session_factory`` is none of these, or its
            ``sync_session_class`` is not a ``Session`` subclass.
        ValueError: The session class is the base ``Session`` (for an async
            factory: no ``sync_session_class`` was given), or an
            ``AuditTrail`` is already installed on it, a base class or a
            subclass of it.
    """
    cls = _session_class(session_factory)
    other = next(
        (c for c in _installed if issubclass(cls, c) or issubclass(c, cls)), None
    )
    if other is not None:
        raise ValueError(
            f"an AuditTrail is already installed on {other.__qualname__}; "
            f"installing on {cls.__qualname__} would audit its sessions twice"
        )
    listener = _Listener(trail)
    event.listen(cls, "after_flush", listener.after_flush)
    event.listen(cls, "do_orm_execute", listener.do_orm_execute)
    event.listen(cls, "do_orm_execute", _explain_async_load)
    event.listen(cls, "after_transaction_end", _after_transaction_end)
    event.listen(cls, "after_soft_rollback", _after_soft_rollback)
    event.listen(cls, "after_rollback", _after_rollback)
    _installed[cls] = trail
    _track_all_relationships()


def installed_trail(session: Session) -> AuditTrail | None:
    """Return the ``AuditTrail`` installed on the session's class, if any.

    Args:
        session: A session.

    Returns:
        The installed configuration, or ``None``.
    """
    for cls in type(session).__mro__:
        trail = _installed.get(cls)
        if trail is not None:
            return trail
    return None


def _session_class(factory: object) -> type[Session]:
    if isinstance(factory, sessionmaker):
        cls: type[Session] = factory.class_
    elif isinstance(factory, type) and issubclass(factory, Session):
        cls = factory
    else:
        sync_class = _sync_session_class(factory)
        if sync_class is None:
            raise TypeError(
                "install() needs a sessionmaker or a Session subclass (or their "
                f"async counterparts), got {factory!r}"
            )
        if sync_class is Session:
            raise ValueError(
                "install() refuses an async factory whose sync_session_class is "
                "the base Session: its listeners would audit every session in "
                "the process; pass sync_session_class=<your Session subclass>"
            )
        if not (isinstance(sync_class, type) and issubclass(sync_class, Session)):
            raise TypeError(
                f"sync_session_class must be a Session subclass, got {sync_class!r}"
            )
        cls = sync_class
    if cls is Session:
        raise ValueError(
            "install() refuses the base Session: its listeners would audit "
            "every session in the process; pass your sessionmaker or a "
            "Session subclass"
        )
    return cls


def _sync_session_class(factory: object) -> object | None:
    # Looked up through sys.modules so sync-only hosts never import asyncio
    # support (and greenlet): an async factory implies it is loaded already.
    # Returns None when factory is not an async factory.
    asyncio_module = sys.modules.get("sqlalchemy.ext.asyncio")
    if asyncio_module is None:
        return None
    if isinstance(factory, asyncio_module.async_sessionmaker):
        explicit: object = factory.kw.get("sync_session_class")
        return explicit or factory.class_.sync_session_class
    if isinstance(factory, type) and issubclass(factory, asyncio_module.AsyncSession):
        return cast("type[AsyncSession]", factory).sync_session_class
    return None


_tracking_registered = False


def _track_all_relationships() -> None:
    global _tracking_registered
    if not _tracking_registered:
        # Fires for Audited models configured from now on, including ones
        # declared already but not configured yet.
        event.listen(Audited, "mapper_configured", _track_model, propagate=True)
        _tracking_registered = True
    for cls in _subclasses(Audited):
        mapper = inspect(cls, raiseerr=False)
        if mapper is not None and mapper.configured:
            _track_model(mapper, cls)


def _subclasses(cls: type[Any]) -> Iterable[type[Any]]:
    pending = list(cls.__subclasses__())
    while pending:
        sub = pending.pop()
        pending.extend(sub.__subclasses__())
        yield sub


def _track_model(mapper: Mapper[_A], cls: type[_A]) -> None:
    # Runs inside mapper configuration, for every Audited model in the
    # process: an exception here would leave SQLAlchemy's configuration
    # failed for all models, so a bad name is skipped with a warning and
    # check_models() reports it as an error.
    for name in sorted(options_of(cls).track_relationships):
        prop = mapper.relationships.get(name)
        if prop is None or not prop.uselist:
            what = "not a relationship" if prop is None else "a scalar relationship"
            logger.warning(
                "%s: track_relationships names %r, which is %s; it is not "
                "tracked (check_models() reports this)",
                cls.__qualname__,
                name,
                what,
            )
            continue
        # Tracked on the declaring class; tracking again from a subclass is a
        # no-op in track_relationships.
        track_relationships(getattr(prop.parent.class_, name))


class _Listener:
    """The capture listener of one ``install()``."""

    def __init__(self, trail: AuditTrail) -> None:
        self.trail = trail

    def after_flush(self, session: Session, flush_context: UOWTransaction) -> None:
        if session.info.get(AUDIT_ENABLED_KEY) is False:
            return
        ctx = resolve_context(session, self.trail.context_provider)
        entries = self._entries(session, ctx)
        if entries:
            write_entries(session, self.trail, entries, ctx)

    def do_orm_execute(self, orm_execute_state: ORMExecuteState) -> None:
        """Warn about a bulk ``UPDATE``/``DELETE`` of an audited table.

        Such statements bypass the flush, so no entry is written for them.
        """
        state = orm_execute_state
        if not self.trail.warn_on_bulk:
            return
        if not (state.is_update or state.is_delete):
            return
        if state.session.info.get(AUDIT_ENABLED_KEY) is False:
            return
        if state.execution_options.get("audit_bulk_ok"):
            return
        model = _audited_model(state)
        if model is not None:
            logger.warning(
                "Bulk %s of %s bypasses the audit trail: no entry is written. "
                "Pass execution_options(audit_bulk_ok=True) if this is intended.",
                "UPDATE" if state.is_update else "DELETE",
                model.__qualname__,
            )

    def _entries(self, session: Session, ctx: AuditContext) -> list[PendingEntry]:
        trail = self.trail
        context = context_data(ctx, trail.json_encoder)
        batches: tuple[tuple[ChangeKind, Iterable[object]], ...] = (
            ("created", session.new),
            ("updated", session.dirty),
            ("deleted", session.deleted),
        )
        entries: list[PendingEntry] = []
        for kind, objects in batches:
            for obj in objects:
                if not isinstance(obj, Audited):
                    continue
                entry = self._entry(obj, kind, ctx, context)
                if entry is not None:
                    entries.append(PendingEntry(entry, obj))
        # Only now: the snapshots were the old values of this flush's changes.
        for obj in chain(session.new, session.dirty):
            if isinstance(obj, Audited):
                refresh_snapshot(obj)
        return entries

    def _entry(
        self,
        obj: Audited,
        kind: ChangeKind,
        ctx: AuditContext,
        context: ContextSnapshot,
    ) -> Entry | None:
        trail = self.trail
        changes: dict[str, FieldChange] = {}
        changes.update(
            entity_changes(
                obj,
                kind,
                keys=trail.keys,
                json_encoder=trail.json_encoder,
                global_redact=trail.global_redact,
            )
        )
        relationship_changes = pop_relationship_changes(obj)
        if kind != "deleted":
            # A deleted instance's memberships end with it; its delta, if
            # any, is dropped.
            changes.update(relationship_changes)
        if kind == "updated" and not changes:
            return None
        options = options_of(type(obj))
        scope = resolve_scope(obj, options)
        target_type, target_id = resolve_target(obj, options) or (None, None)
        event_ = _VERBS[kind]
        return {
            "verb": event_.value,
            "severity": int(trail.registry.severity_of(event_, options)),
            "object_type": object_type_of(obj),
            "object_id": object_id_of(obj),
            "object_label": resolve_label(obj, options),
            "target_type": target_type,
            "target_id": target_id,
            "actor_id": ctx.actor_id,
            "scope_id": ctx.scope_id if scope is USE_CONTEXT else scope,
            "data": {"v": ENVELOPE_VERSION, "changes": changes, "context": context},
        }


# Private SQLAlchemy load option holding the instance of a column load (2.0
# and 2.1); without it the message names only the model.
_REFRESH_STATE = "_refresh_state"


def _explain_async_load(orm_execute_state: ORMExecuteState) -> Result[Any] | None:
    # Runs for every ORM statement of an installed session class, so the
    # common case (not a lazy or expired-attribute load of an Audited
    # instance on an async dialect) returns before running anything, and a
    # session bound to a sync engine returns first.
    state = orm_execute_state
    bind = state.session.bind
    if bind is not None and not bind.dialect.is_async:
        return None
    if state.is_column_load:
        instance: InstanceState[Any] | None = getattr(
            state.load_options, _REFRESH_STATE, None
        )
        mapper = state.bind_mapper if instance is None else instance.mapper
    elif state.is_relationship_load:
        instance = state.lazy_loaded_from
        if instance is None:
            return None  # an eager loader, run by an awaited query
        mapper = instance.mapper
    else:
        return None
    if mapper is None or not issubclass(mapper.class_, Audited):
        return None
    if bind is None:  # bound per mapper or table
        bind = state.session.get_bind(**state.bind_arguments)
        if not bind.dialect.is_async:
            return None
    try:
        return state.invoke_statement()
    except (MissingGreenlet, StatementError) as exc:
        cause = exc if isinstance(exc, MissingGreenlet) else exc.orig
        if not isinstance(cause, MissingGreenlet) or isinstance(exc, AsyncLoadError):
            raise
        message = (
            _column_load_message(mapper, instance)
            if state.is_column_load
            else _collection_load_message(mapper, instance, state.bind_mapper)
        )
        if message is None:
            raise
        raise AsyncLoadError(message) from exc


_NO_IMPLICIT_IO = (
    "loading it needs database I/O, which an AsyncSession cannot run outside "
    "an awaited call"
)


def _column_load_message(
    mapper: Mapper[Any], instance: InstanceState[Any] | None
) -> str:
    name = mapper.class_.__qualname__
    columns = {prop.key for prop in mapper.column_attrs}
    unloaded = [] if instance is None else sorted(instance.unloaded & columns)
    if not unloaded:
        what = f"an attribute of {name} is"
    elif len(unloaded) == 1:
        what = f"{name}.{unloaded[0]} is"
    else:
        what = ", ".join(f"{name}.{key}" for key in unloaded) + " are"
    return (
        f"{what} not loaded (expired, e.g. by commit), and {_NO_IMPLICIT_IO}. "
        "This happens when an unloaded attribute is read, and for an audited "
        "column also when it is assigned: Audited loads the old value to "
        "record the change. Load it first with `await session.refresh(obj)`, "
        "or create the session with expire_on_commit=False."
    )


def _collection_load_message(
    mapper: Mapper[Any],
    instance: InstanceState[Any] | None,
    target: Mapper[Any] | None,
) -> str | None:
    # SQLAlchemy does not say which relationship is being loaded: name the
    # tracked ones that are unloaded and point at the loaded class.
    if instance is None or target is None:
        return None
    tracked = options_of(mapper.class_).track_relationships
    keys = [
        rel.key
        for rel in mapper.relationships
        if rel.key in tracked
        and rel.key in instance.unloaded
        and (target.isa(rel.mapper) or rel.mapper.isa(target))
    ]
    if not keys:
        return None
    name = mapper.class_.__qualname__
    attributes = " or ".join(f"{name}.{key}" for key in keys)
    loaders = " or ".join(f"selectinload({name}.{key})" for key in keys)
    return (
        f"{attributes} is not loaded, and {_NO_IMPLICIT_IO}. Load tracked "
        f"collections eagerly before changing them: {loaders} in the query, "
        'or lazy="selectin" on the relationship.'
    )


def _audited_model(state: ORMExecuteState) -> type[Any] | None:
    # Matched by table, which covers ORM update(Model) and Core update(table).
    table = getattr(state.statement, "table", None)
    for cls in _subclasses(Audited):
        mapper = inspect(cls, raiseerr=False)
        if mapper is not None and table in mapper.tables:
            return cls
    return None


def write_entries(
    session: Session,
    trail: AuditTrail,
    entries: Sequence[PendingEntry],
    ctx: AuditContext,
) -> None:
    """Write entries in the session's current database transaction.

    Each entry goes on the connection its object's rows were flushed on:
    ``session.connection()`` with the base mapper of the object, as the flush
    resolves it (mapper binds, then its table's, then the default bind). An
    entry without an object uses the audit tables as the clause (their binds,
    then the default bind). A ``get_bind`` override is honoured.

    Per connection, inserts the ``audit_transaction`` row first when that
    connection's transaction has none yet, then its entries with one
    ``executemany``, following ``trail.on_error``. Uses only the connections,
    never the ORM.

    Args:
        session: A session of an installed class.
        trail: The configuration to write with.
        entries: The entries, with the objects they are about.
        ctx: The context, used when a transaction row is created.

    Raises:
        UnboundExecutionError: An entry without an object, and the session
            has no bind for the audit tables.
    """
    by_mapper: dict[Mapper[Any] | None, Connection] = {}
    groups: dict[Connection, list[Entry]] = {}
    for pending in entries:
        mapper = _base_mapper(pending.obj)
        connection = by_mapper.get(mapper)
        if connection is None:
            connection = by_mapper[mapper] = _connection_for(session, trail, mapper)
        groups.setdefault(connection, []).append(pending.entry)
    for connection, group in groups.items():
        _write_group(session, trail, connection, group, ctx)


def _base_mapper(obj: object | None) -> Mapper[Any] | None:
    # The flush resolves an object's connection from its base mapper.
    state = None if obj is None else inspect(obj, raiseerr=False)
    mapper: Mapper[Any] | None = getattr(state, "mapper", None)
    return None if mapper is None else mapper.base_mapper


def _connection_for(
    session: Session, trail: AuditTrail, mapper: Mapper[Any] | None
) -> Connection:
    if mapper is not None:
        return session.connection(bind_arguments={"mapper": mapper})
    return audit_connection(
        session,
        trail.tables,
        " log() and alog() with obj= use the bind of the object instead.",
    )


def _write_group(
    session: Session,
    trail: AuditTrail,
    connection: Connection,
    entries: Sequence[Entry],
    ctx: AuditContext,
) -> None:
    cached = _cached_row(session, connection)

    def work() -> TransactionRow:
        row = cached or insert_transaction(
            connection,
            trail.tables.transaction,
            transaction_values(ctx, trail.json_encoder),
        )
        insert_activities(connection, trail.tables.activity, row, entries)
        return row

    row = run_isolated(connection, trail.on_error, work)
    if row is not None and cached is None:
        owner = session.get_nested_transaction() or session.get_transaction()
        assert owner is not None  # session.connection() began one
        rows: dict[Connection, _CachedRow] = session.info.setdefault(_CACHE_KEY, {})
        rows[connection] = _CachedRow(owner, row)


def _cached_row(session: Session, connection: Connection) -> TransactionRow | None:
    rows: dict[Connection, _CachedRow] = session.info.get(_CACHE_KEY, {})
    cached = rows.get(connection)
    return None if cached is None else cached.row


def _after_transaction_end(session: Session, transaction: SessionTransaction) -> None:
    # Fires for every way a transaction ends, including Session.close()
    # without commit or rollback, which fires no commit or rollback event.
    # A released savepoint or a flush's subtransaction is not the end of the
    # database transaction: the rows live on in the enclosing one.
    if transaction.parent is None:
        session.info.pop(_CACHE_KEY, None)


def _after_soft_rollback(
    session: Session, previous_transaction: SessionTransaction
) -> None:
    rows: dict[Connection, _CachedRow] | None = session.info.get(_CACHE_KEY)
    if not rows:
        return
    # A savepoint spans every connection of the session, so its rollback
    # removes the rows it holds on each.
    for connection, cached in list(rows.items()):
        if _within(cached.owner, previous_transaction):
            del rows[connection]


def _within(transaction: SessionTransaction, ancestor: SessionTransaction) -> bool:
    current: SessionTransaction | None = transaction
    while current is not None:
        if current is ancestor:
            return True
        current = current.parent
    return False


def _after_rollback(session: Session) -> None:
    # Also fires for a savepoint rollback, so it must not drop the cached
    # transaction row (see the module docstring).
    discard_relationship_changes(session)
