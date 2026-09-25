"""Session event listeners that capture ORM changes.

``install`` registers the listeners on one session class: the class a
``sessionmaker`` builds, or a ``Session`` subclass (and so its subclasses).
Never on the base ``Session``, which would also cover Alembic, other engines
and every other session in the process.

``after_flush`` turns the flushed ``Audited`` instances into ``entity.*``
entries and writes them with plain SQL on ``session.connection()``, in the
same database transaction as the changes, so a rollback undoes both.

The ``audit_transaction`` row is inserted by the first entry of a database
transaction and cached in ``session.info`` together with the
``SessionTransaction`` (root or savepoint) it was inserted in:

- rolling back that ``SessionTransaction`` or one of its ancestors
  (``after_soft_rollback``) drops the cache, because the row is gone;
- ``after_transaction_end`` drops it when the outermost transaction ends,
  however it ends: commit, rollback, or ``Session.close()`` (which fires no
  commit or rollback event). Releasing a savepoint also ends a
  ``SessionTransaction``, but the row then lives on in the enclosing one;
- ``after_rollback`` never touches it, since it also fires when a savepoint
  is rolled back, which may leave a row of the enclosing transaction intact.

These state listeners run even when ``session.info["audit_enabled"]`` is
``False``; only capture is switched off, so toggling the flag in the middle
of a transaction cannot leave a stale cache behind.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import Iterable, Sequence
from itertools import chain
from typing import TYPE_CHECKING, Any, NamedTuple, TypeVar

from sqlalchemy import event, inspect
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
    from sqlalchemy.orm import Mapper, SessionTransaction, UOWTransaction

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


class _CachedRow(NamedTuple):
    owner: SessionTransaction
    row: TransactionRow


def install(
    trail: AuditTrail, session_factory: sessionmaker[Any] | type[Session]
) -> None:
    """Register the audit listeners on a session factory's class.

    Also starts tracking the ``track_relationships`` of every ``Audited``
    model, configured now or later. Tracking is attached to the model
    classes, so it is process-wide: tracked collections record their net
    changes in any session, and those records are dropped when the instance
    is expired or garbage collected.

    Args:
        trail: The configuration the listeners write with.
        session_factory: A ``sessionmaker`` or a ``Session`` subclass.

    Raises:
        TypeError: ``session_factory`` is not a ``sessionmaker`` or a
            ``Session`` subclass, or it is asynchronous (not supported yet).
        ValueError: ``session_factory`` is the base ``Session``, or an
            ``AuditTrail`` is already installed on its class, a base class or
            a subclass of it.
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
        if _is_async(factory):
            raise TypeError("async sessions are not supported yet")
        raise TypeError(
            f"install() needs a sessionmaker or a Session subclass, got {factory!r}"
        )
    if cls is Session:
        raise ValueError(
            "install() refuses the base Session: its listeners would audit "
            "every session in the process; pass your sessionmaker or a "
            "Session subclass"
        )
    return cls


def _is_async(factory: object) -> bool:
    # Checked through sys.modules so sync-only hosts never import asyncio
    # support (and greenlet) just to be told it is not supported.
    asyncio_module = sys.modules.get("sqlalchemy.ext.asyncio")
    if asyncio_module is None:
        return False
    async_types = (asyncio_module.async_sessionmaker, asyncio_module.AsyncSession)
    return isinstance(factory, async_types) or (
        isinstance(factory, type) and issubclass(factory, asyncio_module.AsyncSession)
    )


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
    for name in options_of(cls).track_relationships:
        prop = mapper.relationships.get(name)
        if prop is None:
            raise ValueError(
                f"{cls.__qualname__}: track_relationships names {name!r}, "
                "which is not a relationship"
            )
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

    def _entries(self, session: Session, ctx: AuditContext) -> list[Entry]:
        trail = self.trail
        context = context_data(ctx, trail.json_encoder)
        batches: tuple[tuple[ChangeKind, Iterable[object]], ...] = (
            ("created", session.new),
            ("updated", session.dirty),
            ("deleted", session.deleted),
        )
        entries: list[Entry] = []
        for kind, objects in batches:
            for obj in objects:
                if not isinstance(obj, Audited):
                    continue
                entry = self._entry(obj, kind, ctx, context)
                if entry is not None:
                    entries.append(entry)
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


def write_entries(
    session: Session, trail: AuditTrail, entries: Sequence[Entry], ctx: AuditContext
) -> None:
    """Write entries in the session's current database transaction.

    Inserts the ``audit_transaction`` row first when the transaction has
    none yet, then all entries with one ``executemany``, following
    ``trail.on_error``. Uses only ``session.connection()``, never the ORM.

    Args:
        session: A session of an installed class.
        trail: The configuration to write with.
        entries: The entries.
        ctx: The context, used when the transaction row is created.
    """
    connection = session.connection()
    cached = _cached_row(session)

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
        session.info[_CACHE_KEY] = _CachedRow(owner, row)


def _cached_row(session: Session) -> TransactionRow | None:
    cached: _CachedRow | None = session.info.get(_CACHE_KEY)
    return None if cached is None else cached.row


def _after_transaction_end(session: Session, transaction: SessionTransaction) -> None:
    # Fires for every way a transaction ends, including Session.close()
    # without commit or rollback, which fires no commit or rollback event.
    # A released savepoint or a flush's subtransaction is not the end of the
    # database transaction: the row lives on in the enclosing one.
    if transaction.parent is None:
        session.info.pop(_CACHE_KEY, None)


def _after_soft_rollback(
    session: Session, previous_transaction: SessionTransaction
) -> None:
    cached: _CachedRow | None = session.info.get(_CACHE_KEY)
    if cached is None:
        return
    transaction: SessionTransaction | None = cached.owner
    while transaction is not None:
        if transaction is previous_transaction:
            session.info.pop(_CACHE_KEY, None)
            return
        transaction = transaction.parent


def _after_rollback(session: Session) -> None:
    # Also fires for a savepoint rollback, so it must not drop the cached
    # transaction row (see the module docstring).
    discard_relationship_changes(session)
