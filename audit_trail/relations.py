"""Relationship deltas captured from attribute events.

Collection changes are recorded from the ORM's ``append`` / ``remove``
attribute events, not from ``attr.history``: history is reset by every flush,
so a removal written by an autoflush between two collection operations is no
longer visible when the unit of work ends. Events see every operation once,
and their cost is proportional to the delta, not to the collection size.

Loading a collection from the database (lazy, ``selectinload``,
``joinedload``, ``refresh``) populates it without firing these events, so a
load never looks like an edit.

Known limitations: changes that bypass the collection API (writing a foreign
key column directly, raw inserts into an association table) are invisible,
and a backref that moves an object away from a parent that is not loaded in
the session fires no ``remove`` on that parent.
"""

from __future__ import annotations

import json
from typing import Any, NamedTuple, TypedDict, cast

from sqlalchemy import event, inspect
from sqlalchemy.orm import (
    InstanceState,
    InstrumentedAttribute,
    RelationshipProperty,
    Session,
)

__all__ = [
    "RelationshipChange",
    "discard_relationship_changes",
    "pop_relationship_changes",
    "track_relationships",
]

_INFO_KEY = "audit_trail.relations"


class RelationshipChange(TypedDict):
    """Net change of one tracked collection since the last flush.

    Attributes:
        added: Object ids of members added to the collection.
        removed: Object ids of members removed from it.
    """

    added: list[str]
    removed: list[str]


class _TrackedAttribute(NamedTuple):
    cls: type[Any]
    key: str


_tracked: set[_TrackedAttribute] = set()


class _Delta:
    """Net changes of one collection since the last flush.

    Items are keyed by their ``InstanceState``, which hashes by identity, so a
    user-defined ``__eq__`` / ``__hash__`` on the model cannot merge two
    distinct rows. Plain dicts keep insertion order for deterministic output.
    """

    __slots__ = ("added", "removed")

    def __init__(self) -> None:
        self.added: dict[InstanceState[Any], None] = {}
        self.removed: dict[InstanceState[Any], None] = {}

    def append(self, item: InstanceState[Any]) -> None:
        if item in self.removed:
            del self.removed[item]
        else:
            self.added[item] = None

    def remove(self, item: InstanceState[Any]) -> None:
        if item in self.added:
            del self.added[item]
        else:
            self.removed[item] = None


def _delta(state: InstanceState[Any], key: str) -> _Delta:
    # InstanceState.info lives exactly as long as the instance, so the store
    # can't outlive its object or be confused by a recycled id().
    store: dict[str, _Delta] = state.info.setdefault(_INFO_KEY, {})
    return store.setdefault(key, _Delta())


def _on_expire(state: InstanceState[Any], attrs: Any) -> None:
    # Rollback, savepoint rollback, expire() and refresh() all throw away the
    # ORM's unflushed collection state; the deltas describing it go too.
    store: dict[str, _Delta] | None = state.info.get(_INFO_KEY)
    if not store:
        return
    if attrs is None:
        store.clear()
    else:
        for key in attrs:
            store.pop(key, None)


def track_relationships(*attributes: InstrumentedAttribute[Any]) -> None:
    """Record net ``added`` / ``removed`` changes of collection relationships.

    Registers ``append`` and ``remove`` listeners on each attribute (also
    covering assignment, ``clear()``, slicing and ``del``, which emit the same
    events) and an ``expire`` listener on its class. Listeners propagate to
    subclasses, so registering an attribute already tracked on the same class
    or a base class is a no-op.

    Args:
        *attributes: Class-bound collection relationships, e.g. ``Post.tags``.

    Raises:
        ValueError: If an attribute is not a collection ``relationship()``,
            or if the same relationship is already tracked on a subclass.
    """
    for attr in attributes:
        prop = attr.property
        if not isinstance(prop, RelationshipProperty) or not prop.uselist:
            raise ValueError(f"{attr} is not a collection relationship")
        cls, key = cast("type[Any]", attr.class_), attr.key
        # Listeners propagate to subclasses, so a key tracked on any class in
        # the MRO already covers this one; registering again would count
        # every change twice.
        if any(_TrackedAttribute(base, key) in _tracked for base in cls.__mro__):
            continue
        for tracked in _tracked:
            if tracked.key == key and issubclass(tracked.cls, cls):
                raise ValueError(
                    f"cannot track {cls.__name__}.{key}: subclass attribute "
                    f"{tracked.cls.__name__}.{key} is already tracked and its "
                    "changes would be counted twice"
                )
        _listen(attr, key)
        if not event.contains(cls, "expire", _on_expire):
            event.listen(cls, "expire", _on_expire, raw=True, propagate=True)
        _tracked.add(_TrackedAttribute(cls, key))


def _listen(attr: InstrumentedAttribute[Any], key: str) -> None:
    # The key comes from the closure, not from ``initiator.key``: an event
    # triggered through a backref carries the other side's token.
    def on_append(state: InstanceState[Any], value: Any, initiator: Any) -> None:
        _delta(state, key).append(inspect(value))

    def on_remove(state: InstanceState[Any], value: Any, initiator: Any) -> None:
        _delta(state, key).remove(inspect(value))

    event.listen(attr, "append", on_append, raw=True, propagate=True)
    event.listen(attr, "remove", on_remove, raw=True, propagate=True)


def pop_relationship_changes(obj: object) -> dict[str, RelationshipChange]:
    """Return and clear the net collection changes of ``obj``.

    Meant to be called from ``after_flush`` or later, when every added item
    has a primary key. Items that still have none were not written by the flush
    (SQLAlchemy skips objects not cascaded into the session), so they are
    left out, matching the database.

    Args:
        obj: A mapped instance whose relationships are tracked.

    Returns:
        ``{attribute: {"added": [object_id, ...], "removed": [...]}}`` for
        each tracked attribute with a non-empty net change; empty when nothing
        changed.
    """
    state = cast("InstanceState[Any]", inspect(obj))
    store: dict[str, _Delta] | None = state.info.pop(_INFO_KEY, None)
    if not store:
        return {}
    changes: dict[str, RelationshipChange] = {}
    for key, delta in store.items():
        added = _object_ids(delta.added)
        removed = _object_ids(delta.removed)
        if added or removed:
            changes[key] = {"added": added, "removed": removed}
    return changes


def discard_relationship_changes(session: Session) -> None:
    """Drop the pending deltas of every object attached to ``session``.

    A belt-and-braces call for rollback listeners: the ``expire`` listener
    already drops deltas whenever the ORM discards unflushed collection
    state. Pending objects expunged by a rollback keep their deltas, just as
    they keep their in-memory collections, so re-adding them to a session
    reports what that session's flush writes.

    Args:
        session: The session being rolled back.
    """
    for state in session.identity_map.all_states():
        state.info.pop(_INFO_KEY, None)
    for obj in session.new:
        inspect(obj).info.pop(_INFO_KEY, None)


def _object_ids(states: dict[InstanceState[Any], None]) -> list[str]:
    ids = []
    for state in states:
        identity = _primary_key(state)
        if identity is not None:
            ids.append(_object_id(identity))
    return ids


def _primary_key(state: InstanceState[Any]) -> tuple[Any, ...] | None:
    if state.key is not None:
        return state.key[1]
    # Objects inserted by the current flush get their identity key only after
    # after_flush; their primary key values are already in the instance dict.
    mapper = state.mapper
    values = tuple(
        state.dict.get(mapper.get_property_by_column(column).key)
        for column in mapper.primary_key
    )
    return None if any(value is None for value in values) else values


def _object_id(identity: tuple[Any, ...]) -> str:
    # Temporary local copy of the object_id format until the public
    # object_id_of helper lands: single-column key -> str(pk), composite key
    # -> canonical JSON array of strings.
    if len(identity) == 1:
        return str(identity[0])
    return json.dumps([str(v) for v in identity], separators=(",", ":"))
