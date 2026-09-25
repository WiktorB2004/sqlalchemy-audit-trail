"""Read-time compaction of activity rows.

The listener writes one ``entity.*`` row per flush and object, so a single
database transaction can hold several rows for the same object. Compaction
merges them into the net change the transaction made. It is a pure function
over rows that were already fetched: no session, no SQL.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from datetime import datetime
from itertools import pairwise
from typing import TypeAlias, TypedDict
from uuid import UUID

from audit_trail._typing import assert_never
from audit_trail.context import ContextSnapshot
from audit_trail.events import Crud
from audit_trail.relations import RelationshipChange
from audit_trail.serialization import JSONValue

__all__ = ["ActivityData", "ActivityRow", "FieldChange", "compact_rows"]

FieldChange: TypeAlias = list[JSONValue] | RelationshipChange
"""A column change ``[old, new]`` or a relationship change."""

_REDACTED = "***"  # same as diff.REDACTED
_UNKNOWN = "<unknown>"  # same as diff.UNKNOWN

_CRUD_BY_VERB: dict[str, Crud] = {member.value: member for member in Crud}

_GroupKey: TypeAlias = tuple[int, str | None, str | None]


class _ActivityDataBase(TypedDict):
    v: int


class ActivityData(_ActivityDataBase, total=False):
    """The ``data`` envelope of an activity row.

    Attributes:
        v: Envelope version.
        changes: ``entity.*`` changes keyed by attribute name.
        payload: Payload of a custom event.
        context: Request context snapshot taken when the entry was written.
    """

    changes: dict[str, FieldChange]
    payload: dict[str, JSONValue]
    context: ContextSnapshot


class ActivityRow(TypedDict):
    """One ``audit_activity`` row, as fetched from the database.

    Attributes:
        id: Row id.
        transaction_id: Id of the audit transaction the row belongs to.
        verb: Event verb, e.g. ``entity.updated``.
        severity: Severity value.
        object_type: Type of the changed object.
        object_id: Id of the changed object.
        object_label: Label of the object when the row was written.
        target_type: Type of the parent object.
        target_id: Id of the parent object.
        actor_id: Actor of the event.
        scope_id: Scope, e.g. a tenant.
        correlation_id: Correlation id of the transaction.
        created_at: Start of the database transaction.
        data: The ``data`` envelope.
    """

    id: int
    transaction_id: int
    verb: str
    severity: int
    object_type: str | None
    object_id: str | None
    object_label: str | None
    target_type: str | None
    target_id: str | None
    actor_id: str | None
    scope_id: str | None
    correlation_id: UUID | None
    created_at: datetime
    data: ActivityData


def compact_rows(
    rows: Iterable[ActivityRow], *, compact: bool = True
) -> list[ActivityRow]:
    """Merge the ``entity.*`` rows of each object within each transaction.

    Rows are grouped by ``(transaction_id, object_type, object_id)`` and each
    group is folded in ``id`` order. Whether the object existed before the
    transaction (the first verb is not ``entity.created``) and exists after it
    (the last verb is not ``entity.deleted``) decides the result:

    - neither: the object never existed outside the transaction, so the group
      is hidden;
    - only after: one ``entity.created`` with the final values;
    - only before: one ``entity.deleted`` with the old values of the first row;
    - both: one ``entity.updated``. A delete and re-insert of the same id
      becomes the difference between the state before the delete and after the
      insert. An update with no field left is hidden.

    Column changes merge to ``[first old, last new]``. In an
    ``entity.updated`` result a column whose old and new values are equal is
    dropped; ``entity.created`` and ``entity.deleted`` keep every column, as a
    replay needs the full state. Equality is on the canonical JSON form of the
    stored values (typed comparison already happened when they were written),
    so ``true`` and ``1`` differ. A ``"***"`` or ``"<unknown>"`` marker on
    either side is never treated as equal: it hides whether the value changed.
    Relationship changes merge net: an id added and then removed disappears,
    and the other way round. A relationship left with no ids is dropped for
    every verb.

    The merged row takes ``id``, ``created_at``, ``correlation_id`` and the
    output position of the group's lowest-id row; the other rows of the group
    are removed. ``severity`` is the highest of the group. ``object_label``,
    ``target_type``, ``target_id``, ``scope_id`` and ``data.context`` come from
    the last row. Every other row keeps its position, so input sorted by ``id``
    in either direction stays sorted.

    A group is returned as is when its rows have different ``actor_id``
    values, when its verbs are not a possible sequence (e.g. an update after a
    delete), or when it re-inserts a deleted id and has relationship changes
    (the collection before the delete is not known). Single-row groups and
    rows with other verbs are returned as the same objects. The input is never
    modified; merged rows may share nested values with it. Compacting a
    compacted result changes nothing.

    Args:
        rows: Activity rows, typically all rows of some transactions.
        compact: ``False`` returns the rows unchanged.

    Returns:
        The rows, compacted unless ``compact`` is ``False``.
    """
    rows = list(rows)
    if not compact:
        return rows

    groups: dict[_GroupKey, list[int]] = {}
    for index, row in enumerate(rows):
        if row["verb"] in _CRUD_BY_VERB:
            key = (row["transaction_id"], row["object_type"], row["object_id"])
            groups.setdefault(key, []).append(index)

    output: list[ActivityRow | None] = list(rows)
    for indices in groups.values():
        if len(indices) < 2:
            continue
        ordered = sorted(indices, key=lambda index: rows[index]["id"])
        group = [rows[index] for index in ordered]
        if not _can_compact(group):
            continue
        for index in indices:
            output[index] = None
        output[ordered[0]] = _merge(group)
    return [row for row in output if row is not None]


def _can_compact(group: Sequence[ActivityRow]) -> bool:
    if len({row["actor_id"] for row in group}) > 1:
        return False
    verbs = [_CRUD_BY_VERB[row["verb"]] for row in group]
    pairs = list(pairwise(verbs))
    if not all(_may_follow(previous, current) for previous, current in pairs):
        return False
    reinserts = (Crud.DELETED, Crud.CREATED) in pairs
    return not (reinserts and any(_has_relationships(row) for row in group))


def _may_follow(previous: Crud, current: Crud) -> bool:
    match previous:
        case Crud.CREATED | Crud.UPDATED:
            return current is not Crud.CREATED
        case Crud.DELETED:
            return current is Crud.CREATED
        case _:
            assert_never(previous)


def _has_relationships(row: ActivityRow) -> bool:
    changes = row["data"].get("changes", {})
    return any(isinstance(change, dict) for change in changes.values())


def _merge(group: Sequence[ActivityRow]) -> ActivityRow | None:
    first, last = group[0], group[-1]
    existed = _CRUD_BY_VERB[first["verb"]] is not Crud.CREATED
    exists = _CRUD_BY_VERB[last["verb"]] is not Crud.DELETED
    if existed and exists:
        verb = Crud.UPDATED
    elif exists:
        verb = Crud.CREATED
    elif existed:
        verb = Crud.DELETED
    else:
        return None

    changes = _merge_changes(group, drop_unchanged=verb is Crud.UPDATED)
    if verb is Crud.UPDATED and not changes:
        return None
    data: ActivityData = {"v": last["data"]["v"], "changes": changes}
    if "context" in last["data"]:
        data["context"] = last["data"]["context"]
    return {
        "id": first["id"],
        "transaction_id": first["transaction_id"],
        "verb": verb.value,
        "severity": max(row["severity"] for row in group),
        "object_type": first["object_type"],
        "object_id": first["object_id"],
        "object_label": last["object_label"],
        "target_type": last["target_type"],
        "target_id": last["target_id"],
        "actor_id": first["actor_id"],
        "scope_id": last["scope_id"],
        "correlation_id": first["correlation_id"],
        "created_at": first["created_at"],
        "data": data,
    }


def _merge_changes(
    group: Sequence[ActivityRow], *, drop_unchanged: bool
) -> dict[str, FieldChange]:
    order: dict[str, None] = {}
    columns: dict[str, list[JSONValue]] = {}
    # Insertion-ordered dicts used as sets keep the output deterministic.
    relations: dict[str, tuple[dict[str, None], dict[str, None]]] = {}
    for row in group:
        for field, change in row["data"].get("changes", {}).items():
            order[field] = None
            if isinstance(change, list):
                old = columns[field][0] if field in columns else change[0]
                columns[field] = [old, change[1]]
                continue
            added, removed = relations.setdefault(field, ({}, {}))
            for item in change["removed"]:
                if item in added:
                    del added[item]
                else:
                    removed[item] = None
            for item in change["added"]:
                if item in removed:
                    del removed[item]
                else:
                    added[item] = None

    merged: dict[str, FieldChange] = {}
    for field in order:
        if field in columns:
            old, new = columns[field]
            if not (drop_unchanged and _unchanged(old, new)):
                merged[field] = [old, new]
        else:
            added, removed = relations[field]
            if added or removed:
                merged[field] = {"added": list(added), "removed": list(removed)}
    return merged


def _unchanged(old: JSONValue, new: JSONValue) -> bool:
    if _is_marker(old) or _is_marker(new):
        return False
    return _canonical(old) == _canonical(new)


def _is_marker(value: JSONValue) -> bool:
    return value == _REDACTED or value == _UNKNOWN


def _canonical(value: JSONValue) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))
