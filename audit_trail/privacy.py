"""GDPR operations: scrub and scrub_actor.

These are the only updates the library ever makes to audit rows. Each one
runs in the caller's transaction on a ``Connection`` and records itself as an
``audit.scrubbed`` entry in that same transaction, so the erasure and its
record are committed together or not at all. The entry holds what was
scrubbed and how many rows changed, never an erased value.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Callable
from datetime import datetime
from typing import TYPE_CHECKING, NamedTuple

from sqlalchemy import (
    Connection,
    Text,
    Update,
    and_,
    false,
    func,
    literal_column,
    null,
    or_,
    update,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB

from audit_trail.context import AuditContext, current_context
from audit_trail.diff import ERASED
from audit_trail.events import AuditSystem
from audit_trail.writer import (
    ENVELOPE_VERSION,
    Entry,
    context_data,
    insert_activities,
    insert_transaction,
    transaction_values,
)

if TYPE_CHECKING:
    from audit_trail.serialization import JSONValue
    from audit_trail.tables import AuditTables

ACTOR_FIELDS: tuple[str, ...] = ("actor_label", "remote_addr", "user_agent", "meta")
"""Columns of ``audit_transaction`` and keys of ``data.context`` that
``scrub_actor`` clears."""

_LIBRARY_VERBS = [member.value for member in AuditSystem]

# SQL building blocks of the erased ``data``. ``data`` is the column of the
# row being updated; the subquery aliases (e, f, r) have no column of that
# name. The marker is a constant, never a bound value.
_MARK = f"'{json.dumps(ERASED)}'::jsonb"


def _erase(value: str) -> str:
    # A non-null JSON value becomes the marker; JSON null stays null.
    return f"CASE WHEN jsonb_typeof({value}) = 'null' THEN {value} ELSE {_MARK} END"


def _erase_items(array: str) -> str:
    # Every element of a JSON array erased, order and length kept.
    return (
        f"(SELECT coalesce(jsonb_agg({_erase('e.x')} ORDER BY e.n), '[]'::jsonb) "
        f"FROM jsonb_array_elements({array}) WITH ORDINALITY AS e(x, n))"
    )


# One entry of data.changes: a column change [old, new], or a relationship
# change {"added": [...], "removed": [...]}; both keep their shape.
_ERASED_CHANGE = (
    "CASE jsonb_typeof(f.v) "
    f"WHEN 'array' THEN {_erase_items('f.v')} "
    "WHEN 'object' THEN (SELECT coalesce(jsonb_object_agg(r.k, "
    f"CASE WHEN jsonb_typeof(r.v) = 'array' THEN {_erase_items('r.v')} "
    f"ELSE {_erase('r.v')} END), '{{}}'::jsonb) "
    "FROM jsonb_each(f.v) AS r(k, v)) "
    f"ELSE {_erase('f.v')} END"
)

# Keys of data.changes and data.payload are kept. A payload value is erased
# whole: keys nested inside it can be personal data themselves. A changes or
# payload that is not an object is erased whole; a missing one stays missing.
_ERASED_CHANGES = (
    "CASE WHEN jsonb_typeof(data -> 'changes') = 'object' THEN "
    f"(SELECT coalesce(jsonb_object_agg(f.k, {_ERASED_CHANGE}), '{{}}'::jsonb) "
    f"FROM jsonb_each(data -> 'changes') AS f(k, v)) ELSE {_MARK} END"
)
_ERASED_PAYLOAD = (
    "CASE WHEN jsonb_typeof(data -> 'payload') = 'object' THEN "
    f"(SELECT coalesce(jsonb_object_agg(f.k, {_erase('f.v')}), '{{}}'::jsonb) "
    f"FROM jsonb_each(data -> 'payload') AS f(k, v)) ELSE {_MARK} END"
)
_ERASED_DATA = (
    f"jsonb_set(jsonb_set(data, '{{changes}}', {_ERASED_CHANGES}, false), "
    f"'{{payload}}', {_ERASED_PAYLOAD}, false)"
)

_ACTOR_KEYS = "ARRAY[" + ", ".join(f"'{key}'" for key in ACTOR_FIELDS) + "]"


class ScrubNotAllowedError(RuntimeError):
    """``scrub`` or ``scrub_actor`` was called without ``allow_scrub=True``."""


class ScrubResult(NamedTuple):
    """Rows a scrub changed.

    Attributes:
        activity_rows: ``audit_activity`` rows updated.
        transaction_rows: ``audit_transaction`` rows updated (always ``0``
            for ``scrub``).
    """

    activity_rows: int
    transaction_rows: int


class ScrubbedRecord(NamedTuple):
    """What the ``audit.scrubbed`` entry of a scrub is built from.

    Attributes:
        severity: Severity of the entry (the registry's ``system_severity``).
        context: Context of whoever runs the scrub.
        json_encoder: Host encoder for ``extra`` values of the context.
    """

    severity: int
    context: AuditContext
    json_encoder: type[json.JSONEncoder] | None


def check_allowed(allow_scrub: bool) -> None:
    """Refuse a scrub unless it was enabled.

    Args:
        allow_scrub: The ``AuditTrail`` setting.

    Raises:
        ScrubNotAllowedError: ``allow_scrub`` is ``False``.
    """
    if not allow_scrub:
        raise ScrubNotAllowedError(
            "scrub needs AuditTrail(allow_scrub=True) and an engine whose role "
            "may update the audit tables"
        )


def check_since(since: datetime | None) -> None:
    """Refuse a naive ``since``, which PostgreSQL would read in the session's zone.

    Args:
        since: The lower bound of ``created_at``, or ``None``.

    Raises:
        ValueError: ``since`` has no time zone.
    """
    if since is not None and since.utcoffset() is None:
        raise ValueError("since must be timezone-aware")


def scrub_context(
    context_provider: Callable[[], AuditContext | None] | None,
) -> AuditContext:
    """Return the context of whoever runs a scrub; there is no session.

    Args:
        context_provider: The host hook, checked before the context variable.

    Returns:
        The provided context, else the active ``context()``, else an
        anonymous one.
    """
    if context_provider is not None:
        provided = context_provider()
        if provided is not None:
            return provided
    active = current_context()
    return AuditContext() if active is None else active


def scrub_statement(
    tables: AuditTables,
    object_type: str,
    object_id: str,
    *,
    include_targets: bool,
    since: datetime | None,
) -> Update:
    """Build the ``UPDATE`` that erases the entries of one object.

    Args:
        tables: The audit tables.
        object_type: Stored ``object_type`` of the object.
        object_id: Stored ``object_id`` of the object.
        include_targets: Also erase entries whose target is the object.
        since: Only entries with ``created_at >= since``; ``None`` for all.

    Returns:
        The statement; its rowcount is the number of rows erased.
    """
    c = tables.activity.c
    erased = literal_column(_ERASED_DATA, JSONB)
    match = and_(c.object_type == object_type, c.object_id == object_id)
    if include_targets:
        match = or_(match, and_(c.target_type == object_type, c.target_id == object_id))
    conditions = [match, c.verb.not_in(_LIBRARY_VERBS)]
    if since is not None:
        conditions.append(c.created_at >= since)
    # Rows already erased are left alone, so a repeated scrub changes nothing.
    conditions.append(or_(c.object_label.is_not(None), c.data.is_distinct_from(erased)))
    return (
        update(tables.activity)
        .where(*conditions)
        .values(object_label=null(), data=erased)
    )


def scrub(
    connection: Connection,
    tables: AuditTables,
    object_type: str,
    object_id: str,
    *,
    include_targets: bool,
    since: datetime | None,
    record: ScrubbedRecord,
) -> ScrubResult:
    """Erase the values an object's entries hold, and record it.

    In every matching ``audit_activity`` row (except the library's own
    ``audit.*`` entries), each non-null value in ``data.changes`` and
    ``data.payload`` becomes ``"[erased]"``, and ``object_label`` becomes
    ``NULL``. Field keys stay, so the history still shows what changed; a
    ``null`` stays ``null``. Column changes keep their ``[old, new]`` shape
    and relationship changes their ``added``/``removed`` lists, with every id
    erased; a payload value is erased whole, including anything nested in
    it. ``data.context`` is left to ``scrub_actor``.

    Runs in the connection's current transaction; the caller commits.

    Args:
        connection: Connection whose role may update the audit tables.
        tables: The audit tables.
        object_type: Stored ``object_type`` of the object.
        object_id: Stored ``object_id`` of the object.
        include_targets: Also erase entries whose target is the object, such
            as changes of its children.
        since: Only entries with ``created_at >= since``; ``None`` for all.
        record: Builds the ``audit.scrubbed`` entry.

    Returns:
        The number of rows erased.

    Raises:
        ValueError: The connection is in ``AUTOCOMMIT`` mode.
    """
    _check_transaction(connection)
    statement = scrub_statement(
        tables,
        object_type,
        object_id,
        include_targets=include_targets,
        since=since,
    )
    erased = connection.execute(statement).rowcount
    _write_record(
        connection,
        tables,
        record.context,
        record,
        object_type=object_type,
        object_id=object_id,
        payload={
            "operation": "scrub",
            "object_type": object_type,
            "object_id": object_id,
            "include_targets": include_targets,
            "since": None if since is None else since.isoformat(),
            "activity_rows": erased,
        },
    )
    return ScrubResult(activity_rows=erased, transaction_rows=0)


def scrub_actor(
    connection: Connection,
    tables: AuditTables,
    actor_id: str,
    *,
    record: ScrubbedRecord,
) -> ScrubResult:
    """Clear an actor's personal context, and record it.

    ``audit_transaction`` rows with this ``actor_id`` get ``actor_label``,
    ``remote_addr``, ``user_agent`` and ``meta`` set to ``NULL``; the
    ``audit_activity`` rows with this ``actor_id`` lose those keys from
    ``data.context``. ``actor_id`` itself stays everywhere.

    A transaction row belongs to the actor it was created with: a request
    that wrote its first entry anonymously and then called ``set_actor``
    keeps its address and user agent on that anonymous row.

    When the actor scrubs themself, the ``audit.scrubbed`` entry is written
    without those fields too.

    Runs in the connection's current transaction; the caller commits.

    Args:
        connection: Connection whose role may update the audit tables.
        tables: The audit tables.
        actor_id: The actor's ``actor_id``.
        record: Builds the ``audit.scrubbed`` entry.

    Returns:
        The numbers of rows changed.

    Raises:
        ValueError: The connection is in ``AUTOCOMMIT`` mode.
    """
    _check_transaction(connection)
    transaction = tables.transaction
    cleared = connection.execute(
        update(transaction)
        .where(
            transaction.c.actor_id == actor_id,
            or_(*(transaction.c[name].is_not(None) for name in ACTOR_FIELDS)),
        )
        .values({name: null() for name in ACTOR_FIELDS})
    ).rowcount

    activity = tables.activity
    keys = literal_column(_ACTOR_KEYS, ARRAY(Text))
    context = activity.c.data["context"]
    stripped = connection.execute(
        update(activity)
        .where(activity.c.actor_id == actor_id, context.has_any(keys))
        .values(
            data=func.jsonb_set(
                activity.c.data,
                literal_column("'{context}'"),
                context.op("-", return_type=JSONB)(keys),
                false(),
                type_=JSONB,
            )
        )
    ).rowcount

    ctx = record.context
    if ctx.actor_id == actor_id:
        ctx = dataclasses.replace(
            ctx, actor_label=None, remote_addr=None, user_agent=None, extra={}
        )
    _write_record(
        connection,
        tables,
        ctx,
        record,
        object_type=None,
        object_id=None,
        payload={
            "operation": "scrub_actor",
            "actor_id": actor_id,
            "transaction_rows": cleared,
            "activity_rows": stripped,
        },
    )
    return ScrubResult(activity_rows=stripped, transaction_rows=cleared)


def _check_transaction(connection: Connection) -> None:
    if getattr(connection.connection.dbapi_connection, "autocommit", False):
        raise ValueError("scrub needs a transaction, not AUTOCOMMIT")


def _write_record(
    connection: Connection,
    tables: AuditTables,
    ctx: AuditContext,
    record: ScrubbedRecord,
    *,
    object_type: str | None,
    object_id: str | None,
    payload: dict[str, JSONValue],
) -> None:
    # The payload comes from the arguments and the row counts only.
    row = insert_transaction(
        connection, tables.transaction, transaction_values(ctx, record.json_encoder)
    )
    entry: Entry = {
        "verb": AuditSystem.SCRUBBED.value,
        "severity": record.severity,
        "object_type": object_type,
        "object_id": object_id,
        "object_label": None,
        "target_type": None,
        "target_id": None,
        "actor_id": ctx.actor_id,
        "scope_id": ctx.scope_id,
        "data": {
            "v": ENVELOPE_VERSION,
            "payload": payload,
            "context": context_data(ctx, record.json_encoder),
        },
    }
    insert_activities(connection, tables.activity, row, [entry])
