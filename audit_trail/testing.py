"""Test helpers for applications that use audit_trail.

``assert_audited`` checks that an entry with the given fields was written and
``assert_not_audited`` that none was; ``aassert_audited`` and
``aassert_not_audited`` do the same on async binds. A failed assertion lists
the closest entries and the fields that differ.

``create_test_tables``, ``drop_test_tables`` and ``clear_audit_entries`` set
up the audit tables on a test database whose migrations do not create them.
The pytest fixtures built on them live in ``audit_trail.pytest_plugin``;
enable them in the root ``conftest.py``::

    pytest_plugins = ["audit_trail.pytest_plugin"]

This module does not import pytest.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Final, NamedTuple, TypeVar

from sqlalchemy import (
    ColumnElement,
    Connection,
    Engine,
    RowMapping,
    and_,
    or_,
    select,
)
from sqlalchemy.orm import Session

from audit_trail._compaction import ActivityRow
from audit_trail.config import Target
from audit_trail.diff import format_target, object_id_of, object_type_of
from audit_trail.maintenance import ensure_partitions
from audit_trail.migrations import (
    create_audit_tables,
    drop_audit_tables,
    qualified_name,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, AsyncSession

    from audit_trail.config import AuditTrail

__all__ = [
    "UNSET",
    "Unset",
    "aassert_audited",
    "aassert_not_audited",
    "assert_audited",
    "assert_not_audited",
    "clear_audit_entries",
    "create_test_tables",
    "drop_test_tables",
]

_SHOWN = 5
_T = TypeVar("_T")


class Unset(Enum):
    """Type of ``UNSET``, the default of every assertion filter."""

    UNSET = "UNSET"

    def __repr__(self) -> str:
        return "UNSET"


UNSET: Final = Unset.UNSET
"""Filter not given: the field is not checked. ``None`` means ``NULL``."""


class _ObjectKey(NamedTuple):
    type: str
    id: str


@dataclass(frozen=True)
class _Expected:
    """The filters, with ``obj`` and ``target`` as stored ids."""

    verb: str | Unset
    obj: _ObjectKey | Unset
    target: _ObjectKey | None | Unset
    actor_id: str | None | Unset
    scope_id: str | None | Unset
    severity: int | Unset
    changes: Mapping[str, object] | Unset
    payload: Mapping[str, object] | Unset


class _Result(NamedTuple):
    expected: _Expected
    matches: list[ActivityRow]
    candidates: list[ActivityRow]


class _Filters(NamedTuple):
    """The filters as given; ``obj`` and ``target`` are resolved after a flush."""

    verb: str | Unset
    obj: object
    target: object
    actor_id: str | None | Unset
    scope_id: str | None | Unset
    severity: int | Unset
    changes: Mapping[str, object] | Unset
    payload: Mapping[str, object] | Unset


def assert_audited(
    audit: AuditTrail,
    bind: Session | Connection | Engine,
    *,
    verb: str | Unset = UNSET,
    obj: object = UNSET,
    target: object = UNSET,
    actor_id: str | None | Unset = UNSET,
    scope_id: str | None | Unset = UNSET,
    severity: int | Unset = UNSET,
    changes: Mapping[str, object] | Unset = UNSET,
    payload: Mapping[str, object] | Unset = UNSET,
) -> list[ActivityRow]:
    """Assert that at least one audit entry matches every given filter.

    Reads the raw ``audit_activity`` rows as written, not compacted. A
    ``Session`` is flushed first, so its pending changes are audited. A
    ``Session`` or ``Connection`` also sees rows not committed yet; an
    ``Engine`` reads on a new connection and sees committed rows only.

    Values are compared with their stored JSON form: a datetime is an ISO
    string, a redacted value ``"***"``. ``unittest.mock.ANY`` matches any
    value, e.g. ``changes={"status": [ANY, "paid"]}``.

    Args:
        audit: The ``AuditTrail`` whose tables are read.
        bind: Session, connection or engine to read with.
        verb: The verb; an ``AuditEvent`` member works too.
        obj: The object: a mapped instance, a ``Target`` or a
            ``(type, id)`` tuple.
        target: The parent object, like ``obj``; ``None`` means no target.
        actor_id: The actor id; ``None`` means no actor.
        scope_id: The scope id; ``None`` means no scope.
        severity: The severity.
        changes: Changes the entry must contain; other keys are ignored.
            A column change is ``[old, new]``, a relationship change
            ``{"added": [...], "removed": [...]}``.
        payload: Payload fields the entry must contain; other keys are
            ignored.

    Returns:
        The matching entries, oldest first.

    Raises:
        AssertionError: No entry matches; the message lists the closest ones
            and how they differ.
        ValueError: ``obj`` or ``target`` has no primary key, or ``obj`` is
            ``None``.
    """
    __tracebackhide__ = True
    filters = _Filters(
        verb, obj, target, actor_id, scope_id, severity, changes, payload
    )
    return _check_audited(_run(bind, lambda sync: _search(audit, sync, filters)))


def assert_not_audited(
    audit: AuditTrail,
    bind: Session | Connection | Engine,
    *,
    verb: str | Unset = UNSET,
    obj: object = UNSET,
    target: object = UNSET,
    actor_id: str | None | Unset = UNSET,
    scope_id: str | None | Unset = UNSET,
    severity: int | Unset = UNSET,
    changes: Mapping[str, object] | Unset = UNSET,
    payload: Mapping[str, object] | Unset = UNSET,
) -> None:
    """Assert that no audit entry matches every given filter.

    Reads as ``assert_audited`` does, with the same filters.

    Args:
        audit: See ``assert_audited``.
        bind: See ``assert_audited``.
        verb: See ``assert_audited``.
        obj: See ``assert_audited``.
        target: See ``assert_audited``.
        actor_id: See ``assert_audited``.
        scope_id: See ``assert_audited``.
        severity: See ``assert_audited``.
        changes: See ``assert_audited``.
        payload: See ``assert_audited``.

    Raises:
        AssertionError: An entry matches; the message lists the matches.
        ValueError: See ``assert_audited``.
    """
    __tracebackhide__ = True
    filters = _Filters(
        verb, obj, target, actor_id, scope_id, severity, changes, payload
    )
    _check_not_audited(_run(bind, lambda sync: _search(audit, sync, filters)))


async def aassert_audited(
    audit: AuditTrail,
    bind: AsyncSession | AsyncConnection | AsyncEngine,
    *,
    verb: str | Unset = UNSET,
    obj: object = UNSET,
    target: object = UNSET,
    actor_id: str | None | Unset = UNSET,
    scope_id: str | None | Unset = UNSET,
    severity: int | Unset = UNSET,
    changes: Mapping[str, object] | Unset = UNSET,
    payload: Mapping[str, object] | Unset = UNSET,
) -> list[ActivityRow]:
    """Async ``assert_audited``, for an async session, connection or engine.

    Args:
        audit: See ``assert_audited``.
        bind: Async session, connection or engine to read with.
        verb: See ``assert_audited``.
        obj: See ``assert_audited``.
        target: See ``assert_audited``.
        actor_id: See ``assert_audited``.
        scope_id: See ``assert_audited``.
        severity: See ``assert_audited``.
        changes: See ``assert_audited``.
        payload: See ``assert_audited``.

    Returns:
        The matching entries, oldest first.

    Raises:
        AssertionError: See ``assert_audited``.
        ValueError: See ``assert_audited``.
    """
    __tracebackhide__ = True
    filters = _Filters(
        verb, obj, target, actor_id, scope_id, severity, changes, payload
    )
    result = await _arun(bind, lambda sync: _search(audit, sync, filters))
    return _check_audited(result)


async def aassert_not_audited(
    audit: AuditTrail,
    bind: AsyncSession | AsyncConnection | AsyncEngine,
    *,
    verb: str | Unset = UNSET,
    obj: object = UNSET,
    target: object = UNSET,
    actor_id: str | None | Unset = UNSET,
    scope_id: str | None | Unset = UNSET,
    severity: int | Unset = UNSET,
    changes: Mapping[str, object] | Unset = UNSET,
    payload: Mapping[str, object] | Unset = UNSET,
) -> None:
    """Async ``assert_not_audited``, for an async session, connection or engine.

    Args:
        audit: See ``assert_audited``.
        bind: Async session, connection or engine to read with.
        verb: See ``assert_audited``.
        obj: See ``assert_audited``.
        target: See ``assert_audited``.
        actor_id: See ``assert_audited``.
        scope_id: See ``assert_audited``.
        severity: See ``assert_audited``.
        changes: See ``assert_audited``.
        payload: See ``assert_audited``.

    Raises:
        AssertionError: See ``assert_not_audited``.
        ValueError: See ``assert_audited``.
    """
    __tracebackhide__ = True
    filters = _Filters(
        verb, obj, target, actor_id, scope_id, severity, changes, payload
    )
    _check_not_audited(await _arun(bind, lambda sync: _search(audit, sync, filters)))


def create_test_tables(
    audit: AuditTrail,
    connection: Connection,
    *,
    months_ahead: int = 1,
    now: datetime | None = None,
) -> None:
    """Create the audit tables and their partitions on a test database.

    For databases whose migrations do not create the audit tables: it fails
    when they exist. Runs in the connection's current transaction, which must
    not be ``AUTOCOMMIT``; the caller commits.

    Args:
        audit: The ``AuditTrail`` whose tables are created.
        connection: Connection with DDL privileges.
        months_ahead: Monthly partitions to create after the current month.
        now: Reference time for the partitions. ``None`` uses the database's
            ``now()``.
    """
    create_audit_tables(connection, audit.tables, audit.severities)
    ensure_partitions(
        connection,
        audit.tables,
        audit.severities,
        months_ahead=months_ahead,
        now=now,
    )


def drop_test_tables(audit: AuditTrail, connection: Connection) -> None:
    """Drop the audit tables with their partitions; the schema is kept.

    Args:
        audit: The ``AuditTrail`` whose tables are dropped.
        connection: Connection with DDL privileges.
    """
    drop_audit_tables(connection, audit.tables)


def clear_audit_entries(audit: AuditTrail, connection: Connection) -> None:
    """Delete every audit entry and transaction row with ``TRUNCATE``.

    Args:
        audit: The ``AuditTrail`` whose tables are emptied.
        connection: Connection to run on.
    """
    names = ", ".join(
        qualified_name(table.schema, table.name)
        for table in (audit.tables.activity, audit.tables.transaction)
    )
    connection.exec_driver_sql(
        f"TRUNCATE {names}", execution_options={"no_parameters": True}
    )


def _run(
    bind: Session | Connection | Engine,
    work: Callable[[Session | Connection], _T],
) -> _T:
    if isinstance(bind, Engine):
        with bind.connect() as connection:
            return work(connection)
    return work(bind)


async def _arun(
    bind: AsyncSession | AsyncConnection | AsyncEngine,
    work: Callable[[Session | Connection], _T],
) -> _T:
    # Imported here: sqlalchemy's asyncio support is an optional extra.
    from sqlalchemy.ext.asyncio import AsyncEngine

    if isinstance(bind, AsyncEngine):
        async with bind.connect() as connection:
            return await connection.run_sync(work)
    return await bind.run_sync(work)


def _search(
    audit: AuditTrail, bind: Session | Connection, filters: _Filters
) -> _Result:
    if isinstance(bind, Session):
        bind.flush()
    obj = UNSET if isinstance(filters.obj, Unset) else _object_key(filters.obj)
    if obj is None:
        raise ValueError("obj must name an object, not None")
    expected = _Expected(
        verb=filters.verb if isinstance(filters.verb, Unset) else str(filters.verb),
        obj=obj,
        target=(
            UNSET if isinstance(filters.target, Unset) else _object_key(filters.target)
        ),
        actor_id=filters.actor_id,
        scope_id=filters.scope_id,
        severity=(
            filters.severity
            if isinstance(filters.severity, Unset)
            else int(filters.severity)
        ),
        changes=filters.changes,
        payload=filters.payload,
    )
    table = audit.tables.activity
    near: list[ColumnElement[bool]] = []
    if not isinstance(expected.verb, Unset):
        near.append(table.c.verb == expected.verb)
    if not isinstance(expected.obj, Unset):
        near.append(
            and_(
                table.c.object_type == expected.obj.type,
                table.c.object_id == expected.obj.id,
            )
        )
    statement = select(table).order_by(table.c.id)
    if near:
        statement = statement.where(or_(*near))
    candidates = [_activity(row) for row in bind.execute(statement).mappings()]
    matches = [row for row in candidates if not _mismatches(row, expected)]
    return _Result(expected, matches, candidates)


def _check_audited(result: _Result) -> list[ActivityRow]:
    __tracebackhide__ = True
    if result.matches:
        return result.matches
    lines = ["no audit entry matches", f"  expected: {_describe(result.expected)}"]
    where = _candidate_scope(result.expected)
    if not result.candidates:
        lines.append(f"  no audit entries {where}")
    else:
        closest = sorted(
            result.candidates,
            key=lambda row: (len(_mismatches(row, result.expected)), -row["id"]),
        )[:_SHOWN]
        lines.append(
            f"  closest {len(closest)} of {len(result.candidates)} entries {where}:"
        )
        for row in closest:
            lines.append(f"    {_headline(row)}")
            lines.extend(f"      {line}" for line in _mismatches(row, result.expected))
    raise AssertionError("\n".join(lines))


def _check_not_audited(result: _Result) -> None:
    __tracebackhide__ = True
    matches = result.matches
    if not matches:
        return
    noun = "entry matches" if len(matches) == 1 else "entries match"
    lines = [
        f"{len(matches)} audit {noun}",
        f"  expected none with: {_describe(result.expected)}",
    ]
    lines.extend(f"    {_headline(row)}" for row in matches[:_SHOWN])
    if len(matches) > _SHOWN:
        lines.append(f"    ... and {len(matches) - _SHOWN} more")
    raise AssertionError("\n".join(lines))


def _candidate_scope(expected: _Expected) -> str:
    has_verb = not isinstance(expected.verb, Unset)
    has_obj = not isinstance(expected.obj, Unset)
    if has_verb and has_obj:
        return "with this verb or object"
    if has_verb:
        return "with this verb"
    if has_obj:
        return "on this object"
    return "recorded"


def _object_key(value: object) -> _ObjectKey | None:
    if value is None:
        return None
    if isinstance(value, tuple):
        stored = format_target(Target(*value))
        return None if stored is None else _ObjectKey(stored.type, stored.id)
    return _ObjectKey(object_type_of(value), object_id_of(value))


def _pair(key: _ObjectKey | None) -> tuple[str, str] | None:
    return None if key is None else (key.type, key.id)


def _mismatches(row: ActivityRow, expected: _Expected) -> list[str]:
    found: list[str] = []
    if not isinstance(expected.verb, Unset) and row["verb"] != expected.verb:
        found.append(f"verb: expected {expected.verb!r}, got {row['verb']!r}")
    if not isinstance(expected.obj, Unset):
        want_obj = _pair(expected.obj)
        got_obj = (row["object_type"], row["object_id"])
        if got_obj != want_obj:
            found.append(f"obj: expected {want_obj!r}, got {got_obj!r}")
    if not isinstance(expected.target, Unset):
        want_target = _pair(expected.target)
        got_target = (
            None
            if row["target_type"] is None and row["target_id"] is None
            else (row["target_type"], row["target_id"])
        )
        if got_target != want_target:
            found.append(f"target: expected {want_target!r}, got {got_target!r}")
    if (
        not isinstance(expected.actor_id, Unset)
        and row["actor_id"] != expected.actor_id
    ):
        found.append(
            f"actor_id: expected {expected.actor_id!r}, got {row['actor_id']!r}"
        )
    if (
        not isinstance(expected.scope_id, Unset)
        and row["scope_id"] != expected.scope_id
    ):
        found.append(
            f"scope_id: expected {expected.scope_id!r}, got {row['scope_id']!r}"
        )
    if (
        not isinstance(expected.severity, Unset)
        and row["severity"] != expected.severity
    ):
        found.append(
            f"severity: expected {expected.severity!r}, got {row['severity']!r}"
        )
    data = row["data"]
    if not isinstance(expected.changes, Unset):
        found.extend(_subset("changes", expected.changes, data.get("changes")))
    if not isinstance(expected.payload, Unset):
        found.extend(_subset("payload", expected.payload, data.get("payload")))
    return found


def _subset(
    name: str, expected: Mapping[str, object], actual: Mapping[str, object] | None
) -> list[str]:
    if actual is None:
        return [f"{name}: expected {dict(expected)!r}, entry has none"]
    found: list[str] = []
    for key, value in expected.items():
        if key not in actual:
            found.append(f"{name}[{key!r}]: missing")
        elif value != actual[key]:  # expected on the left, so ANY matches
            found.append(f"{name}[{key!r}]: expected {value!r}, got {actual[key]!r}")
    return found


def _describe(expected: _Expected) -> str:
    parts: list[str] = []
    if not isinstance(expected.verb, Unset):
        parts.append(f"verb={expected.verb!r}")
    if not isinstance(expected.obj, Unset):
        parts.append(f"obj={_pair(expected.obj)!r}")
    if not isinstance(expected.target, Unset):
        parts.append(f"target={_pair(expected.target)!r}")
    if not isinstance(expected.actor_id, Unset):
        parts.append(f"actor_id={expected.actor_id!r}")
    if not isinstance(expected.scope_id, Unset):
        parts.append(f"scope_id={expected.scope_id!r}")
    if not isinstance(expected.severity, Unset):
        parts.append(f"severity={expected.severity!r}")
    if not isinstance(expected.changes, Unset):
        parts.append(f"changes={dict(expected.changes)!r}")
    if not isinstance(expected.payload, Unset):
        parts.append(f"payload={dict(expected.payload)!r}")
    return ", ".join(parts) or "any entry"


def _headline(row: ActivityRow) -> str:
    parts = [
        f"#{row['id']}",
        row["verb"],
        row["object_type"],
        row["object_id"],
        f"(transaction {row['transaction_id']})",
    ]
    return " ".join(part for part in parts if part is not None)


def _activity(row: RowMapping) -> ActivityRow:
    return {
        "id": row["id"],
        "transaction_id": row["transaction_id"],
        "verb": row["verb"],
        "severity": row["severity"],
        "object_type": row["object_type"],
        "object_id": row["object_id"],
        "object_label": row["object_label"],
        "target_type": row["target_type"],
        "target_id": row["target_id"],
        "actor_id": row["actor_id"],
        "scope_id": row["scope_id"],
        "correlation_id": row["correlation_id"],
        "created_at": row["created_at"],
        "data": row["data"],
    }
