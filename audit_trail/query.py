"""Read path: grouped listing, object history and entry details.

``AuditQuery.list_groups`` lists audit entries grouped by database
transaction, newest first, with keyset pagination. It runs in two stages:

1. One query per requested severity (``LIMIT limit + 1`` each, merged in
   Python) collects the ids of the page's transactions. A single-severity
   query reads the monthly partitions in order and stops at the limit; a query
   over several severities would read all of their rows.
2. The complete groups are fetched with ``transaction_id IN (...)`` and
   explicit ``created_at`` bounds, so only the partitions of the page's time
   range are read, and their ``audit_transaction`` rows likewise.

Both stages run after ``SET LOCAL plan_cache_mode = 'force_custom_plan'``: a
generic plan of a prepared statement (asyncpg, psycopg after a few executions)
cannot prune partitions by the query's parameters at plan time.
"""

from __future__ import annotations

import base64
import binascii
import heapq
from collections.abc import Collection, Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, NamedTuple
from uuid import UUID

from sqlalchemy import (
    ColumnElement,
    RowMapping,
    and_,
    false,
    select,
    text,
    true,
    tuple_,
)

from audit_trail._compaction import ActivityRow, compact_rows
from audit_trail.serialization import JSONValue
from audit_trail.tables import AuditTables

if TYPE_CHECKING:
    from sqlalchemy import ColumnClause, Table
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import Session

__all__ = [
    "ActivityRow",
    "AuditQuery",
    "Cursor",
    "Group",
    "Page",
    "TransactionHeader",
    "Visibility",
    "changed_fields",
]

_CUSTOM_PLAN = text("SET LOCAL plan_cache_mode = 'force_custom_plan'")


class Cursor(NamedTuple):
    """Position in the listing: ``(created_at, id)`` of an activity row.

    ``list_groups`` continues with the rows after it in
    ``(created_at DESC, id DESC)`` order.

    Attributes:
        created_at: ``created_at`` of the row; must be timezone-aware.
        id: ``id`` of the row.
    """

    created_at: datetime
    id: int

    def encode(self) -> str:
        """Return the cursor as an opaque, URL-safe token.

        Returns:
            Unpadded URL-safe base64 of ``<ISO created_at>|<id>``.
        """
        raw = f"{self.created_at.isoformat()}|{self.id}".encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @classmethod
    def decode(cls, token: str) -> Cursor:
        """Parse a token made by ``encode``.

        Args:
            token: The token.

        Returns:
            The cursor.

        Raises:
            ValueError: The token is malformed or its datetime has no offset.
        """
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
            created_at, row_id = raw.decode().split("|")
            cursor = cls(datetime.fromisoformat(created_at), int(row_id))
        except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"malformed cursor: {token!r}") from exc
        _check_aware(cursor.created_at, "cursor created_at")
        return cursor


@dataclass(frozen=True)
class Visibility:
    """What the caller may see; applied to every row the query returns.

    The library knows nothing about the host's permissions: the host builds a
    ``Visibility`` from its own rules. It restricts both which transactions
    are listed and which of their entries a group shows.

    Each field is a set of allowed values. ``None`` means no restriction; an
    empty collection allows nothing. A row whose column is ``NULL`` never
    passes a restriction that is set, so access control fails closed: with
    ``scope_ids={"t1"}``, entries without a scope are hidden.

    Attributes:
        object_types: Allowed ``object_type`` values.
        verbs: Allowed ``verb`` values.
        scope_ids: Allowed ``scope_id`` values.

    Raises:
        TypeError: A field is a ``str`` instead of a collection of them.
    """

    object_types: Collection[str] | None = None
    verbs: Collection[str] | None = None
    scope_ids: Collection[str] | None = None

    def __post_init__(self) -> None:
        _check_collection(self.object_types, "object_types")
        _check_collection(self.verbs, "verbs")
        _check_collection(self.scope_ids, "scope_ids")

    def predicate(self, table: Table) -> ColumnElement[bool]:
        """Return the SQL condition on ``audit_activity`` rows.

        Args:
            table: The ``audit_activity`` table.

        Returns:
            The condition; ``true()`` when nothing is restricted.
        """
        conditions = [
            condition
            for condition in (
                _member_of(table.c.object_type, self.object_types),
                _member_of(table.c.verb, self.verbs),
                _member_of(table.c.scope_id, self.scope_ids),
            )
            if condition is not None
        ]
        return and_(*conditions) if conditions else true()


@dataclass(frozen=True)
class TransactionHeader:
    """Who, where and how of one group: its ``audit_transaction`` row.

    When the row no longer exists (retention), the header is built from the
    ``data.context`` snapshot of the group's earliest visible entry and from
    that entry's columns, and ``from_snapshot`` is ``True``.

    Attributes:
        id: The transaction id.
        issued_at: Start of the database transaction (``created_at`` of its
            entries).
        actor_type: Kind of actor; ``None`` when a snapshot does not carry it.
        actor_id: Actor id; from a snapshot, the entry's ``actor_id``.
        actor_label: Actor label when the transaction started.
        remote_addr: Client address.
        user_agent: Client user agent.
        method: Request method.
        path: Request path.
        channel: Channel, e.g. ``api``.
        auth_method: Authentication method.
        request_id: Request id.
        correlation_id: Correlation id.
        scope_id: ``scope_id`` of the group's earliest visible entry.
        meta: Extra host context.
        from_snapshot: Whether the header was rebuilt from an entry.
    """

    id: int
    issued_at: datetime
    actor_type: str | None
    actor_id: str | None
    actor_label: str | None
    remote_addr: str | None
    user_agent: str | None
    method: str | None
    path: str | None
    channel: str | None
    auth_method: str | None
    request_id: UUID | None
    correlation_id: UUID | None
    scope_id: str | None
    meta: dict[str, JSONValue] | None
    from_snapshot: bool


@dataclass(frozen=True)
class Group:
    """The entries of one database transaction.

    Attributes:
        transaction: The transaction header.
        activities: The visible entries of every severity, in ``id`` order,
            compacted unless the listing asked for raw rows. Never empty.
    """

    transaction: TransactionHeader
    activities: list[ActivityRow]

    @property
    def change_count(self) -> int:
        """Number of entries in the group."""
        return len(self.activities)

    @property
    def max_severity(self) -> int:
        """Highest severity among the group's entries."""
        return max(activity["severity"] for activity in self.activities)


@dataclass(frozen=True)
class Page:
    """One page of groups.

    A page may hold fewer groups than the limit even when more follow (a
    group whose entries compaction hides entirely is left out); only
    ``next_cursor is None`` ends the listing.

    Attributes:
        groups: Groups, newest first.
        next_cursor: Cursor of the next page, or ``None`` after the last one.
    """

    groups: list[Group]
    next_cursor: Cursor | None


def changed_fields(activity: ActivityRow) -> list[str]:
    """Return the names of the fields an entry changed.

    Args:
        activity: An entry.

    Returns:
        The keys of ``data.changes``; empty for entries without changes.
    """
    return list(activity["data"].get("changes", {}))


class _Hit(NamedTuple):
    created_at: datetime
    id: int
    transaction_id: int


class _Selection(NamedTuple):
    """Stage 1 result: the page's transactions and the next cursor."""

    transactions: dict[int, datetime]
    next_cursor: Cursor | None


class AuditQuery:
    """Queries over the audit tables.

    Args:
        tables: The audit tables.
        severities: Every severity in use; ``list_groups`` queries these when
            it is not given ``severities``.
    """

    def __init__(self, tables: AuditTables, severities: Iterable[int]) -> None:
        self.tables = tables
        self.severities = tuple(sorted({int(severity) for severity in severities}))

    def list_groups(
        self,
        session: Session,
        *,
        severities: Collection[int] | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        actor_id: str | None = None,
        object_type: str | None = None,
        object_id: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        verbs: Collection[str] | None = None,
        scope_ids: Collection[str] | None = None,
        correlation_id: UUID | None = None,
        visibility: Visibility | None = None,
        extra_predicate: ColumnElement[bool] | None = None,
        cursor: Cursor | None = None,
        limit: int = 50,
        compact: bool = True,
    ) -> Page:
        """List entries grouped by database transaction, newest first.

        The filters select which transactions are listed: a transaction is
        listed when at least one of its entries matches all of them and
        ``visibility``. A group then shows every entry of the transaction
        that ``visibility`` allows, of any severity: ``severities`` and the
        other filters narrow the list, they do not control access.

        Collection filters take the allowed values: ``None`` means no
        restriction, an empty collection matches nothing. A ``NULL`` column
        never matches a restriction that is set.

        Pagination counts transactions. A transaction appears whole on the
        page holding its newest matching entry and on no other, so following
        ``next_cursor`` returns every matching transaction exactly once, also
        when several transactions share a ``created_at``.

        Statements run in the session's current transaction (one is begun if
        needed) after ``SET LOCAL plan_cache_mode = 'force_custom_plan'``,
        which stays in effect until that transaction ends. On an
        ``AUTOCOMMIT`` connection the setting has no effect, so prepared
        statements may fall back to generic plans that read every partition.

        Args:
            session: The session to query with.
            severities: Severities to list; ``None`` lists all configured.
            since: Only entries with ``created_at >= since``.
            until: Only entries with ``created_at < until``.
            actor_id: Only entries of this actor.
            object_type: Only entries on objects of this type.
            object_id: Only entries on the object with this id.
            target_type: Only entries whose parent object has this type.
            target_id: Only entries whose parent object has this id.
            verbs: Only entries with one of these verbs.
            scope_ids: Only entries in one of these scopes.
            correlation_id: Only entries with this correlation id.
            visibility: What the caller may see; ``None`` shows everything.
            extra_predicate: Further condition on ``audit_activity`` columns
                for selecting transactions; its performance is the host's
                concern.
            cursor: ``next_cursor`` of the previous page; ``None`` starts at
                the newest entry.
            limit: Maximum number of groups on the page.
            compact: Merge each object's rows within a transaction (see
                ``compact_rows``); ``False`` returns the raw rows.

        Returns:
            The page.

        Raises:
            ValueError: ``limit`` is below 1, or ``since``, ``until`` or the
                cursor's ``created_at`` is not timezone-aware.
            TypeError: A collection filter is a ``str``.
        """
        if limit < 1:
            raise ValueError("limit must be at least 1")
        _check_aware(since, "since")
        _check_aware(until, "until")
        if cursor is not None:
            _check_aware(cursor.created_at, "cursor created_at")
        _check_collection(severities, "severities")
        _check_collection(verbs, "verbs")
        _check_collection(scope_ids, "scope_ids")

        a = self.tables.activity
        common: list[ColumnElement[bool]] = []
        equal: list[tuple[ColumnClause[object], object]] = [
            (a.c.actor_id, actor_id),
            (a.c.object_type, object_type),
            (a.c.object_id, object_id),
            (a.c.target_type, target_type),
            (a.c.target_id, target_id),
            (a.c.correlation_id, correlation_id),
        ]
        common.extend(column == value for column, value in equal if value is not None)
        for column, values in ((a.c.verb, verbs), (a.c.scope_id, scope_ids)):
            condition = _member_of(column, values)
            if condition is not None:
                common.append(condition)
        if since is not None:
            common.append(a.c.created_at >= since)
        if until is not None:
            common.append(a.c.created_at < until)
        if visibility is not None:
            common.append(visibility.predicate(a))
        if extra_predicate is not None:
            common.append(extra_predicate)

        # An actor or scope filter without severities uses its own index in a
        # single query; otherwise one query per severity (see the module doc).
        streams: list[list[ColumnElement[bool]]]
        if severities is None and (actor_id is not None or scope_ids is not None):
            streams = [common]
            boundary = common
        else:
            wanted = self.severities if severities is None else sorted(set(severities))
            if not wanted:
                return Page(groups=[], next_cursor=None)
            streams = [[a.c.severity == severity, *common] for severity in wanted]
            boundary = [a.c.severity.in_(wanted), *common]

        session.execute(_CUSTOM_PLAN)
        shown = self._shown(session, boundary, cursor)
        selection = self._select(session, streams, cursor, shown, limit)
        groups = self._groups(session, selection.transactions, visibility, compact)
        return Page(groups=groups, next_cursor=selection.next_cursor)

    async def alist_groups(
        self,
        session: AsyncSession,
        *,
        severities: Collection[int] | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        actor_id: str | None = None,
        object_type: str | None = None,
        object_id: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        verbs: Collection[str] | None = None,
        scope_ids: Collection[str] | None = None,
        correlation_id: UUID | None = None,
        visibility: Visibility | None = None,
        extra_predicate: ColumnElement[bool] | None = None,
        cursor: Cursor | None = None,
        limit: int = 50,
        compact: bool = True,
    ) -> Page:
        """Async variant of ``list_groups``, with the same arguments.

        Args:
            session: The async session to query with.
            severities: See ``list_groups``.
            since: See ``list_groups``.
            until: See ``list_groups``.
            actor_id: See ``list_groups``.
            object_type: See ``list_groups``.
            object_id: See ``list_groups``.
            target_type: See ``list_groups``.
            target_id: See ``list_groups``.
            verbs: See ``list_groups``.
            scope_ids: See ``list_groups``.
            correlation_id: See ``list_groups``.
            visibility: See ``list_groups``.
            extra_predicate: See ``list_groups``.
            cursor: See ``list_groups``.
            limit: See ``list_groups``.
            compact: See ``list_groups``.

        Returns:
            The page.

        Raises:
            ValueError: See ``list_groups``.
            TypeError: See ``list_groups``.
        """
        return await session.run_sync(
            lambda sync_session: self.list_groups(
                sync_session,
                severities=severities,
                since=since,
                until=until,
                actor_id=actor_id,
                object_type=object_type,
                object_id=object_id,
                target_type=target_type,
                target_id=target_id,
                verbs=verbs,
                scope_ids=scope_ids,
                correlation_id=correlation_id,
                visibility=visibility,
                extra_predicate=extra_predicate,
                cursor=cursor,
                limit=limit,
                compact=compact,
            )
        )

    def _shown(
        self,
        session: Session,
        conditions: list[ColumnElement[bool]],
        cursor: Cursor | None,
    ) -> frozenset[int]:
        # Transactions an earlier page listed: they have a matching row at or
        # above the cursor. Only those sharing the cursor's created_at can
        # also have rows below it.
        if cursor is None:
            return frozenset()
        a = self.tables.activity
        statement = (
            select(a.c.transaction_id)
            .distinct()
            .where(
                *conditions,
                a.c.created_at == cursor.created_at,
                a.c.id >= cursor.id,
            )
        )
        return frozenset(session.scalars(statement))

    def _select(
        self,
        session: Session,
        streams: list[list[ColumnElement[bool]]],
        cursor: Cursor | None,
        shown: frozenset[int],
        limit: int,
    ) -> _Selection:
        merged = heapq.merge(
            *(self._hits(session, stream, cursor, limit + 1) for stream in streams),
            key=lambda hit: (hit.created_at, hit.id),
            reverse=True,
        )
        transactions: dict[int, datetime] = {}
        last: Cursor | None = None
        for hit in merged:
            new = (
                hit.transaction_id not in shown
                and hit.transaction_id not in transactions
            )
            if new:
                if len(transactions) == limit:
                    # The last row consumed, not the oldest row of the last
                    # group: rows of another transaction with the same
                    # created_at may lie between the two.
                    return _Selection(transactions, last)
                transactions[hit.transaction_id] = hit.created_at
            last = Cursor(hit.created_at, hit.id)
        return _Selection(transactions, None)

    def _hits(
        self,
        session: Session,
        conditions: list[ColumnElement[bool]],
        cursor: Cursor | None,
        batch: int,
    ) -> Iterator[_Hit]:
        # One transaction can have many rows, so a stream is read again from
        # its last row when a full batch was not enough.
        a = self.tables.activity
        after = cursor
        while True:
            keyset: list[ColumnElement[bool]] = []
            if after is not None:
                # The row comparison alone does not prune partitions.
                keyset = [
                    a.c.created_at <= after.created_at,
                    tuple_(a.c.created_at, a.c.id) < tuple_(after.created_at, after.id),
                ]
            statement = (
                select(a.c.created_at, a.c.id, a.c.transaction_id)
                .where(*conditions, *keyset)
                .order_by(a.c.created_at.desc(), a.c.id.desc())
                .limit(batch)
            )
            hits = [_Hit(*row) for row in session.execute(statement)]
            yield from hits
            if len(hits) < batch:
                return
            after = Cursor(hits[-1].created_at, hits[-1].id)

    def _groups(
        self,
        session: Session,
        transactions: dict[int, datetime],
        visibility: Visibility | None,
        compact: bool,
    ) -> list[Group]:
        if not transactions:
            return []
        a = self.tables.activity
        t = self.tables.transaction
        ids = list(transactions)
        # Every row of a transaction has the same created_at, so explicit
        # bounds from stage 1 prune both tables to the page's partitions.
        low, high = min(transactions.values()), max(transactions.values())
        conditions: list[ColumnElement[bool]] = [
            a.c.transaction_id.in_(ids),
            a.c.created_at.between(low, high),
        ]
        if visibility is not None:
            conditions.append(visibility.predicate(a))
        rows: dict[int, list[ActivityRow]] = {}
        statement = select(a).where(*conditions).order_by(a.c.transaction_id, a.c.id)
        for mapping in session.execute(statement).mappings():
            activity = _activity(mapping)
            rows.setdefault(activity["transaction_id"], []).append(activity)
        headers = {
            mapping["id"]: mapping
            for mapping in session.execute(
                select(t).where(t.c.id.in_(ids), t.c.issued_at.between(low, high))
            ).mappings()
        }

        groups: list[Group] = []
        for transaction_id in ids:
            raw = rows.get(transaction_id)
            if not raw:
                continue  # removed between the stages
            activities = compact_rows(raw, compact=compact)
            if not activities:
                continue
            header = _header(headers.get(transaction_id), raw[0])
            groups.append(Group(transaction=header, activities=activities))
        return groups


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


def _header(row: RowMapping | None, earliest: ActivityRow) -> TransactionHeader:
    if row is not None:
        remote_addr = row["remote_addr"]
        return TransactionHeader(
            id=row["id"],
            issued_at=row["issued_at"],
            actor_type=row["actor_type"],
            actor_id=row["actor_id"],
            actor_label=row["actor_label"],
            # Drivers return inet as ipaddress objects.
            remote_addr=None if remote_addr is None else str(remote_addr),
            user_agent=row["user_agent"],
            method=row["method"],
            path=row["path"],
            channel=row["channel"],
            auth_method=row["auth_method"],
            request_id=row["request_id"],
            correlation_id=row["correlation_id"],
            scope_id=earliest["scope_id"],
            meta=_json_object(row["meta"]),
            from_snapshot=False,
        )
    snapshot = earliest["data"].get("context", {})
    request_id = snapshot.get("request_id")
    return TransactionHeader(
        id=earliest["transaction_id"],
        issued_at=earliest["created_at"],
        actor_type=snapshot.get("actor_type"),
        actor_id=earliest["actor_id"],
        actor_label=snapshot.get("actor_label"),
        remote_addr=snapshot.get("remote_addr"),
        user_agent=snapshot.get("user_agent"),
        method=snapshot.get("method"),
        path=snapshot.get("path"),
        channel=snapshot.get("channel"),
        auth_method=snapshot.get("auth_method"),
        request_id=None if request_id is None else UUID(request_id),
        correlation_id=earliest["correlation_id"],
        scope_id=earliest["scope_id"],
        meta=_json_object(snapshot.get("meta")),
        from_snapshot=True,
    )


def _json_object(value: object) -> dict[str, JSONValue] | None:
    # A JSON object read back from a jsonb column.
    return value if isinstance(value, dict) else None


def _member_of(
    column: ColumnClause[str], values: Collection[str] | None
) -> ColumnElement[bool] | None:
    if values is None:
        return None
    if not values:
        return false()
    return column.in_(sorted(values))


def _check_collection(values: Collection[object] | None, name: str) -> None:
    if isinstance(values, str):
        raise TypeError(f"{name} must be a collection of values, not a str")


def _check_aware(value: datetime | None, name: str) -> None:
    if value is not None and value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
