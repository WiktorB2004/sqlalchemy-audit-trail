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

``object_history`` and ``related`` page through transactions the same way,
with their own stage 1 streams: the object and target indexes for a record's
history, the correlation index for related transactions. ``get`` reads one
entry by ``(id, created_at)``, which prunes to one monthly partition per
severity (one partition when the severity is given), and ``access_summary``
counts an object's accesses per actor. ``LabelResolver`` labels the objects
that foreign-key and relationship changes refer to.

Every query runs after ``SET LOCAL plan_cache_mode = 'force_custom_plan'``:
a generic plan of a prepared statement (asyncpg, psycopg after a few
executions) cannot prune partitions by the query's parameters at plan time.
"""

from __future__ import annotations

import base64
import binascii
import heapq
from collections.abc import Collection, Iterable, Iterator, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, NamedTuple, TypeAlias, TypedDict
from uuid import UUID

from sqlalchemy import (
    Column,
    ColumnElement,
    RowMapping,
    String,
    and_,
    column,
    false,
    func,
    or_,
    select,
    text,
    true,
    tuple_,
    values,
)
from sqlalchemy.exc import NoReferenceError

from audit_trail._compaction import ActivityRow, FieldChange, compact_rows
from audit_trail._typing import assert_never
from audit_trail.checks import _registry_of
from audit_trail.diff import REDACTED, UNKNOWN, field_policy, options_of
from audit_trail.serialization import JSONValue
from audit_trail.tables import AuditTables

if TYPE_CHECKING:
    from sqlalchemy import ColumnClause, Table
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import Mapper, Session, registry

__all__ = [
    "ALL_HISTORY",
    "AccessCount",
    "ActivityDetail",
    "ActivityRow",
    "AllHistory",
    "AuditQuery",
    "Cursor",
    "FieldLabels",
    "Group",
    "LabelResolver",
    "Page",
    "RelationshipLabels",
    "TransactionHeader",
    "Visibility",
    "changed_fields",
]

_CUSTOM_PLAN = text("SET LOCAL plan_cache_mode = 'force_custom_plan'")

_ALL_HISTORY_TOKEN = "*"


class AllHistory(Enum):
    """Type of ``ALL_HISTORY``: a listing without a lower time bound."""

    ALL_HISTORY = "all_history"


ALL_HISTORY = AllHistory.ALL_HISTORY
"""Pass as ``since`` to list the whole log, even with a default query window.

``since=None`` means "not given", which applies the configured window.
"""


class Cursor(NamedTuple):
    """Position in the listing: ``(created_at, id)`` of an activity row.

    ``list_groups`` continues with the rows after it in
    ``(created_at DESC, id DESC)`` order. The cursor also carries the lower
    time bound of the listing, so that every page uses the bound of the
    first one.

    Attributes:
        created_at: ``created_at`` of the row; must be timezone-aware.
        id: ``id`` of the row.
        since: The listing's lower bound: a timezone-aware datetime, or
            ``ALL_HISTORY`` for none. A ``next_cursor`` always records it;
            ``None`` means not recorded (a cursor built by hand or a token
            from an older version), and the next page then resolves the
            bound as a first page would.
    """

    created_at: datetime
    id: int
    since: datetime | AllHistory | None = None

    def encode(self) -> str:
        """Return the cursor as an opaque, URL-safe token.

        Returns:
            Unpadded URL-safe base64 of ``<ISO created_at>|<id>``, followed
            by ``|<ISO since>`` or ``|*`` (``ALL_HISTORY``) when ``since`` is
            recorded.
        """
        parts = [self.created_at.isoformat(), str(self.id)]
        match self.since:
            case None:
                pass
            case AllHistory.ALL_HISTORY:
                parts.append(_ALL_HISTORY_TOKEN)
            case datetime():
                parts.append(self.since.isoformat())
            case _:
                assert_never(self.since)
        raw = "|".join(parts).encode()
        return base64.urlsafe_b64encode(raw).decode().rstrip("=")

    @classmethod
    def decode(cls, token: str) -> Cursor:
        """Parse a token made by ``encode``.

        Args:
            token: The token.

        Returns:
            The cursor.

        Raises:
            ValueError: The token is malformed or one of its datetimes has no
                offset.
        """
        try:
            raw = base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))
            created_at, row_id, *rest = raw.decode().split("|")
            since: datetime | AllHistory | None
            match rest:
                case []:
                    since = None
                case [str() as bound] if bound == _ALL_HISTORY_TOKEN:
                    since = ALL_HISTORY
                case [str() as bound]:
                    since = datetime.fromisoformat(bound)
                case _:
                    raise ValueError("too many fields")
            cursor = cls(datetime.fromisoformat(created_at), int(row_id), since)
        except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"malformed cursor: {token!r}") from exc
        _check_cursor(cursor)
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
        since: The lower time bound the listing used (``created_at >=
            since``), or ``None`` when it had none. With a default query
            window this is where the window starts: pass it as ``until`` to
            load the older entries.
    """

    groups: list[Group]
    next_cursor: Cursor | None
    since: datetime | None = None


@dataclass(frozen=True)
class ActivityDetail:
    """One entry with the header of its transaction.

    Attributes:
        activity: The entry, as stored (not compacted).
        transaction: The header of its transaction, rebuilt from the entry's
            snapshot when the ``audit_transaction`` row no longer exists.
    """

    activity: ActivityRow
    transaction: TransactionHeader


class AccessCount(NamedTuple):
    """How often one actor accessed an object.

    Attributes:
        actor_id: The actor; ``None`` for entries without an actor.
        entries: Number of matching entries.
        first_at: ``created_at`` of the actor's oldest matching entry.
        last_at: ``created_at`` of the actor's newest matching entry.
    """

    actor_id: str | None
    entries: int
    first_at: datetime
    last_at: datetime


class RelationshipLabels(TypedDict):
    """Labels of the members a relationship change added and removed.

    Attributes:
        added: Labels of the added members, in the order of their ids.
        removed: Labels of the removed members, in the order of their ids.
    """

    added: list[str]
    removed: list[str]


FieldLabels: TypeAlias = list[str | None] | RelationshipLabels
"""Labels of one change: ``[old, new]`` for a column (``None`` where the value
is ``None``) or ``RelationshipLabels`` for a relationship."""


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
        default_window: How far back ``list_groups`` reads when it is not
            given ``since``; ``None`` reads the whole log.

    Raises:
        TypeError: ``default_window`` is not a ``timedelta``.
        ValueError: ``default_window`` is not positive.
    """

    def __init__(
        self,
        tables: AuditTables,
        severities: Iterable[int],
        *,
        default_window: timedelta | None = None,
    ) -> None:
        self.tables = tables
        self.severities = tuple(sorted({int(severity) for severity in severities}))
        self.default_window = _check_window(default_window)

    def list_groups(
        self,
        session: Session,
        *,
        severities: Collection[int] | None = None,
        since: datetime | AllHistory | None = None,
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

        With a default query window (``AuditTrail(default_query_window=...)``)
        and no ``since``, the listing starts at ``until`` (or now) minus the
        window. The first page fixes that bound and its ``next_cursor``
        carries it, so later pages neither move nor drop it. ``Page.since``
        reports the bound: pass it as ``until`` to read the window before.

        Statements run in the session's current transaction (one is begun if
        needed) after ``SET LOCAL plan_cache_mode = 'force_custom_plan'``,
        which stays in effect until that transaction ends. On an
        ``AUTOCOMMIT`` connection the setting has no effect, so prepared
        statements may fall back to generic plans that read every partition.

        Args:
            session: The session to query with.
            severities: Severities to list; ``None`` lists all configured.
            since: Only entries with ``created_at >= since``. ``ALL_HISTORY``
                sets no lower bound, even with a default window. ``None``
                takes the bound recorded in ``cursor``, else applies the
                default window, else sets no bound.
            until: Only entries with ``created_at < until``; also the end of
                the default window.
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
            ValueError: ``limit`` is below 1, or ``since``, ``until`` or a
                datetime of the cursor is not timezone-aware.
            TypeError: A collection filter is a ``str``, or ``since`` is
                neither a datetime, ``ALL_HISTORY`` nor ``None``.
        """
        _check_page(since, until, cursor, limit)
        bound = self._bound(since, until, cursor, self.default_window)
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
        common.extend(field == value for field, value in equal if value is not None)
        for field, allowed in ((a.c.verb, verbs), (a.c.scope_id, scope_ids)):
            condition = _member_of(field, allowed)
            if condition is not None:
                common.append(condition)
        common.extend(self._window(_lower(bound), until, visibility))
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
                return Page(groups=[], next_cursor=None, since=_lower(bound))
            streams = [[a.c.severity == severity, *common] for severity in wanted]
            boundary = [a.c.severity.in_(wanted), *common]

        return self._page(
            session, streams, boundary, cursor, limit, visibility, compact, bound
        )

    async def alist_groups(
        self,
        session: AsyncSession,
        *,
        severities: Collection[int] | None = None,
        since: datetime | AllHistory | None = None,
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

    def get(
        self,
        session: Session,
        id: int,
        created_at: datetime,
        *,
        severity: int | None = None,
        visibility: Visibility | None = None,
    ) -> ActivityDetail | None:
        """Return one entry with its transaction header.

        An entry is found by ``id`` and ``created_at`` together: ``id`` alone
        would read every partition, while ``created_at`` limits the read to
        one monthly partition of each severity, and ``severity`` (the entry's
        own, as a listing row carries it) to exactly one partition.

        Args:
            session: The session to query with.
            id: The entry's ``id``.
            created_at: The entry's ``created_at``.
            severity: The entry's severity, if known.
            visibility: What the caller may see; ``None`` shows everything.

        Returns:
            The entry and its header, or ``None`` when there is no such entry
            or ``visibility`` hides it; the two cases are indistinguishable.

        Raises:
            ValueError: ``created_at`` is not timezone-aware.
        """
        _check_aware(created_at, "created_at")
        a = self.tables.activity
        t = self.tables.transaction
        conditions = [a.c.id == id, a.c.created_at == created_at]
        if severity is not None:
            conditions.append(a.c.severity == severity)
        if visibility is not None:
            conditions.append(visibility.predicate(a))
        session.execute(_CUSTOM_PLAN)
        row = session.execute(select(a).where(*conditions)).mappings().first()
        if row is None:
            return None
        activity = _activity(row)
        header = (
            session.execute(
                select(t).where(
                    t.c.id == activity["transaction_id"],
                    t.c.issued_at == activity["created_at"],
                )
            )
            .mappings()
            .first()
        )
        return ActivityDetail(activity=activity, transaction=_header(header, activity))

    async def aget(
        self,
        session: AsyncSession,
        id: int,
        created_at: datetime,
        *,
        severity: int | None = None,
        visibility: Visibility | None = None,
    ) -> ActivityDetail | None:
        """Async variant of ``get``, with the same arguments.

        Args:
            session: The async session to query with.
            id: See ``get``.
            created_at: See ``get``.
            severity: See ``get``.
            visibility: See ``get``.

        Returns:
            See ``get``.

        Raises:
            ValueError: See ``get``.
        """
        return await session.run_sync(
            lambda sync_session: self.get(
                sync_session,
                id,
                created_at,
                severity=severity,
                visibility=visibility,
            )
        )

    def object_history(
        self,
        session: Session,
        object_type: str,
        object_id: str,
        *,
        include_children: bool = True,
        since: datetime | None = None,
        until: datetime | None = None,
        visibility: Visibility | None = None,
        cursor: Cursor | None = None,
        limit: int = 50,
        compact: bool = True,
    ) -> Page:
        """List the history of one record, grouped by database transaction.

        The history holds the entries on the record and, with
        ``include_children``, the entries whose target is the record (the
        changes of its children). Each group shows only those entries of its
        transaction, not the transaction's other entries. ``visibility``
        applies to every entry on its own: children of types the caller may
        not see are left out, and a visible child's entries are listed even
        when the record's own type is hidden.

        A child's entries follow the target it had when they were written: a
        child moved to another parent appears, from the move on, in the new
        parent's history only.

        Pagination works as in ``list_groups``: it counts transactions,
        newest first, and ``next_cursor`` returns each transaction once. The
        default query window does not apply: without ``since`` (given or
        recorded in ``cursor``) the whole history is listed.

        Args:
            session: The session to query with.
            object_type: The record's ``object_type``.
            object_id: The record's ``object_id``, formatted as
                ``object_id_for()`` formats it; any other string matches
                nothing.
            include_children: Also list the entries targeting the record.
            since: Only entries with ``created_at >= since``.
            until: Only entries with ``created_at < until``.
            visibility: What the caller may see; ``None`` shows everything.
            cursor: ``next_cursor`` of the previous page; ``None`` starts at
                the newest entry.
            limit: Maximum number of groups on the page.
            compact: Merge each object's rows within a transaction;
                ``False`` returns the raw rows.

        Returns:
            The page.

        Raises:
            ValueError: ``limit`` is below 1, or ``since``, ``until`` or the
                cursor's ``created_at`` is not timezone-aware.
        """
        _check_page(since, until, cursor, limit)
        bound = self._bound(since, until, cursor, None)
        a = self.tables.activity
        common = self._window(_lower(bound), until, visibility)
        own = and_(a.c.object_type == object_type, a.c.object_id == object_id)
        # Two streams, one per index, merged in Python: an OR of both
        # conditions could not read either index in order.
        streams = [[own, *common]]
        scope: ColumnElement[bool] = own
        if include_children:
            children = and_(a.c.target_type == object_type, a.c.target_id == object_id)
            streams.append([children, *common])
            scope = or_(own, children)
        return self._page(
            session,
            streams,
            [scope, *common],
            cursor,
            limit,
            visibility,
            compact,
            bound,
            scope=scope,
        )

    async def aobject_history(
        self,
        session: AsyncSession,
        object_type: str,
        object_id: str,
        *,
        include_children: bool = True,
        since: datetime | None = None,
        until: datetime | None = None,
        visibility: Visibility | None = None,
        cursor: Cursor | None = None,
        limit: int = 50,
        compact: bool = True,
    ) -> Page:
        """Async variant of ``object_history``, with the same arguments.

        Args:
            session: The async session to query with.
            object_type: See ``object_history``.
            object_id: See ``object_history``.
            include_children: See ``object_history``.
            since: See ``object_history``.
            until: See ``object_history``.
            visibility: See ``object_history``.
            cursor: See ``object_history``.
            limit: See ``object_history``.
            compact: See ``object_history``.

        Returns:
            The page.

        Raises:
            ValueError: See ``object_history``.
        """
        return await session.run_sync(
            lambda sync_session: self.object_history(
                sync_session,
                object_type,
                object_id,
                include_children=include_children,
                since=since,
                until=until,
                visibility=visibility,
                cursor=cursor,
                limit=limit,
                compact=compact,
            )
        )

    def related(
        self,
        session: Session,
        correlation_id: UUID,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        visibility: Visibility | None = None,
        cursor: Cursor | None = None,
        limit: int = 50,
        compact: bool = True,
    ) -> Page:
        """List the transactions sharing a correlation id, newest first.

        Groups and pagination are those of ``list_groups``; the transactions
        are selected with one query over the correlation index. The default
        query window does not apply, as for ``object_history``.

        Args:
            session: The session to query with.
            correlation_id: The correlation id.
            since: Only entries with ``created_at >= since``.
            until: Only entries with ``created_at < until``.
            visibility: What the caller may see; ``None`` shows everything.
            cursor: ``next_cursor`` of the previous page; ``None`` starts at
                the newest entry.
            limit: Maximum number of groups on the page.
            compact: Merge each object's rows within a transaction;
                ``False`` returns the raw rows.

        Returns:
            The page.

        Raises:
            ValueError: ``limit`` is below 1, or ``since``, ``until`` or the
                cursor's ``created_at`` is not timezone-aware.
        """
        _check_page(since, until, cursor, limit)
        bound = self._bound(since, until, cursor, None)
        a = self.tables.activity
        conditions = [
            a.c.correlation_id == correlation_id,
            *self._window(_lower(bound), until, visibility),
        ]
        return self._page(
            session, [conditions], conditions, cursor, limit, visibility, compact, bound
        )

    async def arelated(
        self,
        session: AsyncSession,
        correlation_id: UUID,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        visibility: Visibility | None = None,
        cursor: Cursor | None = None,
        limit: int = 50,
        compact: bool = True,
    ) -> Page:
        """Async variant of ``related``, with the same arguments.

        Args:
            session: The async session to query with.
            correlation_id: See ``related``.
            since: See ``related``.
            until: See ``related``.
            visibility: See ``related``.
            cursor: See ``related``.
            limit: See ``related``.
            compact: See ``related``.

        Returns:
            The page.

        Raises:
            ValueError: See ``related``.
        """
        return await session.run_sync(
            lambda sync_session: self.related(
                sync_session,
                correlation_id,
                since=since,
                until=until,
                visibility=visibility,
                cursor=cursor,
                limit=limit,
                compact=compact,
            )
        )

    def access_summary(
        self,
        session: Session,
        object_type: str,
        object_id: str,
        verb: str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        visibility: Visibility | None = None,
    ) -> list[AccessCount]:
        """Count one verb's entries on a record per actor.

        For example who read a person's sensitive data, and how often.
        Entries are counted raw, without compaction. The default query window
        does not apply: without ``since`` every entry is counted.

        Args:
            session: The session to query with.
            object_type: The record's ``object_type``.
            object_id: The record's ``object_id`` (see ``object_id_for``).
            verb: The verb to count, e.g. ``person.viewed``.
            since: Only entries with ``created_at >= since``.
            until: Only entries with ``created_at < until``.
            visibility: What the caller may see; ``None`` counts everything.

        Returns:
            One count per actor, the most recent access first.

        Raises:
            ValueError: ``since`` or ``until`` is not timezone-aware.
        """
        _check_aware(since, "since")
        _check_aware(until, "until")
        a = self.tables.activity
        last_at = func.max(a.c.created_at)
        statement = (
            select(a.c.actor_id, func.count(), func.min(a.c.created_at), last_at)
            .where(
                a.c.object_type == object_type,
                a.c.object_id == object_id,
                a.c.verb == verb,
                *self._window(since, until, visibility),
            )
            .group_by(a.c.actor_id)
            .order_by(last_at.desc(), a.c.actor_id)
        )
        session.execute(_CUSTOM_PLAN)
        return [AccessCount(*row) for row in session.execute(statement)]

    async def aaccess_summary(
        self,
        session: AsyncSession,
        object_type: str,
        object_id: str,
        verb: str,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        visibility: Visibility | None = None,
    ) -> list[AccessCount]:
        """Async variant of ``access_summary``, with the same arguments.

        Args:
            session: The async session to query with.
            object_type: See ``access_summary``.
            object_id: See ``access_summary``.
            verb: See ``access_summary``.
            since: See ``access_summary``.
            until: See ``access_summary``.
            visibility: See ``access_summary``.

        Returns:
            See ``access_summary``.

        Raises:
            ValueError: See ``access_summary``.
        """
        return await session.run_sync(
            lambda sync_session: self.access_summary(
                sync_session,
                object_type,
                object_id,
                verb,
                since=since,
                until=until,
                visibility=visibility,
            )
        )

    def _bound(
        self,
        since: datetime | AllHistory | None,
        until: datetime | None,
        cursor: Cursor | None,
        window: timedelta | None,
    ) -> datetime | AllHistory:
        # The listing's lower bound, fixed at the first page: the argument,
        # else the one the cursor recorded, else the window, else none.
        if since is None and cursor is not None:
            since = cursor.since
        match since:
            case datetime() | AllHistory.ALL_HISTORY:
                return since
            case None:
                if window is None:
                    return ALL_HISTORY
                return (datetime.now(timezone.utc) if until is None else until) - window
            case _:
                assert_never(since)

    def _window(
        self,
        since: datetime | None,
        until: datetime | None,
        visibility: Visibility | None,
    ) -> list[ColumnElement[bool]]:
        a = self.tables.activity
        conditions: list[ColumnElement[bool]] = []
        if since is not None:
            conditions.append(a.c.created_at >= since)
        if until is not None:
            conditions.append(a.c.created_at < until)
        if visibility is not None:
            conditions.append(visibility.predicate(a))
        return conditions

    def _page(
        self,
        session: Session,
        streams: list[list[ColumnElement[bool]]],
        boundary: list[ColumnElement[bool]],
        cursor: Cursor | None,
        limit: int,
        visibility: Visibility | None,
        compact: bool,
        bound: datetime | AllHistory,
        *,
        scope: ColumnElement[bool] | None = None,
    ) -> Page:
        # Stage 1 reads each stream in (created_at, id) order; `boundary`
        # matches the rows of all streams together; `scope` narrows the rows
        # a group shows (None: every visible row of the transaction); `bound`
        # is recorded in the next cursor.
        session.execute(_CUSTOM_PLAN)
        shown = self._shown(session, boundary, cursor)
        selection = self._select(session, streams, cursor, shown, limit)
        groups = self._groups(
            session, selection.transactions, visibility, compact, scope
        )
        next_cursor = selection.next_cursor
        if next_cursor is not None:
            next_cursor = next_cursor._replace(since=bound)
        return Page(groups=groups, next_cursor=next_cursor, since=_lower(bound))

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
        scope: ColumnElement[bool] | None,
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
        if scope is not None:
            conditions.append(scope)
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


class _Reference(NamedTuple):
    object_type: str
    object_id: str


class _Label(NamedTuple):
    created_at: datetime
    id: int
    label: str


class _Found(NamedTuple):
    activity_id: int
    key: str
    change: FieldChange
    types: frozenset[str]


class LabelResolver:
    """Labels for the objects that entries' foreign keys and relationships name.

    A change such as ``{"board_id": [1, 2]}`` stores ids. The resolver finds
    which fields refer to other objects from the models' metadata, never from
    field names: a column with a single-column ``ForeignKey`` to the primary
    key of a mapped table, and every relationship (whose tracked changes list
    member ids). It then looks each referenced object up in the audit trail,
    not in the host's tables.

    The label of an object is the newest non-null ``object_label`` among its
    entries that ``visibility`` lets the caller see. So a deleted object keeps
    the label of its ``entity.deleted`` entry, and an object the caller may
    not see (its type, scope or verbs hidden) is not revealed: it gets the
    fallback ``#<id>``, as does an object without a labelled entry, e.g. of a
    model without a ``label`` option. A label is as fresh as the object's
    last audited change: an unaudited rename is not reflected.

    Not resolved: composite foreign keys, foreign keys to columns other than
    the primary key, fields with an audit policy (``redact``, ``hash``) and
    redacted or unknown values, as well as ``target_type``/``target_id``.

    Args:
        tables: The audit tables.
        base: The registry of the models, or a declarative base class using
            it, as for ``check_models``. Its mappers are configured.
    """

    def __init__(self, tables: AuditTables, base: registry | type[Any]) -> None:
        self.tables = tables
        reg = _registry_of(base)
        reg.configure()
        mappers = list(reg.mappers)
        self._labelled = frozenset(
            _type_name(mapper.class_)
            for mapper in mappers
            if options_of(mapper.class_).label is not None
        )
        self._fields: dict[str, dict[str, frozenset[str]]] = {}
        for mapper in mappers:
            fields = self._fields.setdefault(_type_name(mapper.class_), {})
            for prop in mapper.column_attrs:
                types = _referenced_types(mapper, prop.key, prop.columns, mappers)
                if types:
                    fields[prop.key] = types
            for relationship in mapper.relationships:
                fields[relationship.key] = _types_of(relationship.mapper)

    def resolve(
        self,
        session: Session,
        activities: Iterable[ActivityRow],
        *,
        visibility: Visibility | None = None,
    ) -> dict[int, dict[str, FieldLabels]]:
        """Label the referenced objects of the entries' changes.

        Args:
            session: The session to query with.
            activities: The entries, e.g. those of a page's groups.
            visibility: What the caller may see; ``None`` shows everything.

        Returns:
            By entry ``id``, then by field, the labels in the shape of the
            change: ``[old, new]`` for a column, ``RelationshipLabels`` for a
            relationship. Entries without reference fields are left out.
        """
        found: list[_Found] = []
        wanted: set[_Reference] = set()
        for activity in activities:
            object_type = activity["object_type"]
            fields = {} if object_type is None else self._fields.get(object_type, {})
            for key, change in activity["data"].get("changes", {}).items():
                types = fields.get(key)
                ids = None if types is None else _referenced_ids(change)
                if types is None or ids is None:
                    continue
                found.append(_Found(activity["id"], key, change, types))
                wanted.update(
                    _Reference(object_type, object_id)
                    for object_type in types & self._labelled
                    for object_id in ids
                )
        labels = self._labels(session, wanted, visibility)

        def label(types: frozenset[str], object_id: str) -> str:
            hits = [
                labels[reference]
                for reference in (_Reference(t, object_id) for t in types)
                if reference in labels
            ]
            return max(hits).label if hits else f"#{object_id}"

        result: dict[int, dict[str, FieldLabels]] = {}
        for item in found:
            change = item.change
            labelled: FieldLabels
            if isinstance(change, list):
                labelled = [
                    None if value is None else label(item.types, str(value))
                    for value in change
                ]
            else:
                labelled = {
                    "added": [label(item.types, i) for i in change["added"]],
                    "removed": [label(item.types, i) for i in change["removed"]],
                }
            result.setdefault(item.activity_id, {})[item.key] = labelled
        return result

    async def aresolve(
        self,
        session: AsyncSession,
        activities: Iterable[ActivityRow],
        *,
        visibility: Visibility | None = None,
    ) -> dict[int, dict[str, FieldLabels]]:
        """Async variant of ``resolve``, with the same arguments.

        Args:
            session: The async session to query with.
            activities: See ``resolve``.
            visibility: See ``resolve``.

        Returns:
            See ``resolve``.
        """
        rows = list(activities)
        return await session.run_sync(
            lambda sync_session: self.resolve(sync_session, rows, visibility=visibility)
        )

    def _labels(
        self,
        session: Session,
        wanted: set[_Reference],
        visibility: Visibility | None,
    ) -> dict[_Reference, _Label]:
        if not wanted:
            return {}
        a = self.tables.activity
        references = values(
            column("object_type", String), column("object_id", String), name="wanted"
        ).data(sorted(wanted))
        conditions = [
            a.c.object_type == references.c.object_type,
            a.c.object_id == references.c.object_id,
            a.c.object_label.is_not(None),
        ]
        if visibility is not None:
            conditions.append(visibility.predicate(a))
        # Newest labelled entry per object: one ordered read of the object
        # index each, stopping at the first row.
        latest = (
            select(a.c.created_at, a.c.id, a.c.object_label)
            .where(*conditions)
            .order_by(a.c.created_at.desc(), a.c.id.desc())
            .limit(1)
            .lateral("latest")
        )
        statement = select(
            references.c.object_type,
            references.c.object_id,
            latest.c.created_at,
            latest.c.id,
            latest.c.object_label,
        ).select_from(references.join(latest, true()))
        session.execute(_CUSTOM_PLAN)
        return {
            _Reference(object_type, object_id): _Label(created_at, row_id, label)
            for object_type, object_id, created_at, row_id, label in session.execute(
                statement
            )
        }


def _type_name(model: type[Any]) -> str:
    # The object_type of the model's instances (see diff.object_type_of).
    return options_of(model).object_type or model.__name__


def _types_of(mapper: Mapper[Any]) -> frozenset[str]:
    # A reference to a class can name an instance of any of its subclasses.
    return frozenset(_type_name(m.class_) for m in mapper.self_and_descendants)


def _referenced_types(
    mapper: Mapper[Any],
    key: str,
    columns: Sequence[ColumnElement[Any]],
    mappers: list[Mapper[Any]],
) -> frozenset[str]:
    if len(columns) != 1 or not isinstance(columns[0], Column):
        return frozenset()
    local = columns[0]
    if len(local.foreign_keys) != 1:
        return frozenset()
    if field_policy(mapper.class_, key, local) is not None:
        return frozenset()  # redacted or hashed values are no ids
    (foreign_key,) = local.foreign_keys
    if foreign_key.constraint is None or len(foreign_key.constraint.elements) != 1:
        return frozenset()
    try:
        referenced = foreign_key.column
    except NoReferenceError:
        return frozenset()
    for candidate in mappers:
        # The mapper that owns the referenced table, not one inheriting it.
        owns = candidate.inherits is None or (
            candidate.inherits.local_table is not candidate.local_table
        )
        if (
            owns
            and candidate.local_table is referenced.table
            and len(candidate.primary_key) == 1
            and candidate.primary_key[0] is referenced
        ):
            return _types_of(candidate)
    return frozenset()


def _referenced_ids(change: FieldChange) -> list[str] | None:
    # The ids a change refers to, or None when its values cannot be ids.
    if not isinstance(change, list):
        return [*change["added"], *change["removed"]]
    ids: list[str] = []
    for value in change:
        if value is None:
            continue
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            return None
        if value in (REDACTED, UNKNOWN):
            return None
        ids.append(str(value))
    return ids


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


def _lower(bound: datetime | AllHistory) -> datetime | None:
    # The `created_at >=` bound of a resolved lower bound.
    match bound:
        case datetime():
            return bound
        case AllHistory.ALL_HISTORY:
            return None
        case _:
            assert_never(bound)


def _check_window(window: object) -> timedelta | None:
    if window is None:
        return None
    if not isinstance(window, timedelta):
        raise TypeError("the default query window must be a timedelta or None")
    if window <= timedelta(0):
        raise ValueError("the default query window must be positive")
    return window


def _check_since(since: object, name: str) -> None:
    if since is None or isinstance(since, AllHistory):
        return
    if not isinstance(since, datetime):
        raise TypeError(f"{name} must be a datetime, ALL_HISTORY or None")
    _check_aware(since, name)


def _check_cursor(cursor: Cursor) -> None:
    _check_aware(cursor.created_at, "cursor created_at")
    _check_since(cursor.since, "cursor since")


def _check_page(
    since: object, until: datetime | None, cursor: Cursor | None, limit: int
) -> None:
    if limit < 1:
        raise ValueError("limit must be at least 1")
    _check_since(since, "since")
    _check_aware(until, "until")
    if cursor is not None:
        _check_cursor(cursor)


def _check_aware(value: datetime | None, name: str) -> None:
    if value is not None and value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
