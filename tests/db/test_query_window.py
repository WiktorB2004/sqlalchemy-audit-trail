"""The default query window of ``list_groups`` and the bound its cursor carries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from sqlalchemy import Engine, insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import Session

from audit_trail import AuditTrail
from audit_trail.maintenance import ensure_partitions
from audit_trail.query import ALL_HISTORY, AuditQuery, Cursor, Page
from tests.db.listener_support import Sev, create_trail

WINDOW = timedelta(days=30)
CORRELATION = UUID("00000000-0000-0000-0000-00000000000c")

# One entry per transaction, all on Board 1: three inside the window, one
# before it.
AGES = {
    "a": timedelta(hours=1),
    "b": timedelta(days=2),
    "c": timedelta(days=10),
    "old": timedelta(days=40),
}


@dataclass
class Log:
    trail: AuditTrail
    engine: Engine
    now: datetime

    def query(self, window: timedelta | None) -> AuditQuery:
        return AuditQuery(self.trail.tables, Sev, default_window=window)


@pytest.fixture
def log(engine: Engine, schema: str) -> Log:
    trail = create_trail(engine, schema, default_query_window=WINDOW)
    t = trail.tables.transaction
    a = trail.tables.activity
    now = datetime.now(timezone.utc)
    with engine.begin() as conn:
        ensure_partitions(
            conn, trail.tables, list(Sev), months_ahead=3, now=now - timedelta(days=60)
        )
        for name, age in AGES.items():
            issued_at = now - age
            transaction_id: int = conn.execute(
                insert(t)
                .values(issued_at=issued_at, actor_type="user")
                .returning(t.c.id)
            ).scalar_one()
            conn.execute(
                insert(a).values(
                    transaction_id=transaction_id,
                    verb="board.viewed",
                    severity=Sev.HIGH,
                    created_at=issued_at,
                    object_type="Board",
                    object_id="1",
                    object_label=name,
                    actor_id="u1",
                    correlation_id=CORRELATION,
                    data={"v": 1, "payload": {}},
                )
            )
    return Log(trail, engine, now)


def names(page: Page) -> list[str | None]:
    return [group.activities[0]["object_label"] for group in page.groups]


# The window and ALL_HISTORY


def test_window_applies_without_since(log: Log) -> None:
    before = datetime.now(timezone.utc)
    with Session(log.engine) as session:
        page = log.trail.query.list_groups(session)
    after = datetime.now(timezone.utc)

    assert names(page) == ["a", "b", "c"]
    assert page.since is not None
    assert before - WINDOW <= page.since <= after - WINDOW


def test_all_history_is_not_the_window(log: Log) -> None:
    with Session(log.engine) as session:
        page = log.trail.query.list_groups(session, since=ALL_HISTORY)

    assert names(page) == ["a", "b", "c", "old"]
    assert page.since is None


def test_no_window_lists_everything(log: Log) -> None:
    with Session(log.engine) as session:
        page = log.query(None).list_groups(session)

    assert names(page) == ["a", "b", "c", "old"]
    assert page.since is None


def test_explicit_since_overrides_the_window(log: Log) -> None:
    since = log.now - timedelta(days=50)
    with Session(log.engine) as session:
        page = log.trail.query.list_groups(session, since=since)

    assert names(page) == ["a", "b", "c", "old"]
    assert page.since == since


def test_until_anchors_the_window(log: Log) -> None:
    # Anchored at now, a 36-day window would not reach "old".
    until = log.now - timedelta(days=5)
    with Session(log.engine) as session:
        page = log.query(timedelta(days=36)).list_groups(session, until=until)

    assert names(page) == ["c", "old"]
    assert page.since == until - timedelta(days=36)


def test_load_older_continues_at_page_since(log: Log) -> None:
    with Session(log.engine) as session:
        first = log.trail.query.list_groups(session)
        older = log.trail.query.list_groups(session, until=first.since)

    assert first.next_cursor is None
    assert names(older) == ["old"]


# Paging keeps the bound of the first page


@pytest.mark.parametrize("window", [None, timedelta(days=1)])
def test_cursor_keeps_the_window(log: Log, window: timedelta | None) -> None:
    # The second page is read with a different window (or none): only the
    # bound the cursor carries decides.
    with Session(log.engine) as session:
        first = log.trail.query.list_groups(session, limit=2)
        assert first.next_cursor is not None
        second = log.query(window).list_groups(session, cursor=first.next_cursor)

    assert names(first) == ["a", "b"]
    assert first.next_cursor.since == first.since
    assert names(second) == ["c"]
    assert second.next_cursor is None
    assert second.since == first.since


def test_all_history_survives_paging(log: Log) -> None:
    with Session(log.engine) as session:
        first = log.trail.query.list_groups(session, since=ALL_HISTORY, limit=2)
        assert first.next_cursor is not None
        second = log.trail.query.list_groups(session, cursor=first.next_cursor)

    assert first.next_cursor.since is ALL_HISTORY
    assert names(second) == ["c", "old"]


def test_explicit_since_beats_the_cursor(log: Log) -> None:
    with Session(log.engine) as session:
        first = log.trail.query.list_groups(session, limit=2)
        assert first.next_cursor is not None
        second = log.trail.query.list_groups(
            session, since=ALL_HISTORY, cursor=first.next_cursor
        )

    assert names(second) == ["c", "old"]


def test_cursor_without_a_bound_applies_the_window(log: Log) -> None:
    # A hand-built cursor records no bound: that is not "no bound".
    with Session(log.engine) as session:
        first = log.query(None).list_groups(session, limit=2)
        assert first.next_cursor is not None
        cursor = Cursor(first.next_cursor.created_at, first.next_cursor.id)
        second = log.trail.query.list_groups(session, cursor=cursor)

    assert names(second) == ["c"]


async def test_async_passes_since_through(log: Log, async_engine: AsyncEngine) -> None:
    async with AsyncSession(async_engine) as session:
        windowed = await log.trail.query.alist_groups(session)
        everything = await log.trail.query.alist_groups(session, since=ALL_HISTORY)

    assert names(windowed) == ["a", "b", "c"]
    assert names(everything) == ["a", "b", "c", "old"]


# Methods the window does not apply to


def test_object_history_is_not_windowed(log: Log) -> None:
    with Session(log.engine) as session:
        page = log.trail.query.object_history(session, "Board", "1")

    assert names(page) == ["a", "b", "c", "old"]


def test_related_is_not_windowed(log: Log) -> None:
    with Session(log.engine) as session:
        page = log.trail.query.related(session, CORRELATION)

    assert names(page) == ["a", "b", "c", "old"]


def test_access_summary_is_not_windowed(log: Log) -> None:
    with Session(log.engine) as session:
        (count,) = log.trail.query.access_summary(session, "Board", "1", "board.viewed")

    assert count.entries == len(AGES)


def test_object_history_cursor_keeps_since(log: Log) -> None:
    since = log.now - timedelta(days=15)
    with Session(log.engine) as session:
        first = log.trail.query.object_history(
            session, "Board", "1", since=since, limit=2
        )
        assert first.next_cursor is not None
        second = log.trail.query.object_history(
            session, "Board", "1", cursor=first.next_cursor
        )

    assert first.next_cursor.since == since
    assert names(second) == ["c"]
