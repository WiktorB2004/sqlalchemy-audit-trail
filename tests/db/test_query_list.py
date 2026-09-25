"""``AuditQuery.list_groups``: grouping, filters, visibility and pagination."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy import Engine, MetaData, delete, insert
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from audit_trail import Audited, AuditOptions
from audit_trail.maintenance import ensure_partitions
from audit_trail.query import AuditQuery, Cursor, Group, Visibility, changed_fields
from tests.db.listener_support import Env, Sev, make_env, record_statements

REQUEST = UUID("00000000-0000-0000-0000-00000000000a")
CORRELATION = UUID("00000000-0000-0000-0000-00000000000c")


@dataclass
class Models:
    Note: Any
    Alert: Any


@pytest.fixture
def models(engine: Engine, schema: str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    class Note(Base, Audited):
        __tablename__ = "note"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(default="")
        board_id: Mapped[int | None] = mapped_column(default=None)

        __audit__ = AuditOptions(
            label=lambda note: note.name,
            target=lambda note: ("Board", note.board_id),
        )

    class Alert(Base, Audited):
        __tablename__ = "alert"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(default="")

        __audit__ = AuditOptions(severity=Sev.HIGH, label=lambda alert: alert.name)

    Base.metadata.create_all(engine)
    return Models(Note, Alert)


@pytest.fixture
def env(engine: Engine, schema: str, models: Models) -> Env:
    return make_env(engine, schema)


def query(env: Env) -> AuditQuery:
    return env.trail.query


def listing(env: Env, **options: Any) -> list[Group]:
    with Session(env.engine) as session:
        return query(env).list_groups(session, **options).groups


def labels(groups: list[Group]) -> list[list[str | None]]:
    return [[row["object_label"] for row in group.activities] for group in groups]


def add(env: Env, *objects: object, **context: Any) -> None:
    """Commit ``objects`` in one transaction, under ``context`` if given."""
    with env.trail.context(**context), env.factory() as session:
        session.add_all(objects)
        session.commit()


def walk(env: Env, limit: int, **options: Any) -> list[Group]:
    """Every group of the listing, following ``next_cursor``."""
    groups: list[Group] = []
    cursor: Cursor | None = None
    for _ in range(100):
        with Session(env.engine) as session:
            page = query(env).list_groups(
                session, cursor=cursor, limit=limit, **options
            )
        assert len(page.groups) <= limit
        groups.extend(page.groups)
        if page.next_cursor is None:
            return groups
        cursor = page.next_cursor
    raise AssertionError("the listing does not end")


# Grouping and compaction


def test_groups_are_transactions_newest_first(env: Env, models: Models) -> None:
    with env.factory() as session:
        note = models.Note(name="draft")
        session.add(note)
        session.flush()
        note.name = "final"
        session.flush()
        session.add(models.Alert(name="alarm"))
        session.commit()
    add(env, models.Note(name="later"))

    groups = listing(env)

    assert labels(groups) == [["later"], ["final", "alarm"]]
    older = groups[1]
    assert older.activities[0]["verb"] == "entity.created"
    assert older.activities[0]["data"]["changes"]["name"] == [None, "final"]
    assert older.change_count == 2
    assert older.max_severity == Sev.HIGH
    assert groups[0].max_severity == Sev.LOW
    assert changed_fields(older.activities[1]) == ["id", "name"]
    assert older.transaction.id == older.activities[0]["transaction_id"]
    assert older.transaction.issued_at == older.activities[0]["created_at"]


def test_compact_false_returns_raw_rows(env: Env, models: Models) -> None:
    with env.factory() as session:
        note = models.Note(name="draft")
        session.add(note)
        session.flush()
        note.name = "final"
        session.commit()

    (group,) = listing(env, compact=False)

    assert [row["verb"] for row in group.activities] == [
        "entity.created",
        "entity.updated",
    ]
    assert group.change_count == 2


def test_group_hidden_by_compaction_is_skipped_but_paged_past(
    env: Env, models: Models
) -> None:
    add(env, models.Note(name="oldest"))
    with env.factory() as session:
        ghost = models.Note(name="ghost")
        session.add(ghost)
        session.flush()
        session.delete(ghost)
        session.commit()
    add(env, models.Note(name="newest"))

    with Session(env.engine) as session:
        first = query(env).list_groups(session, limit=1)
        second = query(env).list_groups(session, limit=1, cursor=first.next_cursor)
        third = query(env).list_groups(session, limit=1, cursor=second.next_cursor)

    assert labels(first.groups) == [["newest"]]
    assert second.groups == []
    assert second.next_cursor is not None
    assert labels(third.groups) == [["oldest"]]
    assert third.next_cursor is None
    assert labels(walk(env, 1, compact=False)) == [
        ["newest"],
        ["ghost", "ghost"],
        ["oldest"],
    ]


# Severities and visibility


def test_severity_filter_does_not_filter_the_expansion(
    env: Env, models: Models
) -> None:
    add(env, models.Note(name="info"), models.Alert(name="critical"))
    add(env, models.Note(name="info only"))

    (group,) = listing(env, severities={Sev.HIGH})

    assert labels([group]) == [["info", "critical"]]
    assert group.max_severity == Sev.HIGH


def test_visibility_filters_the_expansion(env: Env, models: Models) -> None:
    add(env, models.Note(name="info"), models.Alert(name="critical"))

    groups = listing(
        env, severities={Sev.HIGH}, visibility=Visibility(object_types={"Alert"})
    )

    assert labels(groups) == [["critical"]]


def test_visibility_selects_the_transactions(env: Env, models: Models) -> None:
    add(env, models.Alert(name="visible"))
    add(env, models.Note(name="hidden"))

    with Session(env.engine) as session:
        page = query(env).list_groups(
            session, limit=1, visibility=Visibility(object_types={"Alert"})
        )

    assert labels(page.groups) == [["visible"]]
    assert page.next_cursor is None


# None means no restriction, an empty collection matches nothing.

EMPTY_OR_ABSENT = [
    "severities",
    "verbs",
    "scope_ids",
    "visibility.object_types",
    "visibility.verbs",
    "visibility.scope_ids",
]


def options_for(field: str, value: frozenset[Any] | None) -> dict[str, Any]:
    if field.startswith("visibility."):
        return {"visibility": Visibility(**{field.removeprefix("visibility."): value})}
    return {field: value}


@pytest.mark.parametrize("field", EMPTY_OR_ABSENT)
def test_none_is_no_restriction(env: Env, models: Models, field: str) -> None:
    add(env, models.Note(name="n"), scope_id="t1")

    assert labels(listing(env, **options_for(field, None))) == [["n"]]


@pytest.mark.parametrize("field", EMPTY_OR_ABSENT)
def test_empty_collection_matches_nothing(env: Env, models: Models, field: str) -> None:
    add(env, models.Note(name="older"), scope_id="t1")
    add(env, models.Note(name="newer"), scope_id="t1")

    with Session(env.engine) as session:
        page = query(env).list_groups(
            session, limit=1, **options_for(field, frozenset())
        )

    # Nothing is selected in stage 1 either, so there is no next page.
    assert page.groups == []
    assert page.next_cursor is None


def test_null_scope_fails_a_visibility_restriction(env: Env, models: Models) -> None:
    add(env, models.Note(name="scoped"), models.Alert(name="unscoped"), scope_id="t1")
    add(env, models.Note(name="no scope"))
    with env.engine.begin() as conn:
        activity = env.trail.tables.activity
        conn.execute(
            activity.update()
            .where(activity.c.object_label == "unscoped")
            .values(scope_id=None)
        )

    groups = listing(env, visibility=Visibility(scope_ids={"t1"}))

    assert labels(groups) == [["scoped"]]


def test_null_scope_fails_a_scope_filter(env: Env, models: Models) -> None:
    add(env, models.Note(name="scoped"), scope_id="t1")
    add(env, models.Note(name="no scope"))

    assert labels(listing(env, scope_ids={"t1"})) == [["scoped"]]


# Filters


@pytest.fixture
def filtered(env: Env, models: Models) -> Env:
    add(env, models.Note(name="n1", board_id=7), actor_id="u1", scope_id="s1")
    add(env, models.Alert(name="a1"), actor_id="u2", correlation_id=CORRELATION)
    add(env, models.Note(name="n2"), actor_id="u1", scope_id="s2")
    with env.engine.begin() as conn:
        activity = env.trail.tables.activity
        conn.execute(
            activity.update()
            .where(activity.c.object_label == "a1")
            .values(verb="shop.alerted")
        )
    return env


def object_id_of(env: Env, label: str) -> str:
    for row in env.activities():
        if row["object_label"] == label:
            value: str = row["object_id"]
            return value
    raise AssertionError(label)


@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({}, ["n2", "a1", "n1"]),
        ({"actor_id": "u1"}, ["n2", "n1"]),
        ({"actor_id": "u2"}, ["a1"]),
        ({"object_type": "Alert"}, ["a1"]),
        ({"target_type": "Board"}, ["n1"]),
        ({"target_id": "7"}, ["n1"]),
        ({"verbs": {"shop.alerted"}}, ["a1"]),
        ({"scope_ids": {"s1", "s2"}}, ["n2", "n1"]),
        ({"scope_ids": {"s2"}}, ["n2"]),
        ({"correlation_id": CORRELATION}, ["a1"]),
        ({"severities": {Sev.LOW}}, ["n2", "n1"]),
    ],
)
def test_filter(filtered: Env, options: dict[str, Any], expected: list[str]) -> None:
    groups = listing(filtered, **options)

    assert [label for (label,) in labels(groups)] == expected


def test_object_id_filter(filtered: Env) -> None:
    groups = listing(
        filtered, object_type="Note", object_id=object_id_of(filtered, "n2")
    )

    assert labels(groups) == [["n2"]]


@pytest.mark.parametrize(
    ("options", "queries"),
    [
        ({"actor_id": "u1"}, 1),
        ({"scope_ids": {"s1"}}, 1),
        ({"actor_id": "u1", "severities": set(Sev)}, 2),
        ({"object_type": "Note"}, 2),
    ],
)
def test_actor_or_scope_without_severities_is_one_query(
    filtered: Env, options: dict[str, Any], queries: int
) -> None:
    activity = filtered.trail.tables.activity.name
    with record_statements(filtered.engine) as log:
        log.recording = True
        groups = listing(filtered, **options)
    assert groups

    stage_one = [
        statement
        for statement in log.statements
        if activity in statement and "LIMIT" in statement
    ]
    assert len(stage_one) == queries, stage_one


def test_extra_predicate(filtered: Env) -> None:
    activity = filtered.trail.tables.activity

    groups = listing(filtered, extra_predicate=activity.c.object_label == "a1")

    assert labels(groups) == [["a1"]]


def test_since_is_inclusive_and_until_exclusive(filtered: Env) -> None:
    (middle,) = [g for g in listing(filtered) if labels([g]) == [["a1"]]]
    at = middle.transaction.issued_at

    assert labels(listing(filtered, since=at)) == [["n2"], ["a1"]]
    assert labels(listing(filtered, until=at)) == [["n1"]]
    assert labels(
        listing(filtered, since=at, until=at + timedelta(microseconds=1))
    ) == [["a1"]]


# Headers


def test_header_from_the_transaction_row(env: Env, models: Models) -> None:
    add(
        env,
        models.Note(name="n"),
        actor_type="user",
        actor_id="u1",
        actor_label="ann@example.com",
        remote_addr="10.0.0.1",
        request_id=REQUEST,
        scope_id="t1",
        extra={"ticket": 5},
    )

    (group,) = listing(env)

    header = group.transaction
    assert header.from_snapshot is False
    assert (header.actor_type, header.actor_id, header.actor_label) == (
        "user",
        "u1",
        "ann@example.com",
    )
    assert header.remote_addr == "10.0.0.1"
    assert header.request_id == REQUEST
    assert header.correlation_id == REQUEST
    assert header.scope_id == "t1"
    assert header.meta == {"ticket": 5}


def test_header_from_the_snapshot_when_the_transaction_row_is_gone(
    env: Env, models: Models
) -> None:
    with (
        env.trail.context(
            actor_type="user",
            actor_id="u1",
            actor_label="ann@example.com",
            remote_addr="10.0.0.1",
            user_agent="agent",
            method="POST",
            path="/notes",
            channel="api",
            auth_method="session",
            request_id=REQUEST,
            scope_id="t1",
            extra={"ticket": 5},
        ),
        env.factory() as session,
    ):
        session.add(models.Note(name="first"))
        session.flush()
        with env.trail.context(actor_type="system", actor_id="u2", scope_id="t2"):
            session.add(models.Note(name="second"))
            session.commit()
    with env.engine.begin() as conn:
        conn.execute(delete(env.trail.tables.transaction))

    (group,) = listing(env)

    first = group.activities[0]
    header = group.transaction
    assert header.from_snapshot is True
    assert header.id == first["transaction_id"]
    assert header.issued_at == first["created_at"]
    assert (header.actor_type, header.actor_id, header.actor_label) == (
        "user",
        "u1",
        "ann@example.com",
    )
    assert (header.remote_addr, header.user_agent) == ("10.0.0.1", "agent")
    assert (header.method, header.path) == ("POST", "/notes")
    assert (header.channel, header.auth_method) == ("api", "session")
    assert header.request_id == REQUEST
    assert header.correlation_id == REQUEST
    assert header.scope_id == "t1"
    assert header.meta == {"ticket": 5}


# Pagination


@dataclass(frozen=True)
class Row:
    transaction: str
    severity: int
    verb: str
    at: int  # seconds before the base time


# Rows in insertion (id) order: transactions A, B and C share one created_at
# and their ids interleave; D and E share another. Some rows are LOW, some
# have a verb the filtered walks exclude.
ROWS = [
    Row("A", Sev.HIGH, "shop.a", 0),
    Row("B", Sev.LOW, "shop.a", 0),
    Row("A", Sev.LOW, "shop.b", 0),
    Row("C", Sev.HIGH, "shop.b", 0),
    Row("B", Sev.HIGH, "shop.a", 0),
    Row("A", Sev.HIGH, "shop.a", 0),
    Row("C", Sev.LOW, "shop.a", 0),
    Row("D", Sev.HIGH, "shop.a", 1),
    Row("E", Sev.LOW, "shop.b", 1),
    Row("D", Sev.LOW, "shop.b", 1),
    Row("E", Sev.HIGH, "shop.a", 1),
    Row("B", Sev.LOW, "shop.b", 0),
    Row("F", Sev.LOW, "shop.a", 2),
    Row("F", Sev.LOW, "shop.a", 2),
    Row("G", Sev.HIGH, "shop.b", 2),
]


# Fixed times in partitions the fixture creates, across a month boundary:
# F and G fall in February, the rest in March.
BASE = datetime(2026, 3, 1, 0, 0, 1, tzinfo=timezone.utc)


@pytest.fixture
def collisions(env: Env) -> Iterator[tuple[Env, dict[int, str]]]:
    """Insert ``ROWS``; yields the env and transaction names by id."""
    base = BASE
    tables = env.trail.tables
    names: dict[int, str] = {}
    ids: dict[str, int] = {}
    with env.engine.begin() as conn:
        ensure_partitions(
            conn,
            tables,
            list(Sev),
            months_ahead=1,
            now=datetime(2026, 2, 15, tzinfo=timezone.utc),
        )
        for row in ROWS:
            at = base - timedelta(seconds=row.at)
            if row.transaction not in ids:
                ids[row.transaction] = conn.execute(
                    insert(tables.transaction)
                    .values(actor_type="user", issued_at=at)
                    .returning(tables.transaction.c.id)
                ).scalar_one()
                names[ids[row.transaction]] = row.transaction
            conn.execute(
                insert(tables.activity).values(
                    transaction_id=ids[row.transaction],
                    verb=row.verb,
                    severity=row.severity,
                    created_at=at,
                    data={"v": 1, "payload": {}},
                )
            )
    yield env, names


WALKS: list[dict[str, Any]] = [
    {},
    {"severities": {Sev.HIGH}},
    {"severities": {Sev.LOW}},
    {"verbs": {"shop.a"}},
    {"verbs": {"shop.b"}, "severities": {Sev.LOW}},
]


@pytest.mark.parametrize("limit", [1, 2, 3])
@pytest.mark.parametrize("options", WALKS)
def test_pages_have_no_gaps_or_duplicates(
    collisions: tuple[Env, dict[int, str]], limit: int, options: dict[str, Any]
) -> None:
    env, names = collisions
    severities = options.get("severities")
    verbs = options.get("verbs")
    matching = {
        row.transaction
        for row in ROWS
        if (severities is None or row.severity in severities)
        and (verbs is None or row.verb in verbs)
    }
    everything = sorted(row["id"] for row in env.activities())

    groups = walk(env, limit, compact=False, **options)

    listed = [names[group.transaction.id] for group in groups]
    assert len(listed) == len(set(listed)), listed
    assert set(listed) == matching
    shown = sorted(row["id"] for group in groups for row in group.activities)
    assert len(shown) == len(set(shown))
    assert set(shown) == {
        row["id"]
        for row in env.activities()
        if names[row["transaction_id"]] in matching
    }
    if not options:
        assert shown == everything
    newest_first = [group.transaction.issued_at for group in groups]
    assert newest_first == sorted(newest_first, reverse=True)


def test_page_counts_transactions_across_many_rows(env: Env, models: Models) -> None:
    add(env, models.Note(name="small"))
    with env.factory() as session:
        for index in range(7):
            session.add(models.Note(name=f"big{index}"))
            session.flush()
        session.commit()
    add(env, models.Note(name="newest"))

    # limit=2 reads 3 rows per query; the 7 rows of one transaction take
    # several queries before the next transaction is reached.
    with Session(env.engine) as session:
        page = query(env).list_groups(session, limit=2)
        rest = query(env).list_groups(session, limit=2, cursor=page.next_cursor)

    assert [len(group.activities) for group in page.groups] == [1, 7]
    assert labels(rest.groups) == [["small"]]
    assert rest.next_cursor is None


# Async


async def test_async_matches_sync(
    engine: Engine, schema: str, models: Models, async_engine: AsyncEngine
) -> None:
    env = make_env(engine, schema)
    add(env, models.Note(name="n"), models.Alert(name="a"))
    add(env, models.Note(name="m"))
    with Session(engine) as session:
        expected = query(env).list_groups(session, limit=1)

    async with AsyncSession(async_engine) as session:
        page = await query(env).alist_groups(session, limit=1)
        rest = await query(env).alist_groups(session, cursor=page.next_cursor)

    assert page == expected
    assert labels(rest.groups) == [["n", "a"]]
