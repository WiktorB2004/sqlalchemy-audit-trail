"""``AuditQuery`` details, object history, related transactions, access
summaries, and ``LabelResolver``."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, NamedTuple
from uuid import UUID

import pytest
from sqlalchemy import (
    Column,
    Engine,
    ForeignKey,
    MetaData,
    Table,
    delete,
    insert,
)
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship

from audit_trail import Audited, AuditOptions
from audit_trail.maintenance import ensure_partitions
from audit_trail.query import (
    AccessCount,
    ActivityRow,
    AuditQuery,
    Cursor,
    FieldLabels,
    Group,
    LabelResolver,
    Page,
    Visibility,
)
from tests.db.listener_support import Env, Sev, make_env, record_statements

CORRELATION = UUID("00000000-0000-0000-0000-00000000000c")
OTHER_CORRELATION = UUID("00000000-0000-0000-0000-00000000000d")

VISIBILITY_FIELDS = ["object_types", "verbs", "scope_ids"]

ENV_OPTIONS: dict[str, Any] = {
    "pseudonymize_key": b"k" * 32,
    "global_redact": {"private_board_id"},
}


@dataclass
class Models:
    Base: Any
    Board: Any
    Card: Any
    Secret: Any
    Tag: Any
    Folder: Any


@pytest.fixture
def models(engine: Engine, schema: str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    card_tags = Table(
        "card_tags",
        Base.metadata,
        Column("card_id", ForeignKey("card.id"), primary_key=True),
        Column("tag_id", ForeignKey("tag.id"), primary_key=True),
    )

    class Board(Base, Audited):
        __tablename__ = "board"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(default="")

        __audit__ = AuditOptions(label=lambda board: board.name)

    class Folder(Base, Audited):
        # Audited, but without a label option.
        __tablename__ = "folder"
        id: Mapped[int] = mapped_column(primary_key=True)

    class Tag(Base, Audited):
        __tablename__ = "tag"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(default="")

        __audit__ = AuditOptions(label=lambda tag: tag.name)

    class Card(Base, Audited):
        __tablename__ = "card"
        id: Mapped[int] = mapped_column(primary_key=True)
        title: Mapped[str] = mapped_column(default="")
        board_id: Mapped[int | None] = mapped_column(ForeignKey("board.id"))
        # A foreign key whose name does not end in _id.
        home: Mapped[int | None] = mapped_column(ForeignKey("board.id"))
        # An _id name without a foreign key.
        owner_id: Mapped[int | None] = mapped_column(default=None)
        hidden_board_id: Mapped[int | None] = mapped_column(
            ForeignKey("board.id"), info={"audit": "redact"}
        )
        folder_id: Mapped[int | None] = mapped_column(ForeignKey("folder.id"))
        hashed_board_id: Mapped[int | None] = mapped_column(
            ForeignKey("board.id"), info={"audit": "hash"}
        )
        # Redacted through global_redact.
        private_board_id: Mapped[int | None] = mapped_column(ForeignKey("board.id"))
        tags: Mapped[list[Tag]] = relationship(secondary=card_tags)

        __audit__ = AuditOptions(
            label=lambda card: card.title,
            target=lambda card: ("Board", card.board_id),
            track_relationships={"tags"},
        )

    class Secret(Base, Audited):
        __tablename__ = "secret"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(default="")
        board_id: Mapped[int | None] = mapped_column(ForeignKey("board.id"))

        __audit__ = AuditOptions(
            label=lambda secret: secret.name,
            target=lambda secret: ("Board", secret.board_id),
        )

    Base.metadata.create_all(engine)
    return Models(Base, Board, Card, Secret, Tag, Folder)


@pytest.fixture
def env(engine: Engine, schema: str, models: Models) -> Env:
    return make_env(engine, schema, **ENV_OPTIONS)


def query(env: Env) -> AuditQuery:
    return env.trail.query


def add(env: Env, *objects: object, **context: Any) -> None:
    """Commit ``objects`` in one transaction, under ``context`` if given."""
    with env.trail.context(**context), env.factory() as session:
        session.add_all(objects)
        session.commit()


def history(env: Env, object_type: str, object_id: object, **options: Any) -> Page:
    with Session(env.engine) as session:
        return query(env).object_history(
            session, object_type, str(object_id), **options
        )


Entry = tuple[str, str | None]  # (verb, object_label)


def entries(groups: list[Group]) -> list[list[Entry]]:
    return [
        [(row["verb"], row["object_label"]) for row in group.activities]
        for group in groups
    ]


def created(label: str) -> Entry:
    return ("entity.created", label)


def updated(label: str) -> Entry:
    return ("entity.updated", label)


def deleted(label: str) -> Entry:
    return ("entity.deleted", label)


# Rows with fixed times, in partitions the helper creates: February and
# March 2026. BASE is one second into March.

BASE = datetime(2026, 3, 1, 0, 0, 1, tzinfo=timezone.utc)


class Row(NamedTuple):
    transaction: str
    at: int  # seconds before BASE
    object_type: str | None = None
    object_id: str | None = None
    target_id: str | None = None  # of a "Board" target
    verb: str = "shop.x"
    severity: int = Sev.LOW
    actor_id: str | None = None
    scope_id: str | None = None
    label: str | None = None


def insert_rows(env: Env, rows: list[Row]) -> dict[int, str]:
    """Insert ``rows`` in order; returns transaction names by id."""
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
        for row in rows:
            at = BASE - timedelta(seconds=row.at)
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
                    object_type=row.object_type,
                    object_id=row.object_id,
                    object_label=row.label,
                    target_type=None if row.target_id is None else "Board",
                    target_id=row.target_id,
                    actor_id=row.actor_id,
                    scope_id=row.scope_id,
                    created_at=at,
                    data={"v": 1, "payload": {}},
                )
            )
    return names


def only(field: str, value: frozenset[str] | None) -> Visibility:
    return Visibility(**{field: value})


# get


def test_get_returns_the_entry_and_its_header(env: Env, models: Models) -> None:
    add(env, models.Board(name="Roadmap"), actor_type="user", actor_id="u1")
    (row,) = env.activities()

    with Session(env.engine) as session:
        detail = query(env).get(session, row["id"], row["created_at"])
        by_severity = query(env).get(
            session, row["id"], row["created_at"], severity=row["severity"]
        )
        other_severity = query(env).get(
            session, row["id"], row["created_at"], severity=Sev.HIGH
        )

    assert detail is not None
    assert detail.activity["object_label"] == "Roadmap"
    assert detail.activity["verb"] == "entity.created"
    assert detail.activity["data"]["changes"]["name"] == [None, "Roadmap"]
    assert detail.transaction.id == row["transaction_id"]
    assert (detail.transaction.actor_type, detail.transaction.actor_id) == (
        "user",
        "u1",
    )
    assert detail.transaction.from_snapshot is False
    assert by_severity == detail
    assert other_severity is None


def test_get_needs_the_entry_created_at(env: Env, models: Models) -> None:
    add(env, models.Board(name="Roadmap"))
    (row,) = env.activities()

    with Session(env.engine) as session:
        found = query(env).get(
            session, row["id"], row["created_at"] + timedelta(microseconds=1)
        )

    assert found is None


def test_get_header_from_the_snapshot(env: Env, models: Models) -> None:
    add(env, models.Board(name="Roadmap"), actor_label="ann@example.com")
    (row,) = env.activities()
    with env.engine.begin() as conn:
        conn.execute(delete(env.trail.tables.transaction))

    with Session(env.engine) as session:
        detail = query(env).get(session, row["id"], row["created_at"])

    assert detail is not None
    assert detail.transaction.from_snapshot is True
    assert detail.transaction.actor_label == "ann@example.com"


@pytest.mark.parametrize("field", VISIBILITY_FIELDS)
def test_get_visibility_none_and_empty(env: Env, models: Models, field: str) -> None:
    add(env, models.Board(name="Roadmap"), scope_id="t1")
    (row,) = env.activities()

    with Session(env.engine) as session:
        shown = query(env).get(
            session, row["id"], row["created_at"], visibility=only(field, None)
        )
        hidden = query(env).get(
            session,
            row["id"],
            row["created_at"],
            visibility=only(field, frozenset()),
        )

    assert shown is not None
    assert hidden is None


def test_get_hides_an_invisible_entry(env: Env, models: Models) -> None:
    add(env, models.Board(name="Roadmap"))
    (row,) = env.activities()

    with Session(env.engine) as session:
        found = query(env).get(
            session,
            row["id"],
            row["created_at"],
            # The entry has no scope: NULL fails a scope restriction.
            visibility=Visibility(scope_ids={"t1"}),
        )

    assert found is None


# object_history


@pytest.fixture
def boards(env: Env, models: Models) -> tuple[int, int]:
    """Two boards; one card moved from the first to the second."""
    with env.factory() as session:
        alpha = models.Board(name="Alpha")
        beta = models.Board(name="Beta")
        session.add_all([alpha, beta])
        session.commit()
        alpha_id, beta_id = alpha.id, beta.id
    with env.factory() as session:
        session.add(models.Card(title="c1", board_id=alpha_id))
        session.add(models.Board(name="unrelated"))
        session.commit()
    with env.factory() as session:
        card = session.query(models.Card).one()
        card.board_id = beta_id
        session.commit()
    with env.factory() as session:
        board = session.get(models.Board, alpha_id)
        assert board is not None
        board.name = "Alpha 2"
        session.commit()
    return alpha_id, beta_id


def test_history_lists_the_record_and_its_children(
    env: Env, boards: tuple[int, int]
) -> None:
    alpha, _ = boards

    page = history(env, "Board", alpha)

    # The unrelated board created with c1 is not part of Alpha's history,
    # nor is c1's move to Beta.
    assert entries(page.groups) == [
        [updated("Alpha 2")],
        [created("c1")],
        [created("Alpha")],
    ]
    assert page.next_cursor is None


def test_history_without_children(env: Env, boards: tuple[int, int]) -> None:
    alpha, _ = boards

    page = history(env, "Board", alpha, include_children=False)

    assert entries(page.groups) == [[updated("Alpha 2")], [created("Alpha")]]


def test_moved_child_is_in_the_new_parent_history(
    env: Env, boards: tuple[int, int]
) -> None:
    alpha, beta = boards

    page = history(env, "Board", beta)

    assert entries(page.groups) == [[updated("c1")], [created("Beta")]]
    (move,) = page.groups[0].activities
    assert move["target_id"] == str(beta)
    assert move["data"]["changes"]["board_id"] == [alpha, beta]


def test_deleted_child_is_in_the_parent_history(env: Env, models: Models) -> None:
    add(env, models.Board(id=1, name="Alpha"))
    add(env, models.Card(id=5, title="c1", board_id=1))
    with env.factory() as session:
        card = session.get(models.Card, 5)
        session.delete(card)
        session.commit()

    page = history(env, "Board", 1)

    assert entries(page.groups) == [
        [deleted("c1")],
        [created("c1")],
        [created("Alpha")],
    ]
    assert page.groups[0].activities[0]["target_id"] == "1"


def test_history_of_a_deleted_object_keeps_its_label(env: Env, models: Models) -> None:
    add(env, models.Board(id=1, name="Alpha"))
    with env.factory() as session:
        session.delete(session.get(models.Board, 1))
        session.commit()

    page = history(env, "Board", 1)

    assert entries(page.groups) == [[deleted("Alpha")], [created("Alpha")]]


def test_children_of_invisible_types_are_left_out(env: Env, models: Models) -> None:
    add(env, models.Board(id=1, name="Alpha"))
    add(env, models.Card(id=5, title="c1", board_id=1))
    add(env, models.Secret(id=7, name="s1", board_id=1))
    add(env, models.Card(id=6, title="c2", board_id=1), models.Secret(name="s2"))

    visible = Visibility(object_types={"Board", "Card"})
    with Session(env.engine) as session:
        page = query(env).object_history(
            session, "Board", "1", visibility=visible, limit=2
        )
        rest = query(env).object_history(
            session, "Board", "1", visibility=visible, cursor=page.next_cursor
        )

    assert entries(page.groups) == [[created("c2")], [created("c1")]]
    assert entries(rest.groups) == [[created("Alpha")]]
    assert rest.next_cursor is None
    assert entries(history(env, "Board", 1).groups)[:2] == [
        [created("c2")],
        [created("s1")],
    ]


def test_visible_children_of_an_invisible_record(env: Env, models: Models) -> None:
    add(env, models.Board(id=1, name="Alpha"))
    add(env, models.Card(id=5, title="c1", board_id=1))

    page = history(env, "Board", 1, visibility=Visibility(object_types={"Card"}))

    assert entries(page.groups) == [[created("c1")]]


@pytest.mark.parametrize("field", VISIBILITY_FIELDS)
def test_history_visibility_none_and_empty(
    env: Env, models: Models, field: str
) -> None:
    add(env, models.Board(id=1, name="Alpha"), scope_id="t1")
    add(env, models.Card(id=5, title="c1", board_id=1), scope_id="t1")

    shown = history(env, "Board", 1, visibility=only(field, None))
    hidden = history(env, "Board", 1, visibility=only(field, frozenset()), limit=1)

    assert entries(shown.groups) == [[created("c1")], [created("Alpha")]]
    assert hidden.groups == []
    assert hidden.next_cursor is None


def test_history_null_scope_fails_a_scope_restriction(env: Env, models: Models) -> None:
    add(env, models.Board(id=1, name="Alpha"), scope_id="t1")
    add(env, models.Card(id=5, title="c1", board_id=1))

    page = history(env, "Board", 1, visibility=Visibility(scope_ids={"t1"}), limit=1)

    assert entries(page.groups) == [[created("Alpha")]]
    assert page.next_cursor is None


def test_history_since_is_inclusive_and_until_exclusive(env: Env) -> None:
    insert_rows(
        env,
        [
            Row("A", 30, "Board", "1", label="a"),
            Row("B", 20, "Card", "5", target_id="1", label="b"),
            Row("C", 10, "Board", "1", label="c"),
        ],
    )

    page = history(
        env,
        "Board",
        1,
        since=BASE - timedelta(seconds=30),
        until=BASE - timedelta(seconds=10),
    )

    assert entries(page.groups) == [[("shop.x", "b")], [("shop.x", "a")]]


# Rows in insertion (id) order, for Board 1. Transactions A, B and C share a
# created_at, their rows interleave, and A reaches the board both as object
# and as target; D and E share another created_at; F and G fall in
# February. Rows of other objects are in the same transactions.
HISTORY_ROWS = [
    Row("A", 1, "Board", "1", label="A board"),
    Row("B", 1, "Card", "5", target_id="1", label="B card"),
    Row("C", 1, "Board", "2", label="C other"),
    Row("A", 1, "Card", "6", target_id="1", label="A card"),
    Row("C", 1, "Board", "1", severity=Sev.HIGH, label="C board"),
    Row("B", 1, "Card", "7", target_id="2", label="B other"),
    Row("D", 5, "Card", "5", target_id="1", label="D card"),
    Row("E", 5, "Board", "1", label="E board"),
    Row("D", 5, "Board", "1", label="D board"),
    Row("H", 5, "Board", "3", label="H other"),
    Row("F", 7200, "Board", "1", label="F board"),
    Row("G", 7200, "Card", "8", target_id="1", label="G card"),
    Row("G", 7200, "Card", "8", target_id="1", label="G card 2"),
]


def history_walk(env: Env, limit: int, **options: Any) -> list[Group]:
    groups: list[Group] = []
    cursor: Cursor | None = None
    for _ in range(100):
        page = history(env, "Board", 1, cursor=cursor, limit=limit, **options)
        assert len(page.groups) <= limit
        groups.extend(page.groups)
        if page.next_cursor is None:
            return groups
        cursor = page.next_cursor
    raise AssertionError("the history does not end")


@pytest.mark.parametrize("limit", [1, 2, 3])
@pytest.mark.parametrize("include_children", [True, False])
def test_history_pages_have_no_gaps_or_duplicates(
    env: Env, limit: int, include_children: bool
) -> None:
    names = insert_rows(env, HISTORY_ROWS)

    def belongs(row: Row) -> bool:
        own = (row.object_type, row.object_id) == ("Board", "1")
        return own or (include_children and row.target_id == "1")

    groups = history_walk(env, limit, include_children=include_children, compact=False)

    listed = [names[group.transaction.id] for group in groups]
    assert len(listed) == len(set(listed)), listed
    assert set(listed) == {row.transaction for row in HISTORY_ROWS if belongs(row)}
    shown = sorted(
        (names[group.transaction.id], row["object_label"])
        for group in groups
        for row in group.activities
    )
    assert shown == sorted(
        (row.transaction, row.label) for row in HISTORY_ROWS if belongs(row)
    )
    newest_first = [group.transaction.issued_at for group in groups]
    assert newest_first == sorted(newest_first, reverse=True)


# related


def test_related_lists_the_correlated_transactions(env: Env, models: Models) -> None:
    add(env, models.Board(name="first"), correlation_id=CORRELATION)
    add(env, models.Board(name="elsewhere"), correlation_id=OTHER_CORRELATION)
    add(
        env,
        models.Board(name="second"),
        models.Tag(name="tag"),
        correlation_id=CORRELATION,
    )

    with record_statements(env.engine) as log, Session(env.engine) as session:
        log.recording = True
        page = query(env).related(session, CORRELATION)

    assert entries(page.groups) == [
        [created("second"), created("tag")],
        [created("first")],
    ]
    assert page.next_cursor is None
    # One stage 1 query over the correlation index, not one per severity.
    assert len([s for s in log.statements if "LIMIT" in s]) == 1


def test_related_pages(env: Env, models: Models) -> None:
    for name in ("first", "second", "third"):
        add(env, models.Board(name=name), correlation_id=CORRELATION)

    with Session(env.engine) as session:
        page = query(env).related(session, CORRELATION, limit=2)
        rest = query(env).related(session, CORRELATION, cursor=page.next_cursor)

    assert entries(page.groups) == [[created("third")], [created("second")]]
    assert entries(rest.groups) == [[created("first")]]


@pytest.mark.parametrize("field", VISIBILITY_FIELDS)
def test_related_visibility_none_and_empty(
    env: Env, models: Models, field: str
) -> None:
    add(env, models.Board(name="a"), scope_id="t1", correlation_id=CORRELATION)
    add(env, models.Board(name="b"), scope_id="t1", correlation_id=CORRELATION)

    with Session(env.engine) as session:
        shown = query(env).related(session, CORRELATION, visibility=only(field, None))
        hidden = query(env).related(
            session, CORRELATION, visibility=only(field, frozenset()), limit=1
        )

    assert entries(shown.groups) == [[created("b")], [created("a")]]
    # Nothing is selected in stage 1 either, so there is no next page.
    assert hidden.groups == []
    assert hidden.next_cursor is None


def test_related_visibility_filters_the_expansion(env: Env, models: Models) -> None:
    add(
        env,
        models.Board(name="board"),
        models.Tag(name="tag"),
        correlation_id=CORRELATION,
    )

    with Session(env.engine) as session:
        page = query(env).related(
            session, CORRELATION, visibility=Visibility(object_types={"Tag"})
        )

    assert entries(page.groups) == [[created("tag")]]


# access_summary

VIEWED = "person.viewed"

ACCESS_ROWS = [
    Row("A", 7200, "Person", "p1", verb=VIEWED, actor_id="u1", scope_id="t1"),
    Row("B", 50, "Person", "p1", verb=VIEWED, actor_id="u2", scope_id="t1"),
    Row("C", 40, "Person", "p1", verb=VIEWED, actor_id="u1", scope_id="t1"),
    Row("D", 30, "Person", "p1", verb=VIEWED, actor_id=None, scope_id="t1"),
    Row("E", 20, "Person", "p1", verb=VIEWED, actor_id="u1", scope_id=None),
    Row("F", 10, "Person", "p1", verb="person.exported", actor_id="u3"),
    Row("G", 5, "Person", "p2", verb=VIEWED, actor_id="u4"),
]


def at(seconds: int) -> datetime:
    return BASE - timedelta(seconds=seconds)


def summary(env: Env, **options: Any) -> list[AccessCount]:
    with Session(env.engine) as session:
        return query(env).access_summary(session, "Person", "p1", VIEWED, **options)


def test_access_summary_counts_per_actor(env: Env) -> None:
    insert_rows(env, ACCESS_ROWS)

    assert summary(env) == [
        AccessCount("u1", 3, at(7200), at(20)),
        AccessCount(None, 1, at(30), at(30)),
        AccessCount("u2", 1, at(50), at(50)),
    ]


def test_access_summary_window(env: Env) -> None:
    insert_rows(env, ACCESS_ROWS)

    assert summary(env, since=at(50), until=at(20)) == [
        AccessCount(None, 1, at(30), at(30)),
        AccessCount("u1", 1, at(40), at(40)),
        AccessCount("u2", 1, at(50), at(50)),
    ]


def test_access_summary_visibility(env: Env) -> None:
    insert_rows(env, ACCESS_ROWS)

    # E has no scope: NULL fails the restriction.
    assert summary(env, visibility=Visibility(scope_ids={"t1"})) == [
        AccessCount(None, 1, at(30), at(30)),
        AccessCount("u1", 2, at(7200), at(40)),
        AccessCount("u2", 1, at(50), at(50)),
    ]
    assert summary(env, visibility=Visibility(verbs={"person.exported"})) == []


@pytest.mark.parametrize("field", VISIBILITY_FIELDS)
def test_access_summary_visibility_none_and_empty(env: Env, field: str) -> None:
    insert_rows(env, ACCESS_ROWS)

    assert len(summary(env, visibility=only(field, None))) == 3
    assert summary(env, visibility=only(field, frozenset())) == []


# LabelResolver


@pytest.fixture
def labelled(env: Env, models: Models) -> Env:
    """Boards 1 and 2, folder 3, tags 4 and 5, card 9 referring to them."""
    add(
        env,
        models.Board(id=1, name="Alpha"),
        models.Board(id=2, name="Beta"),
        models.Folder(id=3),
        scope_id="t1",
    )
    with env.trail.context(scope_id="t1"), env.factory() as session:
        red, blue = models.Tag(id=4, name="red"), models.Tag(id=5, name="blue")
        session.add(
            models.Card(
                id=9,
                title="card",
                board_id=1,
                home=2,
                owner_id=1,
                hidden_board_id=1,
                hashed_board_id=1,
                private_board_id=1,
                folder_id=3,
                tags=[red, blue],
            )
        )
        session.commit()
    with env.trail.context(scope_id="t1"), env.factory() as session:
        card = session.get(models.Card, 9)
        assert card is not None
        # Loading the tags first, so both changes are one flush and entry.
        card.tags.remove(card.tags[0])
        card.board_id = 2
        session.commit()
    return env


def card_activities(env: Env) -> list[ActivityRow]:
    """The card's raw entries, oldest first."""
    with Session(env.engine) as session:
        page = query(env).object_history(session, "Card", "9", compact=False)
    return sorted(
        (row for group in page.groups for row in group.activities),
        key=lambda row: row["id"],
    )


def resolve(
    env: Env, models: Models, base: Any = None, **options: Any
) -> list[dict[str, FieldLabels]]:
    """Labels of the card's entries, oldest first."""
    activities = card_activities(env)
    resolver = LabelResolver(env.trail.tables, base or models.Base)
    with Session(env.engine) as session:
        labels = resolver.resolve(session, activities, **options)
    return [labels.get(row["id"], {}) for row in activities]


def test_resolver_labels_foreign_keys_from_the_metadata(
    labelled: Env, models: Models
) -> None:
    created_labels, updated_labels = resolve(labelled, models)

    # owner_id has no foreign key; the redacted and hashed foreign keys hold
    # no ids; id and title refer to nothing.
    assert created_labels == {
        "board_id": [None, "Alpha"],
        "home": [None, "Beta"],
        "folder_id": [None, "#3"],  # Folder has no label option
        "tags": {"added": ["red", "blue"], "removed": []},
    }
    assert updated_labels == {
        "board_id": ["Alpha", "Beta"],
        "tags": {"added": [], "removed": ["red"]},
    }


def test_resolver_keeps_a_deleted_object_label(labelled: Env, models: Models) -> None:
    with labelled.trail.context(scope_id="t1"), labelled.factory() as session:
        card = session.get(models.Card, 9)
        assert card is not None
        card.hidden_board_id = None
        card.hashed_board_id = None
        card.private_board_id = None
        board = session.get(models.Board, 1)
        assert board is not None
        board.name = "Alpha renamed"
        session.flush()
        card.board_id = None
        session.flush()
        session.delete(board)
        session.commit()

    created_labels, updated_labels, *_ = resolve(labelled, models)

    assert created_labels["board_id"] == [None, "Alpha renamed"]
    assert updated_labels["board_id"] == ["Alpha renamed", "Beta"]


def test_resolver_falls_back_to_the_id(labelled: Env, models: Models) -> None:
    with labelled.engine.begin() as conn:
        activity = labelled.trail.tables.activity
        conn.execute(delete(activity).where(activity.c.object_type == "Board"))

    created_labels, _ = resolve(labelled, models)

    assert created_labels["board_id"] == [None, "#1"]


def test_resolver_does_not_reveal_invisible_objects(
    labelled: Env, models: Models
) -> None:
    _, by_type = resolve(
        labelled, models, visibility=Visibility(object_types={"Card", "Tag"})
    )
    _, by_scope = resolve(labelled, models, visibility=Visibility(scope_ids={"t2"}))

    assert by_type == {
        "board_id": ["#1", "#2"],
        "tags": {"added": [], "removed": ["red"]},
    }
    assert by_scope == {
        "board_id": ["#1", "#2"],
        "tags": {"added": [], "removed": ["#4"]},
    }


def test_resolver_skips_entries_without_a_label(labelled: Env, models: Models) -> None:
    with labelled.trail.context(scope_id="t1"), labelled.factory() as session:
        board = session.get(models.Board, 1)
        assert board is not None
        board.name = "Alpha renamed"
        session.commit()
    with labelled.engine.begin() as conn:
        activity = labelled.trail.tables.activity
        conn.execute(
            activity.update()
            .where(activity.c.object_label == "Alpha renamed")
            .values(object_label=None)
        )

    created_labels, _ = resolve(labelled, models)

    assert created_labels["board_id"] == [None, "Alpha"]


def test_resolver_labels_subclass_instances(engine: Engine, schema: str) -> None:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    class Area(Base, Audited):
        __tablename__ = "area"
        id: Mapped[int] = mapped_column(primary_key=True)
        kind: Mapped[str] = mapped_column(default="area")
        name: Mapped[str] = mapped_column(default="")

        __mapper_args__ = {  # noqa: RUF012
            "polymorphic_on": "kind",
            "polymorphic_identity": "area",
        }
        __audit__ = AuditOptions(label=lambda area: area.name)

    class Zone(Area):
        __mapper_args__ = {"polymorphic_identity": "zone"}  # noqa: RUF012

    class Pin(Base, Audited):
        __tablename__ = "pin"
        id: Mapped[int] = mapped_column(primary_key=True)
        area_id: Mapped[int | None] = mapped_column(ForeignKey("area.id"))

    Base.metadata.create_all(engine)
    env = make_env(engine, schema)
    add(env, Zone(id=1, name="North"))
    add(env, Pin(id=2, area_id=1))

    with Session(engine) as session:
        page = query(env).object_history(session, "Pin", "2")
        (activity,) = page.groups[0].activities
        labels = LabelResolver(env.trail.tables, Base).resolve(session, [activity])

    # The Zone is stored as object_type "Zone", referred to through Area.
    assert labels == {activity["id"]: {"area_id": [None, "North"]}}


@pytest.mark.parametrize("field", VISIBILITY_FIELDS)
def test_resolver_visibility_none_and_empty(
    labelled: Env, models: Models, field: str
) -> None:
    _, shown = resolve(labelled, models, visibility=only(field, None))
    _, hidden = resolve(labelled, models, visibility=only(field, frozenset()))

    assert shown["board_id"] == ["Alpha", "Beta"]
    assert hidden["board_id"] == ["#1", "#2"]


def test_resolver_takes_a_registry(labelled: Env, models: Models) -> None:
    _, updated_labels = resolve(labelled, models, base=models.Base.registry)

    assert updated_labels["board_id"] == ["Alpha", "Beta"]


# Async


async def test_async_matches_sync(
    engine: Engine, schema: str, models: Models, async_engine: AsyncEngine
) -> None:
    env = make_env(engine, schema, **ENV_OPTIONS)
    add(env, models.Board(id=1, name="Alpha"), correlation_id=CORRELATION)
    add(env, models.Card(id=5, title="c1", board_id=1), correlation_id=CORRELATION)
    row = env.activities()[-1]
    resolver = LabelResolver(env.trail.tables, models.Base)
    q = query(env)
    with Session(engine) as session:
        detail = q.get(session, row["id"], row["created_at"])
        page = q.object_history(session, "Board", "1", limit=1)
        related = q.related(session, CORRELATION)
        accesses = q.access_summary(session, "Card", "5", "entity.created")
        activities = [r for group in related.groups for r in group.activities]
        labels = resolver.resolve(session, activities)

    async with AsyncSession(async_engine) as session:
        assert await q.aget(session, row["id"], row["created_at"]) == detail
        assert await q.aobject_history(session, "Board", "1", limit=1) == page
        assert await q.arelated(session, CORRELATION) == related
        assert (
            await q.aaccess_summary(session, "Card", "5", "entity.created") == accesses
        )
        assert await resolver.aresolve(session, activities) == labels
    assert detail is not None
    assert labels[row["id"]]["board_id"] == [None, "Alpha"]
