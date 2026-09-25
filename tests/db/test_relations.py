"""Relationship deltas against the rows actually written to PostgreSQL.

Every scenario reads the association table (or foreign keys) with SQL after
commit and compares it with the net delta the tracker reported, never with
the tracker's own state.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from itertools import chain
from typing import Any

import pytest
from sqlalchemy import (
    Column,
    Engine,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    MetaData,
    String,
    Table,
    event,
    inspect,
    select,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    joinedload,
    mapped_column,
    relationship,
    selectinload,
    sessionmaker,
)

from audit_trail.relations import (
    discard_relationship_changes,
    pop_relationship_changes,
    track_relationships,
)

INITIAL_TAGS = {"101", "102"}


class RecordingSession(Session):
    """Pops relationship deltas after every flush, like the audit listener."""


@event.listens_for(RecordingSession, "after_flush")
def _record(session: Session, flush_context: Any) -> None:
    for obj in chain(session.new, session.dirty, session.deleted):
        changes = pop_relationship_changes(obj)
        if changes:
            session.info.setdefault("changes", []).append((obj, changes))


def net_changes(session: Session, obj: object, key: str) -> tuple[set[str], set[str]]:
    """Net ``(added, removed)`` over all flushes recorded in ``session``."""
    added: set[str] = set()
    removed: set[str] = set()
    for recorded, changes in session.info.get("changes", []):
        if recorded is not obj or key not in changes:
            continue
        for item in changes[key]["added"]:
            if item in removed:
                removed.discard(item)
            else:
                added.add(item)
        for item in changes[key]["removed"]:
            if item in added:
                added.discard(item)
            else:
                removed.add(item)
    return added, removed


@dataclass
class Models:
    Tag: Any
    Label: Any
    Post: Any
    Parent: Any
    Child: Any
    post_tags: Table
    post_labels: Table


@pytest.fixture
def models(engine: Engine, schema: str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    post_tags = Table(
        "post_tags",
        Base.metadata,
        Column("post_id", ForeignKey("post.id"), primary_key=True),
        Column("tag_id", ForeignKey("tag.id"), primary_key=True),
    )
    post_labels = Table(
        "post_labels",
        Base.metadata,
        Column("post_id", ForeignKey("post.id"), primary_key=True),
        Column("label_code", String, primary_key=True),
        Column("label_version", Integer, primary_key=True),
        ForeignKeyConstraint(
            ["label_code", "label_version"], ["label.code", "label.version"]
        ),
    )

    class Tag(Base):
        __tablename__ = "tag"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(default="")

    class Label(Base):
        __tablename__ = "label"
        code: Mapped[str] = mapped_column(primary_key=True)
        version: Mapped[int] = mapped_column(primary_key=True)

    class Post(Base):
        __tablename__ = "post"
        id: Mapped[int] = mapped_column(primary_key=True)
        title: Mapped[str] = mapped_column(default="")
        tags: Mapped[list[Tag]] = relationship(secondary=post_tags)
        labels: Mapped[list[Label]] = relationship(secondary=post_labels)

    class Parent(Base):
        __tablename__ = "parent"
        id: Mapped[int] = mapped_column(primary_key=True)
        children: Mapped[list[Child]] = relationship(back_populates="parent")

    class Child(Base):
        __tablename__ = "child"
        id: Mapped[int] = mapped_column(primary_key=True)
        parent_id: Mapped[int | None] = mapped_column(ForeignKey("parent.id"))
        parent: Mapped[Parent | None] = relationship(back_populates="children")

    Base.metadata.create_all(engine)
    track_relationships(Post.tags, Post.labels, Parent.children)

    with Session(engine) as session:
        session.add_all(
            [
                Post(id=1, tags=[Tag(id=101), Tag(id=102)]),
                Tag(id=103),
                Tag(id=104),
                Parent(id=1, children=[Child(id=1), Child(id=2)]),
                Parent(id=2),
            ]
        )
        session.commit()
    return Models(Tag, Label, Post, Parent, Child, post_tags, post_labels)


@pytest.fixture
def session(engine: Engine, models: Models) -> Iterator[Session]:
    with sessionmaker(engine, class_=RecordingSession)() as s:
        yield s


def db_tags(engine: Engine, models: Models, post_id: int) -> set[str]:
    table = models.post_tags
    with engine.connect() as conn:
        rows = conn.execute(select(table.c.tag_id).where(table.c.post_id == post_id))
        return {str(tag_id) for (tag_id,) in rows}


def db_children(engine: Engine, models: Models, parent_id: int) -> set[str]:
    table = models.Child.__table__
    with engine.connect() as conn:
        rows = conn.execute(select(table.c.id).where(table.c.parent_id == parent_id))
        return {str(child_id) for (child_id,) in rows}


def assert_matches_db(
    session: Session, engine: Engine, models: Models, post: Any, initial: set[str]
) -> None:
    final = db_tags(engine, models, post.id)
    added, removed = net_changes(session, post, "tags")
    assert (added, removed) == (final - initial, initial - final)


Scenario = Callable[[Session, Any, Models], None]


def remove_append(s: Session, post: Any, m: Models) -> None:
    post.tags.remove(s.get_one(m.Tag, 101))
    # Fetching an object not yet in the session autoflushes the removal.
    post.tags.append(s.get_one(m.Tag, 103))


def assign(s: Session, post: Any, m: Models) -> None:
    post.tags = [s.get_one(m.Tag, 102), s.get_one(m.Tag, 103)]


def clear(s: Session, post: Any, m: Models) -> None:
    post.tags.clear()


def extend(s: Session, post: Any, m: Models) -> None:
    post.tags.extend([s.get_one(m.Tag, 103), s.get_one(m.Tag, 104)])


def delete_item(s: Session, post: Any, m: Models) -> None:
    del post.tags[0]


def assign_same_set(s: Session, post: Any, m: Models) -> None:
    post.tags = [s.get_one(m.Tag, 102), s.get_one(m.Tag, 101)]


def append_then_remove(s: Session, post: Any, m: Models) -> None:
    tag = s.get_one(m.Tag, 103)
    post.tags.append(tag)
    post.tags.remove(tag)


def remove_then_reappend(s: Session, post: Any, m: Models) -> None:
    tag = s.get_one(m.Tag, 101)
    post.tags.remove(tag)
    s.get_one(m.Tag, 104)
    post.tags.append(tag)


def pop(s: Session, post: Any, m: Models) -> None:
    post.tags.pop()


def replace_item(s: Session, post: Any, m: Models) -> None:
    post.tags[0] = s.get_one(m.Tag, 103)


def append_new_item(s: Session, post: Any, m: Models) -> None:
    post.tags.append(m.Tag(name="new"))


def flush_in_between(s: Session, post: Any, m: Models) -> None:
    tag = s.get_one(m.Tag, 101)
    post.tags.remove(tag)
    s.flush()
    post.tags.remove(s.get_one(m.Tag, 102))
    post.tags.append(tag)


@pytest.mark.parametrize(
    "scenario",
    [
        remove_append,
        assign,
        clear,
        extend,
        delete_item,
        assign_same_set,
        append_then_remove,
        remove_then_reappend,
        pop,
        replace_item,
        append_new_item,
        flush_in_between,
    ],
)
@pytest.mark.parametrize("loaded", [True, False], ids=["loaded", "unloaded"])
def test_delta_matches_association_table(
    engine: Engine, models: Models, session: Session, scenario: Scenario, loaded: bool
) -> None:
    post = session.get_one(models.Post, 1)
    if loaded:
        assert len(post.tags) == 2
    else:
        assert "tags" not in inspect(post).dict

    scenario(session, post, models)
    session.commit()

    assert_matches_db(session, engine, models, post, INITIAL_TAGS)


def test_new_parent_reports_all_items(
    engine: Engine, models: Models, session: Session
) -> None:
    post = models.Post(id=2, tags=[session.get_one(models.Tag, 103), models.Tag()])
    session.add(post)
    session.commit()

    added, removed = net_changes(session, post, "tags")
    assert added == db_tags(engine, models, 2)
    assert len(added) == 2
    assert removed == set()


def test_multiple_flushes_report_each_flush(
    engine: Engine, models: Models, session: Session
) -> None:
    post = session.get_one(models.Post, 1)
    post.tags.append(session.get_one(models.Tag, 103))
    session.flush()
    post.tags.remove(session.get_one(models.Tag, 101))
    session.commit()

    assert [changes for _, changes in session.info["changes"]] == [
        {"tags": {"added": ["103"], "removed": []}},
        {"tags": {"added": [], "removed": ["101"]}},
    ]
    assert db_tags(engine, models, 1) == {"102", "103"}


def lazy(s: Session, m: Models) -> Any:
    post = s.get_one(m.Post, 1)
    post.tags  # noqa: B018 - triggers the lazy load
    return post


def selectin(s: Session, m: Models) -> Any:
    return s.scalars(select(m.Post).options(selectinload(m.Post.tags))).one()


def joined(s: Session, m: Models) -> Any:
    stmt = select(m.Post).options(joinedload(m.Post.tags))
    return s.scalars(stmt).unique().one()


def refreshed(s: Session, m: Models) -> Any:
    post = lazy(s, m)
    s.refresh(post)
    post.tags  # noqa: B018 - reloads the expired collection
    return post


@pytest.mark.parametrize("load", [lazy, selectin, joined, refreshed])
def test_loading_collection_is_not_a_change(
    models: Models, session: Session, load: Callable[[Session, Models], Any]
) -> None:
    post = load(session, models)
    assert "tags" in inspect(post).dict

    post.title = "changed"
    session.commit()

    assert "changes" not in session.info


def test_rollback_discards_deltas(
    engine: Engine, models: Models, session: Session
) -> None:
    post = session.get_one(models.Post, 1)
    post.tags.append(session.get_one(models.Tag, 103))
    session.rollback()

    assert pop_relationship_changes(post) == {}
    post.title = "changed"
    session.commit()
    assert "changes" not in session.info
    assert db_tags(engine, models, 1) == INITIAL_TAGS


def test_savepoint_rollback_discards_deltas(
    engine: Engine, models: Models, session: Session
) -> None:
    post = session.get_one(models.Post, 1)
    savepoint = session.begin_nested()
    post.tags.append(session.get_one(models.Tag, 103))
    savepoint.rollback()
    session.commit()

    assert "changes" not in session.info
    assert db_tags(engine, models, 1) == INITIAL_TAGS


@pytest.mark.parametrize("discard", ["expire", "refresh"])
def test_expired_collection_discards_deltas(
    engine: Engine, models: Models, session: Session, discard: str
) -> None:
    post = session.get_one(models.Post, 1)
    post.tags.append(session.get_one(models.Tag, 103))
    getattr(session, discard)(post)
    session.commit()

    assert "changes" not in session.info
    assert db_tags(engine, models, 1) == INITIAL_TAGS


def test_discard_relationship_changes(models: Models, session: Session) -> None:
    post = session.get_one(models.Post, 1)
    new_post = models.Post(id=2)
    session.add(new_post)
    post.tags.append(session.get_one(models.Tag, 103))
    new_post.tags.append(session.get_one(models.Tag, 104))

    discard_relationship_changes(session)

    assert pop_relationship_changes(post) == {}
    assert pop_relationship_changes(new_post) == {}


def test_pending_object_rolled_back_then_readded(
    engine: Engine, models: Models, session: Session
) -> None:
    post = models.Post(id=2, tags=[models.Tag(name="new")])
    session.add(post)
    session.rollback()
    assert inspect(post).transient

    with sessionmaker(engine, class_=RecordingSession)() as other:
        other.add(post)
        other.commit()
        added, removed = net_changes(other, post, "tags")
        assert (added, removed) == (db_tags(engine, models, 2), set())
        assert len(added) == 1


def test_detached_object_readded_to_another_session(
    engine: Engine, models: Models, session: Session
) -> None:
    post = session.get_one(models.Post, 1)
    post.tags.append(session.get_one(models.Tag, 103))
    session.close()

    with sessionmaker(engine, class_=RecordingSession)() as other:
        other.add(post)
        other.commit()
        assert_matches_db(other, engine, models, post, INITIAL_TAGS)
        assert net_changes(other, post, "tags") == ({"103"}, set())


@pytest.mark.parametrize("children_loaded", [True, False])
def test_one_to_many_foreign_key_change(
    engine: Engine, models: Models, session: Session, children_loaded: bool
) -> None:
    old_parent = session.get_one(models.Parent, 1)
    new_parent = session.get_one(models.Parent, 2)
    if children_loaded:
        old_parent.children  # noqa: B018
        new_parent.children  # noqa: B018
    child = session.get_one(models.Child, 1)

    child.parent = new_parent
    session.commit()

    for parent, initial in ((old_parent, {"1", "2"}), (new_parent, set())):
        final = db_children(engine, models, parent.id)
        added, removed = net_changes(session, parent, "children")
        assert (added, removed) == (final - initial, initial - final)
    assert db_children(engine, models, 2) == {"1"}


def test_limitation_backref_from_parent_not_in_session_records_no_removal(
    engine: Engine, models: Models, session: Session
) -> None:
    child = session.get_one(models.Child, 1)
    new_parent = session.get_one(models.Parent, 2)

    child.parent = new_parent
    session.commit()

    assert db_children(engine, models, 1) == {"2"}
    recorded = [(type(obj).__name__, obj.id) for obj, _ in session.info["changes"]]
    assert recorded == [("Parent", 2)]


def test_composite_key_items(engine: Engine, models: Models, session: Session) -> None:
    post = session.get_one(models.Post, 1)
    post.labels.append(models.Label(code="a", version=1))
    session.commit()

    table = models.post_labels
    with engine.connect() as conn:
        rows = conn.execute(select(table.c.label_code, table.c.label_version)).all()
    assert rows == [("a", 1)]
    assert net_changes(session, post, "labels") == ({'["a","1"]'}, set())


def test_rejects_non_collection_attributes(models: Models) -> None:
    with pytest.raises(ValueError, match="not a collection relationship"):
        track_relationships(models.Child.parent)
    with pytest.raises(ValueError, match="not a collection relationship"):
        track_relationships(models.Post.title)


def test_tracking_twice_does_not_double_count(
    engine: Engine, models: Models, session: Session
) -> None:
    track_relationships(models.Post.tags)
    post = session.get_one(models.Post, 1)
    append_then_remove(session, post, models)
    post.tags.remove(session.get_one(models.Tag, 101))
    session.commit()

    assert_matches_db(session, engine, models, post, INITIAL_TAGS)
    assert net_changes(session, post, "tags") == (set(), {"101"})


REVISIT = (
    "SQLAlchemy changed how collection history behaves across an autoflush; "
    "revisit the relationship tracking design"
)


def test_history_loses_removal_flushed_by_intermediate_autoflush(
    engine: Engine, models: Models, session: Session
) -> None:
    """Pins why deltas come from events rather than ``attr.history``.

    History only covers changes since the last flush. ``session.get`` of an
    object not yet in the session autoflushes, so a removal made before it is
    no longer in the history read at the end, although the database has it.
    """
    post = session.get_one(models.Post, 1)
    removed_tag = post.tags[0]
    post.tags.remove(removed_tag)
    post.tags.append(session.get_one(models.Tag, 103))

    history = inspect(post).attrs.tags.history
    assert removed_tag not in history.deleted, REVISIT
    assert [t.id for t in history.added] == [103], REVISIT
    session.commit()

    assert str(removed_tag.id) not in db_tags(engine, models, 1)
    assert str(removed_tag.id) in net_changes(session, post, "tags")[1]


def test_history_keeps_removal_without_intermediate_flush(
    models: Models, session: Session
) -> None:
    post = session.get_one(models.Post, 1)
    new_tag = session.get_one(models.Tag, 103)
    removed_tag = post.tags[0]
    post.tags.remove(removed_tag)
    post.tags.append(new_tag)

    history = inspect(post).attrs.tags.history
    assert history.deleted == [removed_tag], REVISIT
    assert history.added == [new_tag], REVISIT
