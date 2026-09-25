"""The session listener: ``entity.*`` entries written by real flushes."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import (
    Column,
    Engine,
    ForeignKey,
    MetaData,
    Numeric,
    PickleType,
    Table,
    event,
    select,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

from audit_trail import Actor, AuditContext, Audited, AuditOptions
from audit_trail.serialization import UnserializableValueError
from tests.db.listener_support import (
    SESSION_KINDS,
    Env,
    SessionKind,
    Sev,
    create_trail,
    each_session_kind,
    make_env,
    record_statements,
    session_kind,
)


@dataclass
class Models:
    User: Any
    Tag: Any
    Post: Any
    Comment: Any
    Note: Any
    Blob: Any


@pytest.fixture
def models(engine: Engine, schema: str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    post_tags = Table(
        "post_tags",
        Base.metadata,
        Column("post_id", ForeignKey("post.id", ondelete="CASCADE"), primary_key=True),
        Column("tag_id", ForeignKey("tag.id"), primary_key=True),
    )

    class User(Base):
        __tablename__ = "app_user"
        id: Mapped[int] = mapped_column(primary_key=True)
        email: Mapped[str]

    class Tag(Base):
        __tablename__ = "tag"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(default="")

    class Post(Base, Audited):
        __tablename__ = "post"
        id: Mapped[int] = mapped_column(primary_key=True)
        title: Mapped[str]
        price: Mapped[Decimal | None] = mapped_column(Numeric(10, 2))
        secret: Mapped[str | None] = mapped_column(info={"audit": "redact"})
        password: Mapped[str | None]
        body: Mapped[str | None] = mapped_column(deferred=True)
        settings: Mapped[dict[str, Any] | None] = mapped_column(
            MutableDict.as_mutable(JSONB)
        )
        tenant: Mapped[str | None]
        tags: Mapped[list[Tag]] = relationship(secondary=post_tags)
        comments: Mapped[list[Comment]] = relationship(
            back_populates="post", cascade="all, delete-orphan"
        )
        notes: Mapped[list[Note]] = relationship(
            cascade="all, delete-orphan", passive_deletes=True
        )

        __audit__ = AuditOptions(
            label=lambda post: post.title,
            scope=lambda post: post.tenant,
            track_relationships={"tags"},
            snapshot_on_load={"settings"},
        )

    class Comment(Base, Audited):
        __tablename__ = "comment"
        id: Mapped[int] = mapped_column(primary_key=True)
        post_id: Mapped[int] = mapped_column(ForeignKey("post.id"))
        text: Mapped[str] = mapped_column(default="")
        post: Mapped[Post] = relationship(back_populates="comments")

        __audit__ = AuditOptions(
            severity=Sev.HIGH,
            verb_severity={"entity.created": Sev.LOW},
            label=lambda comment: comment.post.title,
            target=lambda comment: ("Post", comment.post_id),
        )

    class Note(Base, Audited):
        __tablename__ = "note"
        id: Mapped[int] = mapped_column(primary_key=True)
        post_id: Mapped[int] = mapped_column(ForeignKey("post.id", ondelete="CASCADE"))

    class Blob(Base, Audited):
        __tablename__ = "blob"
        id: Mapped[int] = mapped_column(primary_key=True)
        value: Mapped[object] = mapped_column(PickleType)

    Base.metadata.create_all(engine)
    return Models(User, Tag, Post, Comment, Note, Blob)


@pytest.fixture(params=SESSION_KINDS)
async def kind(
    request: pytest.FixtureRequest, engine: Engine
) -> AsyncIterator[SessionKind]:
    async with session_kind(request.param, engine) as value:
        yield value


@pytest.fixture
def env(engine: Engine, schema: str, models: Models, kind: SessionKind) -> Env:
    return make_env(engine, schema, kind)


def only(rows: list[Any]) -> Any:
    assert len(rows) == 1, rows
    return rows[0]


@each_session_kind
def test_created_entry(env: Env, models: Models) -> None:
    with env.factory() as session:
        post = models.Post(
            title="Hello", price=Decimal("1.50"), secret="s", tenant="t1"
        )
        session.add(post)
        session.commit()
        post_id = post.id

    transaction = only(env.transactions())
    row = only(env.activities())
    assert row["verb"] == "entity.created"
    assert row["severity"] == Sev.LOW
    assert (row["object_type"], row["object_id"]) == ("Post", str(post_id))
    assert row["object_label"] == "Hello"
    assert row["scope_id"] == "t1"
    assert row["target_type"] is None and row["target_id"] is None
    assert row["transaction_id"] == transaction["id"]
    assert row["created_at"] == transaction["issued_at"]
    assert row["data"] == {
        "v": 1,
        "changes": {
            "id": [None, post_id],
            "title": [None, "Hello"],
            "price": [None, "1.50"],
            "secret": [None, "***"],
            "password": [None, None],
            "body": [None, None],
            "settings": [None, None],
            "tenant": [None, "t1"],
        },
        "context": {"actor_type": "anonymous"},
    }
    assert transaction["actor_type"] == "anonymous"


@each_session_kind
def test_updated_entry_has_only_net_changes(env: Env, models: Models) -> None:
    with env.factory() as session:
        post = models.Post(title="a", price=Decimal("1.5"))
        session.add(post)
        session.commit()
        post.title = "b"
        post.price = Decimal("1.50")  # typed comparison: no change
        session.commit()
        post.title = "b"  # no net change at all: no entry
        session.commit()

    rows = env.activities()
    assert [row["verb"] for row in rows] == ["entity.created", "entity.updated"]
    assert rows[1]["data"]["changes"] == {"title": ["a", "b"]}
    assert rows[1]["object_label"] == "b"
    assert len(env.transactions()) == 2


@each_session_kind
def test_deleted_entry(env: Env, models: Models) -> None:
    with env.factory() as session:
        post = models.Post(title="gone", tenant="t1")
        session.add(post)
        session.commit()
        post_id = post.id
        session.delete(post)
        session.commit()

    row = env.activities()[1]
    assert row["verb"] == "entity.deleted"
    assert row["object_id"] == str(post_id)
    assert row["object_label"] == "gone"
    assert row["data"]["changes"]["title"] == ["gone", None]
    assert row["data"]["changes"]["tenant"] == ["t1", None]


@each_session_kind
def test_severity_target_and_context_scope(env: Env, models: Models) -> None:
    with env.factory() as session:
        env.trail.bind(session, AuditContext(scope_id="ctx-scope"))
        post = models.Post(title="P", tenant=None)
        session.add(post)
        session.flush()
        post_id = post.id
        comment = models.Comment(post=post, text="c")
        session.add(comment)
        session.commit()
        comment.text = "d"
        session.commit()

    rows = [row for row in env.activities() if row["object_type"] == "Comment"]
    created, updated = rows
    assert created["severity"] == Sev.LOW  # verb_severity
    assert updated["severity"] == Sev.HIGH  # model severity
    assert (created["target_type"], created["target_id"]) == ("Post", str(post_id))
    assert created["scope_id"] == "ctx-scope"  # no scope option: from context
    post_row = only([row for row in env.activities() if row["object_type"] == "Post"])
    assert post_row["scope_id"] is None  # the option returned None: no scope


@each_session_kind
def test_relationship_changes(env: Env, models: Models) -> None:
    with env.factory() as session:
        tags = [models.Tag(id=1), models.Tag(id=2)]
        post = models.Post(title="t", tags=tags[:1])
        session.add_all([*tags, post])
        session.commit()
        post.tags.append(tags[1])
        post.tags.remove(tags[0])
        session.commit()
        with session.no_autoflush:  # delete() loads cascades, which would flush
            post.tags.append(tags[0])
            session.delete(post)
        session.commit()

    created, updated, deleted = (
        row for row in env.activities() if row["object_type"] == "Post"
    )
    assert created["data"]["changes"]["tags"] == {"added": ["1"], "removed": []}
    assert updated["data"]["changes"] == {"tags": {"added": ["2"], "removed": ["1"]}}
    assert "tags" not in deleted["data"]["changes"]


@each_session_kind
def test_context_actor_and_meta(env: Env, models: Models) -> None:
    ctx = AuditContext(
        actor_type="system",
        actor_label="cleanup",
        channel="worker",
        extra={"job": "nightly", "amount": Decimal("2.5")},
    )
    with env.trail.context(ctx), env.factory() as session:
        session.add(models.Post(title="x"))
        session.commit()

    transaction = only(env.transactions())
    assert transaction["actor_type"] == "system"
    assert transaction["actor_id"] is None
    assert transaction["channel"] == "worker"
    assert transaction["meta"] == {"job": "nightly", "amount": "2.5"}
    row = only(env.activities())
    assert row["actor_id"] is None
    assert row["data"]["context"] == {
        "actor_type": "system",
        "actor_label": "cleanup",
        "channel": "worker",
        "meta": {"job": "nightly", "amount": "2.5"},
    }


@each_session_kind
def test_actor_label_survives_deleting_the_user(env: Env, models: Models) -> None:
    with env.factory() as session:
        user = models.User(id=7, email="a@b.pl")
        session.add(user)
        session.commit()
        with env.trail.context(actor_type="user"):
            env.trail.set_actor(Actor(type="user", id="7", label=user.email))
            session.add(models.Post(title="x"))
            session.commit()
        session.delete(user)
        session.commit()

    transaction = only(env.transactions())
    assert (transaction["actor_id"], transaction["actor_label"]) == ("7", "a@b.pl")
    row = only(env.activities())
    assert row["actor_id"] == "7"
    assert row["data"]["context"]["actor_label"] == "a@b.pl"


@each_session_kind
def test_only_installed_sessions_are_audited(
    engine: Engine, env: Env, models: Models
) -> None:
    with Session(engine) as session:
        session.add(models.Post(title="bare"))
        session.commit()
    with sessionmaker(engine)() as session:
        session.add(models.Post(title="second factory"))
        session.commit()
    with env.factory() as session:
        session.info["audit_enabled"] = False
        session.add(models.Post(title="disabled"))
        session.commit()
    assert env.activities() == []

    with env.factory() as session:
        session.add(models.Post(title="audited"))
        session.commit()
    assert only(env.activities())["object_label"] == "audited"


def test_session_subclass_install_covers_its_factories(
    engine: Engine, schema: str, models: Models
) -> None:
    class AppSession(Session):
        pass

    trail = create_trail(engine, schema)
    trail.install(AppSession)
    with sessionmaker(engine, class_=AppSession)() as session:
        session.add(models.Post(title="x"))
        session.commit()
    env = Env(engine, trail, sessionmaker(engine, class_=AppSession))
    assert only(env.activities())["verb"] == "entity.created"


@each_session_kind
def test_global_redact(
    engine: Engine, schema: str, models: Models, kind: SessionKind
) -> None:
    env = make_env(engine, schema, kind, global_redact={"password"})
    with env.factory() as session:
        session.add(models.Post(title="x", password="hunter2"))
        session.commit()
    changes = only(env.activities())["data"]["changes"]
    assert changes["password"] == [None, "***"]
    assert changes["title"] == [None, "x"]


@each_session_kind
def test_snapshot_is_refreshed_after_each_flush(env: Env, models: Models) -> None:
    with env.factory() as session:
        post = models.Post(title="x", settings={"a": 1})
        session.add(post)
        session.commit()
        assert post.title == "x"  # reloads after commit and snapshots settings
        post.settings["a"] = 2
        session.flush()
        post.settings["a"] = 3
        session.commit()

    first, second = env.activities()[1:]
    assert first["data"]["changes"] == {"settings": [{"a": 1}, {"a": 2}]}
    assert second["data"]["changes"] == {"settings": [{"a": 2}, {"a": 3}]}


@each_session_kind
def test_expired_attributes_after_commit(env: Env, models: Models) -> None:
    with env.factory() as session:
        post = models.Post(title="old", price=Decimal(1))
        session.add(post)
        session.commit()  # expire_on_commit=True
        post.title = "new"
        session.commit()

    assert env.activities()[1]["data"]["changes"] == {"title": ["old", "new"]}


@each_session_kind
def test_deleting_an_expired_instance(env: Env, models: Models) -> None:
    # The flush reloads an expired instance before deleting it, so after_flush
    # sees its values; a deferred column is not loaded and stays unknown.
    with env.factory() as session:
        post = models.Post(title="t", body="long text")
        session.add(post)
        session.commit()
        session.delete(post)
        session.commit()

    changes = env.activities()[1]["data"]["changes"]
    assert changes["title"] == ["t", None]
    assert changes["body"] == ["<unknown>", None]


@each_session_kind
def test_after_flush_emits_no_sql_besides_audit_inserts(
    env: Env, models: Models, caplog: pytest.LogCaptureFixture
) -> None:
    with env.factory() as session:
        post = models.Post(title="p", tags=[models.Tag(id=1)])
        post.comments.append(models.Comment(text="c"))
        session.add(post)
        session.commit()
        comment_id = post.comments[0].id

    with record_statements(env.engine) as log, env.factory() as session:
        cls = env.factory.class_

        def start(session: Session, flush_context: Any) -> None:
            log.recording = True

        def stop(session: Session, flush_context: Any) -> None:
            log.recording = False

        # Bracket the audit listener: "start" runs before it, "stop" after.
        event.listen(cls, "after_flush", start, insert=True)
        event.listen(cls, "after_flush", stop)
        try:
            comment = session.get(models.Comment, comment_id)
            assert comment is not None
            post = session.get(models.Post, comment.post_id)
            assert post is not None
            session.commit()  # everything expired
            comment.text = "d"  # its label reads comment.post: not loaded
            post.tags.append(models.Tag(id=2))  # tags not loaded
            session.flush()
            session.delete(post)  # deferred body, expired comments
            session.commit()
        finally:
            event.remove(cls, "after_flush", start)
            event.remove(cls, "after_flush", stop)

    assert log.statements, "the bracket recorded nothing"
    allowed = (
        f"INSERT INTO {env.trail.schema}.audit_",
        "SAVEPOINT ",  # on_error="log" isolates the inserts
        "RELEASE SAVEPOINT ",
    )
    assert [s for s in log.statements if not s.startswith(allowed)] == []
    assert "AuditOptions.label of" in caplog.text


@each_session_kind
def test_orm_cascade_and_passive_deletes(env: Env, models: Models) -> None:
    with env.factory() as session:
        post = models.Post(title="p")
        post.comments.append(models.Comment(text="c"))
        post.notes.append(models.Note())
        session.add(post)
        session.commit()
        session.delete(post)
        session.commit()

    deleted = {
        row["object_type"]
        for row in env.activities()
        if row["verb"] == "entity.deleted"
    }
    # Comments are deleted by the ORM cascade and audited. Notes use
    # passive_deletes: the database deletes them, the session never sees
    # them, and they have no entry.
    assert deleted == {"Post", "Comment"}
    with env.engine.connect() as conn:
        assert conn.execute(select(models.Note.__table__)).all() == []


@each_session_kind
def test_one_row_per_flush_and_object(env: Env, models: Models) -> None:
    with env.factory() as session:
        post = models.Post(title="a")
        session.add(post)
        session.flush()
        post.title = "b"
        session.flush()
        post.title = "c"
        session.add(models.Post(title="other"))
        session.commit()

    rows = env.activities()
    # Within a flush: new instances first, then updated ones.
    assert [(row["verb"], row["object_label"]) for row in rows] == [
        ("entity.created", "a"),
        ("entity.updated", "b"),
        ("entity.created", "other"),
        ("entity.updated", "c"),
    ]
    transaction = only(env.transactions())
    assert {row["transaction_id"] for row in rows} == {transaction["id"]}
    assert {row["created_at"] for row in rows} == {transaction["issued_at"]}


@pytest.mark.parametrize("on_error", ["log", "raise"])
@each_session_kind
def test_serialization_errors_propagate(
    engine: Engine, schema: str, models: Models, kind: SessionKind, on_error: str
) -> None:
    env = make_env(engine, schema, kind, on_error=on_error)
    with env.factory() as session:
        session.add(models.Blob(value={1, 2}))
        with pytest.raises(UnserializableValueError):
            session.commit()
    assert env.activities() == []


@pytest.fixture
def failing_label(models: Models) -> Iterator[None]:
    def boom(post: Any) -> str:
        raise RuntimeError("host bug")

    original = models.Post.__audit__
    models.Post.__audit__ = AuditOptions(label=boom)
    yield
    models.Post.__audit__ = original


@pytest.mark.usefixtures("failing_label")
@each_session_kind
def test_label_errors_propagate_in_log_mode(env: Env, models: Models) -> None:
    with env.factory() as session:
        session.add(models.Post(title="x"))
        with pytest.raises(RuntimeError, match="host bug"):
            session.commit()
    with env.engine.connect() as conn:
        assert conn.execute(select(models.Post.__table__)).all() == []
