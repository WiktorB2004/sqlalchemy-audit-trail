"""The listener and ``AuditTrail.alog`` under ``AsyncSession``.

The ``entity.*`` capture tests of ``test_listener*.py`` run under
``AsyncSession`` too (see ``listener_support``); these cover what only the
async API has: context variables set in coroutines, ``alog``, the async
durable writer and ``AsyncLoadError`` for loads outside the greenlet.
``async_engine`` runs each test on asyncpg and psycopg.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import (
    Column,
    Engine,
    ForeignKey,
    MetaData,
    RowMapping,
    Table,
    create_engine,
    select,
)
from sqlalchemy.exc import DBAPIError, MissingGreenlet, StatementError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    ORMExecuteState,
    Session,
    mapped_column,
    relationship,
    selectinload,
    sessionmaker,
)

from audit_trail import (
    Actor,
    Audited,
    AuditEvent,
    AuditOptions,
    AuditTrail,
    Severity,
    event,
    listener,
)
from audit_trail.listener import AsyncLoadError
from audit_trail.writer import AuditWriteError
from tests.db.listener_support import create_trail, logged_error, record_statements
from tests.db.outage_support import OUTAGES, outage

CAP = 15
"""Seconds after which a test that should not block fails instead of hanging."""


class AsyncEvent(AuditEvent):
    NOTED = event("async_test.noted", Severity.INFO)
    DENIED = event("async_test.denied", Severity.CRITICAL, durable=True)
    LOCKED = event("async_test.locked", Severity.CRITICAL, fail_closed=True)


@dataclass
class Models:
    Tag: Any
    Post: Any
    Comment: Any


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

    class Tag(Base):
        __tablename__ = "tag"
        id: Mapped[int] = mapped_column(primary_key=True)

    class Post(Base, Audited):
        __tablename__ = "post"
        id: Mapped[int] = mapped_column(primary_key=True)
        title: Mapped[str] = mapped_column(default="")
        tags: Mapped[list[Tag]] = relationship(secondary=post_tags)
        comments: Mapped[list[Comment]] = relationship()  # not tracked

        __audit__ = AuditOptions(track_relationships={"tags"})

    class Comment(Base):
        __tablename__ = "comment"
        id: Mapped[int] = mapped_column(primary_key=True)
        post_id: Mapped[int] = mapped_column(ForeignKey("post.id"))

    Base.metadata.create_all(engine)
    return Models(Tag, Post, Comment)


@dataclass
class AsyncEnv:
    engine: Engine
    trail: AuditTrail
    factory: async_sessionmaker[AsyncSession]

    def activities(self) -> list[RowMapping]:
        table = self.trail.tables.activity
        with self.engine.connect() as conn:
            return list(conn.execute(select(table).order_by(table.c.id)).mappings())

    def transactions(self) -> list[RowMapping]:
        table = self.trail.tables.transaction
        with self.engine.connect() as conn:
            return list(conn.execute(select(table).order_by(table.c.id)).mappings())

    def verbs(self) -> list[str]:
        return [row["verb"] for row in self.activities()]


EnvMaker = Callable[..., AsyncEnv]


@pytest.fixture
async def make(
    engine: Engine, schema: str, async_engine: AsyncEngine, models: Models
) -> AsyncIterator[EnvMaker]:
    """Builds envs on ``async_engine`` and disposes their durable engines."""
    made: list[AsyncEnv] = []

    def build(**options: Any) -> AsyncEnv:
        options.setdefault("events", [AsyncEvent])
        options.setdefault("severities", Severity)
        trail = create_trail(engine, schema, trail_engine=async_engine, **options)
        sync_class = type("AuditedSession", (Session,), {})
        factory = async_sessionmaker(async_engine, sync_session_class=sync_class)
        trail.install(factory)
        made.append(AsyncEnv(engine, trail, factory))
        return made[-1]

    yield build
    for env in made:
        await env.trail.adispose()


async def test_context_set_in_a_coroutine_reaches_the_listener(
    make: EnvMaker, models: Models
) -> None:
    env = make()
    with env.trail.context(actor_type="anonymous", remote_addr="10.0.0.1"):
        env.trail.set_actor(Actor(type="user", id="7", label="ann"))
        async with env.factory() as session:
            session.add(models.Post(title="a"))
            await session.commit()

    (transaction,) = env.transactions()
    assert (transaction["actor_id"], transaction["actor_label"]) == ("7", "ann")
    assert str(transaction["remote_addr"]) == "10.0.0.1"
    (row,) = env.activities()
    assert row["actor_id"] == "7"


async def test_concurrent_tasks_keep_their_own_contexts(
    make: EnvMaker, models: Models
) -> None:
    env = make()
    flushed = [asyncio.Event(), asyncio.Event()]

    async def request(index: int) -> None:
        with env.trail.context(actor_type="user", actor_id=f"user-{index}"):
            async with env.factory() as session:
                session.add(models.Post(title=f"post-{index}"))
                await session.flush()
                # Interleave: both transactions are open, each in its task.
                flushed[index].set()
                await asyncio.gather(*(event.wait() for event in flushed))
                session.add(models.Post(title=f"second-{index}"))
                await session.commit()

    await asyncio.wait_for(asyncio.gather(request(0), request(1)), CAP)

    actors = {row["id"]: row["actor_id"] for row in env.transactions()}
    assert sorted(actors.values()) == ["user-0", "user-1"]
    rows = env.activities()
    assert len(rows) == 4
    for row in rows:
        actor = actors[row["transaction_id"]]
        assert row["actor_id"] == actor
        assert row["data"]["changes"]["title"][1].endswith(actor[-1])


async def test_alog_writes_in_the_session_transaction(
    make: EnvMaker, models: Models
) -> None:
    env = make()
    async with env.factory() as session:
        session.add(models.Post(title="discarded"))
        await session.flush()
        await env.trail.alog(session, AsyncEvent.NOTED)
        await session.rollback()
    assert env.activities() == []

    async with env.factory() as session:
        post = models.Post(title="kept")
        session.add(post)
        await session.flush()
        await env.trail.alog(session, AsyncEvent.NOTED, obj=post)
        await session.commit()
    created, noted = env.activities()
    assert (created["verb"], noted["verb"]) == ("entity.created", "async_test.noted")
    assert noted["object_id"] == created["object_id"]
    assert noted["transaction_id"] == created["transaction_id"]


async def test_alog_without_a_session_uses_the_session_provider(
    make: EnvMaker, models: Models
) -> None:
    env = make()
    async with env.factory() as session:
        env.trail.session_provider = lambda: session
        post = models.Post(title="kept")
        session.add(post)
        await session.flush()
        await env.trail.alog(AsyncEvent.NOTED, obj=post)
        await session.commit()
    created, noted = env.activities()
    assert noted["verb"] == "async_test.noted"
    assert noted["object_id"] == created["object_id"]
    assert noted["transaction_id"] == created["transaction_id"]


async def test_alog_durable_entry_survives_rollback(
    make: EnvMaker, models: Models
) -> None:
    env = make()
    async with env.factory() as session:
        session.add(models.Post(title="discarded"))
        await session.flush()
        await env.trail.alog(session, AsyncEvent.DENIED, actor=Actor("user", "7"))
        await env.trail.alog(session, AsyncEvent.NOTED, durable=True)
        assert env.verbs() == ["async_test.denied", "async_test.noted"]
        await session.rollback()

    denied, noted = env.activities()
    assert denied["actor_id"] == "7"
    assert denied["transaction_id"] != noted["transaction_id"]
    assert env.verbs() == ["async_test.denied", "async_test.noted"]


async def test_alog_fail_closed_raises_audit_write_error(make: EnvMaker) -> None:
    env = make(partitions=[Severity.INFO], on_error="log")  # CRITICAL months missing
    async with env.factory() as session:
        with pytest.raises(AuditWriteError, match="fail_closed") as raised:
            await env.trail.alog(session, AsyncEvent.LOCKED)
    cause = raised.value.__cause__
    assert isinstance(cause, DBAPIError)
    assert "no partition of relation" in str(cause.orig)
    assert env.activities() == []


async def test_alog_creates_a_missing_partition_and_retries(
    make: EnvMaker, caplog: pytest.LogCaptureFixture
) -> None:
    env = make(partitions=[Severity.INFO], auto_create_partitions=True)
    with caplog.at_level(logging.WARNING, logger="audit_trail"):
        async with env.factory() as session:
            await env.trail.alog(session, AsyncEvent.LOCKED)
    assert env.verbs() == ["async_test.locked"]
    assert "retried once" in caplog.text


@pytest.mark.parametrize(
    ("on_error", "verb", "raises"),
    [
        ("log", AsyncEvent.DENIED, False),
        ("raise", AsyncEvent.DENIED, True),
        ("log", AsyncEvent.LOCKED, True),
    ],
)
async def test_exhausted_async_durable_pool_times_out(
    async_engine: AsyncEngine,
    make: EnvMaker,
    on_error: str,
    verb: AsyncEvent,
    raises: bool,
    caplog: pytest.LogCaptureFixture,
) -> None:
    durable = create_async_engine(
        async_engine.url, pool_size=1, max_overflow=0, pool_timeout=0.3
    )
    env = make(durable_engine=durable, on_error=on_error)
    held = await durable.connect()  # the only connection of the pool
    try:
        async with env.factory() as session:
            write = env.trail.alog(session, verb)
            # A deadlock fails here after CAP seconds instead of hanging.
            if raises:
                with pytest.raises(AuditWriteError) as raised:
                    await asyncio.wait_for(write, CAP)
                assert isinstance(raised.value.__cause__, PoolTimeoutError)
            else:
                with caplog.at_level(logging.ERROR, logger="audit_trail"):
                    await asyncio.wait_for(write, CAP)
                assert isinstance(logged_error(caplog), PoolTimeoutError)
    finally:
        await held.close()
        await durable.dispose()
    assert env.activities() == []


@pytest.mark.parametrize("name", OUTAGES)
@pytest.mark.parametrize(
    ("verb", "raises"),
    [(AsyncEvent.LOCKED, True), (AsyncEvent.DENIED, False)],
    ids=["fail_closed", "durable"],
)
async def test_async_durable_engine_outage_follows_the_policy(
    database_url: str,
    async_engine: AsyncEngine,
    make: EnvMaker,
    name: str,
    verb: AsyncEvent,
    raises: bool,
    caplog: pytest.LogCaptureFixture,
) -> None:
    driver = async_engine.url.get_driver_name()
    cause: BaseException | None
    with outage(database_url, name, driver) as broken:
        durable = create_async_engine(broken.url, connect_args=broken.connect_args)
        env = make(durable_engine=durable, on_error="log")
        try:
            with caplog.at_level(logging.ERROR, logger="audit_trail"):
                async with env.factory() as session:
                    write = asyncio.wait_for(env.trail.alog(session, verb), CAP)
                    if raises:
                        with pytest.raises(
                            AuditWriteError, match="fail_closed"
                        ) as raised:
                            await write
                        cause = raised.value.__cause__
                    else:
                        await write
                        cause = logged_error(caplog)
        finally:
            await durable.dispose()
    assert isinstance(cause, Exception)
    assert not isinstance(cause, AuditWriteError)
    assert env.activities() == []


async def test_alog_refuses_a_sync_durable_engine(
    database_url: str, make: EnvMaker
) -> None:
    env = make(durable_engine=create_engine(database_url))  # never connects
    async with env.factory() as session:
        with pytest.raises(TypeError, match=r"use log\(\)"):
            await env.trail.alog(session, AsyncEvent.DENIED)
    assert env.activities() == []


def missing_greenlet(exc: BaseException | None) -> bool:
    """``MissingGreenlet`` as raised by asyncpg, or wrapped by psycopg."""
    if isinstance(exc, StatementError) and not isinstance(exc, MissingGreenlet):
        exc = exc.orig
    return isinstance(exc, MissingGreenlet) and not isinstance(exc, AsyncLoadError)


async def seed(env: AsyncEnv, models: Models) -> None:
    async with env.factory() as session:
        session.add_all([models.Post(id=1, title="p"), models.Tag(id=1)])
        session.add(models.Comment(id=1, post_id=1))
        await session.commit()


async def test_unloaded_tracked_collection_is_explained(
    make: EnvMaker, models: Models
) -> None:
    # Appending to an unloaded collection loads it first, which is I/O
    # outside the greenlet, in the host's code before any flush. The error
    # names the tracked collection and how to load it.
    env = make()
    await seed(env, models)

    async with env.factory() as session:
        post = await session.get(models.Post, 1)
        tag = await session.get(models.Tag, 1)
        assert post is not None
        with pytest.raises(AsyncLoadError) as raised:
            post.tags.append(tag)
    message = str(raised.value)
    assert "Post.tags is not loaded" in message
    assert "selectinload(models.<locals>.Post.tags)" in message
    assert 'lazy="selectin"' in message
    assert isinstance(raised.value, MissingGreenlet)
    assert missing_greenlet(raised.value.__cause__)
    assert env.verbs() == ["entity.created"]

    async with env.factory() as session:
        post = await session.get(
            models.Post, 1, options=[selectinload(models.Post.tags)]
        )
        assert post is not None
        post.tags.append(await session.get(models.Tag, 1))
        await session.commit()
    updated = env.activities()[-1]
    assert updated["data"]["changes"] == {"tags": {"added": ["1"], "removed": []}}


async def test_expired_audited_column_is_explained(
    make: EnvMaker, models: Models
) -> None:
    # Audited keeps the old value of an assigned column (active_history), so
    # assigning an expired column loads it: outside the greenlet that fails.
    env = make()
    await seed(env, models)

    async with env.factory() as session:
        post = await session.get(models.Post, 1)
        assert post is not None
        await session.commit()  # expires post
        with pytest.raises(AsyncLoadError) as assigned:
            post.title = "changed"
        with pytest.raises(AsyncLoadError) as read:
            _ = post.title
        for raised in (assigned, read):
            message = str(raised.value)
            assert "Post.id, models.<locals>.Post.title are not loaded" in message
            assert "await session.refresh(obj)" in message
            assert "expire_on_commit=False" in message
            assert missing_greenlet(raised.value.__cause__)

        await session.refresh(post)
        post.title = "changed"
        await session.commit()
    assert env.activities()[-1]["data"]["changes"] == {"title": ["p", "changed"]}


async def test_expired_column_without_the_instance_names_the_model(
    make: EnvMaker, models: Models, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The instance of a column load comes from a private SQLAlchemy option;
    # should it disappear, the error still is AsyncLoadError.
    monkeypatch.setattr(listener, "_REFRESH_STATE", "_no_such_option")
    env = make()
    await seed(env, models)
    async with env.factory() as session:
        post = await session.get(models.Post, 1)
        assert post is not None
        await session.commit()
        with pytest.raises(AsyncLoadError) as raised:
            post.title = "changed"
    assert "an attribute of models.<locals>.Post is not loaded" in str(raised.value)
    assert missing_greenlet(raised.value.__cause__)


async def test_loads_the_library_does_not_cause_keep_their_error(
    make: EnvMaker, models: Models
) -> None:
    env = make()
    await seed(env, models)

    async with env.factory() as session:
        post = await session.get(models.Post, 1)
        tag = await session.get(models.Tag, 1)
        assert post is not None
        assert tag is not None
        with pytest.raises((MissingGreenlet, StatementError)) as untracked:
            _ = post.comments  # a relationship not in track_relationships
        await session.commit()  # expires tag, which is not Audited
        with pytest.raises((MissingGreenlet, StatementError)) as unaudited:
            _ = tag.id
    for raised in (untracked, unaudited):
        assert missing_greenlet(raised.value), raised.value


async def test_audit_flush_emits_no_select(
    make: EnvMaker, models: Models, async_engine: AsyncEngine
) -> None:
    # Under AsyncSession the flush runs in the greenlet, where a lazy load
    # would succeed silently: only the statements show that none happens.
    env = make()
    await seed(env, models)
    async with env.factory() as session:
        post = await session.get(models.Post, 1)
        tag = await session.get(models.Tag, 1)
        assert post is not None
        await session.refresh(post, ["tags"])
        with record_statements(async_engine.sync_engine) as log:
            log.recording = True
            post.title = "changed"
            post.tags.append(tag)
            await session.commit()
    assert log.statements
    assert [s for s in log.statements if s.lstrip().upper().startswith("SELECT")] == []


@pytest.mark.parametrize("per_mapper", [False, True], ids=["bind", "binds"])
def test_sync_loads_skip_the_async_translation(
    engine: Engine,
    schema: str,
    models: Models,
    monkeypatch: pytest.MonkeyPatch,
    per_mapper: bool,
) -> None:
    trail = create_trail(engine, schema)
    session_class: type[Session] = type("AuditedSyncSession", (Session,), {})
    factory = sessionmaker(class_=session_class)
    trail.install(factory)
    with factory(bind=engine) as session:
        session.add_all([models.Post(id=1, title="p"), models.Tag(id=1)])
        session.commit()

    invoked: list[ORMExecuteState] = []
    invoke = ORMExecuteState.invoke_statement

    def spy(self: ORMExecuteState, *args: Any, **kwargs: Any) -> Any:
        invoked.append(self)
        return invoke(self, *args, **kwargs)

    monkeypatch.setattr(ORMExecuteState, "invoke_statement", spy)
    if per_mapper:
        session = factory(binds={models.Post: engine, models.Tag: engine})
    else:
        session = factory(bind=engine)
    with session:
        post = session.get(models.Post, 1)
        assert post is not None
        session.expire(post)
        assert post.tags == []  # tracked collection lazy load
        post.title = "changed"  # expired column load
        assert len(invoked) == 0
        session.rollback()


async def test_async_session_bound_per_mapper_is_explained(
    make: EnvMaker, models: Models, async_engine: AsyncEngine
) -> None:
    env = make()
    await seed(env, models)
    factory = async_sessionmaker(
        binds={models.Post: async_engine},
        sync_session_class=env.factory.kw["sync_session_class"],
    )
    async with factory() as session:
        post = await session.get(models.Post, 1)
        assert post is not None
        session.expire(post)
        with pytest.raises(AsyncLoadError, match=r"Post\.title are not loaded"):
            post.title = "changed"
