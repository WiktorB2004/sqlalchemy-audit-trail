"""Sessions without a default bind, configured with ``binds``.

Entity entries and ``log(obj=...)`` go on the connection the object is flushed
on; ``log()`` without an object and the queries on the connection for the
audit tables. Most tests run once per session kind (see ``listener_support``);
a second bind is a second engine on the test database.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable, Mapping
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import Engine, ForeignKey, MetaData, RowMapping, create_engine, select
from sqlalchemy.exc import UnboundExecutionError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from audit_trail import Audited, AuditEvent, AuditTrail, Severity, event
from tests.db.listener_support import (
    SESSION_KINDS,
    SessionKind,
    create_trail,
    each_session_kind,
    session_kind,
)

NO_AUDIT_BIND = "no bind for the audit tables"

Bind = Engine | AsyncEngine


class BindEvent(AuditEvent):
    SEEN = event("binds_test.seen", Severity.NOTICE)


@dataclass
class Models:
    Base: Any
    Doc: Any
    Page: Any
    OtherBase: Any
    Note: Any


@pytest.fixture
def models(engine: Engine, schema: str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    class Doc(Base, Audited):
        __tablename__ = "doc"
        id: Mapped[int] = mapped_column(primary_key=True)
        kind: Mapped[str] = mapped_column(default="doc")

        __mapper_args__ = {  # noqa: RUF012
            "polymorphic_on": "kind",
            "polymorphic_identity": "doc",
        }

    class Page(Doc):
        __tablename__ = "page"
        id: Mapped[int] = mapped_column(ForeignKey("doc.id"), primary_key=True)

        __mapper_args__ = {"polymorphic_identity": "page"}  # noqa: RUF012

    class OtherBase(DeclarativeBase):
        metadata = MetaData(schema=schema)

    class Note(OtherBase, Audited):
        __tablename__ = "note"
        id: Mapped[int] = mapped_column(primary_key=True)

    Base.metadata.create_all(engine)
    OtherBase.metadata.create_all(engine)
    return Models(Base, Doc, Page, OtherBase, Note)


@pytest.fixture(params=SESSION_KINDS)
async def kind(
    request: pytest.FixtureRequest, engine: Engine
) -> AsyncIterator[SessionKind]:
    async with session_kind(request.param, engine) as value:
        yield value


@pytest.fixture
def trail(engine: Engine, schema: str, kind: SessionKind) -> AuditTrail:
    return create_trail(
        engine,
        schema,
        trail_engine=kind.async_engine,
        severities=Severity,
        events=[BindEvent],
    )


@pytest.fixture
def first(engine: Engine, kind: SessionKind) -> Bind:
    """The engine of the session kind."""
    return engine if kind.async_engine is None else kind.async_engine


@pytest.fixture
async def second(engine: Engine, kind: SessionKind) -> AsyncIterator[Bind]:
    """Another engine of the session kind, on the test database."""
    if kind.async_engine is None:
        other_sync = create_engine(engine.url)
        yield other_sync
        other_sync.dispose()
        return
    other = create_async_engine(kind.async_engine.url)
    yield other
    await other.dispose()


def sessions(
    trail: AuditTrail, kind: SessionKind, binds: Mapping[Any, Bind]
) -> Callable[[], Session]:
    """Sessions of a new installed factory with ``binds`` and no default bind."""
    if kind.async_engine is None:
        factory = sessionmaker(binds=dict(binds))
        trail.install(factory)
        return factory
    async_factory = async_sessionmaker(
        binds=dict(binds), sync_session_class=type("BindsSession", (Session,), {})
    )
    trail.install(async_factory)
    return lambda: async_factory().sync_session


def audit_binds(trail: AuditTrail, bind: Bind) -> dict[Any, Bind]:
    return {trail.tables.activity: bind, trail.tables.transaction: bind}


def activities(engine: Engine, trail: AuditTrail) -> list[RowMapping]:
    table = trail.tables.activity
    with engine.connect() as conn:
        return list(conn.execute(select(table).order_by(table.c.id)).mappings())


def transaction_ids(engine: Engine, trail: AuditTrail) -> list[int]:
    table = trail.tables.transaction
    with engine.connect() as conn:
        return list(conn.scalars(select(table.c.id).order_by(table.c.id)))


@each_session_kind
def test_mapper_bind_is_used_for_capture_and_log(
    engine: Engine, trail: AuditTrail, models: Models, kind: SessionKind, first: Bind
) -> None:
    factory = sessions(trail, kind, {models.Base: first})
    with factory() as session:
        doc = models.Doc(id=1)
        session.add(doc)
        session.flush()
        trail.log(session, BindEvent.SEEN, obj=doc)
        session.commit()

    rows = activities(engine, trail)
    assert [row["verb"] for row in rows] == ["entity.created", "binds_test.seen"]
    assert len(transaction_ids(engine, trail)) == 1
    assert {row["transaction_id"] for row in rows} == set(
        transaction_ids(engine, trail)
    )


@each_session_kind
def test_table_bind_of_the_model_is_used(
    engine: Engine, trail: AuditTrail, models: Models, kind: SessionKind, first: Bind
) -> None:
    factory = sessions(trail, kind, {models.Note.__table__: first})
    with factory() as session:
        session.add(models.Note(id=1))
        session.commit()

    assert [row["verb"] for row in activities(engine, trail)] == ["entity.created"]


@each_session_kind
def test_log_without_obj_uses_the_bind_of_the_audit_tables(
    engine: Engine, trail: AuditTrail, models: Models, kind: SessionKind, first: Bind
) -> None:
    factory = sessions(trail, kind, {models.Base: first, **audit_binds(trail, first)})
    with factory() as session:
        session.add(models.Doc(id=1))
        session.flush()
        trail.log(session, BindEvent.SEEN)
        session.commit()

    rows = activities(engine, trail)
    assert [row["verb"] for row in rows] == ["entity.created", "binds_test.seen"]
    # One engine: one connection, so one transaction row.
    assert len(transaction_ids(engine, trail)) == 1


@each_session_kind
def test_log_without_obj_and_without_an_audit_bind_raises(
    engine: Engine, trail: AuditTrail, models: Models, kind: SessionKind, first: Bind
) -> None:
    factory = sessions(trail, kind, {models.Base: first})
    with factory() as session:
        with pytest.raises(UnboundExecutionError, match=NO_AUDIT_BIND) as raised:
            trail.log(session, BindEvent.SEEN)
        assert isinstance(raised.value.__cause__, UnboundExecutionError)

    assert activities(engine, trail) == []


@each_session_kind
def test_one_transaction_row_per_bind(
    engine: Engine,
    trail: AuditTrail,
    models: Models,
    kind: SessionKind,
    first: Bind,
    second: Bind,
) -> None:
    factory = sessions(trail, kind, {models.Base: first, models.OtherBase: second})
    with factory() as session:
        session.add_all([models.Doc(id=1), models.Note(id=1)])
        session.flush()
        session.add_all([models.Doc(id=2), models.Note(id=2)])
        session.commit()

    rows = activities(engine, trail)
    by_type: dict[str, set[int]] = {}
    for row in rows:
        by_type.setdefault(row["object_type"], set()).add(row["transaction_id"])
    assert len(rows) == 4
    assert len(by_type["Doc"]) == 1
    assert len(by_type["Note"]) == 1
    assert by_type["Doc"] != by_type["Note"]
    assert by_type["Doc"] | by_type["Note"] == set(transaction_ids(engine, trail))


@each_session_kind
def test_savepoint_rollback_drops_the_row_of_every_bind(
    engine: Engine,
    trail: AuditTrail,
    models: Models,
    kind: SessionKind,
    first: Bind,
    second: Bind,
) -> None:
    factory = sessions(trail, kind, {models.Base: first, models.OtherBase: second})
    with factory() as session:
        # Both connections join the session before the savepoint.
        session.connection(bind_arguments={"mapper": models.Doc})
        session.connection(bind_arguments={"mapper": models.Note})
        savepoint = session.begin_nested()
        session.add_all([models.Doc(id=1), models.Note(id=1)])
        session.flush()
        savepoint.rollback()
        session.add_all([models.Doc(id=2), models.Note(id=2)])
        session.commit()

    rows = activities(engine, trail)
    assert [row["object_id"] for row in rows] == ["2", "2"]
    # Every entry points at a transaction row that was committed.
    assert {row["transaction_id"] for row in rows} == set(
        transaction_ids(engine, trail)
    )
    assert len(transaction_ids(engine, trail)) == 2


@each_session_kind
def test_subclass_entry_uses_the_bind_of_the_base_mapper(
    engine: Engine,
    trail: AuditTrail,
    models: Models,
    kind: SessionKind,
    first: Bind,
    second: Bind,
) -> None:
    # The flush writes a Page on the bind of its base mapper, Doc's; its
    # entry follows it into that transaction.
    factory = sessions(trail, kind, {models.Base: first, models.Page: second})
    with factory() as session:
        session.add_all([models.Doc(id=1), models.Page(id=2)])
        session.commit()

    assert len(activities(engine, trail)) == 2
    assert len(transaction_ids(engine, trail)) == 1


def test_get_bind_override_is_honoured(
    engine: Engine, schema: str, models: Models
) -> None:
    class RoutingSession(Session):
        def get_bind(self, mapper: Any = None, clause: Any = None, **kw: Any) -> Any:
            if mapper is None and clause is None:
                raise UnboundExecutionError("no routing context")
            return engine

    trail = create_trail(engine, schema, severities=Severity, events=[BindEvent])
    factory = sessionmaker(class_=RoutingSession)
    trail.install(factory)
    with factory() as session:
        doc = models.Doc(id=1)
        session.add(doc)
        session.flush()
        trail.log(session, BindEvent.SEEN, obj=doc)
        trail.log(session, BindEvent.SEEN)
        session.commit()
    with factory() as session:
        page = trail.query.list_groups(session)

    assert [len(group.activities) for group in page.groups] == [3]
    assert len(transaction_ids(engine, trail)) == 1


@each_session_kind
def test_list_groups_uses_the_bind_of_the_audit_tables(
    trail: AuditTrail, models: Models, kind: SessionKind, first: Bind
) -> None:
    factory = sessions(trail, kind, {models.Base: first, **audit_binds(trail, first)})
    with factory() as session:
        session.add(models.Doc(id=1))
        session.commit()
    with factory() as session:
        page = trail.query.list_groups(session)

    assert [len(group.activities) for group in page.groups] == [1]


@each_session_kind
def test_list_groups_without_an_audit_bind_raises(
    trail: AuditTrail, models: Models, kind: SessionKind, first: Bind
) -> None:
    factory = sessions(trail, kind, {models.Base: first})
    with factory() as session:
        with pytest.raises(UnboundExecutionError, match=NO_AUDIT_BIND) as raised:
            trail.query.list_groups(session)
        assert isinstance(raised.value.__cause__, UnboundExecutionError)


async def test_async_session_with_binds(
    engine: Engine, schema: str, models: Models, async_engine: AsyncEngine
) -> None:
    trail = create_trail(
        engine,
        schema,
        trail_engine=async_engine,
        severities=Severity,
        events=[BindEvent],
    )
    factory = async_sessionmaker(
        binds={models.Base: async_engine, **audit_binds(trail, async_engine)},
        sync_session_class=type("BindsSession", (Session,), {}),
    )
    trail.install(factory)
    async with factory() as session:
        doc = models.Doc(id=1)
        session.add(doc)
        await session.flush()
        await trail.alog(session, BindEvent.SEEN, obj=doc)
        await trail.alog(session, BindEvent.SEEN)
        await session.commit()
    async with factory() as session:
        page = await trail.query.alist_groups(session)

    assert [len(group.activities) for group in page.groups] == [3]


async def test_async_session_without_an_audit_bind_raises(
    engine: Engine, schema: str, models: Models, async_engine: AsyncEngine
) -> None:
    trail = create_trail(
        engine,
        schema,
        trail_engine=async_engine,
        severities=Severity,
        events=[BindEvent],
    )
    factory: async_sessionmaker[AsyncSession] = async_sessionmaker(
        binds={models.Base: async_engine},
        sync_session_class=type("BindsSession", (Session,), {}),
    )
    trail.install(factory)
    async with factory() as session:
        with pytest.raises(UnboundExecutionError, match=NO_AUDIT_BIND):
            await trail.query.alist_groups(session)
        with pytest.raises(UnboundExecutionError, match=NO_AUDIT_BIND):
            await trail.alog(session, BindEvent.SEEN)
