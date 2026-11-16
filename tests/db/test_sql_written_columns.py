"""Columns an UPDATE or INSERT writes with SQL, recorded by the listener.

Assigned SQL expressions (``obj.placed_at = func.now()``), ``onupdate``,
``server_onupdate``/``Computed`` and the version counter leave no attribute
history, so ``entity_changes`` reads their old values from the capture that
``Audited``'s ``before_update`` listener keeps during the flush. Most tests
run once per ``eager_defaults`` setting, since it decides what is fetched
back.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, ClassVar

import pytest
from sqlalchemy import (
    Computed,
    DateTime,
    Engine,
    ForeignKey,
    MetaData,
    event,
    func,
    inspect,
    select,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    UOWTransaction,
    mapped_column,
    object_session,
    relationship,
)
from sqlalchemy.sql import ColumnElement

from audit_trail import Audited
from audit_trail.diff import _FLUSH_CAPTURE_KEY, REDACTED, UNKNOWN, entity_changes
from audit_trail.serialization import encode_value
from tests.db.listener_support import (
    Env,
    SessionKind,
    each_session_kind,
    make_env,
    session_kind,
)

EAGER_MODES: list[bool | str] = [False, True, "auto"]

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Now:
    """Not a ClauseElement, but rendered as SQL through ``__clause_element__``."""

    def __clause_element__(self) -> ColumnElement[Any]:
        return func.now()


@dataclass
class Models:
    Order: Any
    Versioned: Any
    Calc: Any
    Parent: Any
    Kid: Any
    Animal: Any
    Dog: Any


def mapper_args(eager: bool | str | None = None, **args: Any) -> dict[str, Any]:
    if eager is not None:
        args["eager_defaults"] = eager
    return args


@pytest.fixture(params=EAGER_MODES, ids=lambda mode: f"eager={mode}")
def eager(request: pytest.FixtureRequest) -> bool | str:
    mode: bool | str = request.param
    return mode


@pytest.fixture
def models(engine: Engine, schema: str, eager: bool | str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)
        type_annotation_map: ClassVar[dict[Any, Any]] = {
            datetime: DateTime(timezone=True)
        }

    class Order(Base, Audited):
        __tablename__ = "orders"
        __mapper_args__ = mapper_args(eager)
        id: Mapped[int] = mapped_column(primary_key=True)
        status: Mapped[str]
        placed_at: Mapped[datetime | None]
        modified_at: Mapped[datetime | None] = mapped_column(
            onupdate=func.clock_timestamp()
        )
        touched_at: Mapped[datetime | None] = mapped_column(onupdate=_now)
        created_at: Mapped[datetime | None] = mapped_column(default=func.now())
        secret: Mapped[str | None] = mapped_column(info={"audit": "redact"})
        blob: Mapped[str | None] = mapped_column(info={"audit": "exclude"})

    class Versioned(Base, Audited):
        __tablename__ = "versioned"
        id: Mapped[int] = mapped_column(primary_key=True)
        status: Mapped[str]
        version: Mapped[int] = mapped_column()
        __mapper_args__ = mapper_args(eager, version_id_col=version)

    class Calc(Base, Audited):
        __tablename__ = "calc"
        __mapper_args__ = mapper_args(eager)
        id: Mapped[int] = mapped_column(primary_key=True)
        a: Mapped[int]
        b: Mapped[int]
        total: Mapped[int | None] = mapped_column(Computed("a * b"))

    class Parent(Base, Audited):
        __tablename__ = "parent"
        __mapper_args__ = mapper_args(eager)
        id: Mapped[int] = mapped_column(primary_key=True)
        kids: Mapped[list[Kid]] = relationship()

    class Kid(Base, Audited):
        __tablename__ = "kid"
        __mapper_args__ = mapper_args(eager)
        id: Mapped[int] = mapped_column(primary_key=True)
        parent_id: Mapped[int | None] = mapped_column(ForeignKey("parent.id"))
        touched_at: Mapped[datetime | None] = mapped_column(onupdate=_now)

    class Animal(Base, Audited):
        __tablename__ = "animal"
        __mapper_args__ = mapper_args(eager, polymorphic_on="kind")
        id: Mapped[int] = mapped_column(primary_key=True)
        kind: Mapped[str]
        name: Mapped[str]
        modified_at: Mapped[datetime | None] = mapped_column(
            onupdate=func.clock_timestamp()
        )

    class Dog(Animal):
        __tablename__ = "dog"
        __mapper_args__ = mapper_args(polymorphic_identity="dog")
        id: Mapped[int] = mapped_column(ForeignKey("animal.id"), primary_key=True)
        breed: Mapped[str]

    Base.metadata.create_all(engine)
    return Models(Order, Versioned, Calc, Parent, Kid, Animal, Dog)


@pytest.fixture
def env(engine: Engine, schema: str, models: Models) -> Env:
    return make_env(engine, schema)


def updates(env: Env, object_type: str = "Order") -> list[dict[str, Any]]:
    return [
        row["data"]["changes"]
        for row in env.activities()
        if row["verb"] == "entity.updated" and row["object_type"] == object_type
    ]


def created(env: Env, object_type: str = "Order") -> dict[str, Any]:
    changes: dict[str, Any]
    (changes,) = [
        row["data"]["changes"]
        for row in env.activities()
        if row["verb"] == "entity.created" and row["object_type"] == object_type
    ]
    return changes


def db_value(session: Session, column: Any, pk: int) -> Any:
    table = column.table
    return session.execute(select(column).where(table.c.id == pk)).scalar_one()


def place_order(env: Env, models: Models, **values: Any) -> int:
    with env.factory() as session:
        order = models.Order(status="DRAFT", placed_at=T0, **values)
        session.add(order)
        session.commit()
        order_id: int = order.id
    return order_id


def test_assigned_expression_next_to_a_change(
    env: Env, models: Models, eager: bool | str
) -> None:
    order_id = place_order(env, models)
    with env.factory() as session:
        order = session.get_one(models.Order, order_id)
        order.status = "PLACED"
        order.placed_at = func.now()
        session.commit()
        touched = db_value(session, models.Order.__table__.c.touched_at, order_id)
        modified = db_value(session, models.Order.__table__.c.modified_at, order_id)

    (changes,) = updates(env)
    assert changes["status"] == ["DRAFT", "PLACED"]
    assert changes["placed_at"] == [encode_value(T0), UNKNOWN]
    assert changes["touched_at"] == [None, encode_value(touched)]
    if eager is True:
        assert changes["modified_at"] == [None, encode_value(modified)]
    else:
        assert changes["modified_at"] == [None, UNKNOWN]
    assert set(changes) == {"status", "placed_at", "touched_at", "modified_at"}


def test_assigned_expression_alone_writes_an_entry(env: Env, models: Models) -> None:
    order_id = place_order(env, models)
    with env.factory() as session:
        order = session.get_one(models.Order, order_id)
        order.placed_at = func.now()
        session.commit()

    (changes,) = updates(env)
    assert changes["placed_at"] == [encode_value(T0), UNKNOWN]


def test_onupdate_columns_with_a_known_old_value(
    env: Env, models: Models, eager: bool | str
) -> None:
    order_id = place_order(env, models)
    with env.factory() as session:
        order = session.get_one(models.Order, order_id)
        order.status = "A"
        session.commit()  # modified_at and touched_at now hold a value
        old_modified = db_value(session, models.Order.__table__.c.modified_at, order_id)
        old_touched = db_value(session, models.Order.__table__.c.touched_at, order_id)
        order.status = "B"  # loads the expired row: old values are in memory
        session.commit()
        modified = db_value(session, models.Order.__table__.c.modified_at, order_id)
        touched = db_value(session, models.Order.__table__.c.touched_at, order_id)

    assert modified != old_modified
    changes = updates(env)[1]
    assert changes["status"] == ["A", "B"]
    assert changes["touched_at"] == [encode_value(old_touched), encode_value(touched)]
    new_modified = encode_value(modified) if eager is True else UNKNOWN
    assert changes["modified_at"] == [encode_value(old_modified), new_modified]


def test_version_counter_goes_with_a_change(env: Env, models: Models) -> None:
    with env.factory() as session:
        row = models.Versioned(status="a")
        session.add(row)
        session.commit()
        row.status = "b"
        session.commit()

    assert updates(env, "Versioned") == [{"status": ["a", "b"], "version": [1, 2]}]


def test_computed_column_recorded_only_when_fetched_and_changed(
    env: Env, models: Models, eager: bool | str
) -> None:
    with env.factory() as session:
        calc = models.Calc(a=1, b=2)
        session.add(calc)
        session.commit()
        calc.a = 5  # loads the expired row, total included
        session.commit()

    (changes,) = updates(env, "Calc")
    if eager is True:
        assert changes == {"a": [1, 5], "total": [2, 10]}
    else:
        assert changes == {"a": [1, 5]}


def test_excluded_column_alone_writes_no_entry(env: Env, models: Models) -> None:
    order_id = place_order(env, models)
    with env.factory() as session:
        order = session.get_one(models.Order, order_id)
        order.blob = "x"
        session.commit()
        assert db_value(session, models.Order.__table__.c.touched_at, order_id)

    assert updates(env) == []


def test_literal_values_are_unchanged(env: Env, models: Models) -> None:
    order_id = place_order(env, models)
    with env.factory() as session:
        order = session.get_one(models.Order, order_id)
        order.status = "DRAFT"  # same value: nothing to write
        session.commit()
        order.status = "PLACED"
        session.commit()

    (changes,) = updates(env)
    assert changes["status"] == ["DRAFT", "PLACED"]
    assert "placed_at" not in changes


def test_foreign_key_sync_of_an_expired_child(env: Env, models: Models) -> None:
    with env.factory() as session:
        parent = models.Parent(id=1)
        kid = models.Kid(id=1, touched_at=T0)
        session.add_all([parent, kid])
        session.commit()  # both expired
        parent.kids.append(kid)  # kid.parent_id is set by the flush
        session.commit()
        touched = db_value(session, models.Kid.__table__.c.touched_at, 1)

    assert updates(env, "Kid") == [
        {
            "parent_id": [None, 1],
            "touched_at": [encode_value(T0), encode_value(touched)],
        }
    ]


def test_expression_set_by_a_later_before_flush_handler(
    env: Env, models: Models
) -> None:
    order_id = place_order(env, models)
    with env.factory() as session:

        def stamp(session: Session, context: UOWTransaction, objects: object) -> None:
            for obj in session.dirty:
                if isinstance(obj, models.Order):
                    obj.placed_at = func.now()

        event.listen(session, "before_flush", stamp)
        order = session.get_one(models.Order, order_id)
        order.status = "PLACED"
        session.commit()

    (changes,) = updates(env)
    assert changes["placed_at"] == [encode_value(T0), UNKNOWN]


def test_joined_inheritance_child_only_change(env: Env, models: Models) -> None:
    with env.factory() as session:
        dog = models.Dog(name="Rex", breed="lab")
        session.add(dog)
        session.commit()
        dog.name = "Max"
        session.commit()  # parent row updated: modified_at holds a value
        dog.breed = "pug"  # only the dog table is updated
        session.commit()

    assert updates(env, "Dog")[1] == {"breed": ["lab", "pug"]}


def test_failed_flush_leaves_no_capture_behind(env: Env, models: Models) -> None:
    order_id = place_order(env, models)
    with env.factory() as session:
        order = session.get_one(models.Order, order_id)
        order.status = None  # NOT NULL: the flush fails
        order.placed_at = func.now()
        with pytest.raises(Exception, match="null value"):
            session.flush()
        assert _FLUSH_CAPTURE_KEY not in session.info
        session.rollback()
        assert _FLUSH_CAPTURE_KEY not in session.info
        order.status = "PLACED"
        session.commit()
        assert _FLUSH_CAPTURE_KEY not in session.info

    (changes,) = updates(env)
    assert changes["status"] == ["DRAFT", "PLACED"]
    assert "placed_at" not in changes


@pytest.mark.parametrize("eager", [False], ids=["eager=False"])
@pytest.mark.parametrize(
    "placement", ["before_flush", "mapper_before_update", "after_flush_first"]
)
def test_savepoint_released_inside_flush_keeps_capture(
    env: Env, models: Models, placement: str
) -> None:
    order_id = place_order(env, models)

    def savepoint(session: Session | None) -> None:
        assert session is not None
        # begin_nested flushes, which would fire this listener again.
        if session.info.get("test.in_savepoint"):
            return
        session.info["test.in_savepoint"] = True
        try:
            with session.begin_nested():
                pass
        finally:
            session.info["test.in_savepoint"] = False

    if placement == "before_flush":
        event.listen(env.factory, "before_flush", lambda s, *_: savepoint(s))
    elif placement == "mapper_before_update":
        event.listen(
            models.Order,
            "before_update",
            lambda mapper, connection, target: savepoint(object_session(target)),
        )
    else:
        event.listen(env.factory, "after_flush", lambda s, _: savepoint(s), insert=True)

    with env.factory() as session:
        order = session.get_one(models.Order, order_id)
        order.status = "PLACED"
        order.placed_at = func.now()
        session.commit()

    (changes,) = updates(env)
    assert changes["status"] == ["DRAFT", "PLACED"]
    assert changes["placed_at"] == [encode_value(T0), UNKNOWN]


def test_created_columns_written_by_sql(
    env: Env, models: Models, eager: bool | str
) -> None:
    with env.factory() as session:
        order = models.Order(status="NEW", placed_at=func.now())
        session.add(order)
        session.commit()
        created_at = db_value(session, models.Order.__table__.c.created_at, order.id)

    changes = created(env)
    assert changes["placed_at"] == [None, UNKNOWN]
    if eager is False:
        assert changes["created_at"] == [None, UNKNOWN]
    else:
        assert changes["created_at"] == [None, encode_value(created_at)]
    assert changes["modified_at"] == [None, None]  # not set, no default


def test_redacted_column_assigned_an_expression(env: Env, models: Models) -> None:
    order_id = place_order(env, models, secret="s")
    with env.factory() as session:
        order = session.get_one(models.Order, order_id)
        order.secret = func.concat("a", "b")
        session.commit()

    (changes,) = updates(env)
    assert changes["secret"] == [REDACTED, UNKNOWN]


def test_sessions_without_capture_keep_nothing(
    engine: Engine, env: Env, models: Models
) -> None:
    order_id = place_order(env, models)
    seen: list[object] = []

    def peek(session: Session, context: UOWTransaction) -> None:
        seen.append(session.info.get(_FLUSH_CAPTURE_KEY))

    # Not installed, and installed with capture switched off.
    for session in (Session(engine), env.factory(info={"audit_enabled": False})):
        with session:
            event.listen(session, "after_flush", peek)
            order = session.get_one(models.Order, order_id)
            order.status = "X"
            order.placed_at = func.now()
            session.commit()
            assert _FLUSH_CAPTURE_KEY not in session.info
            assert dict(inspect(order).info) == {}

    assert seen == [None, None]
    assert updates(env) == []


def test_second_flush_in_one_transaction(
    env: Env, models: Models, eager: bool | str
) -> None:
    order_id = place_order(env, models)
    with env.factory() as session:
        order = session.get_one(models.Order, order_id)
        order.status = "A"
        session.flush()
        first = db_value(session, models.Order.__table__.c.modified_at, order_id)
        order.status = "B"
        session.flush()
        second = db_value(session, models.Order.__table__.c.modified_at, order_id)
        session.commit()

    changes = updates(env)[1]
    assert changes["status"] == ["A", "B"]
    if eager is True:
        assert changes["modified_at"] == [encode_value(first), encode_value(second)]
    else:
        # The first flush expired modified_at, and nothing loaded it again.
        assert "modified_at" not in changes


def test_clause_element_object_is_an_expression(env: Env, models: Models) -> None:
    order_id = place_order(env, models)
    with env.factory() as session:
        order = session.get_one(models.Order, order_id)
        order.placed_at = Now()
        session.commit()

    (changes,) = updates(env)
    assert changes["placed_at"] == [encode_value(T0), UNKNOWN]


def test_host_after_flush_gets_the_same_changes(env: Env, models: Models) -> None:
    order_id = place_order(env, models)
    seen: list[dict[str, Any]] = []
    with env.factory() as session:

        def collect(session: Session, context: UOWTransaction) -> None:
            for obj in session.dirty:
                seen.append(entity_changes(obj, "updated"))

        event.listen(session, "after_flush", collect)
        order = session.get_one(models.Order, order_id)
        order.status = "PLACED"
        order.placed_at = func.now()
        session.commit()

    (stored,) = updates(env)
    assert seen == [stored]
    assert stored["placed_at"] == [encode_value(T0), UNKNOWN]


@pytest.fixture(params=["asyncpg", "psycopg_async"])
async def kind(
    request: pytest.FixtureRequest, engine: Engine
) -> AsyncIterator[SessionKind]:
    async with session_kind(request.param, engine) as value:
        yield value


@pytest.mark.parametrize("eager", [False], ids=["eager=False"])
@each_session_kind
def test_assigned_expression_under_async_session(
    engine: Engine, schema: str, models: Models, kind: SessionKind
) -> None:
    async_env = make_env(engine, schema, kind)
    order_id = place_order(async_env, models)
    with async_env.factory() as session:
        order = session.get_one(models.Order, order_id)
        order.status = "PLACED"
        order.placed_at = func.now()
        session.commit()

    (changes,) = updates(async_env)
    assert changes["status"] == ["DRAFT", "PLACED"]
    assert changes["placed_at"] == [encode_value(T0), UNKNOWN]
