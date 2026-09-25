"""The ``Audited`` mixin and the option proxy against PostgreSQL.

The proxy tests count statements with a ``before_cursor_execute`` listener:
reading an expired or unloaded attribute through ``label``/``scope``/``target``
must fall back without a single statement.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

import pytest
from sqlalchemy import Engine, ForeignKey, String, event, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship
from sqlalchemy.orm.attributes import instance_state

from audit_trail.config import AuditOptions
from audit_trail.diff import (
    SNAPSHOT_INFO_KEY,
    USE_CONTEXT,
    options_of,
    resolve_label,
    resolve_scope,
    resolve_target,
)
from audit_trail.mixin import Audited, refresh_snapshot


class Base(DeclarativeBase):
    pass


class Company(Base):
    __tablename__ = "company"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String)


class Order(Base, Audited):
    __tablename__ = "orders"
    __audit__ = AuditOptions(
        label=lambda obj: obj.title,
        scope=lambda obj: obj.company_id,
        target=lambda obj: ("Company", obj.company_id),
        snapshot_on_load={"settings"},
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String)
    company_id: Mapped[int] = mapped_column(ForeignKey("company.id"))
    company: Mapped[Company] = relationship()
    settings: Mapped[dict[str, Any] | None] = mapped_column(
        MutableDict.as_mutable(JSONB)
    )

    @property
    def display(self) -> str:
        return f"#{self.id} {self.title}"


def snapshot(obj: object) -> dict[str, object]:
    result: dict[str, object] = instance_state(obj).info.get(SNAPSHOT_INFO_KEY, {})
    return result


class Statements:
    def __init__(self) -> None:
        self.count = 0

    def __call__(self, *args: object) -> None:
        self.count += 1


@pytest.fixture
def db(engine: Engine, schema: str) -> Iterator[Engine]:
    bound = engine.execution_options(schema_translate_map={None: schema})
    Base.metadata.create_all(bound)
    yield bound


@pytest.fixture
def statements(engine: Engine) -> Iterator[Statements]:
    counter = Statements()
    event.listen(engine, "before_cursor_execute", counter)
    yield counter
    event.remove(engine, "before_cursor_execute", counter)


@pytest.fixture
def session(db: Engine) -> Iterator[Session]:
    with Session(db) as sess:
        sess.add(Company(id=10, name="Acme"))
        sess.add(Order(id=1, title="First", company_id=10, settings={"a": 1}))
        sess.commit()
        yield sess


@pytest.fixture
def order(session: Session) -> Order:
    order = session.get(Order, 1)
    assert order is not None
    return order


def test_loaded_attributes_are_read_without_sql(
    order: Order, statements: Statements
) -> None:
    options = options_of(Order)
    assert resolve_label(order, options) == "First"
    assert resolve_scope(order, options) == "10"
    assert resolve_target(order, options) == ("Company", "10")
    assert statements.count == 0


def test_expired_attribute_falls_back_without_sql(
    session: Session,
    order: Order,
    statements: Statements,
    caplog: pytest.LogCaptureFixture,
) -> None:
    session.expire(order)
    options = options_of(Order)
    with caplog.at_level(logging.WARNING, logger="audit_trail.diff"):
        assert resolve_label(order, options) is None
        assert resolve_scope(order, options) is USE_CONTEXT
        assert resolve_target(order, options) is None
    assert statements.count == 0
    messages = [record.getMessage() for record in caplog.records]
    assert len(messages) == 3
    for option, attribute, message in zip(
        ("label", "scope", "target"), ("title", "company_id", "company_id"), messages
    ):
        assert f"AuditOptions.{option} of Order read '{attribute}'" in message


def test_property_reading_expired_attribute_emits_no_sql(
    session: Session, order: Order, statements: Statements
) -> None:
    session.expire(order, ["title"])
    options = AuditOptions(label=lambda obj: obj.display)
    assert resolve_label(order, options) is None
    assert statements.count == 0


def test_unloaded_relationship_falls_back_without_sql(
    order: Order, statements: Statements
) -> None:
    options = AuditOptions(label=lambda obj: obj.company.name)
    assert resolve_label(order, options) is None
    assert statements.count == 0


def test_loaded_relationship_is_readable(order: Order, statements: Statements) -> None:
    assert order.company.name == "Acme"
    statements.count = 0
    options = AuditOptions(label=lambda obj: obj.company.name)
    assert resolve_label(order, options) == "Acme"
    assert statements.count == 0


def test_expired_attribute_of_related_object_emits_no_sql(
    session: Session, order: Order, statements: Statements
) -> None:
    assert order.company.name == "Acme"
    session.expire(order.company)
    statements.count = 0
    options = AuditOptions(label=lambda obj: obj.company.name)
    assert resolve_label(order, options) is None
    assert statements.count == 0


async def test_expired_attribute_under_async_session(
    async_engine: AsyncEngine, session: Session, schema: str
) -> None:
    """Without the proxy this read would be a lazy load: MissingGreenlet."""
    bound = async_engine.execution_options(schema_translate_map={None: schema})
    async with AsyncSession(bound) as async_session:
        order = await async_session.get(Order, 1)
        assert order is not None
        async_session.expire(order)
        assert resolve_label(order, options_of(Order)) is None


def test_snapshot_taken_on_load_and_partial_refresh(
    session: Session, order: Order, db: Engine
) -> None:
    assert snapshot(order) == {"settings": {"a": 1}}

    with db.begin() as conn:
        conn.execute(update(Order).values(settings={"a": 2}, title="Changed"))
    with session.no_autoflush:
        assert order.settings is not None
        order.settings["a"] = 5  # pending; refreshing other attributes keeps it
        session.refresh(order, ["title"])
        assert snapshot(order) == {"settings": {"a": 1}}
        session.refresh(order, ["settings"])
        assert snapshot(order) == {"settings": {"a": 2}}


def test_snapshot_is_a_deep_copy(order: Order) -> None:
    assert order.settings is not None
    order.settings["a"] = 99
    assert snapshot(order) == {"settings": {"a": 1}}
    refresh_snapshot(order)
    assert snapshot(order) == {"settings": {"a": 99}}


def test_refresh_snapshot_ignores_models_without_snapshot(session: Session) -> None:
    company = session.get(Company, 10)
    assert company is not None
    refresh_snapshot(company)
    assert SNAPSHOT_INFO_KEY not in instance_state(company).info
