"""The listener across rollbacks, savepoints and failing audit writes."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import Column, Engine, ForeignKey, MetaData, Table, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from audit_trail import Audited, AuditOptions
from tests.db.listener_support import Env, Sev, make_env


@dataclass
class Models:
    Tag: Any
    Item: Any


@pytest.fixture
def models(engine: Engine, schema: str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    item_tags = Table(
        "item_tags",
        Base.metadata,
        Column("item_id", ForeignKey("item.id"), primary_key=True),
        Column("tag_id", ForeignKey("tag.id"), primary_key=True),
    )

    class Tag(Base):
        __tablename__ = "tag"
        id: Mapped[int] = mapped_column(primary_key=True)

    class Item(Base, Audited):
        __tablename__ = "item"
        id: Mapped[int] = mapped_column(primary_key=True)
        name: Mapped[str] = mapped_column(default="")
        tags: Mapped[list[Tag]] = relationship(secondary=item_tags)

        __audit__ = AuditOptions(
            label=lambda item: item.name, track_relationships={"tags"}
        )

    Base.metadata.create_all(engine)
    return Models(Tag, Item)


@pytest.fixture
def env(engine: Engine, schema: str, models: Models) -> Env:
    return make_env(engine, schema)


def labels(env: Env) -> list[str]:
    return [row["object_label"] for row in env.activities()]


def assert_one_transaction(env: Env) -> None:
    """Every activity row belongs to the single transaction row."""
    transactions = env.transactions()
    assert len(transactions) == 1, transactions
    (transaction,) = transactions
    for row in env.activities():
        assert row["transaction_id"] == transaction["id"]
        assert row["created_at"] == transaction["issued_at"]


def item_names(env: Env, models: Models) -> list[str]:
    with env.engine.connect() as conn:
        return list(conn.scalars(select(models.Item.__table__.c.name)))


@pytest.mark.parametrize("on_error", ["log", "raise"])
def test_rollback_writes_nothing(
    engine: Engine, schema: str, models: Models, on_error: str
) -> None:
    env = make_env(engine, schema, on_error=on_error)
    with env.factory() as session:
        session.add(models.Item(name="a"))
        session.flush()
        session.add(models.Item(name="b"))
        session.flush()
        session.rollback()
    assert env.activities() == []
    assert env.transactions() == []


def test_released_savepoint_keeps_the_outer_transaction_row(
    env: Env, models: Models
) -> None:
    with env.factory() as session:
        session.add(models.Item(name="outer"))
        session.flush()
        with session.begin_nested():
            session.add(models.Item(name="inner"))
        session.add(models.Item(name="after"))
        session.commit()

    assert labels(env) == ["outer", "inner", "after"]
    assert_one_transaction(env)


def test_row_created_in_a_rolled_back_savepoint_is_not_reused(
    env: Env, models: Models
) -> None:
    with env.factory() as session:
        savepoint = session.begin_nested()
        session.add(models.Item(name="discarded"))
        session.flush()  # the transaction row is inserted inside the savepoint
        savepoint.rollback()
        session.add(models.Item(name="kept"))
        session.commit()

    assert labels(env) == ["kept"]
    assert_one_transaction(env)


def test_rolling_back_a_later_savepoint_keeps_a_released_one(
    env: Env, models: Models
) -> None:
    with env.factory() as session:
        with session.begin_nested():
            session.add(models.Item(name="released"))
            session.flush()  # row inserted in the first savepoint
        savepoint = session.begin_nested()
        session.add(models.Item(name="discarded"))
        session.flush()
        savepoint.rollback()
        session.add(models.Item(name="kept"))
        session.commit()

    assert labels(env) == ["released", "kept"]
    assert_one_transaction(env)


def test_rolling_back_a_savepoint_keeps_the_outer_row(env: Env, models: Models) -> None:
    with env.factory() as session:
        session.add(models.Item(name="outer"))
        session.flush()
        savepoint = session.begin_nested()
        session.add(models.Item(name="discarded"))
        session.flush()
        savepoint.rollback()
        session.add(models.Item(name="after"))
        session.commit()

    assert labels(env) == ["outer", "after"]
    assert_one_transaction(env)


def test_outer_rollback_after_a_released_savepoint(env: Env, models: Models) -> None:
    with env.factory() as session:
        with session.begin_nested():
            session.add(models.Item(name="discarded"))
        session.rollback()
        session.add(models.Item(name="next"))
        session.commit()

    assert labels(env) == ["next"]
    assert_one_transaction(env)


def test_disabling_audit_mid_transaction_keeps_the_cache_consistent(
    env: Env, models: Models
) -> None:
    with env.factory() as session:
        savepoint = session.begin_nested()
        session.add(models.Item(name="discarded"))
        session.flush()
        session.info["audit_enabled"] = False
        savepoint.rollback()
        session.info["audit_enabled"] = True
        session.add(models.Item(name="kept"))
        session.commit()

    assert labels(env) == ["kept"]
    assert_one_transaction(env)


def test_savepoint_rollback_discards_relationship_changes(
    env: Env, models: Models
) -> None:
    with env.factory() as session:
        item = models.Item(name="a")
        tag = models.Tag(id=1)
        session.add_all([item, tag])
        session.commit()
        assert item.tags == []
        savepoint = session.begin_nested()
        item.tags.append(tag)
        savepoint.rollback()
        item.name = "b"
        session.commit()

    assert env.activities()[1]["data"]["changes"] == {"name": ["a", "b"]}


def test_failed_audit_write_is_logged_and_the_commit_goes_through(
    engine: Engine, schema: str, models: Models, caplog: pytest.LogCaptureFixture
) -> None:
    env = make_env(engine, schema, partitions=[])  # no partitions: 23514
    with (
        caplog.at_level(logging.ERROR, logger="audit_trail"),
        env.factory() as session,
    ):
        session.add(models.Item(name="business"))
        session.commit()

    assert item_names(env, models) == ["business"]
    assert env.transactions() == []
    assert env.activities() == []
    assert "no partition for the row" in caplog.text
    assert "run ensure_partitions" in caplog.text.lower()


def test_failed_activity_insert_leaves_no_transaction_row(
    engine: Engine, schema: str, models: Models
) -> None:
    # Only the HIGH partitions exist: the transaction row fits, the LOW
    # activity row does not, and the savepoint takes both back.
    env = make_env(engine, schema, partitions=[Sev.HIGH])
    with env.factory() as session:
        session.add(models.Item(name="business"))
        session.commit()

    assert item_names(env, models) == ["business"]
    assert env.transactions() == []


def test_failed_audit_write_inside_a_session_savepoint(
    engine: Engine, schema: str, models: Models
) -> None:
    env = make_env(engine, schema, partitions=[])
    with env.factory() as session:
        session.add(models.Item(name="outer"))
        with session.begin_nested():
            session.add(models.Item(name="inner"))
        session.commit()

    assert sorted(item_names(env, models)) == ["inner", "outer"]


def test_failed_audit_write_aborts_the_commit_with_raise(
    engine: Engine, schema: str, models: Models
) -> None:
    env = make_env(engine, schema, partitions=[], on_error="raise")
    with env.factory() as session:
        session.add(models.Item(name="business"))
        with pytest.raises(IntegrityError, match="no partition of relation"):
            session.commit()

    assert item_names(env, models) == []


def test_closing_the_session_forgets_the_transaction_row(
    env: Env, models: Models
) -> None:
    session = env.factory()
    session.add(models.Item(name="discarded"))
    session.flush()
    session.close()  # neither commit nor rollback
    session.add(models.Item(name="kept"))
    session.commit()
    session.close()

    assert labels(env) == ["kept"]
    assert_one_transaction(env)


def test_leaving_the_session_block_forgets_the_transaction_row(
    env: Env, models: Models
) -> None:
    with env.factory() as session:
        session.add(models.Item(name="discarded"))
        session.flush()
    session.add(models.Item(name="kept"))
    session.commit()

    assert labels(env) == ["kept"]
    assert_one_transaction(env)


def test_rolling_back_an_enclosing_savepoint(env: Env, models: Models) -> None:
    with env.factory() as session:
        outer = session.begin_nested()
        with session.begin_nested():
            session.add(models.Item(name="discarded"))
            session.flush()  # row inserted in the inner savepoint
        outer.rollback()  # takes the released inner savepoint with it
        session.add(models.Item(name="kept"))
        session.commit()

    assert labels(env) == ["kept"]
    assert_one_transaction(env)
