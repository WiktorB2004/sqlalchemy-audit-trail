"""``audit_trail.testing``: the assertions and the test table helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from unittest.mock import ANY

import pytest
from sqlalchemy import Engine, MetaData, insert, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from audit_trail import (
    AuditContext,
    Audited,
    AuditEvent,
    AuditOptions,
    AuditTrail,
    Severity,
    Target,
    event,
)
from audit_trail.events import Crud
from audit_trail.testing import (
    UNSET,
    aassert_audited,
    aassert_not_audited,
    assert_audited,
    assert_not_audited,
    clear_audit_entries,
    create_test_tables,
    drop_test_tables,
)
from tests.db.listener_support import Env, Sev, make_env


class ShopEvent(AuditEvent):
    VIEWED = event("testing_test.viewed", Severity.CRITICAL)


@dataclass
class Models:
    Order: Any


@pytest.fixture
def models(engine: Engine, schema: str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    class Order(Base, Audited):
        __tablename__ = "shop_order"
        id: Mapped[int] = mapped_column(primary_key=True)
        status: Mapped[str] = mapped_column(default="new")
        tenant: Mapped[str | None] = mapped_column(default=None)
        customer_id: Mapped[int | None] = mapped_column(default=None)

        __audit__ = AuditOptions(
            scope=lambda order: order.tenant,
            target=lambda order: ("Customer", order.customer_id),
        )

    Base.metadata.create_all(engine)
    return Models(Order)


@pytest.fixture
def env(engine: Engine, schema: str, models: Models) -> Env:
    return make_env(engine, schema, severities=Severity, events=[ShopEvent])


def place_and_pay(env: Env, models: Models) -> Any:
    """Order 1: created as ``new`` (entry #1), then ``paid`` (entry #2)."""
    with env.factory() as session:
        env.trail.bind(session, AuditContext(actor_type="user", actor_id="u1"))
        order = models.Order(id=1, tenant="t1", customer_id=7)
        session.add(order)
        session.commit()
        order.status = "paid"
        session.commit()
    return order


def test_assert_audited_returns_the_matching_entries(env: Env, models: Models) -> None:
    order = place_and_pay(env, models)

    rows = assert_audited(
        env.trail,
        env.engine,
        verb="entity.updated",
        obj=order,
        target=("Customer", 7),
        actor_id="u1",
        scope_id="t1",
        severity=Severity.INFO,
        changes={"status": ["new", "paid"]},
    )

    assert [row["id"] for row in rows] == [2]
    assert rows[0]["data"]["changes"] == {"status": ["new", "paid"]}


def test_assert_audited_accepts_targets_events_and_any(
    env: Env, models: Models
) -> None:
    place_and_pay(env, models)

    by_target = assert_audited(env.trail, env.engine, obj=Target("Order", 1))
    by_tuple = assert_audited(
        env.trail,
        env.engine,
        verb=Crud.CREATED,
        obj=("Order", 1),
        changes={"status": [ANY, "new"], "id": ANY},
    )

    assert [row["id"] for row in by_target] == [1, 2]
    assert [row["id"] for row in by_tuple] == [1]


def test_assert_audited_matches_an_event_payload(env: Env, models: Models) -> None:
    with env.factory() as session:
        env.trail.log(session, ShopEvent.VIEWED, payload={"page": 3, "tab": "info"})
        session.commit()

    rows = assert_audited(
        env.trail,
        env.engine,
        verb=ShopEvent.VIEWED,
        target=None,
        actor_id=None,
        severity=Severity.CRITICAL,
        payload={"page": 3},
    )
    assert [row["verb"] for row in rows] == ["testing_test.viewed"]


def test_failure_lists_the_closest_entries_and_their_differences(
    env: Env, models: Models
) -> None:
    order = place_and_pay(env, models)

    with pytest.raises(AssertionError) as raised:
        assert_audited(
            env.trail,
            env.engine,
            verb="entity.created",
            obj=order,
            changes={"status": [None, "paid"], "note": "x"},
        )

    # #1 differs in one field, #2 in two: the closer, older entry comes first.
    assert str(raised.value) == (
        "no audit entry matches\n"
        "  expected: verb='entity.created', obj=('Order', '1'),"
        " changes={'status': [None, 'paid'], 'note': 'x'}\n"
        "  closest 2 of 2 entries with this verb or object:\n"
        "    #1 entity.created Order 1 (transaction 1)\n"
        "      changes['status']: expected [None, 'paid'], got [None, 'new']\n"
        "      changes['note']: missing\n"
        "    #2 entity.updated Order 1 (transaction 2)\n"
        "      verb: expected 'entity.created', got 'entity.updated'\n"
        "      changes['status']: expected [None, 'paid'], got ['new', 'paid']\n"
        "      changes['note']: missing"
    )


def test_failure_reports_every_differing_column(env: Env, models: Models) -> None:
    order = place_and_pay(env, models)

    with pytest.raises(AssertionError) as raised:
        assert_audited(
            env.trail,
            env.engine,
            obj=order,
            target=None,
            actor_id="u2",
            scope_id=None,
            severity=Severity.CRITICAL,
            payload={"page": 1},
        )

    message = str(raised.value)
    assert message.startswith(
        "no audit entry matches\n"
        "  expected: obj=('Order', '1'), target=None, actor_id='u2',"
        " scope_id=None, severity=40, payload={'page': 1}\n"
        "  closest 2 of 2 entries on this object:\n"
        "    #2 entity.updated Order 1 (transaction 2)\n"
        "      target: expected None, got ('Customer', '7')\n"
        "      actor_id: expected 'u2', got 'u1'\n"
        "      scope_id: expected None, got 't1'\n"
        "      severity: expected 40, got 10\n"
        "      payload: expected {'page': 1}, entry has none\n"
    )


def test_failure_on_a_wrong_object_shows_the_verb_matches(
    env: Env, models: Models
) -> None:
    place_and_pay(env, models)

    with pytest.raises(AssertionError) as raised:
        assert_audited(env.trail, env.engine, verb="entity.updated", obj=("Order", 2))

    assert str(raised.value) == (
        "no audit entry matches\n"
        "  expected: verb='entity.updated', obj=('Order', '2')\n"
        "  closest 1 of 1 entries with this verb or object:\n"
        "    #2 entity.updated Order 1 (transaction 2)\n"
        "      obj: expected ('Order', '2'), got ('Order', '1')"
    )


def test_failure_on_an_empty_log(env: Env) -> None:
    with pytest.raises(AssertionError) as by_verb:
        assert_audited(env.trail, env.engine, verb="entity.deleted")
    with pytest.raises(AssertionError) as by_actor:
        assert_audited(env.trail, env.engine, actor_id="u1")
    with pytest.raises(AssertionError) as by_object:
        assert_audited(env.trail, env.engine, obj=("Order", 1))

    assert str(by_verb.value) == (
        "no audit entry matches\n"
        "  expected: verb='entity.deleted'\n"
        "  no audit entries with this verb"
    )
    assert str(by_actor.value) == (
        "no audit entry matches\n  expected: actor_id='u1'\n  no audit entries recorded"
    )
    assert str(by_object.value).endswith("  no audit entries on this object")


def test_failure_shows_at_most_five_entries_newest_first(
    env: Env, models: Models
) -> None:
    with env.factory() as session:
        session.add_all([models.Order(id=n) for n in range(1, 8)])
        session.commit()

    with pytest.raises(AssertionError) as raised:
        assert_audited(env.trail, env.engine, verb="entity.created", scope_id="t9")

    headlines = [
        line.strip()
        for line in str(raised.value).splitlines()
        if line.startswith("    #")
    ]
    assert "  closest 5 of 7 entries with this verb:" in str(raised.value)
    assert headlines == [
        f"#{n} entity.created Order {n} (transaction 1)" for n in (7, 6, 5, 4, 3)
    ]


def test_obj_none_is_rejected(env: Env) -> None:
    with pytest.raises(ValueError, match="obj must name an object"):
        assert_audited(env.trail, env.engine, obj=None)


def test_assert_not_audited(env: Env, models: Models) -> None:
    order = place_and_pay(env, models)
    assert_not_audited(env.trail, env.engine, verb="entity.deleted")
    assert_not_audited(
        env.trail, env.engine, obj=order, changes={"status": ANY, "x": 1}
    )

    with pytest.raises(AssertionError) as raised:
        assert_not_audited(
            env.trail, env.engine, obj=order, changes={"status": ["new", "paid"]}
        )

    assert str(raised.value) == (
        "1 audit entry matches\n"
        "  expected none with: obj=('Order', '1'),"
        " changes={'status': ['new', 'paid']}\n"
        "    #2 entity.updated Order 1 (transaction 2)"
    )


def test_assert_not_audited_caps_the_list(env: Env, models: Models) -> None:
    with env.factory() as session:
        session.add_all([models.Order(id=n) for n in range(1, 8)])
        session.commit()

    with pytest.raises(AssertionError) as raised:
        assert_not_audited(env.trail, env.engine)

    assert str(raised.value) == (
        "7 audit entries match\n"
        "  expected none with: any entry\n"
        "    #1 entity.created Order 1 (transaction 1)\n"
        "    #2 entity.created Order 2 (transaction 1)\n"
        "    #3 entity.created Order 3 (transaction 1)\n"
        "    #4 entity.created Order 4 (transaction 1)\n"
        "    #5 entity.created Order 5 (transaction 1)\n"
        "    ... and 2 more"
    )


def test_a_session_is_flushed_and_sees_its_own_entries(
    env: Env, models: Models
) -> None:
    # Without autoflush only the helper's own flush writes the entry.
    with env.factory(autoflush=False) as session:
        session.add(models.Order(id=1))

        assert_audited(env.trail, session, verb="entity.created", obj=("Order", 1))
        # Not committed: a new connection of the engine does not see it.
        assert_not_audited(env.trail, env.engine, verb="entity.created")


def test_a_connection_sees_its_uncommitted_entries(env: Env, models: Models) -> None:
    with env.engine.connect() as connection:
        session = env.factory(bind=connection)
        session.add(models.Order(id=1))
        session.flush()

        rows = assert_audited(env.trail, connection, obj=("Order", 1))
        assert [row["verb"] for row in rows] == ["entity.created"]
        assert_not_audited(env.trail, env.engine, obj=("Order", 1))
        session.close()


def test_unset_repr() -> None:
    assert repr(UNSET) == "UNSET"


async def test_async_binds(env: Env, models: Models, async_engine: AsyncEngine) -> None:
    order = place_and_pay(env, models)

    by_engine = await aassert_audited(
        env.trail, async_engine, verb="entity.updated", obj=order
    )
    async with async_engine.connect() as connection:
        by_connection = await aassert_audited(
            env.trail, connection, changes={"status": ["new", "paid"]}
        )
        await aassert_not_audited(env.trail, connection, verb="entity.deleted")
    async with AsyncSession(async_engine) as session:
        by_session = await aassert_audited(env.trail, session, obj=("Order", 1))
        await aassert_not_audited(env.trail, session, actor_id="u2")

    assert [row["id"] for row in by_engine] == [2]
    assert [row["id"] for row in by_connection] == [2]
    assert [row["id"] for row in by_session] == [1, 2]


async def test_async_failures(
    env: Env, models: Models, async_engine: AsyncEngine
) -> None:
    place_and_pay(env, models)

    with pytest.raises(AssertionError) as missing:
        await aassert_audited(env.trail, async_engine, verb="entity.deleted")
    async with AsyncSession(async_engine) as session:
        with pytest.raises(AssertionError) as present:
            await aassert_not_audited(env.trail, session, verb="entity.created")

    assert str(missing.value) == (
        "no audit entry matches\n"
        "  expected: verb='entity.deleted'\n"
        "  no audit entries with this verb"
    )
    assert str(present.value) == (
        "1 audit entry matches\n"
        "  expected none with: verb='entity.created'\n"
        "    #1 entity.created Order 1 (transaction 1)"
    )


# Test table helpers ------------------------------------------------------

JAN_2030 = datetime(2030, 1, 15, tzinfo=timezone.utc)


def insert_entry(connection: Any, trail: AuditTrail, created_at: datetime) -> None:
    connection.execute(
        insert(trail.tables.activity).values(
            transaction_id=1,
            verb="testing_test.viewed",
            severity=int(Sev.LOW),
            created_at=created_at,
        )
    )


def test_create_clear_and_drop_test_tables(engine: Engine, schema: str) -> None:
    trail = AuditTrail(engine, schema=schema, severities=Sev, events=[])
    with engine.begin() as connection:
        create_test_tables(trail, connection, now=JAN_2030)
    with engine.begin() as connection:
        # months_ahead=1: January and February 2030 exist.
        insert_entry(connection, trail, datetime(2030, 2, 28, tzinfo=timezone.utc))
    assert_audited(trail, engine, verb="testing_test.viewed")

    with engine.begin() as connection:
        clear_audit_entries(trail, connection)
    assert_not_audited(trail, engine)

    with engine.begin() as connection:
        drop_test_tables(trail, connection)
    assert inspect(engine).get_table_names(schema=schema) == []


def test_create_test_tables_covers_months_ahead_only(
    engine: Engine, schema: str
) -> None:
    trail = AuditTrail(engine, schema=schema, severities=Sev, events=[])
    with engine.begin() as connection:
        create_test_tables(trail, connection, now=JAN_2030, months_ahead=0)

    with pytest.raises(IntegrityError), engine.begin() as connection:
        insert_entry(connection, trail, datetime(2030, 2, 1, tzinfo=timezone.utc))
