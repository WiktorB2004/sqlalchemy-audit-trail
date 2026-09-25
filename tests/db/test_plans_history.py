"""Query plans of ``get`` and ``object_history`` on the sixth execution.

See ``plan_support`` for how the plans are captured.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from audit_trail.maintenance import ensure_partitions
from audit_trail.query import AuditQuery, Cursor
from tests.conftest import with_driver
from tests.db.listener_support import Sev, create_trail
from tests.db.plan_support import (
    MODES,
    Explained,
    asixth_execution,
    check_custom,
    explained,
    nodes,
    relations,
    require_superuser,
    sixth_execution,
)

# One transaction a minute going back from the 20th of January to April
# 2026, each with three rows: Board 1 itself (LOW), a card targeting Board 1
# (HIGH) and another board (LOW).
MONTHS = 4
PER_MONTH = 1000
CURSOR = Cursor(datetime(2026, 2, 20, tzinfo=timezone.utc) - timedelta(minutes=100), 0)
LIMIT = 5

# The Board 1 row of the transaction ten minutes before February 20th.
ENTRY_ID = 2 * 100000 + 10
ENTRY_AT = datetime(2026, 2, 20, tzinfo=timezone.utc) - timedelta(minutes=10)

FEBRUARY = {"audit_activity_10_p2026_02", "audit_activity_40_p2026_02"}
UP_TO_FEBRUARY = FEBRUARY | {
    "audit_activity_10_p2026_01",
    "audit_activity_40_p2026_01",
}


@pytest.fixture
def query(engine: Engine, schema: str) -> AuditQuery:
    trail = create_trail(engine, schema, partitions=[])
    tables = trail.tables
    with engine.begin() as conn:
        require_superuser(conn)
        ensure_partitions(
            conn,
            tables,
            list(Sev),
            months_ahead=MONTHS - 1,
            now=datetime(2026, 1, 15, tzinfo=timezone.utc),
        )
        months = ", ".join(
            f"({index}, timestamptz '2026-{index:02d}-20 00:00+00')"
            for index in range(1, MONTHS + 1)
        )
        source = f"FROM generate_series(1, {PER_MONTH}) g, (VALUES {months}) m(n, ts)"
        conn.execute(
            text(
                f'INSERT INTO "{schema}".audit_transaction (id, issued_at, actor_type) '
                "OVERRIDING SYSTEM VALUE "
                f"SELECT m.n * 100000 + g, m.ts - g * interval '1 minute', 'user' "
                + source
            )
        )
        # The Board 1 rows get the transaction id as their id, so ENTRY_ID
        # is known.
        conn.execute(
            text(
                f'INSERT INTO "{schema}".audit_activity '
                "(id, transaction_id, verb, severity, object_type, object_id, "
                "target_type, target_id, created_at, data) OVERRIDING SYSTEM VALUE "
                "SELECT m.n * 100000 + g + r.offset_, m.n * 100000 + g, 'shop.x', "
                "r.severity, r.object_type, "
                "CASE WHEN r.object_type = 'Card' THEN g::text "
                "WHEN r.offset_ = 0 THEN '1' ELSE (g % 50 + 2)::text END, "
                "r.target_type, r.target_id, "
                "m.ts - g * interval '1 minute', '{\"v\": 1, \"payload\": {}}' "
                + source
                + ", (VALUES (0, 10, 'Board', NULL, NULL), "
                "(50000, 40, 'Card', 'Board', '1'), "
                "(70000, 10, 'Board', NULL, NULL)) "
                "r(offset_, severity, object_type, target_type, target_id)"
            )
        )
        conn.execute(text(f'ANALYZE "{schema}".audit_activity'))
        conn.execute(text(f'ANALYZE "{schema}".audit_transaction'))
    return trail.query


@pytest.fixture(params=["asyncpg", "psycopg"])
async def plan_engine(
    request: pytest.FixtureRequest, database_url: str
) -> AsyncIterator[AsyncEngine]:
    """Async engine without a pool: auto_explain must not leak to other tests."""
    engine = create_async_engine(
        with_driver(database_url, request.param), poolclass=NullPool
    )
    yield engine
    await engine.dispose()


def plans_by_kind(notices: list[str]) -> dict[str, list[dict[str, Any]]]:
    plans: dict[str, list[dict[str, Any]]] = {}
    for item in explained(notices):
        plans.setdefault(kind_of(item), []).append(item.plan)
    for plan in (plan for kind in plans.values() for plan in kind):
        check_custom(plan)
    return plans


def kind_of(item: Explained) -> str:
    statement = item.statement
    if "audit_transaction" in statement:
        return "transaction"
    if "DISTINCT" in statement:
        return "boundary"
    if "LIMIT" in statement:
        return "children" if "target_id =" in statement else "own"
    if "transaction_id IN" in statement:
        return "stage 2"
    return "get by severity" if "severity =" in statement else "get"


# get


def get_both(query: AuditQuery, session: Session) -> None:
    assert query.get(session, ENTRY_ID, ENTRY_AT) is not None
    assert query.get(session, ENTRY_ID, ENTRY_AT, severity=Sev.LOW) is not None


async def aget_both(query: AuditQuery, session: AsyncSession) -> None:
    assert await query.aget(session, ENTRY_ID, ENTRY_AT) is not None
    assert await query.aget(session, ENTRY_ID, ENTRY_AT, severity=Sev.LOW) is not None


def check_get(notices: list[str]) -> None:
    plans = plans_by_kind(notices)
    assert set(plans) == {"get", "get by severity", "transaction"}
    # Without the severity, one month in each severity; with it, one
    # partition.
    (by_created_at,) = plans["get"]
    assert relations(by_created_at) == FEBRUARY
    (by_severity,) = plans["get by severity"]
    assert relations(by_severity) == {"audit_activity_10_p2026_02"}
    assert len(plans["transaction"]) == 2
    for plan in plans["transaction"]:
        assert relations(plan) == {"audit_transaction_p2026_02"}


@pytest.mark.parametrize("mode", MODES)
def test_get_psycopg(query: AuditQuery, database_url: str, mode: str) -> None:
    notices = sixth_execution(database_url, mode, lambda s: get_both(query, s))

    check_get(notices)


@pytest.mark.parametrize("mode", MODES)
async def test_get_async(
    query: AuditQuery, plan_engine: AsyncEngine, mode: str
) -> None:
    notices = await asixth_execution(plan_engine, mode, lambda s: aget_both(query, s))

    check_get(notices)


# object_history


def history_page(query: AuditQuery, session: Session) -> None:
    page = query.object_history(session, "Board", "1", cursor=CURSOR, limit=LIMIT)
    assert len(page.groups) == LIMIT


async def ahistory_page(query: AuditQuery, session: AsyncSession) -> None:
    page = await query.aobject_history(
        session, "Board", "1", cursor=CURSOR, limit=LIMIT
    )
    assert len(page.groups) == LIMIT


def check_stream(plan: dict[str, Any], index: str) -> None:
    """An ordered read of ``index`` up to the cursor's month, no sort."""
    assert not [node for node in nodes(plan) if node["Node Type"] == "Sort"]
    scans = [node for node in nodes(plan) if "Relation Name" in node]
    assert {node["Relation Name"] for node in scans} == UP_TO_FEBRUARY
    for node in scans:
        assert node["Node Type"] == "Index Scan", node
        assert index in node["Index Name"], node


def check_history(notices: list[str]) -> None:
    plans = plans_by_kind(notices)
    assert set(plans) == {"boundary", "own", "children", "stage 2", "transaction"}
    ((own,), (children,)) = (plans["own"], plans["children"])
    check_stream(own, "object_type_object_id")
    check_stream(children, "target_type_target_id")
    ((stage_two,), (transaction,)) = (plans["stage 2"], plans["transaction"])
    assert relations(stage_two) == FEBRUARY
    assert relations(transaction) == {"audit_transaction_p2026_02"}


@pytest.mark.parametrize("mode", MODES)
def test_history_psycopg(query: AuditQuery, database_url: str, mode: str) -> None:
    notices = sixth_execution(database_url, mode, lambda s: history_page(query, s))

    check_history(notices)


@pytest.mark.parametrize("mode", MODES)
async def test_history_async(
    query: AuditQuery, plan_engine: AsyncEngine, mode: str
) -> None:
    notices = await asixth_execution(
        plan_engine, mode, lambda s: ahistory_page(query, s)
    )

    check_history(notices)
