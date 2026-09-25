"""Query plans of ``list_groups`` on the sixth execution of each statement.

Drivers prepare statements (asyncpg always, psycopg from the sixth
execution), and PostgreSQL may then switch to a generic plan that no longer
prunes partitions at plan time. The plans are the ones the server actually
ran, reported by ``auto_explain`` as notices on the test's own connection.
``auto_explain`` needs a superuser; without one the tests skip, except in CI
(``AUDIT_TEST_EXPECT_PG`` set), where they fail.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncIterator, Callable, Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import Connection, Engine, create_engine, text
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    create_async_engine,
)
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

from audit_trail.maintenance import ensure_partitions
from audit_trail.query import AuditQuery, Cursor
from tests.conftest import with_driver
from tests.db.listener_support import Sev, create_trail

# Two rows (LOW and HIGH) per transaction, one transaction a minute going
# back from the 20th of January to April 2026.
MONTHS = ["2026_01", "2026_02", "2026_03", "2026_04"]
PER_MONTH = 2000
CURSOR = Cursor(datetime(2026, 2, 20, tzinfo=timezone.utc) - timedelta(minutes=100), 0)
LIMIT = 5

EXPLAIN_SETTINGS = [
    "LOAD 'auto_explain'",
    "SET auto_explain.log_min_duration = 0",
    "SET auto_explain.log_analyze = on",
    "SET auto_explain.log_format = json",
    "SET auto_explain.log_level = notice",
]

# The session's own plan_cache_mode: "auto" is the server default; with
# "force_generic_plan" every execution is generic unless list_groups
# overrides it.
MODES = ["auto", "force_generic_plan"]


def require_superuser(conn: Connection) -> None:
    superuser: bool = conn.execute(
        text("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
    ).scalar_one()
    if superuser:
        return
    reason = "auto_explain needs a superuser"
    if os.environ.get("AUDIT_TEST_EXPECT_PG"):
        pytest.fail(reason)
    pytest.skip(reason)


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
            months_ahead=len(MONTHS) - 1,
            now=datetime(2026, 1, 15, tzinfo=timezone.utc),
        )
        months = ", ".join(
            f"({index}, timestamptz '2026-{index:02d}-20 00:00+00')"
            for index in range(1, len(MONTHS) + 1)
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
        conn.execute(
            text(
                f'INSERT INTO "{schema}".audit_activity '
                "(transaction_id, verb, severity, created_at, data) "
                "SELECT m.n * 100000 + g, 'shop.x', s.severity, "
                "m.ts - g * interval '1 minute', '{\"v\": 1, \"payload\": {}}' "
                + source
                + ", (VALUES (10), (40)) s(severity)"
            )
        )
        conn.execute(text(f'ANALYZE "{schema}".audit_activity'))
        conn.execute(text(f'ANALYZE "{schema}".audit_transaction'))
    return trail.query


def list_page(query: AuditQuery, session: Session) -> None:
    page = query.list_groups(session, severities={Sev.HIGH}, cursor=CURSOR, limit=LIMIT)
    assert len(page.groups) == LIMIT


async def alist_page(query: AuditQuery, session: AsyncSession) -> None:
    page = await query.alist_groups(
        session, severities={Sev.HIGH}, cursor=CURSOR, limit=LIMIT
    )
    assert len(page.groups) == LIMIT


def plans_of(notices: list[str]) -> dict[str, dict[str, Any]]:
    """Plans of the auto_explain notices, keyed by statement kind."""
    plans: dict[str, dict[str, Any]] = {}
    for notice in notices:
        if "{" not in notice:
            continue
        explained = json.loads(notice[notice.index("{") :])
        statement: str = explained["Query Text"]
        if "audit_transaction" in statement:
            kind = "transaction"
        elif "DISTINCT" in statement:
            kind = "boundary"
        elif "LIMIT" in statement:
            kind = "stage 1"
        else:
            kind = "stage 2"
        assert kind not in plans, statement
        plans[kind] = explained["Plan"]
    return plans


def nodes(plan: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield plan
    for child in plan.get("Plans", []):
        yield from nodes(child)


def relations(plan: dict[str, Any]) -> set[str]:
    return {node["Relation Name"] for node in nodes(plan) if "Relation Name" in node}


def check_custom(plan: dict[str, Any]) -> None:
    """A custom plan: pruned at plan time, no parameters left."""
    for node in nodes(plan):
        assert node.get("Subplans Removed", 0) == 0, node
        for key in ("Index Cond", "Filter", "Recheck Cond"):
            assert "$" not in node.get(key, ""), node


def check_plans(notices: list[str]) -> None:
    plans = plans_of(notices)
    assert set(plans) == {"boundary", "stage 1", "stage 2", "transaction"}
    for plan in plans.values():
        check_custom(plan)

    # Single severity: an ordered Append over the months up to the cursor,
    # stopping in the cursor's month.
    stage_one = plans["stage 1"]
    assert stage_one["Node Type"] == "Limit"
    (append,) = stage_one["Plans"]
    assert append["Node Type"] == "Append"
    assert not [node for node in nodes(stage_one) if node["Node Type"] == "Sort"]
    scans = {node["Relation Name"]: node for node in append["Plans"]}
    assert set(scans) == {"audit_activity_40_p2026_02", "audit_activity_40_p2026_01"}
    assert scans["audit_activity_40_p2026_02"]["Actual Loops"] == 1
    assert scans["audit_activity_40_p2026_01"]["Actual Loops"] == 0

    # Stage 2: the page's month only, every severity.
    assert relations(plans["stage 2"]) == {
        "audit_activity_10_p2026_02",
        "audit_activity_40_p2026_02",
    }
    assert relations(plans["transaction"]) == {"audit_transaction_p2026_02"}


@pytest.mark.parametrize("mode", MODES)
def test_sixth_execution_psycopg(
    query: AuditQuery, database_url: str, mode: str
) -> None:
    engine = create_engine(database_url, poolclass=NullPool)
    notices: list[str] = []
    try:
        with engine.connect() as conn:
            driver: Any = conn.connection.dbapi_connection
            driver.add_notice_handler(
                lambda diagnostic: notices.append(diagnostic.message_primary)
            )
            for setting in [*EXPLAIN_SETTINGS, f"SET plan_cache_mode = {mode}"]:
                conn.execute(text(setting))
            conn.commit()
            for _ in range(6):
                notices.clear()
                with Session(conn) as session:
                    list_page(query, session)
                conn.rollback()
    finally:
        engine.dispose()

    check_plans(notices)


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


async def notice_listener(conn: AsyncConnection, notices: list[str]) -> None:
    raw = await conn.get_raw_connection()
    driver: Any = raw.driver_connection
    record: Callable[..., None]
    if conn.dialect.driver == "asyncpg":

        def record(_: Any, message: Any) -> None:
            notices.append(message.message)

        driver.add_log_listener(record)
    else:

        def record(diagnostic: Any) -> None:
            notices.append(diagnostic.message_primary)

        driver.add_notice_handler(record)


@pytest.mark.parametrize("mode", MODES)
async def test_sixth_execution_async(
    query: AuditQuery, plan_engine: AsyncEngine, mode: str
) -> None:
    notices: list[str] = []
    async with plan_engine.connect() as conn:
        await notice_listener(conn, notices)
        for setting in [*EXPLAIN_SETTINGS, f"SET plan_cache_mode = {mode}"]:
            await conn.execute(text(setting))
        await conn.commit()
        for _ in range(6):
            notices.clear()
            async with AsyncSession(conn) as session:
                await alist_page(query, session)
            await conn.rollback()

    check_plans(notices)
