"""Query plans of ``list_groups`` on the sixth execution of each statement.

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
    asixth_execution,
    check_custom,
    explained,
    nodes,
    relations,
    require_superuser,
    sixth_execution,
)

# Two rows (LOW and HIGH) per transaction, one transaction a minute going
# back from the 20th of January to April 2026.
MONTHS = ["2026_01", "2026_02", "2026_03", "2026_04"]
PER_MONTH = 2000
CURSOR = Cursor(datetime(2026, 2, 20, tzinfo=timezone.utc) - timedelta(minutes=100), 0)
LIMIT = 5


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
    for statement, plan in explained(notices):
        if "audit_transaction" in statement:
            kind = "transaction"
        elif "DISTINCT" in statement:
            kind = "boundary"
        elif "LIMIT" in statement:
            kind = "stage 1"
        else:
            kind = "stage 2"
        assert kind not in plans, statement
        plans[kind] = plan
    return plans


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
    notices = sixth_execution(
        database_url, mode, lambda session: list_page(query, session)
    )

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


@pytest.mark.parametrize("mode", MODES)
async def test_sixth_execution_async(
    query: AuditQuery, plan_engine: AsyncEngine, mode: str
) -> None:
    notices = await asixth_execution(
        plan_engine, mode, lambda session: alist_page(query, session)
    )

    check_plans(notices)
