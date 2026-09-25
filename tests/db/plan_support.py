"""Capture the plans PostgreSQL ran, on the sixth execution of each statement.

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
from collections.abc import Awaitable, Callable, Iterator
from typing import Any, NamedTuple

import pytest
from sqlalchemy import Connection, create_engine, text
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
)
from sqlalchemy.orm import Session
from sqlalchemy.pool import NullPool

EXPLAIN_SETTINGS = [
    "LOAD 'auto_explain'",
    "SET auto_explain.log_min_duration = 0",
    "SET auto_explain.log_analyze = on",
    "SET auto_explain.log_format = json",
    "SET auto_explain.log_level = notice",
]

# The session's own plan_cache_mode: "auto" is the server default; with
# "force_generic_plan" every execution is generic unless the query overrides
# it.
MODES = ["auto", "force_generic_plan"]

EXECUTIONS = 6


class Explained(NamedTuple):
    """One statement and the plan it ran with."""

    statement: str
    plan: dict[str, Any]


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


def explained(notices: list[str]) -> list[Explained]:
    """The plans among the auto_explain notices, in execution order."""
    result: list[Explained] = []
    for notice in notices:
        if "{" not in notice:
            continue
        document = json.loads(notice[notice.index("{") :])
        result.append(Explained(document["Query Text"], document["Plan"]))
    return result


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


def sixth_execution(
    database_url: str, mode: str, run: Callable[[Session], object]
) -> list[str]:
    """Notices of the sixth ``run`` on one psycopg connection."""
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
            for _ in range(EXECUTIONS):
                notices.clear()
                with Session(conn) as session:
                    run(session)
                conn.rollback()
    finally:
        engine.dispose()
    return notices


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


async def asixth_execution(
    engine: AsyncEngine, mode: str, run: Callable[[AsyncSession], Awaitable[object]]
) -> list[str]:
    """Notices of the sixth ``run`` on one async connection.

    ``engine`` must not pool connections: auto_explain must not leak to other
    tests.
    """
    notices: list[str] = []
    async with engine.connect() as conn:
        await notice_listener(conn, notices)
        for setting in [*EXPLAIN_SETTINGS, f"SET plan_cache_mode = {mode}"]:
            await conn.execute(text(setting))
        await conn.commit()
        for _ in range(EXECUTIONS):
            notices.clear()
            async with AsyncSession(conn) as session:
                await run(session)
            await conn.rollback()
    return notices
