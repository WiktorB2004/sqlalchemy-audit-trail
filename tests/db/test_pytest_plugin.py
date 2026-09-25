"""``audit_trail.pytest_plugin``, run in an inner pytest session."""

from __future__ import annotations

import pytest
from sqlalchemy import Engine, inspect

from tests.conftest import with_driver

pytest_plugins = ["pytester"]

INI = "[pytest]\nasyncio_mode = auto\nasyncio_default_fixture_loop_scope = function\n"

SYNC_CONFTEST = """
import pytest
from sqlalchemy import create_engine

from audit_trail import AuditTrail

pytest_plugins = ["audit_trail.pytest_plugin"]


@pytest.fixture(scope="session")
def audit_trail():
    return AuditTrail(create_engine({url!r}), schema={schema!r}, events=[])
"""

ASYNC_CONFTEST = """
import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from audit_trail import AuditTrail

pytest_plugins = ["audit_trail.pytest_plugin"]


@pytest.fixture(scope="session")
def audit_trail():
    engine = create_async_engine({url!r}{pool})
    return AuditTrail(engine, schema={schema!r}, events=[])
"""

# test_a writes an entry; test_b sees an empty log only if audit_clean
# emptied it. Both need the current month's partition.
SYNC_TESTS = """
from sqlalchemy import func, insert

from audit_trail.testing import assert_audited, assert_not_audited


def write(audit):
    with audit.engine.begin() as conn:
        conn.execute(
            insert(audit.tables.activity).values(
                transaction_id=1,
                verb="plugin_test.viewed",
                severity=min(audit.severities),
                created_at=func.now(),
            )
        )


def test_a(audit_clean):
    write(audit_clean)
    assert_audited(audit_clean, audit_clean.engine, verb="plugin_test.viewed")


def test_b(audit_clean):
    assert_not_audited(audit_clean, audit_clean.engine)
"""

ASYNC_TESTS = """
from sqlalchemy import func, insert

from audit_trail.testing import aassert_audited, aassert_not_audited


async def test_a(audit_clean):
    async with audit_clean.engine.begin() as conn:
        await conn.execute(
            insert(audit_clean.tables.activity).values(
                transaction_id=1,
                verb="plugin_test.viewed",
                severity=min(audit_clean.severities),
                created_at=func.now(),
            )
        )
    await aassert_audited(audit_clean, audit_clean.engine, verb="plugin_test.viewed")


async def test_b(audit_clean):
    await aassert_not_audited(audit_clean, audit_clean.engine)
"""


def test_fixtures_create_clear_and_drop_the_tables(
    pytester: pytest.Pytester, engine: Engine, database_url: str, schema: str
) -> None:
    pytester.makeini(INI)
    pytester.makeconftest(SYNC_CONFTEST.format(url=database_url, schema=schema))
    pytester.makepyfile(SYNC_TESTS)

    result = pytester.runpytest("-p", "no:cacheprovider")

    result.assert_outcomes(passed=2)
    assert inspect(engine).get_table_names(schema=schema) == []


@pytest.mark.parametrize(
    ("pool", "loop_scope"),
    [
        # Each test in its own event loop: pooled connections cannot be shared.
        (", poolclass=NullPool", "function"),
        # One loop for all tests: the fixtures must not leave connections of
        # their own loop in the pool.
        ("", "session"),
    ],
)
def test_fixtures_with_an_async_engine(
    pytester: pytest.Pytester,
    engine: Engine,
    database_url: str,
    schema: str,
    pool: str,
    loop_scope: str,
) -> None:
    url = with_driver(database_url, "asyncpg")
    pytester.makeini(f"{INI}asyncio_default_test_loop_scope = {loop_scope}\n")
    pytester.makeconftest(ASYNC_CONFTEST.format(url=url, schema=schema, pool=pool))
    pytester.makepyfile(ASYNC_TESTS)

    # In a subprocess: asyncpg hung connecting in a second in-process session.
    result = pytester.runpytest_subprocess("-p", "no:cacheprovider")

    result.assert_outcomes(passed=2)
    assert inspect(engine).get_table_names(schema=schema) == []


def test_audit_trail_must_be_overridden(pytester: pytest.Pytester) -> None:
    pytester.makeini(INI)
    pytester.makeconftest('pytest_plugins = ["audit_trail.pytest_plugin"]\n')
    pytester.makepyfile("def test_x(audit_clean):\n    pass\n")

    result = pytester.runpytest("-p", "no:cacheprovider")

    result.assert_outcomes(errors=1)
    result.stdout.fnmatch_lines(
        [
            (
                "*override the audit_trail fixture in your conftest.py"
                ' (scope="session") to return your AuditTrail*'
            )
        ]
    )
