"""The test environment is the one the CI matrix asked for.

``AUDIT_TEST_EXPECT_PG`` (major version) and ``AUDIT_TEST_EXPECT_SA``
(``major.minor``) are set per matrix cell. Without them only connectivity is
checked. With ``AUDIT_TEST_EXPECT_PG`` the server must also allow prepared
transactions, so the tests that need them are not skipped in CI.
"""

from __future__ import annotations

import os

import sqlalchemy
from sqlalchemy import Engine, text
from sqlalchemy.ext.asyncio import AsyncEngine


def _check_server_version(server_version_num: int) -> None:
    expected = os.environ.get("AUDIT_TEST_EXPECT_PG")
    if expected:
        assert server_version_num // 10000 == int(expected)


def test_sync_connection(engine: Engine) -> None:
    with engine.connect() as conn:
        num: str = conn.execute(text("SHOW server_version_num")).scalar_one()
    _check_server_version(int(num))


async def test_async_connection(async_engine: AsyncEngine) -> None:
    async with async_engine.connect() as conn:
        num: str = (await conn.execute(text("SHOW server_version_num"))).scalar_one()
    _check_server_version(int(num))


def test_sqlalchemy_version() -> None:
    expected = os.environ.get("AUDIT_TEST_EXPECT_SA")
    if expected:
        assert sqlalchemy.__version__.startswith(expected + ".")


def test_prepared_transactions_are_enabled(engine: Engine) -> None:
    if not os.environ.get("AUDIT_TEST_EXPECT_PG"):
        return
    with engine.connect() as conn:
        allowed: str = conn.execute(text("SHOW max_prepared_transactions")).scalar_one()
    assert int(allowed) > 0
