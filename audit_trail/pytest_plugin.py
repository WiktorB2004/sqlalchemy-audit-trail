"""pytest fixtures for the audit tables of a test database.

For test databases whose migrations do not create the audit tables. Enable
the plugin in the root ``conftest.py`` and override ``audit_trail`` there,
session-scoped, to return the application's ``AuditTrail``; its engine must
point at the test database::

    pytest_plugins = ["audit_trail.pytest_plugin"]

    @pytest.fixture(scope="session")
    def audit_trail() -> AuditTrail:
        return AuditTrail(test_engine, schema="audit")

Fixtures:

- ``audit_tables`` (session): creates the audit tables and the partitions of
  the current and the next month, and drops the tables at the end.
- ``audit_clean`` (function): empties the tables before the test.

Both return the ``AuditTrail``. With an ``AsyncEngine`` they run in an event
loop of their own, on a copy of the engine's pool that is closed afterwards:
the pool the tests use is not touched, whatever event loop its connections
belong to.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from functools import partial

import pytest
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from audit_trail.config import AuditTrail
from audit_trail.testing import (
    clear_audit_entries,
    create_test_tables,
    drop_test_tables,
)

__all__ = ["audit_clean", "audit_tables", "audit_trail"]


@pytest.fixture(scope="session")
def audit_trail() -> AuditTrail:
    """The application's ``AuditTrail``; override it in ``conftest.py``."""
    pytest.fail(
        "override the audit_trail fixture in your conftest.py "
        '(scope="session") to return your AuditTrail',
        pytrace=False,
    )


@pytest.fixture(scope="session")
def audit_tables(audit_trail: AuditTrail) -> Iterator[AuditTrail]:
    """Create the audit tables and partitions; drop the tables afterwards."""
    _run(audit_trail, partial(create_test_tables, audit_trail))
    yield audit_trail
    _run(audit_trail, partial(drop_test_tables, audit_trail))


@pytest.fixture
def audit_clean(audit_tables: AuditTrail) -> AuditTrail:
    """``audit_tables``, emptied before the test."""
    _run(audit_tables, partial(clear_audit_entries, audit_tables))
    return audit_tables


def _run(audit: AuditTrail, work: Callable[[Connection], None]) -> None:
    engine = audit.engine
    if isinstance(engine, AsyncEngine):
        asyncio.run(_arun(engine, work))
        return
    with engine.begin() as connection:
        work(connection)


async def _arun(engine: AsyncEngine, work: Callable[[Connection], None]) -> None:
    """Run ``work`` in a transaction on a private copy of ``engine``.

    Connections are bound to the event loop that opened them, so this loop
    gets an engine of its own, disposed afterwards; the pool of ``engine`` is
    not touched. Only the URL and the pool settings (including the connection
    arguments) carry over, not dialect options such as a JSON serializer;
    that is enough for DDL and ``TRUNCATE``.
    """
    private = create_async_engine(engine.url, pool=engine.sync_engine.pool.recreate())
    try:
        async with private.begin() as connection:
            await connection.run_sync(work)
    finally:
        await private.dispose()
