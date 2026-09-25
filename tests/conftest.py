"""Shared fixtures.

Tests under ``tests/db`` get the ``db`` marker and need PostgreSQL. They use
``AUDIT_TEST_DATABASE_URL`` when it is set (CI does this with a service
container); otherwise a throwaway container is started with testcontainers.
``AUDIT_TEST_PG_IMAGE`` picks its image (default ``postgres:18``).
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

DB_TESTS = Path(__file__).parent / "db"


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if DB_TESTS in Path(str(item.path)).parents:
            item.add_marker(pytest.mark.db)


def with_driver(url: str, driver: str) -> str:
    """Return ``url`` with its driver replaced, e.g. ``psycopg`` -> ``asyncpg``."""
    return (
        make_url(url)
        .set(drivername=f"postgresql+{driver}")
        .render_as_string(hide_password=False)
    )


@pytest.fixture(scope="session")
def database_url() -> Iterator[str]:
    """Sync (psycopg) URL of the test database."""
    url = os.environ.get("AUDIT_TEST_DATABASE_URL")
    if url:
        yield with_driver(url, "psycopg")
        return

    from testcontainers.community.postgres import PostgresContainer

    image = os.environ.get("AUDIT_TEST_PG_IMAGE", "postgres:18")
    with PostgresContainer(image, driver="psycopg") as pg:
        yield pg.get_connection_url()


@pytest.fixture(scope="session")
def engine(database_url: str) -> Iterator[Engine]:
    eng = create_engine(database_url)
    yield eng
    eng.dispose()


@pytest.fixture
def schema(engine: Engine) -> Iterator[str]:
    """A fresh, empty schema, dropped after the test."""
    name = f"test_{uuid.uuid4().hex[:12]}"
    with engine.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{name}"'))
    yield name
    with engine.begin() as conn:
        conn.execute(text(f'DROP SCHEMA "{name}" CASCADE'))


@pytest.fixture(params=["asyncpg", "psycopg"])
async def async_engine(
    request: pytest.FixtureRequest, database_url: str
) -> AsyncIterator[AsyncEngine]:
    """Async engine, once per async driver."""
    eng = create_async_engine(with_driver(database_url, request.param))
    yield eng
    await eng.dispose()
