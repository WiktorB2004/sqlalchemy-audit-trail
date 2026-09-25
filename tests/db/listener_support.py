"""Helpers shared by the session listener tests.

The listener tests run once per session kind: a sync ``Session`` on psycopg,
and an ``AsyncSession`` on asyncpg and on psycopg's async driver. A test body
stays sync code. For an async kind, ``each_session_kind`` runs it in a
greenlet, the way ``AsyncSession`` runs its sync ``Session`` (so the flush and
the listeners run in the greenlet on the async driver, exactly as under
``await session.commit()``), and ``Env.factory`` hands out the
``sync_session`` of new ``AsyncSession`` objects from an
``async_sessionmaker`` the trail is installed on.
"""

from __future__ import annotations

import functools
from collections.abc import AsyncIterator, Callable, Coroutine, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, ParamSpec, Protocol

import pytest
from sqlalchemy import Engine, RowMapping, event, select
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.util import greenlet_spawn

from audit_trail import AuditTrail
from audit_trail.maintenance import ensure_partitions
from audit_trail.migrations import create_audit_tables


class Sev(IntEnum):
    LOW = 10
    HIGH = 40


_P = ParamSpec("_P")

SESSION_KINDS = ["sync", "asyncpg", "psycopg_async"]
"""Parameters of the ``kind`` fixtures."""

_ASYNC_DRIVERS = {"asyncpg": "asyncpg", "psycopg_async": "psycopg"}


@dataclass(frozen=True)
class SessionKind:
    """How a test's sessions talk to the database.

    Attributes:
        name: One of ``SESSION_KINDS``.
        async_engine: The async engine of an ``AsyncSession`` kind, ``None``
            for the sync kind.
    """

    name: str
    async_engine: AsyncEngine | None = None


SYNC = SessionKind("sync")


@asynccontextmanager
async def session_kind(name: str, engine: Engine) -> AsyncIterator[SessionKind]:
    """The ``SessionKind`` called ``name``, with its async engine disposed after.

    Args:
        name: One of ``SESSION_KINDS``.
        engine: The sync test engine, whose database the async engine uses.
    """
    driver = _ASYNC_DRIVERS.get(name)
    if driver is None:
        yield SYNC
        return
    async_engine = create_async_engine(
        engine.url.set(drivername=f"postgresql+{driver}")
    )
    try:
        yield SessionKind(name, async_engine)
    finally:
        await async_engine.dispose()


def each_session_kind(
    test: Callable[_P, None],
) -> Callable[_P, Coroutine[Any, Any, None]]:
    """Run a sync test body the way its session kind runs a flush.

    The kind comes from the test's ``kind`` argument, else from ``env.kind``.
    """

    @functools.wraps(test)
    async def run(*args: _P.args, **kwargs: _P.kwargs) -> None:
        arguments: dict[str, object] = dict(kwargs)
        kind = arguments.get("kind")
        if kind is None:
            env = arguments["env"]
            assert isinstance(env, Env)
            kind = env.kind
        assert isinstance(kind, SessionKind)
        if kind.async_engine is None:
            test(*args, **kwargs)
        else:
            await greenlet_spawn(functools.partial(test, *args, **kwargs))

    return run


def create_trail(
    engine: Engine,
    schema: str,
    *,
    trail_engine: Engine | AsyncEngine | None = None,
    partitions: list[int] | None = None,
    severities: type[IntEnum] = Sev,
    **options: Any,
) -> AuditTrail:
    """Build an ``AuditTrail`` for ``schema`` and create its tables.

    Args:
        engine: Test engine, used to create the tables.
        schema: Schema for the audit tables.
        trail_engine: The ``AuditTrail``'s engine; ``engine`` by default.
        partitions: Severities to create partitions for (all by default);
            ``[]`` creates none, so every audit write fails with 23514.
        severities: The severity enum.
        **options: Further ``AuditTrail`` arguments.
    """
    options.setdefault("events", [])
    trail = AuditTrail(
        engine if trail_engine is None else trail_engine,
        schema=schema,
        severities=severities,
        **options,
    )
    with engine.begin() as conn:
        create_audit_tables(conn, trail.tables, severities)
        values = list(severities) if partitions is None else partitions
        if values:
            ensure_partitions(conn, trail.tables, values, months_ahead=0)
    return trail


class SessionFactory(Protocol):
    """Makes the sessions of a test; ``class_`` is the installed class."""

    class_: type[Session]

    def __call__(self) -> Session: ...


class _AsyncSessions:
    # The sync sessions inside new AsyncSession objects.

    def __init__(self, factory: async_sessionmaker[AsyncSession]) -> None:
        self.factory = factory
        self.class_: type[Session] = factory.kw["sync_session_class"]

    def __call__(self) -> Session:
        return self.factory().sync_session


@dataclass
class Env:
    """An installed trail and the engine and sessions of one session kind.

    Attributes:
        engine: Engine of the sessions (for an async kind, its sync facade,
            usable inside the test's greenlet).
        trail: The installed trail.
        factory: Makes sessions of the installed class.
        kind: The session kind.
    """

    engine: Engine
    trail: AuditTrail
    factory: SessionFactory
    kind: SessionKind = SYNC

    def activities(self) -> list[RowMapping]:
        table = self.trail.tables.activity
        with self.engine.connect() as conn:
            return list(conn.execute(select(table).order_by(table.c.id)).mappings())

    def transactions(self) -> list[RowMapping]:
        table = self.trail.tables.transaction
        with self.engine.connect() as conn:
            return list(conn.execute(select(table).order_by(table.c.id)).mappings())


def make_env(
    engine: Engine, schema: str, kind: SessionKind = SYNC, **options: Any
) -> Env:
    """An ``AuditTrail`` installed on a new session factory of ``kind``.

    For an async kind: an ``async_sessionmaker`` with a new
    ``sync_session_class``, and the trail built on the async engine.
    """
    if kind.async_engine is None:
        trail = create_trail(engine, schema, **options)
        factory = sessionmaker(engine)
        trail.install(factory)
        return Env(engine, trail, factory)
    trail = create_trail(engine, schema, trail_engine=kind.async_engine, **options)
    sync_class = type("AuditedSession", (Session,), {})
    async_factory = async_sessionmaker(kind.async_engine, sync_session_class=sync_class)
    trail.install(async_factory)
    return Env(
        kind.async_engine.sync_engine, trail, _AsyncSessions(async_factory), kind
    )


@dataclass
class StatementLog:
    """Statements executed on an engine while ``recording`` is on."""

    recording: bool = False
    statements: list[str] = field(default_factory=list)


@contextmanager
def record_statements(engine: Engine) -> Iterator[StatementLog]:
    log = StatementLog()

    def before_cursor_execute(
        conn: Any, cursor: Any, statement: str, *args: Any
    ) -> None:
        if log.recording:
            log.statements.append(statement)

    event.listen(engine, "before_cursor_execute", before_cursor_execute)
    try:
        yield log
    finally:
        event.remove(engine, "before_cursor_execute", before_cursor_execute)


def logged_error(caplog: pytest.LogCaptureFixture) -> BaseException | None:
    """The exception logged with the one "durable audit entry was not written"."""
    (record,) = [
        r for r in caplog.records if "durable audit entry was not written" in r.message
    ]
    return None if record.exc_info is None else record.exc_info[1]
