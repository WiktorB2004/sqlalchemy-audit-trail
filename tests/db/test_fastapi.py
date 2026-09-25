"""The FastAPI integration end to end: an app served through httpx.

Requests go through ``AuditMiddleware``, open their session with
``session_dependency`` and set the actor from a synchronous dependency, which
FastAPI runs in its thread pool, after the session was opened.
"""

from __future__ import annotations

import asyncio
import threading
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI
from sqlalchemy import Engine, MetaData, RowMapping, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from audit_trail import Actor, Audited, AuditEvent, AuditTrail, Severity, event
from audit_trail.integrations.fastapi import (
    AuditMiddleware,
    context_provider,
    session_dependency,
    session_provider,
    set_actor,
)
from tests.db.listener_support import create_trail

CAP = 15
"""Seconds after which a test that should not block fails instead of hanging."""

PROXY = "10.0.0.5"
CLIENT = "198.51.100.4"
REQUEST_ID = uuid.UUID("5d0c4c8e-5f55-4a55-a1bb-1f3c2b6e7a90")


class ItemEvent(AuditEvent):
    VIEWED = event("fastapi_test.viewed", Severity.INFO)


@pytest.fixture
def item_model(engine: Engine, schema: str) -> Any:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    class Item(Base, Audited):
        __tablename__ = "item"
        id: Mapped[int] = mapped_column(primary_key=True)
        title: Mapped[str] = mapped_column(default="")

    Base.metadata.create_all(engine)
    return Item


@dataclass
class Rows:
    engine: Engine
    trail: AuditTrail

    def transactions(self) -> list[RowMapping]:
        table = self.trail.tables.transaction
        with self.engine.connect() as conn:
            return list(conn.execute(select(table).order_by(table.c.id)).mappings())

    def activities(self) -> list[RowMapping]:
        table = self.trail.tables.activity
        with self.engine.connect() as conn:
            return list(conn.execute(select(table).order_by(table.c.id)).mappings())


@pytest.fixture
def sync_trail(engine: Engine, schema: str) -> Iterator[AuditTrail]:
    trail = create_trail(engine, schema, context_provider=context_provider)
    yield trail
    trail.dispose()


def client_for(app: FastAPI, peer: str = PROXY) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app, client=(peer, 40000))
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


def proxied_headers(**extra: str) -> dict[str, str]:
    return {
        "User-Agent": "pytest-agent/1",
        "X-Forwarded-For": CLIENT,
        "X-Request-ID": str(REQUEST_ID),
        **extra,
    }


def authenticate(user_id: str = "42") -> None:
    # Runs in the thread pool, after the session dependency.
    set_actor(Actor("user", user_id, f"{user_id}@example.com"), auth_method="bearer")


def assert_request_context(rows: Rows) -> None:
    (transaction,) = rows.transactions()
    assert str(transaction["remote_addr"]) == CLIENT
    assert transaction["user_agent"] == "pytest-agent/1"
    assert (transaction["method"], transaction["path"]) == ("POST", "/items")
    assert transaction["channel"] == "api"
    assert transaction["request_id"] == REQUEST_ID
    assert (transaction["actor_type"], transaction["actor_id"]) == ("user", "42")
    assert transaction["actor_label"] == "42@example.com"
    assert transaction["auth_method"] == "bearer"

    (activity,) = rows.activities()
    assert activity["actor_id"] == "42"
    snapshot = activity["data"]["context"]
    assert snapshot["remote_addr"] == CLIENT
    assert snapshot["user_agent"] == "pytest-agent/1"
    assert snapshot["path"] == "/items"
    assert snapshot["request_id"] == str(REQUEST_ID)
    assert snapshot["actor_label"] == "42@example.com"


async def test_sync_session_entry_has_the_request_context_and_actor(
    engine: Engine, sync_trail: AuditTrail, item_model: Any
) -> None:
    factory = sessionmaker(engine)
    sync_trail.install(factory)
    get_session = session_dependency(factory)
    session_dep = Depends(get_session)

    def auth(session: Session = session_dep) -> None:
        authenticate()

    app = FastAPI()
    app.add_middleware(AuditMiddleware, trusted_proxies=[PROXY])

    @app.post("/items", dependencies=[Depends(auth)])
    def create(session: Session = session_dep) -> dict[str, bool]:
        session.add(item_model(title="a"))
        session.commit()
        return {"provided": session_provider() is session}

    async with client_for(app) as client:
        response = await client.post("/items", headers=proxied_headers())

    assert response.json() == {"provided": True}
    assert_request_context(Rows(engine, sync_trail))


async def test_async_session_entry_has_the_request_context_and_actor(
    engine: Engine, schema: str, async_engine: AsyncEngine, item_model: Any
) -> None:
    trail = create_trail(engine, schema, trail_engine=async_engine)
    sync_class = type("FastAPISession", (Session,), {})
    factory = async_sessionmaker(async_engine, sync_session_class=sync_class)
    trail.install(factory)
    get_session = session_dependency(factory)
    session_dep = Depends(get_session)

    def auth(session: AsyncSession = session_dep) -> None:
        authenticate()

    app = FastAPI()
    app.add_middleware(AuditMiddleware, trusted_proxies=[PROXY])

    @app.post("/items", dependencies=[Depends(auth)])
    async def create(session: AsyncSession = session_dep) -> dict[str, bool]:
        session.add(item_model(title="a"))
        await session.commit()
        return {"provided": session_provider() is session}

    try:
        async with client_for(app) as client:
            response = await client.post("/items", headers=proxied_headers())
    finally:
        await trail.adispose()

    assert response.json() == {"provided": True}
    assert_request_context(Rows(engine, trail))


async def test_sync_endpoint_logs_without_a_session(
    engine: Engine, schema: str
) -> None:
    trail = create_trail(
        engine,
        schema,
        severities=Severity,
        events=[ItemEvent],
        session_provider=session_provider,
    )
    factory = sessionmaker(engine)
    trail.install(factory)
    session_dep = Depends(session_dependency(factory))

    def auth(session: Session = session_dep) -> None:
        authenticate()

    def record_view() -> None:
        # Code that has no session at hand.
        trail.log(ItemEvent.VIEWED)

    app = FastAPI()
    app.add_middleware(AuditMiddleware, trusted_proxies=[PROXY])

    @app.post("/items", dependencies=[Depends(auth)])
    def view(session: Session = session_dep) -> None:
        record_view()
        session.commit()

    try:
        async with client_for(app) as client:
            response = await client.post("/items", headers=proxied_headers())
    finally:
        trail.dispose()

    assert response.status_code == 200
    rows = Rows(engine, trail)
    assert [row["verb"] for row in rows.activities()] == ["fastapi_test.viewed"]
    assert_request_context(rows)


async def test_async_endpoint_logs_without_a_session(
    engine: Engine, schema: str, async_engine: AsyncEngine
) -> None:
    trail = create_trail(
        engine,
        schema,
        trail_engine=async_engine,
        severities=Severity,
        events=[ItemEvent],
        session_provider=session_provider,
    )
    sync_class = type("FastAPISession", (Session,), {})
    factory = async_sessionmaker(async_engine, sync_session_class=sync_class)
    trail.install(factory)
    session_dep = Depends(session_dependency(factory))

    def auth(session: AsyncSession = session_dep) -> None:
        authenticate()

    async def record_view() -> None:
        await trail.alog(ItemEvent.VIEWED)

    app = FastAPI()
    app.add_middleware(AuditMiddleware, trusted_proxies=[PROXY])

    @app.post("/items", dependencies=[Depends(auth)])
    async def view(session: AsyncSession = session_dep) -> None:
        await record_view()
        await session.commit()

    try:
        async with client_for(app) as client:
            response = await client.post("/items", headers=proxied_headers())
    finally:
        await trail.adispose()

    assert response.status_code == 200
    rows = Rows(engine, trail)
    assert [row["verb"] for row in rows.activities()] == ["fastapi_test.viewed"]
    assert_request_context(rows)


async def test_the_dependency_does_not_commit(
    engine: Engine, sync_trail: AuditTrail, item_model: Any
) -> None:
    factory = sessionmaker(engine)
    sync_trail.install(factory)
    get_session = session_dependency(factory)
    session_dep = Depends(get_session)
    app = FastAPI()
    app.add_middleware(AuditMiddleware)

    @app.post("/items")
    def create(session: Session = session_dep) -> None:
        session.add(item_model(title="dropped"))
        session.flush()

    async with client_for(app) as client:
        await client.post("/items")

    rows = Rows(engine, sync_trail)
    assert rows.transactions() == []
    with factory() as session:
        assert session.scalars(select(item_model)).all() == []


async def test_nested_context_wins_over_the_provider(
    engine: Engine, sync_trail: AuditTrail, item_model: Any
) -> None:
    factory = sessionmaker(engine)
    sync_trail.install(factory)
    get_session = session_dependency(factory)
    session_dep = Depends(get_session)
    app = FastAPI()
    app.add_middleware(AuditMiddleware)

    def auth(session: Session = session_dep) -> None:
        authenticate()

    @app.post("/items", dependencies=[Depends(auth)])
    def create(session: Session = session_dep) -> None:
        with sync_trail.context(actor_type="system", channel="worker"):
            session.add(item_model(title="nested"))
            session.commit()

    async with client_for(app) as client:
        await client.post("/items")

    (transaction,) = Rows(engine, sync_trail).transactions()
    assert (transaction["actor_type"], transaction["actor_id"]) == ("system", None)
    assert transaction["channel"] == "worker"
    assert transaction["path"] is None


@pytest.fixture
async def concurrent_app(
    engine: Engine, sync_trail: AuditTrail, item_model: Any
) -> FastAPI:
    factory = sessionmaker(engine)
    sync_trail.install(factory)
    get_session = session_dependency(factory)
    session_dep = Depends(get_session)
    # Both requests hold an open session and have set their actor before
    # either flushes.
    barrier = threading.Barrier(2, timeout=CAP)

    def auth(user: str, session: Session = session_dep) -> None:
        authenticate(user)

    app = FastAPI()
    app.add_middleware(AuditMiddleware)

    @app.post("/items", dependencies=[Depends(auth)])
    def create(user: str, session: Session = session_dep) -> None:
        barrier.wait()
        session.add(item_model(title=user))
        session.commit()

    return app


async def test_concurrent_requests_do_not_mix_contexts(
    engine: Engine, sync_trail: AuditTrail, concurrent_app: FastAPI
) -> None:
    async with client_for(concurrent_app, peer="203.0.113.7") as client:
        responses = await asyncio.wait_for(
            asyncio.gather(
                *(
                    client.post(
                        "/items", params={"user": user}, headers={"User-Agent": user}
                    )
                    for user in ("ann", "bob")
                )
            ),
            CAP,
        )
    assert [r.status_code for r in responses] == [200, 200]

    rows = Rows(engine, sync_trail)
    transactions = {row["id"]: row for row in rows.transactions()}
    assert sorted(row["actor_id"] for row in transactions.values()) == ["ann", "bob"]
    for row in transactions.values():
        assert row["user_agent"] == row["actor_id"]
    assert len({row["request_id"] for row in transactions.values()}) == 2
    activities = rows.activities()
    assert len(activities) == 2
    for activity in activities:
        owner = transactions[activity["transaction_id"]]
        assert activity["actor_id"] == owner["actor_id"]
        assert activity["data"]["changes"]["title"][1] == owner["actor_id"]
        assert activity["data"]["context"]["request_id"] == str(owner["request_id"])
