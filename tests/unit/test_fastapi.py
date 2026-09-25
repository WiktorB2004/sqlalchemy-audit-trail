"""``AuditMiddleware`` and the FastAPI helpers, without a database."""

from __future__ import annotations

import asyncio
import subprocess
import sys
import uuid
from typing import NamedTuple

import pytest
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import Session, sessionmaker
from starlette.types import Message, Receive, Scope, Send

from audit_trail import Actor, AuditTrail
from audit_trail.context import AuditContext, _current, context, current_context
from audit_trail.integrations.fastapi import (
    AuditMiddleware,
    context_provider,
    request_context,
    session_dependency,
    session_provider,
    set_actor,
)

REQUEST_ID = uuid.UUID("0b7c5a52-8f7e-4b43-9f0e-3a3c6f1d2e10")
PROXY = "10.0.0.5"


class Seen(NamedTuple):
    """What the wrapped application saw."""

    active: AuditContext | None
    request: AuditContext | None


class Recorder:
    """ASGI application that records the contexts it runs in."""

    def __init__(self) -> None:
        self.seen: list[Seen] = []

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        self.seen.append(Seen(current_context(), request_context()))

    @property
    def context(self) -> AuditContext:
        (seen,) = self.seen
        assert seen.active is not None
        return seen.active


async def _receive() -> Message:
    return {"type": "http.request", "body": b""}


async def _send(message: Message) -> None:
    pass


def http_scope(
    *,
    client: tuple[str, int] | None = ("203.0.113.7", 5000),
    headers: list[tuple[str, str]] | None = None,
    kind: str = "http",
) -> Scope:
    scope: Scope = {
        "type": kind,
        "path": "/items/1",
        "query_string": b"token=secret",
        "headers": [
            (name.lower().encode(), value.encode()) for name, value in headers or []
        ],
        "client": client,
    }
    if kind == "http":
        scope["method"] = "POST"
    return scope


def run(middleware: AuditMiddleware, scope: Scope) -> None:
    asyncio.run(middleware(scope, _receive, _send))


def seen_context(scope: Scope, **options: object) -> AuditContext:
    app = Recorder()
    run(AuditMiddleware(app, **options), scope)  # type: ignore[arg-type]
    return app.context


# Network part of the context


def test_sets_the_network_part_of_the_context() -> None:
    ctx = seen_context(http_scope(headers=[("User-Agent", "curl/8")]))

    assert ctx.remote_addr == "203.0.113.7"
    assert ctx.user_agent == "curl/8"
    assert (ctx.method, ctx.path) == ("POST", "/items/1")
    assert ctx.channel == "api"
    assert ctx.actor_type == "anonymous"
    assert isinstance(ctx.request_id, uuid.UUID)
    assert ctx.correlation_id == ctx.request_id


def test_channel_is_configurable() -> None:
    assert seen_context(http_scope(), channel="admin").channel == "admin"


def test_invalid_or_missing_peer_is_stored_as_none() -> None:
    assert seen_context(http_scope(client=("testclient", 50000))).remote_addr is None
    assert seen_context(http_scope(client=None)).remote_addr is None


def test_websocket_has_no_method() -> None:
    ctx = seen_context(http_scope(kind="websocket"))
    assert ctx.method is None
    assert ctx.path == "/items/1"


def test_lifespan_passes_through() -> None:
    app = Recorder()
    run(AuditMiddleware(app), {"type": "lifespan"})
    assert app.seen == [Seen(None, None)]


def test_request_context_is_the_active_one_and_is_reset_after() -> None:
    app = Recorder()
    after: list[tuple[AuditContext | None, AuditContext | None]] = []

    async def main() -> None:
        # Same task as the middleware, so a missing reset would show here.
        await AuditMiddleware(app)(http_scope(), _receive, _send)
        after.append((current_context(), request_context()))

    asyncio.run(main())
    (seen,) = app.seen
    assert seen.request is seen.active is not None
    assert after == [(None, None)]


def test_concurrent_requests_get_their_own_context() -> None:
    both_in = [asyncio.Event(), asyncio.Event()]
    seen: dict[str, AuditContext | None] = {}

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        agent = dict(scope["headers"])[b"user-agent"].decode()
        both_in[int(agent)].set()
        await asyncio.gather(*(event.wait() for event in both_in))
        seen[agent] = request_context()

    middleware = AuditMiddleware(app)

    async def main() -> None:
        await asyncio.wait_for(
            asyncio.gather(
                *(
                    middleware(
                        http_scope(headers=[("User-Agent", str(i))]), _receive, _send
                    )
                    for i in range(2)
                )
            ),
            10,
        )

    asyncio.run(main())
    first, second = seen["0"], seen["1"]
    assert first is not None
    assert second is not None
    assert (first.user_agent, second.user_agent) == ("0", "1")
    assert first.request_id != second.request_id


# Trusted proxies


def test_forwarded_for_is_ignored_without_trusted_proxies() -> None:
    scope = http_scope(client=(PROXY, 1), headers=[("X-Forwarded-For", "1.2.3.4")])
    assert seen_context(scope).remote_addr == PROXY


def test_forwarded_for_is_ignored_from_an_untrusted_peer() -> None:
    scope = http_scope(headers=[("X-Forwarded-For", "1.2.3.4")])
    ctx = seen_context(scope, trusted_proxies=[PROXY])
    assert ctx.remote_addr == "203.0.113.7"


def test_forwarded_for_skips_trusted_hops_from_the_right() -> None:
    scope = http_scope(
        client=(PROXY, 1),
        headers=[("X-Forwarded-For", "6.6.6.6, 1.2.3.4, 10.1.2.3")],
    )
    ctx = seen_context(scope, trusted_proxies=["10.0.0.0/8"])
    assert ctx.remote_addr == "1.2.3.4"


@pytest.mark.parametrize(
    "values",
    [
        # The client is in the first header, the second holds a trusted hop.
        ["1.2.3.4", "10.9.9.9"],
        # The first header alone would give a trusted hop.
        ["10.1.1.1", "1.2.3.4, 10.9.9.9"],
    ],
)
def test_forwarded_for_joins_repeated_headers(values: list[str]) -> None:
    scope = http_scope(
        client=(PROXY, 1),
        headers=[("X-Forwarded-For", value) for value in values],
    )
    ctx = seen_context(scope, trusted_proxies=["10.0.0.0/8"])
    assert ctx.remote_addr == "1.2.3.4"


def test_forwarded_for_with_only_trusted_hops_takes_the_leftmost() -> None:
    scope = http_scope(
        client=(PROXY, 1), headers=[("X-Forwarded-For", "10.1.1.1, 10.2.2.2")]
    )
    ctx = seen_context(scope, trusted_proxies=["10.0.0.0/8"])
    assert ctx.remote_addr == "10.1.1.1"


def test_forwarded_for_with_an_invalid_client_hop_stores_none() -> None:
    scope = http_scope(
        client=(PROXY, 1), headers=[("X-Forwarded-For", "1.2.3.4, unknown")]
    )
    assert seen_context(scope, trusted_proxies=[PROXY]).remote_addr is None


def test_trusted_peer_without_forwarded_for_is_the_client() -> None:
    ctx = seen_context(http_scope(client=(PROXY, 1)), trusted_proxies=[PROXY])
    assert ctx.remote_addr == PROXY


def test_invalid_trusted_proxy_is_rejected() -> None:
    with pytest.raises(ValueError, match="does not appear to be"):
        AuditMiddleware(Recorder(), trusted_proxies=["proxy.local"])


# Request id


def test_request_id_header_from_a_trusted_proxy_is_kept() -> None:
    scope = http_scope(client=(PROXY, 1), headers=[("X-Request-ID", str(REQUEST_ID))])
    assert seen_context(scope, trusted_proxies=[PROXY]).request_id == REQUEST_ID


def test_request_id_header_from_an_untrusted_peer_is_replaced() -> None:
    scope = http_scope(headers=[("X-Request-ID", str(REQUEST_ID))])
    ctx = seen_context(scope, trusted_proxies=[PROXY])
    assert isinstance(ctx.request_id, uuid.UUID)
    assert ctx.request_id != REQUEST_ID


def test_request_id_header_is_ignored_by_default() -> None:
    scope = http_scope(client=(PROXY, 1), headers=[("X-Request-ID", str(REQUEST_ID))])
    assert seen_context(scope).request_id != REQUEST_ID


def test_invalid_request_id_header_is_replaced() -> None:
    scope = http_scope(client=(PROXY, 1), headers=[("X-Request-ID", "not-a-uuid")])
    ctx = seen_context(scope, trusted_proxies=[PROXY])
    assert isinstance(ctx.request_id, uuid.UUID)


def test_request_id_header_name_is_configurable() -> None:
    headers = [("X-Request-ID", str(uuid.uuid4())), ("X-Trace", str(REQUEST_ID))]
    scope = http_scope(client=(PROXY, 1), headers=headers)
    ctx = seen_context(scope, trusted_proxies=[PROXY], request_id_header="X-Trace")
    assert ctx.request_id == REQUEST_ID


def test_request_id_header_none_always_generates() -> None:
    scope = http_scope(client=(PROXY, 1), headers=[("X-Request-ID", str(REQUEST_ID))])
    ctx = seen_context(scope, trusted_proxies=[PROXY], request_id_header=None)
    assert ctx.request_id != REQUEST_ID


# set_actor and the providers


def test_set_actor_needs_a_request() -> None:
    with pytest.raises(RuntimeError, match="AuditMiddleware"):
        set_actor(Actor("user", "1"))


def test_set_actor_updates_the_request_context_not_a_nested_one() -> None:
    results: list[tuple[AuditContext, AuditContext]] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        with context(actor_type="system") as nested:
            updated = set_actor(Actor("user", "7", "ann"), auth_method="bearer")
        results.append((updated, nested))

    run(AuditMiddleware(app), http_scope())
    ((updated, nested),) = results
    assert (updated.actor_type, updated.actor_id, updated.actor_label) == (
        "user",
        "7",
        "ann",
    )
    assert updated.auth_method == "bearer"
    assert nested.actor_type == "system"


def test_set_actor_keeps_auth_method_when_not_given() -> None:
    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        ctx = request_context()
        assert ctx is not None
        ctx.auth_method = "cookie"
        assert set_actor(Actor("user", "1")).auth_method == "cookie"

    run(AuditMiddleware(app), http_scope())


def test_context_provider_prefers_a_nested_context() -> None:
    results: list[tuple[AuditContext | None, AuditContext | None]] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        outer = context_provider()
        with context(actor_type="system") as nested:
            results.append((outer, context_provider()))
        assert nested is results[0][1]

    run(AuditMiddleware(app), http_scope())
    ((outer, inner),) = results
    assert outer is not None
    assert outer.channel == "api"
    assert inner is not None
    assert inner.actor_type == "system"
    assert context_provider() is None


def test_context_provider_falls_back_to_the_request_context() -> None:
    results: list[AuditContext | None] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        # The request state without the built-in variable, as when a host
        # clears it with a nested scope of its own.
        token = _current.set(None)
        results.append(context_provider())
        _current.reset(token)

    run(AuditMiddleware(app), http_scope())
    (provided,) = results
    assert provided is not None
    assert provided.path == "/items/1"


# Session dependency


@pytest.fixture
def installed() -> sessionmaker[Session]:
    factory = sessionmaker()
    AuditTrail(
        create_engine("postgresql+psycopg://localhost/unused"), events=[]
    ).install(factory)
    return factory


def test_session_dependency_yields_and_tracks_the_session(
    installed: sessionmaker[Session],
) -> None:
    get_session = session_dependency(installed)
    results: list[object] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        dependency = get_session()
        session = next(dependency)
        results.extend([session, session_provider()])
        dependency.close()
        results.append(session_provider())

    run(AuditMiddleware(app), http_scope())
    session, provided, after = results
    assert isinstance(session, installed.class_)
    assert provided is session
    assert after is None


def test_session_dependency_works_without_the_middleware(
    installed: sessionmaker[Session],
) -> None:
    dependency = session_dependency(installed)()
    session = next(dependency)
    assert isinstance(session, Session)
    assert session_provider() is None
    dependency.close()


def test_session_dependency_rejects_a_factory_without_a_trail() -> None:
    dependency = session_dependency(sessionmaker())()
    with pytest.raises(TypeError, match="no AuditTrail is installed"):
        next(dependency)


def test_session_dependency_rejects_other_factories() -> None:
    with pytest.raises(TypeError, match="sessionmaker"):
        session_dependency(Session)  # type: ignore[call-overload]


def test_async_session_dependency_yields_and_tracks_the_session() -> None:
    sync_class = type("FastAPIUnitSession", (Session,), {})
    factory = async_sessionmaker(sync_session_class=sync_class)
    AuditTrail(
        create_engine("postgresql+psycopg://localhost/unused"), events=[]
    ).install(factory)
    get_session = session_dependency(factory)
    results: list[object] = []

    async def app(scope: Scope, receive: Receive, send: Send) -> None:
        dependency = get_session()
        session = await anext(dependency)
        results.extend([session, session_provider()])
        await dependency.aclose()
        results.append(session_provider())

    run(AuditMiddleware(app), http_scope())
    session, provided, after = results
    assert isinstance(session, AsyncSession)
    assert provided is session
    assert after is None


# Import boundaries


def test_core_does_not_import_fastapi() -> None:
    code = (
        "import sys, audit_trail; "
        "sys.exit(any(m in sys.modules for m in ('fastapi', 'starlette')))"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_core_works_without_fastapi_and_the_integration_names_the_extra() -> None:
    code = """
import sys
sys.modules["fastapi"] = None
sys.modules["starlette"] = None
from sqlalchemy import create_engine
from audit_trail import AuditTrail
AuditTrail(create_engine("postgresql+psycopg://localhost/unused"))
try:
    import audit_trail.integrations.fastapi
except ImportError as exc:
    assert "sqlalchemy-audit-trail[fastapi]" in str(exc), exc
else:
    sys.exit("the integration imported without starlette")
"""
    subprocess.run([sys.executable, "-c", code], check=True)
