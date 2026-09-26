"""FastAPI integration: ASGI middleware, session dependency and providers.

Needs the ``fastapi`` extra (``pip install 'sqlalchemy-audit-trail[fastapi]'``).

:class:`AuditMiddleware` activates an ``AuditContext`` for each request, with
the network part filled in: client address, user agent, method, path, channel
and request id. The same object stays active for the whole request, including
synchronous dependencies and endpoints, which FastAPI runs in its thread pool
in a copy of the request's context variables. The copy still refers to the
same object, so :func:`set_actor` called there updates the context the
session listener reads when it flushes.

Example::

    from audit_trail import Actor
    from audit_trail.integrations.fastapi import (
        AuditMiddleware,
        session_dependency,
        set_actor,
    )

    app = FastAPI()
    app.add_middleware(AuditMiddleware)
    get_session = session_dependency(SessionLocal)  # the factory given to install()


    def current_user(token: str = Depends(oauth2_scheme)) -> User:
        user = authenticate(token)
        set_actor(Actor("user", str(user.id), user.email), auth_method="bearer")
        return user
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import AsyncGenerator, Callable, Generator, Iterable, Iterator
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, TypeVar, overload

from sqlalchemy.orm import Session, sessionmaker

from audit_trail.context import Actor, AuditContext, context, current_context
from audit_trail.listener import installed_trail

try:
    from starlette.types import ASGIApp, Receive, Scope, Send
except ImportError as exc:
    raise ImportError(
        "audit_trail.integrations.fastapi needs the 'fastapi' extra: "
        "pip install 'sqlalchemy-audit-trail[fastapi]'"
    ) from exc

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

__all__ = [
    "AuditMiddleware",
    "context_provider",
    "request_context",
    "session_dependency",
    "session_provider",
    "set_actor",
]

_S = TypeVar("_S", bound=Session)
_A = TypeVar("_A", bound="AsyncSession")

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network
_Address = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass
class _RequestState:
    # Set once per request by the middleware and mutated in place afterwards,
    # so changes made in the thread pool are seen by the request's task.
    context: AuditContext
    session: Session | AsyncSession | None = None


_request: ContextVar[_RequestState | None] = ContextVar(
    "audit_trail_fastapi_request", default=None
)


class AuditMiddleware:
    """ASGI middleware that activates an audit context for each request.

    For ``http`` and ``websocket`` requests it builds an ``AuditContext``
    with ``remote_addr``, ``user_agent``, ``method`` (``None`` for a
    websocket), ``path`` (without the query string), ``channel`` and
    ``request_id``, and runs the application inside ``context(...)``. Other
    scopes, such as ``lifespan``, pass through untouched.

    Headers set by clients are trusted only when the direct peer is a
    trusted proxy; by default none is:

    - ``remote_addr`` is the direct peer's address. When the peer is in
      ``trusted_proxies``, it is taken from ``X-Forwarded-For`` instead: the
      list is read from right to left, trusted proxies are skipped and the
      first other address is the client (the leftmost one if all are
      trusted). ``Forwarded`` (RFC 7239) is not read.
    - ``request_id`` comes from the ``request_id_header`` only when the peer
      is in ``trusted_proxies`` and the value is a UUID; otherwise a new
      UUID is generated, so a client cannot reuse the id of another request.

    An address that is not a valid IP (for example Starlette's
    ``"testclient"``) is stored as ``None``: ``remote_addr`` is an ``inet``
    column.

    Args:
        app: The ASGI application to wrap.
        channel: Stored as the context's ``channel``.
        request_id_header: Header carrying the request id set by a trusted
            proxy. ``None`` always generates a new id.
        trusted_proxies: IP addresses or networks (``"10.0.0.0/8"``) of the
            proxies whose ``X-Forwarded-For`` and request id headers are
            believed. Empty by default.

    Raises:
        ValueError: An entry of ``trusted_proxies`` is not an IP address or
            network.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        channel: str | None = "api",
        request_id_header: str | None = "x-request-id",
        trusted_proxies: Iterable[str] = (),
    ) -> None:
        self.app = app
        self.channel = channel
        self.request_id_header = (
            None
            if request_id_header is None
            else request_id_header.lower().encode("latin-1")
        )
        self.trusted_proxies: tuple[_Network, ...] = tuple(
            ipaddress.ip_network(entry, strict=False) for entry in trusted_proxies
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope["type"]
        if kind not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
        client = scope.get("client")
        peer = _ip(client[0]) if client else None
        remote_addr = None if peer is None else str(peer)
        request_id = uuid.uuid4()
        if peer is not None and self._trusted(peer):
            remote_addr = self._client_addr(peer, headers)
            request_id = self._request_id(headers)
        ctx = AuditContext(
            remote_addr=remote_addr,
            user_agent=_header(headers, b"user-agent"),
            method=scope.get("method") if kind == "http" else None,
            path=scope.get("path"),
            channel=self.channel,
            request_id=request_id,
        )
        token = _request.set(_RequestState(ctx))
        try:
            with context(ctx):
                await self.app(scope, receive, send)
        finally:
            _request.reset(token)

    def _trusted(self, address: _Address) -> bool:
        return any(address in network for network in self.trusted_proxies)

    def _client_addr(
        self,
        peer: _Address,
        headers: list[tuple[bytes, bytes]],
    ) -> str | None:
        hops = [
            hop.strip()
            for name, value in headers
            if name == b"x-forwarded-for"
            for hop in value.decode("latin-1").split(",")
            if hop.strip()
        ]
        if not hops:
            return str(peer)
        for hop in reversed(hops):
            address = _ip(hop)
            if address is None:
                return None
            if not self._trusted(address):
                return str(address)
        leftmost = _ip(hops[0])
        return None if leftmost is None else str(leftmost)

    def _request_id(self, headers: list[tuple[bytes, bytes]]) -> uuid.UUID:
        if self.request_id_header is not None:
            value = _header(headers, self.request_id_header)
            if value is not None:
                with suppress(ValueError):
                    return uuid.UUID(value.strip())
        return uuid.uuid4()


def _header(headers: list[tuple[bytes, bytes]], name: bytes) -> str | None:
    for key, value in headers:
        if key == name:
            return value.decode("latin-1")
    return None


def _ip(value: str) -> _Address | None:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def request_context() -> AuditContext | None:
    """Return the context ``AuditMiddleware`` activated for this request.

    A nested ``audit.context(...)`` block does not change it.

    Returns:
        The request's context, or ``None`` outside a request.
    """
    state = _request.get()
    return None if state is None else state.context


def context_provider() -> AuditContext | None:
    """``context_provider`` for ``AuditTrail`` that follows the active context.

    Returns the context of an ``audit.context(...)`` block when one is
    active (a nested block inside a request wins), otherwise the request's
    context. Passing it is optional when ``AuditMiddleware`` is installed:
    the middleware activates the request's context in the built-in context
    variable, which the listener reads anyway.

    Returns:
        The active context, or ``None`` outside a request and any block.
    """
    active = current_context()
    return active if active is not None else request_context()


def session_provider() -> Session | AsyncSession | None:
    """``session_provider`` for ``AuditTrail``: this request's session.

    Returns:
        The session opened by a :func:`session_dependency` dependency for
        the current request, or ``None`` when there is none or no
        ``AuditMiddleware`` is installed.
    """
    state = _request.get()
    return None if state is None else state.session


def set_actor(
    actor: Actor, *, auth_method: str | None = None, scope_id: str | None = None
) -> AuditContext:
    """Set the actor of the current request, after authentication.

    Updates the request's context (the one ``AuditMiddleware`` activated) in
    place, not a nested ``audit.context(...)`` block, so it can be called
    from a synchronous dependency running in the thread pool. Entries flushed
    afterwards in the request carry the actor.

    Args:
        actor: The actor. All three actor fields are overwritten.
        auth_method: How the actor authenticated, stored when given.
        scope_id: Scope (such as the tenant) of the request's entries,
            stored when given; ``None`` keeps the current one.

    Returns:
        The request's context.

    Raises:
        RuntimeError: No ``AuditMiddleware`` request is active.
    """
    ctx = request_context()
    if ctx is None:
        raise RuntimeError(
            "no active request context: add AuditMiddleware to the application"
        )
    ctx.actor_type = actor.type
    ctx.actor_id = actor.id
    ctx.actor_label = actor.label
    if auth_method is not None:
        ctx.auth_method = auth_method
    if scope_id is not None:
        ctx.scope_id = scope_id
    return ctx


@overload
def session_dependency(
    factory: sessionmaker[_S],
) -> Callable[[], Generator[_S, None, None]]: ...


@overload
def session_dependency(
    factory: async_sessionmaker[_A],
) -> Callable[[], AsyncGenerator[_A, None]]: ...


def session_dependency(
    factory: sessionmaker[_S] | async_sessionmaker[_A],
) -> Callable[[], Generator[_S, None, None]] | Callable[[], AsyncGenerator[_A, None]]:
    """Build a FastAPI dependency yielding a session of ``factory``.

    Pass the factory given to ``AuditTrail.install``. The session is closed
    after the request and never committed by the dependency. For a
    ``sessionmaker`` the dependency is synchronous, so FastAPI runs it in
    its thread pool; for an ``async_sessionmaker`` it is asynchronous.

    The session is not bound to a context: the listener reads the request's
    context (or a nested ``audit.context(...)``) when it flushes, so an actor
    set with :func:`set_actor` after the session was opened still reaches
    its entries.

    Args:
        factory: A ``sessionmaker`` or ``async_sessionmaker``.

    Returns:
        The dependency, for ``Depends(...)``. It raises ``TypeError`` when
        the session's class has no ``AuditTrail`` installed.

    Raises:
        TypeError: ``factory`` is neither.
    """
    if isinstance(factory, sessionmaker):
        sync_factory: sessionmaker[_S] = factory

        def get_session() -> Generator[_S, None, None]:
            with sync_factory() as session:
                _check_installed(session)
                with _tracked(session):
                    yield session

        return get_session

    from sqlalchemy.ext.asyncio import async_sessionmaker

    if not isinstance(factory, async_sessionmaker):
        raise TypeError(
            "session_dependency() needs a sessionmaker or an async_sessionmaker, "
            f"got {factory!r}"
        )
    async_factory: async_sessionmaker[_A] = factory

    async def get_async_session() -> AsyncGenerator[_A, None]:
        async with async_factory() as session:
            _check_installed(session.sync_session)
            with _tracked(session):
                yield session

    return get_async_session


def _check_installed(session: Session) -> None:
    if installed_trail(session) is None:
        raise TypeError(
            f"no AuditTrail is installed on {type(session).__qualname__}: pass "
            "session_dependency() the factory given to install()"
        )


@contextmanager
def _tracked(session: Session | AsyncSession) -> Iterator[None]:
    # Records the session on the request state while the dependency is open.
    state = _request.get()
    if state is not None:
        state.session = session
    try:
        yield
    finally:
        if state is not None and state.session is session:
            state.session = None
