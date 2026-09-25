"""Request context: who, where and how an audited change happened.

The context reaches the audit writer in one of three ways, checked in this
order by :func:`resolve_context`:

1. bound to a session with :func:`bind` (``session.info["audit_context"]``);
2. returned by a host-supplied ``context_provider``;
3. the built-in context variable, set with :func:`context`.

When none of them yields a context, an anonymous one is used.
"""

from __future__ import annotations

from collections.abc import Callable
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from types import TracebackType
from typing import TYPE_CHECKING, Any
from uuid import UUID

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import Session

SESSION_INFO_KEY = "audit_context"

_SNAPSHOT_FIELDS = (
    "actor_type",
    "actor_label",
    "remote_addr",
    "user_agent",
    "method",
    "path",
    "channel",
    "auth_method",
    "request_id",
)


@dataclass(frozen=True)
class Actor:
    """Who performed an action.

    Attributes:
        type: Kind of actor, defined by the host (for example ``"user"``,
            ``"system"``, ``"api_key"``).
        id: Opaque identifier of the actor, stored in ``actor_id``.
        label: Human-readable snapshot (for example an e-mail address) that
            survives deletion of the actor.
    """

    type: str
    id: str | None = None
    label: str | None = None


@dataclass
class AuditContext:
    """Who, where and how of the current unit of work.

    The object is mutable on purpose: it is set once (for example by a
    middleware) and later updated in place with :func:`set_actor`, so changes
    made in a worker thread are visible to the code that started it.

    Attributes:
        actor_type: Kind of actor. Defaults to ``"anonymous"``.
        actor_id: Opaque identifier of the actor.
        actor_label: Human-readable snapshot of the actor.
        remote_addr: Client IP address.
        user_agent: Client user agent.
        method: Request method, for example ``"POST"``.
        path: Request path.
        channel: Entry point, for example ``"api"``, ``"admin"``, ``"cli"``,
            ``"worker"``.
        auth_method: How the actor authenticated.
        request_id: Identifier of the request.
        correlation_id: Links several database transactions. When not given,
            it is set to ``request_id`` at construction; changing
            ``request_id`` later does not update it.
        scope_id: Scope of the change, for example a tenant.
        extra: Additional host-defined context, stored as ``meta``.
    """

    actor_type: str = "anonymous"
    actor_id: str | None = None
    actor_label: str | None = None
    remote_addr: str | None = None
    user_agent: str | None = None
    method: str | None = None
    path: str | None = None
    channel: str | None = None
    auth_method: str | None = None
    request_id: UUID | None = None
    correlation_id: UUID | None = None
    scope_id: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.correlation_id is None:
            self.correlation_id = self.request_id


_current: ContextVar[AuditContext | None] = ContextVar(
    "audit_trail_context", default=None
)


def current_context() -> AuditContext | None:
    """Return the context set with :func:`context`, if any.

    Returns:
        The active context object, or ``None`` outside a :func:`context` block.
    """
    return _current.get()


class _ContextScope:
    """Sync and async context manager that activates one ``AuditContext``."""

    def __init__(self, ctx: AuditContext) -> None:
        self._ctx = ctx
        self._tokens: list[Token[AuditContext | None]] = []

    def __enter__(self) -> AuditContext:
        self._tokens.append(_current.set(self._ctx))
        return self._ctx

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        _current.reset(self._tokens.pop())

    async def __aenter__(self) -> AuditContext:
        return self.__enter__()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.__exit__(exc_type, exc, tb)


def context(ctx: AuditContext | None = None, /, **fields: Any) -> _ContextScope:
    """Activate an audit context for a block of code.

    Usable as ``with context(...)`` and ``async with context(...)``. The
    previous context is restored on exit. A nested block replaces the outer
    context; it does not inherit its fields.

    Example::

        with context(actor_type="system", actor_label="cleanup", channel="worker"):
            ...

    Args:
        ctx: A ready context to activate. Mutually exclusive with ``fields``.
        **fields: Fields of a new :class:`AuditContext`: ``actor_type``,
            ``actor_id``, ``actor_label``, ``remote_addr``, ``user_agent``,
            ``method``, ``path``, ``channel``, ``auth_method``,
            ``request_id``, ``correlation_id``, ``scope_id``, ``extra``.

    Returns:
        A context manager yielding the active :class:`AuditContext`.

    Raises:
        TypeError: If both ``ctx`` and ``fields`` are given, or a field name
            is unknown.
    """
    if ctx is not None and fields:
        raise TypeError("pass either an AuditContext or its fields, not both")
    return _ContextScope(ctx if ctx is not None else AuditContext(**fields))


def set_actor(actor: Actor) -> AuditContext:
    """Set the actor on the active context, in place.

    The active object is mutated rather than replaced, so an actor set from a
    thread pool (for example a synchronous dependency) is visible to the
    caller.

    Args:
        actor: The actor. All three actor fields are overwritten.

    Returns:
        The updated context.

    Raises:
        RuntimeError: If no :func:`context` block is active.
    """
    ctx = _current.get()
    if ctx is None:
        raise RuntimeError(
            "no active audit context: enter context() first, or bind() an "
            "AuditContext to the session and set its actor fields directly"
        )
    ctx.actor_type = actor.type
    ctx.actor_id = actor.id
    ctx.actor_label = actor.label
    return ctx


def bind(session: Session | AsyncSession, context: AuditContext) -> None:
    """Attach a context to one session.

    Takes precedence over the provider and the built-in context variable.
    Binding does not enable auditing on the session.

    Args:
        session: The session to attach the context to.
        context: The context used for audit entries written by this session.
    """
    session.info[SESSION_INFO_KEY] = context


def resolve_context(
    session: Session | AsyncSession,
    context_provider: Callable[[], AuditContext | None] | None = None,
) -> AuditContext:
    """Return the context that applies to ``session``.

    Checks, in order: the context bound with :func:`bind`, then
    ``context_provider()``, then the built-in context variable. The object is
    returned as is, not copied, so later :func:`set_actor` calls stay visible.

    Args:
        session: The session being audited.
        context_provider: Optional host hook returning the current context,
            or ``None`` to fall through.

    Returns:
        The first context found, or a new anonymous one.

    Raises:
        TypeError: If ``session.info["audit_context"]`` is not an
            :class:`AuditContext`.
    """
    bound = session.info.get(SESSION_INFO_KEY)
    if bound is not None:
        if not isinstance(bound, AuditContext):
            raise TypeError(
                f'session.info["{SESSION_INFO_KEY}"] must be an AuditContext, '
                f"got {type(bound).__name__}"
            )
        return bound
    if context_provider is not None:
        provided = context_provider()
        if provided is not None:
            return provided
    active = _current.get()
    if active is not None:
        return active
    return AuditContext()


def context_snapshot(ctx: AuditContext) -> dict[str, Any]:
    """Build the ``data.context`` snapshot stored on each audit entry.

    Empty values (``None``, ``""``, an empty ``extra``) are left out.
    ``actor_id`` is never included: it is stored in its own column.

    Args:
        ctx: The context to snapshot.

    Returns:
        A JSON-ready dict; ``request_id`` is a string and ``extra`` is copied
        as ``meta``.
    """
    snapshot: dict[str, Any] = {}
    for name in _SNAPSHOT_FIELDS:
        value = getattr(ctx, name)
        if value is None or value == "":
            continue
        snapshot[name] = str(value) if isinstance(value, UUID) else value
    if ctx.extra:
        snapshot["meta"] = dict(ctx.extra)
    return snapshot
