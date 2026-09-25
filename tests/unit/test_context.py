from __future__ import annotations

import asyncio
import contextvars
import dataclasses
import inspect
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from sqlalchemy.orm import Session

from audit_trail.context import (
    Actor,
    AuditContext,
    ContextSnapshot,
    bind,
    context,
    context_snapshot,
    current_context,
    resolve_context,
    set_actor,
)

USER = Actor(type="user", id="42", label="a@example.com")


@pytest.fixture
def session() -> Iterator[Session]:
    with Session() as s:
        yield s


def test_set_actor_from_thread_is_visible_to_caller_sync() -> None:
    # Same mechanism as Starlette's run_in_threadpool: the worker runs in a
    # copy of the caller's context.
    with context() as ctx, ThreadPoolExecutor(max_workers=1) as pool:
        run = contextvars.copy_context().run
        pool.submit(run, set_actor, USER).result()

        assert current_context() is ctx
        assert (ctx.actor_type, ctx.actor_id, ctx.actor_label) == (
            "user",
            "42",
            "a@example.com",
        )


async def test_set_actor_from_to_thread_is_visible_to_caller() -> None:
    async with context() as ctx:
        await asyncio.to_thread(set_actor, USER)

        active = current_context()
        assert active is ctx
        assert active.actor_id == "42"
        assert active.actor_type == "user"


async def test_concurrent_tasks_do_not_see_each_other() -> None:
    async def request(actor_id: str) -> tuple[str | None, str | None]:
        async with context(channel="api"):
            await asyncio.sleep(0)
            set_actor(Actor(type="user", id=actor_id))
            await asyncio.sleep(0)
            active = current_context()
            assert active is not None
            return actor_id, active.actor_id

    results = await asyncio.gather(*(request(str(i)) for i in range(10)))

    assert all(expected == seen for expected, seen in results)
    assert current_context() is None


def test_set_actor_without_context_raises() -> None:
    with pytest.raises(RuntimeError, match="bind"):
        set_actor(USER)


def test_set_actor_overwrites_all_actor_fields() -> None:
    with context(actor_type="user", actor_id="1", actor_label="old") as ctx:
        set_actor(Actor(type="system"))

    assert (ctx.actor_type, ctx.actor_id, ctx.actor_label) == ("system", None, None)


def test_context_restores_previous_on_exit_and_error() -> None:
    outer = AuditContext(channel="cli")
    with context(outer):
        with pytest.raises(ValueError), context(channel="worker") as inner:
            assert current_context() is inner
            assert inner.channel == "worker"
            raise ValueError
        assert current_context() is outer
    assert current_context() is None


async def test_async_context_restores_previous() -> None:
    async with context(channel="worker") as ctx:
        assert current_context() is ctx
    assert current_context() is None


def test_context_activates_given_object() -> None:
    ctx = AuditContext()
    with context(ctx) as active:
        assert active is ctx


def test_context_rejects_object_and_fields_together() -> None:
    with pytest.raises(TypeError):
        context(AuditContext(), channel="api")


@pytest.mark.parametrize("name", [f.name for f in dataclasses.fields(AuditContext)])
def test_context_rejects_object_with_any_field(name: str) -> None:
    fields: dict[str, Any] = {name: object()}
    with pytest.raises(TypeError):
        context(AuditContext(), **fields)


def test_context_rejects_unknown_field() -> None:
    with pytest.raises(TypeError):
        context(no_such_field=1)  # type: ignore[call-arg]


def test_context_accepts_exactly_the_audit_context_fields() -> None:
    # Keeps the explicit keyword arguments in sync with the dataclass.
    params = inspect.signature(context).parameters.values()
    keywords = {p.name for p in params if p.kind is p.KEYWORD_ONLY}
    assert keywords == {f.name for f in dataclasses.fields(AuditContext)}


def test_context_passes_every_field_through() -> None:
    values: dict[str, Any] = {
        f.name: object() for f in dataclasses.fields(AuditContext)
    }
    with context(**values) as ctx:
        for name, value in values.items():
            assert getattr(ctx, name) is value, name


def test_context_defaults_match_audit_context() -> None:
    with context() as ctx:
        assert ctx == AuditContext()


def test_bind_only_sets_session_info(session: Session) -> None:
    ctx = AuditContext()
    bind(session, context=ctx)

    assert session.info == {"audit_context": ctx}


def test_resolve_prefers_bound_context(session: Session) -> None:
    bound = AuditContext(channel="bound")
    bind(session, context=bound)

    with context(channel="var"):
        resolved = resolve_context(session, lambda: AuditContext(channel="provider"))

    assert resolved is bound


def test_resolve_prefers_provider_over_context_var(session: Session) -> None:
    provided = AuditContext(channel="provider")

    with context(channel="var"):
        assert resolve_context(session, lambda: provided) is provided


def test_resolve_falls_through_provider_returning_none(session: Session) -> None:
    with context(channel="var") as active:
        assert resolve_context(session, lambda: None) is active


def test_resolve_uses_context_var(session: Session) -> None:
    with context(channel="var") as active:
        assert resolve_context(session) is active


def test_resolve_defaults_to_anonymous(session: Session) -> None:
    resolved = resolve_context(session, lambda: None)

    assert resolved == AuditContext()
    assert resolved.actor_type == "anonymous"


def test_resolve_rejects_wrong_bound_type(session: Session) -> None:
    session.info["audit_context"] = {"actor_type": "user"}

    with pytest.raises(TypeError):
        resolve_context(session)


def test_resolved_context_sees_later_set_actor(session: Session) -> None:
    with context() as active:
        resolved = resolve_context(session)
        set_actor(USER)

        assert resolved is active
        assert resolved.actor_id == "42"


def test_correlation_id_defaults_to_request_id() -> None:
    request_id = uuid.uuid4()

    assert AuditContext(request_id=request_id).correlation_id == request_id


def test_explicit_correlation_id_wins() -> None:
    request_id, correlation_id = uuid.uuid4(), uuid.uuid4()
    ctx = AuditContext(request_id=request_id, correlation_id=correlation_id)

    assert ctx.correlation_id == correlation_id


def test_snapshot_of_default_context_has_only_actor_type() -> None:
    assert context_snapshot(AuditContext()) == {"actor_type": "anonymous"}


def test_snapshot_omits_empty_values() -> None:
    ctx = AuditContext(actor_label="", path=None, extra={})

    snapshot = context_snapshot(ctx)

    assert "actor_label" not in snapshot
    assert "path" not in snapshot
    assert "meta" not in snapshot


def test_snapshot_full() -> None:
    request_id = uuid.uuid4()
    ctx = AuditContext(
        actor_type="user",
        actor_id="42",
        actor_label="a@example.com",
        remote_addr="10.0.0.1",
        user_agent="curl/8",
        method="POST",
        path="/tenants",
        channel="api",
        auth_method="password",
        request_id=request_id,
        scope_id="acme",
        extra={"ticket": "T-1"},
    )

    snapshot = context_snapshot(ctx)

    # Keeps the TypedDict and the builder in sync.
    assert set(snapshot) == set(ContextSnapshot.__annotations__)
    assert snapshot == {
        "actor_type": "user",
        "actor_label": "a@example.com",
        "remote_addr": "10.0.0.1",
        "user_agent": "curl/8",
        "method": "POST",
        "path": "/tenants",
        "channel": "api",
        "auth_method": "password",
        "request_id": str(request_id),
        "meta": {"ticket": "T-1"},
    }


def test_snapshot_meta_is_a_copy() -> None:
    ctx = AuditContext(extra={"ticket": "T-1"})

    snapshot = context_snapshot(ctx)
    ctx.extra["ticket"] = "T-2"

    assert snapshot["meta"] == {"ticket": "T-1"}


@pytest.mark.parametrize(
    "name",
    [
        "actor_type",
        "actor_label",
        "remote_addr",
        "user_agent",
        "method",
        "path",
        "channel",
        "auth_method",
    ],
)
@pytest.mark.parametrize("empty", [None, ""])
def test_snapshot_omits_each_empty_field(name: str, empty: str | None) -> None:
    ctx = AuditContext()
    setattr(ctx, name, "x")
    assert name in context_snapshot(ctx)

    setattr(ctx, name, empty)

    assert name not in context_snapshot(ctx)
