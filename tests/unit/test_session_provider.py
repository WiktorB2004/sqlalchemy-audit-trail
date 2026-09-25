"""How ``log``/``alog`` find their session, checked before any database I/O."""

from __future__ import annotations

from typing import Any

import pytest
from sqlalchemy import Engine, create_engine
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from audit_trail import AuditEvent, AuditTrail, Severity, event


@pytest.fixture
def trail() -> AuditTrail:
    engine: Engine = create_engine("postgresql+psycopg://localhost/unused")
    return AuditTrail(engine, events=[])


@pytest.fixture
def noted() -> AuditEvent:
    class ProviderEvent(AuditEvent):
        NOTED = event("provider_test.noted", Severity.INFO)

    return ProviderEvent.NOTED


async def test_no_session_without_a_provider_is_an_error(
    trail: AuditTrail, noted: AuditEvent
) -> None:
    with pytest.raises(RuntimeError, match=r"log\(\) needs a session"):
        trail.log(noted)
    with pytest.raises(RuntimeError, match=r"log\(\) needs a session"):
        trail.log(None, noted)
    with pytest.raises(RuntimeError, match=r"alog\(\) needs a session"):
        await trail.alog(noted)


async def test_a_provider_returning_none_is_an_error(
    trail: AuditTrail, noted: AuditEvent
) -> None:
    trail.session_provider = lambda: None
    with pytest.raises(RuntimeError, match="no session from session_provider"):
        trail.log(noted)
    with pytest.raises(RuntimeError, match="no session from session_provider"):
        await trail.alog(None, noted)


def test_log_refuses_an_async_session(trail: AuditTrail, noted: AuditEvent) -> None:
    session = AsyncSession()
    with pytest.raises(TypeError, match=r"not AsyncSession; use alog\(\)"):
        trail.log(session, noted)  # type: ignore[call-overload]
    trail.session_provider = lambda: session
    with pytest.raises(TypeError, match=r"not AsyncSession; use alog\(\)"):
        trail.log(noted)


async def test_alog_refuses_a_sync_session(
    trail: AuditTrail, noted: AuditEvent
) -> None:
    session = Session()
    with pytest.raises(TypeError, match=r"not Session; use log\(\)"):
        await trail.alog(session, noted)  # type: ignore[call-overload]
    trail.session_provider = lambda: session
    with pytest.raises(TypeError, match=r"not Session; use log\(\)"):
        await trail.alog(noted)


@pytest.mark.parametrize("shape", ["session", "event, session", "event, event"])
async def test_other_argument_shapes_are_refused(
    trail: AuditTrail, noted: AuditEvent, shape: str
) -> None:
    session = Session()
    trail.session_provider = lambda: pytest.fail("the provider was called")
    values = {"session": session, "event": noted}
    args = [values[name] for name in shape.split(", ")]
    loose: Any = trail
    with pytest.raises(TypeError, match=r"takes \(session, event\) or \(event\)"):
        loose.log(*args)
    with pytest.raises(TypeError, match=r"takes \(session, event\) or \(event\)"):
        await loose.alog(*args)
