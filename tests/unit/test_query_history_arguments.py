"""Argument checks of ``AuditQuery.get``, ``object_history``, ``related`` and
``access_summary``, and of ``LabelResolver``."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import pytest
from sqlalchemy.orm import Session

from audit_trail.query import AuditQuery, Cursor, LabelResolver, Visibility
from audit_trail.tables import build_tables

NAIVE = datetime(2026, 9, 1)
AWARE = datetime(2026, 9, 1, tzinfo=timezone.utc)
CORRELATION = UUID("00000000-0000-0000-0000-00000000000c")

Call = Callable[[AuditQuery, Session, dict[str, Any]], object]


def history(query: AuditQuery, session: Session, options: dict[str, Any]) -> object:
    return query.object_history(session, "Board", "1", **options)


def related(query: AuditQuery, session: Session, options: dict[str, Any]) -> object:
    return query.related(session, CORRELATION, **options)


def summary(query: AuditQuery, session: Session, options: dict[str, Any]) -> object:
    return query.access_summary(session, "Board", "1", "board.viewed", **options)


@pytest.fixture
def query() -> AuditQuery:
    return AuditQuery(build_tables(), [10, 40])


PAGED = [
    ({"limit": 0}, "limit"),
    ({"since": NAIVE}, "since"),
    ({"until": NAIVE}, "until"),
    ({"cursor": Cursor(NAIVE, 1)}, "cursor"),
]


@pytest.mark.parametrize("call", [history, related])
@pytest.mark.parametrize(("options", "message"), PAGED)
def test_paged_invalid_arguments(
    query: AuditQuery, call: Call, options: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message), Session() as session:
        call(query, session, options)


@pytest.mark.parametrize(
    ("options", "message"), [({"since": NAIVE}, "since"), ({"until": NAIVE}, "until")]
)
def test_summary_invalid_arguments(
    query: AuditQuery, options: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message), Session() as session:
        summary(query, session, options)


def test_get_rejects_a_naive_created_at(query: AuditQuery) -> None:
    with pytest.raises(ValueError, match="created_at"), Session() as session:
        query.get(session, 1, NAIVE)


def test_resolver_rejects_other_arguments() -> None:
    with pytest.raises(TypeError, match="registry"):
        LabelResolver(build_tables(), object)


# The async variants pass every argument on to the sync method.


class Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def __call__(self, session: object, *args: object, **kwargs: object) -> str:
        # Set on the class, so not bound: the first argument is the session.
        self.calls.append((args, kwargs))
        return "result"


PAGE_OPTIONS: dict[str, Any] = {
    "since": AWARE,
    "until": AWARE,
    "visibility": Visibility(verbs={"v"}),
    "cursor": Cursor(AWARE, 7),
    "limit": 3,
    "compact": False,
}

FORWARDED: list[tuple[str, tuple[object, ...], dict[str, Any]]] = [
    ("get", (1, AWARE), {"severity": 40, "visibility": Visibility(verbs={"v"})}),
    (
        "object_history",
        ("Board", "1"),
        {"include_children": False, **PAGE_OPTIONS},
    ),
    ("related", (CORRELATION,), PAGE_OPTIONS),
    (
        "access_summary",
        ("Board", "1", "board.viewed"),
        {"since": AWARE, "until": AWARE, "visibility": Visibility(verbs={"v"})},
    ),
]


@pytest.mark.parametrize(("name", "args", "kwargs"), FORWARDED)
async def test_async_variant_forwards_every_argument(
    query: AuditQuery,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    args: tuple[object, ...],
    kwargs: dict[str, Any],
) -> None:
    from sqlalchemy.ext.asyncio import AsyncSession

    recorder = Recorder()
    monkeypatch.setattr(AuditQuery, name, recorder)

    async with AsyncSession() as session:
        result = await getattr(query, f"a{name}")(session, *args, **kwargs)

    assert result == "result"
    assert recorder.calls == [(args, kwargs)]


async def test_aresolve_forwards_every_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy.orm import DeclarativeBase

    class Base(DeclarativeBase):
        pass

    recorder = Recorder()
    monkeypatch.setattr(LabelResolver, "resolve", recorder)
    resolver = LabelResolver(build_tables(), Base)
    visibility = Visibility(verbs={"v"})

    async with AsyncSession() as session:
        result: object = await resolver.aresolve(
            session, iter([]), visibility=visibility
        )

    assert result == "result"
    assert recorder.calls == [(([],), {"visibility": visibility})]
