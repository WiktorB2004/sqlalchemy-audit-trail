"""Cursor tokens and argument checks of ``audit_trail.query``."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy.orm import Session

from audit_trail.query import AuditQuery, Cursor, Visibility
from audit_trail.tables import build_tables

NAIVE = datetime(2026, 9, 1)  # noqa: DTZ001
AT = datetime(2026, 9, 25, 12, 30, 1, 123456, tzinfo=timezone(timedelta(hours=2)))


@pytest.mark.parametrize(
    "cursor",
    [Cursor(AT, 42), Cursor(AT.astimezone(timezone.utc), 1), Cursor(AT, 2**62)],
)
def test_cursor_round_trip(cursor: Cursor) -> None:
    token = cursor.encode()

    assert Cursor.decode(token) == cursor
    assert "=" not in token
    assert token.isascii()


def token_of(raw: str) -> str:
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


@pytest.mark.parametrize(
    "token",
    [
        "",
        "!!!",
        token_of("2026-09-25T12:00:00+00:00"),
        token_of("2026-09-25T12:00:00+00:00|x"),
        token_of("yesterday|1"),
        token_of("2026-09-25T12:00:00+00:00|1|2"),
        base64.urlsafe_b64encode(b"\xff\xfe|1").decode(),
    ],
)
def test_malformed_cursor(token: str) -> None:
    with pytest.raises(ValueError, match="malformed cursor"):
        Cursor.decode(token)


def test_cursor_without_offset() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        Cursor.decode(token_of("2026-09-25T12:00:00|1"))


@pytest.fixture
def query() -> AuditQuery:
    return AuditQuery(build_tables(), [10, 40])


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"limit": 0}, "limit"),
        ({"since": NAIVE}, "since"),
        ({"until": NAIVE}, "until"),
        ({"cursor": Cursor(NAIVE, 1)}, "cursor"),
    ],
)
def test_invalid_arguments(
    query: AuditQuery, options: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message), Session() as session:
        query.list_groups(session, **options)


@pytest.mark.parametrize("field", ["severities", "verbs", "scope_ids"])
def test_str_is_not_a_collection(query: AuditQuery, field: str) -> None:
    with pytest.raises(TypeError, match=field), Session() as session:
        options: dict[str, Any] = {field: "abc"}
        query.list_groups(session, **options)


@pytest.mark.parametrize("field", ["object_types", "verbs", "scope_ids"])
def test_visibility_rejects_str(field: str) -> None:
    with pytest.raises(TypeError, match=field):
        Visibility(**{field: "abc"})


def test_severities_are_deduplicated_and_sorted() -> None:
    assert AuditQuery(build_tables(), [40, 10, 40]).severities == (10, 40)
