"""Cursor tokens and argument checks of ``audit_trail.query``."""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from audit_trail import AuditTrail
from audit_trail.query import ALL_HISTORY, AuditQuery, Cursor, Visibility
from audit_trail.tables import build_tables

NAIVE = datetime(2026, 9, 1)
AT = datetime(2026, 9, 25, 12, 30, 1, 123456, tzinfo=timezone(timedelta(hours=2)))


@pytest.mark.parametrize(
    "cursor",
    [
        Cursor(AT, 42),
        Cursor(AT.astimezone(timezone.utc), 1),
        Cursor(AT, 2**62),
        Cursor(AT, 7, AT - timedelta(days=30)),
        Cursor(AT, 7, ALL_HISTORY),
    ],
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
        token_of("2026-09-25T12:00:00+00:00|1|*|*"),
        token_of("2026-09-25T12:00:00+00:00|1|"),
        base64.urlsafe_b64encode(b"\xff\xfe|1").decode(),
    ],
)
def test_malformed_cursor(token: str) -> None:
    with pytest.raises(ValueError, match="malformed cursor"):
        Cursor.decode(token)


def test_cursor_without_offset() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        Cursor.decode(token_of("2026-09-25T12:00:00|1"))


def test_cursor_since_without_offset() -> None:
    with pytest.raises(ValueError, match="cursor since"):
        Cursor.decode(token_of("2026-09-25T12:00:00+00:00|1|2026-09-01T00:00:00"))


def test_token_without_since_records_none() -> None:
    # Tokens of earlier versions: the bound is "not recorded", not "none".
    cursor = Cursor.decode(token_of("2026-09-25T12:00:00+00:00|1"))

    assert cursor.since is None


def test_all_history_token_is_not_a_datetime() -> None:
    cursor = Cursor.decode(token_of("2026-09-25T12:00:00+00:00|1|*"))

    assert cursor.since is ALL_HISTORY


@pytest.mark.parametrize(
    ("window", "error"),
    [
        (timedelta(0), ValueError),
        (timedelta(days=-1), ValueError),
        (30, TypeError),
        ("30d", TypeError),
    ],
)
def test_invalid_default_window(window: object, error: type[Exception]) -> None:
    options: dict[str, Any] = {"default_window": window}
    with pytest.raises(error, match="default query window"):
        AuditQuery(build_tables(), [10], **options)


def test_trail_passes_the_default_window() -> None:
    window = timedelta(days=30)
    trail = AuditTrail(
        create_engine("postgresql+psycopg://"), events=[], default_query_window=window
    )

    assert trail.query.default_window == window
    assert (
        AuditTrail(
            create_engine("postgresql+psycopg://"), events=[]
        ).query.default_window
        is None
    )


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
        ({"cursor": Cursor(AT, 1, NAIVE)}, "cursor since"),
    ],
)
def test_invalid_arguments(
    query: AuditQuery, options: dict[str, Any], message: str
) -> None:
    with pytest.raises(ValueError, match=message), Session() as session:
        query.list_groups(session, **options)


def test_since_of_another_type(query: AuditQuery) -> None:
    options: dict[str, Any] = {"since": "2026-09-01"}
    with pytest.raises(TypeError, match="since"), Session() as session:
        query.list_groups(session, **options)


@pytest.mark.parametrize("field", ["severities", "verbs", "scope_ids"])
def test_str_is_not_a_collection(query: AuditQuery, field: str) -> None:
    options: dict[str, Any] = {field: "abc"}
    with pytest.raises(TypeError, match=field), Session() as session:
        query.list_groups(session, **options)


@pytest.mark.parametrize("field", ["object_types", "verbs", "scope_ids"])
def test_visibility_rejects_str(field: str) -> None:
    with pytest.raises(TypeError, match=field):
        Visibility(**{field: "abc"})


def test_severities_are_deduplicated_and_sorted() -> None:
    assert AuditQuery(build_tables(), [40, 10, 40]).severities == (10, 40)
