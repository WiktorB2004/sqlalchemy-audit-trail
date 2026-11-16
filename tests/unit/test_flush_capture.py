"""The ``before_update`` capture that ``entity_changes`` reads, on SQLite.

The installed ``before_flush`` listener is stood in for by a test listener
that opens the capture the same way, so these run without PostgreSQL. What
the listener stores is tested in ``tests/db/test_sql_written_columns.py``.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import Engine, create_engine, event, func, literal_column
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from audit_trail.diff import (
    _FLUSH_CAPTURE_KEY,
    UNKNOWN,
    Changes,
    _is_sql,
    entity_changes,
)
from audit_trail.mixin import Audited
from audit_trail.serialization import encode_value

T0 = datetime(2026, 1, 1)
T1 = datetime(2026, 1, 2)


def _now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Doc(Base, Audited):
    __tablename__ = "doc"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str]
    stamped_at: Mapped[datetime | None]
    touched_at: Mapped[datetime | None] = mapped_column(onupdate=_now)
    blob: Mapped[str | None] = mapped_column(info={"audit": "exclude"})


class _Clause:
    def __clause_element__(self) -> Any:
        return func.now()


@pytest.fixture
def engine() -> Iterator[Engine]:
    eng = create_engine("sqlite://")
    Base.metadata.create_all(eng)
    yield eng
    eng.dispose()


def capturing(session: Session) -> list[Changes]:
    """Open the capture each flush and collect the ``updated`` change sets."""
    seen: list[Changes] = []

    def before_flush(session: Session, context: object, instances: object) -> None:
        session.info[_FLUSH_CAPTURE_KEY] = {}

    def after_flush(session: Session, context: object) -> None:
        for obj in session.dirty:
            changes = entity_changes(obj, "updated")
            if changes:
                seen.append(changes)

    def after_flush_postexec(session: Session, context: object) -> None:
        session.info.pop(_FLUSH_CAPTURE_KEY, None)

    event.listen(session, "before_flush", before_flush)
    event.listen(session, "after_flush", after_flush)
    event.listen(session, "after_flush_postexec", after_flush_postexec)
    return seen


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (func.now(), True),
        (literal_column("1"), True),
        (_Clause(), True),
        (T0, False),
        ("now()", False),
        (None, False),
    ],
)
def test_is_sql_matches_what_the_flush_sends_as_sql(
    value: object, expected: bool
) -> None:
    assert _is_sql(value) is expected


def test_derived_columns_only_next_to_a_real_change(engine: Engine) -> None:
    with Session(engine) as session:
        doc = Doc(title="a", touched_at=T0)
        session.add(doc)
        session.commit()
        seen = capturing(session)
        doc.blob = "x"  # excluded: touched_at changes, but nothing is recorded
        session.commit()
        assert seen == []
        doc.touched_at = T0  # reset for a known old value
        session.commit()
        doc.title = "b"
        session.commit()
        touched = doc.touched_at

    assert seen[-1] == {
        "title": ["a", "b"],
        "touched_at": [encode_value(T0), encode_value(touched)],
    }


def test_assigned_expression_without_other_change(engine: Engine) -> None:
    with Session(engine) as session:
        doc = Doc(title="a", stamped_at=T0)
        session.add(doc)
        session.commit()
        seen = capturing(session)
        doc.stamped_at = _Clause()  # type: ignore[assignment]
        session.commit()
        touched = doc.touched_at

    # A real change on its own, so the onupdate column comes with it.
    assert seen == [
        {
            "stamped_at": [encode_value(T0), UNKNOWN],
            "touched_at": [None, encode_value(touched)],
        }
    ]


def test_no_capture_without_the_before_flush_listener(engine: Engine) -> None:
    with Session(engine) as session:
        doc = Doc(title="a", stamped_at=T0)
        session.add(doc)
        session.commit()
        seen: list[Changes] = []
        event.listen(
            session,
            "after_flush",
            lambda s, c: seen.append(entity_changes(doc, "updated")),
        )
        doc.title = "b"
        doc.stamped_at = func.now()
        doc.touched_at = T1
        session.commit()

    # Unchanged from before the capture existed: history only.
    assert seen == [{"title": ["a", "b"], "touched_at": [None, encode_value(T1)]}]
