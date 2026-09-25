"""Change sets computed in ``after_flush`` against PostgreSQL.

A test-local ``after_flush`` listener stands in for the audit listener: it
builds the change set of every ``Audited`` instance in the flush and then
calls ``refresh_snapshot`` for new and updated ones, the way the listener
will.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest
from sqlalchemy import DateTime, Engine, Numeric, String, Text, event, select, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    UOWTransaction,
    deferred,
    mapped_column,
)

from audit_trail.config import AuditOptions
from audit_trail.diff import (
    REDACTED,
    UNKNOWN,
    USE_CONTEXT,
    ChangeKind,
    Changes,
    entity_changes,
    object_id_for,
    object_id_of,
    resolve_label,
    resolve_scope,
)
from audit_trail.mixin import Audited, refresh_snapshot
from audit_trail.serialization import KeyRing, hash_value

KEYS = KeyRing(b"1" * 32)


class Base(DeclarativeBase):
    pass


class Item(Base, Audited):
    __tablename__ = "item"
    __audit__ = AuditOptions(snapshot_on_load={"snapped"})

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str | None] = mapped_column(String)
    amount: Mapped[Decimal | None] = mapped_column(Numeric(10, 2))
    happened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    naive_at: Mapped[datetime | None] = mapped_column(DateTime())
    secret: Mapped[str | None] = mapped_column(String, info={"audit": "redact"})
    email: Mapped[str | None] = mapped_column(String, info={"audit": "hash"})
    blob: Mapped[bytes | None] = mapped_column(info={"audit": "exclude"})
    marker: Mapped[str | None] = mapped_column(String, server_default=text("'x'"))
    notes: Mapped[str | None] = deferred(mapped_column(Text))
    plain: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    tracked: Mapped[dict[str, Any] | None] = mapped_column(
        MutableDict.as_mutable(JSONB)
    )
    snapped: Mapped[dict[str, Any] | None] = mapped_column(
        MutableDict.as_mutable(JSONB)
    )


class Pair(Base, Audited):
    __tablename__ = "pair"

    a: Mapped[str] = mapped_column(primary_key=True)
    b: Mapped[int] = mapped_column(primary_key=True)
    value: Mapped[str | None]


class Thing(Base, Audited):
    __tablename__ = "thing"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True)


@dataclass(frozen=True)
class Entry:
    kind: ChangeKind
    object_id: str
    changes: Changes


class Recorder:
    def __init__(self) -> None:
        self.entries: list[Entry] = []

    def after_flush(self, session: Session, flush_context: UOWTransaction) -> None:
        batches: list[tuple[ChangeKind, list[object]]] = [
            ("created", list(session.new)),
            ("updated", list(session.dirty)),
            ("deleted", list(session.deleted)),
        ]
        for kind, objects in batches:
            for obj in objects:
                if not isinstance(obj, Audited):
                    continue
                changes = entity_changes(obj, kind, keys=KEYS)
                if changes:
                    self.entries.append(Entry(kind, object_id_of(obj), changes))
        for obj in [*session.new, *session.dirty]:
            refresh_snapshot(obj)

    def take(self) -> list[Entry]:
        entries, self.entries = self.entries, []
        return entries


@pytest.fixture
def db(engine: Engine, schema: str) -> Iterator[Engine]:
    bound = engine.execution_options(schema_translate_map={None: schema})
    Base.metadata.create_all(bound)
    yield bound


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


@pytest.fixture
def session(db: Engine, recorder: Recorder) -> Iterator[Session]:
    with Session(db) as sess:
        event.listen(sess, "after_flush", recorder.after_flush)
        yield sess


def add_item(session: Session, recorder: Recorder, **values: Any) -> Item:
    item = Item(id=1, **values)
    session.add(item)
    session.commit()
    recorder.take()
    return item


def test_created_records_every_audited_column(
    session: Session, recorder: Recorder
) -> None:
    session.add(Item(id=1, name="Acme", secret="s", email="a@b.c", blob=b"\x00"))
    session.flush()
    [entry] = recorder.take()
    assert entry.kind == "created"
    assert entry.object_id == "1"
    assert entry.changes == {
        "id": [None, 1],
        "name": [None, "Acme"],
        "amount": [None, None],
        "happened_at": [None, None],
        "naive_at": [None, None],
        "secret": [None, REDACTED],
        "email": [None, hash_value("a@b.c", keys=KEYS)],
        # eager_defaults="auto" fetches the server default with RETURNING.
        "marker": [None, "x"],
        "notes": [None, None],
        "plain": [None, None],
        "tracked": [None, None],
        "snapped": [None, None],
    }


def test_update_records_only_net_changes(session: Session, recorder: Recorder) -> None:
    item = add_item(session, recorder, name="a", secret=None, email="a@b.c")
    item.name = "b"
    item.secret = "s"
    item.email = "a@b.c"
    session.flush()
    [entry] = recorder.take()
    assert entry.kind == "updated"
    assert entry.changes == {"name": ["a", "b"], "secret": [None, REDACTED]}


def test_update_of_expired_attribute_has_old_value(
    session: Session, recorder: Recorder
) -> None:
    """``active_history`` loads the old value when an expired column is set."""
    item = add_item(session, recorder, name="a", email="old@b.c")
    session.expire(item)
    item.name = "b"
    item.email = "new@b.c"
    session.flush()
    [entry] = recorder.take()
    assert entry.changes == {
        "name": ["a", "b"],
        "email": [hash_value("old@b.c", keys=KEYS), hash_value("new@b.c", keys=KEYS)],
    }


def test_update_without_net_change_writes_nothing(
    session: Session, recorder: Recorder
) -> None:
    """Equal values of a different form are no change.

    These cases mostly pin SQLAlchemy's own attribute history, which already
    compares with ``column.type.compare_values``; the snapshot test below is
    the one that exercises the comparison in ``entity_changes`` itself.
    """
    moment = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
    naive = moment.replace(tzinfo=None)
    item = add_item(
        session,
        recorder,
        amount=Decimal("1.50"),
        happened_at=moment,
        naive_at=naive,
    )
    session.refresh(item)
    item.amount = Decimal("1.5")
    item.happened_at = moment.astimezone(timezone(timedelta(hours=2)))
    item.naive_at = naive.replace()  # an equal, distinct object
    session.flush()
    assert recorder.take() == []


def test_redact_and_hash_to_null(session: Session, recorder: Recorder) -> None:
    item = add_item(session, recorder, secret="s", email="a@b.c")
    item.secret = None
    item.email = None
    session.flush()
    [entry] = recorder.take()
    assert entry.changes == {
        "secret": [REDACTED, None],
        "email": [hash_value("a@b.c", keys=KEYS), None],
    }


def test_deleted_records_old_values(session: Session, recorder: Recorder) -> None:
    item = add_item(session, recorder, name="Acme", secret="s")
    session.refresh(item)
    session.delete(item)
    session.flush()
    [entry] = recorder.take()
    assert entry.kind == "deleted"
    assert entry.object_id == "1"
    assert entry.changes["name"] == ["Acme", None]
    assert entry.changes["secret"] == [REDACTED, None]
    assert "blob" not in entry.changes
    # Deferred and never loaded: not read with SQL, marked unknown.
    assert entry.changes["notes"] == [UNKNOWN, None]


def test_primary_key_change_uses_old_object_id(
    session: Session, recorder: Recorder
) -> None:
    item = add_item(session, recorder, name="a")
    item.id = 2
    session.flush()
    [entry] = recorder.take()
    assert entry.object_id == "1"
    assert entry.changes == {"id": [1, 2]}
    assert object_id_of(item) == "2"


def test_composite_primary_key_object_id(session: Session, recorder: Recorder) -> None:
    pair = Pair(a="a", b=1, value="v")
    session.add(pair)
    session.flush()
    session.commit()
    pair.value = "w"
    session.flush()
    [created, updated] = recorder.take()
    assert created.object_id == updated.object_id == '["a","1"]'
    assert updated.object_id == object_id_for(Pair, ("a", 1))


def test_uuid_primary_key_object_id(session: Session, recorder: Recorder) -> None:
    value = uuid.UUID("0E4F5A1C-7B2D-4C3E-9F80-112233445566")
    session.add(Thing(id=value))
    session.commit()
    [entry] = recorder.take()
    assert entry.object_id == "0e4f5a1c-7b2d-4c3e-9f80-112233445566"
    thing = session.get(Thing, value)
    assert thing is not None
    assert object_id_of(thing) == object_id_for(Thing, value)


# --- JSON columns (ARCHITECTURE S3) ------------------------------------------


def test_plain_jsonb_in_place_change_is_not_detected(
    session: Session, recorder: Recorder, db: Engine
) -> None:
    """Documented limitation: SQLAlchemy neither sees nor writes the change."""
    item = add_item(session, recorder, plain={"a": 1})
    assert item.plain is not None
    item.plain["a"] = 2
    session.commit()
    assert recorder.take() == []
    with db.connect() as conn:
        stored: object = conn.execute(select(Item.plain)).scalar_one()
    assert stored == {"a": 1}


def test_plain_jsonb_assignment_has_full_history(
    session: Session, recorder: Recorder
) -> None:
    item = add_item(session, recorder, plain={"a": 1})
    item.plain = {"a": 2}
    session.flush()
    [entry] = recorder.take()
    assert entry.changes == {"plain": [{"a": 1}, {"a": 2}]}


def test_mutable_dict_without_snapshot_has_unknown_old_value(
    session: Session, recorder: Recorder
) -> None:
    item = add_item(session, recorder, tracked={"a": 1})
    assert item.tracked is not None
    item.tracked["b"] = 2
    session.flush()
    [entry] = recorder.take()
    assert entry.changes == {"tracked": [UNKNOWN, {"a": 1, "b": 2}]}


def test_snapshot_on_load_gives_old_value(session: Session, recorder: Recorder) -> None:
    item = add_item(session, recorder, snapped={"a": 1})
    assert item.snapped is not None  # reloaded after commit: refresh event
    item.snapped["b"] = 2
    session.flush()
    assert recorder.take()[0].changes == {"snapped": [{"a": 1}, {"a": 1, "b": 2}]}

    # The snapshot follows the flushed value, not the value first loaded.
    item.snapped["c"] = 3
    session.flush()
    assert recorder.take()[0].changes == {
        "snapped": [{"a": 1, "b": 2}, {"a": 1, "b": 2, "c": 3}]
    }


def test_snapshot_taken_on_query_load(
    db: Engine, recorder: Recorder, session: Session
) -> None:
    add_item(session, recorder, snapped={"a": 1})
    with Session(db) as other:
        event.listen(other, "after_flush", recorder.after_flush)
        loaded = other.get(Item, 1)
        assert loaded is not None and loaded.snapped is not None
        loaded.snapped["a"] = 2
        other.flush()
    assert recorder.take()[0].changes == {"snapped": [{"a": 1}, {"a": 2}]}


def test_snapshot_change_restored_in_place_writes_nothing(
    session: Session, recorder: Recorder
) -> None:
    """Proves the typed comparison in ``entity_changes``: SQLAlchemy's history
    reports the in-place change, only the snapshot comparison drops it."""
    item = add_item(session, recorder, snapped={"a": 1})
    assert item.snapped is not None
    item.snapped["a"] = 2
    item.snapped["a"] = 1
    session.flush()
    assert recorder.take() == []


def test_options_see_unset_columns_of_an_inserted_instance_as_null(
    session: Session, caplog: pytest.LogCaptureFixture
) -> None:
    seen: list[object] = []

    def after_flush(session: Session, flush_context: UOWTransaction) -> None:
        for obj in session.new:
            seen.append(resolve_label(obj, AuditOptions(label=lambda o: o.name)))
            seen.append(resolve_scope(obj, AuditOptions(scope=lambda o: o.notes)))
            seen.append(resolve_scope(obj, AuditOptions(scope=lambda o: o.marker)))

    event.listen(session, "after_flush", after_flush)
    with caplog.at_level(logging.WARNING, logger="audit_trail.diff"):
        session.add(Item(id=1))
        session.flush()
    # marker's server default is fetched back by the INSERT (eager_defaults).
    assert seen == [None, None, "x"]
    assert caplog.records == []


def test_options_fall_back_for_expired_attributes_of_a_persistent_instance(
    session: Session, recorder: Recorder
) -> None:
    item = add_item(session, recorder, name="a", notes="n")
    seen: list[object] = []

    def after_flush(session: Session, flush_context: UOWTransaction) -> None:
        for obj in session.dirty:
            # Setting amount reloads the expired row, but not the deferred notes.
            seen.append(resolve_scope(obj, AuditOptions(scope=lambda o: o.notes)))

    event.listen(session, "after_flush", after_flush)
    item.amount = Decimal("1.00")
    session.flush()
    assert seen == [USE_CONTEXT]
