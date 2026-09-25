"""``scrub`` and ``scrub_actor`` against a real PostgreSQL.

Most rows are inserted directly with fixed timestamps in January and March
2026, in partitions created for those months. The ``audit.scrubbed`` entry
of a scrub is stamped by the database with ``now()`` and lands in the
current month's partition, which ``create_trail`` creates; no test reads
its timestamp.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, cast

import pytest
from sqlalchemy import Connection, Engine, MetaData, insert, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from audit_trail import AuditContext, Audited, AuditOptions, AuditTrail
from audit_trail._compaction import ActivityData, ActivityRow, compact_rows
from audit_trail.maintenance import ensure_partitions
from audit_trail.privacy import ScrubNotAllowedError, ScrubResult, scrub_statement
from audit_trail.tables import AuditTables
from audit_trail.writer import Entry
from tests.db.listener_support import Sev, create_trail, record_statements

JAN = datetime(2026, 1, 10, 12, tzinfo=timezone.utc)
MAR = datetime(2026, 3, 10, 12, tzinfo=timezone.utc)
MARCH_1 = datetime(2026, 3, 1, tzinfo=timezone.utc)
UPDATED = "entity.updated"
SCRUBBED = "audit.scrubbed"

ADMIN = AuditContext(
    actor_type="user",
    actor_id="admin-1",
    actor_label="Admin",
    remote_addr="10.9.9.9",
)

# Personal data seeded into the rows a scrub erases; none of it may appear in
# an audit.scrubbed entry.
ERASED_VALUES = [
    "Old title",
    "New title",
    "ann@example.com",
    "bob@example.com",
    "x@example.com",
    "Doc One",
    "Page Five",
    "secret text",
    "10.0.0.1",
    "Firefox",
    "T-42",
]


def add_months(engine: Engine, tables: AuditTables) -> None:
    """Partitions for January to March 2026."""
    with engine.begin() as conn:
        ensure_partitions(
            conn,
            tables,
            list(Sev),
            months_ahead=2,
            now=datetime(2026, 1, 15, tzinfo=timezone.utc),
        )


def make_entry(
    object_type: str,
    object_id: str,
    data: dict[str, Any],
    *,
    verb: str = UPDATED,
    label: str | None = None,
    target: tuple[str, str] | None = None,
    actor_id: str | None = None,
) -> Entry:
    return {
        "verb": verb,
        "severity": int(Sev.LOW),
        "object_type": object_type,
        "object_id": object_id,
        "object_label": label,
        "target_type": None if target is None else target[0],
        "target_id": None if target is None else target[1],
        "actor_id": actor_id,
        "scope_id": None,
        "data": cast("ActivityData", {"v": 1, **data}),
    }


def add(
    conn: Connection,
    tables: AuditTables,
    entry: Entry,
    *,
    at: datetime,
    transaction: dict[str, object] | None = None,
) -> int:
    """Insert one transaction row and one activity row at ``at``."""
    transaction_id: int = conn.execute(
        insert(tables.transaction)
        .values(
            issued_at=at,
            actor_type="user",
            actor_id=entry["actor_id"],
            **(transaction or {}),
        )
        .returning(tables.transaction.c.id)
    ).scalar_one()
    activity_id: int = conn.execute(
        insert(tables.activity)
        .values(**entry, transaction_id=transaction_id, created_at=at)
        .returning(tables.activity.c.id)
    ).scalar_one()
    return activity_id


def activities(engine: Engine, tables: AuditTables) -> dict[int, dict[str, Any]]:
    table = tables.activity
    with engine.connect() as conn:
        rows = conn.execute(select(table).order_by(table.c.id)).mappings()
        return {row["id"]: dict(row) for row in rows}


def transactions(engine: Engine, tables: AuditTables) -> dict[int, dict[str, Any]]:
    table = tables.transaction
    with engine.connect() as conn:
        rows = conn.execute(select(table).order_by(table.c.id)).mappings()
        return {row["id"]: dict(row) for row in rows}


def scrubbed_entries(engine: Engine, tables: AuditTables) -> list[dict[str, Any]]:
    return [
        row for row in activities(engine, tables).values() if row["verb"] == SCRUBBED
    ]


CONTEXT = {"actor_type": "user", "actor_label": "ann@example.com"}


@dataclass
class Seed:
    """Ids of the seeded activity rows."""

    doc_jan: int
    doc_mar: int
    child: int
    other_doc: int
    other_type: int


def seed(engine: Engine, tables: AuditTables) -> Seed:
    with engine.begin() as conn:
        doc_jan = add(
            conn,
            tables,
            make_entry(
                "Doc",
                "1",
                {
                    "changes": {
                        "title": ["Old title", "New title"],
                        "note": [None, "ann@example.com"],
                        "tags": {"added": ["7", "9"], "removed": ["8"]},
                        "settings": [{"owner": "ann@example.com"}, None],
                    },
                    "context": CONTEXT,
                },
                label="Doc One",
            ),
            at=JAN,
        )
        doc_mar = add(
            conn,
            tables,
            make_entry(
                "Doc",
                "1",
                {
                    "payload": {
                        "email": "bob@example.com",
                        "nested": {"to": ["x@example.com"], "x@example.com": 1},
                        "count": 3,
                        "none": None,
                    },
                    "context": CONTEXT,
                },
                verb="doc.shared",
                label="Doc One",
            ),
            at=MAR,
        )
        child = add(
            conn,
            tables,
            make_entry(
                "Page",
                "5",
                {"changes": {"text": [None, "secret text"]}, "context": CONTEXT},
                verb="entity.created",
                label="Page Five",
                target=("Doc", "1"),
            ),
            at=JAN,
        )
        other_doc = add(
            conn,
            tables,
            make_entry("Doc", "2", {"changes": {"title": ["a", "b"]}}, label="Doc Two"),
            at=JAN,
        )
        other_type = add(
            conn,
            tables,
            make_entry("Page", "1", {"changes": {"title": ["c", "d"]}}, label="P1"),
            at=MAR,
        )
    return Seed(doc_jan, doc_mar, child, other_doc, other_type)


@pytest.fixture
def trail(engine: Engine, schema: str) -> AuditTrail:
    t = create_trail(engine, schema, allow_scrub=True)
    add_months(engine, t.tables)
    return t


ERASED_DOC_JAN_CHANGES = {
    "title": ["[erased]", "[erased]"],
    "note": [None, "[erased]"],
    "tags": {"added": ["[erased]", "[erased]"], "removed": ["[erased]"]},
    "settings": ["[erased]", None],
}
ERASED_DOC_MAR_PAYLOAD = {
    "email": "[erased]",
    "nested": "[erased]",
    "count": "[erased]",
    "none": None,
}


def test_scrub_erases_values_and_keeps_keys(engine: Engine, trail: AuditTrail) -> None:
    ids = seed(engine, trail.tables)
    before = activities(engine, trail.tables)

    with trail.context(ADMIN):
        result = trail.scrub("Doc", "1")

    assert result == ScrubResult(activity_rows=3, transaction_rows=0)
    after = activities(engine, trail.tables)
    assert after[ids.doc_jan]["data"] == {
        "v": 1,
        "changes": ERASED_DOC_JAN_CHANGES,
        "context": CONTEXT,
    }
    assert after[ids.doc_mar]["data"] == {
        "v": 1,
        "payload": ERASED_DOC_MAR_PAYLOAD,
        "context": CONTEXT,
    }
    assert after[ids.child]["data"] == {
        "v": 1,
        "changes": {"text": [None, "[erased]"]},
        "context": CONTEXT,
    }
    for row_id in (ids.doc_jan, ids.doc_mar, ids.child):
        assert after[row_id]["object_label"] is None
        rest = {
            k: v for k, v in after[row_id].items() if k not in {"data", "object_label"}
        }
        assert rest == {
            k: v for k, v in before[row_id].items() if k not in {"data", "object_label"}
        }
    assert after[ids.other_doc] == before[ids.other_doc]
    assert after[ids.other_type] == before[ids.other_type]


def test_scrub_without_targets_leaves_children(
    engine: Engine, trail: AuditTrail
) -> None:
    ids = seed(engine, trail.tables)
    before = activities(engine, trail.tables)

    result = trail.scrub("Doc", "1", include_targets=False)

    assert result == ScrubResult(activity_rows=2, transaction_rows=0)
    after = activities(engine, trail.tables)
    assert after[ids.child] == before[ids.child]
    assert after[ids.doc_jan]["data"]["changes"] == ERASED_DOC_JAN_CHANGES


def test_scrub_since_leaves_older_entries(engine: Engine, trail: AuditTrail) -> None:
    ids = seed(engine, trail.tables)
    before = activities(engine, trail.tables)

    result = trail.scrub("Doc", "1", since=MARCH_1)

    assert result == ScrubResult(activity_rows=1, transaction_rows=0)
    after = activities(engine, trail.tables)
    assert after[ids.doc_mar]["data"]["payload"] == ERASED_DOC_MAR_PAYLOAD
    assert after[ids.doc_jan] == before[ids.doc_jan]
    assert after[ids.child] == before[ids.child]


def test_scrub_records_what_without_erased_values(
    engine: Engine, trail: AuditTrail
) -> None:
    seed(engine, trail.tables)
    before = set(transactions(engine, trail.tables))

    with trail.context(ADMIN):
        trail.scrub("Doc", "1", since=MARCH_1)

    (record,) = scrubbed_entries(engine, trail.tables)
    assert record["data"] == {
        "v": 1,
        "payload": {
            "operation": "scrub",
            "object_type": "Doc",
            "object_id": "1",
            "include_targets": True,
            "since": "2026-03-01T00:00:00+00:00",
            "activity_rows": 1,
        },
        "context": {
            "actor_type": "user",
            "actor_label": "Admin",
            "remote_addr": "10.9.9.9",
        },
    }
    assert (record["severity"], record["actor_id"]) == (Sev.HIGH, "admin-1")
    assert (record["object_type"], record["object_id"]) == ("Doc", "1")
    assert record["object_label"] is None
    assert (record["target_type"], record["target_id"]) == (None, None)
    (new_transaction,) = [
        row
        for row_id, row in transactions(engine, trail.tables).items()
        if row_id not in before
    ]
    assert new_transaction["id"] == record["transaction_id"]
    assert (new_transaction["actor_id"], new_transaction["actor_label"]) == (
        "admin-1",
        "Admin",
    )
    stored = json.dumps(record["data"]) + json.dumps(new_transaction, default=str)
    assert [value for value in ERASED_VALUES if value in stored] == []


def test_repeated_scrub_changes_nothing_and_keeps_the_record(
    engine: Engine, trail: AuditTrail
) -> None:
    seed(engine, trail.tables)
    trail.scrub("Doc", "1")
    before = activities(engine, trail.tables)

    result = trail.scrub("Doc", "1")

    assert result == ScrubResult(activity_rows=0, transaction_rows=0)
    after = activities(engine, trail.tables)
    first, second = scrubbed_entries(engine, trail.tables)
    assert after[first["id"]] == before[first["id"]]
    assert {k: v for k, v in after.items() if k != second["id"]} == before
    assert second["data"]["payload"]["activity_rows"] == 0


def test_scrub_records_the_context_provider_actor(engine: Engine, schema: str) -> None:
    trail = create_trail(
        engine, schema, allow_scrub=True, context_provider=lambda: ADMIN
    )
    add_months(engine, trail.tables)
    seed(engine, trail.tables)

    trail.scrub("Doc", "1")

    (record,) = scrubbed_entries(engine, trail.tables)
    assert record["actor_id"] == "admin-1"
    assert record["data"]["context"]["actor_label"] == "Admin"


def test_empty_ids_match_nothing(engine: Engine, trail: AuditTrail) -> None:
    seed(engine, trail.tables)
    with engine.begin() as conn:
        add(conn, trail.tables, make_entry("Doc", "", {}, actor_id=""), at=JAN)
    before = activities(engine, trail.tables)

    assert trail.scrub("", "") == ScrubResult(0, 0)
    assert trail.scrub("Doc", "") == ScrubResult(0, 0)
    assert trail.scrub_actor("") == ScrubResult(0, 0)

    after = activities(engine, trail.tables)
    assert {k: v for k, v in after.items() if k in before} == before


def test_scrub_is_refused_without_allow_scrub(engine: Engine, schema: str) -> None:
    trail = create_trail(engine, schema)
    add_months(engine, trail.tables)
    seed(engine, trail.tables)
    before = activities(engine, trail.tables)

    with record_statements(engine) as log:
        log.recording = True
        with pytest.raises(ScrubNotAllowedError):
            trail.scrub("Doc", "1")
        with pytest.raises(ScrubNotAllowedError):
            trail.scrub_actor("u1")
        log.recording = False

    assert log.statements == []
    assert activities(engine, trail.tables) == before


def test_naive_since_is_refused(trail: AuditTrail) -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        trail.scrub("Doc", "1", since=datetime(2026, 3, 1))  # noqa: DTZ001


def test_autocommit_engine_is_refused(engine: Engine, schema: str) -> None:
    auto = engine.execution_options(isolation_level="AUTOCOMMIT")
    trail = create_trail(engine, schema, trail_engine=auto, allow_scrub=True)
    add_months(engine, trail.tables)
    seed(engine, trail.tables)
    before = activities(engine, trail.tables)

    with pytest.raises(ValueError, match="AUTOCOMMIT"):
        trail.scrub("Doc", "1")
    with pytest.raises(ValueError, match="AUTOCOMMIT"):
        trail.scrub_actor("u1")

    assert activities(engine, trail.tables) == before


def test_scrub_fails_whole_without_a_partition_for_its_record(
    engine: Engine, schema: str
) -> None:
    trail = create_trail(engine, schema, partitions=[], allow_scrub=True)
    add_months(engine, trail.tables)
    seed(engine, trail.tables)
    before = activities(engine, trail.tables)

    with pytest.raises(DBAPIError):
        trail.scrub("Doc", "1")
    with pytest.raises(DBAPIError):
        trail.scrub_actor("u1")

    assert activities(engine, trail.tables) == before


@pytest.mark.parametrize("operation", ["scrub", "scrub_actor"])
def test_auto_create_partitions_creates_the_current_month_first(
    engine: Engine, schema: str, operation: str
) -> None:
    trail = create_trail(
        engine, schema, partitions=[], allow_scrub=True, auto_create_partitions=True
    )
    add_months(engine, trail.tables)
    seed(engine, trail.tables)

    if operation == "scrub":
        assert trail.scrub("Doc", "1").activity_rows == 3
    else:
        trail.scrub_actor("u1")

    (record,) = scrubbed_entries(engine, trail.tables)
    assert record["data"]["payload"]["operation"] == operation


def test_plan_skips_months_before_since(engine: Engine, trail: AuditTrail) -> None:
    statement = scrub_statement(
        trail.tables, "Doc", "1", include_targets=True, since=MARCH_1
    )
    with engine.connect() as conn:
        compiled = statement.compile(
            dialect=conn.dialect, compile_kwargs={"literal_binds": True}
        )
        plan: list[object] = conn.exec_driver_sql(
            f"EXPLAIN (FORMAT JSON) {compiled}"
        ).scalar_one()

    relations: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            name = node.get("Relation Name")
            if isinstance(name, str):
                relations.add(name)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(plan)
    assert "audit_activity_10_p2026_03" in relations
    assert "audit_activity_40_p2026_03" in relations
    assert not {name for name in relations if name.endswith(("_p2026_01", "_p2026_02"))}


# scrub_actor, with rows written by the session listener


@dataclass
class Models:
    Note: Any


@pytest.fixture
def models(engine: Engine, schema: str) -> Models:
    class Base(DeclarativeBase):
        metadata = MetaData(schema=schema)

    class Note(Base, Audited):
        __tablename__ = "note"
        id: Mapped[int] = mapped_column(primary_key=True)
        title: Mapped[str]

        __audit__ = AuditOptions(label=lambda note: note.title)

    Base.metadata.create_all(engine)
    return Models(Note)


SessionMaker = Callable[[], Any]


@pytest.fixture
def sessions(
    engine: Engine, trail: AuditTrail, models: Models
) -> Iterator[SessionMaker]:
    factory = sessionmaker(engine)
    trail.install(factory)
    yield factory


def ann(**changes: Any) -> AuditContext:
    values: dict[str, Any] = {
        "actor_type": "user",
        "actor_id": "u1",
        "actor_label": "ann@example.com",
        "remote_addr": "10.0.0.1",
        "user_agent": "Firefox",
        "method": "POST",
        "path": "/notes",
        "extra": {"ticket": "T-42"},
    }
    values.update(changes)
    return AuditContext(**values)


BOB = AuditContext(
    actor_type="user",
    actor_id="u2",
    actor_label="bob@example.com",
    remote_addr="10.0.0.2",
    user_agent="Safari",
    extra={"ticket": "T-7"},
)


def test_scrub_actor_clears_context_and_meta(
    engine: Engine, trail: AuditTrail, sessions: SessionMaker, models: Models
) -> None:
    with trail.context(ann()), sessions() as session:
        session.add(models.Note(id=1, title="a"))
        session.commit()
    with trail.context(BOB), sessions() as session:
        session.add(models.Note(id=2, title="b"))
        session.commit()
    ((ann_tx_id, ann_tx), (bob_tx_id, bob_tx)) = transactions(
        engine, trail.tables
    ).items()
    ann_row, bob_row = activities(engine, trail.tables).values()
    assert ann_tx["meta"] == {"ticket": "T-42"}
    assert ann_row["data"]["context"]["meta"] == {"ticket": "T-42"}

    with trail.context(ADMIN):
        result = trail.scrub_actor("u1")

    assert result == ScrubResult(activity_rows=1, transaction_rows=1)
    after_tx = transactions(engine, trail.tables)
    assert after_tx[ann_tx_id] == {
        **ann_tx,
        "actor_label": None,
        "remote_addr": None,
        "user_agent": None,
        "meta": None,
    }
    assert after_tx[ann_tx_id]["actor_id"] == "u1"
    assert after_tx[bob_tx_id] == bob_tx
    after = activities(engine, trail.tables)
    assert after[ann_row["id"]] == {
        **ann_row,
        "data": {
            **ann_row["data"],
            "context": {"actor_type": "user", "method": "POST", "path": "/notes"},
        },
    }
    assert after[ann_row["id"]]["actor_id"] == "u1"
    assert after[bob_row["id"]] == bob_row

    (record,) = scrubbed_entries(engine, trail.tables)
    assert record["data"] == {
        "v": 1,
        "payload": {
            "operation": "scrub_actor",
            "actor_id": "u1",
            "transaction_rows": 1,
            "activity_rows": 1,
        },
        "context": {
            "actor_type": "user",
            "actor_label": "Admin",
            "remote_addr": "10.9.9.9",
        },
    }
    assert (record["object_type"], record["object_id"]) == (None, None)
    assert record["actor_id"] == "admin-1"
    stored = json.dumps(record["data"]) + json.dumps(
        after_tx[record["transaction_id"]], default=str
    )
    assert [value for value in ERASED_VALUES if value in stored] == []


def test_scrub_actor_run_by_the_actor_records_no_personal_context(
    engine: Engine, trail: AuditTrail, sessions: SessionMaker, models: Models
) -> None:
    with trail.context(ann()), sessions() as session:
        session.add(models.Note(id=1, title="a"))
        session.commit()

    with trail.context(ann()):
        trail.scrub_actor("u1")

    (record,) = scrubbed_entries(engine, trail.tables)
    assert record["data"]["context"] == {
        "actor_type": "user",
        "method": "POST",
        "path": "/notes",
    }
    record_tx = transactions(engine, trail.tables)[record["transaction_id"]]
    assert (record_tx["actor_label"], record_tx["remote_addr"]) == (None, None)
    assert (record_tx["user_agent"], record_tx["meta"]) == (None, None)
    assert record_tx["method"] == "POST"


def as_activity_row(row: dict[str, Any]) -> ActivityRow:
    return {
        "id": row["id"],
        "transaction_id": row["transaction_id"],
        "verb": row["verb"],
        "severity": row["severity"],
        "object_type": row["object_type"],
        "object_id": row["object_id"],
        "object_label": row["object_label"],
        "target_type": row["target_type"],
        "target_id": row["target_id"],
        "actor_id": row["actor_id"],
        "scope_id": row["scope_id"],
        "correlation_id": row["correlation_id"],
        "created_at": row["created_at"],
        "data": row["data"],
    }


def test_compaction_keeps_scrubbed_updates(
    engine: Engine, trail: AuditTrail, sessions: SessionMaker, models: Models
) -> None:
    with sessions() as session:
        session.add(models.Note(id=1, title="a"))
        session.commit()
        note = session.get(models.Note, 1)
        note.title = "b"
        session.flush()
        note.title = "c"
        session.commit()

    trail.scrub("Note", "1")

    rows = [
        as_activity_row(row)
        for row in activities(engine, trail.tables).values()
        if row["verb"] == UPDATED
    ]
    assert len(rows) == 2
    (merged,) = compact_rows(rows)
    assert merged["verb"] == UPDATED
    assert merged["data"]["changes"] == {"title": ["[erased]", "[erased]"]}


# Async


@pytest.fixture
def async_trail(engine: Engine, schema: str, async_engine: AsyncEngine) -> AuditTrail:
    t = create_trail(engine, schema, trail_engine=async_engine, allow_scrub=True)
    add_months(engine, t.tables)
    return t


async def test_ascrub_erases_and_records(
    engine: Engine, async_trail: AuditTrail
) -> None:
    ids = seed(engine, async_trail.tables)

    with async_trail.context(ADMIN):
        result = await async_trail.ascrub("Doc", "1", since=MARCH_1)

    assert result == ScrubResult(activity_rows=1, transaction_rows=0)
    after = activities(engine, async_trail.tables)
    assert after[ids.doc_mar]["data"]["payload"] == ERASED_DOC_MAR_PAYLOAD
    assert after[ids.doc_mar]["object_label"] is None
    (record,) = scrubbed_entries(engine, async_trail.tables)
    assert record["data"]["payload"]["since"] == "2026-03-01T00:00:00+00:00"
    assert record["actor_id"] == "admin-1"


async def test_ascrub_actor_clears_context(
    engine: Engine, async_trail: AuditTrail
) -> None:
    with engine.begin() as conn:
        row_id = add(
            conn,
            async_trail.tables,
            make_entry(
                "Doc",
                "1",
                {
                    "changes": {},
                    "context": {"actor_type": "user", "user_agent": "Firefox"},
                },
                actor_id="u1",
            ),
            at=JAN,
            transaction={"actor_label": "ann@example.com", "meta": {"k": "v"}},
        )

    result = await async_trail.ascrub_actor("u1")

    assert result == ScrubResult(activity_rows=1, transaction_rows=1)
    row = activities(engine, async_trail.tables)[row_id]
    assert row["data"]["context"] == {"actor_type": "user"}
    (tx,) = [
        t
        for t in transactions(engine, async_trail.tables).values()
        if t["id"] == row["transaction_id"]
    ]
    assert (tx["actor_label"], tx["meta"]) == (None, None)
    (record,) = scrubbed_entries(engine, async_trail.tables)
    assert record["data"]["payload"]["operation"] == "scrub_actor"


async def test_async_scrub_is_refused_without_allow_scrub(
    engine: Engine, schema: str, async_engine: AsyncEngine
) -> None:
    trail = create_trail(engine, schema, trail_engine=async_engine)
    add_months(engine, trail.tables)
    seed(engine, trail.tables)
    before = activities(engine, trail.tables)

    with record_statements(async_engine.sync_engine) as log:
        log.recording = True
        with pytest.raises(ScrubNotAllowedError):
            await trail.ascrub("Doc", "1")
        with pytest.raises(ScrubNotAllowedError):
            await trail.ascrub_actor("u1")
        log.recording = False

    assert log.statements == []
    assert activities(engine, trail.tables) == before


async def test_sync_methods_refuse_an_async_engine(async_trail: AuditTrail) -> None:
    with pytest.raises(TypeError, match="use ascrub$"):
        async_trail.scrub("Doc", "1")
    with pytest.raises(TypeError, match="use ascrub_actor"):
        async_trail.scrub_actor("u1")


async def test_async_methods_refuse_a_sync_engine(trail: AuditTrail) -> None:
    with pytest.raises(TypeError, match="use scrub$"):
        await trail.ascrub("Doc", "1")
    with pytest.raises(TypeError, match="use scrub_actor"):
        await trail.ascrub_actor("u1")
