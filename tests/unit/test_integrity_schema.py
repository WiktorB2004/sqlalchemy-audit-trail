"""Integrity columns, writer rows and migration DDL, without a database."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import pytest
from sqlalchemy import bindparam, select
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.schema import CreateTable

from audit_trail import migrations
from audit_trail._compaction import ActivityData
from audit_trail.integrity import _schema
from audit_trail.integrity._types import Xid8
from audit_trail.query import _ACTIVITY_COLUMNS, _HEADER_COLUMNS
from audit_trail.tables import build_tables
from audit_trail.writer import Entry, TransactionRow, activity_rows

DIALECT = PGDialect()  # type: ignore[no-untyped-call]

# The columns of the tables before integrity existed; integrity=False must
# keep exactly these.
TRANSACTION_COLUMNS = [
    "id",
    "issued_at",
    "actor_type",
    "actor_id",
    "actor_label",
    "remote_addr",
    "user_agent",
    "method",
    "path",
    "channel",
    "auth_method",
    "request_id",
    "correlation_id",
    "meta",
]
ACTIVITY_COLUMNS = [
    "id",
    "transaction_id",
    "verb",
    "severity",
    "object_type",
    "object_id",
    "object_label",
    "target_type",
    "target_id",
    "actor_id",
    "scope_id",
    "correlation_id",
    "created_at",
    "data",
]
INTEGRITY_COLUMNS = ["xid", "seal_commitments", "seal_salts", "seal_erased"]


def entry(**fields: Any) -> Entry:
    base: Entry = {
        "verb": "entity.updated",
        "severity": 10,
        "object_type": "Doc",
        "object_id": "1",
        "object_label": None,
        "target_type": None,
        "target_id": None,
        "actor_id": None,
        "scope_id": None,
        "data": cast("ActivityData", {"v": 1}),
    }
    base.update(cast("Entry", fields))
    return base


# Entries whose present groups differ: the first has none, later ones some.
MIXED_ENTRIES = [
    entry(),
    entry(object_label="Doc", data={"v": 1, "changes": {"a": [1, 2]}}),
    entry(data={"v": 1, "payload": {"p": 1}, "context": {"actor_label": "Ann"}}),
]
ROW = TransactionRow(1, datetime(2026, 1, 1, tzinfo=UTC), None)


@pytest.mark.parametrize("integrity", [False, True])
def test_activity_rows_share_one_key_set(integrity: bool) -> None:
    # executemany takes its columns from the first row: a later row missing a
    # key raises, and a later row with an extra key loses it silently.
    tables = build_tables(integrity=integrity)
    rows = activity_rows(tables.activity, ROW, MIXED_ENTRIES)
    first = set(rows[0])
    assert all(set(row) == first for row in rows)
    expected = {name for name in ACTIVITY_COLUMNS if name != "id"}
    if integrity:
        expected |= {"seal_commitments", "seal_salts", "seal_erased"}
    assert first == expected


def test_activity_rows_commit_to_each_rows_groups() -> None:
    tables = build_tables(integrity=True)
    rows = activity_rows(tables.activity, ROW, MIXED_ENTRIES)
    assert [set(cast("dict[str, str]", r["seal_salts"])) for r in rows] == [
        set(),
        {"label", "changes"},
        {"payload", "actor"},
    ]


def test_without_integrity_the_tables_are_unchanged() -> None:
    tables = build_tables()
    assert list(tables.transaction.c.keys()) == TRANSACTION_COLUMNS
    assert list(tables.activity.c.keys()) == ACTIVITY_COLUMNS
    sql = migrations.create_sql(tables, [10, 40])
    assert "xid" not in sql
    assert "seal_" not in sql


def test_with_integrity_the_tables_have_the_columns() -> None:
    tables = build_tables(integrity=True)
    assert list(tables.transaction.c.keys()) == TRANSACTION_COLUMNS + INTEGRITY_COLUMNS
    assert list(tables.activity.c.keys()) == ACTIVITY_COLUMNS + INTEGRITY_COLUMNS
    ddl = str(CreateTable(tables.activity).compile(dialect=DIALECT))
    assert "xid xid8 DEFAULT pg_current_xact_id() NOT NULL" in ddl
    sql = migrations.create_sql(tables, [10])
    assert (
        "CREATE INDEX audit_activity_xid_idx ON audit.audit_activity (xid, id)" in sql
    )
    assert (
        "CREATE INDEX audit_transaction_xid_idx ON audit.audit_transaction (xid, id)"
        in sql
    )


def test_add_integrity_sets_the_default_in_its_own_statement() -> None:
    # One-step ADD COLUMN ... DEFAULT pg_current_xact_id() would stamp every
    # existing row with the migration's xid (the function is STABLE).
    statements = migrations.add_integrity_statements(build_tables())
    adds = [s for s in statements if "ADD COLUMN" in s]
    defaults = [s for s in statements if "SET DEFAULT" in s]
    assert len(adds) == len(defaults) == 2
    assert all("DEFAULT" not in s for s in adds)
    assert statements.index(adds[0]) < statements.index(defaults[0])


def test_xid8_binds_text_then_casts() -> None:
    statement = select(bindparam("x", 5, type_=Xid8()))
    compiled = statement.compile(dialect=DIALECT)
    assert "CAST(CAST(%(x)s AS TEXT) AS xid8)" in str(compiled)
    processor = Xid8().bind_processor(DIALECT)
    assert processor is not None
    assert processor(5) == "5"


@pytest.mark.parametrize("integrity", [False, True])
def test_reads_list_every_column_but_the_integrity_ones(integrity: bool) -> None:
    # A column added to a table later must be added to the read lists too, or
    # reads silently drop it.
    tables = build_tables(integrity=integrity)
    left_out = {_schema.XID, *_schema.SEAL_COLUMNS}
    for table, read in (
        (tables.activity, _ACTIVITY_COLUMNS),
        (tables.transaction, _HEADER_COLUMNS),
    ):
        names = [column.name for column in table.columns]
        assert sorted(read) == sorted(set(names) - left_out)
        assert len(set(read)) == len(read)
