"""Integrity columns, writer rows and migration DDL, without a database."""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from sqlalchemy import bindparam, select
from sqlalchemy.dialects.postgresql.base import PGDialect
from sqlalchemy.schema import CreateTable

from audit_trail import migrations
from audit_trail._compaction import ActivityData, ActivityRow
from audit_trail.integrity import _schema
from audit_trail.integrity._types import Xid8
from audit_trail.query import _ACTIVITY_COLUMNS, _HEADER_COLUMNS, TransactionHeader
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


def test_reads_list_every_column_but_the_integrity_ones() -> None:
    assert list(_schema.INTEGRITY_COLUMNS) == INTEGRITY_COLUMNS
    assert list(_ACTIVITY_COLUMNS) == ACTIVITY_COLUMNS
    assert list(_HEADER_COLUMNS) == TRANSACTION_COLUMNS


def test_every_read_column_reaches_the_row() -> None:
    # The read lists follow the tables, so a column added to a table later is
    # read; the rows built from the reads must carry it too.
    assert list(ActivityRow.__annotations__) == list(_ACTIVITY_COLUMNS)
    fields = {field.name for field in dataclasses.fields(TransactionHeader)}
    assert set(_HEADER_COLUMNS) <= fields


# -- the block table ------------------------------------------------------------


def test_the_block_table_is_declared_only_with_integrity() -> None:
    assert build_tables().seal_block is None
    tables = build_tables(integrity=True)
    block = tables.seal_block
    assert block is not None
    assert block.metadata is tables.metadata
    assert block.fullname == f"audit.{_schema.BLOCK_TABLE}"
    sql = migrations.create_sql(tables, [10])
    assert "CREATE TABLE audit.audit_seal_block" in sql
    assert "body BYTEA NOT NULL" in sql
    assert (
        "CREATE UNIQUE INDEX audit_seal_block_retired_partition_key ON "
        "audit.audit_seal_block (retired_partition) WHERE retired_partition IS NOT NULL"
    ) in sql
    assert migrations.drop_sql(tables).startswith(
        "DROP TABLE IF EXISTS audit.audit_seal_block;"
    )


def test_the_block_table_name_is_configurable() -> None:
    tables = build_tables(schema="s", seal_block_table="chain", integrity=True)
    assert tables.seal_block is not None
    assert tables.seal_block.fullname == "s.chain"
    sql = migrations.create_sql(tables, [10])
    assert "CREATE TABLE s.chain" in sql
    assert "CONSTRAINT chain_kind_check" in sql
    assert "CREATE UNIQUE INDEX chain_retired_partition_key ON s.chain" in sql
    assert "audit_seal_block" not in sql
    assert "s.chain" in migrations.add_integrity_statements(tables)[-2]


@pytest.mark.parametrize(
    ("names", "message"),
    [
        ({"seal_block_table": ""}, "must not be empty"),
        ({"seal_block_table": "b" * 42}, "longer than 41 bytes"),
        ({"seal_block_table": "audit_activity"}, "must differ"),
        ({"seal_block_table": "x", "transaction_table": "x"}, "must differ"),
    ],
)
def test_the_block_table_name_is_checked(names: dict[str, str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_tables(integrity=True, **names)


def test_add_integrity_creates_the_block_table_if_missing() -> None:
    statements = migrations.add_integrity_statements(build_tables(schema="s"))
    assert "CREATE TABLE IF NOT EXISTS s.audit_seal_block" in statements[-2]
    assert statements[-1].startswith("CREATE UNIQUE INDEX IF NOT EXISTS")


def test_add_integrity_names_the_block_table_also_without_integrity() -> None:
    # The tables of an install that has no integrity yet.
    tables = build_tables(schema="s", seal_block_table="chain")
    assert tables.seal_block is None
    statements = migrations.add_integrity_statements(tables)
    assert "CREATE TABLE IF NOT EXISTS s.chain" in statements[-2]
    assert "ON s.chain" in statements[-1]
    assert not any("audit_seal_block" in s for s in statements)
