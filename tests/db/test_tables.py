"""Audit tables, DDL and indexes against a real PostgreSQL."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime, timezone
from enum import IntEnum

import pytest
from sqlalchemy import Connection, Engine, insert, select, text
from sqlalchemy.exc import DBAPIError

from audit_trail.maintenance import ensure_partitions
from audit_trail.migrations import (
    create_audit_tables,
    create_sql,
    drop_audit_tables,
    qualified_name,
)
from audit_trail.tables import (
    ALL_INDEXES,
    DEFAULT_INDEXES,
    OPTIONAL_INDEXES,
    AuditTables,
    build_tables,
)


class Sev(IntEnum):
    INFO = 10
    NOTICE = 20
    WARNING = 30
    CRITICAL = 40


SEPT = datetime(2026, 9, 10, 12, tzinfo=timezone.utc)


@pytest.fixture
def tables(engine: Engine, schema: str) -> AuditTables:
    t = build_tables(schema=schema)
    with engine.begin() as conn:
        create_audit_tables(conn, t, Sev)
    return t


def index_defs(conn: Connection, schema: str, table: str) -> dict[str, str]:
    rows = conn.execute(
        text(
            "SELECT indexname, indexdef FROM pg_indexes "
            "WHERE schemaname = :schema AND tablename = :table"
        ),
        {"schema": schema, "table": table},
    )
    return dict(rows.all())


def sqlstate(exc: DBAPIError) -> str | None:
    return getattr(exc.orig, "sqlstate", None)


def test_partitioning_layout_without_default(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    with engine.begin() as conn:
        ensure_partitions(conn, tables, Sev, now=SEPT)
        layout: dict[str, str] = dict(
            conn.execute(
                text(
                    """
                    SELECT c.relname,
                           p.partstrat::text || ':' || pg_get_partkeydef(c.oid)
                               || ':' || (p.partdefid = 0)::text
                    FROM pg_partitioned_table p
                    JOIN pg_class c ON c.oid = p.partrelid
                    JOIN pg_namespace n ON n.oid = c.relnamespace
                    WHERE n.nspname = :schema
                    """
                ),
                {"schema": schema},
            ).all()
        )

    assert layout == {
        "audit_transaction": "r:RANGE (issued_at):true",
        "audit_activity": "l:LIST (severity):true",
        **{f"audit_activity_{s.value}": "r:RANGE (created_at):true" for s in Sev},
    }


def test_default_indexes_on_parent_and_partitions(
    engine: Engine, tables: AuditTables, schema: str
) -> None:
    with engine.begin() as conn:
        ensure_partitions(conn, tables, Sev, now=SEPT)
        parent = index_defs(conn, schema, "audit_activity")
        leaf = index_defs(conn, schema, "audit_activity_30_p2026_09")

    expected = {f"audit_activity_{key}_idx" for key in DEFAULT_INDEXES}
    assert set(parent) == expected | {"audit_activity_pkey"}
    assert len(leaf) == len(parent)
    assert parent["audit_activity_target_idx"].endswith(
        "(target_type, target_id, created_at DESC, id DESC) "
        "WHERE (target_type IS NOT NULL)"
    )
    assert parent["audit_activity_scope_idx"].endswith(
        "(scope_id, created_at DESC, id DESC) WHERE (scope_id IS NOT NULL)"
    )
    assert parent["audit_activity_correlation_idx"].endswith(
        "(correlation_id, created_at) WHERE (correlation_id IS NOT NULL)"
    )


def test_index_subset_and_changes_gin(engine: Engine, schema: str) -> None:
    tables = build_tables(schema=schema, indexes={"severity", "changes_gin"})
    with engine.begin() as conn:
        create_audit_tables(conn, tables, Sev)
        ensure_partitions(conn, tables, Sev, now=SEPT)
        parent = index_defs(conn, schema, "audit_activity")
        conn.execute(text("SET LOCAL enable_seqscan = off"))
        plan = "\n".join(
            conn.execute(
                text(
                    "EXPLAIN SELECT id FROM "
                    f"{qualified_name(schema, 'audit_activity_10_p2026_09')} "
                    "WHERE data -> 'changes' ? 'email'"
                )
            ).scalars()
        )

    assert set(parent) == {
        "audit_activity_pkey",
        "audit_activity_severity_idx",
        "audit_activity_changes_gin_idx",
    }
    assert (
        "USING gin (((data -> 'changes'::text)))"
        in (parent["audit_activity_changes_gin_idx"])
    )
    # The key-exists query the index is for can use it.
    assert "Bitmap Index Scan" in plan
    assert "Index Cond: ((data -> 'changes'::text) ? 'email'::text)" in plan


def test_insert_into_every_severity_gets_identity(
    engine: Engine, tables: AuditTables
) -> None:
    with engine.begin() as conn:
        ensure_partitions(conn, tables, Sev)
        tx_id, issued_at = conn.execute(
            insert(tables.transaction)
            .values(actor_type="user", remote_addr="10.0.0.1")
            .returning(tables.transaction.c.id, tables.transaction.c.issued_at)
        ).one()
        ids: list[int] = [
            conn.execute(
                insert(tables.activity)
                .values(
                    transaction_id=tx_id,
                    verb="entity.created",
                    severity=severity,
                    created_at=issued_at,
                )
                .returning(tables.activity.c.id)
            ).scalar_one()
            for severity in Sev
        ]
        data: Sequence[object] = (
            conn.execute(select(tables.activity.c.data)).scalars().all()
        )

    assert tx_id is not None
    assert len(set(ids)) == len(Sev)
    assert data == [{}] * len(Sev)


@pytest.mark.parametrize("missing", ["month", "severity"])
def test_insert_without_partition_fails_with_23514(
    engine: Engine, tables: AuditTables, missing: str
) -> None:
    with engine.begin() as conn:
        ensure_partitions(conn, tables, Sev, now=SEPT)
    at, severity = (datetime(2030, 1, 1, tzinfo=timezone.utc), 10)
    if missing == "severity":
        at, severity = SEPT, 99

    with engine.begin() as conn, pytest.raises(DBAPIError) as activity_err:
        conn.execute(
            insert(tables.activity).values(
                transaction_id=1, verb="x", severity=severity, created_at=at
            )
        )
    assert sqlstate(activity_err.value) == "23514"
    assert "no partition of relation" in str(activity_err.value)

    if missing == "month":
        with engine.begin() as conn, pytest.raises(DBAPIError) as tx_err:
            conn.execute(
                insert(tables.transaction).values(actor_type="user", issued_at=at)
            )
        assert sqlstate(tx_err.value) == "23514"


def test_names_needing_quotes(engine: Engine) -> None:
    schema = 'Au"dit %s :x'
    tables = build_tables(
        schema=schema, transaction_table="Tx", activity_table="Act ivity"
    )
    try:
        with engine.begin() as conn:
            create_audit_tables(conn, tables, Sev)
            ensure_partitions(conn, tables, Sev)
            conn.execute(insert(tables.transaction).values(actor_type="user"))
            names: Iterable[str] = conn.execute(
                text(
                    "SELECT c.relname FROM pg_class c JOIN pg_namespace n "
                    "ON n.oid = c.relnamespace WHERE n.nspname = :schema"
                ),
                {"schema": schema},
            ).scalars()
            assert {"Tx", "Act ivity", "Act ivity_10"} <= set(names)
    finally:
        with engine.begin() as conn:
            conn.exec_driver_sql(
                f"DROP SCHEMA IF EXISTS {qualified_name(None, schema)} CASCADE",
                execution_options={"no_parameters": True},
            )


def test_create_sql_is_a_runnable_script(engine: Engine, schema: str) -> None:
    tables = build_tables(schema=schema)
    script = create_sql(tables, Sev)
    with engine.begin() as conn:
        conn.exec_driver_sql(script, execution_options={"no_parameters": True})
        ensure_partitions(conn, tables, Sev)
        conn.execute(insert(tables.transaction).values(actor_type="user"))

    assert "PARTITION BY LIST (severity);\n" in script
    assert "DEFAULT PARTITION" not in script.upper()


def test_drop_removes_tables(engine: Engine, tables: AuditTables, schema: str) -> None:
    with engine.begin() as conn:
        ensure_partitions(conn, tables, Sev)
        drop_audit_tables(conn, tables)
        left: int = conn.execute(
            text(
                "SELECT count(*) FROM pg_class c JOIN pg_namespace n "
                "ON n.oid = c.relnamespace WHERE n.nspname = :schema"
            ),
            {"schema": schema},
        ).scalar_one()
    assert left == 0


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"activity_table": "a" * 48}, "longer than 47 bytes"),
        ({"schema": "s" * 64}, "longer than 63 bytes"),
        ({"schema": ""}, "must not be empty"),
        ({"activity_table": "x", "transaction_table": "x"}, "must differ"),
        ({"indexes": {"severity", "nope"}}, "unknown index keys"),
    ],
)
def test_build_tables_rejects_bad_config(
    kwargs: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        build_tables(**kwargs)  # type: ignore[arg-type]


def test_index_key_sets_partition_all_keys() -> None:
    assert DEFAULT_INDEXES | OPTIONAL_INDEXES == ALL_INDEXES
    assert not DEFAULT_INDEXES & OPTIONAL_INDEXES


def test_every_index_key_builds_an_index() -> None:
    tables = build_tables(indexes=ALL_INDEXES)
    names = {index.name for index in tables.activity.indexes}
    assert names == {f"audit_activity_{key}_idx" for key in ALL_INDEXES}
