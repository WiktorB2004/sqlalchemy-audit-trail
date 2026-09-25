"""Helpers shared by the session listener tests."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from sqlalchemy import Engine, RowMapping, event, select
from sqlalchemy.orm import Session, sessionmaker

from audit_trail import AuditTrail
from audit_trail.maintenance import ensure_partitions
from audit_trail.migrations import create_audit_tables


class Sev(IntEnum):
    LOW = 10
    HIGH = 40


def create_trail(
    engine: Engine,
    schema: str,
    *,
    partitions: list[int] | None = None,
    **options: Any,
) -> AuditTrail:
    """Build an ``AuditTrail`` for ``schema`` and create its tables.

    Args:
        engine: Test engine.
        schema: Schema for the audit tables.
        partitions: Severities to create partitions for (all by default);
            ``[]`` creates none, so every audit write fails with 23514.
        **options: Further ``AuditTrail`` arguments.
    """
    trail = AuditTrail(engine, schema=schema, severities=Sev, events=[], **options)
    with engine.begin() as conn:
        create_audit_tables(conn, trail.tables, Sev)
        severities = list(Sev) if partitions is None else partitions
        if severities:
            ensure_partitions(conn, trail.tables, severities, months_ahead=0)
    return trail


@dataclass
class Env:
    engine: Engine
    trail: AuditTrail
    factory: sessionmaker[Session]

    def activities(self) -> list[RowMapping]:
        table = self.trail.tables.activity
        with self.engine.connect() as conn:
            return list(conn.execute(select(table).order_by(table.c.id)).mappings())

    def transactions(self) -> list[RowMapping]:
        table = self.trail.tables.transaction
        with self.engine.connect() as conn:
            return list(conn.execute(select(table).order_by(table.c.id)).mappings())


def make_env(engine: Engine, schema: str, **options: Any) -> Env:
    """An ``AuditTrail`` installed on a new ``sessionmaker``."""
    trail = create_trail(engine, schema, **options)
    factory = sessionmaker(engine)
    trail.install(factory)
    return Env(engine, trail, factory)


@dataclass
class StatementLog:
    """Statements executed on an engine while ``recording`` is on."""

    recording: bool = False
    statements: list[str] = field(default_factory=list)


@contextmanager
def record_statements(engine: Engine) -> Iterator[StatementLog]:
    log = StatementLog()

    def before_cursor_execute(
        conn: Any, cursor: Any, statement: str, *args: Any
    ) -> None:
        if log.recording:
            log.statements.append(statement)

    event.listen(engine, "before_cursor_execute", before_cursor_execute)
    try:
        yield log
    finally:
        event.remove(engine, "before_cursor_execute", before_cursor_execute)
