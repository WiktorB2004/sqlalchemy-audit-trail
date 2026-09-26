"""The models and events the write benchmark uses.

``BenchPlain`` and ``BenchAudited`` have the same columns; only the second
mixes in ``Audited``. Their tables have no schema: the runner maps them into
its own schema with ``schema_translate_map``.
"""

from __future__ import annotations

from decimal import Decimal
from functools import cache

from sqlalchemy import Numeric
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from audit_trail import Audited, AuditEvent, Severity, event


class Base(DeclarativeBase):
    """Declarative base of the benchmark models."""


class _Columns:
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str]
    status: Mapped[str]
    counter: Mapped[int]
    amount: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    note: Mapped[str | None]


class BenchPlain(_Columns, Base):
    """Not audited: the baseline."""

    __tablename__ = "bench_plain"


class BenchAudited(_Columns, Base, Audited):
    """Audited, with the same columns as ``BenchPlain``."""

    __tablename__ = "bench_audited"


@cache
def bench_events() -> type[AuditEvent]:
    """The events written with ``log()``: ``VIEWED`` and durable ``EXPORTED``.

    Built on first use, not at import. ``AuditTrail(events=None)`` registers
    every ``AuditEvent`` subclass in the process, and an event with the
    built-in ``Severity`` would break that for a host with its own severity
    enum. Importing the benchmark therefore defines none; only running the
    write benchmark does, in its own process. The verbs use the
    ``benchmark.`` prefix so they cannot clash with anyone's.
    """

    class BenchEvent(AuditEvent):
        VIEWED = event("benchmark.viewed", Severity.INFO)
        EXPORTED = event("benchmark.exported", Severity.WARNING, durable=True)

    return BenchEvent


def row_values(index: int) -> dict[str, object]:
    """Column values of the ``index``-th benchmark object."""
    return {
        "name": f"item {index}",
        "status": "draft",
        "counter": 0,
        "amount": Decimal(index % 1000) + Decimal("0.99"),
        "note": None if index % 2 else f"note {index}",
    }
