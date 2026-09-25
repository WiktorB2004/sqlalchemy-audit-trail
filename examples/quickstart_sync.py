"""Quickstart: audit a model and log a domain event with a sync ``Session``.

Run against an empty PostgreSQL database::

    DATABASE_URL=postgresql+psycopg://user:password@localhost/app \
        python examples/quickstart_sync.py
"""

from __future__ import annotations

import os
from decimal import Decimal

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from audit_trail import (
    Actor,
    Audited,
    AuditEvent,
    AuditOptions,
    AuditTrail,
    Severity,
    event,
)
from audit_trail.migrations import create_audit_tables

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+psycopg://postgres:postgres@localhost:5432/app"
)


# --8<-- [start:models]
class Base(DeclarativeBase):
    pass


class Invoice(Base, Audited):
    __tablename__ = "invoice"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer: Mapped[str]
    total: Mapped[Decimal]
    status: Mapped[str] = mapped_column(default="draft")
    # Never stored in the audit log; only "***" shows that it changed.
    payment_token: Mapped[str | None] = mapped_column(info={"audit": "redact"})

    __audit__ = AuditOptions(label=lambda invoice: f"Invoice for {invoice.customer}")


class BillingEvent(AuditEvent):
    INVOICE_SENT = event("billing.invoice_sent", Severity.NOTICE)


# --8<-- [end:models]

# --8<-- [start:setup]
engine = create_engine(DATABASE_URL)
audit = AuditTrail(engine, events=[BillingEvent])
SessionLocal = sessionmaker(engine)
audit.install(SessionLocal)


def create_tables() -> None:
    # In an application, this belongs in a migration (see the partitions guide).
    with engine.begin() as connection:
        Base.metadata.create_all(connection)
        create_audit_tables(connection, audit.tables, audit.severities)
    # Monthly partitions: run this on a schedule too, not only at start-up.
    audit.maintenance.ensure_partitions()


# --8<-- [end:setup]


# --8<-- [start:write]
def work() -> None:
    with (
        audit.context(channel="cli"),
        SessionLocal() as session,
    ):
        audit.set_actor(Actor(type="user", id="42", label="ada@example.com"))

        invoice = Invoice(customer="Acme", total=Decimal("120.00"))
        session.add(invoice)
        session.commit()  # entity.created

        invoice.status = "sent"
        invoice.payment_token = "tok_123"
        audit.log(
            session,
            BillingEvent.INVOICE_SENT,
            obj=invoice,
            payload={"channel": "email"},
        )
        session.commit()  # entity.updated and billing.invoice_sent


# --8<-- [end:write]


# --8<-- [start:read]
def show_history() -> None:
    with SessionLocal() as session:
        page = audit.query.object_history(session, "Invoice", "1")
        for group in page.groups:
            header = group.transaction
            print(f"{header.issued_at:%Y-%m-%d %H:%M} by {header.actor_label}")
            for activity in group.activities:
                data = activity["data"]
                print(" ", activity["verb"], data.get("changes") or data["payload"])


# --8<-- [end:read]


def main() -> None:
    create_tables()
    work()
    show_history()
    audit.dispose()
    engine.dispose()


if __name__ == "__main__":
    main()
