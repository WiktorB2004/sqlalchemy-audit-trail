"""What is recorded: the audited models and the domain events."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel
from sqlalchemy import DateTime, ForeignKey, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from audit_trail import (
    Audited,
    AuditEvent,
    AuditOptions,
    Pseudonymized,
    Severity,
    Target,
    event,
)


class Base(DeclarativeBase):
    pass


class Customer(Base, Audited):
    __tablename__ = "customer"
    # Fetch updated_at with RETURNING: an AsyncSession cannot load it later.
    __mapper_args__ = {"eager_defaults": True}  # noqa: RUF012

    id: Mapped[int] = mapped_column(primary_key=True)
    tenant_id: Mapped[str]
    name: Mapped[str]
    # Correlatable (equal e-mails give equal hashes), never stored in clear.
    email: Mapped[str] = mapped_column(info={"audit": "hash"})
    # The log shows that it was set or changed, not the value.
    iban: Mapped[str | None] = mapped_column(info={"audit": "redact"})
    # Bookkeeping: it changes on every write and the entry has its own time.
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        info={"audit": "exclude"},
    )
    # Deleted by the ORM, not by the database, so each deletion is audited.
    contacts: Mapped[list[Contact]] = relationship(
        back_populates="customer", cascade="all, delete-orphan"
    )

    __audit__ = AuditOptions(
        label=lambda customer: customer.name,
        scope=lambda customer: customer.tenant_id,
        track_relationships={"contacts"},
    )


class Contact(Base, Audited):
    __tablename__ = "contact"

    id: Mapped[int] = mapped_column(primary_key=True)
    customer_id: Mapped[int] = mapped_column(ForeignKey("customer.id"))
    tenant_id: Mapped[str]
    name: Mapped[str]
    email: Mapped[str] = mapped_column(info={"audit": "hash"})
    customer: Mapped[Customer] = relationship(back_populates="contacts")

    __audit__ = AuditOptions(
        label=lambda contact: contact.name,
        # Options read loaded columns, not relationships.
        scope=lambda contact: contact.tenant_id,
        # A contact's changes also show up in its customer's history.
        target=lambda contact: Target("Customer", contact.customer_id),
    )


class LoginFailed(BaseModel):
    # What was typed into the login field; it may be a password.
    login: Pseudonymized[str]
    reason: str


class AuthEvent(AuditEvent):
    LOGIN = event("auth.login", Severity.INFO)
    # Durable: written on its own connection, so it survives the 401.
    LOGIN_FAILED = event(
        "auth.login_failed", Severity.WARNING, LoginFailed, durable=True
    )


class CustomerEvent(AuditEvent):
    # Fail-closed: if the entry cannot be written, the data is not returned.
    PAYMENT_DETAILS_VIEWED = event(
        "customer.payment_details_viewed", Severity.NOTICE, fail_closed=True
    )
