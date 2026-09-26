"""Engines, sessions and the two audit trails: the application's and maintenance's."""

from __future__ import annotations

import os
from datetime import timedelta

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

from audit_trail import AuditTrail, Severity
from audit_trail.migrations import create_audit_tables

from .models import AuthEvent, Base, CustomerEvent

DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/app"
)
# In production: the maintenance role of examples/roles.sql, which owns the
# audit tables and may update them. The application role can only insert and
# read. The demo uses one superuser for both.
MAINTENANCE_DATABASE_URL = os.environ.get("MAINTENANCE_DATABASE_URL", DATABASE_URL)
# Demo default only: a real key is a secret of at least 32 random bytes.
PSEUDONYMIZE_KEY = os.environ.get(
    "AUDIT_PSEUDONYMIZE_KEY", "demo-key-do-not-use-in-production!!"
).encode()

RETENTION: dict[Severity, timedelta | None] = {
    Severity.INFO: timedelta(days=90),  # entity changes, logins
    Severity.NOTICE: timedelta(days=365),  # sensitive reads
    Severity.WARNING: timedelta(days=3 * 365),  # failed logins
    Severity.CRITICAL: None,  # audit.scrubbed: kept forever
}


class AppSession(Session):
    """The audit listeners are registered on this class only."""


engine = create_async_engine(DATABASE_URL)
SessionLocal = async_sessionmaker(
    engine, sync_session_class=AppSession, expire_on_commit=False
)
audit = AuditTrail(
    engine,
    events=[AuthEvent, CustomerEvent],
    pseudonymize_key=PSEUDONYMIZE_KEY,
    # The activity feed reads the last 30 days unless asked otherwise.
    default_query_window=timedelta(days=30),
)
audit.install(SessionLocal)

maintenance_engine = create_async_engine(MAINTENANCE_DATABASE_URL)
# Partitions, retention and GDPR scrubbing. Same schema and severities as
# `audit`; only this one may scrub.
maintenance = AuditTrail(maintenance_engine, events=[], allow_scrub=True)


async def create_schema() -> None:
    """Create every table and this month's partitions.

    For the demo; use migrations in production (see the partitions guide),
    and run `maintenance.py` on a schedule.
    """
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with maintenance_engine.begin() as connection:
        await connection.run_sync(create_audit_tables, audit.tables, audit.severities)
    await maintenance.maintenance.aensure_partitions()


async def dispose() -> None:
    await audit.adispose()
    await maintenance.adispose()
    await engine.dispose()
    await maintenance_engine.dispose()
