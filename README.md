# sqlalchemy-audit-trail

Audit trail for SQLAlchemy on PostgreSQL: automatic entity change diffs and explicit domain events in one chronological, partitioned log.

- **Entity changes, automatically.** Mark a model `Audited` and every flush records `entity.created`, `entity.updated` and `entity.deleted` with `{"field": [old, new]}` diffs, in the same transaction as the change.
- **Domain events.** Declare `auth.login_failed` or `record.sensitive_viewed` once, with a severity, a payload schema and whether it must survive a rollback (`durable`) or be written before data leaves (`fail_closed`).
- **Who, where, how.** Actor, IP address, user agent, path, channel and your own fields on every entry; FastAPI middleware included.
- **Built for PostgreSQL.** Tables partitioned by severity and month, retention by dropping partitions, keyset pagination that prunes partitions.
- **Privacy.** Per-column `exclude`, `redact` and `hash` policies, pseudonymized payload fields, and `scrub` for erasure requests.
- **Sync and async.** `Session` and `AsyncSession`, psycopg 3 and asyncpg.

> **Pre-alpha.** The API will change before 1.0.

## Install

```bash
pip install "sqlalchemy-audit-trail[psycopg]"
```

Extras: `psycopg`, `asyncpg`, `asyncio`, `pydantic` (payload schemas) and `fastapi`. Requires Python 3.10+, SQLAlchemy 2.0 or 2.1, and PostgreSQL 14+.

## Example

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from audit_trail import Actor, Audited, AuditOptions, AuditTrail
from audit_trail.migrations import create_audit_tables


class Base(DeclarativeBase):
    pass


class Invoice(Base, Audited):
    __tablename__ = "invoice"

    id: Mapped[int] = mapped_column(primary_key=True)
    status: Mapped[str] = mapped_column(default="draft")
    payment_token: Mapped[str | None] = mapped_column(info={"audit": "redact"})

    __audit__ = AuditOptions(label=lambda invoice: f"Invoice {invoice.id}")


engine = create_engine("postgresql+psycopg://localhost/app")
audit = AuditTrail(engine, events=[])
SessionLocal = sessionmaker(engine)
audit.install(SessionLocal)

with engine.begin() as connection:  # in a migration, in a real application
    Base.metadata.create_all(connection)
    create_audit_tables(connection, audit.tables, audit.severities)
audit.maintenance.ensure_partitions()  # and on a schedule

with audit.context(actor_type="user", actor_id="42", actor_label="ada@example.com"):
    with SessionLocal() as session:
        invoice = Invoice()
        session.add(invoice)
        session.commit()
        invoice.status = "sent"
        session.commit()

with SessionLocal() as session:
    for group in audit.query.object_history(session, "Invoice", "1").groups:
        for activity in group.activities:
            print(activity["verb"], activity["data"]["changes"])
# entity.updated {'status': ['draft', 'sent']}
# entity.created {'id': [None, 1], 'status': [None, 'draft'], 'payment_token': [None, None]}
```

## Documentation

[wiktorb2004.github.io/sqlalchemy-audit-trail](https://wiktorb2004.github.io/sqlalchemy-audit-trail/): the [quickstart](https://wiktorb2004.github.io/sqlalchemy-audit-trail/quickstart/) (sync, async and FastAPI), guides, [limitations](https://wiktorb2004.github.io/sqlalchemy-audit-trail/limitations/) and the API reference.

## License

MIT
