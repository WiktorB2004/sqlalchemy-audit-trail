# sqlalchemy-audit-trail

Audit trail for **SQLAlchemy on PostgreSQL**: automatic entity change diffs and explicit domain events in one chronological, partitioned log, with who, where and how on every entry. Not a version-table library like sqlalchemy-continuum.

[![PyPI](https://img.shields.io/pypi/v/sqlalchemy-audit-trail)](https://pypi.org/project/sqlalchemy-audit-trail/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://pypi.org/project/sqlalchemy-audit-trail/)
[![Docs](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://wiktorb2004.github.io/sqlalchemy-audit-trail/)
[![CI](https://img.shields.io/github/actions/workflow/status/WiktorB2004/sqlalchemy-audit-trail/ci.yml?branch=main&label=CI)](https://github.com/WiktorB2004/sqlalchemy-audit-trail/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/WiktorB2004/sqlalchemy-audit-trail)](LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/sqlalchemy-audit-trail)](https://pypi.org/project/sqlalchemy-audit-trail/)

> **Alpha.** The API may change before 1.0.

## Install

```bash
pip install "sqlalchemy-audit-trail[psycopg]"   # Session on psycopg 3
pip install "sqlalchemy-audit-trail[asyncpg]"   # AsyncSession on asyncpg
                                                # more extras: asyncio, pydantic (payload schemas), fastapi
```

Requires Python 3.10+, SQLAlchemy 2.0 or 2.1, and PostgreSQL 14+.

## Quickstart

**Entity changes**: mark a model `Audited`, install the listener, and every flush records `entity.created` / `entity.updated` / `entity.deleted` with `{"field": [old, new]}` diffs:

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from audit_trail import Audited, AuditOptions, AuditTrail
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

**Domain events**: declare what else is worth auditing once, with a severity, then log it:

```python
from audit_trail import AuditEvent, Severity, event


class AuthEvent(AuditEvent):
    LOGIN = event("auth.login", Severity.INFO)
    LOGIN_FAILED = event("auth.login_failed", Severity.WARNING, durable=True)


audit = AuditTrail(engine, events=[AuthEvent])
audit.log(session, AuthEvent.LOGIN_FAILED, payload={"reason": "bad password"})
```

Docs: [wiktorb2004.github.io/sqlalchemy-audit-trail](https://wiktorb2004.github.io/sqlalchemy-audit-trail/). Runnable, tested quickstarts for sync, async and FastAPI: [`examples/`](examples/).

Audit rows are written **in your transaction**: roll back and they are gone with the change. A failed audit write does not fail your transaction by default (`on_error="log"`). `durable` events are committed on their own connection and survive a rollback; `fail_closed` events raise `AuditWriteError` when they cannot be written.

## Why this instead of sqlalchemy-continuum, triggers or pgaudit

[sqlalchemy-continuum](https://github.com/kvesteri/sqlalchemy-continuum) copies every changed row into a version table per model. That answers "what did this row look like then", but a login, a download or someone viewing sensitive data has no row to version. Database triggers and pgaudit see statements, not the application's user, request or intent.

This library stores what changed as diffs, next to the domain events you declare and the request context (actor, IP, user agent, path, channel), in one log you can list chronologically, per object or per actor. The trade-off: there is no revert and no state at a point in time. See [migrating from continuum](https://wiktorb2004.github.io/sqlalchemy-audit-trail/migrating-from-continuum/) and [limitations](https://wiktorb2004.github.io/sqlalchemy-audit-trail/limitations/).

## Design

### One partitioned log

Two tables: `audit_transaction` (who, where and how, once per database transaction) and `audit_activity` (one row per object and flush, or per event). Both are partitioned by severity, then by month, so retention drops whole partitions per severity and reads touch only the partitions they need. There is no default partition: schedule `ensure_partitions()` (see [operations](https://wiktorb2004.github.io/sqlalchemy-audit-trail/guides/operations/)).

### In your transaction, unless you say otherwise

| Kind | Written | When the audit write fails |
| --- | --- | --- |
| entity change, plain event | in your transaction | `on_error="log"`: logged, your transaction goes on; `"raise"`: propagates |
| `durable` event | on its own connection, committed before `log()` returns | as `on_error` |
| `fail_closed` event | on its own connection, committed before `log()` returns | always raises `AuditWriteError` |

### Privacy by default, erasure on request

Per-column `exclude`, `redact` and `hash` policies, `Pseudonymized` payload fields with versioned keys, and `scrub()` / `scrub_actor()` to erase an object's values or an actor's personal context, each recorded as an `audit.scrubbed` entry. See [privacy](https://wiktorb2004.github.io/sqlalchemy-audit-trail/guides/privacy/).

### Reads fail closed

`list_groups()` lists entries grouped by transaction, with keyset pagination. `Visibility` restrictions fail closed: `None` means no restriction, an empty set allows nothing, and a `NULL` column never passes a restriction that is set.

### Sync, async and FastAPI

`Session` and `AsyncSession` on psycopg 3 or asyncpg. `audit_trail.integrations.fastapi` adds ASGI middleware for the request context (the client IP is read from `X-Forwarded-For` only behind trusted proxies), a session dependency, and `set_actor()` for after authentication.

## Tests

Tests under `tests/db` run against a real PostgreSQL. With Docker running, a throwaway `postgres:18` container is started with testcontainers.

```bash
uv sync --frozen

uv run pytest tests/unit                          # no database needed
uv run pytest                                     # everything, needs Docker
AUDIT_TEST_PG_IMAGE=postgres:14 uv run pytest     # oldest supported PostgreSQL

uv run ruff check . && uv run mypy
```

To use a server you already have, set `AUDIT_TEST_DATABASE_URL`. CI runs PostgreSQL 14, 16, 17 and 18, SQLAlchemy 2.0 and 2.1, and Python 3.10 to 3.13.

## Docs

```bash
uv sync --group docs
uv run mkdocs serve
```

Published at [wiktorb2004.github.io/sqlalchemy-audit-trail](https://wiktorb2004.github.io/sqlalchemy-audit-trail/).

## Contributing

Issues and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). To report a vulnerability, use [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE). Changelog: [CHANGELOG.md](CHANGELOG.md). Cite this repo with [CITATION.cff](CITATION.cff).
