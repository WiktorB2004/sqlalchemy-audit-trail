# sqlalchemy-audit-trail

Audit trail for SQLAlchemy on PostgreSQL. Entity changes are recorded automatically as field-level diffs, and explicit domain events are logged next to them, in one chronological table partitioned by severity and month.

!!! warning "Pre-alpha"
    The package is under active development. The API will change before 1.0.

## What gets recorded

- **Entity changes.** Mix `Audited` into a model and install the library on your session factory. Every flush then writes `entity.created`, `entity.updated` and `entity.deleted` entries with `{"field": [old, new]}` diffs, and membership changes of chosen relationships as `{"added": [...], "removed": [...]}`. The entries are written in the same database transaction as the change, so a rollback removes both.
- **Domain events.** Declare your own events (`auth.login_failed`, `billing.invoice_sent`, ...) on an `AuditEvent` enum, with a severity, an optional pydantic payload schema, and whether they must survive a rollback (`durable`) or must be written before any data leaves (`fail_closed`).
- **Context.** Every entry records who (actor), where (IP address, user agent, method, path) and how (channel, authentication method), plus an optional scope such as a tenant and a correlation id that links several transactions.

## How it is stored

Two tables in their own schema (`audit` by default):

- `audit_transaction`: one row per database transaction that wrote audit entries, holding the request context.
- `audit_activity`: one row per entry. It is partitioned by severity, and each severity by month, so retention drops whole partitions instead of deleting rows. It holds diffs, not copies of your rows.

Reads are keyset-paginated, newest first, grouped by transaction, and prune partitions by time.

## Where to go next

- [Install](install.md) and the [quickstart](quickstart.md): sync, async and FastAPI.
- Guides: [audited models](guides/models.md), [domain events](guides/events.md), [request context](guides/context.md), [FastAPI](guides/fastapi.md), [querying](guides/querying.md), [privacy and GDPR](guides/privacy.md), [partitions and retention](guides/partitions.md), [testing](guides/testing.md), [database roles](guides/permissions.md) and [operations](guides/operations.md).
- [Limitations](limitations.md): what is not captured, and why.
- [Migrating from sqlalchemy-continuum](migrating-from-continuum.md).
- The API reference, generated from the docstrings.
