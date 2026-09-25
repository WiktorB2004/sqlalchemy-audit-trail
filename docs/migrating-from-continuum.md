# Migrating from sqlalchemy-continuum

[SQLAlchemy-Continuum](https://github.com/kvesteri/sqlalchemy-continuum) keeps a version table next to each versioned table and copies the row into it on every change. This library keeps no copies: it stores what changed, as diffs, in one chronological log, next to domain events and request context. The two answer different questions, so check the differences below before switching.

## What maps to what

| sqlalchemy-continuum | sqlalchemy-audit-trail |
|---|---|
| `make_versioned()` and `__versioned__ = {}` on a model | mix in `Audited` and call `audit.install(SessionLocal)` |
| `__versioned__ = {"exclude": [...]}` | `mapped_column(info={"audit": "exclude"})` per column, plus `"redact"` and `"hash"` |
| one `*_version` table per model | the shared `audit_activity` table, partitioned by severity and month |
| the `transaction` table | `audit_transaction`, with actor, IP, user agent, path, channel and a `meta` JSON column |
| `transaction.user_id` | `actor_id` from the [request context](guides/context.md) |
| `TransactionMetaPlugin` | `AuditContext(extra={...})`, stored in `meta` |
| `ActivityPlugin` | [domain events](guides/events.md): `AuditEvent` members logged with `audit.log()` |
| `article.versions`, `version.changeset` | `audit.query.object_history(session, "Article", "5")`, and `data["changes"]` on each entry |
| relationship versioning | `AuditOptions(track_relationships={...})`: membership changes as `added`/`removed` ids |
| `version.revert()`, the state of a row at a version | nothing yet; see [below](#what-you-lose) |

The shape of a change is similar: continuum's `changeset` is `{"field": [old, new]}`, and so is `data["changes"]` here. Values are JSON-encoded: decimals as strings, datetimes as ISO 8601 strings.

## What you gain

- Domain events, severities and request context in the same log as entity changes.
- Diffs are written once, at flush time, so listing the log reads one table; there is no changeset to compute from version tables.
- Per-column policies (`exclude`, `redact`, `hash`), `scrub()` and `scrub_actor()` for erasure requests, and per-severity retention that drops whole partitions.
- Explicit support for `AsyncSession` and FastAPI.

## What you lose

- **Point-in-time state.** Without copies of rows, the log cannot answer "which records had status X on date D" in one query, and there is no function to revert a record or rebuild its state at a point in time. Replaying diffs by hand works only for columns that were not excluded, redacted, hashed, scrubbed or `"<unknown>"`.
- **Other databases.** Only PostgreSQL 14+ is supported.
- **Changes outside the ORM.** Bulk `UPDATE`/`DELETE` statements and database cascades are not audited, and there is no trigger-based mode; see [limitations](limitations.md).

## Switching over

There is no importer for continuum's history. A workable plan:

1. Add the audit tables in a migration and schedule `ensure_partitions()` (see [partitions](guides/partitions.md) and [operations](guides/operations.md)).
2. Mark the models `Audited`, with column policies where `__versioned__` had excludes, and run [`check_models()`](guides/models.md#checking-models-in-ci) in CI.
3. Set the actor and request context (see [context](guides/context.md), or the [FastAPI integration](guides/fastapi.md)), and replace `ActivityPlugin` activities with domain events.
4. Run both libraries side by side for a while and compare `object_history()` with your version tables.
5. Remove continuum's versioning from the models. Keep its version and transaction tables, read-only, for as long as you need the old history, or export them, then drop them in a later migration.
