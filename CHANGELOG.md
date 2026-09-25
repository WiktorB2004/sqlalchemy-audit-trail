# Changelog

## Unreleased

- `PartitionManager.drop_expired()`: drops monthly partitions past their per-severity retention with `DETACH ... CONCURRENTLY`, finishing interrupted detaches; `PartitionManager.health()` reports partition coverage ahead, pending detaches and orphaned tables
- `ensure_partitions()` works with tables declared without a schema and returns schema-qualified names
- Renovate opens pull requests for dependency and GitHub Actions updates
- `check_models()`: static checks for CI that report sensitive-looking columns without an audit policy, JSON columns whose in-place changes go undetected, relationships tracked on both sides, and tracked names that are not collection relationships
- `AuditTrail.install()`: the session listener writes one `entity.created`/`updated`/`deleted` row per flush and object, with a lazily created `audit_transaction` row per database transaction, inside the business transaction; `on_error="log"` isolates audit write failures in a savepoint
- `AuditTrail` gains `default_severity`, `system_severity`, `events` and `global_redact`, and exposes `context()`, `set_actor()`, `bind()`, `pseudonymize()` and `maintenance`
- Audit options read a column never set on a new instance as `None` instead of falling back as if it were not loaded
- `AuditTrail.log()`: records an explicit event in the session's transaction, with payload validation, `Pseudonymized` payload fields, a per-entry `actor=` and a `Target` (also returned by the `target` option); `warn_on_bulk` warns about bulk `UPDATE`/`DELETE` statements on audited tables, which bypass the trail
- `audit.query.list_groups()` / `alist_groups()`: lists audit entries grouped by transaction, newest first, with keyset pagination (`Cursor`), filters, `Visibility` restrictions and read-time compaction of per-flush rows; queries prune partitions and force custom plans
- Async sessions: `AuditTrail.install()` accepts an `async_sessionmaker` or `AsyncSession` subclass with a `sync_session_class`, and `AuditTrail.alog()` records explicit events from async code
- Durable and `fail_closed` events are written on a separate small pool and committed before `log()`/`alog()` returns, surviving the caller's rollback; a missing partition is created and the write retried once; `fail_closed` failures raise `AuditWriteError`
- `AuditTrail.dispose()` / `adispose()` close the durable pool the library created
- `audit_trail.testing`: `assert_audited()` / `assert_not_audited()` (and async variants) that show the closest entries and their differences on failure, table setup helpers, and an opt-in pytest plugin (`pytest_plugins = ["audit_trail.pytest_plugin"]`)

## 0.1.0a1 - 2026-09-25

Pre-release to verify the publishing pipeline. The flush listener and the read API are not included yet, so no audit entries are written.

- `AuditContext` and `Actor`: request context set with `context()`, updated in place with `set_actor()`, or attached to one session with `bind()`
- Value serialization for audit entries and keyed HMAC pseudonyms with versioned keys; `Pseudonymized[...]` marks payload fields
- `AuditEvent` with per-event severity, payload schema and durability, declared with `event()`; the default `Severity` levels; a registry that validates events against the configured severity enum
- Relationship tracking: net `added`/`removed` changes of chosen collection relationships, captured from ORM events
- Audit tables partitioned by severity and month, DDL helpers for migrations, and `PartitionManager.ensure_partitions()`, which creates missing partitions under a lock timeout
- Entity change sets with per-column `exclude`/`redact`/`hash` policies, and the `Audited` mixin with `AuditOptions` for labels, scope and target read from loaded attributes only
