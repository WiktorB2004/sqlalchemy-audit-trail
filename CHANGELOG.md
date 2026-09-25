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

## 0.1.0a1 - 2026-09-25

Pre-release to verify the publishing pipeline. The flush listener and the read API are not included yet, so no audit entries are written.

- `AuditContext` and `Actor`: request context set with `context()`, updated in place with `set_actor()`, or attached to one session with `bind()`
- Value serialization for audit entries and keyed HMAC pseudonyms with versioned keys; `Pseudonymized[...]` marks payload fields
- `AuditEvent` with per-event severity, payload schema and durability, declared with `event()`; the default `Severity` levels; a registry that validates events against the configured severity enum
- Relationship tracking: net `added`/`removed` changes of chosen collection relationships, captured from ORM events
- Audit tables partitioned by severity and month, DDL helpers for migrations, and `PartitionManager.ensure_partitions()`, which creates missing partitions under a lock timeout
- Entity change sets with per-column `exclude`/`redact`/`hash` policies, and the `Audited` mixin with `AuditOptions` for labels, scope and target read from loaded attributes only
