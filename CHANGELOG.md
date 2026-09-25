# Changelog

## Unreleased

- `PartitionManager.drop_expired()`: drops monthly partitions past their per-severity retention with `DETACH ... CONCURRENTLY`, finishing interrupted detaches; `PartitionManager.health()` reports partition coverage ahead, pending detaches and orphaned tables
- `ensure_partitions()` works with tables declared without a schema and returns schema-qualified names

## 0.1.0a1 - 2026-09-25

Pre-release to verify the publishing pipeline. The flush listener and the read API are not included yet, so no audit entries are written.

- `AuditContext` and `Actor`: request context set with `context()`, updated in place with `set_actor()`, or attached to one session with `bind()`
- Value serialization for audit entries and keyed HMAC pseudonyms with versioned keys; `Pseudonymized[...]` marks payload fields
- `AuditEvent` with per-event severity, payload schema and durability, declared with `event()`; the default `Severity` levels; a registry that validates events against the configured severity enum
- Relationship tracking: net `added`/`removed` changes of chosen collection relationships, captured from ORM events
- Audit tables partitioned by severity and month, DDL helpers for migrations, and `PartitionManager.ensure_partitions()`, which creates missing partitions under a lock timeout
- Entity change sets with per-column `exclude`/`redact`/`hash` policies, and the `Audited` mixin with `AuditOptions` for labels, scope and target read from loaded attributes only
