# Changelog

## Unreleased

### Changed

- **Breaking:** `examples/roles.sql` narrows the scrub-only role from `UPDATE` on the whole audit tables to `UPDATE` of the columns a scrub erases (`object_label` and `data` of `audit_activity`; `actor_label`, `remote_addr`, `user_agent` and `meta` of `audit_transaction`). A column grant does not narrow a table grant, so on an existing install run `REVOKE UPDATE ON audit.audit_transaction, audit.audit_activity FROM audit_scrubber` before the new column grants

### Added

- Tamper evidence, opt-in with `AuditTrail(integrity=Integrity())`: every audit row carries its transaction id and salted commitments to its erasable parts; `audit.maintenance.seal()` / `aseal()` hash the rows of finished transactions into a chain of blocks; `audit.maintenance.verify()` / `averify()` rebuild the chain from the rows and report every failure; `acknowledge()` waives a known incident in the chain. Writes take no extra lock or round trip. See the new tamper evidence guide; it is tamper evidence, not prevention
- Checkpoints: `audit_trail.integrity.export_checkpoint()` returns the head of the chain as a C2SP signed note for storing off the database host, optionally only once a synchronous standby has flushed it (`require_replicated=True`); `verify(checkpoints=...)` catches a rewritten, cut-off or restored chain against them. A `Signer` / `SignatureVerifier` hook signs blocks and checkpoints, with an Ed25519 reference in `audit_trail.integrity.ed25519` behind the new `sqlalchemy-audit-trail[integrity]` extra
- `declare_fork()` starts a new incarnation of the chain after a point-in-time recovery or a `pg_dump` / `pg_restore`, with an id window where transaction ids were rewound
- Upgrading: `migrations.add_integrity()` adds the columns and the `audit_seal_block` table under a short `lock_timeout` with retries, `migrations.add_integrity_indexes()` builds the `(xid, id)` indexes online, and `migrations.write_genesis()` starts the chain once every writer runs with `Integrity()`. `build_tables(integrity=True)` declares everything for a new install
- With integrity, `drop_expired()` seals, verifies (`verify_before_drop=True`) and writes a retire block before each drop, on a second pooled connection, and reports the partitions it kept in `skipped`; like without integrity, it refuses a transaction-mode pooler, before writing any retire block; `health()` reports the sealing lag and old prepared transactions in `seal`; scrubbing deletes the salt of each erased part and stamps it with the scrub's transaction id
- `examples/roles.sql` gains the grants for integrity: the application role inserts every column except `id` and `xid` (after `REVOKE INSERT`), and new sealer and verifier roles

### Fixed

- `drop_expired()` behind a pooler in transaction or statement mode (PgBouncer `pool_mode=transaction`) left its advisory lock and `lock_timeout` on a pooled server connection, so later runs failed with `PartitionLockTimeoutError` or hung. It now checks that its statements stay on one server connection and raises `PartitionError` before taking the lock if they do not; use a direct or session-pooled connection for it. `ensure_partitions()` already worked behind such poolers.

## 0.3.0 - 2026-11-17

- Python 3.10 is no longer supported; it reached end of life in October 2026. The package now requires Python 3.11+.
- `entity.updated` and `entity.created` record columns written by SQL instead of dropping them or storing `null`. A column assigned a SQL expression (`obj.placed_at = func.now()`) is a change on its own and stores `[old, "<unknown>"]`. Next to another change, `onupdate`, the version counter and, with `eager_defaults=True`, `server_onupdate`/`Computed` are recorded too. On INSERT, a SQL default or expression that was not fetched back is `"<unknown>"`, not `null`. Stored entries gain these keys; exclude a timestamp with `info={"audit": "exclude"}` to keep it out. Tests that compare `data["changes"]` exactly, expect `null` for such columns, or call `assert_not_audited` after a flush that only assigns a SQL expression need updating; `assert_audited(changes=...)` matches a subset and still passes.

## 0.2.0 - 2026-09-27

- Repository: a reproducible benchmark (`benchmark/`) and an example multi-tenant FastAPI application (`examples/fastapi_app/`), neither part of the package
- `scrub()` / `scrub_actor()` (and async variants) take `scope_ids=` to erase only one tenant's entries, failing closed like `Visibility`; the FastAPI `set_actor()` takes `scope_id=`; `ActivityData` and `FieldChange` are exported for typing API responses
- With asyncpg, a durable engine that cannot connect (refused, unresolvable host, timeout, or on SQLAlchemy 2.0 a missing database or bad password) now follows the durable write policy: `fail_closed` raises `AuditWriteError` and `on_error="log"` logs, instead of a raw driver error escaping `alog()`

## 0.1.0 - 2026-09-26

First release with the full audit trail: the flush listener, domain events, durable writes, async sessions, the read API, erasure, retention, the FastAPI integration and testing helpers. The API may still change before 1.0.

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
- `audit_trail.integrations.fastapi`: `AuditMiddleware` fills the request part of the audit context (client IP behind trusted proxies, user agent, method, path, request id), `session_dependency()` yields sessions for sync and async factories, and `set_actor()` records the actor after authentication, also from sync dependencies
- `audit.query.get()`, `object_history()`, `related()` and `access_summary()` (with async variants): one entry in detail, an object's history, entries of related objects and access counts; `LabelResolver` turns stored ids in changes into display labels
- `AuditTrail.scrub()` / `scrub_actor()` (and async variants), enabled with `allow_scrub=True`: erase an object's stored values or an actor's personal context in one transaction, recorded as an `audit.scrubbed` entry; erased values are never merged away when entries are grouped
- `log()` / `alog()` accept just the event and take the session from `AuditTrail(session_provider=...)`; a missing session or one of the wrong kind raises a clear error
- `AuditTrail(default_query_window=...)`: `list_groups()` without `since` reads only that window; `since=ALL_HISTORY` reads the whole log, the cursor keeps the first page's bound, and `Page.since` tells where the window started
- Under `AsyncSession`, loading an expired column of an `Audited` model (for example assigning to it after a commit) or an unloaded tracked collection raises `AsyncLoadError`, a `MissingGreenlet` subclass that names the attribute and the fix
- Sessions without a default bind work: audit rows go on the connection the flush used for the object (per mapper or table `binds`, or an overridden `get_bind`), one `audit_transaction` row per database; `log()` without `obj` and the query API use a bind of the audit tables, otherwise raise a clear `UnboundExecutionError`

## 0.1.0a1 - 2026-09-25

Pre-release to verify the publishing pipeline. The flush listener and the read API are not included yet, so no audit entries are written.

- `AuditContext` and `Actor`: request context set with `context()`, updated in place with `set_actor()`, or attached to one session with `bind()`
- Value serialization for audit entries and keyed HMAC pseudonyms with versioned keys; `Pseudonymized[...]` marks payload fields
- `AuditEvent` with per-event severity, payload schema and durability, declared with `event()`; the default `Severity` levels; a registry that validates events against the configured severity enum
- Relationship tracking: net `added`/`removed` changes of chosen collection relationships, captured from ORM events
- Audit tables partitioned by severity and month, DDL helpers for migrations, and `PartitionManager.ensure_partitions()`, which creates missing partitions under a lock timeout
- Entity change sets with per-column `exclude`/`redact`/`hash` policies, and the `Audited` mixin with `AuditOptions` for labels, scope and target read from loaded attributes only
