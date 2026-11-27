# Database roles and permissions

The application only ever inserts into and reads from the audit tables. Everything else (creating tables and partitions, dropping expired partitions, scrubbing) can run under a separate role, so that the role your application connects with cannot rewrite or delete the audit log.

The SQL below is [`examples/roles.sql`](https://github.com/WiktorB2004/sqlalchemy-audit-trail/blob/main/examples/roles.sql) from the repository; the test suite runs it and tries every operation under each role. Replace `app` with your database name, and the role names as you like.

## Roles

```sql
--8<-- "examples/roles.sql:roles"
```

- `audit_maintenance` owns the audit schema and tables. It runs the audit migration, `ensure_partitions`, `drop_expired` and scrubbing.
- `app_user` is the role your application connects with.

## Grants for the application

Once the maintenance role has created the tables, it grants the application role what it needs, for example at the end of the same migration:

```sql
--8<-- "examples/roles.sql:grants"
```

## What each operation needs

| Operation | Needs |
|---|---|
| Writing entries: the session listener, `log()`/`alog()`, durable events | `USAGE` on the schema, `INSERT` and `SELECT` on both tables (`SELECT` for `INSERT ... RETURNING`) |
| `audit.query.*`, `LabelResolver`, `health()` | `USAGE` on the schema, `SELECT` on both tables |
| `create_audit_tables()` | `CREATE` on the database: it runs `CREATE SCHEMA IF NOT EXISTS`, which PostgreSQL checks even when the schema exists. The role that runs it owns the tables it creates |
| `ensure_partitions()`, `auto_create_partitions=True`, `drop_expired()` | ownership of both parent tables: PostgreSQL requires the owner to create, detach or drop partitions |
| `scrub()`, `scrub_actor()` | `SELECT` and `INSERT` on both tables (the scrub records itself as an `audit.scrubbed` entry), and `UPDATE` of the columns it erases: `object_label` and `data` of `audit_activity`, `actor_label`, `remote_addr`, `user_agent` and `meta` of `audit_transaction` |

Grants on the partitioned parents are enough: PostgreSQL checks privileges on the table a statement names, not on the partitions it reaches, so partitions created later need no grants. The id columns are identity columns, which need no sequence privileges.

Keep `auto_create_partitions` off (the default) for an application that connects as `app_user`: it cannot create partitions.

## A scrub-only role

If scrubbing should run under a role that cannot manage partitions, give it `UPDATE` of the erased columns, without ownership:

```sql
--8<-- "examples/roles.sql:scrubber"
```

Before 0.4.0 this role had `UPDATE` on the whole tables. A column grant does not narrow a table grant, so on an existing install run the `REVOKE` above before the column grants. Even narrowed, the role can rewrite the whole `data` column, since the scrub rewrites it with `jsonb_set`; keep it for admin tasks.

## With integrity

[Tamper evidence](integrity.md) adds two roles and narrows the others. Run these after `migrations.add_integrity()`.

The application loses its table-wide `INSERT`: it may insert every column except `id` and `xid`, so it cannot backdate a row into a range the sealer has already sealed. A column grant does not narrow a table grant, so the `REVOKE` comes first:

```sql
--8<-- "examples/roles.sql:integrity"
```

The scrub-only role gets the same `INSERT` columns, and `UPDATE` of the two columns a scrub changes besides the erased ones:

```sql
--8<-- "examples/roles.sql:integrity-scrubber"
```

The sealer reads the audit tables and appends blocks; it never updates or deletes anything. `export_checkpoint(require_replicated=True)` needs `pg_monitor`, since the standbys' WAL positions in `pg_stat_replication` are hidden from other roles; leave the grant out if you do not use it:

```sql
--8<-- "examples/roles.sql:sealer"
```

The verifier only reads. `verify()` reads each partition by name, and PostgreSQL checks the privileges of a partition read by name on the partition itself, so the grant covers every table in the schema, and the default privileges cover the partitions created later:

```sql
--8<-- "examples/roles.sql:verifier"
```

| Role | May | May not |
|---|---|---|
| `app_user` | insert entries (no `id`, no `xid`), read them, `health()` | update or delete entries, write blocks, seal, scrub |
| `audit_scrubber` | `scrub()`, `scrub_actor()` | update `verb`, `xid`, `seal_commitments`, `actor_id` or any other column it does not erase; delete; write blocks |
| `audit_sealer` | `seal()`, `health()`, `export_checkpoint()`, `declare_fork()` | update or delete blocks or entries, insert entries |
| `audit_verifier` | `verify()`, `health()` | write anything |
| `audit_maintenance` | as before, plus `write_genesis()`, retire blocks in `drop_expired()`, `acknowledge()` | (owner of the tables) |

Nobody gets `UPDATE` or `DELETE` on `audit_seal_block`. The maintenance role owns it, like the audit tables, so it could change both: run the sealer under its own role, and see the [limitations](../limitations.md#tamper-evidence) for what a table owner or superuser can still do.

## Using two roles from Python

Each role gets its own engine and `AuditTrail`, with the same `schema`, severities and indexes:

```python
from sqlalchemy import create_engine

from audit_trail import AuditTrail

# The application
audit = AuditTrail(create_engine(APP_DATABASE_URL), events=[BillingEvent])
audit.install(SessionLocal)

# The maintenance job (see Operations)
maintenance = AuditTrail(
    create_engine(MAINTENANCE_DATABASE_URL), allow_scrub=True, events=[]
)
maintenance.maintenance.ensure_partitions()
```

Scrubbing is refused unless the `AuditTrail` has `allow_scrub=True`, so the application's `AuditTrail` cannot scrub even if its role were allowed to.
