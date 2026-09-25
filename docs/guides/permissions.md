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
| `scrub()`, `scrub_actor()` | `SELECT`, `INSERT` and `UPDATE` on both tables (the scrub records itself as an `audit.scrubbed` entry) |

Grants on the partitioned parents are enough: PostgreSQL checks privileges on the table a statement names, not on the partitions it reaches, so partitions created later need no grants. The id columns are identity columns, which need no sequence privileges.

Keep `auto_create_partitions` off (the default) for an application that connects as `app_user`: it cannot create partitions.

## A scrub-only role

If scrubbing should run under a role that cannot manage partitions, give it `UPDATE` without ownership:

```sql
--8<-- "examples/roles.sql:scrubber"
```

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
