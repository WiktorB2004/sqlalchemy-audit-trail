# Partitions and retention

## Layout

Both audit tables are partitioned, and neither has a `DEFAULT` partition:

- `audit_transaction` is partitioned by month of `issued_at`: `audit_transaction_p2026_09`, ...
- `audit_activity` is partitioned by severity (`audit_activity_10`, `audit_activity_40`, ...), and each severity partition by month of `created_at`: `audit_activity_10_p2026_09`, ...

Months are UTC: the September 2026 partitions hold `['2026-09-01 00:00:00+00', '2026-10-01 00:00:00+00')` whatever the server's time zone. Retention then drops whole partitions instead of deleting rows, and queries with a time window read only the partitions they need.

The indexes are created on the partitioned parents, so PostgreSQL adds them to every partition, including future ones. `AuditTrail(indexes=...)` chooses which to create, from `severity`, `actor`, `object`, `target`, `scope`, `transaction` and `correlation` (all by default) and `changes_gin`, an optional GIN index on `data -> 'changes'` for "who changed field X" queries. Leave out an index you do not query by (for example `scope` without tenants); measure the write cost before adding `changes_gin`.

## Creating the tables

Alembic's autogenerate does not understand partitioned tables, so create the audit tables with `audit_trail.migrations` in a migration of their own:

```python
from alembic import op

from audit_trail import migrations
from audit_trail.tables import build_tables
from myapp.audit import Level  # your severity enum, or audit_trail.Severity

tables = build_tables(schema="audit")


def upgrade() -> None:
    migrations.create_audit_tables(op.get_bind(), tables, Level)


def downgrade() -> None:
    migrations.drop_audit_tables(op.get_bind(), tables)
```

`build_tables()` must match your `AuditTrail`: the same `schema`, and the same `indexes` if you changed them. `create_audit_tables()` creates the schema if needed, both parent tables, one partition per severity and the indexes. `migrations.create_sql(tables, Level)` renders the same DDL as a SQL script, if you prefer to review or apply it by hand.

Adding a severity level later: `ensure_partitions()` creates the partition of any severity that has none.

Migrations create no monthly partitions: those depend on the date the code runs, not the date the migration was written. Until `ensure_partitions()` has run, every audit insert fails.

## Creating partitions ahead

```python
created = audit.maintenance.ensure_partitions(months_ahead=3)
```

`ensure_partitions(months_ahead=3, *, lock_timeout="5s")` creates the missing partitions for the current UTC month and the `months_ahead` months after it, and returns their names. It is idempotent: a partition that exists with the same (or wider) bounds, under any name, counts as present. Run it on a schedule, and at application start if you like (see [operations](operations.md)).

Creating a partition takes an `ACCESS EXCLUSIVE` lock on the parent table, so it waits for open transactions that have written audit rows, and new audit inserts queue behind it. `lock_timeout` bounds that wait; past it, nothing is created and `PartitionLockTimeoutError` is raised. Retrying later is safe: `months_ahead` leaves room for missed runs.

The module-level functions in `audit_trail.maintenance` (`ensure_partitions`, `drop_expired`, `health`) do the same work on a `Connection` you provide.

### When a partition is missing

A row without a partition fails with SQLSTATE `23514` ("no partition of relation ... found for row").

- An entry written in the session's transaction is lost: with `on_error="log"` the error is logged and your transaction continues; with `on_error="raise"` your transaction fails.
- A durable entry, with `AuditTrail(auto_create_partitions=True)`, creates the missing partitions and retries once. That needs DDL privileges (see [roles](permissions.md)), and the creation waits for every open transaction that has written audit rows, including the caller's own. It is a fallback, not a replacement for the schedule.

## Retention

```python
from datetime import timedelta

dropped = maintenance.maintenance.drop_expired(
    {
        Level.LOW: timedelta(days=90),
        Level.MEDIUM: timedelta(days=365),
        Level.HIGH: None,  # keep forever
    },
    transaction_retention=timedelta(days=90),
)
```

`drop_expired(retention, *, transaction_retention=None, lock_timeout="5s")` detaches and drops every monthly partition whose upper bound is older than `now - retention` for its severity, and returns the names of the partitions dropped.

- `None` keeps a severity forever. A severity missing from the mapping is also kept, with a warning, so an empty mapping drops no activity partition.
- `transaction_retention` applies to `audit_transaction`. It is capped at the shortest finite severity retention, with a warning if it is longer, and `None` means that shortest retention. So a request whose entries were all short-lived does not leave its IP address and user agent behind on the transaction row. Entries of longer-kept severities keep their context in `data["context"]`, and listings rebuild the group header from it.
- Partitions are detached one at a time with `DETACH PARTITION ... CONCURRENTLY`, which does not block audit inserts, then dropped. The call switches its connection to `AUTOCOMMIT`, as `CONCURRENTLY` requires.
- Waiting for transactions that have used the audit tables counts against `lock_timeout`, so a long-running transaction makes the call fail with `PartitionLockTimeoutError`. Partitions dropped before that stay dropped; a detach left pending is finished by the next call.

## Health

```python
report = audit.maintenance.health(min_months_ahead=2)
if not report.ok:
    alert(report)
```

`health(min_months_ahead=2)` is read-only and returns a `HealthReport`:

- `transaction` and `activity` (by severity value): `PartitionHealth` with `covers_now`, `months_ahead` and `below` (the current month is not covered, or fewer than `min_months_ahead` months ahead are);
- `pending_detach`: partitions left "pending detach" by an interrupted `drop_expired`, which its next call finishes;
- `orphaned`: tables named like monthly partitions that are not attached, left by a crash between detach and drop. Nothing drops them automatically: check the name, then `DROP TABLE` it;
- `ok`: nothing is below the threshold, pending or orphaned.

The default threshold of 2 flags one missed monthly run of `ensure_partitions(months_ahead=3)`.

## Sync and async

`audit.maintenance` runs on the `AuditTrail`'s engine. With an `AsyncEngine`, use `aensure_partitions()`, `adrop_expired()` and `ahealth()`.
