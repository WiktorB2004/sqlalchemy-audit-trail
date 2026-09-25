# Operations

The library gives you the maintenance functions; scheduling them is up to you (cron, a Kubernetes CronJob, Celery beat, APScheduler, ...). There is no command-line tool: a maintenance job is a short script.

## A maintenance job

Use an `AuditTrail` on an engine with the [maintenance role](permissions.md), with the same schema, severities and indexes as your application's:

```python
"""Audit maintenance, run daily."""

import logging
import sys
from datetime import timedelta

from sqlalchemy import create_engine

from audit_trail import AuditTrail, Severity
from audit_trail.maintenance import PartitionLockTimeoutError

RETENTION = {
    Severity.INFO: timedelta(days=90),
    Severity.NOTICE: timedelta(days=365),
    Severity.WARNING: timedelta(days=3 * 365),
    Severity.CRITICAL: None,  # kept forever
}


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    audit = AuditTrail(create_engine(MAINTENANCE_DATABASE_URL), events=[])
    try:
        audit.maintenance.ensure_partitions(months_ahead=3)
        audit.maintenance.drop_expired(RETENTION)
    except PartitionLockTimeoutError:
        logging.warning("a lock was not granted in time; the next run retries")
    report = audit.maintenance.health()
    if not report.ok:
        logging.error("audit partitions need attention: %s", report)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### `ensure_partitions`

Run it at least daily, with `months_ahead=3` (the default). A missed run is harmless while partitions exist for months ahead; `health()` flags coverage dropping below `min_months_ahead` (2 by default) long before writes would fail. Running it at application start as well is fine: it is idempotent, and concurrent calls are serialized. It needs the maintenance role, though, so an application connecting as `app_user` should leave it to the job.

### `drop_expired`

Run it daily or weekly. Partitions are monthly, so a partition is dropped once its whole month is older than the retention. Schedule it outside peak hours: each detach waits for transactions that are using the audit tables, and a long-running transaction makes the call stop with `PartitionLockTimeoutError` after `lock_timeout` (5 seconds by default). That is expected; what was dropped stays dropped, and the next run continues. `ensure_partitions` and `drop_expired` take the same advisory lock, so they never run at the same time.

Every severity you use should have a key in the retention mapping, with `None` for "keep forever"; one that is missing is kept, with a warning in the log.

### `health`

`health()` only reads the catalog, so any role that can see the audit tables can run it, for example a monitoring probe that alerts when `report.ok` is false:

- coverage below the threshold: `ensure_partitions` has not been running;
- `pending_detach`: a `drop_expired` was interrupted; the next run finishes it;
- `orphaned`: a detached table was left behind by a crash between the detach and the drop. Check the name and drop it by hand.

## Logging

The library logs on `audit_trail` and its child loggers. Alert on errors from:

- `audit_trail.writer`: audit entries that were not written, for example because a partition was missing (with `on_error="log"`, the business transaction went on without them);
- `audit_trail.listener`: warnings about bulk `UPDATE`/`DELETE` statements that bypassed the audit trail;
- `audit_trail.diff`: `label`, `scope` or `target` options that read attributes that were not loaded.

## Shutdown

If the library built the durable engine (you did not pass `durable_engine`), close its pool on shutdown with `audit.dispose()`, or `await audit.adispose()` for an async engine.
